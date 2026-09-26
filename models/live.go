package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// LivePlannerPromptVersion identifies the planner prompt and the reply shape it
// asks for. It is recorded with a run so a benchmark can never mix two prompts
// without saying so.
const LivePlannerPromptVersion = "planner-prompt/v2"

// LivePlanner is the model-driven planner: it proposes competing hypotheses and
// chooses the next piece of evidence to collect.
//
// It runs on the controller, not in the sandbox, because it needs a credential
// and the network. That is the same split the whole design rests on: the worker
// decides *what* to ask for, the trusted side is the only thing that can reach a
// model or a datasource.
//
// The shape is deliberately identical to the evaluator arms — an endpoint from
// run configuration, a transport that refuses redirects, and strict decoding of
// our own contract inside a leniently-decoded provider envelope.
type LivePlanner struct {
	Endpoint         Endpoint
	Transport        Transport
	Now              func() time.Time
	MaxResponseBytes int64
}

func (p LivePlanner) Version() string { return LivePlannerPromptVersion }

func (p LivePlanner) Plan(ctx context.Context, request investigation.ModelRequest) (investigation.ModelResponse, error) {
	if !p.Endpoint.Configured() {
		return investigation.ModelResponse{}, errors.New("planner is not configured: set VORA_PROBE_MODEL_BASE_URL")
	}
	transport := p.Transport
	if transport == nil {
		transport = NewHTTPTransport(p.Endpoint.Timeout)
	}
	req := chatRequest{
		Model: p.Endpoint.Model,
		Messages: []chatMessage{
			{Role: "system", Content: PlannerSystemPrompt()},
			{Role: "user", Content: renderPlannerRequest(request)},
		},
		MaxTokens:   p.Endpoint.MaxOutputTokens,
		Temperature: 0,
		// The provider enforces the reply's shape. Lab runs failed on replies
		// that left out an action's entity or window; a strict schema makes
		// such a reply impossible to produce rather than a retry to spend.
		ResponseFormat: &chatResponseFormat{Type: "json_schema", JSONSchema: &chatJSONSchema{
			Name: "planner_reply", Strict: true, Schema: PlannerResponseSchema(request.AllowedActions),
		}},
	}
	if requiresParameterPinning(p.Endpoint.BaseURL) {
		req.Provider = &providerPrefs{RequireParameters: true}
	}
	body, err := json.Marshal(req)
	if err != nil {
		return investigation.ModelResponse{}, err
	}
	headers := map[string]string{}
	if p.Endpoint.APIKey != "" {
		headers["Authorization"] = "Bearer " + p.Endpoint.APIKey
	}
	status, raw, err := transport.Do(ctx, "POST", strings.TrimRight(p.Endpoint.BaseURL, "/")+"/chat/completions", headers, body, p.MaxResponseBytes)
	if err != nil {
		return investigation.ModelResponse{}, err
	}
	if status < 200 || status > 299 {
		return investigation.ModelResponse{}, fmt.Errorf("planner endpoint returned %d: %s", status, snippet(raw, 200))
	}

	// The provider envelope is decoded leniently; our contract inside it is not.
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return investigation.ModelResponse{}, err
	}
	if len(parsed.Choices) == 0 {
		return investigation.ModelResponse{}, errors.New("planner endpoint returned no choices")
	}
	var answer plannerAnswer
	if err := decodeStrict([]byte(parsed.Choices[0].Message.Content), &answer); err != nil {
		return investigation.ModelResponse{}, err
	}
	// The schema version is the client's contract, not a question for the model.
	// What the model does have to get right is the content, and the engine
	// validates that unchanged.
	model := parsed.Model
	if model == "" {
		model = p.Endpoint.Model
	}
	return investigation.ModelResponse{
		SchemaVersion: gateway.SchemaVersion,
		Hypotheses:    answer.Hypotheses,
		NextAction:    answer.NextAction,
		Reason:        answer.Reason,
		AnsweredBy:    endpointHost(p.Endpoint.BaseURL) + " " + model,
		Attempts:      1,
	}, nil
}

// FallbackPlanner asks each planner in turn until one answers. It is for the
// planner alone: an evaluator arm under comparison is never substituted, but a
// run whose planner endpoint is down can still be planned by the next one, and
// the report says which answered, and why the others were passed over.
type FallbackPlanner struct {
	Planners []Planner
}

func (f FallbackPlanner) Plan(ctx context.Context, request investigation.ModelRequest) (investigation.ModelResponse, error) {
	var reasons []string
	var errs []error
	attempts := 0
	for _, p := range f.Planners {
		resp, err := p.Plan(ctx, request)
		n := resp.Attempts
		if n == 0 {
			n = 1
		}
		attempts += n
		if err == nil {
			resp.Attempts = attempts
			resp.FallbackReasons = append(reasons, resp.FallbackReasons...)
			return resp, nil
		}
		errs = append(errs, err)
		reasons = append(reasons, err.Error())
		if ctx.Err() != nil {
			// The run's deadline passed: no endpoint can answer in time.
			break
		}
	}
	return investigation.ModelResponse{}, fmt.Errorf("every planner endpoint failed: %w", errors.Join(errs...))
}

// PlannerFromConfig is the live planner for a run: the primary endpoint, then
// the fallback when one is configured, each with its own timeout.
func PlannerFromConfig(cfg Config) Planner {
	primary := LivePlanner{Endpoint: cfg.Baseline, MaxResponseBytes: 1 << 20}
	if !cfg.PlannerFallback.Configured() {
		return primary
	}
	return FallbackPlanner{Planners: []Planner{primary, LivePlanner{Endpoint: cfg.PlannerFallback, MaxResponseBytes: 1 << 20}}}
}

func endpointHost(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return base
	}
	return u.Host
}

type plannerAnswer struct {
	Hypotheses []investigation.HypothesisSpec `json:"hypotheses"`
	NextAction *gateway.Action                `json:"next_action"`
	Reason     string                         `json:"reason"`
}

// PlannerSystemPrompt renders the closed sets from code. A prompt that restated
// them by hand would drift from the contract the engine actually enforces, and
// the drift would show up as a rejected planner response rather than as a
// mistake in the prompt.
func PlannerSystemPrompt() string {
	return fmt.Sprintf(`You plan a read-only infrastructure investigation.

You never execute anything. You propose competing hypotheses about an incident
and choose the single next piece of evidence to collect; a controller carries the
request out and returns the answer, and you then reassess.

Reply with JSON only:
{"hypotheses":[{"statement":"...","fault_domain":"...","claim_kind":"...","evidence_needed":["..."]}],
 "next_action":{"kind":"...","entity":"...","reason":"..."} or null,
 "reason":"..."}

Allowed fault domains: %s
Allowed claim kinds: %s
Allowed action kinds: %s
Allowed metrics: %s
Log filters (logs.query only): %s

Rules:
- While the cause is unestablished, propose at least two genuinely competing
  hypotheses. Restatements of one explanation are not competing.
- When the symptom is a restart or a termination, the decisive evidence is the
  container's termination state (its last termination reason and exit code) and
  the namespace events around it. Metrics show pressure, not why a container
  stopped, so collect the termination evidence before concluding anything about
  it.
- Choose exactly one next action, or null when the evidence is sufficient or the
  budget is exhausted. Give a reason either way.
- Every action needs "kind", "entity" (the service name from the incident) and
  "reason". A "metrics.query" action needs three more fields, and looks exactly
  like this:
  {"kind":"metrics.query","entity":"<service>","reason":"<why>",
   "metric":"container_memory_working_set_bytes",
   "window":{"start":"<RFC3339 UTC>","end":"<RFC3339 UTC>"},"resolution":"30s"}
  The window may span at most one hour. A "logs.query" action, when it is
  offered, names one filter and a window, and sets "metric" and "resolution"
  to null:
  {"kind":"logs.query","entity":"<service>","reason":"<why>","filter":"error",
   "window":{"start":"<RFC3339 UTC>","end":"<RFC3339 UTC>"},"metric":null,"resolution":null}
  Other action kinds set "metric", "window", "resolution" and "filter" to null,
  except kubernetes.events, which takes a window.
- A missing, empty or malformed required field is rejected, and the whole reply
  with it. Do not omit a field to save space: an action is all of its fields or
  it is nothing.
- Ask only for the actions offered for this incident (listed with it) and the
  metrics and log filters listed above. Anything else is rejected.
- You are read-only. Never propose a restart, a change, a rollout or a
  remediation, and never assert a cause the evidence does not support.`,
		joinDomains(), joinClaimKinds(), joinActionKinds(), strings.Join(gateway.AllowedMetrics, ", "),
		strings.Join(gateway.LogFilterNames(), ", "))
}

func joinDomains() string {
	out := make([]string, 0, len(investigation.AllFaultDomains))
	for _, d := range investigation.AllFaultDomains {
		out = append(out, string(d))
	}
	return strings.Join(out, ", ")
}

func joinClaimKinds() string {
	out := make([]string, 0, len(investigation.AllClaimKinds))
	for _, k := range investigation.AllClaimKinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

func joinActionKinds() string {
	out := make([]string, 0, len(gateway.AllowedActions))
	for _, a := range gateway.AllowedActions {
		out = append(out, string(a))
	}
	return strings.Join(out, ", ")
}

// renderPlannerRequest is everything the planner is allowed to see. It carries
// observation summaries, never payloads, so a compromised datasource cannot
// smuggle instructions into the planning context.
func renderPlannerRequest(r investigation.ModelRequest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PHASE\n%s\n", r.Phase)
	fmt.Fprintf(&b, "INCIDENT\nid %s\nservice %s, environment %s\nsymptom: %s\nstarted: %s\n",
		r.Incident.ID, r.Incident.Service, r.Incident.Environment, r.Incident.Symptom,
		r.Incident.StartedAt.UTC().Format(time.RFC3339))
	if class, ok := investigation.ClassNamed(r.Incident.Class); ok {
		// Guidance, not a constraint: the planner still proposes what it
		// judges, and the claims policy is the same for every class.
		kinds := make([]string, 0, len(class.Hypotheses))
		for _, k := range class.Hypotheses {
			kinds = append(kinds, string(k))
		}
		first := make([]string, 0, len(class.FirstEvidence))
		for _, a := range class.FirstEvidence {
			first = append(first, string(a))
		}
		fmt.Fprintf(&b, "\nINCIDENT CLASS %s\n%s\nCompeting hypotheses worth weighing: %s. Evidence to collect first: %s.\n",
			class.Name, class.Guidance, strings.Join(kinds, ", "), strings.Join(first, ", "))
	}
	if r.Incident.Trigger == investigation.TriggerForecast {
		// A forecast is a hypothesis about the future. The planner is told so,
		// so it weighs the trend against the explanations that would make it
		// harmless instead of treating the forecast as a failure to explain.
		b.WriteString("\nFORECAST\nThis incident was opened by a forecast: nothing has failed yet. Weigh " +
			string(investigation.ClaimExhaustionForecast) + " (the growth continues to the limit) against competing explanations, " +
			"such as a cycle that will not cross the limit, workload growth that will level off, or growth that follows a recent change " +
			"(" + string(investigation.ClaimDeploymentRegression) + "). Collect the memory series and the memory limit. " +
			"Never describe the forecast as a failure that has happened.\n")
	}
	offered := make([]string, 0, len(r.AllowedActions))
	for _, a := range r.AllowedActions {
		offered = append(offered, string(a))
	}
	fmt.Fprintf(&b, "\nOFFERED ACTIONS FOR THIS INCIDENT\n%s\n", strings.Join(offered, ", "))
	fmt.Fprintf(&b, "\nBUDGET\nmodel calls remaining %d, infrastructure calls remaining %d, seconds remaining %d\n",
		r.Budget.ModelCallsRemaining, r.Budget.InfraCallsRemaining, r.Budget.SecondsRemaining)

	if r.RetryNote != "" {
		fmt.Fprintf(&b, "\nYOUR PREVIOUS REPLY WAS REJECTED\n%s\n", r.RetryNote)
	}
	if len(r.Hypotheses) > 0 {
		b.WriteString("\nCURRENT HYPOTHESES\n")
		for _, h := range r.Hypotheses {
			fmt.Fprintf(&b, "- [%s] %s (fault_domain %s, claim_kind %s, status %s)\n",
				h.ID, h.Statement, h.FaultDomain, h.ClaimKind, h.Status)
		}
	}
	if len(r.Observations) > 0 {
		b.WriteString("\nEVIDENCE COLLECTED SO FAR\n")
		for _, o := range r.Observations {
			fmt.Fprintf(&b, "- [%s] %s (type %s, source %s, completeness %s)\n",
				o.ID, o.Statement, o.Type, o.Source, o.Completeness)
		}
	}
	if len(r.Relations) > 0 {
		b.WriteString("\nHOW THE EVIDENCE BEARS ON EACH HYPOTHESIS\n")
		for _, rel := range r.Relations {
			fmt.Fprintf(&b, "- %s %s %s: %s\n", rel.Observation, rel.Relationship, rel.Hypothesis, rel.Reason)
		}
	}
	return b.String()
}
