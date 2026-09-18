package models

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

// JevSchemaVersion identifies the question shape and the response fields Probe
// reads. It is stamped on every relation the arm produces.
const JevSchemaVersion = "jev-choice/v1"

// JevArm classifies an evidence relation with one TypeSafe Choice question per
// observation.
//
// POST {base}/v1/systemone with a bearer token, a state string, and a questions
// map. Choice answers come back with the selected criterion, a probability per
// criterion, and a derived confidence, all of which are retained as
// classification metadata.
//
// The confidence and probabilities describe how concentrated the model's answer
// distribution was. They are recorded and reported as classification metadata;
// Probe never presents them as the probability that a root cause or a label is
// correct, and never lets them override the claims policy.
type JevArm struct {
	Endpoint  Endpoint
	Transport Transport
	Now       func() time.Time
	// MaxResponseBytes bounds one answer.
	MaxResponseBytes int64
	// QuestionName is the single question key sent in each request.
	QuestionName string
}

func (a JevArm) Arm() string { return investigation.JevArm }

func (a JevArm) ArmVersion() string { return JevSchemaVersion }

func (a JevArm) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

func (a JevArm) questionName(observationID string) string {
	if a.QuestionName != "" {
		return a.QuestionName + ":" + observationID
	}
	return "relation:" + observationID
}

// jevInstructionsFor keeps the instruction identical across observations. Only
// which observation is being asked about changes; the evidence itself is in the
// request state, and the rules are shared with the baseline arm.
func jevInstructionsFor(s investigation.ObservationSummary) string {
	return jevInstructions + "\nThe evidence under consideration is " + observationRef(s) + "."
}

// Classification is the metadata one Jev answer carries, kept separate from the
// incident evidence status: it says how the model answered, not what happened in
// the incident.
type Classification struct {
	Choice        string             `json:"choice"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities,omitempty"`
	Model         string             `json:"model,omitempty"`
}

func (a JevArm) Label(h investigation.Hypothesis, f investigation.Facts, obs map[string]investigation.Observation) ([]investigation.RelationDraft, []investigation.EvaluatorCall, error) {
	if !a.Endpoint.Configured() {
		return nil, failed(investigation.CallFailed,
			"jev arm is not configured: set VORA_PROBE_JEV_BASE_URL", a.Arm(), a.ArmVersion(), a.Endpoint.Model, h.ID, len(obs)), nil
	}
	summaries := sortedSummaries(obs)
	if len(summaries) == 0 {
		return nil, nil, nil
	}
	transport := a.Transport
	if transport == nil {
		transport = NewHTTPTransport(a.Endpoint.Timeout)
	}

	started := a.now()
	drafts, call, err := a.classify(context.Background(), transport, h, summaries, AggregateContext(f))
	call.LatencyMS = a.now().Sub(started).Milliseconds()
	if err != nil {
		// A Jev failure is a failed arm. Substituting another evaluator here
		// would make the benchmark report a result for an arm that never ran.
		return nil, []investigation.EvaluatorCall{call}, err
	}
	return drafts, []investigation.EvaluatorCall{call}, nil
}

// classify asks one question per piece of evidence in a single request. Jev
// takes a questions map, so N independent Choice answers cost one round trip,
// which is what keeps the arm's call count comparable to the baseline's.
func (a JevArm) classify(ctx context.Context, transport Transport, h investigation.Hypothesis, summaries []investigation.ObservationSummary, aggregate []string) ([]investigation.RelationDraft, investigation.EvaluatorCall, error) {
	call := investigation.EvaluatorCall{
		SchemaVersion: gateway.SchemaVersion,
		Arm:           a.Arm(),
		ArmVersion:    a.ArmVersion(),
		Model:         a.Endpoint.Model,
		Remote:        true,
		Hypothesis:    h.ID,
		Observations:  len(summaries),
		Status:        investigation.CallOK,
	}
	questions := make(map[string]jevQuestion, len(summaries))
	for _, s := range summaries {
		questions[a.questionName(s.ID)] = jevQuestion{
			Type:         "choice",
			Instructions: jevInstructionsFor(s),
			Criteria:     Criteria(),
		}
	}
	request := jevRequest{
		State:     renderBatch(h, summaries, aggregate),
		Model:     a.Endpoint.Model,
		Questions: questions,
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, call, err
	}
	headers := map[string]string{}
	if a.Endpoint.APIKey != "" {
		headers["Authorization"] = "Bearer " + a.Endpoint.APIKey
	}
	status, raw, err := transport.Do(ctx, "POST", strings.TrimRight(a.Endpoint.BaseURL, "/")+"/v1/systemone", headers, body, a.MaxResponseBytes)
	if err != nil {
		call.Status = investigation.CallFailed
		call.Reason = err.Error()
		return nil, call, err
	}
	if status < 200 || status > 299 {
		call.Status = investigation.CallFailed
		call.Reason = fmt.Sprintf("endpoint returned %d: %s", status, snippet(raw, 200))
		return nil, call, fmt.Errorf("%s", call.Reason)
	}
	var parsed jevResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		call.Status = investigation.CallInvalid
		call.Reason = err.Error()
		return nil, call, err
	}
	if parsed.Model != "" {
		call.Model = parsed.Model
	}
	if parsed.Usage.InputTokens != nil {
		call.PromptTokens = *parsed.Usage.InputTokens
	}
	if parsed.Usage.OutputTokens != nil {
		call.CompletionTokens = *parsed.Usage.OutputTokens
	}

	drafts := make([]investigation.RelationDraft, 0, len(summaries))
	metadata := make([]string, 0, len(summaries))
	for _, s := range summaries {
		answer, ok := parsed.Answers[a.questionName(s.ID)]
		if !ok {
			call.Status = investigation.CallInvalid
			call.Reason = missingAnswerReason(parsed.Answers, a, summaries)
			return nil, call, fmt.Errorf("%s", call.Reason)
		}
		if answer.Type != "" && answer.Type != "choice" {
			call.Status = investigation.CallInvalid
			call.Reason = fmt.Sprintf("answer for %s has type %q, which is not a choice", s.ID, answer.Type)
			return nil, call, fmt.Errorf("%s", call.Reason)
		}
		if strings.TrimSpace(answer.Choice) == "" {
			call.Status = investigation.CallInvalid
			call.Reason = fmt.Sprintf("answer for %s carried no choice", s.ID)
			return nil, call, fmt.Errorf("%s", call.Reason)
		}
		relationship, err := validateLabel(answer.Choice)
		if err != nil {
			call.Status = investigation.CallInvalid
			call.Reason = fmt.Sprintf("for %s: %v", s.ID, err)
			return nil, call, fmt.Errorf("%s", call.Reason)
		}
		classification := Classification{
			Choice:        answer.Choice,
			Confidence:    answer.Confidence,
			Probabilities: answer.Probabilities,
			Model:         parsed.Model,
		}
		metadata = append(metadata, fmt.Sprintf("%s=%s", s.ID, describeClassification(classification, "")))
		drafts = append(drafts, investigation.RelationDraft{
			Observation:  s.ID,
			Relationship: relationship,
			Reason:       fmt.Sprintf("jev %s, confidence %s", relationship, investigation.FormatFloat(answer.Confidence, 3)),
		})
	}
	call.Reason = strings.Join(metadata, " | ")
	return drafts, call, nil
}

// missingAnswerReason reports which questions went unanswered, by name, so a
// partial response is diagnosable rather than just rejected.
func missingAnswerReason(answers map[string]jevChoiceAnswer, a JevArm, summaries []investigation.ObservationSummary) string {
	var missing, extra []string
	for _, s := range summaries {
		if _, ok := answers[a.questionName(s.ID)]; !ok {
			missing = append(missing, s.ID)
		}
	}
	known := map[string]bool{}
	for _, s := range summaries {
		known[a.questionName(s.ID)] = true
	}
	for name := range answers {
		if !known[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	switch {
	case len(missing) > 0:
		return "response has no answer for " + strings.Join(missing, ", ")
	default:
		return "response contains answers that were not asked for: " + strings.Join(extra, ", ")
	}
}

// describeClassification records the distribution-derived metadata alongside the
// outcome. It is metadata about the model's answer, deliberately worded so it
// cannot be mistaken for a statement about the incident.
func describeClassification(c Classification, existing string) string {
	parts := []string{}
	if existing != "" {
		parts = append(parts, existing)
	}
	if c.Choice != "" {
		parts = append(parts, fmt.Sprintf("choice %s", c.Choice))
	}
	if c.Confidence != 0 {
		parts = append(parts, fmt.Sprintf("confidence %s (concentration of the answer distribution)",
			investigation.FormatFloat(c.Confidence, 3)))
	}
	if len(c.Probabilities) > 0 {
		keys := make([]string, 0, len(c.Probabilities))
		for k := range c.Probabilities {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		rendered := make([]string, 0, len(keys))
		for _, k := range keys {
			rendered = append(rendered, fmt.Sprintf("%s %s", k, investigation.FormatFloat(c.Probabilities[k], 3)))
		}
		parts = append(parts, "probabilities "+strings.Join(rendered, ", "))
	}
	return strings.Join(parts, "; ")
}

// jevInstructions is the question instruction. The label definitions travel as
// the question's criteria and the shared rules are stated here, so the Jev arm is
// asked the same thing as the baseline arm.
var jevInstructions = "How does the evidence under consideration bear on the hypothesis?\n\nRules:\n" + Rules

type jevRequest struct {
	State     string                 `json:"state"`
	Model     string                 `json:"model"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria"`
}

type jevResponse struct {
	Model   string                     `json:"model"`
	Answers map[string]jevChoiceAnswer `json:"answers"`
	Usage   struct {
		InputTokens  *int `json:"input_tokens"`
		OutputTokens *int `json:"output_tokens"`
	} `json:"usage"`
}

type jevChoiceAnswer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}
