package investigation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// The step protocol.
//
// A worker invocation is a pure function of a bounded state envelope: it
// consumes at most one pending result and emits exactly one schema-validated
// request, or the final report. The controller owns the state, the credentials
// and the network; the worker owns the transition. That split is what lets the
// same engine run in-process for replay and inside a network-denied sandbox in
// step 4, with no special case for either.
const (
	PhasePlan     = "plan"
	PhaseReassess = "reassess"

	ResultModelRequest = "model_request"
	ResultInfraRequest = "infra_request"
	ResultFinal        = "final"

	PendingModel = "model"
	PendingInfra = "infra"
)

// WorkerInput is what the controller hands the worker: the bounded state plus the
// one result it is waiting on.
//
// The two have separate budgets on purpose. State stays under the worker state
// budget, while an infrastructure answer may be up to the tool response budget.
// Keeping the pending answer out of the state is what allows a multi-megabyte
// answer to be reduced to a bounded observation before it is ever stored.
type WorkerInput struct {
	State   StepEnvelope `json:"state"`
	Pending *Pending     `json:"pending,omitempty"`
}

// Pending is one answer and the request it answers, so the worker never has to
// remember what it asked for.
type Pending struct {
	Kind     string            `json:"kind"`
	Action   *gateway.Action   `json:"action,omitempty"`
	Response *gateway.Response `json:"response,omitempty"`
	Model    *ModelResponse    `json:"model,omitempty"`
}

func (p Pending) Validate() error {
	switch p.Kind {
	case PendingInfra:
		if p.Action == nil || p.Response == nil {
			return fmt.Errorf("an infrastructure result needs both the request and the answer")
		}
		return nil
	case PendingModel:
		if p.Model == nil {
			return fmt.Errorf("a model result needs the response")
		}
		return nil
	default:
		return fmt.Errorf("pending result kind %q is not one of %s or %s", p.Kind, PendingModel, PendingInfra)
	}
}

// ObservationSummary is what the planner is allowed to see: the rendered
// statement and its provenance, never the raw payload. Payloads cannot carry
// instructions into the model if they never reach it.
type ObservationSummary struct {
	ID           string            `json:"id"`
	Type         ObservationType   `json:"type"`
	Source       string            `json:"source"`
	Entity       string            `json:"entity"`
	Statement    string            `json:"statement"`
	Window       Window            `json:"window"`
	RetrievedAt  time.Time         `json:"retrieved_at"`
	Completeness Completeness      `json:"completeness"`
	Digest       string            `json:"digest"`
	Query        gateway.QueryMeta `json:"query"`
	CalcVersion  string            `json:"calc_version,omitempty"`
	Parents      []string          `json:"parents,omitempty"`
}

func (o Observation) Summary() ObservationSummary {
	return ObservationSummary{
		ID:           o.ID,
		Type:         o.Type,
		Source:       o.Source,
		Entity:       o.Entity,
		Statement:    o.Statement,
		Window:       o.Window,
		RetrievedAt:  o.RetrievedAt,
		Completeness: o.Completeness,
		Digest:       o.Digest,
		Query:        o.Query,
		CalcVersion:  o.CalcVersion,
		Parents:      o.Parents,
	}
}

// ModelRequest is the entire planner context. It carries summaries only, and it
// states the closed set of actions the planner may name.
type ModelRequest struct {
	SchemaVersion  string               `json:"schema_version"`
	Phase          string               `json:"phase"`
	Incident       Incident             `json:"incident"`
	Step           int                  `json:"step"`
	Hypotheses     []Hypothesis         `json:"hypotheses"`
	Observations   []ObservationSummary `json:"observations"`
	Relations      []Relation           `json:"relations"`
	AllowedActions []gateway.ActionKind `json:"allowed_actions"`
	AllowedMetrics []string             `json:"allowed_metrics"`
	Budget         BudgetsLeft          `json:"budget"`
	RetryNote      string               `json:"retry_note,omitempty"`
}

type BudgetsLeft struct {
	ModelCallsRemaining int `json:"model_calls_remaining"`
	InfraCallsRemaining int `json:"infra_calls_remaining"`
	SecondsRemaining    int `json:"seconds_remaining"`
}

// HypothesisSpec is a planner-proposed hypothesis. The claim kind is a closed
// enum so that a model cannot invent an assertion the policy does not police.
type HypothesisSpec struct {
	Statement      string      `json:"statement"`
	FaultDomain    FaultDomain `json:"fault_domain"`
	ClaimKind      ClaimKind   `json:"claim_kind"`
	EvidenceNeeded []string    `json:"evidence_needed,omitempty"`
}

// ModelResponse is the validated planner output.
type ModelResponse struct {
	SchemaVersion string           `json:"schema_version"`
	Hypotheses    []HypothesisSpec `json:"hypotheses"`
	NextAction    *gateway.Action  `json:"next_action,omitempty"`
	Reason        string           `json:"reason"`

	// The fields below are set by the planner client, never by the model: its
	// reply is decoded into the three fields above alone.

	// AnsweredBy names the endpoint and the model the provider says answered.
	AnsweredBy string `json:"answered_by,omitempty"`
	// Attempts is how many provider calls this reply cost, fallbacks
	// included. Every one is charged to the model-call budget.
	Attempts int `json:"attempts,omitempty"`
	// FallbackReasons are why each earlier endpoint was passed over.
	FallbackReasons []string `json:"fallback_reasons,omitempty"`
}

// Validate enforces the planner contract. Invalid output is retried once and
// otherwise rejected; it is never partially interpreted.
func (m ModelResponse) Validate(phase string) error {
	if m.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("planner schema_version %q, want %q", m.SchemaVersion, gateway.SchemaVersion)
	}
	if m.Reason == "" {
		return fmt.Errorf("planner response must state its reason")
	}
	if phase == PhasePlan && len(m.Hypotheses) < 2 {
		return fmt.Errorf("planner must propose at least two competing hypotheses, got %d", len(m.Hypotheses))
	}
	for i, h := range m.Hypotheses {
		if h.Statement == "" {
			return fmt.Errorf("hypothesis %d has no statement", i)
		}
		if !h.FaultDomain.Valid() {
			return fmt.Errorf("hypothesis %d fault domain %q is invalid", i, h.FaultDomain)
		}
		if !h.ClaimKind.Valid() {
			return fmt.Errorf("hypothesis %d claim kind %q is not a known claim kind", i, h.ClaimKind)
		}
	}
	if m.NextAction != nil {
		if err := m.NextAction.Validate(); err != nil {
			return fmt.Errorf("planner action: %w", err)
		}
	}
	return nil
}

// HypothesisFromSpec materializes a proposed hypothesis with a stable ID.
func HypothesisFromSpec(ids *IDGen, h HypothesisSpec) Hypothesis {
	return Hypothesis{
		SchemaVersion:  gateway.SchemaVersion,
		ID:             ids.Next(PrefixHypothesis),
		Statement:      h.Statement,
		FaultDomain:    h.FaultDomain,
		Status:         HypothesisProposed,
		EvidenceNeeded: h.EvidenceNeeded,
		ClaimKind:      h.ClaimKind,
		Origin:         "planner",
	}
}

// StepEnvelope is the whole worker state: bounded, self-describing and complete.
// Nothing else is needed to reproduce a step.
type StepEnvelope struct {
	SchemaVersion  string          `json:"schema_version"`
	Incident       Incident        `json:"incident"`
	Run            Run             `json:"run"`
	Step           int             `json:"step"`
	Phase          string          `json:"phase"`
	ModelAttempts  int             `json:"model_attempts"`
	Hypotheses     []Hypothesis    `json:"hypotheses"`
	Observations   []Observation   `json:"observations"`
	Relations      []Relation      `json:"relations"`
	Decisions      []Decision      `json:"decisions"`
	Trace          []Call          `json:"trace,omitempty"`
	EvaluatorCalls []EvaluatorCall `json:"evaluator_calls,omitempty"`
	Counters       map[string]int  `json:"counters,omitempty"`
	Note           string          `json:"note,omitempty"`
}

func (e StepEnvelope) Validate(maxBytes int64) error {
	if e.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("envelope schema_version %q, want %q", e.SchemaVersion, gateway.SchemaVersion)
	}
	if err := e.Incident.Validate(); err != nil {
		return fmt.Errorf("envelope incident: %w", err)
	}
	if e.Run.ID == "" {
		return fmt.Errorf("envelope run id must be set")
	}
	if e.Run.IncidentID != e.Incident.ID {
		return fmt.Errorf("envelope run %s does not belong to incident %s", e.Run.ID, e.Incident.ID)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("envelope is not serializable: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("envelope of %d bytes exceeds the %d byte limit", len(raw), maxBytes)
	}
	return nil
}

// StepResult is the worker's single output: a request to execute, or the report.
type StepResult struct {
	SchemaVersion string          `json:"schema_version"`
	Step          int             `json:"step"`
	Kind          string          `json:"kind"`
	Reason        string          `json:"reason"`
	Run           Run             `json:"run"`
	ModelRequest  *ModelRequest   `json:"model_request,omitempty"`
	InfraRequest  *gateway.Action `json:"infra_request,omitempty"`
	Report        *Report         `json:"report,omitempty"`
	Decision      *Decision       `json:"decision,omitempty"`
	Envelope      StepEnvelope    `json:"envelope"`
}
