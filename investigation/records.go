// Package investigation owns the Probe investigation domain: the records that
// make an investigation auditable, the claims policy that decides what may be
// asserted, and the deterministic derivations that supply every number in a
// report.
//
// Two rules shape this package. First, no claim may outrun its evidence: a
// memory-limit kill and a memory leak are different assertions with different
// evidence requirements, and the policy refuses the second when only the first
// is proven. Second, every number is computed here, never by a model, so a
// report can be reproduced from its inputs.
package investigation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// Window and Completeness are shared with the infrastructure contract so that a
// recorded answer and the observation derived from it cannot drift apart.
type (
	Window       = gateway.Window
	Completeness = gateway.Completeness
)

const (
	Complete    = gateway.Complete
	Truncated   = gateway.Truncated
	Redacted    = gateway.Redacted
	Incomplete  = gateway.Incomplete
	Unavailable = gateway.Unavailable
)

// Trigger records how an investigation was started.
type Trigger string

const (
	TriggerManual Trigger = "manual"
	TriggerCLI    Trigger = "cli"
	TriggerAlert  Trigger = "alert"
	// TriggerForecast: opened by a forecast, before anything has failed.
	TriggerForecast Trigger = "forecast"
)

// ClaimPolicyVersion is bumped whenever claim admissibility changes, so that
// saved reports can be read in the light of the rules that produced them.
const ClaimPolicyVersion = "claims/v3"

// RelationPolicyVersion is the version of the deterministic relation rules.
const RelationPolicyVersion = "relations/v1"

// IDs are stable, human-referencable and deterministic: the sequence counter
// makes the Nth observation of a replay identical to the Nth observation of the
// original run, which is what lets a saved report be re-checked.
type IDGen struct{ n map[string]int }

func NewIDGen() *IDGen { return &IDGen{n: map[string]int{}} }

// NewIDGenFrom restores counter state. A step worker is invoked fresh for every
// transition, so the counters travel in the state envelope; without that, the
// second observation of a run would be numbered OBS-0001 again.
func NewIDGenFrom(counters map[string]int) *IDGen {
	g := NewIDGen()
	for prefix, n := range counters {
		g.n[prefix] = n
	}
	return g
}

func (g *IDGen) Next(prefix string) string {
	g.n[prefix]++
	return fmt.Sprintf("%s-%04d", prefix, g.n[prefix])
}

// Snapshot returns the counter state for the next transition.
func (g *IDGen) Snapshot() map[string]int {
	out := make(map[string]int, len(g.n))
	for prefix, n := range g.n {
		if n > 0 {
			out[prefix] = n
		}
	}
	return out
}

const (
	PrefixIncident    = "INC"
	PrefixRun         = "RUN"
	PrefixObservation = "OBS"
	PrefixHypothesis  = "HYP"
	PrefixRelation    = "REL"
	PrefixDecision    = "DEC"
	PrefixCall        = "CALL"
)

// IncidentStatus tracks the incident itself, independently of any one run
// attempt: an incident can outlive several interrupted attempts.
type IncidentStatus string

const (
	IncidentOpen          IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentComplete      IncidentStatus = "complete"
	IncidentFailed        IncidentStatus = "failed"
)

// Incident is the investigation trigger and its fixed evidence window.
type Incident struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Environment   string         `json:"environment"`
	Service       string         `json:"service"`
	Symptom       string         `json:"symptom"`
	Trigger       Trigger        `json:"trigger"`
	StartedAt     time.Time      `json:"started_at"`
	Window        Window         `json:"window"`
	Status        IncidentStatus `json:"status"`
	// Severity is the alert's, when the incident came from one. It decides
	// which actions an investigation is offered: logs only for serious ones.
	Severity string `json:"severity,omitempty"`
	// Class is the incident class its alert maps to (see Classes). It guides
	// the planner; it never limits what may be concluded.
	Class string `json:"class,omitempty"`
}

func (i Incident) Validate() error {
	if i.SchemaVersion != gateway.SchemaVersion {
		return fmt.Errorf("incident schema_version %q, want %q", i.SchemaVersion, gateway.SchemaVersion)
	}
	if i.ID == "" {
		return fmt.Errorf("incident id must be set")
	}
	if i.Environment == "" {
		return fmt.Errorf("incident environment must be set")
	}
	if i.Service == "" {
		return fmt.Errorf("incident service must be set")
	}
	if i.Symptom == "" {
		return fmt.Errorf("incident symptom must be set")
	}
	switch i.Trigger {
	case TriggerManual, TriggerCLI, TriggerAlert, TriggerForecast:
	default:
		return fmt.Errorf("incident trigger %q is invalid", i.Trigger)
	}
	if i.StartedAt.IsZero() {
		return fmt.Errorf("incident started_at must be set")
	}
	switch i.Status {
	case IncidentOpen, IncidentInvestigating, IncidentComplete, IncidentFailed:
	default:
		return fmt.Errorf("incident status %q is invalid", i.Status)
	}
	return i.Window.Validate(24 * time.Hour)
}

// ObservationType enumerates normalized evidence kinds.
type ObservationType string

const (
	ObsMetric            ObservationType = "metric"
	ObsLog               ObservationType = "log"
	ObsTrace             ObservationType = "trace"
	ObsK8sEvent          ObservationType = "k8s_event"
	ObsK8sContainerState ObservationType = "k8s_container_state"
	ObsK8sDeployment     ObservationType = "k8s_deployment"
	ObsConfiguration     ObservationType = "configuration"
	ObsDerived           ObservationType = "derived"
	ObsHumanInput        ObservationType = "human_input"
)

// Observation is normalized evidence. The statement is rendered by code from
// the payload, so a model never authors a number that appears in a report.
type Observation struct {
	SchemaVersion string             `json:"schema_version"`
	ID            string             `json:"id"`
	Type          ObservationType    `json:"type"`
	Action        gateway.ActionKind `json:"action"`
	Source        string             `json:"source"`
	Entity        string             `json:"entity"`
	Statement     string             `json:"statement"`
	Window        Window             `json:"window"`
	RetrievedAt   time.Time          `json:"retrieved_at"`
	Query         gateway.QueryMeta  `json:"query"`
	Digest        string             `json:"digest"`
	Completeness  Completeness       `json:"completeness"`
	CalcVersion   string             `json:"calc_version,omitempty"`
	Parents       []string           `json:"parents,omitempty"`
	Payload       json.RawMessage    `json:"payload,omitempty"`
}

// FaultDomain is the coarse classification a hypothesis is filed under.
type FaultDomain string

const (
	DomainApplication        FaultDomain = "application"
	DomainKubernetes         FaultDomain = "kubernetes"
	DomainDatabase           FaultDomain = "database"
	DomainNetwork            FaultDomain = "network"
	DomainExternalDependency FaultDomain = "external_dependency"
	DomainHost               FaultDomain = "host"
	DomainUnknown            FaultDomain = "unknown"
)

func (d FaultDomain) Valid() bool {
	switch d {
	case DomainApplication, DomainKubernetes, DomainDatabase, DomainNetwork,
		DomainExternalDependency, DomainHost, DomainUnknown:
		return true
	}
	return false
}

// AllFaultDomains is the closed set of domains a hypothesis may be filed under.
// It exists so a prompt can render the set from code rather than restating it,
// which is what stops the prompt and the contract drifting apart.
var AllFaultDomains = []FaultDomain{
	DomainApplication,
	DomainKubernetes,
	DomainDatabase,
	DomainNetwork,
	DomainExternalDependency,
	DomainHost,
	DomainUnknown,
}

type HypothesisStatus string

const (
	HypothesisProposed   HypothesisStatus = "proposed"
	HypothesisTesting    HypothesisStatus = "testing"
	HypothesisSupported  HypothesisStatus = "supported"
	HypothesisRefuted    HypothesisStatus = "refuted"
	HypothesisNarrowed   HypothesisStatus = "narrowed"
	HypothesisUnresolved HypothesisStatus = "unresolved"
)

type Hypothesis struct {
	SchemaVersion  string           `json:"schema_version"`
	ID             string           `json:"id"`
	Statement      string           `json:"statement"`
	FaultDomain    FaultDomain      `json:"fault_domain"`
	Status         HypothesisStatus `json:"status"`
	EvidenceNeeded []string         `json:"evidence_needed,omitempty"`
	ClaimKind      ClaimKind        `json:"claim_kind"`
	Origin         string           `json:"origin"`
}

// Relationship is the qualitative answer to "does this observation bear on this
// hypothesis?". It is a label, not a probability: Probe does not present a
// model's distribution as a probability that a root cause is correct.
type Relationship string

const (
	Supports            Relationship = "supports"
	Contradicts         Relationship = "contradicts"
	Neutral             Relationship = "neutral"
	InsufficientContext Relationship = "insufficient_context"
)

// Evaluator names who produced a relation. Keeping the deterministic rules
// distinguishable from model judgements is what makes the step-3 comparison
// meaningful.
type Evaluator string

const (
	EvaluatorDeterministic Evaluator = "deterministic"
	EvaluatorBaseline      Evaluator = "baseline"
	EvaluatorJev           Evaluator = "jev"
)

type Relation struct {
	SchemaVersion string       `json:"schema_version"`
	ID            string       `json:"id"`
	Observation   string       `json:"observation"`
	Hypothesis    string       `json:"hypothesis"`
	Relationship  Relationship `json:"relationship"`
	Reason        string       `json:"reason"`
	Evaluator     Evaluator    `json:"evaluator"`
	PolicyVersion string       `json:"policy_version"`
}

type Outcome string

const (
	OutcomeContinue Outcome = "continue"
	OutcomeStop     Outcome = "stop"
	OutcomePivot    Outcome = "pivot"
	OutcomeEscalate Outcome = "escalate"
)

type Decision struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	At            time.Time `json:"at"`
	Step          int       `json:"step"`
	Outcome       Outcome   `json:"outcome"`
	Reason        string    `json:"reason"`
	Hypothesis    string    `json:"hypothesis,omitempty"`
	PolicyVersion string    `json:"policy_version"`
}

type CallKind string

const (
	CallModel CallKind = "model"
	CallInfra CallKind = "infra"
)

type CallStatus string

const (
	CallOK      CallStatus = "ok"
	CallFailed  CallStatus = "failed"
	CallDenied  CallStatus = "denied"
	CallInvalid CallStatus = "invalid"
)

// Call is the audit record for one outbound request. Requests are journaled
// before execution and results before the next step, so a missing result reads
// as interrupted rather than successful.
type Call struct {
	SchemaVersion  string     `json:"schema_version"`
	ID             string     `json:"id"`
	RunID          string     `json:"run_id"`
	IncidentID     string     `json:"incident_id"`
	Step           int        `json:"step"`
	Kind           CallKind   `json:"kind"`
	Target         string     `json:"target"`
	RequestDigest  string     `json:"request_digest"`
	ResponseDigest string     `json:"response_digest,omitempty"`
	Bytes          int        `json:"bytes"`
	DurationMS     int64      `json:"duration_ms"`
	Status         CallStatus `json:"status"`
	Reason         string     `json:"reason,omitempty"`
	// Model is what answered a model call: the endpoint and the model the
	// provider reported, so a run says which model planned it.
	Model string `json:"model,omitempty"`
}

// Budgets are the hard ceilings for one run. Every retry consumes the same
// persisted budget: there is no unbounded repair loop.
type Budgets struct {
	MaxDurationSeconds int   `json:"max_duration_seconds"`
	MaxInfraCalls      int   `json:"max_infra_calls"`
	MaxModelCalls      int   `json:"max_model_calls"`
	MaxResponseBytes   int64 `json:"max_response_bytes"`
	MaxEnvelopeBytes   int64 `json:"max_envelope_bytes"`
	MaxSteps           int   `json:"max_steps"`
}

// DefaultBudgets are the agreed first-slice limits.
func DefaultBudgets() Budgets {
	return Budgets{
		MaxDurationSeconds: 600,
		MaxInfraCalls:      50,
		MaxModelCalls:      20,
		MaxResponseBytes:   2 << 20,
		MaxEnvelopeBytes:   64 << 10,
		MaxSteps:           40,
	}
}

type BudgetState struct {
	ModelCalls int       `json:"model_calls"`
	InfraCalls int       `json:"infra_calls"`
	Steps      int       `json:"steps"`
	StartedAt  time.Time `json:"started_at"`
}

type RunStatus string

const (
	RunActive          RunStatus = "active"
	RunCompleted       RunStatus = "completed"
	RunFailed          RunStatus = "failed"
	RunBudgetExhausted RunStatus = "budget_exhausted"
	RunInterrupted     RunStatus = "interrupted"
)

// Run is one attempt at an incident. Resuming an interrupted investigation
// means starting a new attempt, not rewriting this record.
type Run struct {
	SchemaVersion string      `json:"schema_version"`
	ID            string      `json:"id"`
	IncidentID    string      `json:"incident_id"`
	Attempt       int         `json:"attempt"`
	StartedAt     time.Time   `json:"started_at"`
	EndedAt       *time.Time  `json:"ended_at,omitempty"`
	Status        RunStatus   `json:"status"`
	Reason        string      `json:"reason,omitempty"`
	Budgets       Budgets     `json:"budgets"`
	Used          BudgetState `json:"used"`
}
