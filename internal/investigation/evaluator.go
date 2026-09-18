package investigation

import "github.com/vorash/vora-probe/internal/gateway"

// The evaluator port.
//
// An arm answers one question: how does this body of evidence bear on this
// hypothesis? Swapping the arm is the entire step-3 comparison; the evidence, the
// hypotheses, the label definitions and the planner are held constant, which is
// what makes the comparison mean anything.
//
// Deterministic rules are an arm like any other. They are not a fallback and not
// a baseline to be replaced: if a model arm cannot beat them, that is the result.
const (
	DeterministicArm = "deterministic"
	BaselineArm      = "baseline"
	JevArm           = "jev"
)

// RelationDraft is a relation before the engine gives it an ID. Evaluators return
// drafts, so an evaluator can never invent an observation ID or a relation ID.
type RelationDraft struct {
	Observation  string
	Relationship Relationship
	Reason       string
}

// EvaluatorCall records what one evaluator invocation actually did: which arm,
// which prompt or schema version, which model the provider says answered, how
// much it cost in tokens and time, and whether it worked. A failure is data.
type EvaluatorCall struct {
	SchemaVersion string `json:"schema_version"`
	Arm           string `json:"arm"`
	ArmVersion    string `json:"arm_version"`
	Model         string `json:"model,omitempty"`
	// Remote marks a call that actually reached a model service. Only remote
	// calls consume the model-call budget: the deterministic arm answers from
	// rules and must not be charged for it, or a whole-loop comparison would
	// price the two arms as if they cost the same.
	Remote           bool       `json:"remote"`
	Hypothesis       string     `json:"hypothesis"`
	Observations     int        `json:"observations"`
	PromptTokens     int        `json:"prompt_tokens,omitempty"`
	CompletionTokens int        `json:"completion_tokens,omitempty"`
	LatencyMS        int64      `json:"latency_ms"`
	Status           CallStatus `json:"status"`
	Reason           string     `json:"reason,omitempty"`
}

// RelationEvaluator is implemented by every arm.
type RelationEvaluator interface {
	Arm() string
	// ArmVersion is the prompt or rule version, stamped on every relation and
	// reported, so a benchmark is attributable to a specific evaluator.
	ArmVersion() string
	// Label answers how the evidence bears on the hypothesis. Every observation
	// it was given must come back with a label: silently dropping the ones that
	// are inconvenient is the failure mode the whole repository exists to
	// prevent. A failure is returned as an error, never smoothed into a default
	// label.
	//
	// Calls are returned rather than aggregated because an arm may make one call
	// per observation, and a benchmark that cannot show how many calls an arm
	// needed, and which of them failed, is not a benchmark.
	Label(h Hypothesis, f Facts, obs map[string]Observation) ([]RelationDraft, []EvaluatorCall, error)
}

// DeterministicEvaluator is the rule-based arm documented in
// docs/claims-policy.md.
type DeterministicEvaluator struct {
	Policy ClaimPolicy
}

func (d DeterministicEvaluator) Arm() string { return DeterministicArm }

func (d DeterministicEvaluator) ArmVersion() string { return RelationPolicyVersion }

func (d DeterministicEvaluator) Label(h Hypothesis, f Facts, obs map[string]Observation) ([]RelationDraft, []EvaluatorCall, error) {
	policy := d.Policy
	if policy.ImpactRatio == 0 {
		policy = DefaultClaimPolicy()
	}
	b := &relationBuilder{hypothesis: h, policy: policy, obs: obs}

	switch h.ClaimKind {
	case ClaimMemoryLimitTermination:
		b.memoryLimit(f)
	case ClaimNonMemoryRestart:
		b.nonMemoryRestart(f)
	case ClaimMemoryLeak:
		b.memoryLeak(f)
	case ClaimAllocationDefect:
		b.allocationDefect(f)
	case ClaimDeploymentRegression:
		b.deploymentRegression(f)
	case ClaimResourceSaturation:
		b.saturation(f)
	default:
		b.inconclusive(f)
	}
	b.restartContext(f)
	b.coverageGaps(f)

	return b.drafts, []EvaluatorCall{{
		SchemaVersion: gateway.SchemaVersion,
		Arm:           d.Arm(),
		ArmVersion:    d.ArmVersion(),
		Hypothesis:    h.ID,
		Observations:  len(obs),
		Status:        CallOK,
	}}, nil
}

// EvaluatorByName resolves an arm name, so a run configuration can select one
// without the engine knowing which arms exist.
func EvaluatorByName(name string, policy ClaimPolicy) (RelationEvaluator, bool) {
	if name == DeterministicArm || name == "" {
		return DeterministicEvaluator{Policy: policy}, true
	}
	return nil, false
}
