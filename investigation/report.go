package investigation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// Report is the product of an investigation: a summary, the claims that were
// considered and refused, the evidence on both sides, what was missing, and
// whether anything was executed. Every claim resolves to retained evidence by
// ID, and validation rejects a report that cites an ID it does not have.
type Report struct {
	SchemaVersion       string             `json:"schema_version"`
	Incident            Incident           `json:"incident"`
	Run                 Run                `json:"run"`
	Summary             string             `json:"summary"`
	Impact              string             `json:"impact,omitempty"`
	Timeline            []TimelineEntry    `json:"timeline"`
	Leading             *ClaimReport       `json:"leading,omitempty"`
	Claims              []ClaimReport      `json:"claims"`
	Hypotheses          []HypothesisReport `json:"hypotheses"`
	Supporting          []EvidenceLink     `json:"supporting"`
	Contradicting       []EvidenceLink     `json:"contradicting"`
	InsufficientContext []EvidenceLink     `json:"insufficient_context"`
	Derived             []Observation      `json:"derived,omitempty"`
	CoverageGaps        []CoverageGap      `json:"coverage_gaps,omitempty"`
	Unresolved          []string           `json:"unresolved"`
	Recommendation      *Recommendation    `json:"recommendation,omitempty"`
	Relations           []Relation         `json:"relations"`
	Decisions           []Decision         `json:"decisions"`
	Trace               []Call             `json:"trace,omitempty"`
	// Arm is the evaluator that labelled the evidence, so a report says which
	// question produced its relations.
	Arm            string          `json:"arm"`
	ArmVersion     string          `json:"arm_version"`
	EvaluatorCalls []EvaluatorCall `json:"evaluator_calls,omitempty"`
}

type ClaimReport struct {
	Kind          ClaimKind `json:"kind"`
	Statement     string    `json:"statement"`
	Allowed       bool      `json:"allowed"`
	Overclaim     bool      `json:"overclaim"`
	Reasons       []string  `json:"reasons,omitempty"`
	Narrowed      string    `json:"narrowed,omitempty"`
	Evidence      []string  `json:"evidence"`
	PolicyVersion string    `json:"policy_version"`
}

type EvidenceLink struct {
	Observation  string            `json:"observation"`
	Type         ObservationType   `json:"type"`
	Statement    string            `json:"statement"`
	Source       string            `json:"source"`
	Query        gateway.QueryMeta `json:"query"`
	Window       Window            `json:"window"`
	RetrievedAt  time.Time         `json:"retrieved_at"`
	Digest       string            `json:"digest"`
	Completeness Completeness      `json:"completeness"`
	// URL lets a human open the exact evidence in its source, when the
	// controller was told where that source is. It is attached after the
	// report is built, never by a model, and is absent in replay.
	URL string `json:"url,omitempty"`
}

// AttachLinks sets URL on every evidence link in the report, using link to
// build each from the link's own query and window. Links link returns ""
// for are left without one.
func (r *Report) AttachLinks(link func(EvidenceLink) string) {
	groups := [][]EvidenceLink{r.Supporting, r.Contradicting, r.InsufficientContext}
	for i := range r.Hypotheses {
		groups = append(groups, r.Hypotheses[i].Supporting, r.Hypotheses[i].Against, r.Hypotheses[i].Missing)
	}
	for _, g := range groups {
		for i := range g {
			g[i].URL = link(g[i])
		}
	}
}

type TimelineEntry struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
	Text   string    `json:"text"`
}

type HypothesisReport struct {
	Hypothesis   Hypothesis     `json:"hypothesis"`
	Supports     int            `json:"supports"`
	Contradicts  int            `json:"contradicts"`
	Insufficient int            `json:"insufficient_context"`
	Supporting   []EvidenceLink `json:"supporting,omitempty"`
	Against      []EvidenceLink `json:"contradicting,omitempty"`
	Missing      []EvidenceLink `json:"insufficient_evidence,omitempty"`
}

// Recommendation is always inert in this slice. The execution state is part of
// the report rather than a convention, so a reader never has to guess.
type Recommendation struct {
	Action    string `json:"action"`
	Rationale string `json:"rationale"`
	Executed  bool   `json:"executed"`
	Status    string `json:"status"`
}

// BuildReport turns the final state into a report. The leading claim is the best
// admissible hypothesis; when none is admissible the report says so instead of
// promoting the least bad one.
func BuildReport(env *StepEnvelope, policy ClaimPolicy, now time.Time) (Report, error) {
	byID := evidenceIndex(env.Observations)
	facts := BuildFacts(env.Incident.Service, env.Observations)
	if env.Run.Status != RunCompleted {
		return notConcluded(env, facts, byID), nil
	}

	candidates := make([]claimCandidate, 0, len(env.Hypotheses))
	for _, h := range env.Hypotheses {
		candidates = append(candidates, claimCandidate{
			hypothesis: h,
			verdict: policy.Evaluate(Claim{
				Kind:      h.ClaimKind,
				Subject:   env.Incident.Service,
				Statement: h.Statement,
				Evidence:  allObservationIDs(env.Observations),
			}, facts, byID),
		})
	}

	leading := chooseLeading(candidates, env.Relations)
	if leading == nil {
		v := policy.Evaluate(Claim{
			Kind:      ClaimUnknownCause,
			Subject:   env.Incident.Service,
			Statement: inconclusiveStatement(env),
			Evidence:  allObservationIDs(env.Observations),
		}, facts, byID)
		leading = &v
	}
	if leading.Claim.Kind == ClaimUnknownCause {
		// An inconclusive finding is a machine verdict, not something a model
		// asserted. Rendering the planner's candidate text here would let the
		// report present a cause it explicitly could not establish.
		leading.Claim.Statement = inconclusiveStatement(env)
	}

	report := Report{
		SchemaVersion: gateway.SchemaVersion,
		Incident:      env.Incident,
		Run:           env.Run,
		Timeline:      buildTimeline(env, byID),
		Leading:       claimReport(*leading, byID),
		Hypotheses:    hypothesisReports(env.Hypotheses, env.Relations, byID),
		Relations:     env.Relations,
		Decisions:     env.Decisions,
		Trace:         env.Trace,
		CoverageGaps:  facts.Gaps,
		Unresolved:    unresolved(env, leading, facts),
	}
	for _, c := range candidates {
		report.Claims = append(report.Claims, *claimReport(c.verdict, byID))
	}
	// A leading claim that no hypothesis proposed - the synthesized inconclusive
	// finding - still belongs in the list of claims considered, or the report
	// would present a conclusion it never shows its work for.
	alreadyListed := false
	for _, c := range candidates {
		if c.verdict.Claim.Kind == leading.Claim.Kind && c.verdict.Claim.Statement == leading.Claim.Statement {
			alreadyListed = true
			break
		}
	}
	if !alreadyListed {
		report.Claims = append(report.Claims, *claimReport(*leading, byID))
	}
	report.Derived = DeriveObservations(facts, byID)

	// The top-level evidence lists are scoped to the leading finding, because
	// "contradicting evidence" only means something relative to a specific
	// hypothesis. Every hypothesis keeps its own evidence beside it, so nothing
	// is hidden by that scoping.
	scope := leadingHypothesis(candidates, *leading)
	report.Supporting = linksFor(env.Relations, scope, Supports, byID)
	report.Contradicting = linksFor(env.Relations, scope, Contradicts, byID)
	report.InsufficientContext = linksFor(env.Relations, scope, InsufficientContext, byID)
	report.Arm, report.ArmVersion = armOf(env)
	report.EvaluatorCalls = env.EvaluatorCalls
	report.Impact = impactSummary(facts)
	report.Summary = summary(env, leading)
	report.Recommendation = recommend(env, *leading)
	_ = now
	return report, nil
}

// Validate is the traceability gate: a report that cites evidence it does not
// have, or attributes a relation to an unknown hypothesis, is not publishable.
func (r Report) Validate(obs map[string]Observation, hypotheses map[string]Hypothesis) error {
	ids := make([]string, 0, len(obs))
	for id := range obs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	check := func(where, id string) error {
		if _, ok := obs[id]; !ok {
			return fmt.Errorf("%s cites evidence %q which is not retained", where, id)
		}
		return nil
	}
	if r.Leading != nil {
		for _, id := range r.Leading.Evidence {
			if err := check("leading claim", id); err != nil {
				return err
			}
		}
	}
	for _, c := range r.Claims {
		for _, id := range c.Evidence {
			if err := check("claim "+string(c.Kind), id); err != nil {
				return err
			}
		}
	}
	for _, group := range [][]EvidenceLink{r.Supporting, r.Contradicting, r.InsufficientContext} {
		for _, l := range group {
			if err := check("evidence link", l.Observation); err != nil {
				return err
			}
		}
	}
	for _, d := range r.Derived {
		for _, parent := range d.Parents {
			if err := check("derived observation "+d.ID, parent); err != nil {
				return err
			}
		}
	}
	for _, rel := range r.Relations {
		if _, ok := hypotheses[rel.Hypothesis]; !ok {
			return fmt.Errorf("relation %s is attributed to unknown hypothesis %q", rel.ID, rel.Hypothesis)
		}
		if err := check("relation "+rel.ID, rel.Observation); err != nil {
			return err
		}
	}
	for _, t := range r.Timeline {
		if err := r.checkTimelineRef(t.Source, obs, hypotheses); err != nil {
			return err
		}
	}
	if r.Recommendation != nil && r.Recommendation.Executed {
		return fmt.Errorf("this slice never executes remediation")
	}
	return nil
}

// checkTimelineRef resolves a timeline reference by prefix. References are
// checked rather than trusted, so a timeline cannot point at evidence that was
// never retained.
func (r Report) checkTimelineRef(ref string, obs map[string]Observation, hypotheses map[string]Hypothesis) error {
	switch {
	case strings.HasPrefix(ref, PrefixObservation+"-"):
		if _, ok := obs[ref]; !ok {
			return fmt.Errorf("timeline entry cites unretained evidence %q", ref)
		}
		return nil
	case strings.HasPrefix(ref, PrefixHypothesis+"-"):
		if _, ok := hypotheses[ref]; !ok {
			return fmt.Errorf("timeline entry cites unknown hypothesis %q", ref)
		}
		return nil
	case strings.HasPrefix(ref, PrefixDerived+"-"):
		for _, d := range r.Derived {
			if d.ID == ref {
				return nil
			}
		}
		return fmt.Errorf("timeline entry cites unknown derived observation %q", ref)
	case strings.HasPrefix(ref, PrefixDecision+"-"):
		for _, d := range r.Decisions {
			if d.ID == ref {
				return nil
			}
		}
		return fmt.Errorf("timeline entry cites unknown decision %q", ref)
	default:
		return fmt.Errorf("timeline entry cites unrecognised reference %q", ref)
	}
}

func claimReport(v ClaimVerdict, byID map[string]Observation) *ClaimReport {
	c := &ClaimReport{
		Kind:          v.Claim.Kind,
		Statement:     v.Claim.Statement,
		Allowed:       v.Allowed,
		Overclaim:     v.Overclaim,
		Reasons:       v.Reasons,
		Narrowed:      v.Narrowed,
		Evidence:      v.Claim.Evidence,
		PolicyVersion: v.PolicyVersion,
	}
	return c
}

// claimCandidate is a hypothesis together with the verdict on the claim it makes.
type claimCandidate struct {
	hypothesis Hypothesis
	verdict    ClaimVerdict
}

// chooseLeading picks the best admissible claim among the hypotheses the planner
// proposed. Ranking is by supporting evidence, then by the absence of
// contradicting evidence, then by proposal order, so the choice is reproducible
// and never depends on map iteration.
func chooseLeading(candidates []claimCandidate, relations []Relation) *ClaimVerdict {
	var best *claimCandidate
	var bestSupports, bestContradicts int
	for _, c := range candidates {
		if !c.verdict.Allowed || c.verdict.Overclaim {
			continue
		}
		supports, contradicts := countRelations(c.hypothesis.ID, relations)
		if best == nil || supports > bestSupports ||
			(supports == bestSupports && contradicts < bestContradicts) {
			copied := c
			best = &copied
			bestSupports, bestContradicts = supports, contradicts
		}
	}
	if best == nil {
		return nil
	}
	return &best.verdict
}

func countRelations(hypothesisID string, relations []Relation) (supports, contradicts int) {
	for _, rel := range relations {
		if rel.Hypothesis != hypothesisID {
			continue
		}
		switch rel.Relationship {
		case Supports:
			supports++
		case Contradicts:
			contradicts++
		}
	}
	return supports, contradicts
}

// leadingHypothesis finds the hypothesis the leading claim came from. A
// synthesized inconclusive claim has no hypothesis, and in that case every
// hypothesis's evidence is shown, because ruling the candidates out is the
// finding.
func leadingHypothesis(candidates []claimCandidate, leading ClaimVerdict) string {
	for _, c := range candidates {
		if c.verdict.Claim.Kind == leading.Claim.Kind && c.verdict.Claim.Statement == leading.Claim.Statement {
			return c.hypothesis.ID
		}
	}
	return ""
}

func linksFor(relations []Relation, hypothesis string, want Relationship, byID map[string]Observation) []EvidenceLink {
	seen := map[string]bool{}
	var out []EvidenceLink
	for _, r := range relations {
		if r.Relationship != want || seen[r.Observation] {
			continue
		}
		if hypothesis != "" && r.Hypothesis != hypothesis {
			continue
		}
		o, ok := byID[r.Observation]
		if !ok {
			continue
		}
		seen[r.Observation] = true
		out = append(out, link(o))
	}
	return out
}

func link(o Observation) EvidenceLink {
	return EvidenceLink{
		Observation:  o.ID,
		Type:         o.Type,
		Statement:    o.Statement,
		Source:       o.Source,
		Query:        o.Query,
		Window:       o.Window,
		RetrievedAt:  o.RetrievedAt,
		Digest:       o.Digest,
		Completeness: o.Completeness,
	}
}

func hypothesisReports(hypotheses []Hypothesis, relations []Relation, byID map[string]Observation) []HypothesisReport {
	out := make([]HypothesisReport, 0, len(hypotheses))
	for _, h := range hypotheses {
		hr := HypothesisReport{
			Hypothesis: h,
			Supporting: linksFor(relations, h.ID, Supports, byID),
			Against:    linksFor(relations, h.ID, Contradicts, byID),
			Missing:    linksFor(relations, h.ID, InsufficientContext, byID),
		}
		hr.Supports = len(hr.Supporting)
		hr.Contradicts = len(hr.Against)
		hr.Insufficient = len(hr.Missing)
		out = append(out, hr)
	}
	return out
}

func buildTimeline(env *StepEnvelope, byID map[string]Observation) []TimelineEntry {
	var entries []TimelineEntry
	for _, o := range env.Observations {
		entries = append(entries, TimelineEntry{
			At:     o.RetrievedAt,
			Source: o.ID,
			Text:   o.Statement,
		})
	}
	for _, d := range env.Decisions {
		entries = append(entries, TimelineEntry{At: d.At, Source: d.ID, Text: string(d.Outcome) + ": " + d.Reason})
	}
	for _, o := range env.Observations {
		if term, ok := terminatedAt(o); ok {
			entries = append(entries, TimelineEntry{
				At:     term,
				Source: o.ID,
				Text:   "container termination recorded",
			})
		}
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].At.Before(entries[j].At) })
	return entries
}

func terminatedAt(o Observation) (time.Time, bool) {
	if o.Action != gateway.ActionKubernetesContainers {
		return time.Time{}, false
	}
	pods, err := gateway.Response{Status: gateway.StatusOK, Payload: o.Payload}.Pods()
	if err != nil {
		return time.Time{}, false
	}
	for _, p := range pods.Pods {
		for _, c := range p.Containers {
			if c.LastTerminatedAt != nil {
				return c.LastTerminatedAt.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

// armOf names the evaluator that produced the relations, preferring the recorded
// calls because they survive even when no relation was produced.
func armOf(env *StepEnvelope) (string, string) {
	if len(env.EvaluatorCalls) > 0 {
		return env.EvaluatorCalls[0].Arm, env.EvaluatorCalls[0].ArmVersion
	}
	for _, r := range env.Relations {
		return string(r.Evaluator), r.PolicyVersion
	}
	return DeterministicArm, RelationPolicyVersion
}

func inconclusiveStatement(env *StepEnvelope) string {
	return "the retained evidence does not establish a cause for the reported symptom (" + env.Incident.Symptom + ")"
}

func impactSummary(f Facts) string {
	var parts []string
	if st, err := Summarize(f.LatencySamples()); err == nil {
		parts = append(parts, fmt.Sprintf("p99 latency peaked at %s (baseline %s, %sx)",
			FormatFloat(st.Max, 3), FormatFloat(st.First, 3), FormatFloat(st.Ratio(), 2)))
	}
	if count, ok := f.RestartCount(); ok && count > 0 {
		parts = append(parts, fmt.Sprintf("the container restarted %d times", count))
	}
	if st, err := Summarize(f.MemorySamples()); err == nil {
		peak := fmt.Sprintf("working set peaked at %s", FormatBytes(st.Max))
		if limit, ok := f.MemoryLimit(); ok && limit.Value > 0 {
			peak += fmt.Sprintf(", %s%% of the %s limit", FormatFloat(st.Max/limit.Value*100, 0), FormatBytes(limit.Value))
		}
		parts = append(parts, peak)
	}
	return strings.Join(parts, "; ")
}

func summary(env *StepEnvelope, leading *ClaimVerdict) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s reported: %s\n", env.Incident.Environment, env.Incident.Symptom)
	if leading.Allowed {
		fmt.Fprintf(&b, "Leading finding (%s): %s\n", leading.Claim.Kind, leading.Claim.Statement)
		if leading.Narrowed != "" {
			fmt.Fprintf(&b, "Scope: %s\n", leading.Narrowed)
		}
	} else {
		fmt.Fprintf(&b, "No admissible finding. %s\n", leading.Narrowed)
	}
	return b.String()
}

// recommend proposes at most a next investigation step, never an executed
// change. The plan is explicit that increasing a memory limit is not a safe
// automatic response to limit exhaustion.
func recommend(env *StepEnvelope, leading ClaimVerdict) *Recommendation {
	if !AllowRemediation(leading) {
		return nil
	}
	switch leading.Claim.Kind {
	case ClaimMemoryLimitTermination:
		return &Recommendation{
			Action:    fmt.Sprintf("Identify what drove %s to its memory limit before changing the limit", env.Incident.Service),
			Rationale: "the container is evidenced as killed at its limit, which establishes the mechanism of the restart but not why the working set reached it; raising the limit without that would move the failure rather than remove it",
			Status:    "not executed: this slice is read-only and requires human approval",
		}
	case ClaimNonMemoryRestart:
		return &Recommendation{
			Action:    fmt.Sprintf("Review the probe configuration and the health endpoint of %s", env.Incident.Service),
			Rationale: "the container terminates with an application error while its liveness probe keeps failing, so the two are investigated together",
			Status:    "not executed: this slice is read-only and requires human approval",
		}
	default:
		return nil
	}
}

func unresolved(env *StepEnvelope, leading *ClaimVerdict, facts Facts) []string {
	var out []string
	if !leading.Allowed {
		out = append(out, "the terminating cause is not established by the retained evidence")
	}
	if leading.Overclaim {
		out = append(out, "an overclaiming assertion was refused: "+strings.Join(leading.Reasons, "; "))
	}
	return dedupe(append(out, missingEvidence(facts)...))
}

func missingEvidence(facts Facts) []string {
	var out []string
	for _, g := range facts.Gaps {
		out = append(out, "missing evidence: "+g.String())
	}
	if _, ok := facts.MemoryLimit(); !ok && len(facts.Memory) > 0 {
		out = append(out, "the configured memory limit was not collected for this service")
	}
	if _, ok := facts.LatestRollout(); !ok && len(facts.Rollouts) == 0 {
		out = append(out, "no rollout evidence was collected for this service in the window")
	}
	return out
}

// notConcluded is the report of a run that stopped before it concluded: failed,
// or out of budget. It is built by code from the state alone, so a stalled
// planner or a lost model still leaves a readable record.
//
// It records what was gathered and states no finding. The claims are not
// evaluated at all: a verdict on partial evidence reads as a conclusion
// whatever it is labelled, and "admissible so far" is exactly the kind of
// statement this repository exists to refuse. Every hypothesis still shows the
// evidence labelled against it.
func notConcluded(env *StepEnvelope, facts Facts, byID map[string]Observation) Report {
	report := Report{
		SchemaVersion: gateway.SchemaVersion,
		Incident:      env.Incident,
		Run:           env.Run,
		Timeline:      buildTimeline(env, byID),
		Claims:        []ClaimReport{},
		Hypotheses:    hypothesisReports(env.Hypotheses, env.Relations, byID),
		Relations:     env.Relations,
		Decisions:     env.Decisions,
		Trace:         env.Trace,
		CoverageGaps:  facts.Gaps,
		Derived:       DeriveObservations(facts, byID),
		Impact:        impactSummary(facts),
	}
	report.Arm, report.ArmVersion = armOf(env)
	report.EvaluatorCalls = env.EvaluatorCalls
	stopped := fmt.Sprintf("the investigation did not conclude: it ended as %s (%s)", env.Run.Status, env.Run.Reason)
	report.Summary = fmt.Sprintf("%s reported: %s\nNot concluded. The run ended as %s: %s. No finding is drawn from partial evidence.\n",
		env.Incident.Environment, env.Incident.Symptom, env.Run.Status, env.Run.Reason)
	report.Unresolved = dedupe(append([]string{stopped}, missingEvidence(facts)...))
	return report
}

// Concluded reports whether the run reached a conclusion. A report that did not
// carries no leading claim and no recommendation, and must not be read as a
// finding.
func (r Report) Concluded() bool {
	return r.Run.Status == RunCompleted
}

func allObservationIDs(obs []Observation) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.ID)
	}
	sort.Strings(out)
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
