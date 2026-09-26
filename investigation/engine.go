package investigation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// errBudgetExhausted ends the run without failing it: running out of budget is an
// outcome, and the report says so rather than presenting a partial investigation
// as a conclusion.
var errBudgetExhausted = errors.New("model call budget exhausted while evaluating evidence")

// Engine is the transition function of an investigation. It performs no I/O: it
// consumes the state envelope and one pending result, and returns exactly one
// request or the final report. Everything it needs to be reproducible is in the
// envelope, including the ID counters, which is why the same code runs
// in-process for replay and, later, invoked once per step inside a
// network-denied sandbox.
type Engine struct {
	Policy gateway.Policy
	Claims ClaimPolicy
	// Relations is the arm that labels evidence against hypotheses. It defaults
	// to the deterministic rules, so a caller that does not choose an arm gets
	// the reviewed one.
	Relations RelationEvaluator
	Now       func() time.Time
}

func (e *Engine) relations() RelationEvaluator {
	if e.Relations != nil {
		return e.Relations
	}
	return DeterministicEvaluator{Policy: e.Claims}
}

// state carries the envelope and its ID counters together, so that every exit
// path publishes a consistent snapshot.
type state struct {
	env StepEnvelope
	ids *IDGen
	// stale holds hypotheses the planner revised in this step. Their evidence
	// labels are no longer answers to the current question, so they are dropped
	// rather than kept.
	stale map[string]bool
}

func (s *state) markStale(hypothesisID string) {
	if s.stale == nil {
		s.stale = map[string]bool{}
	}
	s.stale[hypothesisID] = true
}

func (s *state) result(kind, reason string) StepResult {
	s.env.Counters = s.ids.Snapshot()
	return StepResult{
		SchemaVersion: gateway.SchemaVersion,
		Step:          s.env.Step,
		Kind:          kind,
		Reason:        reason,
		Run:           s.env.Run,
		Envelope:      s.env,
	}
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// Step advances the investigation by one transition.
func (e *Engine) Step(input WorkerInput) (StepResult, error) {
	env := input.State
	if env.SchemaVersion == "" {
		env.SchemaVersion = gateway.SchemaVersion
	}
	if err := env.Validate(env.Run.Budgets.MaxEnvelopeBytes); err != nil {
		return StepResult{}, err
	}
	if input.Pending != nil {
		if err := input.Pending.Validate(); err != nil {
			return StepResult{}, err
		}
	}
	s := &state{env: env, ids: NewIDGenFrom(env.Counters)}
	now := e.now()
	s.env.Step++
	s.env.Run.Used.Steps = s.env.Step

	consumed := ""
	var action *gateway.Action
	switch {
	case input.Pending == nil:
	case input.Pending.Kind == PendingInfra:
		if err := e.consumeInfra(s, input.Pending); err != nil {
			if errors.Is(err, errBudgetExhausted) {
				return e.finish(s, RunBudgetExhausted, err.Error())
			}
			return e.finish(s, RunFailed, err.Error())
		}
		consumed = "infra"
	case input.Pending.Kind == PendingModel:
		done, pending, err := e.consumeModel(s, input.Pending)
		if err != nil {
			if errors.Is(err, errBudgetExhausted) {
				return e.finish(s, RunBudgetExhausted, err.Error())
			}
			// Ended as a failed run, not a worker error: an error leaves the
			// controller nothing to record, and a twice-rejected planner is an
			// outcome of the run, with the escalation that explains it.
			return e.finish(s, RunFailed, err.Error())
		}
		if done {
			return e.finalReport(s, now)
		}
		action = pending
		consumed = "model"
	}

	if reason := e.exhausted(&s.env, now); reason != "" {
		return e.finish(s, RunBudgetExhausted, reason)
	}

	if action != nil {
		// A planner turn that named an action: ask the infrastructure for it.
		if err := e.Policy.Authorize(*action); err != nil {
			e.decide(s, OutcomeEscalate, "request refused before execution: "+err.Error(), "")
			return e.finish(s, RunFailed, err.Error())
		}
		s.env.Run.Used.InfraCalls++
		if err := e.fit(&s.env); err != nil {
			return e.finish(s, RunBudgetExhausted, err.Error())
		}
		result := s.result(ResultInfraRequest, "requesting "+action.String())
		result.InfraRequest = action
		return result, nil
	}

	phase := PhaseReassess
	if len(s.env.Hypotheses) == 0 {
		phase = PhasePlan
	}
	note := s.env.Note
	s.env.Phase = phase
	s.env.Note = ""
	s.env.Run.Used.ModelCalls++
	if err := e.fit(&s.env); err != nil {
		return e.finish(s, RunBudgetExhausted, err.Error())
	}
	reason := describePhase(phase, consumed)
	if note != "" {
		reason = note
	}
	result := s.result(ResultModelRequest, reason)
	result.ModelRequest = e.modelRequest(&s.env, phase, note)
	return result, nil
}

// consumeInfra normalizes one answer, re-derives the numeric observations the
// report will cite, and evaluates every hypothesis against the new evidence.
func (e *Engine) consumeInfra(s *state, pending *Pending) error {
	if err := e.Policy.Authorize(*pending.Action); err != nil {
		e.decide(s, OutcomeEscalate, "answer arrived for a request that policy refuses: "+err.Error(), "")
		return err
	}
	redacted := gateway.RedactResponse(*pending.Response)
	retrieved := redacted.RetrievedAt
	if retrieved.IsZero() {
		retrieved = e.now()
	}
	obs, err := ObservationFromResponse(s.ids.Next(PrefixObservation), *pending.Action, redacted, retrieved)
	if err != nil {
		e.decide(s, OutcomeContinue, "answer could not be normalized into evidence: "+err.Error(), "")
		return nil
	}
	s.env.Observations = append(s.env.Observations, obs)
	return e.reassess(s)
}

// reassess recomputes facts and relations for the whole run. Recomputing rather
// than appending keeps the relation set a pure function of the evidence.
//
// An arm that fails fails the run. Substituting another arm, or dropping the
// relations and continuing, would turn "this arm did not work" into a result that
// looks like a finding.
func (e *Engine) reassess(s *state) error {
	byID := make(map[string]Observation, len(s.env.Observations))
	for _, o := range s.env.Observations {
		byID[o.ID] = o
	}
	facts := BuildFacts(s.env.Incident.Service, s.env.Observations)
	arm := e.relations()

	// Keep the labels that still answer the current question: same arm, same
	// version, hypothesis still live and unrevised, evidence still retained.
	// Everything else is re-asked. Re-labelling evidence that is already
	// labelled would multiply a model arm's cost by the number of reassessments.
	//
	// The deterministic arm keeps nothing. Its rules read the whole body of
	// evidence, so a label can go stale when other evidence arrives: a working
	// set labelled "no configured limit to compare against" is wrong once the
	// limit is retained. It is free to re-ask, so it always is.
	fresh := arm.Arm() == DeterministicArm
	alive := make(map[string]bool, len(s.env.Hypotheses))
	for _, h := range s.env.Hypotheses {
		alive[h.ID] = true
	}
	kept := make([]Relation, 0, len(s.env.Relations))
	labelled := map[string]map[string]bool{}
	for _, r := range s.env.Relations {
		if _, ok := byID[r.Observation]; !ok {
			continue
		}
		if fresh || !alive[r.Hypothesis] || s.stale[r.Hypothesis] {
			continue
		}
		if string(r.Evaluator) != arm.Arm() || r.PolicyVersion != arm.ArmVersion() {
			continue
		}
		kept = append(kept, r)
		if labelled[r.Hypothesis] == nil {
			labelled[r.Hypothesis] = map[string]bool{}
		}
		labelled[r.Hypothesis][r.Observation] = true
	}
	s.env.Relations = kept
	s.stale = nil

	for _, h := range s.env.Hypotheses {
		pending := make(map[string]Observation)
		for id, o := range byID {
			if !labelled[h.ID][id] {
				pending[id] = o
			}
		}
		if len(pending) == 0 {
			continue
		}
		drafts, calls, err := arm.Label(h, facts, pending)
		for _, call := range calls {
			if call.Remote {
				s.env.Run.Used.ModelCalls++
			}
		}
		s.env.EvaluatorCalls = append(s.env.EvaluatorCalls, calls...)
		if err != nil {
			return fmt.Errorf("%s arm failed on %s: %w", arm.Arm(), h.ID, err)
		}
		if s.env.Run.Used.ModelCalls > s.env.Run.Budgets.MaxModelCalls {
			return fmt.Errorf("%w: %d of %d used", errBudgetExhausted,
				s.env.Run.Used.ModelCalls, s.env.Run.Budgets.MaxModelCalls)
		}
		for _, d := range drafts {
			if _, ok := byID[d.Observation]; !ok {
				return fmt.Errorf("%s arm labelled %q, which is not retained evidence", arm.Arm(), d.Observation)
			}
			s.env.Relations = append(s.env.Relations, Relation{
				SchemaVersion: gateway.SchemaVersion,
				ID:            s.ids.Next(PrefixRelation),
				Observation:   d.Observation,
				Hypothesis:    h.ID,
				Relationship:  d.Relationship,
				Reason:        d.Reason,
				Evaluator:     Evaluator(arm.Arm()),
				PolicyVersion: arm.ArmVersion(),
			})
		}
	}
	for i := range s.env.Hypotheses {
		s.env.Hypotheses[i].Status = statusFor(s.env.Hypotheses[i], s.env.Relations)
	}
	return nil
}

// consumeModel validates a planner turn and folds it into the state. It returns
// the action the planner chose, and whether the investigation is finished.
func (e *Engine) consumeModel(s *state, pending *Pending) (bool, *gateway.Action, error) {
	response := pending.Model
	s.env.ModelAttempts++
	// A reply that took fallbacks cost more than one call. The first was
	// charged when the request was issued; the rest are charged here, so a
	// fallback is never free and can never loop past the budget.
	if response.Attempts > 1 {
		s.env.Run.Used.ModelCalls += response.Attempts - 1
	}

	if err := response.Validate(s.env.Phase); err != nil {
		if s.env.ModelAttempts < 2 {
			s.env.Note = "previous planner response was rejected: " + err.Error()
			e.decide(s, OutcomeContinue, "planner response rejected, retrying once: "+err.Error(), "")
			return false, nil, nil
		}
		e.decide(s, OutcomeEscalate, "planner response rejected twice: "+err.Error(), "")
		return false, nil, fmt.Errorf("planner response rejected twice: %w", err)
	}
	s.env.ModelAttempts = 0

	for i, spec := range response.Hypotheses {
		if i < len(s.env.Hypotheses) {
			existing := s.env.Hypotheses[i]
			if existing.ClaimKind != spec.ClaimKind || existing.FaultDomain != spec.FaultDomain {
				// The question changed, so the old labels are answers to a
				// different question and must not be carried over.
				s.markStale(existing.ID)
			}
			// Keeping the existing ID is what lets relations survive a revision.
			s.env.Hypotheses[i].Statement = spec.Statement
			s.env.Hypotheses[i].FaultDomain = spec.FaultDomain
			s.env.Hypotheses[i].ClaimKind = spec.ClaimKind
			s.env.Hypotheses[i].EvidenceNeeded = spec.EvidenceNeeded
			continue
		}
		s.env.Hypotheses = append(s.env.Hypotheses, HypothesisFromSpec(s.ids, spec))
	}
	if err := e.reassess(s); err != nil {
		return false, nil, err
	}

	if response.NextAction == nil {
		e.decide(s, OutcomeStop, response.Reason, "")
		return true, nil, nil
	}
	e.decide(s, OutcomeContinue, response.Reason, "")
	return false, response.NextAction, nil
}

func (e *Engine) exhausted(env *StepEnvelope, now time.Time) string {
	run := env.Run
	switch {
	case run.Used.InfraCalls >= run.Budgets.MaxInfraCalls:
		return fmt.Sprintf("infrastructure call budget of %d exhausted", run.Budgets.MaxInfraCalls)
	case run.Used.ModelCalls >= run.Budgets.MaxModelCalls:
		return fmt.Sprintf("model call budget of %d exhausted", run.Budgets.MaxModelCalls)
	case env.Step > run.Budgets.MaxSteps:
		return fmt.Sprintf("step budget of %d exhausted", run.Budgets.MaxSteps)
	case now.Sub(run.Used.StartedAt) > time.Duration(run.Budgets.MaxDurationSeconds)*time.Second:
		return fmt.Sprintf("wall clock budget of %ds exhausted", run.Budgets.MaxDurationSeconds)
	}
	return ""
}

// controllerReserveBytes is room left in the state for what the controller
// appends after a step and before the next one: the call record for the request
// it just executed. Without it a state fitted to the byte would come back one
// record too large, and the worker would refuse its own next input.
const controllerReserveBytes = 2 << 10

// fit keeps the worker state inside its byte budget. A payload that does not fit
// is dropped and the observation is marked truncated, so oversize input shows up
// as a coverage limitation rather than as evidence. When dropping payloads is
// not enough, the state budget is exhausted like any other budget, and the run
// ends with a report that says so.
func (e *Engine) fit(env *StepEnvelope) error {
	max := env.Run.Budgets.MaxEnvelopeBytes - controllerReserveBytes
	for {
		raw, err := json.Marshal(*env)
		if err != nil {
			return fmt.Errorf("worker state is not serializable: %w", err)
		}
		if int64(len(raw)) <= max {
			return nil
		}
		idx, biggest := -1, 0
		for i, o := range env.Observations {
			if len(o.Payload) > biggest {
				biggest, idx = len(o.Payload), i
			}
		}
		if idx < 0 {
			return fmt.Errorf("worker state budget exhausted: %d bytes with no payload left to drop, over the %d byte budget less %d reserved for the controller",
				len(raw), env.Run.Budgets.MaxEnvelopeBytes, controllerReserveBytes)
		}
		env.Observations[idx].Payload = nil
		env.Observations[idx].Completeness = Truncated
		if !strings.Contains(env.Observations[idx].Statement, "payload omitted") {
			env.Observations[idx].Statement += " (payload omitted: it did not fit the worker state budget)"
		}
	}
}

func (e *Engine) modelRequest(env *StepEnvelope, phase, retryNote string) *ModelRequest {
	summaries := make([]ObservationSummary, 0, len(env.Observations))
	for _, o := range env.Observations {
		summaries = append(summaries, o.Summary())
	}
	remaining := env.Run.Budgets.MaxDurationSeconds - int(e.now().Sub(env.Run.Used.StartedAt).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	return &ModelRequest{
		SchemaVersion:  gateway.SchemaVersion,
		Phase:          phase,
		Incident:       env.Incident,
		Step:           env.Step,
		Hypotheses:     env.Hypotheses,
		Observations:   summaries,
		Relations:      env.Relations,
		AllowedActions: gateway.AllowedActions,
		AllowedMetrics: gateway.AllowedMetrics,
		Budget: BudgetsLeft{
			ModelCallsRemaining: env.Run.Budgets.MaxModelCalls - env.Run.Used.ModelCalls,
			InfraCallsRemaining: env.Run.Budgets.MaxInfraCalls - env.Run.Used.InfraCalls,
			SecondsRemaining:    remaining,
		},
		RetryNote: retryNote,
	}
}

func (e *Engine) decide(s *state, outcome Outcome, reason, hypothesis string) Decision {
	d := Decision{
		SchemaVersion: gateway.SchemaVersion,
		ID:            s.ids.Next(PrefixDecision),
		At:            e.now(),
		Step:          s.env.Step,
		Outcome:       outcome,
		Reason:        reason,
		Hypothesis:    hypothesis,
		PolicyVersion: ClaimPolicyVersion,
	}
	s.env.Decisions = append(s.env.Decisions, d)
	return d
}

// Abandon closes a run the controller could not continue: the planner stalled
// past the deadline, the gateway refused, or the worker failed. It works from
// the last state the controller holds, records why as an escalation, and
// publishes the same report a run that ended itself would, one that does not
// conclude. Without it, exactly the runs an operator most needs to read
// would leave nothing but a journal.
func (e *Engine) Abandon(env StepEnvelope, status RunStatus, reason string) (StepResult, error) {
	if status != RunFailed && status != RunBudgetExhausted {
		return StepResult{}, fmt.Errorf("a run can only be abandoned as %s or %s, not %q", RunFailed, RunBudgetExhausted, status)
	}
	s := &state{env: env, ids: NewIDGenFrom(env.Counters)}
	e.decide(s, OutcomeEscalate, "the controller could not continue the run: "+reason, "")
	return e.finish(s, status, reason)
}

// finish closes a run that did not conclude. It still publishes a report, built
// by code from the state, because a run that stops is exactly the one an
// operator has to read; the report states no finding, so it is never presented
// as a completed investigation.
func (e *Engine) finish(s *state, status RunStatus, reason string) (StepResult, error) {
	ended := e.now()
	s.env.Run.Status = status
	s.env.Run.Reason = reason
	s.env.Run.EndedAt = &ended
	report, err := BuildReport(&s.env, e.Claims, ended)
	if err != nil {
		return StepResult{}, err
	}
	if err := report.Validate(evidenceIndex(s.env.Observations), hypothesisIndex(s.env.Hypotheses)); err != nil {
		return StepResult{}, err
	}
	result := s.result(ResultFinal, reason)
	result.Report = &report
	return result, nil
}

func (e *Engine) finalReport(s *state, now time.Time) (StepResult, error) {
	ended := now
	s.env.Run.Status = RunCompleted
	s.env.Run.EndedAt = &ended
	report, err := BuildReport(&s.env, e.Claims, now)
	if err != nil {
		return StepResult{}, err
	}
	if err := report.Validate(evidenceIndex(s.env.Observations), hypothesisIndex(s.env.Hypotheses)); err != nil {
		return StepResult{}, err
	}
	result := s.result(ResultFinal, "investigation complete")
	result.Report = &report
	return result, nil
}

func describePhase(phase, consumed string) string {
	if phase == PhasePlan {
		return "no hypotheses yet: asking the planner for competing hypotheses and a first evidence request"
	}
	return "evidence returned: asking the planner to reassess and choose the next request (" + consumed + " turn)"
}

func statusFor(h Hypothesis, relations []Relation) HypothesisStatus {
	supports, contradicts := countRelations(h.ID, relations)
	context := 0
	for _, r := range relations {
		if r.Hypothesis == h.ID && r.Relationship == InsufficientContext {
			context++
		}
	}
	switch {
	case supports > 0 && contradicts == 0:
		return HypothesisSupported
	case contradicts > 0 && supports == 0:
		return HypothesisRefuted
	case supports == 0 && contradicts == 0 && context == 0:
		return HypothesisProposed
	default:
		return HypothesisUnresolved
	}
}

func evidenceIndex(obs []Observation) map[string]Observation {
	out := make(map[string]Observation, len(obs))
	for _, o := range obs {
		out[o.ID] = o
	}
	return out
}

func hypothesisIndex(hs []Hypothesis) map[string]Hypothesis {
	out := make(map[string]Hypothesis, len(hs))
	for _, h := range hs {
		out[h.ID] = h
	}
	return out
}
