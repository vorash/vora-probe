package investigation

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
)

// Engine is the transition function of an investigation. It performs no I/O: it
// consumes the state envelope and one pending result, and returns exactly one
// request or the final report. Everything it needs to be reproducible is in the
// envelope, including the ID counters, which is why the same code runs
// in-process for replay and, later, invoked once per step inside a
// network-denied sandbox.
type Engine struct {
	Policy gateway.Policy
	Claims ClaimPolicy
	Now    func() time.Time
}

// state carries the envelope and its ID counters together, so that every exit
// path publishes a consistent snapshot.
type state struct {
	env StepEnvelope
	ids *IDGen
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
			return e.finish(s, RunFailed, err.Error())
		}
		consumed = "infra"
	case input.Pending.Kind == PendingModel:
		done, pending, err := e.consumeModel(s, input.Pending)
		if err != nil {
			return StepResult{}, err
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
			return e.finish(s, RunFailed, err.Error())
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
		return e.finish(s, RunFailed, err.Error())
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
	e.reassess(s)
	return nil
}

// reassess recomputes facts and relations for the whole run. Recomputing rather
// than appending keeps the relation set a pure function of the evidence.
func (e *Engine) reassess(s *state) {
	byID := make(map[string]Observation, len(s.env.Observations))
	for _, o := range s.env.Observations {
		byID[o.ID] = o
	}
	facts := BuildFacts(s.env.Incident.Service, s.env.Observations)

	s.env.Relations = nil
	for _, h := range s.env.Hypotheses {
		s.env.Relations = append(s.env.Relations, EvaluateRelations(s.ids, h, facts, byID, e.Claims, e.now())...)
	}
	for i := range s.env.Hypotheses {
		s.env.Hypotheses[i].Status = statusFor(s.env.Hypotheses[i], s.env.Relations)
	}
}

// consumeModel validates a planner turn and folds it into the state. It returns
// the action the planner chose, and whether the investigation is finished.
func (e *Engine) consumeModel(s *state, pending *Pending) (bool, *gateway.Action, error) {
	response := pending.Model
	s.env.ModelAttempts++

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
			// Keeping the existing ID is what lets relations survive a revision.
			s.env.Hypotheses[i].Statement = spec.Statement
			s.env.Hypotheses[i].FaultDomain = spec.FaultDomain
			s.env.Hypotheses[i].ClaimKind = spec.ClaimKind
			s.env.Hypotheses[i].EvidenceNeeded = spec.EvidenceNeeded
			continue
		}
		s.env.Hypotheses = append(s.env.Hypotheses, HypothesisFromSpec(s.ids, spec))
	}
	e.reassess(s)

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

// fit keeps the worker state inside its byte budget. A payload that does not fit
// is dropped and the observation is marked truncated, so oversize input shows up
// as a coverage limitation rather than as evidence.
func (e *Engine) fit(env *StepEnvelope) error {
	max := env.Run.Budgets.MaxEnvelopeBytes
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
			return fmt.Errorf("worker state of %d bytes exceeds the %d byte budget with no payload left to drop", len(raw), max)
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

// finish closes the run without a report. A run that ends this way is never
// presented as a completed investigation.
func (e *Engine) finish(s *state, status RunStatus, reason string) (StepResult, error) {
	ended := e.now()
	s.env.Run.Status = status
	s.env.Run.Reason = reason
	s.env.Run.EndedAt = &ended
	return s.result(ResultFinal, reason), nil
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
