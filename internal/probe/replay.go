// Package probe wires the offline vertical slice together: a frozen fixture, the
// recorded planner, the fixture gateway, the bounded step worker and the
// journal.
//
// Nothing in this package is special-cased for replay. The loop is the same loop
// that will run against a live gateway; only the two ports differ. That is the
// property worth having, because it is what makes the offline result evidence
// about the engine rather than about a mock.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/models"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/internal/worker"
	"github.com/vorash/vora-probe/test/fixtures"
)

type ReplayOptions struct {
	BundleDir string
	// OutDir holds the journal and artifacts. It is owner-readable and ignored
	// by git: live artifacts are never a source of truth.
	OutDir   string
	Attempt  int
	Budget   investigation.Budgets
	Engine   *investigation.Engine
	MaxSteps int
}

type ReplayResult struct {
	Report             investigation.Report
	JournalPath        string
	ReportJSONPath     string
	ReportMarkdownPath string
	PlannerTurns       int
	InfraCalls         int
	Steps              int
}

// Replay runs one investigation to completion against a frozen fixture.
func Replay(ctx context.Context, opts ReplayOptions) (ReplayResult, error) {
	if opts.OutDir == "" {
		opts.OutDir = ".probe"
	}
	if opts.Attempt <= 0 {
		opts.Attempt = 1
	}
	budget := opts.Budget
	if budget.MaxSteps == 0 {
		budget = investigation.DefaultBudgets()
	}
	engine := opts.Engine
	if engine == nil {
		engine = &investigation.Engine{Policy: gateway.DefaultPolicy(), Claims: investigation.DefaultClaimPolicy()}
	}

	bundle, err := fixtures.Load(opts.BundleDir)
	if err != nil {
		return ReplayResult{}, err
	}
	if err := fixtures.Verify(bundle); err != nil {
		return ReplayResult{}, fmt.Errorf("%s: %w", opts.BundleDir, err)
	}

	clock := newClock(latestRetrieval(bundle))
	engine.Now = clock.now
	planner := models.NewRecordedPlanner(plannerTurns(bundle))
	gw, err := gateway.NewFixtureGateway(engine.Policy, bundle.Evidence, clock.now)
	if err != nil {
		return ReplayResult{}, err
	}

	lock, err := store.AcquireLock(opts.OutDir, "probe")
	if err != nil {
		return ReplayResult{}, err
	}
	defer lock.Release()

	runID := fmt.Sprintf("RUN-%s-%03d", bundle.Incident.ID, opts.Attempt)
	runDir := filepath.Join(opts.OutDir, runID)
	journal, err := store.OpenJournal(runDir, runID)
	if err != nil {
		return ReplayResult{}, err
	}
	defer journal.Close()

	run := investigation.Run{
		SchemaVersion: gateway.SchemaVersion,
		ID:            runID,
		IncidentID:    bundle.Incident.ID,
		Attempt:       opts.Attempt,
		StartedAt:     clock.now(),
		Status:        investigation.RunActive,
		Budgets:       budget,
		Used:          investigation.BudgetState{StartedAt: clock.now()},
	}
	if err := journal.Append(store.Event{
		RunID: runID, IncidentID: bundle.Incident.ID, Kind: store.EventRunStarted,
		At: run.StartedAt, Payload: mustJSON(bundle.Incident),
	}); err != nil {
		return ReplayResult{}, err
	}

	env := investigation.StepEnvelope{
		SchemaVersion: gateway.SchemaVersion,
		Incident:      bundle.Incident,
		Run:           run,
	}

	maxSteps := opts.MaxSteps
	if maxSteps == 0 {
		maxSteps = budget.MaxSteps * 2
	}
	var final investigation.StepResult
	var pending *investigation.Pending
	finished := false
	for step := 0; step < maxSteps; step++ {
		result, next, err := stepOnce(engine, ctx, planner, gw, journal, env, pending, runID, budget, clock)
		if err != nil {
			return ReplayResult{}, err
		}
		env, pending = next, result.Pending
		if result.Result.Kind == investigation.ResultFinal {
			final = result.Result
			finished = true
			break
		}
	}
	if !finished {
		return ReplayResult{}, fmt.Errorf("investigation did not terminate within %d steps", maxSteps)
	}
	if final.Report == nil {
		return ReplayResult{}, fmt.Errorf("run %s ended as %s without a report: %s", runID, final.Run.Status, final.Reason)
	}

	if err := journal.Append(store.Event{
		RunID: runID, IncidentID: bundle.Incident.ID, Kind: store.EventRunFinished,
		At: clock.now(), Payload: mustJSON(final.Run),
	}); err != nil {
		return ReplayResult{}, err
	}

	raw, err := json.MarshalIndent(final.Report, "", "  ")
	if err != nil {
		return ReplayResult{}, err
	}
	jsonPath, err := store.WriteArtifact(runDir, "report.json", append(raw, '\n'))
	if err != nil {
		return ReplayResult{}, err
	}
	mdPath, err := store.WriteArtifact(runDir, "report.md", []byte(final.Report.Markdown()))
	if err != nil {
		return ReplayResult{}, err
	}

	return ReplayResult{
		Report:             *final.Report,
		JournalPath:        journal.Path(),
		ReportJSONPath:     jsonPath,
		ReportMarkdownPath: mdPath,
		PlannerTurns:       planner.Consumed(),
		InfraCalls:         gw.Executed(),
		Steps:              final.Step,
	}, nil
}

// stepOnce performs one transition, resolving whichever request the worker
// emitted and feeding the answer back into the envelope. Requests are journaled
// before they are executed, which is what makes an interruption distinguishable
// from a success.
func stepOnce(
	engine *investigation.Engine,
	ctx context.Context,
	planner models.Planner,
	gw *gateway.FixtureGateway,
	journal *store.Journal,
	env investigation.StepEnvelope,
	pending *investigation.Pending,
	runID string,
	budget investigation.Budgets,
	clock *clock,
) (stepOutcome, investigation.StepEnvelope, error) {
	input, err := json.Marshal(investigation.WorkerInput{State: env, Pending: pending})
	if err != nil {
		return stepOutcome{}, env, err
	}
	out, err := worker.Step(engine, input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	if err != nil {
		return stepOutcome{}, env, err
	}
	var result investigation.StepResult
	if err := json.Unmarshal(out, &result); err != nil {
		return stepOutcome{}, env, err
	}
	env = result.Envelope

	switch result.Kind {
	case investigation.ResultModelRequest:
		call := investigation.Call{
			SchemaVersion: gateway.SchemaVersion,
			ID:            nextCallID(&env),
			RunID:         runID,
			IncidentID:    env.Incident.ID,
			Step:          result.Step,
			Kind:          investigation.CallModel,
			Target:        "planner:" + result.ModelRequest.Phase,
			RequestDigest: gateway.Digest(mustJSON(result.ModelRequest)),
			Status:        investigation.CallOK,
		}
		if err := journal.Append(store.Event{
			RunID: runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventRequest,
			At: clock.now(), Target: call.Target, Payload: mustJSON(result.ModelRequest),
		}); err != nil {
			return stepOutcome{}, env, err
		}
		response, err := planner.Plan(ctx, *result.ModelRequest)
		switch {
		case errors.Is(err, models.ErrExhausted):
			// A fixture that runs out of planning is a fixture bug, not a stop
			// condition: say so instead of inventing a conclusion.
			response = investigation.ModelResponse{
				SchemaVersion: gateway.SchemaVersion,
				Reason:        "recorded planner turns exhausted",
			}
			call.Status = investigation.CallFailed
			call.Reason = "recorded planner turns exhausted"
		case err != nil:
			call.Status = investigation.CallFailed
			call.Reason = err.Error()
			return stepOutcome{}, env, err
		}
		if raw, err := json.Marshal(response); err == nil {
			call.Bytes = len(raw)
			call.ResponseDigest = gateway.Digest(raw)
		}
		if err := journal.Append(store.Event{
			RunID: runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventResult,
			At: clock.now(), Target: call.Target, Payload: mustJSON(response),
		}); err != nil {
			return stepOutcome{}, env, err
		}
		env.Trace = append(env.Trace, call)
		return stepOutcome{Result: result, Pending: &investigation.Pending{Kind: investigation.PendingModel, Model: &response}}, env, nil

	case investigation.ResultInfraRequest:
		action := *result.InfraRequest
		call := investigation.Call{
			SchemaVersion: gateway.SchemaVersion,
			ID:            nextCallID(&env),
			RunID:         runID,
			IncidentID:    env.Incident.ID,
			Step:          result.Step,
			Kind:          investigation.CallInfra,
			Target:        action.Key(),
			RequestDigest: gateway.Digest(mustJSON(action)),
			Status:        investigation.CallOK,
		}
		if err := journal.Append(store.Event{
			RunID: runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventRequest,
			At: clock.now(), Target: call.Target, Payload: mustJSON(action),
		}); err != nil {
			return stepOutcome{}, env, err
		}
		response, err := gw.Execute(action)
		if err != nil {
			call.Status = investigation.CallDenied
			call.Reason = err.Error()
			env.Trace = append(env.Trace, call)
			return stepOutcome{}, env, err
		}
		raw, err := json.Marshal(response)
		if err != nil {
			return stepOutcome{}, env, err
		}
		call.Bytes = len(raw)
		call.ResponseDigest = gateway.Digest(raw)
		if err := journal.Append(store.Event{
			RunID: runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventResult,
			At: clock.now(), Target: call.Target, Payload: raw,
		}); err != nil {
			return stepOutcome{}, env, err
		}
		env.Trace = append(env.Trace, call)
		return stepOutcome{
			Result:  result,
			Pending: &investigation.Pending{Kind: investigation.PendingInfra, Action: &action, Response: &response},
		}, env, nil
	}
	return stepOutcome{Result: result}, env, nil
}

// stepOutcome is one decoded step result together with the answer the next step
// will consume.
type stepOutcome struct {
	Result  investigation.StepResult
	Pending *investigation.Pending
}

func nextCallID(env *investigation.StepEnvelope) string {
	return fmt.Sprintf("%s-%04d", investigation.PrefixCall, len(env.Trace)+1)
}

func plannerTurns(b fixtures.Bundle) []investigation.ModelResponse {
	out := make([]investigation.ModelResponse, 0, len(b.Planner))
	for _, turn := range b.Planner {
		response := investigation.ModelResponse{
			SchemaVersion: gateway.SchemaVersion,
			NextAction:    turn.NextAction,
			Reason:        turn.Reason,
		}
		for _, h := range turn.Hypotheses {
			response.Hypotheses = append(response.Hypotheses, investigation.HypothesisSpec{
				Statement:      h.Statement,
				FaultDomain:    investigation.FaultDomain(h.FaultDomain),
				ClaimKind:      investigation.ClaimKind(h.ClaimKind),
				EvidenceNeeded: h.EvidenceNeeded,
			})
		}
		out = append(out, response)
	}
	return out
}

// latestRetrieval anchors the replay clock after every recorded retrieval, so
// decisions in a report never appear to precede the evidence they were made on.
func latestRetrieval(b fixtures.Bundle) time.Time {
	latest := b.Incident.StartedAt
	for _, r := range b.Evidence {
		if r.Response.RetrievedAt.After(latest) {
			latest = r.Response.RetrievedAt
		}
	}
	return latest.Add(time.Second).UTC()
}

// clock is a deterministic monotonic clock: replay latency is not real latency,
// and pretending otherwise would put meaningless numbers in the report.
type clock struct {
	at   time.Time
	step time.Duration
}

func newClock(start time.Time) *clock {
	return &clock{at: start.UTC(), step: time.Second}
}

func (c *clock) now() time.Time {
	at := c.at
	c.at = c.at.Add(c.step)
	return at
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"unserializable"}`)
	}
	return raw
}
