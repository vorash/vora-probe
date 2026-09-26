// Package probe wires an investigation together: the ports it reads through,
// the bounded step worker and the journal.
//
// Nothing in this package is special-cased for replay. The loop is the same loop
// that runs against a live gateway and a sandboxed worker; only the ports
// differ. That is the property worth having, because it is what makes the
// offline result evidence about the engine rather than about a mock.
package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
	"github.com/vorash/vora-probe/worker"
)

// StepRunner executes one worker step: a bounded state envelope in, exactly one
// result line out. Replay runs the worker in-process, the live controller runs
// the same binary inside a network-denied sandbox, and the loop cannot tell the
// difference. Swapping this port is the whole of step 4.
type StepRunner func(ctx context.Context, input []byte) ([]byte, error)

// inProcessRunner runs the worker in the controller's own address space.
func inProcessRunner(engine *investigation.Engine, budget investigation.Budgets) StepRunner {
	return func(_ context.Context, input []byte) ([]byte, error) {
		return worker.Step(engine, input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	}
}

type ReplayOptions struct {
	BundleDir string
	// OutDir holds the journal and artifacts. It is owner-readable and ignored
	// by git: live artifacts are never a source of truth.
	OutDir   string
	Attempt  int
	Budget   investigation.Budgets
	Engine   *investigation.Engine
	MaxSteps int
	// Runner overrides where a step runs. Nil means in-process, which is what
	// replay has always done; the live controller injects a sandboxed runner.
	Runner StepRunner
	// OnEnvelope is a test/debug hook: it is called with the state envelope
	// before every step.
	OnEnvelope func(investigation.StepEnvelope)
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

// ReplayWithArm runs one investigation with a specific evidence-relation arm and
// returns the report. It is the adapter the comparison harness is given, so that
// the harness itself does not depend on how an investigation is executed.
func ReplayWithArm(ctx context.Context, bundleDir string, arm investigation.RelationEvaluator, outDir string, attempt int, budget investigation.Budgets) (investigation.Report, error) {
	result, err := Replay(ctx, ReplayOptions{
		BundleDir: bundleDir,
		OutDir:    outDir,
		Attempt:   attempt,
		Budget:    budget,
		Engine: &investigation.Engine{
			Policy:    gateway.DefaultPolicy(),
			Claims:    investigation.DefaultClaimPolicy(),
			Relations: arm,
		},
	})
	if err != nil {
		return investigation.Report{}, err
	}
	return result.Report, nil
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

	bundle, err := loadBundle(opts.BundleDir)
	if err != nil {
		return ReplayResult{}, err
	}
	// Replay freezes time so two runs are byte-identical. A live run must not;
	// see wallClock in live.go.
	clock := newClock(latestRetrieval(bundle))
	planner := openPlanner(engine, bundle, clock.now)
	gw, err := openFixtureGateway(engine, bundle, clock.now)
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

	runner := opts.Runner
	if runner == nil {
		runner = inProcessRunner(engine, budget)
	}

	res, err := runLoop(ctx, runConfig{
		engine:     engine,
		planner:    planner,
		gateway:    gw,
		journal:    journal,
		now:        clock.now,
		budget:     budget,
		attempt:    opts.Attempt,
		runID:      runID,
		runDir:     runDir,
		incident:   bundle.Incident,
		maxSteps:   opts.MaxSteps,
		runner:     runner,
		onEnvelope: opts.OnEnvelope,
	})
	if err != nil {
		return ReplayResult{}, err
	}

	return ReplayResult{
		Report:             res.report,
		JournalPath:        journal.Path(),
		ReportJSONPath:     res.reportJSONPath,
		ReportMarkdownPath: res.reportMarkdownPath,
		PlannerTurns:       planner.Consumed(),
		InfraCalls:         gw.Executed(),
		Steps:              res.steps,
	}, nil
}

// loadBundle loads and verifies a fixture bundle. Verification is not optional:
// a corrupted fixture would produce a plausible report about evidence that never
// existed.
func loadBundle(dir string) (fixtures.Bundle, error) {
	bundle, err := fixtures.Load(dir)
	if err != nil {
		return fixtures.Bundle{}, err
	}
	if err := fixtures.Verify(bundle); err != nil {
		return fixtures.Bundle{}, fmt.Errorf("%s: %w", dir, err)
	}
	return bundle, nil
}

// openPlanner builds the recorded planner and anchors the engine's clock. It is
// the same planner for replay and for a live run: step 4 proves the transport,
// and step 6 swaps the gateway without touching planning.
func openPlanner(engine *investigation.Engine, bundle fixtures.Bundle, now func() time.Time) *models.RecordedPlanner {
	engine.Now = now
	return models.NewRecordedPlanner(plannerTurns(bundle))
}

// openFixtureGateway builds the offline evidence port from a verified bundle.
func openFixtureGateway(engine *investigation.Engine, bundle fixtures.Bundle, now func() time.Time) (*gateway.FixtureGateway, error) {
	return gateway.NewFixtureGateway(engine.Policy, bundle.Evidence, now)
}

// runConfig is everything the shared loop needs. Everything that differs between
// replay and a live run is a port or a hook here.
type runConfig struct {
	engine     *investigation.Engine
	planner    models.Planner
	gateway    gateway.Gateway
	journal    *store.Journal
	now        func() time.Time
	budget     investigation.Budgets
	attempt    int
	runID      string
	runDir     string
	incident   investigation.Incident
	maxSteps   int
	runner     StepRunner
	onEnvelope func(investigation.StepEnvelope)
	// onCreate and onDestroy bracket an external resource around the steps. The
	// live controller creates its sandbox in onCreate and destroys it in
	// onDestroy, so the sandbox's whole life is journaled between run_started
	// and run_finished — the same bracket replay has always had.
	onCreate  func(ctx context.Context) (StepRunner, error)
	onDestroy func(ctx context.Context)
}

type loopResult struct {
	report             investigation.Report
	steps              int
	reportJSONPath     string
	reportMarkdownPath string
}

// runLoop is the investigation itself, independent of where the worker runs.
func runLoop(ctx context.Context, cfg runConfig) (loopResult, error) {
	run := investigation.Run{
		SchemaVersion: gateway.SchemaVersion,
		ID:            cfg.runID,
		IncidentID:    cfg.incident.ID,
		Attempt:       cfg.attempt,
		StartedAt:     cfg.now(),
		Status:        investigation.RunActive,
		Budgets:       cfg.budget,
		Used:          investigation.BudgetState{StartedAt: cfg.now()},
	}
	if err := cfg.journal.Append(store.Event{
		RunID: cfg.runID, IncidentID: cfg.incident.ID, Kind: store.EventRunStarted,
		At: run.StartedAt, Payload: mustJSON(cfg.incident),
	}); err != nil {
		return loopResult{}, err
	}

	runner := cfg.runner
	if cfg.onCreate != nil {
		var err error
		runner, err = cfg.onCreate(ctx)
		if err != nil {
			return loopResult{}, err
		}
	}
	// Teardown must survive a cancelled context: if the run is abandoned, the
	// sandbox still has to go away, or the next attempt inherits a leak.
	destroyCtx := context.WithoutCancel(ctx)
	destroyed := false
	destroy := func() {
		if destroyed || cfg.onDestroy == nil {
			return
		}
		destroyed = true
		cfg.onDestroy(destroyCtx)
	}
	// A write to the journal can fail at any point below; reap the resource
	// regardless, including on paths that never reach run_finished.
	defer destroy()

	env := investigation.StepEnvelope{
		SchemaVersion: gateway.SchemaVersion,
		Incident:      cfg.incident,
		Run:           run,
	}

	maxSteps := cfg.maxSteps
	if maxSteps == 0 {
		maxSteps = cfg.budget.MaxSteps * 2
	}
	var final investigation.StepResult
	var pending *investigation.Pending
	finished := false
	for step := 0; step < maxSteps; step++ {
		if cfg.onEnvelope != nil {
			cfg.onEnvelope(env)
		}
		result, next, err := stepOnce(ctx, cfg, runner, env, pending)
		if err != nil {
			return loopResult{}, err
		}
		env, pending = next, result.Pending
		if result.Result.Kind == investigation.ResultFinal {
			final = result.Result
			finished = true
			break
		}
	}
	if !finished {
		return loopResult{}, fmt.Errorf("investigation did not terminate within %d steps", maxSteps)
	}

	// Reap the sandbox before declaring the run finished: run_finished is the
	// last word on the run, and a resource still alive after it would contradict
	// that.
	destroy()

	if err := cfg.journal.Append(store.Event{
		RunID: cfg.runID, IncidentID: cfg.incident.ID, Kind: store.EventRunFinished,
		At: cfg.now(), Payload: mustJSON(final.Run),
	}); err != nil {
		return loopResult{}, err
	}

	if final.Report == nil {
		// A failed or exhausted run publishes no report, because it did not
		// conclude. Its final state is still kept, so the decision that ended it
		// is an artifact rather than something only the journal knows.
		raw, err := json.MarshalIndent(final.Envelope, "", "  ")
		if err != nil {
			return loopResult{}, err
		}
		path, err := store.WriteArtifact(cfg.runDir, "state.json", append(raw, '\n'))
		if err != nil {
			return loopResult{}, err
		}
		return loopResult{}, fmt.Errorf("run %s ended as %s without a report: %s (final state in %s)",
			cfg.runID, final.Run.Status, final.Reason, path)
	}

	raw, err := json.MarshalIndent(final.Report, "", "  ")
	if err != nil {
		return loopResult{}, err
	}
	jsonPath, err := store.WriteArtifact(cfg.runDir, "report.json", append(raw, '\n'))
	if err != nil {
		return loopResult{}, err
	}
	mdPath, err := store.WriteArtifact(cfg.runDir, "report.md", []byte(final.Report.Markdown()))
	if err != nil {
		return loopResult{}, err
	}

	return loopResult{
		report:             *final.Report,
		steps:              final.Step,
		reportJSONPath:     jsonPath,
		reportMarkdownPath: mdPath,
	}, nil
}

// stepOnce performs one transition, resolving whichever request the worker
// emitted and feeding the answer back into the envelope. Requests are journaled
// before they are executed, which is what makes an interruption distinguishable
// from a success.
func stepOnce(
	ctx context.Context,
	cfg runConfig,
	runner StepRunner,
	env investigation.StepEnvelope,
	pending *investigation.Pending,
) (stepOutcome, investigation.StepEnvelope, error) {
	input, err := json.Marshal(investigation.WorkerInput{State: env, Pending: pending})
	if err != nil {
		return stepOutcome{}, env, err
	}
	out, err := runner(ctx, input)
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
			RunID:         cfg.runID,
			IncidentID:    env.Incident.ID,
			Step:          result.Step,
			Kind:          investigation.CallModel,
			Target:        "planner:" + result.ModelRequest.Phase,
			RequestDigest: gateway.Digest(mustJSON(result.ModelRequest)),
			Status:        investigation.CallOK,
		}
		if err := cfg.journal.Append(store.Event{
			RunID: cfg.runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventRequest,
			At: cfg.now(), Target: call.Target, Payload: mustJSON(result.ModelRequest),
		}); err != nil {
			return stepOutcome{}, env, err
		}
		response, err := cfg.planner.Plan(ctx, *result.ModelRequest)
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
		if err := cfg.journal.Append(store.Event{
			RunID: cfg.runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventResult,
			At: cfg.now(), Target: call.Target, Payload: mustJSON(response),
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
			RunID:         cfg.runID,
			IncidentID:    env.Incident.ID,
			Step:          result.Step,
			Kind:          investigation.CallInfra,
			Target:        action.Key(),
			RequestDigest: gateway.Digest(mustJSON(action)),
			Status:        investigation.CallOK,
		}
		if err := cfg.journal.Append(store.Event{
			RunID: cfg.runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventRequest,
			At: cfg.now(), Target: call.Target, Payload: mustJSON(action),
		}); err != nil {
			return stepOutcome{}, env, err
		}
		response, err := cfg.gateway.Execute(action)
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
		if err := cfg.journal.Append(store.Event{
			RunID: cfg.runID, IncidentID: env.Incident.ID, Step: result.Step, Kind: store.EventResult,
			At: cfg.now(), Target: call.Target, Payload: raw,
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
