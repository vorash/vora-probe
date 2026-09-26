package probe

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// RunOptions configures an investigation whose worker runs in-process, with every
// port supplied: the incident, the planner and the gateway. It is the default
// for server mode, where requiring a Vora sandbox would block adoption; the
// sandbox remains the hardened mode (Investigate). The loop, the journal and the
// report are the same loop every other run uses.
type RunOptions struct {
	Incident investigation.Incident
	Planner  models.Planner
	Gateway  gateway.Gateway
	Engine   *investigation.Engine
	OutDir   string
	Attempt  int
	Budget   investigation.Budgets
}

// Run investigates one incident in-process against live time. Like Replay and
// Investigate, a run that does not conclude still returns its report, together
// with ErrNotConcluded.
func Run(ctx context.Context, opts RunOptions) (ReplayResult, error) {
	if opts.Planner == nil || opts.Gateway == nil {
		return ReplayResult{}, errors.New("an in-process run needs a planner and a gateway")
	}
	if err := opts.Incident.Validate(); err != nil {
		return ReplayResult{}, err
	}
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
	// A run against a live source uses the wall clock, for the same reason a
	// sandboxed one does: the budget is measured against real elapsed time.
	engine.Now = wallClock

	lock, err := store.AcquireLock(opts.OutDir, "probe")
	if err != nil {
		return ReplayResult{}, err
	}
	defer lock.Release()

	runID := fmt.Sprintf("RUN-%s-%03d", opts.Incident.ID, opts.Attempt)
	runDir := filepath.Join(opts.OutDir, runID)
	journal, err := store.OpenJournal(runDir, runID)
	if err != nil {
		return ReplayResult{}, err
	}
	defer journal.Close()

	res, err := runLoop(ctx, runConfig{
		engine:   engine,
		planner:  opts.Planner,
		gateway:  opts.Gateway,
		journal:  journal,
		now:      wallClock,
		budget:   budget,
		attempt:  opts.Attempt,
		runID:    runID,
		runDir:   runDir,
		incident: opts.Incident,
		runner:   inProcessRunner(engine, budget),
	})
	if err != nil && !errors.Is(err, ErrNotConcluded) {
		return ReplayResult{JournalPath: journal.Path()}, err
	}
	return ReplayResult{
		Report:             res.report,
		JournalPath:        journal.Path(),
		ReportJSONPath:     res.reportJSONPath,
		ReportMarkdownPath: res.reportMarkdownPath,
		PlannerTurns:       recordedTurns(opts.Planner),
		InfraCalls:         opts.Gateway.Executed(),
		Steps:              res.steps,
	}, err
}
