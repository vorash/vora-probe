package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// stallingPlanner answers its recorded turns, then hangs until the caller gives
// up — the shape of a model endpoint that accepts the connection and never
// replies.
type stallingPlanner struct {
	recorded *models.RecordedPlanner
	answer   int
}

func (p *stallingPlanner) Plan(ctx context.Context, req investigation.ModelRequest) (investigation.ModelResponse, error) {
	if p.answer > 0 {
		p.answer--
		return p.recorded.Plan(ctx, req)
	}
	<-ctx.Done()
	return investigation.ModelResponse{}, ctx.Err()
}

// A stalled planner is the failure that would hold a server's only worker
// forever. The deadline must end the run, and the run must still leave a report
// that says it did not conclude — built without the model that stalled.
func TestAStalledPlannerEndsTheRunWithAReportAtTheDeadline(t *testing.T) {
	bundle, err := loadBundle(filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	engine := defaultEngine()
	gw, err := openFixtureGateway(engine, bundle, wallClock)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	planner := &stallingPlanner{recorded: models.NewRecordedPlanner(plannerTurns(bundle)), answer: 1}
	incident := bundle.Incident
	incident.StartedAt = time.Now().UTC()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := Run(ctx, RunOptions{
		Incident: incident, Planner: planner, Gateway: gw, Engine: engine, OutDir: t.TempDir(),
	})
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the run took %s; the deadline did not release it", elapsed)
	}
	if !errors.Is(err, ErrNotConcluded) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v, want not concluded because the deadline passed", err)
	}
	report := result.Report
	if report.Concluded() || report.Run.Status != investigation.RunBudgetExhausted {
		t.Fatalf("report status = %q, want budget_exhausted: the wall clock ran out", report.Run.Status)
	}
	if report.Leading != nil || report.Recommendation != nil {
		t.Fatal("a stalled run must state no finding")
	}
	if len(report.Hypotheses) == 0 {
		t.Fatal("the report must keep what the planner proposed before it stalled")
	}
	if _, err := os.Stat(result.ReportMarkdownPath); err != nil {
		t.Fatalf("the report was not written: %v", err)
	}
	last := report.Decisions[len(report.Decisions)-1]
	if last.Outcome != investigation.OutcomeEscalate {
		t.Fatalf("the reason the controller gave up must be recorded as an escalation; last decision = %+v", last)
	}
}
