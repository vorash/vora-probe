package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// Evidence links let a reader check the evidence itself. A run told where the
// Prometheus UI is links each metric observation to its exact query and window,
// and links nothing else; a run that was not told carries no links, so replays
// stay byte-identical.
func TestARunLinksMetricEvidenceOnlyWhenToldWhere(t *testing.T) {
	bundle, err := loadBundle(filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	run := func(evidenceURL string) investigation.Report {
		engine := defaultEngine()
		gw, err := openFixtureGateway(engine, bundle, wallClock)
		if err != nil {
			t.Fatalf("gateway: %v", err)
		}
		incident := bundle.Incident
		incident.StartedAt = time.Now().UTC()
		result, err := Run(context.Background(), RunOptions{Incident: incident, Engine: engine, OutDir: t.TempDir(),
			Planner: models.NewRecordedPlanner(plannerTurns(bundle)), Gateway: gw, EvidenceURL: evidenceURL})
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return result.Report
	}

	linked := run("http://prometheus.lab:9090")
	links := 0
	for _, l := range append(append(linked.Supporting, linked.Contradicting...), linked.InsufficientContext...) {
		switch {
		case l.Query.Datasource == "prometheus" && !strings.HasPrefix(l.URL, "http://prometheus.lab:9090/graph?"):
			t.Errorf("metric evidence %s has no graph link: %q", l.Observation, l.URL)
		case l.Query.Datasource != "prometheus" && l.URL != "":
			t.Errorf("%s evidence %s was given a link %q", l.Query.Datasource, l.Observation, l.URL)
		case l.URL != "":
			links++
		}
	}
	if links == 0 {
		t.Fatal("the positive case cites metric evidence, and none of it was linked")
	}
	if !strings.Contains(linked.Markdown(), "open: <http://prometheus.lab:9090/graph?") {
		t.Fatal("the rendered report must show the link")
	}

	plain := run("")
	for _, l := range plain.Supporting {
		if l.URL != "" {
			t.Fatalf("a run not told where the UI is carries a link: %q", l.URL)
		}
	}
}

// labelledPlanner answers from the recorded turns, as a fallback endpoint.
type labelledPlanner struct{ recorded *models.RecordedPlanner }

func (p labelledPlanner) Plan(ctx context.Context, req investigation.ModelRequest) (investigation.ModelResponse, error) {
	resp, err := p.recorded.Plan(ctx, req)
	resp.AnsweredBy, resp.Attempts, resp.FallbackReasons = "backup.example gpt-x", 2, []string{"primary returned 503"}
	return resp, err
}

// A run says which model planned it, and when the primary endpoint was passed
// over, why: the trace carries both on every planner call.
func TestTheTraceSaysWhichModelPlannedAndWhyItFellBack(t *testing.T) {
	bundle, err := loadBundle(filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	engine := defaultEngine()
	gw, err := openFixtureGateway(engine, bundle, wallClock)
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	incident := bundle.Incident
	incident.StartedAt = time.Now().UTC()
	result, err := Run(context.Background(), RunOptions{Incident: incident, Engine: engine, OutDir: t.TempDir(),
		Planner: labelledPlanner{models.NewRecordedPlanner(plannerTurns(bundle))}, Gateway: gw})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	planned := 0
	for _, c := range result.Report.Trace {
		if c.Kind != investigation.CallModel {
			continue
		}
		planned++
		if c.Model != "backup.example gpt-x" || !strings.Contains(c.Reason, "primary returned 503") {
			t.Fatalf("planner call %+v: want the answering model and the fallback reason", c)
		}
	}
	if planned == 0 {
		t.Fatal("the run made no planner calls")
	}
}
