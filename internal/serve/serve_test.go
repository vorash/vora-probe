package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

const token = "test-token"

// notification builds a firing Alertmanager payload for one group, the shape
// intake's fixtures pin.
func notification(group, service, pod string, startsAt time.Time) []byte {
	raw, _ := json.Marshal(map[string]any{
		"version": "4", "groupKey": group, "status": "firing", "receiver": "vora-probe",
		"alerts": []map[string]any{{
			"status":      "firing",
			"labels":      map[string]string{"alertname": "ContainerOOMKilled", "service": service, "pod": pod, "namespace": "lab"},
			"annotations": map[string]string{"summary": service + " was OOMKilled"},
			"startsAt":    startsAt.Format(time.RFC3339),
			"endsAt":      "0001-01-01T00:00:00Z",
		}},
	})
	return raw
}

func resolution(group string, startsAt time.Time) []byte {
	raw, _ := json.Marshal(map[string]any{
		"version": "4", "groupKey": group, "status": "resolved",
		"alerts": []map[string]any{{
			"status": "resolved", "labels": map[string]string{"alertname": "ContainerOOMKilled"},
			"startsAt": startsAt.Format(time.RFC3339), "endsAt": startsAt.Add(5 * time.Minute).Format(time.RFC3339),
		}},
	})
	return raw
}

type harness struct {
	intake *intake.Intake
	server *Server
	http   *httptest.Server
}

func newHarness(t *testing.T, limits Limits, timeout time.Duration, investigate Investigator, now func() time.Time) *harness {
	t.Helper()
	cfg := intake.DefaultConfig()
	cfg.Now = now
	in := intake.New(cfg)
	srv, err := New(Config{Intake: in, Investigate: investigate, Limits: limits, Timeout: timeout, Now: now})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	h, err := intake.Handler(in, token, srv.Accept)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	hs := httptest.NewServer(h)
	t.Cleanup(hs.Close)
	return &harness{intake: in, server: srv, http: hs}
}

func (h *harness) post(t *testing.T, body []byte) intake.Received {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, h.http.URL+"/webhook/alertmanager", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("post: %v", err)
		return intake.Received{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status %d, want 202", resp.StatusCode)
	}
	var got intake.Received
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return got
}

// run starts the worker and returns a function that waits until every incident
// has left the queue and none is running, then stops it.
func (h *harness) run(t *testing.T) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = h.server.Run(ctx); close(done) }()
	return func() {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			busy := len(h.server.Queued()) > 0
			for _, r := range h.intake.List() {
				switch r.Investigation.State {
				case intake.InvestigationQueued, intake.InvestigationRunning:
					busy = true
				}
			}
			if !busy {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		<-done
	}
}

// P1.2 acceptance: alerts arrive in bursts (Alertmanager retries, concurrent
// deliveries of the same group), and the only worker must see one
// investigation, not N.
func TestABurstOfDuplicateAlertsYieldsOneInvestigation(t *testing.T) {
	var calls atomic.Int32
	investigate := func(_ context.Context, incident investigation.Incident, _ int) (probe.ReplayResult, error) {
		calls.Add(1)
		return probe.ReplayResult{Report: investigation.Report{Run: investigation.Run{Status: investigation.RunCompleted}}}, nil
	}
	h := newHarness(t, DefaultLimits(), time.Minute, investigate, time.Now)
	wait := h.run(t)

	body := notification("group-a", "payment-api", "payment-api-1", time.Now().Add(-5*time.Minute))
	const burst = 40
	var wg sync.WaitGroup
	for range burst {
		wg.Add(1)
		go func() { defer wg.Done(); h.post(t, body) }()
	}
	wg.Wait()
	wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("a burst of %d identical alerts started %d investigations, want 1", burst, n)
	}
	records := h.intake.List()
	if len(records) != 1 || records[0].Investigation.State != intake.InvestigationConcluded {
		t.Fatalf("records = %+v, want one concluded incident", records)
	}
	if got := len(records[0].Notifications); got != burst {
		t.Fatalf("the incident holds %d notifications, want all %d: duplicates are kept, not dropped", got, burst)
	}
}

// P1.2 acceptance: a stalled planner would hold the only worker forever. The
// deadline must free the queue, the stalled incident must still have a report,
// and the next incident must then be investigated normally. This runs the real
// in-process loop against a frozen fixture.
func TestAStalledPlannerFreesTheQueueAndLeavesAReport(t *testing.T) {
	bundle, err := fixtures.Load(filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out := t.TempDir()
	var calls atomic.Int32
	investigate := func(ctx context.Context, incident investigation.Incident, attempt int) (probe.ReplayResult, error) {
		gw, err := gateway.NewFixtureGateway(gateway.DefaultPolicy(), bundle.Evidence, nil)
		if err != nil {
			return probe.ReplayResult{}, err
		}
		var planner models.Planner = models.NewRecordedPlanner(recordedTurns(bundle))
		if calls.Add(1) == 1 {
			planner = stalled{}
		}
		return probe.Run(ctx, probe.RunOptions{Incident: incident, Planner: planner, Gateway: gw, OutDir: out, Attempt: attempt})
	}
	h := newHarness(t, DefaultLimits(), 300*time.Millisecond, investigate, time.Now)
	wait := h.run(t)

	start := time.Now().Add(-5 * time.Minute)
	first := h.post(t, notification("group-stalls", "payment-api", "payment-api-1", start))
	second := h.post(t, notification("group-next", "payment-api", "payment-api-2", start.Add(time.Minute)))
	wait()

	stalledRecord, _ := h.intake.Get(first.IncidentID)
	inv := stalledRecord.Investigation
	if inv.State != intake.InvestigationNotConcluded || inv.RunStatus != investigation.RunBudgetExhausted {
		t.Fatalf("stalled incident: state %q run %q (%s), want not_concluded / budget_exhausted", inv.State, inv.RunStatus, inv.Reason)
	}
	if _, err := os.Stat(inv.Report); err != nil {
		t.Fatalf("the stalled incident has no report on disk: %v", err)
	}
	if stalledRecord.Incident.Status != investigation.IncidentFailed {
		t.Fatalf("stalled incident status = %q, want failed", stalledRecord.Incident.Status)
	}
	nextRecord, _ := h.intake.Get(second.IncidentID)
	if nextRecord.Investigation.State != intake.InvestigationConcluded || nextRecord.Incident.Status != investigation.IncidentComplete {
		t.Fatalf("the incident after the stall: state %q (%s), want concluded: the queue was not freed",
			nextRecord.Investigation.State, nextRecord.Investigation.Reason)
	}
}

// A group that keeps resolving and firing again, or a host that trips many
// rules, must not monopolise the worker. The excess is recorded as rate
// limited with the reason, never dropped.
func TestExcessIncidentsAreRecordedAsRateLimited(t *testing.T) {
	var calls atomic.Int32
	investigate := func(_ context.Context, _ investigation.Incident, _ int) (probe.ReplayResult, error) {
		calls.Add(1)
		return probe.ReplayResult{}, nil
	}
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	h := newHarness(t, Limits{Window: time.Hour, PerGroup: 2, PerEntity: 3}, time.Minute, investigate, clock)

	// One group flaps: fire, resolve, fire again (a new incident each time).
	var flaps []intake.Received
	for i := range 3 {
		at := now.Add(time.Duration(-50+i*10) * time.Minute)
		flaps = append(flaps, h.post(t, notification("flapping", "payment-api", "pod-a", at)))
		h.post(t, resolution("flapping", at))
	}
	for i, r := range flaps {
		if r.Outcome != intake.OutcomeOpened {
			t.Fatalf("flap %d: outcome %q, want each refire to open an incident", i, r.Outcome)
		}
	}
	third, _ := h.intake.Get(flaps[2].IncidentID)
	if third.Investigation.State != intake.InvestigationRateLimited || third.Investigation.Reason == "" {
		t.Fatalf("the third firing of one group in an hour: state %q, want rate_limited with a reason", third.Investigation.State)
	}

	// A different group on a pod that already started two runs: one more is
	// allowed (entity limit 3), the next is not.
	other := h.post(t, notification("other-rule", "payment-api", "pod-a", now))
	another := h.post(t, notification("third-rule", "payment-api", "pod-a", now))
	if r, _ := h.intake.Get(other.IncidentID); r.Investigation.State != intake.InvestigationQueued {
		t.Fatalf("within the entity limit: state %q, want queued", r.Investigation.State)
	}
	if r, _ := h.intake.Get(another.IncidentID); r.Investigation.State != intake.InvestigationRateLimited {
		t.Fatalf("over the entity limit: state %q, want rate_limited", r.Investigation.State)
	}

	// The window rolls: an hour later the group may start again.
	now = now.Add(2 * time.Hour)
	later := h.post(t, notification("flapping", "payment-api", "pod-b", now))
	if r, _ := h.intake.Get(later.IncidentID); r.Investigation.State != intake.InvestigationQueued {
		t.Fatalf("after the window: state %q, want queued", r.Investigation.State)
	}

	wait := h.run(t)
	wait()
	if n := calls.Load(); n != 4 {
		t.Fatalf("investigations = %d, want the 4 admitted incidents only", n)
	}
	if len(h.intake.List()) != 6 {
		t.Fatalf("incidents recorded = %d, want all 6, rate limited ones included", len(h.intake.List()))
	}
}

// A run that could not produce any report is still an outcome of the incident,
// recorded with its reason.
func TestAnInvestigationThatCannotReportIsRecordedAsAnError(t *testing.T) {
	investigate := func(_ context.Context, _ investigation.Incident, _ int) (probe.ReplayResult, error) {
		return probe.ReplayResult{}, errors.New("journal could not be opened")
	}
	h := newHarness(t, DefaultLimits(), time.Minute, investigate, time.Now)
	wait := h.run(t)
	got := h.post(t, notification("g", "payment-api", "p", time.Now().Add(-time.Minute)))
	wait()
	r, _ := h.intake.Get(got.IncidentID)
	if r.Investigation.State != intake.InvestigationError || r.Incident.Status != investigation.IncidentFailed {
		t.Fatalf("state %q / incident %q, want error / failed", r.Investigation.State, r.Incident.Status)
	}
}

func TestTheServerRefusesAnUnboundedConfiguration(t *testing.T) {
	in := intake.New(intake.DefaultConfig())
	noop := func(context.Context, investigation.Incident, int) (probe.ReplayResult, error) {
		return probe.ReplayResult{}, nil
	}
	for name, cfg := range map[string]Config{
		"no timeout":  {Intake: in, Investigate: noop, Limits: DefaultLimits()},
		"zero limits": {Intake: in, Investigate: noop, Timeout: time.Minute},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted, want a refusal", name)
		}
	}
}

// stalled is a planner that never answers.
type stalled struct{}

func (stalled) Plan(ctx context.Context, _ investigation.ModelRequest) (investigation.ModelResponse, error) {
	<-ctx.Done()
	return investigation.ModelResponse{}, fmt.Errorf("planner: %w", ctx.Err())
}

func recordedTurns(b fixtures.Bundle) []investigation.ModelResponse {
	out := make([]investigation.ModelResponse, 0, len(b.Planner))
	for _, turn := range b.Planner {
		r := investigation.ModelResponse{SchemaVersion: gateway.SchemaVersion, NextAction: turn.NextAction, Reason: turn.Reason}
		for _, h := range turn.Hypotheses {
			r.Hypotheses = append(r.Hypotheses, investigation.HypothesisSpec{
				Statement: h.Statement, FaultDomain: investigation.FaultDomain(h.FaultDomain),
				ClaimKind: investigation.ClaimKind(h.ClaimKind), EvidenceNeeded: h.EvidenceNeeded,
			})
		}
		out = append(out, r)
	}
	return out
}

type call struct {
	service string
	attempt int
}

// restart simulates the server process dying and starting again on the same
// incident log: the old intake is closed without any orderly shutdown, and a
// new intake and server are built from what is on disk.
func restart(t *testing.T, path string, limits Limits, investigate Investigator, now func() time.Time) (*intake.Intake, *Server) {
	t.Helper()
	cfg := intake.DefaultConfig()
	cfg.Now = now
	in, err := intake.Open(cfg, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { in.Close() })
	srv, err := New(Config{Intake: in, Investigate: investigate, Limits: limits, Timeout: time.Minute, Now: now})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return in, srv
}

func accept(t *testing.T, in *intake.Intake, srv *Server, body []byte) intake.Received {
	t.Helper()
	n, err := intake.Parse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := in.Receive(n, body)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	srv.Accept(got)
	return got
}

// A restart must not lose work. Queued incidents resume in the order they
// arrived, and an incident whose run was cut off by the restart runs again as
// its next attempt — a new journal, the interrupted one kept — with the reason
// on its record.
func TestQueuedAndInterruptedIncidentsResumeAfterARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	now := func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }
	idle := func(context.Context, investigation.Incident, int) (probe.ReplayResult, error) {
		t.Error("nothing may run before the restart")
		return probe.ReplayResult{}, nil
	}
	in, srv := restart(t, path, DefaultLimits(), idle, now)
	start := now().Add(-10 * time.Minute)
	first := accept(t, in, srv, notification("group-1", "payment-api", "pod-1", start))
	second := accept(t, in, srv, notification("group-2", "checkout-api", "pod-2", start.Add(time.Minute)))
	// The first incident's run had started when the process died.
	running := intake.Investigation{State: intake.InvestigationRunning, Attempt: 1}
	if err := in.SetInvestigation(first.IncidentID, running, investigation.IncidentInvestigating); err != nil {
		t.Fatalf("set: %v", err)
	}
	in.Close()

	var mu sync.Mutex
	var calls []call
	record := func(_ context.Context, incident investigation.Incident, attempt int) (probe.ReplayResult, error) {
		mu.Lock()
		calls = append(calls, call{incident.Service, attempt})
		mu.Unlock()
		return probe.ReplayResult{}, nil
	}
	in, srv = restart(t, path, DefaultLimits(), record, now)
	resumed, _ := in.Get(first.IncidentID)
	if resumed.Investigation.State != intake.InvestigationQueued || resumed.Investigation.Attempt != 2 ||
		!strings.Contains(resumed.Investigation.Reason, "interrupted") {
		t.Fatalf("the interrupted incident after restart: %+v, want queued as attempt 2 with the reason", resumed.Investigation)
	}
	h := &harness{intake: in, server: srv}
	wait := h.run(t)
	wait()

	want := []call{{"payment-api", 2}, {"checkout-api", 1}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("runs after restart = %v, want %v: arrival order, and the interrupted run as its next attempt", calls, want)
	}
	for _, id := range []string{first.IncidentID, second.IncidentID} {
		if r, _ := in.Get(id); r.Investigation.State != intake.InvestigationConcluded {
			t.Fatalf("%s after restart: state %q, want concluded", id, r.Investigation.State)
		}
	}
}

// Rate limits are rebuilt from the records. Otherwise a restart would reset
// every window, and a flapping alert would start fresh runs after each one.
func TestRateLimitsSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	now := func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }
	noop := func(context.Context, investigation.Incident, int) (probe.ReplayResult, error) {
		return probe.ReplayResult{}, nil
	}
	limits := Limits{Window: time.Hour, PerGroup: 1, PerEntity: 10}

	in, srv := restart(t, path, limits, noop, now)
	at := now().Add(-30 * time.Minute)
	accept(t, in, srv, notification("flapping", "payment-api", "pod-1", at))
	accept(t, in, srv, resolution("flapping", at))
	in.Close()

	in, srv = restart(t, path, limits, noop, now)
	again := accept(t, in, srv, notification("flapping", "payment-api", "pod-1", at.Add(10*time.Minute)))
	if r, _ := in.Get(again.IncidentID); r.Investigation.State != intake.InvestigationRateLimited {
		t.Fatalf("the group's second firing within the window after a restart: state %q, want rate_limited", r.Investigation.State)
	}
}
