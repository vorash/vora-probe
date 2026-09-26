package watch

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

const mib = 1 << 20

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// fakeGateway answers metrics queries from a curve per target, sampled every
// 15s over the requested window. It enforces the real policy on every action,
// counts the queries, and can drop a target's data to simulate a gap.
type fakeGateway struct {
	t       *testing.T
	curves  map[string]func(m float64) float64 // minutes since t0 -> bytes
	limit   float64
	queries int
	gap     map[string]bool
}

func (g *fakeGateway) Execute(a gateway.Action) (gateway.Response, error) {
	if err := gateway.DefaultPolicy().Authorize(a); err != nil {
		g.t.Fatalf("the watcher asked for something the policy refuses: %v", err)
	}
	g.queries++
	resp := gateway.Response{SchemaVersion: gateway.SchemaVersion, Kind: a.Kind, Entity: a.Entity, Status: gateway.StatusOK, Completeness: gateway.Complete}
	curve, ok := g.curves[a.Entity]
	if !ok || g.gap[a.Entity] {
		resp.Status, resp.Completeness = gateway.StatusUnavailable, gateway.Unavailable
		return resp, nil
	}
	var ms gateway.MetricSeries
	for at := a.Window.Start; !at.After(a.Window.End); at = at.Add(15 * time.Second) {
		v := g.limit
		if a.Metric == workingSet {
			v = curve(at.Sub(t0).Minutes())
		}
		ms.Samples = append(ms.Samples, gateway.MetricSample{At: at, Value: v})
	}
	resp.Payload, _ = json.Marshal(ms)
	return resp, nil
}

func (g *fakeGateway) Executed() int { return g.queries }

type harness struct {
	w                       *Watcher
	in                      *intake.Intake
	gw                      *fakeGateway
	now                     time.Time
	opened, revised, closed int
}

func newHarness(t *testing.T, path string, targets []string, curves map[string]func(float64) float64, budget int) *harness {
	t.Helper()
	h := &harness{now: t0, gw: &fakeGateway{t: t, curves: curves, limit: 256 * mib, gap: map[string]bool{}}}
	cfg := intake.DefaultConfig()
	cfg.Now = func() time.Time { return h.now }
	var err error
	if path == "" {
		h.in = intake.New(cfg)
	} else if h.in, err = intake.Open(cfg, path); err != nil {
		t.Fatalf("open: %v", err)
	}
	h.w, err = New(Config{
		Intake: h.in, Gateway: func() (gateway.Gateway, error) { return h.gw, nil },
		Targets: targets, Namespace: "probe-lab", Every: time.Minute, Window: 30 * time.Minute,
		Forecast: investigation.DefaultForecastPolicy(), MaxQueriesPerTick: budget,
		OnOpened:  func(intake.Received) { h.opened++ },
		OnRevised: func(string) { h.revised++ },
		OnClosed:  func(string) { h.closed++ },
		Now:       func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	return h
}

// run ticks once a minute from minute `from` to `to` since t0.
func (h *harness) run(t *testing.T, from, to int) {
	t.Helper()
	for m := from; m <= to; m++ {
		h.now = t0.Add(time.Duration(m) * time.Minute)
		if err := h.w.Tick(context.Background()); err != nil {
			t.Fatalf("tick at minute %d: %v", m, err)
		}
	}
}

func ramp(m float64) float64     { return 60*mib + 3*m*mib + wobble(m) }
func wobble(m float64) float64   { return []float64{1, -1, 0.5, -0.5, 0}[int(m*4)%5] * mib }
func recovers(m float64) float64 { return min(60*mib+3*m*mib, 190*mib) + wobble(m) }
func sawtooth(m float64) float64 { return 60*mib + 30*mib*(m-3*float64(int(m/3)))/3 + wobble(m) }

// A climb toward the limit opens exactly one forecast incident, triggered by the
// forecast and stated conditionally. It is not reopened on every tick, it is
// revised only when the ETA moves materially, and it is realized when the limit
// is reached.
func TestAClimbOpensOneForecastAndIsRealizedAtTheLimit(t *testing.T) {
	h := newHarness(t, "", []string{"memory-test"}, map[string]func(float64) float64{"memory-test": ramp}, 10)
	h.run(t, 31, 70)
	if h.opened != 1 {
		t.Fatalf("opened %d forecasts, want exactly one for one climb", h.opened)
	}
	records := h.in.List()
	if len(records) != 1 {
		t.Fatalf("incidents = %d, want 1", len(records))
	}
	r := records[0]
	if r.Incident.Trigger != investigation.TriggerForecast || !strings.Contains(r.Incident.Symptom, "if the growth persists") {
		t.Fatalf("incident %+v: want a forecast trigger and a conditional symptom", r.Incident)
	}
	if h.revised > 3 {
		t.Fatalf("%d revisions for a steady climb: revisions must be material, or they flood the thread", h.revised)
	}
	if r.Forecast.Closed != intake.ForecastRealized || h.closed != 1 {
		t.Fatalf("closed %q (%d closures), want realized once at the limit", r.Forecast.Closed, h.closed)
	}
}

// A near miss: it climbs, a forecast opens, then it plateaus. The forecast must
// be withdrawn, with the reason, before the crossing it predicted.
func TestANearMissIsWithdrawnWhenTheTrendStops(t *testing.T) {
	h := newHarness(t, "", []string{"memory-test"}, map[string]func(float64) float64{"memory-test": recovers}, 10)
	h.run(t, 31, 120)
	r := h.in.List()[0]
	if r.Forecast.Closed != intake.ForecastWithdrawn || r.Forecast.Reason == "" {
		t.Fatalf("forecast state %+v, want withdrawn with a reason", r.Forecast)
	}
	predicted := r.Incident.StartedAt.Add(r.Forecast.Current.ETA)
	if !r.Forecast.ClosedAt.Before(predicted) {
		t.Fatalf("withdrawn at %s, after the crossing it predicted at %s", r.Forecast.ClosedAt, predicted)
	}
	if h.opened != 1 || h.closed != 1 {
		t.Fatalf("opened %d, closed %d; want the one forecast opened and withdrawn", h.opened, h.closed)
	}
}

// A shape that is not a trend never becomes a forecast.
func TestASawtoothNeverOpensAForecast(t *testing.T) {
	h := newHarness(t, "", []string{"memory-test"}, map[string]func(float64) float64{"memory-test": sawtooth}, 10)
	h.run(t, 31, 120)
	if h.opened != 0 || len(h.in.List()) != 0 {
		t.Fatalf("a sawtooth opened %d forecasts", h.opened)
	}
}

// A gap in the data is not the trend stopping. An open forecast holds through
// it rather than being withdrawn and reopened.
func TestAGapHoldsAForecastOpen(t *testing.T) {
	h := newHarness(t, "", []string{"memory-test"}, map[string]func(float64) float64{"memory-test": ramp}, 10)
	h.run(t, 31, 40)
	if h.opened != 1 {
		t.Fatalf("setup: opened %d", h.opened)
	}
	h.gw.gap["memory-test"] = true
	h.run(t, 41, 45)
	if h.closed != 0 {
		t.Fatal("a data gap withdrew an open forecast")
	}
	h.gw.gap["memory-test"] = false
	h.run(t, 46, 50)
	if h.opened != 1 || h.closed != 0 {
		t.Fatalf("after the gap: opened %d, closed %d; want the same forecast still open", h.opened, h.closed)
	}
}

// Watching must never overload Prometheus: a tick spends at most its query
// budget, and targets beyond it are observed on later ticks, in turn.
func TestATickStaysWithinItsQueryBudget(t *testing.T) {
	targets := []string{"a", "b", "c", "d", "e"}
	curves := map[string]func(float64) float64{}
	for _, name := range targets {
		curves[name] = sawtooth
	}
	h := newHarness(t, "", targets, curves, 4)
	seen := map[int]bool{}
	for tick := 31; tick <= 33; tick++ {
		before := h.gw.queries
		h.run(t, tick, tick)
		if spent := h.gw.queries - before; spent > 4 {
			t.Fatalf("a tick spent %d queries, over its budget of 4", spent)
		}
		seen[h.w.next] = true
	}
	if len(seen) < 3 {
		t.Fatalf("the watch did not rotate through its targets: %v", seen)
	}
	if h.gw.queries != 12 {
		t.Fatalf("queries = %d, want 2 targets x 2 queries x 3 ticks", h.gw.queries)
	}
}

// A restarted watch reads open forecasts back from the log. It must continue
// the forecast it had, not open a second one for the same climb.
func TestARestartedWatchContinuesItsOpenForecast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	curves := map[string]func(float64) float64{"memory-test": ramp}
	h := newHarness(t, path, []string{"memory-test"}, curves, 10)
	h.run(t, 31, 40)
	h.in.Close()

	h2 := newHarness(t, path, []string{"memory-test"}, curves, 10)
	defer h2.in.Close()
	h2.run(t, 41, 50)
	if h2.opened != 0 || len(h2.in.List()) != 1 {
		t.Fatalf("after a restart: opened %d more, %d incidents; want the one forecast continued", h2.opened, len(h2.in.List()))
	}
}

func TestTheWatchRefusesAnUnboundedConfiguration(t *testing.T) {
	in := intake.New(intake.DefaultConfig())
	gw := func() (gateway.Gateway, error) { return nil, nil }
	for name, cfg := range map[string]Config{
		"no targets":     {Intake: in, Gateway: gw, Every: time.Minute, Window: time.Minute, MaxQueriesPerTick: 2},
		"window too big": {Intake: in, Gateway: gw, Targets: []string{"a"}, Every: time.Minute, Window: 2 * time.Hour, MaxQueriesPerTick: 2},
		"no budget":      {Intake: in, Gateway: gw, Targets: []string{"a"}, Every: time.Minute, Window: time.Minute, MaxQueriesPerTick: 1},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
