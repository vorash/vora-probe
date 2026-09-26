package intake

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// receivedAt is when the fixtures arrive: shortly after the lab's OOM kill.
var receivedAt = time.Date(2026, 9, 18, 20, 5, 0, 0, time.UTC)

func newIntake(now time.Time) *Intake {
	cfg := DefaultConfig()
	cfg.Now = func() time.Time { return now }
	return New(cfg)
}

func fixture(t *testing.T, name string) (Notification, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return n, raw
}

func receive(t *testing.T, in *Intake, name string) Received {
	t.Helper()
	n, raw := fixture(t, name)
	got, err := in.Receive(n, raw)
	if err != nil {
		t.Fatalf("receive %s: %v", name, err)
	}
	return got
}

// TestFixtureNotificationsProduceTheirOutcomes is the P1.1 acceptance case: one
// alert group's life, as Alertmanager delivers it, makes exactly one incident.
func TestFixtureNotificationsProduceTheirOutcomes(t *testing.T) {
	in := newIntake(receivedAt)

	opened := receive(t, in, "firing.json")
	if opened.Outcome != OutcomeOpened || opened.IncidentID == "" {
		t.Fatalf("firing: got %+v, want a new incident", opened)
	}
	// The repeat has grown a second alert, and must still not start a second
	// investigation of the same group.
	if got := receive(t, in, "duplicate.json"); got.Outcome != OutcomeDuplicate || got.IncidentID != opened.IncidentID {
		t.Fatalf("duplicate: got %+v, want a duplicate of %s", got, opened.IncidentID)
	}
	if got := receive(t, in, "heartbeat.json"); got.Outcome != OutcomeHeartbeat || got.IncidentID != "" {
		t.Fatalf("heartbeat: got %+v, want a heartbeat attributed to no incident", got)
	}
	if got := receive(t, in, "resolved.json"); got.Outcome != OutcomeResolved || got.IncidentID != opened.IncidentID {
		t.Fatalf("resolved: got %+v, want %s closed", got, opened.IncidentID)
	}

	records := in.List()
	if len(records) != 1 {
		t.Fatalf("incidents = %d, want 1: only the firing notification may open one", len(records))
	}
	r := records[0]
	if r.Alert != AlertResolved || r.ResolvedAt == nil {
		t.Fatalf("the incident must be closed by its group's resolution; alert = %q", r.Alert)
	}
	var outcomes []Outcome
	for _, d := range r.Notifications {
		outcomes = append(outcomes, d.Outcome)
	}
	if want := []Outcome{OutcomeOpened, OutcomeDuplicate, OutcomeResolved}; !equalOutcomes(outcomes, want) {
		t.Fatalf("the incident's notifications = %v, want %v: every payload for it is kept", outcomes, want)
	}
	if count, last := in.Heartbeats(); count != 1 || !last.Equal(receivedAt) {
		t.Fatalf("heartbeats = %d (last %s), want 1 recorded", count, last)
	}
}

// A resolved notification's key is built from its end time, so it can never
// match the firing one. If dedupe ran first, a resolution with nothing open
// would open an incident for an alert that has already stopped.
func TestResolutionWithNothingOpenIsIgnoredNotOpened(t *testing.T) {
	in := newIntake(receivedAt)
	got := receive(t, in, "resolved.json")
	if got.Outcome != OutcomeIgnored {
		t.Fatalf("got %+v, want ignored", got)
	}
	if n := len(in.List()); n != 0 {
		t.Fatalf("a resolution opened %d incidents", n)
	}
	// And a second resolution of an already closed group is ignored too.
	in = newIntake(receivedAt)
	receive(t, in, "firing.json")
	receive(t, in, "resolved.json")
	if got := receive(t, in, "resolved.json"); got.Outcome != OutcomeIgnored {
		t.Fatalf("a repeated resolution: got %+v, want ignored", got)
	}
}

// A group that resolves and fires again is a new occurrence and gets a new
// investigation; folding it into the closed one would hide a recurrence.
func TestAGroupThatFiresAgainIsANewIncident(t *testing.T) {
	in := newIntake(receivedAt)
	first := receive(t, in, "firing.json")
	receive(t, in, "resolved.json")

	n, _ := fixture(t, "firing.json")
	n.Alerts[0].StartsAt = n.Alerts[0].StartsAt.Add(2 * time.Hour)
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	again, err := in.Receive(n, raw)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if again.Outcome != OutcomeOpened || again.IncidentID == first.IncidentID {
		t.Fatalf("a recurrence: got %+v, want a new incident distinct from %s", again, first.IncidentID)
	}
}

// When the group's first alert resolves on its own, the next repeat carries only
// the later alerts, so its first start — and its dedupe key — changes while the
// group is still firing. It is the same incident; a second investigation of one
// alert group is exactly what dedupe exists to prevent.
func TestAnOpenGroupAbsorbsARepeatWhoseFirstAlertChanged(t *testing.T) {
	in := newIntake(receivedAt)
	opened := receive(t, in, "firing.json")

	n, _ := fixture(t, "duplicate.json")
	n.Alerts = n.Alerts[1:] // only the later pod is still firing
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if Fingerprint(n) == in.List()[0].Fingerprint {
		t.Fatal("the test needs a repeat whose dedupe key differs from the opening one")
	}
	got, err := in.Receive(n, raw)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if got.Outcome != OutcomeDuplicate || got.IncidentID != opened.IncidentID {
		t.Fatalf("got %+v, want a duplicate of %s", got, opened.IncidentID)
	}
}

// Alertmanager delivers groups concurrently and retries on timeouts, so the
// same notification can arrive many times at once. It must open one incident.
func TestABurstOfTheSameNotificationOpensOneIncident(t *testing.T) {
	in := newIntake(receivedAt)
	n, raw := fixture(t, "firing.json")
	const burst = 50
	var wg sync.WaitGroup
	outcomes := make(chan Outcome, burst)
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := in.Receive(n, raw)
			if err != nil {
				t.Errorf("receive: %v", err)
				return
			}
			outcomes <- got.Outcome
		}()
	}
	wg.Wait()
	close(outcomes)
	opened := 0
	for o := range outcomes {
		if o == OutcomeOpened {
			opened++
		}
	}
	if opened != 1 || len(in.List()) != 1 {
		t.Fatalf("a burst of %d opened %d incidents (%d recorded), want 1", burst, opened, len(in.List()))
	}
}

// The incident is what the planner investigates, so every field is checked
// against the alert it came from.
func TestTheIncidentIsNormalizedFromTheEarliestAlert(t *testing.T) {
	in := newIntake(receivedAt)
	receive(t, in, "duplicate.json") // two alerts; the earlier one anchors the incident
	r := in.List()[0]
	inc := r.Incident
	if err := inc.Validate(); err != nil {
		t.Fatalf("the incident must satisfy the contract the engine checks: %v", err)
	}
	earliest := time.Date(2026, 9, 18, 19, 56, 18, 0, time.UTC)
	switch {
	case inc.Service != "memory-test":
		t.Errorf("service = %q, want memory-test from the service label", inc.Service)
	case inc.Environment != "lab":
		t.Errorf("environment = %q, want the configured default", inc.Environment)
	case inc.Trigger != investigation.TriggerAlert:
		t.Errorf("trigger = %q, want alert", inc.Trigger)
	case inc.Status != investigation.IncidentOpen:
		t.Errorf("status = %q, want open: nothing has investigated it yet", inc.Status)
	case !inc.StartedAt.Equal(earliest):
		t.Errorf("started_at = %s, want the earliest alert's start %s", inc.StartedAt, earliest)
	case inc.Symptom != "memory-test was OOMKilled":
		t.Errorf("symptom = %q, want the alert's summary", inc.Symptom)
	case r.Namespace != "probe-lab" || r.Entity != "memory-test-7499b54f69-25kvp":
		t.Errorf("namespace/entity = %q/%q, want the earliest alert's", r.Namespace, r.Entity)
	case r.Severity != "warning" || r.Alertname != "ContainerOOMKilled":
		t.Errorf("severity/alertname = %q/%q", r.Severity, r.Alertname)
	case inc.Severity != "warning":
		// The incident carries the severity, because it decides which
		// actions the investigation is offered.
		t.Errorf("incident severity = %q, want the alert's", inc.Severity)
	}
	if !(inc.Window.Start.Before(inc.StartedAt) && inc.Window.End.After(inc.StartedAt)) {
		t.Errorf("window %s–%s must contain the alert's start %s", inc.Window.Start, inc.Window.End, inc.StartedAt)
	}
}

// Every evidence request is bounded at gateway.MaxWindow. An incident window
// wider than that would ask for evidence the gateway refuses.
func TestTheWindowNeverExceedsTheEvidenceBound(t *testing.T) {
	late := receivedAt.Add(6 * time.Hour)
	in := newIntake(late)
	receive(t, in, "firing.json")
	w := in.List()[0].Incident.Window
	if err := w.Validate(gateway.MaxWindow); err != nil {
		t.Fatalf("a notification received hours after the alert produced %s–%s: %v", w.Start, w.End, err)
	}
}

// An alert Probe cannot map to a service is still an alert: it is recorded and
// visible, never silently dropped, and never guessed into an investigation.
func TestAnUnmappableAlertIsRecordedNotDropped(t *testing.T) {
	in := newIntake(receivedAt)
	n, raw := fixture(t, "firing.json")
	for i := range n.Alerts {
		n.Alerts[i].Labels = map[string]string{"alertname": "DiskFull", "instance": "node-1"}
	}
	n.CommonLabels = map[string]string{"alertname": "DiskFull"}
	got, err := in.Receive(n, raw)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if got.Outcome != OutcomeUnmapped || !strings.Contains(got.Reason, "service") {
		t.Fatalf("got %+v, want unmapped with the reason", got)
	}
	if len(in.List()) != 0 {
		t.Fatal("an unmappable alert must not become an incident")
	}
	if len(in.Unmapped()) != 1 {
		t.Fatal("an unmappable alert must be recorded")
	}
}

// Alert text is written by whoever wrote the rule, and the symptom travels to
// the planner. It is redacted before it is kept, like any tool output.
func TestAlertTextIsRedactedBeforeItIsKept(t *testing.T) {
	in := newIntake(receivedAt)
	n, _ := fixture(t, "firing.json")
	n.Alerts[0].Annotations["summary"] = "memory-test crashed; password=hunter2"
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := in.Receive(n, raw); err != nil {
		t.Fatalf("receive: %v", err)
	}
	r := in.List()[0]
	if strings.Contains(r.Incident.Symptom, "hunter2") {
		t.Fatalf("a secret reached the incident symptom: %q", r.Incident.Symptom)
	}
	if strings.Contains(string(r.Notifications[0].Payload), "hunter2") {
		t.Fatal("a secret was kept in the stored payload")
	}
	if !strings.Contains(r.Incident.Symptom, "[REDACTED]") {
		t.Fatalf("redaction must be visible, got %q", r.Incident.Symptom)
	}
}

func TestParseRefusesWhatItCannotActOn(t *testing.T) {
	_, raw := fixture(t, "firing.json")
	var base map[string]any
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	cases := map[string]func(map[string]any){
		"version 3":    func(m map[string]any) { m["version"] = "3" },
		"no group key": func(m map[string]any) { delete(m, "groupKey") },
		"no alerts":    func(m map[string]any) { m["alerts"] = []any{} },
		"bad status":   func(m map[string]any) { m["status"] = "pending" },
	}
	for name, mutate := range cases {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mutate(m)
		mutated, _ := json.Marshal(m)
		if _, err := Parse(mutated); err == nil {
			t.Errorf("%s: parsed, want a refusal", name)
		}
	}
	// Fields Alertmanager adds later are its business, not a reason to refuse.
	if _, err := Parse(raw); err != nil {
		t.Fatalf("a payload with notification_reason must parse: %v", err)
	}
}

func equalOutcomes(a, b []Outcome) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
