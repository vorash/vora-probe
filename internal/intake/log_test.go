package intake

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/investigation"
)

func openLog(t *testing.T, path string) *Intake {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Now = func() time.Time { return receivedAt }
	in, err := Open(cfg, path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { in.Close() })
	return in
}

// A restart must not change what intake knows or decides. Every record, every
// kept notification, the heartbeat count and the unmapped alerts come back; and
// the decisions that depend on state — dedupe and open groups — still hold.
func TestIntakeStateSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	before := openLog(t, path)
	opened := receive(t, before, "firing.json")
	receive(t, before, "duplicate.json")
	receive(t, before, "heartbeat.json")
	n, raw := fixture(t, "firing.json")
	n.GroupKey = "unmapped-group"
	for i := range n.Alerts {
		n.Alerts[i].Labels = map[string]string{"alertname": "DiskFull"}
	}
	n.CommonLabels = nil
	if _, err := before.Receive(n, raw); err != nil {
		t.Fatalf("receive unmapped: %v", err)
	}
	inv := Investigation{State: InvestigationQueued, Attempt: 1}
	if err := before.SetInvestigation(opened.IncidentID, inv, investigation.IncidentOpen); err != nil {
		t.Fatalf("set investigation: %v", err)
	}
	wantRecords := before.List()
	wantBeats, wantLast := before.Heartbeats()
	wantUnmapped := before.Unmapped()
	before.Close()

	after := openLog(t, path)
	if got := after.List(); !reflect.DeepEqual(normalizeTimes(got), normalizeTimes(wantRecords)) {
		t.Fatalf("records after restart differ:\n got %+v\nwant %+v", got, wantRecords)
	}
	if beats, last := after.Heartbeats(); beats != wantBeats || !last.Equal(wantLast) {
		t.Fatalf("heartbeats after restart = %d (%s), want %d (%s)", beats, last, wantBeats, wantLast)
	}
	if got := after.Unmapped(); len(got) != len(wantUnmapped) {
		t.Fatalf("unmapped after restart = %d, want %d", len(got), len(wantUnmapped))
	}
	// Dedupe still holds: the same firing is a duplicate, not a second incident.
	if got := receive(t, after, "firing.json"); got.Outcome != OutcomeDuplicate || got.IncidentID != opened.IncidentID {
		t.Fatalf("a repeat after restart: got %+v, want a duplicate of %s", got, opened.IncidentID)
	}
	// And the group is still open, so its resolution closes it.
	if got := receive(t, after, "resolved.json"); got.Outcome != OutcomeResolved {
		t.Fatalf("a resolution after restart: got %+v, want resolved", got)
	}
}

// normalizeTimes drops monotonic clock readings, which never survive JSON and
// are not part of the state.
func normalizeTimes(records []Record) []Record {
	raw, _ := json.Marshal(records)
	var out []Record
	_ = json.Unmarshal(raw, &out)
	return out
}

// A crash mid-write leaves a final line without its newline. That write was
// never acknowledged — the sender got no 2xx and will retry — so it is cut off,
// and the log stays appendable instead of gluing the next change onto it.
func TestATornFinalLineIsCutOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	in := openLog(t, path)
	opened := receive(t, in, "firing.json")
	in.Close()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	f.WriteString(`{"kind":"duplicate","id":"` + opened.IncidentID + `","deliv`)
	f.Close()

	in = openLog(t, path)
	if got := len(in.List()[0].Notifications); got != 1 {
		t.Fatalf("notifications = %d, want 1: the torn write must not count", got)
	}
	receive(t, in, "duplicate.json")
	in.Close()
	in = openLog(t, path)
	if got := len(in.List()[0].Notifications); got != 2 {
		t.Fatalf("notifications after a later append = %d, want 2: the log must stay appendable", got)
	}
}

// Corruption before the final line is not an interrupted write. Loading around
// it would silently forget incidents, so the log is refused.
func TestACorruptLineRefusesToLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	in := openLog(t, path)
	receive(t, in, "firing.json")
	in.Close()
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, append([]byte("not json\n"), raw...), 0o600)

	if _, err := Open(DefaultConfig(), path); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("open = %v, want a refusal naming the corrupt line", err)
	}
}

// A notification is acknowledged only once it is on disk. If the write fails,
// the sender gets a 5xx — which Alertmanager retries — and intake's state is
// unchanged, so the retry is handled as if it were the first delivery.
func TestAChangeThatCannotBeWrittenIsNotAcknowledged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	in := openLog(t, path)
	in.log.Close() // every write now fails

	h, err := Handler(in, testToken, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/webhook/alertmanager", bytes.NewReader(readFixture(t, "firing.json")))
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 5 {
		t.Fatalf("status %d, want a 5xx so the sender retries", resp.StatusCode)
	}
	if len(in.List()) != 0 {
		t.Fatal("a change that was not written must not be applied")
	}
}

// Two servers appending to one log would interleave two histories.
func TestTheLogAdmitsOneServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	openLog(t, path)
	if _, err := Open(DefaultConfig(), path); err == nil {
		t.Fatal("a second server opened a log that is in use")
	}
}

// What is on disk is what intake keeps: redacted, and readable by the owner
// only.
func TestTheLogIsRedactedAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	in := openLog(t, path)
	n, _ := fixture(t, "firing.json")
	n.Alerts[0].Annotations["summary"] = "crashed; password=hunter2"
	raw, _ := json.Marshal(n)
	if _, err := in.Receive(n, raw); err != nil {
		t.Fatalf("receive: %v", err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(onDisk, []byte("hunter2")) {
		t.Fatal("a secret reached the incident log")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log mode = %v, want 0600", info.Mode().Perm())
	}
}
