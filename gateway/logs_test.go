package gateway

import (
	"slices"
	"testing"
	"time"
)

// A log query is a filter name from a closed set over a bounded window, and
// nothing else. Each refusal is a way a request could widen into a free search
// over the most secret-laden data an incident has.
func TestALogQueryIsAClosedAction(t *testing.T) {
	w := &Window{Start: time.Now().Add(-30 * time.Minute), End: time.Now()}
	ok := Action{Kind: ActionLogsQuery, Entity: "memory-test", Reason: "r", Filter: "error", Window: w}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a closed log query must validate: %v", err)
	}
	for name, a := range map[string]Action{
		"free-form filter":  {Kind: ActionLogsQuery, Entity: "e", Reason: "r", Filter: `{app="x"} |= "password"`, Window: w},
		"no filter":         {Kind: ActionLogsQuery, Entity: "e", Reason: "r", Window: w},
		"no window":         {Kind: ActionLogsQuery, Entity: "e", Reason: "r", Filter: "error"},
		"a metric":          {Kind: ActionLogsQuery, Entity: "e", Reason: "r", Filter: "error", Window: w, Metric: "db_query_count"},
		"too wide":          {Kind: ActionLogsQuery, Entity: "e", Reason: "r", Filter: "error", Window: &Window{Start: w.End.Add(-2 * time.Hour), End: w.End}},
		"filter on metrics": {Kind: ActionMetricsQuery, Entity: "e", Reason: "r", Metric: "db_query_count", Window: w, Resolution: "30s", Filter: "error"},
	} {
		if err := a.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Logs are offered only to incidents serious enough to warrant reading them;
// an incident of unknown severity is not.
func TestLogsAreOfferedOnlyForSeriousIncidents(t *testing.T) {
	for severity, want := range map[string]bool{"critical": true, "HIGH": true, "warning": true, "info": false, "none": false, "": false} {
		if got := slices.Contains(ActionsFor(severity), ActionLogsQuery); got != want {
			t.Errorf("severity %q: logs offered %t, want %t", severity, got, want)
		}
	}
	if !slices.Contains(ActionsFor(""), ActionMetricsQuery) {
		t.Fatal("gating logs must not withdraw the other actions")
	}
}

// Log lines are redacted before anything keeps them.
func TestLogLinesAreRedacted(t *testing.T) {
	payload := []byte(`{"filter":"error","total":1,"truncated":false,"lines":[{"at":"2026-09-18T12:00:00Z","line":"db connect failed password=hunter2"}]}`)
	r := RedactResponse(Response{SchemaVersion: SchemaVersion, Kind: ActionLogsQuery, Entity: "e", Status: StatusOK, Completeness: Complete, Digest: Digest(payload), Payload: payload})
	lines, err := r.LogLines()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lines.Lines[0].Line == "db connect failed password=hunter2" || r.Completeness != Redacted {
		t.Fatalf("a secret in a log line survived redaction: %q (%s)", lines.Lines[0].Line, r.Completeness)
	}
}
