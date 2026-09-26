package live

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// fakeLoki answers the count and the lines, recording what was asked.
type fakeLoki struct {
	count    string // "" means no series: zero matches
	streams  [][][2]string
	gotCount url.Values
	gotLines url.Values
	hits     atomic.Int32
}

func (f *fakeLoki) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	switch r.URL.Path {
	case "/loki/api/v1/query":
		f.gotCount = r.URL.Query()
		if f.count == "" {
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
			return
		}
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1758196800,%q]}]}}`, f.count)
	case "/loki/api/v1/query_range":
		f.gotLines = r.URL.Query()
		var parts []string
		for _, s := range f.streams {
			var vals []string
			for _, v := range s {
				vals = append(vals, fmt.Sprintf("[%q,%q]", v[0], v[1]))
			}
			parts = append(parts, `{"stream":{"pod":"x"},"values":[`+strings.Join(vals, ",")+`]}`)
		}
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"streams","result":[`+strings.Join(parts, ",")+`]}}`)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func ns(at time.Time) string { return fmt.Sprint(at.UnixNano()) }

var logWindow = gateway.Window{Start: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 18, 12, 30, 0, 0, time.UTC)}

func logAction(entity, filter string) gateway.Action {
	w := logWindow
	return gateway.Action{Kind: gateway.ActionLogsQuery, Entity: entity, Reason: "read errors", Filter: filter, Window: &w}
}

func lokiGateway(t *testing.T, f *fakeLoki) *Gateway {
	t.Helper()
	return newGateway(t, f, func(c *Config) { c.LokiURL = c.PrometheusURL })
}

// The only query a logs request may run is the entity's pods, the configured
// namespace and the filter's fixed matcher. The entity is escaped, so a name
// with regex characters cannot widen the selector.
func TestALogQueryIsBuiltFromTheFilterAndNothingElse(t *testing.T) {
	f := &fakeLoki{count: "1", streams: [][][2]string{{{ns(logWindow.Start.Add(time.Minute)), "boom"}}}}
	gw := lokiGateway(t, f)
	if _, err := gw.Execute(logAction("memory.test", "error")); err != nil {
		t.Fatalf("execute: %v", err)
	}
	want := "{namespace=\"probe-lab\", pod=~\"^memory\\\\.test-.+\"} |~ `" + gateway.LogFilters["error"] + "`"
	if got := f.gotLines.Get("query"); got != want {
		t.Fatalf("query\n got %s\nwant %s", got, want)
	}
	if f.gotLines.Get("start") != ns(logWindow.Start) || f.gotLines.Get("end") != ns(logWindow.End) ||
		f.gotLines.Get("direction") != "forward" || f.gotLines.Get("limit") != fmt.Sprint(maxLogLines) {
		t.Fatalf("range parameters %v", f.gotLines)
	}
	if got := f.gotCount.Get("query"); got != "sum(count_over_time("+want+" [1800s]))" {
		t.Fatalf("count query %s", got)
	}
}

// Lines from several streams are merged by time, so the answer does not depend
// on how Loki split them; an exact count that matches the lines is complete.
func TestACompleteLogAnswerMergesStreamsByTime(t *testing.T) {
	t0 := logWindow.Start
	f := &fakeLoki{count: "3", streams: [][][2]string{
		{{ns(t0.Add(3 * time.Minute)), "c"}},
		{{ns(t0.Add(time.Minute)), "a"}, {ns(t0.Add(2 * time.Minute)), "b"}},
	}}
	resp, err := lokiGateway(t, f).Execute(logAction("memory-test", "error"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	lines, _ := resp.LogLines()
	if resp.Completeness != gateway.Complete || lines.Total != 3 || lines.Truncated {
		t.Fatalf("answer %s total %d truncated %t, want complete 3", resp.Completeness, lines.Total, lines.Truncated)
	}
	if lines.Lines[0].Line != "a" || lines.Lines[2].Line != "c" {
		t.Fatalf("lines not in time order: %+v", lines.Lines)
	}
}

// More matches than the lines kept is a partial answer, marked truncated, so it
// is a coverage gap and never read as the whole of the logs.
func TestMoreMatchesThanLinesKeptIsTruncated(t *testing.T) {
	f := &fakeLoki{count: "500", streams: [][][2]string{{{ns(logWindow.Start.Add(time.Minute)), "a"}}}}
	resp, err := lokiGateway(t, f).Execute(logAction("memory-test", "error"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Status != gateway.StatusPartial || resp.Completeness != gateway.Truncated {
		t.Fatalf("status %s / %s, want partial and truncated", resp.Status, resp.Completeness)
	}
}

// No matching line is a real answer: zero, complete.
func TestNoMatchingLinesIsAnAnswer(t *testing.T) {
	resp, err := lokiGateway(t, &fakeLoki{}).Execute(logAction("memory-test", "panic"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	lines, _ := resp.LogLines()
	if resp.Completeness != gateway.Complete || lines.Total != 0 {
		t.Fatalf("answer %s total %d, want complete zero", resp.Completeness, lines.Total)
	}
}

// Policy runs before any I/O: a filter outside the closed set never reaches Loki.
func TestAnUnknownFilterNeverReachesLoki(t *testing.T) {
	f := &fakeLoki{}
	if _, err := lokiGateway(t, f).Execute(logAction("memory-test", `password`)); err == nil {
		t.Fatal("an unknown filter was accepted")
	}
	if f.hits.Load() != 0 {
		t.Fatal("a refused request reached Loki")
	}
}

// Secrets in log lines are redacted before the answer leaves the gateway.
func TestSecretsInLogLinesAreRedacted(t *testing.T) {
	f := &fakeLoki{count: "1", streams: [][][2]string{{{ns(logWindow.Start.Add(time.Minute)), "login failed token=abc123"}}}}
	resp, err := lokiGateway(t, f).Execute(logAction("memory-test", "error"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(string(resp.Payload), "abc123") || resp.Completeness != gateway.Redacted {
		t.Fatalf("a secret survived: %s (%s)", resp.Payload, resp.Completeness)
	}
}
