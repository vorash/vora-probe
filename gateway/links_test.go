package gateway

import (
	"net/url"
	"testing"
	"time"
)

// A link must reproduce the evidence exactly: the recorded query, the recorded
// window and resolution, in the parameters the Prometheus UI reads. A link that
// showed a different window would let a reader check the wrong thing.
func TestAPrometheusLinkReproducesTheEvidence(t *testing.T) {
	q := QueryMeta{Datasource: "prometheus", Query: `container_memory_working_set_bytes{pod=~"memory-test-.+"}`, Resolution: "30s"}
	w := Window{Start: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC), End: time.Date(2026, 9, 18, 13, 30, 0, 0, time.UTC)}
	link := PrometheusGraphURL("http://prometheus.lab:9090/", q, w)
	u, err := url.Parse(link)
	if err != nil || u.Path != "/graph" || u.Host != "prometheus.lab:9090" {
		t.Fatalf("link %q is not the graph page", link)
	}
	got := u.Query()
	for key, want := range map[string]string{
		"g0.expr": q.Query, "g0.tab": "0", "g0.range_input": "1h30m",
		"g0.end_input": "2026-09-18 13:30:00", "g0.moment_input": "2026-09-18 13:30:00", "g0.step_input": "30",
	} {
		if got.Get(key) != want {
			t.Errorf("%s = %q, want %q", key, got.Get(key), want)
		}
	}
}

// Only a Prometheus query over a real window has a graph. Anything else gets no
// link rather than one that shows something other than the evidence.
func TestOnlyPrometheusEvidenceGetsALink(t *testing.T) {
	w := Window{Start: time.Now(), End: time.Now().Add(time.Minute)}
	for name, link := range map[string]string{
		"kubernetes": PrometheusGraphURL("http://p", QueryMeta{Datasource: "kubernetes", Query: "pods"}, w),
		"no base":    PrometheusGraphURL("", QueryMeta{Datasource: "prometheus", Query: "up"}, w),
		"snapshot":   PrometheusGraphURL("http://p", QueryMeta{Datasource: "prometheus", Query: "up"}, Window{Start: w.Start, End: w.Start}),
	} {
		if link != "" {
			t.Errorf("%s: got a link %q", name, link)
		}
	}
	if d := promDuration(45 * time.Second); d != "45s" {
		t.Errorf("45s rendered as %q", d)
	}
}
