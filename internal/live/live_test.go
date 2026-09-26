package live

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

var evalWindow = func() *gateway.Window {
	end := time.Date(2026, 9, 18, 17, 0, 0, 0, time.UTC)
	return &gateway.Window{Start: end.Add(-30 * time.Minute), End: end}
}()

func metricAction(metric, resolution string) gateway.Action {
	return gateway.Action{
		Kind: gateway.ActionMetricsQuery, Entity: "memory-test", Reason: "test",
		Metric: metric, Window: evalWindow, Resolution: resolution,
	}
}

func TestPromQLMappingIsATableNotASurface(t *testing.T) {
	g, err := New(Config{
		PrometheusURL: "http://prometheus.invalid",
		Kubernetes:    KubernetesConfig{Server: "http://k8s.invalid"},
		Namespace:     "probe-lab",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"container_memory_working_set_bytes": `container_memory_working_set_bytes{namespace="probe-lab",pod=~"^memory-test-.+",container="memory-test"}`,
		"container_spec_memory_limit_bytes":  `container_spec_memory_limit_bytes{namespace="probe-lab",pod=~"^memory-test-.+",container="memory-test"}`,
		"request_latency_p99_seconds":        `request_latency_p99_seconds{service="memory-test"}`,
		"request_error_rate":                 `request_error_rate{service="memory-test"}`,
		"db_query_count":                     `db_query_count{service="memory-test"}`,
	}
	for metric, expected := range want {
		query, _, err := g.promQL(metricAction(metric, "1m"))
		if err != nil {
			t.Fatalf("%s: %v", metric, err)
		}
		if query != expected {
			t.Errorf("%s:\n got %s\nwant %s", metric, query, expected)
		}
	}

	// The CPU ratio is a ratio against the container's own quota, so the policy
	// threshold means the same thing as it does for a fixture.
	query, unit, err := g.promQL(metricAction("container_cpu_usage_ratio", "1m"))
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"rate(container_cpu_usage_seconds_total", "container_spec_cpu_quota", "container_spec_cpu_period"} {
		if !strings.Contains(query, fragment) {
			t.Errorf("cpu ratio query %q is missing %q", query, fragment)
		}
	}
	if unit != "ratio" {
		t.Errorf("cpu ratio unit = %q, want ratio", unit)
	}

	// A metric with no mapping is denied, so the allowlist and the mapping have
	// to agree or nothing runs.
	if _, _, err := g.promQL(metricAction("process_open_fds", "1m")); !gateway.IsDenied(err) {
		t.Fatalf("an unmapped metric must be denied, got %v", err)
	}
}

func newGateway(t *testing.T, h http.Handler, tweak ...func(*Config)) *Gateway {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := Config{
		PrometheusURL: srv.URL,
		Kubernetes:    KubernetesConfig{Server: srv.URL, Token: "test-token"},
		Namespace:     "probe-lab",
	}
	for _, f := range tweak {
		f(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestMetricQueryIsMappedWindowedAndBounded(t *testing.T) {
	var got url.Values
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		got = r.URL.Query()
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"pod":"memory-test-abc"},
			"values":[[1789755392,"1048576"],[1789755407,"2097152"]]}]}}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(metricAction("container_memory_working_set_bytes", "15s"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Status != gateway.StatusOK || resp.Completeness != gateway.Complete {
		t.Fatalf("status/completeness = %s/%s, want ok/complete", resp.Status, resp.Completeness)
	}
	if got.Get("step") != "15s" {
		t.Errorf("step = %q, want 15s", got.Get("step"))
	}
	if got.Get("start") == "" || got.Get("end") == "" {
		t.Error("the request must carry an explicit window")
	}
	if got.Get("query") != `container_memory_working_set_bytes{namespace="probe-lab",pod=~"^memory-test-.+",container="memory-test"}` {
		t.Errorf("query = %q", got.Get("query"))
	}

	series, err := resp.MetricSeries()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if series.Unit != "bytes" || len(series.Samples) != 2 {
		t.Fatalf("series = %+v", series)
	}
	if series.Samples[1].Value != 2097152 {
		t.Errorf("second sample = %v, want 2097152", series.Samples[1].Value)
	}
	if !series.Samples[0].At.Equal(time.Unix(1789755392, 0).UTC()) {
		t.Errorf("sample time = %s", series.Samples[0].At)
	}
	// The digest identifies the bytes actually returned.
	if resp.Digest != gateway.Digest(resp.Payload) {
		t.Errorf("digest does not match payload")
	}
}

// A window with no series is missing evidence, not a zero. It must be reported
// unavailable so the claim that needed it is refused rather than fed a 0.
func TestEmptySeriesIsUnavailableNotZero(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(metricAction("container_memory_working_set_bytes", "15s"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Status != gateway.StatusUnavailable || resp.Completeness != gateway.Unavailable {
		t.Fatalf("status = %s/%s, want unavailable", resp.Status, resp.Completeness)
	}
	if resp.Payload != nil {
		t.Errorf("an unavailable answer must carry no payload, got %s", resp.Payload)
	}
	if resp.Reason == "" {
		t.Error("an unavailable answer must say why")
	}
}

func TestMultipleSeriesIsPartial(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"pod":"a"},"values":[[1789755392,"1"]]},
			{"metric":{"pod":"b"},"values":[[1789755392,"2"]]}]}}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(metricAction("container_memory_working_set_bytes", "15s"))
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Status != gateway.StatusPartial || resp.Completeness != gateway.Truncated {
		t.Fatalf("status = %s/%s, want partial/truncated", resp.Status, resp.Completeness)
	}
}

func TestContainersCarryTheTerminationReason(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/probe-lab/pods") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("labelSelector") != "app=memory-test" {
			t.Errorf("labelSelector = %q", r.URL.Query().Get("labelSelector"))
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("authorization header missing")
		}
		fmt.Fprint(w, `{"items":[{"metadata":{"name":"memory-test-abc","namespace":"probe-lab"},
			"spec":{"nodeName":"vora-mini"},
			"status":{"phase":"Running","startTime":"2026-09-18T16:00:00Z","containerStatuses":[
				{"name":"memory-test","ready":false,"restartCount":3,
				 "state":{"waiting":{"reason":"CrashLoopBackOff"}},
				 "lastState":{"terminated":{"reason":"OOMKilled","exitCode":137,"finishedAt":"2026-09-18T16:59:00Z"}}}]}}]}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "memory-test", Reason: "test"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	pods, err := resp.Pods()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(pods.Pods) != 1 || len(pods.Pods[0].Containers) != 1 {
		t.Fatalf("pods = %+v", pods)
	}
	c := pods.Pods[0].Containers[0]
	if c.State != "waiting" || c.Reason != "CrashLoopBackOff" {
		t.Errorf("state = %s/%s", c.State, c.Reason)
	}
	if c.LastTerminatedReason != "OOMKilled" {
		t.Fatalf("last terminated reason = %q, want OOMKilled", c.LastTerminatedReason)
	}
	if c.LastExitCode == nil || *c.LastExitCode != 137 {
		t.Errorf("last exit code = %v, want 137", c.LastExitCode)
	}
	if c.LastTerminatedAt == nil || !c.LastTerminatedAt.Equal(time.Date(2026, 9, 18, 16, 59, 0, 0, time.UTC)) {
		t.Errorf("last terminated at = %v", c.LastTerminatedAt)
	}
}

func TestEventsAreWindowed(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items":[
			{"type":"Warning","reason":"OOMKilling","message":"cgroup out of memory","count":2,
			 "firstTimestamp":"2026-09-18T16:50:00Z","lastTimestamp":"2026-09-18T16:58:00Z",
			 "involvedObject":{"kind":"Pod","name":"memory-test-abc"}},
			{"type":"Normal","reason":"Old","message":"long before the window","count":1,
			 "firstTimestamp":"2026-09-18T10:00:00Z","lastTimestamp":"2026-09-18T10:05:00Z",
			 "involvedObject":{"kind":"Pod","name":"other"}}]}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(gateway.Action{Kind: gateway.ActionKubernetesEvents, Entity: "memory-test", Reason: "test", Window: evalWindow})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	events, err := resp.Events()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(events.Events) != 1 {
		t.Fatalf("expected only the in-window event, got %d", len(events.Events))
	}
	if events.Events[0].Reason != "OOMKilling" || events.Events[0].InvolvedObject != "Pod/memory-test-abc" {
		t.Errorf("event = %+v", events.Events[0])
	}
}

func TestDeploymentRolloutTime(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/apis/apps/v1/namespaces/probe-lab/deployments") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		fmt.Fprint(w, `{"items":[{"metadata":{"name":"unrelated-api","namespace":"probe-lab","creationTimestamp":"2026-09-18T16:00:00Z"},
			"spec":{"template":{"spec":{"containers":[{"image":"img:1"}]}}},
			"status":{"replicas":1,"availableReplicas":1,"conditions":[
				{"type":"Progressing","status":"False","reason":"NewReplicaSetAvailable","lastUpdateTime":"2026-09-18T16:55:00Z"}]}}]}`)
	})
	g := newGateway(t, h)

	resp, err := g.Execute(gateway.Action{Kind: gateway.ActionKubernetesDeployments, Entity: "memory-test", Reason: "test"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	list, err := resp.Deployments()
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Deployments) != 1 {
		t.Fatalf("deployments = %+v", list)
	}
	d := list.Deployments[0]
	if d.Image != "img:1" {
		t.Errorf("image = %q", d.Image)
	}
	if !d.RolloutCompletedAt.Equal(time.Date(2026, 9, 18, 16, 55, 0, 0, time.UTC)) {
		t.Errorf("rollout completed at = %s, want 16:55", d.RolloutCompletedAt)
	}
}

// Policy runs before any I/O: a withdrawn or out-of-scope request must never
// reach a datasource.
func TestPolicyRunsBeforeAnyRequest(t *testing.T) {
	hit := 0
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit++ })
	g := newGateway(t, h, func(c *Config) {
		c.Policy = gateway.Policy{MaxResponseBytes: 1 << 20, AllowedEntities: []string{"memory-test"}}
	})

	// Out-of-scope entity.
	action := metricAction("container_memory_working_set_bytes", "15s")
	action.Entity = "someone-elses-service"
	if _, err := g.Execute(action); !gateway.IsDenied(err) {
		t.Fatalf("out-of-scope entity must be denied, got %v", err)
	}
	// Unmapped metric.
	bad := metricAction("process_open_fds", "15s")
	if _, err := g.Execute(bad); !gateway.IsDenied(err) {
		t.Fatalf("unmapped metric must be denied, got %v", err)
	}
	// A kind with no adapter.
	if _, err := g.Execute(gateway.Action{Kind: gateway.ActionKind("kubernetes.secrets"), Entity: "memory-test", Reason: "test"}); !gateway.IsDenied(err) {
		t.Fatalf("an unallowed kind must be denied, got %v", err)
	}
	if hit != 0 {
		t.Fatalf("policy must deny before any request, but the datasource was hit %d times", hit)
	}
}

func TestOversizedResponseIsRefused(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[1789755392,"1"]]}]},"padding":"`+strings.Repeat("x", 4096)+`"}`)
	})
	g := newGateway(t, h, func(c *Config) { c.Policy = gateway.Policy{MaxResponseBytes: 256} })

	if _, err := g.Execute(metricAction("container_memory_working_set_bytes", "15s")); err == nil {
		t.Fatal("an oversized response must be refused, not truncated")
	}
}

func TestUnavailableWhenNoPodsMatch(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items":[]}`)
	})
	g := newGateway(t, h)
	resp, err := g.Execute(gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "memory-test", Reason: "test"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if resp.Status != gateway.StatusUnavailable {
		t.Fatalf("status = %s, want unavailable", resp.Status)
	}
}

// A lab without a log source answers a logs request as unavailable, which
// becomes a visible coverage gap. Refusing it instead would end a run over
// evidence that is simply not collected here.
func TestNoLogSourceIsACoverageGapNotARefusal(t *testing.T) {
	gw := newGateway(t, http.NotFoundHandler())
	now := time.Now().UTC()
	a := gateway.Action{Kind: gateway.ActionLogsQuery, Entity: "memory-test", Reason: "read errors", Filter: "error",
		Window: &gateway.Window{Start: now.Add(-30 * time.Minute), End: now}}
	resp, err := gw.Execute(a)
	if err != nil {
		t.Fatalf("a logs request with no log source must be answered, not refused: %v", err)
	}
	if resp.Status != gateway.StatusUnavailable || resp.Completeness != gateway.Unavailable {
		t.Fatalf("status %q / %q, want unavailable", resp.Status, resp.Completeness)
	}
	o, err := investigation.ObservationFromResponse("OBS-0001", a, resp, now)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if facts := investigation.BuildFacts("memory-test", []investigation.Observation{o}); len(facts.Gaps) != 1 {
		t.Fatalf("gaps = %v, want the missing logs as one coverage gap", facts.Gaps)
	}
}
