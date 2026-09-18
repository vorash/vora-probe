package live

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// promQL maps a requested metric onto exactly one query. This is the metric
// mapping the plan requires: a lookup table, not a query language. A metric with
// no entry is denied rather than passed through, so the allowlist and the
// mapping have to agree or nothing runs.
func (g *Gateway) promQL(a gateway.Action) (string, string, error) {
	ns := g.cfg.Namespace
	// A pod belongs to the service when it carries the service's name as its
	// app label, which the lab's manifests guarantee.
	container := func(metric string) string {
		return fmt.Sprintf(`%s{namespace=%q,pod=~%q,container=%q}`,
			metric, ns, "^"+regexp.QuoteMeta(a.Entity)+"-.+", a.Entity)
	}
	switch a.Metric {
	case "container_memory_working_set_bytes":
		return container("container_memory_working_set_bytes"), "bytes", nil
	case "container_spec_memory_limit_bytes":
		return container("container_spec_memory_limit_bytes"), "bytes", nil
	case "container_cpu_usage_ratio":
		// A ratio, not cores: usage over the container's own quota, so the
		// claims policy's 0.85 threshold means the same thing everywhere.
		return fmt.Sprintf(`rate(%s[%s]) / (%s / %s)`,
			container("container_cpu_usage_seconds_total"), a.Resolution,
			container("container_spec_cpu_quota"), container("container_spec_cpu_period")), "ratio", nil
	case "request_latency_p99_seconds":
		return fmt.Sprintf(`request_latency_p99_seconds{service=%q}`, a.Entity), "seconds", nil
	case "request_error_rate":
		return fmt.Sprintf(`request_error_rate{service=%q}`, a.Entity), "ratio", nil
	case "db_query_count":
		return fmt.Sprintf(`db_query_count{service=%q}`, a.Entity), "count", nil
	default:
		return "", "", &gateway.Denied{Reason: fmt.Sprintf("metric %q has no live mapping", a.Metric)}
	}
}

func (g *Gateway) metricSeries(a gateway.Action) (gateway.Response, error) {
	query, unit, err := g.promQL(a)
	if err != nil {
		return gateway.Response{}, err
	}
	meta := gateway.QueryMeta{
		Datasource: "prometheus",
		Query:      query,
		Params:     map[string]string{"metric": a.Metric, "namespace": g.cfg.Namespace},
		Resolution: a.Resolution,
	}

	samples, found, partial, err := g.queryRange(a, query)
	if err != nil {
		return gateway.Response{}, err
	}
	if !found {
		// No series is a real answer: the evidence is missing, and it is
		// reported as missing rather than as a zero.
		return g.response(a, meta, nil, gateway.StatusUnavailable, gateway.Unavailable,
			"no series matched the requested window")
	}
	payload := gateway.MetricSeries{Metric: a.Metric, Unit: unit, Samples: samples}
	if partial {
		return g.response(a, meta, payload, gateway.StatusPartial, gateway.Truncated,
			"more than one series matched; the first is retained and the answer is marked partial")
	}
	return g.response(a, meta, payload, gateway.StatusOK, gateway.Complete, "")
}

// promRange is the subset of Prometheus's query_range response Probe reads.
type promRange struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string    `json:"metric"`
			Values [][2]json.RawMessage `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

func (g *Gateway) queryRange(a gateway.Action, query string) (samples []gateway.MetricSample, found, partial bool, err error) {
	endpoint, err := url.Parse(strings.TrimRight(g.cfg.PrometheusURL, "/") + "/api/v1/query_range")
	if err != nil {
		return nil, false, false, fmt.Errorf("live: prometheus URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(a.Window.Start.UTC().Unix(), 10))
	q.Set("end", strconv.FormatInt(a.Window.End.UTC().Unix(), 10))
	q.Set("step", a.Resolution)
	endpoint.RawQuery = q.Encode()

	raw, err := g.get(endpoint.String(), nil, g.http)
	if err != nil {
		return nil, false, false, err
	}
	var parsed promRange
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, false, false, fmt.Errorf("live: prometheus response is not valid JSON: %w", err)
	}
	if parsed.Status != "success" {
		return nil, false, false, fmt.Errorf("live: prometheus query failed: %s", strings.TrimSpace(parsed.Error))
	}
	if len(parsed.Data.Result) == 0 {
		return nil, false, false, nil
	}
	if parsed.Data.ResultType != "matrix" {
		return nil, false, false, fmt.Errorf("live: prometheus returned %q, want a matrix", parsed.Data.ResultType)
	}
	samples, err = parseSamples(parsed.Data.Result[0].Values)
	if err != nil {
		return nil, false, false, err
	}
	return samples, true, len(parsed.Data.Result) > 1, nil
}

func parseSamples(values [][2]json.RawMessage) ([]gateway.MetricSample, error) {
	out := make([]gateway.MetricSample, 0, len(values))
	for _, pair := range values {
		var seconds float64
		if err := json.Unmarshal(pair[0], &seconds); err != nil {
			return nil, fmt.Errorf("live: sample timestamp: %w", err)
		}
		var text string
		if err := json.Unmarshal(pair[1], &text); err != nil {
			return nil, fmt.Errorf("live: sample value: %w", err)
		}
		value, err := strconv.ParseFloat(text, 64)
		if err != nil {
			// A NaN/Inf string is real Prometheus output for an undefined
			// result. It is kept, because dropping it would silently reshape the
			// series the claims policy reads.
			if text == "NaN" {
				value = math.NaN()
			} else if text == "+Inf" {
				value = math.Inf(1)
			} else if text == "-Inf" {
				value = math.Inf(-1)
			} else {
				return nil, fmt.Errorf("live: sample value %q: %w", text, err)
			}
		}
		whole := math.Floor(seconds)
		out = append(out, gateway.MetricSample{
			At:    time.Unix(int64(whole), int64((seconds-whole)*1e9)).UTC(),
			Value: value,
		})
	}
	return out, nil
}

// get performs a bounded GET. Every response is read under the policy's size
// limit, because an unbounded read is how a datasource turns into a memory
// problem.
func (g *Gateway) get(rawURL string, headers map[string]string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limit := g.cfg.Policy.MaxResponseBytes
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("live: response exceeds the %d byte limit", limit)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("live: %s returned %d: %s", rawURL, resp.StatusCode, snippet(raw))
	}
	return raw, nil
}

func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
