package live

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// maxLogLines bounds the lines one answer keeps. The count is exact; the lines
// are a bounded sample, and an answer with fewer lines than matches is marked
// truncated, so it becomes a coverage gap rather than evidence read as whole.
const maxLogLines = 200

// logQL builds the one query a logs.query may run: the entity's pods in the
// configured namespace, as the Prometheus mapping selects them, and the
// filter's fixed line matcher. Nothing in it comes from the model except the
// filter's name, which must be one of gateway.LogFilters.
func (g *Gateway) logQL(a gateway.Action) (string, error) {
	matcher, ok := gateway.LogFilters[a.Filter]
	if !ok {
		return "", &gateway.Denied{Reason: fmt.Sprintf("log filter %q has no live mapping", a.Filter)}
	}
	// A raw (backtick) string keeps the regex exactly as written; the fixed
	// matchers contain no backtick.
	return fmt.Sprintf("{namespace=%q, pod=~%q} |~ `%s`",
		g.cfg.Namespace, "^"+regexp.QuoteMeta(a.Entity)+"-.+", matcher), nil
}

func (g *Gateway) logs(a gateway.Action) (gateway.Response, error) {
	if strings.TrimSpace(g.cfg.LokiURL) == "" {
		// Without a log source the answer is a visible coverage gap. Denying
		// would end the run over evidence that is merely not collected here.
		return g.response(a, gateway.QueryMeta{Datasource: "loki"}, nil, gateway.StatusUnavailable, gateway.Unavailable,
			"no log source is configured for this lab")
	}
	query, err := g.logQL(a)
	if err != nil {
		return gateway.Response{}, err
	}
	meta := gateway.QueryMeta{Datasource: "loki", Query: query,
		Params: map[string]string{"filter": a.Filter, "namespace": g.cfg.Namespace}}

	total, err := g.lokiCount(query, a.Window)
	if err != nil {
		return gateway.Response{}, err
	}
	lines, err := g.lokiLines(query, a.Window)
	if err != nil {
		return gateway.Response{}, err
	}
	payload := gateway.LogLines{Filter: a.Filter, Total: total, Lines: lines}
	if len(lines) < total {
		payload.Truncated = true
		return g.response(a, meta, payload, gateway.StatusPartial, gateway.Truncated,
			fmt.Sprintf("%d lines matched; the first %d are retained", total, len(lines)))
	}
	return g.response(a, meta, payload, gateway.StatusOK, gateway.Complete, "")
}

// lokiCount is the exact number of matches over the window, from Loki's
// instant query (aggregations are not available on query_range for logs).
func (g *Gateway) lokiCount(query string, w *gateway.Window) (int, error) {
	span := w.End.Sub(w.Start).Round(time.Second)
	endpoint, err := url.Parse(strings.TrimRight(g.cfg.LokiURL, "/") + "/loki/api/v1/query")
	if err != nil {
		return 0, fmt.Errorf("live: loki URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("query", fmt.Sprintf("sum(count_over_time(%s [%ds]))", query, int(span.Seconds())))
	q.Set("time", strconv.FormatInt(w.End.UTC().UnixNano(), 10))
	endpoint.RawQuery = q.Encode()
	raw, err := g.get(endpoint.String(), nil, g.http)
	if err != nil {
		return 0, err
	}
	var answer struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value [2]json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return 0, fmt.Errorf("live: loki count: %w", err)
	}
	if answer.Status != "success" {
		return 0, fmt.Errorf("live: loki count status %q", answer.Status)
	}
	if len(answer.Data.Result) == 0 {
		// No matching line in the window: zero, a real answer.
		return 0, nil
	}
	var s string
	if err := json.Unmarshal(answer.Data.Result[0].Value[1], &s); err != nil {
		return 0, fmt.Errorf("live: loki count value: %w", err)
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("live: loki count value %q: %w", s, err)
	}
	return int(n), nil
}

// lokiLines are the first maxLogLines matches, oldest first, across streams.
func (g *Gateway) lokiLines(query string, w *gateway.Window) ([]gateway.LogLine, error) {
	endpoint, err := url.Parse(strings.TrimRight(g.cfg.LokiURL, "/") + "/loki/api/v1/query_range")
	if err != nil {
		return nil, fmt.Errorf("live: loki URL: %w", err)
	}
	q := endpoint.Query()
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(w.Start.UTC().UnixNano(), 10))
	q.Set("end", strconv.FormatInt(w.End.UTC().UnixNano(), 10))
	q.Set("limit", strconv.Itoa(maxLogLines))
	q.Set("direction", "forward")
	endpoint.RawQuery = q.Encode()
	raw, err := g.get(endpoint.String(), nil, g.http)
	if err != nil {
		return nil, err
	}
	var answer struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Values [][2]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, fmt.Errorf("live: loki lines: %w", err)
	}
	if answer.Status != "success" || answer.Data.ResultType != "streams" {
		return nil, fmt.Errorf("live: loki lines status %q, result type %q", answer.Status, answer.Data.ResultType)
	}
	var out []gateway.LogLine
	for _, stream := range answer.Data.Result {
		for _, v := range stream.Values {
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("live: loki timestamp %q: %w", v[0], err)
			}
			out = append(out, gateway.LogLine{At: time.Unix(0, ns).UTC(), Line: v[1]})
		}
	}
	// Streams arrive one after another; the lines are merged by time, so the
	// payload does not depend on how Loki happened to split them.
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	if len(out) > maxLogLines {
		out = out[:maxLogLines]
	}
	return out, nil
}
