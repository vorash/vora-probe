package gateway

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// PrometheusGraphURL links a human to the exact evidence an observation holds:
// the same query, over the same window, at the same resolution, in the
// Prometheus graph page at base. It is built by code from what the observation
// recorded, never from anything a model wrote. It returns "" for evidence that
// is not a Prometheus query, which has no graph to show.
//
// The parameters are those the Prometheus 2.x UI reads (g0.expr, g0.tab,
// g0.range_input, g0.end_input, g0.moment_input, g0.step_input), with times in
// UTC as "2006-01-02 15:04:05".
func PrometheusGraphURL(base string, q QueryMeta, w Window) string {
	if base == "" || q.Datasource != "prometheus" || q.Query == "" || !w.End.After(w.Start) {
		return ""
	}
	end := w.End.UTC().Format("2006-01-02 15:04:05")
	v := url.Values{}
	v.Set("g0.expr", q.Query)
	v.Set("g0.tab", "0")
	v.Set("g0.range_input", promDuration(w.End.Sub(w.Start)))
	v.Set("g0.end_input", end)
	v.Set("g0.moment_input", end)
	if step, err := time.ParseDuration(q.Resolution); err == nil && step >= time.Second {
		v.Set("g0.step_input", fmt.Sprint(int(step/time.Second)))
	}
	return strings.TrimRight(base, "/") + "/graph?" + v.Encode()
}

// promDuration renders a duration the way the UI parses it: hours, minutes and
// seconds, zero parts left out ("1h30m", "45s").
func promDuration(d time.Duration) string {
	d = d.Round(time.Second)
	var b strings.Builder
	if h := d / time.Hour; h > 0 {
		fmt.Fprintf(&b, "%dh", h)
		d -= h * time.Hour
	}
	if m := d / time.Minute; m > 0 {
		fmt.Fprintf(&b, "%dm", m)
		d -= m * time.Minute
	}
	if s := d / time.Second; s > 0 || b.Len() == 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	return b.String()
}
