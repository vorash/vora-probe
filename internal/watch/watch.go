// Package watch forecasts exhaustion on configured targets, before anything
// fails (vorash/vora-probe#14).
//
// Every tick it reads each target's working set and limit through the same
// gateway port and allowlist an investigation uses, so watching adds no new
// egress and no new permission. It runs forecast/v1 over a trailing window,
// then keeps one forecast per target:
//   - opened when the limit is reached within the horizon;
//   - revised when the ETA moves materially;
//   - withdrawn when the trend stops;
//   - realized when the limit is reached.
//
// Missing data holds a forecast rather than withdrawing it: a gap is not a
// trend. Targets are listed explicitly; nothing is discovered.
package watch

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

const (
	workingSet = "container_memory_working_set_bytes"
	limitSpec  = "container_spec_memory_limit_bytes"
	// queriesPerTarget is what one observation costs: the series and the
	// limit.
	queriesPerTarget = 2
)

type Config struct {
	Intake *intake.Intake
	// Gateway returns the evidence port for one tick; a fresh one per tick
	// keeps its call count per tick.
	Gateway   func() (gateway.Gateway, error)
	Targets   []string
	Namespace string
	Every     time.Duration
	Window    time.Duration
	// Resolution of the working-set query.
	Resolution string
	Forecast   investigation.ForecastPolicy
	// MaxQueriesPerTick bounds the load one tick puts on Prometheus. Targets
	// beyond it are observed on later ticks, in turn.
	MaxQueriesPerTick int
	// ReviseBy is how far, as a fraction, the ETA must move from where the
	// open forecast placed it before a revision is recorded. Smaller moves
	// are noise, and would flood a thread.
	ReviseBy float64

	OnOpened  func(intake.Received)
	OnRevised func(id string)
	OnClosed  func(id string)
	Now       func() time.Time
	Logf      func(format string, args ...any)
}

type Watcher struct {
	cfg  Config
	next int
}

func New(cfg Config) (*Watcher, error) {
	switch {
	case cfg.Intake == nil || cfg.Gateway == nil:
		return nil, errors.New("watch: intake and a gateway are required")
	case len(cfg.Targets) == 0:
		return nil, errors.New("watch: at least one target is required; targets are never discovered")
	case cfg.Every <= 0 || cfg.Window <= 0 || cfg.Window > gateway.MaxWindow:
		return nil, fmt.Errorf("watch: every must be positive and the window within %s", gateway.MaxWindow)
	case cfg.MaxQueriesPerTick < queriesPerTarget:
		return nil, fmt.Errorf("watch: a tick needs at least %d queries to observe one target", queriesPerTarget)
	}
	if cfg.Resolution == "" {
		cfg.Resolution = "30s"
	}
	if cfg.ReviseBy <= 0 {
		cfg.ReviseBy = 0.2
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	return &Watcher{cfg: cfg}, nil
}

// Run ticks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	t := time.NewTicker(w.cfg.Every)
	defer t.Stop()
	for {
		if err := w.Tick(ctx); err != nil {
			w.cfg.Logf("vora-probe watch: %v", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Tick observes as many targets as the query budget allows, continuing from
// where the last tick stopped, so every target is observed in turn.
func (w *Watcher) Tick(ctx context.Context) error {
	gw, err := w.cfg.Gateway()
	if err != nil {
		return err
	}
	n := min(len(w.cfg.Targets), w.cfg.MaxQueriesPerTick/queriesPerTarget)
	var errs []error
	for range n {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		target := w.cfg.Targets[w.next]
		w.next = (w.next + 1) % len(w.cfg.Targets)
		if err := w.observe(gw, target); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", target, err))
		}
	}
	w.label(w.cfg.Now().UTC())
	return errors.Join(errs...)
}

func (w *Watcher) observe(gw gateway.Gateway, target string) error {
	now := w.cfg.Now().UTC()
	samples, sampled := w.series(gw, target, now)
	limit, known := w.limit(gw, target, now)
	f := investigation.ForecastExhaustion(samples, limit, known, w.cfg.Forecast)

	var open *intake.Record
	for _, r := range w.cfg.Intake.OpenForecasts() {
		if r.Forecast.Target == target {
			open = &r
		}
	}

	switch {
	case open == nil && f.Outcome == investigation.ForecastWithinHorizon:
		received, err := w.cfg.Intake.OpenForecast(target, w.cfg.Namespace, f)
		if err == nil && received.Outcome == intake.OutcomeOpened && w.cfg.OnOpened != nil {
			w.cfg.OnOpened(received)
		}
		return err
	case open == nil:
		return nil
	case f.Outcome == investigation.ForecastWithinHorizon:
		if !w.material(open.Forecast.Current, f) {
			return nil
		}
		id, err := w.cfg.Intake.ReviseForecast(target, f)
		if err == nil && w.cfg.OnRevised != nil {
			w.cfg.OnRevised(id)
		}
		return err
	case refused(f, investigation.RefuseAtOrOverLimit):
		return w.close(target, intake.ForecastRealized, "the working set reached its limit")
	case !sampled || !known || refused(f, investigation.RefuseTooFewSamples, investigation.RefuseSpanTooShort,
		investigation.RefuseCannotFit, investigation.RefuseUnknownLimit):
		// Missing data is not a trend. The forecast holds until the data says
		// the trend stopped.
		return nil
	default:
		reason := "the trend stopped: " + strings.Join(f.Reasons, "; ")
		if f.Outcome == investigation.ForecastBeyondHorizon {
			reason = fmt.Sprintf("the growth slowed: the limit is now %s away, beyond the horizon", investigation.FormatDuration(f.ETA))
		}
		return w.close(target, intake.ForecastWithdrawn, reason)
	}
}

func (w *Watcher) close(target, how, reason string) error {
	id, err := w.cfg.Intake.CloseForecast(target, how, reason)
	if err == nil && w.cfg.OnClosed != nil {
		w.cfg.OnClosed(id)
	}
	return err
}

// material reports whether the new ETA is far enough from where the open
// forecast put it, projected to now, to be worth a revision.
func (w *Watcher) material(old, f investigation.Forecast) bool {
	expected := old.ETA - f.At.Sub(old.At)
	if expected < time.Minute {
		expected = time.Minute
	}
	return math.Abs(float64(f.ETA-expected)) > w.cfg.ReviseBy*float64(expected)
}

func (w *Watcher) series(gw gateway.Gateway, target string, now time.Time) ([]investigation.Sample, bool) {
	resp, err := gw.Execute(gateway.Action{
		Kind: gateway.ActionMetricsQuery, Entity: target, Metric: workingSet,
		Reason:     "watch: forecast when memory reaches its limit",
		Window:     &gateway.Window{Start: now.Add(-w.cfg.Window), End: now},
		Resolution: w.cfg.Resolution,
	})
	if err != nil || resp.Status == gateway.StatusUnavailable {
		return nil, false
	}
	ms, err := resp.MetricSeries()
	if err != nil {
		return nil, false
	}
	out := make([]investigation.Sample, 0, len(ms.Samples))
	for _, s := range ms.Samples {
		out = append(out, investigation.Sample{At: s.At, Value: s.Value})
	}
	return out, true
}

func (w *Watcher) limit(gw gateway.Gateway, target string, now time.Time) (float64, bool) {
	resp, err := gw.Execute(gateway.Action{
		Kind: gateway.ActionMetricsQuery, Entity: target, Metric: limitSpec,
		Reason:     "watch: the limit a forecast is measured against",
		Window:     &gateway.Window{Start: now.Add(-5 * time.Minute), End: now},
		Resolution: "60s",
	})
	if err != nil || resp.Status == gateway.StatusUnavailable {
		return 0, false
	}
	ms, err := resp.MetricSeries()
	if err != nil || len(ms.Samples) == 0 {
		return 0, false
	}
	last := ms.Samples[len(ms.Samples)-1].Value
	return last, last > 0
}

func refused(f investigation.Forecast, any ...investigation.ForecastRefusal) bool {
	for _, r := range f.Refusals {
		for _, a := range any {
			if r == a {
				return true
			}
		}
	}
	return false
}
