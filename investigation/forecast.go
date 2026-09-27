package investigation

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Foresight: when will a bounded resource reach its limit?
//
// A forecast is computed by code, never by a model, and it is a hypothesis about
// the future, so it is held to the same standard as any other claim: it is made
// only when the data supports it, and otherwise refused with every reason that
// applies. A refusal is a result, not an error. The interval comes from the
// spread of the fit, and it is a band of plausible crossings, never a
// probability.

// ForecastVersion versions the derivation and its refusal rules. It is separate
// from calc/v1 so the forecast can be tuned without changing a single existing
// report.
const ForecastVersion = "forecast/v1"

// ForecastPolicy holds the thresholds a series must meet before a forecast is
// made. The defaults were set on the development split of the recorded lab
// scenarios and frozen before the held-out split was scored
// (vorash/vora-probe#14); TestTheForecastThresholdsAreFrozen pins them.
type ForecastPolicy struct {
	// MinSamples and MinSpan: a trend drawn through a handful of points, or
	// through a few minutes, is noise.
	MinSamples int
	MinSpan    time.Duration
	// MinR2 is the fit quality below which the series is not a trend, the
	// signature of a sawtooth or a garbage-collection cycle.
	MinR2 float64
	// ResetDrop is the fraction of its previous value a sample may fall by
	// before the fall counts as a reset (a restart) inside the window, which
	// makes one line through the window meaningless.
	ResetDrop float64
	// Spread is the interval's half-width in standard errors.
	Spread float64
	// Horizon: a crossing further out than this is not forecast.
	Horizon time.Duration
}

func DefaultForecastPolicy() ForecastPolicy {
	return ForecastPolicy{
		MinSamples: 10,
		MinSpan:    10 * time.Minute,
		MinR2:      0.8,
		ResetDrop:  0.5,
		Spread:     2,
		Horizon:    2 * time.Hour,
	}
}

// ForecastOutcome is what the derivation concluded.
type ForecastOutcome string

const (
	// ForecastWithinHorizon: the limit is reached within the horizon if the
	// current growth persists.
	ForecastWithinHorizon ForecastOutcome = "within_horizon"
	// ForecastBeyondHorizon: the growth is real but the crossing is further
	// out than the horizon. Nothing is raised.
	ForecastBeyondHorizon ForecastOutcome = "beyond_horizon"
	// ForecastRefused: the data does not support a forecast. See Refusals.
	ForecastRefused ForecastOutcome = "refused"
)

// ForecastRefusal names one reason a forecast was not made.
type ForecastRefusal string

const (
	RefuseUnknownLimit  ForecastRefusal = "unknown_limit"
	RefuseTooFewSamples ForecastRefusal = "too_few_samples"
	RefuseSpanTooShort  ForecastRefusal = "span_too_short"
	RefuseResetInWindow ForecastRefusal = "reset_in_window"
	RefuseNotGrowing    ForecastRefusal = "not_growing"
	RefusePoorFit       ForecastRefusal = "poor_fit"
	RefuseAtOrOverLimit ForecastRefusal = "at_or_over_limit"
	RefuseCannotFit     ForecastRefusal = "cannot_fit"
)

// Forecast is the reproducible result. Every number in it is derived from the
// samples and the limit alone.
type Forecast struct {
	Version  string            `json:"version"`
	Outcome  ForecastOutcome   `json:"outcome"`
	Refusals []ForecastRefusal `json:"refusals,omitempty"`
	// Reasons explain each refusal with the numbers behind it.
	Reasons []string `json:"reasons,omitempty"`

	Samples int           `json:"samples"`
	Span    time.Duration `json:"span"`
	// At is the last sample: every duration below is measured from it.
	At    time.Time `json:"at"`
	Limit float64   `json:"limit,omitempty"`

	SlopePerSecond float64 `json:"slope_per_second"`
	SlopeStdErr    float64 `json:"slope_std_err"`
	R2             float64 `json:"r2"`
	ResidualStdDev float64 `json:"residual_std_dev"`
	// Level is the fitted value at At.
	Level float64 `json:"level"`

	// ETA is the point estimate of the time from At to the limit; Earliest and
	// Latest are where the fit's Spread-standard-error confidence band meets
	// the limit. A band, not a probability.
	ETA      time.Duration `json:"eta,omitempty"`
	Earliest time.Duration `json:"earliest,omitempty"`
	Latest   time.Duration `json:"latest,omitempty"`
}

// ForecastExhaustion forecasts when a series reaches limit. limitKnown is
// separate from the value on purpose: a limit that was not collected is not a
// limit of zero.
func ForecastExhaustion(in []Sample, limit float64, limitKnown bool, p ForecastPolicy) Forecast {
	s := append([]Sample(nil), in...)
	sort.SliceStable(s, func(i, j int) bool { return s[i].At.Before(s[j].At) })

	f := Forecast{Version: ForecastVersion, Samples: len(s)}
	if limitKnown {
		f.Limit = limit
	}
	refuse := func(r ForecastRefusal, format string, args ...any) {
		f.Refusals = append(f.Refusals, r)
		f.Reasons = append(f.Reasons, fmt.Sprintf(format, args...))
	}

	if !limitKnown || limit <= 0 {
		refuse(RefuseUnknownLimit, "the limit is unknown, so there is nothing to forecast a crossing of")
	}
	if len(s) < p.MinSamples {
		refuse(RefuseTooFewSamples, "%d samples, fewer than the %d a trend needs", len(s), p.MinSamples)
	}
	if len(s) < 3 {
		// A line and its residual spread need at least three points; with
		// fewer there is no fit to report at all.
		refuse(RefuseCannotFit, "%d samples cannot be fitted", len(s))
		f.Outcome = ForecastRefused
		return f
	}
	f.At = s[len(s)-1].At.UTC()
	f.Span = f.At.Sub(s[0].At)
	if f.Span < p.MinSpan {
		refuse(RefuseSpanTooShort, "the series spans %s, shorter than the %s a trend needs", FormatDuration(f.Span), FormatDuration(p.MinSpan))
	}
	for i := 1; i < len(s); i++ {
		prev := s[i-1].Value
		if prev > 0 && (prev-s[i].Value)/prev > p.ResetDrop {
			refuse(RefuseResetInWindow, "the series falls from %s to %s at %s, a reset inside the window",
				FormatFloat(prev, 0), FormatFloat(s[i].Value, 0), s[i].At.UTC().Format(time.RFC3339))
			break
		}
	}

	fit := fitLine(s)
	f.SlopePerSecond, f.SlopeStdErr, f.R2, f.ResidualStdDev = fit.slope, fit.slopeErr, fit.r2, fit.residual
	f.Level = fit.at(f.At)

	switch {
	case fit.slope <= 0:
		refuse(RefuseNotGrowing, "the series is not growing (slope %s per second)", FormatFloat(fit.slope, 6))
	case fit.slope-p.Spread*fit.slopeErr <= 0:
		refuse(RefuseNotGrowing, "the growth (slope %s ± %s per second) is not distinguishable from none",
			FormatFloat(fit.slope, 6), FormatFloat(p.Spread*fit.slopeErr, 6))
	}
	if fit.r2 < p.MinR2 {
		refuse(RefusePoorFit, "a line explains %s%% of the variation, below the %s%% a trend needs; the series cycles rather than grows",
			FormatFloat(fit.r2*100, 0), FormatFloat(p.MinR2*100, 0))
	}
	if limitKnown && limit > 0 && (f.Level >= limit || s[len(s)-1].Value >= limit) {
		refuse(RefuseAtOrOverLimit, "the series is already at or over its limit: this is exhaustion, not a forecast")
	}
	if len(f.Refusals) > 0 {
		f.Outcome = ForecastRefused
		return f
	}

	// The band is where the fit's confidence band meets the limit: the upper
	// edge, ŷ(t) + k·s·√(1/n + (t−t̄)²/Sxx), gives the earliest crossing and the
	// lower edge the latest. Both are roots of one quadratic, and the latest
	// exists exactly when the slope is distinguishable from zero, the
	// condition refused above. With no residual spread it is the point
	// estimate.
	earliest, latest := fit.band(limit, p.Spread)
	sinceMean := f.At.Sub(fit.origin).Seconds() - fit.meanX
	f.ETA = seconds((limit - f.Level) / fit.slope)
	f.Earliest = seconds(math.Max(0, earliest-sinceMean))
	f.Latest = seconds(latest - sinceMean)
	f.Outcome = ForecastWithinHorizon
	if f.ETA > p.Horizon {
		f.Outcome = ForecastBeyondHorizon
	}
	return f
}

// Statement renders a forecast the only way it may be stated: conditionally.
// It says when the limit is reached if the growth persists, never that the
// service will fail.
func (f Forecast) Statement() string {
	switch f.Outcome {
	case ForecastWithinHorizon, ForecastBeyondHorizon:
		return fmt.Sprintf("at the current rate of growth the series reaches its limit of %s in %s (between %s and %s) if the growth persists",
			FormatFloat(f.Limit, 0), FormatDuration(f.ETA), FormatDuration(f.Earliest), FormatDuration(f.Latest))
	default:
		return "no forecast: the series does not support one"
	}
}

type line struct {
	origin   time.Time
	n        float64
	meanX    float64
	meanY    float64
	sxx      float64
	slope    float64
	icept    float64
	slopeErr float64
	r2       float64
	residual float64
}

// band returns, in seconds from the mean sample time, where the lower and upper
// edges of the fit's k-standard-error confidence band reach level. It solves
// (b² − c²)u² − 2·b·d·u + d² − k²s²/n = 0 with d = level − ȳ and c = k·SE(b).
func (l line) band(level, k float64) (earliest, latest float64) {
	d := level - l.meanY
	c2 := k * k * l.residual * l.residual / l.sxx
	a := l.slope*l.slope - c2
	disc := c2*d*d + a*k*k*l.residual*l.residual/l.n
	root := math.Sqrt(math.Max(0, disc))
	return (l.slope*d - root) / a, (l.slope*d + root) / a
}

func (l line) at(t time.Time) float64 { return l.icept + l.slope*t.Sub(l.origin).Seconds() }

// fitLine is ordinary least squares against seconds since the first sample,
// with the slope's standard error and the residual standard deviation on n-2
// degrees of freedom. A series with no spread in time or value is reported as
// flat with a perfect fit, which the slope check then refuses.
func fitLine(s []Sample) line {
	origin := s[0].At
	n := float64(len(s))
	var mx, my float64
	for _, v := range s {
		mx += v.At.Sub(origin).Seconds()
		my += v.Value
	}
	mx /= n
	my /= n
	var sxx, sxy, syy float64
	for _, v := range s {
		dx := v.At.Sub(origin).Seconds() - mx
		dy := v.Value - my
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	l := line{origin: origin, n: n, meanX: mx, meanY: my, sxx: sxx}
	if sxx == 0 {
		l.icept = my
		return l
	}
	l.slope = sxy / sxx
	l.icept = my - l.slope*mx
	var sse float64
	for _, v := range s {
		r := v.Value - l.at(v.At)
		sse += r * r
	}
	l.r2 = 1
	if syy > 0 {
		l.r2 = 1 - sse/syy
	}
	l.residual = math.Sqrt(sse / (n - 2))
	l.slopeErr = l.residual / math.Sqrt(sxx)
	return l
}

// seconds converts to a duration, saturating: a crossing centuries away is
// beyond any horizon, and must not overflow into a negative duration.
func seconds(v float64) time.Duration {
	const max = float64(math.MaxInt64 / int64(time.Second))
	if v >= max {
		return time.Duration(math.MaxInt64 / int64(time.Second) * int64(time.Second))
	}
	return time.Duration(math.Round(v)) * time.Second
}
