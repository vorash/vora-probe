package investigation

import (
	"fmt"
	"sort"
	"strconv"
	"time"
)

// CalcVersion versions every derivation in this file. A report records the
// version it was produced with, so a numeric claim can always be recomputed.
const CalcVersion = "calc/v1"

// Sample is one timestamped measurement. Derived numbers are produced only from
// samples, never from text a model wrote.
type Sample struct {
	At    time.Time
	Value float64
}

// SeriesStats is the reproducible summary of a measurement series.
type SeriesStats struct {
	Count             int
	First             float64
	Last              float64
	Min               float64
	Max               float64
	Mean              float64
	FirstAt           time.Time
	LastAt            time.Time
	Span              time.Duration
	SlopePerSecond    float64
	MonotonicIncrease bool
}

// Summarize sorts a copy of the samples before computing, so the result depends
// on the data and not on the order a tool happened to return it in.
func Summarize(in []Sample) (SeriesStats, error) {
	if len(in) == 0 {
		return SeriesStats{}, fmt.Errorf("cannot summarize an empty series")
	}
	s := append([]Sample(nil), in...)
	sort.SliceStable(s, func(i, j int) bool { return s[i].At.Before(s[j].At) })

	st := SeriesStats{
		Count:   len(s),
		First:   s[0].Value,
		Last:    s[len(s)-1].Value,
		Min:     s[0].Value,
		Max:     s[0].Value,
		FirstAt: s[0].At.UTC(),
		LastAt:  s[len(s)-1].At.UTC(),
	}
	st.Span = st.LastAt.Sub(st.FirstAt)

	var sum float64
	monotonic := true
	for i, v := range s {
		sum += v.Value
		if v.Value < st.Min {
			st.Min = v.Value
		}
		if v.Value > st.Max {
			st.Max = v.Value
		}
		if i > 0 && v.Value <= s[i-1].Value {
			monotonic = false
		}
	}
	st.Mean = sum / float64(len(s))
	st.MonotonicIncrease = monotonic
	st.SlopePerSecond = slopePerSecond(s)
	return st, nil
}

// slopePerSecond is the ordinary least squares slope against elapsed seconds.
// The elapsed axis is anchored at the first sample so the result does not
// depend on the absolute epoch.
func slopePerSecond(s []Sample) float64 {
	origin := s[0].At
	var sx, sy, sxy, sxx float64
	for _, v := range s {
		x := v.At.Sub(origin).Seconds()
		y := v.Value
		sx += x
		sy += y
		sxy += x * y
		sxx += x * x
	}
	n := float64(len(s))
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	return (n*sxy - sx*sy) / den
}

// Ratio is last/first. A zero baseline has no meaningful ratio, so it reports 0
// rather than infinity.
func (s SeriesStats) Ratio() float64 {
	if s.First == 0 {
		return 0
	}
	return s.Last / s.First
}

// Delta is the signed distance from a to b.
func Delta(a, b time.Time) time.Duration { return b.Sub(a) }

// RestartDelta is the change in restart count between two readings.
func RestartDelta(first, last int) int { return last - first }

// WithinProximity reports whether two instants are close enough for temporal
// proximity to even be worth mentioning. Proximity is never sufficient on its
// own: see ClaimPolicy.
func WithinProximity(a, b time.Time, max time.Duration) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= max
}

// PercentChange is (to-from)/from as a percentage, or 0 when from is zero.
func PercentChange(from, to float64) float64 {
	if from == 0 {
		return 0
	}
	return (to - from) / from * 100
}

// FormatFloat renders a number with a fixed precision so reports and fixtures
// are byte-identical across runs.
func FormatFloat(v float64, prec int) string {
	return strconv.FormatFloat(v, 'f', prec, 64)
}

// FormatBytes renders a byte quantity in binary units.
func FormatBytes(v float64) string {
	const unit = 1024.0
	switch {
	case v >= unit*unit*unit:
		return FormatFloat(v/(unit*unit*unit), 2) + " GiB"
	case v >= unit*unit:
		return FormatFloat(v/(unit*unit), 1) + " MiB"
	case v >= unit:
		return FormatFloat(v/unit, 1) + " KiB"
	default:
		return FormatFloat(v, 0) + " B"
	}
}

// FormatDuration renders a duration at second resolution.
func FormatDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}
