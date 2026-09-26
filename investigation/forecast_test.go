package investigation_test

import (
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/investigation"
)

const mib = 1 << 20

var t0 = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// series is n samples one step apart, valued by f.
func series(n int, step time.Duration, f func(i int) float64) []investigation.Sample {
	out := make([]investigation.Sample, n)
	for i := range out {
		out[i] = investigation.Sample{At: t0.Add(time.Duration(i) * step), Value: f(i)}
	}
	return out
}

// A steady ramp toward a known limit is the case foresight exists for. With no
// noise the crossing is exact, and the band around it has no width.
func TestASteadyRampIsForecastExactly(t *testing.T) {
	ramp := series(30, time.Minute, func(i int) float64 { return 100*mib + float64(i)*mib })
	f := investigation.ForecastExhaustion(ramp, 200*mib, true, investigation.DefaultForecastPolicy())
	if f.Outcome != investigation.ForecastWithinHorizon {
		t.Fatalf("outcome %q (%v), want within the horizon", f.Outcome, f.Reasons)
	}
	// Level 129 MiB at the last sample, 71 MiB of headroom at 1 MiB a minute.
	if f.ETA != 71*time.Minute || f.Earliest != f.ETA || f.Latest != f.ETA {
		t.Fatalf("eta %s (%s..%s), want exactly 71m with no spread", f.ETA, f.Earliest, f.Latest)
	}
	if f.Version != investigation.ForecastVersion || math.Abs(f.R2-1) > 1e-9 {
		t.Fatalf("version %q r2 %v", f.Version, f.R2)
	}
	if !strings.Contains(f.Statement(), "if the growth persists") {
		t.Fatalf("a forecast must be stated conditionally: %q", f.Statement())
	}
}

// The band must contain the true crossing, and it must tighten as evidence
// accumulates: that is what makes an early forecast worth sending and a late
// one worth trusting more.
func TestTheBandHoldsTheCrossingAndTightensWithMoreData(t *testing.T) {
	// 1 MiB a minute from 100 MiB, with a repeating ±3 MiB wobble; the true
	// line reaches 260 MiB at minute 160.
	truth := t0.Add(160 * time.Minute)
	wobble := []float64{3, -2, 1, -3, 2, 0, -1}
	noisy := series(90, time.Minute, func(i int) float64 {
		return 100*mib + float64(i)*mib + wobble[i%len(wobble)]*mib
	})
	policy := investigation.DefaultForecastPolicy()
	policy.Horizon = 4 * time.Hour

	var widths []time.Duration
	for _, n := range []int{20, 45, 90} {
		f := investigation.ForecastExhaustion(noisy[:n], 260*mib, true, policy)
		if f.Outcome != investigation.ForecastWithinHorizon {
			t.Fatalf("n=%d: outcome %q (%v)", n, f.Outcome, f.Reasons)
		}
		crossing := truth.Sub(f.At)
		if crossing < f.Earliest || crossing > f.Latest {
			t.Fatalf("n=%d: the true crossing in %s is outside the band %s..%s", n, crossing, f.Earliest, f.Latest)
		}
		widths = append(widths, f.Latest-f.Earliest)
	}
	if !(widths[0] > widths[1] && widths[1] > widths[2]) {
		t.Fatalf("band widths %v, want them to tighten as samples accumulate", widths)
	}
}

// Growth that will not reach the limit within the horizon is real, but raising
// it now would be noise.
func TestSlowGrowthIsBeyondTheHorizon(t *testing.T) {
	slow := series(60, time.Minute, func(i int) float64 { return 100*mib + float64(i)*mib/100 })
	f := investigation.ForecastExhaustion(slow, 256*mib, true, investigation.DefaultForecastPolicy())
	if f.Outcome != investigation.ForecastBeyondHorizon || f.ETA <= 2*time.Hour {
		t.Fatalf("outcome %q eta %s, want beyond the 2h horizon", f.Outcome, f.ETA)
	}
	glacial := series(60, time.Minute, func(i int) float64 { return 100*mib + float64(i)*1e-6 })
	if g := investigation.ForecastExhaustion(glacial, 256*mib, true, investigation.DefaultForecastPolicy()); g.ETA <= 0 {
		t.Fatalf("a crossing centuries away must saturate, not overflow: eta %s", g.ETA)
	}
}

// Each refusal is a case where a trend line would be drawn through data that
// does not support one. Every one must stay a refusal, with its reason.
func TestForecastsAreRefusedWhenTheDataDoesNotSupportThem(t *testing.T) {
	ramp := func(n int, step time.Duration) []investigation.Sample {
		return series(n, step, func(i int) float64 { return 100*mib + float64(i)*mib })
	}
	// The relation suite's kill-and-restart shape: it rises, is killed, and
	// starts again low.
	killed := []float64{188743680, 204472320, 251658240, 429916160, 553648128, 190840832, 209715200,
		230000000, 250000000, 270000000}
	// A garbage-collection sawtooth: climbs 40 MiB, collects back, over and
	// over, never trending.
	sawtooth := series(40, time.Minute, func(i int) float64 { return 150*mib + float64(i%8)*5*mib })
	// A step: flat, then a sudden jump just short of the limit.
	step := series(30, time.Minute, func(i int) float64 {
		if i == 29 {
			return 250 * mib
		}
		return 100 * mib
	})
	// A real but tiny upward trend under large noise. The noise is mirrored
	// about the middle of the window, so it adds nothing to the fitted slope:
	// the fit sees exactly the positive trend, and must still refuse it as
	// indistinguishable from none.
	half := []float64{4, -4, 3, -3, 2, -2, 1, -1, 4, -4, 3, -3, 2, -2, 1}
	noise := append(slices.Clone(half), half...)
	slices.Reverse(noise[len(half):])
	lostInNoise := series(30, time.Minute, func(i int) float64 {
		return 100*mib + float64(i)*mib/20 + noise[i]*mib
	})

	cases := []struct {
		name    string
		samples []investigation.Sample
		limit   float64
		known   bool
		want    investigation.ForecastRefusal
	}{
		{"limit not collected", ramp(30, time.Minute), 0, false, investigation.RefuseUnknownLimit},
		{"too few samples", ramp(5, 5*time.Minute), 200 * mib, true, investigation.RefuseTooFewSamples},
		{"span too short", ramp(20, 5*time.Second), 200 * mib, true, investigation.RefuseSpanTooShort},
		{"cannot fit", ramp(2, 10*time.Minute), 200 * mib, true, investigation.RefuseCannotFit},
		{"flat", series(30, time.Minute, func(int) float64 { return 100 * mib }), 200 * mib, true, investigation.RefuseNotGrowing},
		{"shrinking", series(30, time.Minute, func(i int) float64 { return 200*mib - float64(i)*mib }), 256 * mib, true, investigation.RefuseNotGrowing},
		{"growth lost in the noise", lostInNoise, 200 * mib, true, investigation.RefuseNotGrowing},
		{"sawtooth", sawtooth, 256 * mib, true, investigation.RefusePoorFit},
		{"reset inside the window", series(len(killed), 5*time.Minute, func(i int) float64 { return killed[i] }), 600 * mib, true, investigation.RefuseResetInWindow},
		{"step change", step, 256 * mib, true, investigation.RefusePoorFit},
		{"already at the limit", ramp(30, time.Minute), 120 * mib, true, investigation.RefuseAtOrOverLimit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := investigation.ForecastExhaustion(c.samples, c.limit, c.known, investigation.DefaultForecastPolicy())
			if f.Outcome != investigation.ForecastRefused {
				t.Fatalf("outcome %q (eta %s), want refused", f.Outcome, f.ETA)
			}
			if !slices.Contains(f.Refusals, c.want) {
				t.Fatalf("refusals %v, want %s among them", f.Refusals, c.want)
			}
			if len(f.Reasons) != len(f.Refusals) {
				t.Fatalf("every refusal needs its reason: %v / %v", f.Refusals, f.Reasons)
			}
			if f.ETA != 0 || f.Earliest != 0 || f.Latest != 0 {
				t.Fatal("a refused forecast must claim no lead time")
			}
			if strings.Contains(f.Statement(), "reaches its limit") {
				t.Fatalf("a refused forecast must not read as one: %q", f.Statement())
			}
		})
	}
}

// A reader deciding whether to trust a refusal needs all of its reasons, not
// the first one found.
func TestEveryRefusalIsReported(t *testing.T) {
	few := series(4, time.Minute, func(i int) float64 { return float64(100 - i) })
	f := investigation.ForecastExhaustion(few, 0, false, investigation.DefaultForecastPolicy())
	for _, want := range []investigation.ForecastRefusal{
		investigation.RefuseUnknownLimit, investigation.RefuseTooFewSamples,
		investigation.RefuseSpanTooShort, investigation.RefuseNotGrowing,
	} {
		if !slices.Contains(f.Refusals, want) {
			t.Errorf("refusals %v, missing %s", f.Refusals, want)
		}
	}
}

func TestTheForecastIsOrderIndependent(t *testing.T) {
	ramp := series(30, time.Minute, func(i int) float64 { return 100*mib + float64(i)*mib + float64(i%3)*mib/4 })
	shuffled := append([]investigation.Sample(nil), ramp...)
	for i := range shuffled {
		j := (i * 7) % len(shuffled)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	policy := investigation.DefaultForecastPolicy()
	a := investigation.ForecastExhaustion(ramp, 200*mib, true, policy)
	b := investigation.ForecastExhaustion(shuffled, 200*mib, true, policy)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("forecasts differ by input order:\n%+v\n%+v", a, b)
	}
}

// The band is defined as where the fit's confidence band meets the limit: the
// upper edge ŷ(t) + k·s·√(1/n + (t−t̄)²/Sxx) at the earliest crossing, the lower
// edge at the latest. This recomputes the fit independently and checks the
// definition at both ends, to the second, so neither the level nor the slope
// uncertainty can be dropped from the band without failing.
func TestTheBandIsWhereTheConfidenceBandMeetsTheLimit(t *testing.T) {
	wobble := []float64{3, -2, 1, -3, 2, 0, -1}
	noisy := series(25, time.Minute, func(i int) float64 {
		return 100*mib + float64(i)*mib + wobble[i%len(wobble)]*mib
	})
	limit := 160.0 * mib
	policy := investigation.DefaultForecastPolicy()
	f := investigation.ForecastExhaustion(noisy, limit, true, policy)
	if f.Outcome != investigation.ForecastWithinHorizon {
		t.Fatalf("outcome %q (%v)", f.Outcome, f.Reasons)
	}

	n := float64(len(noisy))
	var mx, my float64
	for _, s := range noisy {
		mx += s.At.Sub(t0).Seconds()
		my += s.Value
	}
	mx, my = mx/n, my/n
	var sxx, sxy float64
	for _, s := range noisy {
		dx := s.At.Sub(t0).Seconds() - mx
		sxx += dx * dx
		sxy += dx * (s.Value - my)
	}
	b := sxy / sxx
	var sse float64
	for _, s := range noisy {
		r := s.Value - (my + b*(s.At.Sub(t0).Seconds()-mx))
		sse += r * r
	}
	sd := math.Sqrt(sse / (n - 2))
	edge := func(after time.Duration, sign float64) float64 {
		u := f.At.Add(after).Sub(t0).Seconds() - mx
		return my + b*u + sign*policy.Spread*sd*math.Sqrt(1/n+u*u/sxx)
	}
	if !(edge(f.Earliest-time.Second, +1) < limit && edge(f.Earliest+time.Second, +1) >= limit) {
		t.Fatalf("the upper edge does not meet the limit at the earliest crossing %s", f.Earliest)
	}
	if !(edge(f.Latest-time.Second, -1) < limit && edge(f.Latest+time.Second, -1) >= limit) {
		t.Fatalf("the lower edge does not meet the limit at the latest crossing %s", f.Latest)
	}
	if !(f.Earliest < f.ETA && f.ETA < f.Latest) {
		t.Fatalf("band %s..%s must straddle the point estimate %s", f.Earliest, f.Latest, f.ETA)
	}
}
