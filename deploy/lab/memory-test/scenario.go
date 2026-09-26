package main

import (
	"fmt"
	"math"
	"math/rand/v2"
	"time"
)

// Forecast scenarios (vorash/vora-probe#14).
//
// A scenario is a working-set shape over time: the lab follows it, Prometheus
// samples it, and the recording becomes a frozen fixture whose ground truth is
// known because the shape is. Each is parameterised from a seed, and the
// parameter ranges are split into families: dev and held-out draw from
// different ranges, so a held-out result measures generalisation to shapes the
// thresholds were not tuned on, not memory of particular seeds.
//
// target is a pure function of the scenario, the family, the seed, the limit
// and the elapsed time, including its noise, so the same scenario replays the
// same shape and its ground truth can be recomputed.

// Ground truth for each scenario, as the lab will record it.
const (
	truthPositive      = "positive"      // reaches the limit with warning
	truthNegative      = "negative"      // never reaches it
	truthUnforeseeable = "unforeseeable" // reaches it with no warning to give
)

var scenarios = map[string]string{
	"ramp":         truthPositive,
	"slow-leak":    truthPositive,
	"ramp-recover": truthNegative,
	"sawtooth":     truthNegative,
	"step":         truthUnforeseeable,
	"noisy-flat":   truthNegative,
}

// span is a closed range a parameter is drawn from.
type span struct{ lo, hi float64 }

func (s span) draw(r *rand.Rand) float64 { return s.lo + r.Float64()*(s.hi-s.lo) }

// family holds the parameter ranges for one split. dev and held-out do not
// overlap on the parameters that shape a scenario.
type family struct {
	base      span // MiB at the start
	slope     span // MiB per minute, for ramps
	leak      span // MiB per minute, for the slow leak
	plateau   span // fraction of the limit a recovering ramp stops at
	amplitude span // MiB a sawtooth climbs before it collects
	period    span // minutes per sawtooth cycle
	stepAfter span // minutes flat before a step
	noise     span // MiB of jitter on every shape
	flatNoise span // MiB of jitter on the noisy flat
}

var families = map[string]family{
	"dev": {
		base: span{40, 70}, slope: span{2, 4}, leak: span{0.8, 1.2}, plateau: span{0.70, 0.78},
		amplitude: span{20, 40}, period: span{2, 4}, stepAfter: span{10, 15},
		noise: span{0.5, 1.5}, flatNoise: span{3, 5},
	},
	"held-out": {
		base: span{70, 100}, slope: span{4, 7}, leak: span{1.2, 1.5}, plateau: span{0.78, 0.86},
		amplitude: span{40, 70}, period: span{5, 8}, stepAfter: span{20, 25},
		noise: span{1.5, 2.5}, flatNoise: span{5, 8},
	},
}

// shape is one scenario with its parameters drawn.
type shape struct {
	Scenario  string  `json:"scenario"`
	Family    string  `json:"family"`
	Seed      uint64  `json:"seed"`
	Truth     string  `json:"truth"`
	LimitMB   float64 `json:"limit_mb"`
	BaseMB    float64 `json:"base_mb"`
	SlopeMB   float64 `json:"slope_mb_per_min,omitempty"`
	PlateauMB float64 `json:"plateau_mb,omitempty"`
	AmpMB     float64 `json:"amplitude_mb,omitempty"`
	PeriodMin float64 `json:"period_min,omitempty"`
	StepAtMin float64 `json:"step_at_min,omitempty"`
	NoiseMB   float64 `json:"noise_mb"`
}

// noiseTick is the resolution of the jitter: one value per tick, so noise is a
// function of time rather than of how often the follower happens to run.
const noiseTick = 5 * time.Second

func newShape(scenario, familyName string, seed uint64, limitMB float64) (shape, error) {
	truth, ok := scenarios[scenario]
	if !ok {
		return shape{}, fmt.Errorf("unknown scenario %q", scenario)
	}
	f, ok := families[familyName]
	if !ok {
		return shape{}, fmt.Errorf("unknown family %q (dev or held-out)", familyName)
	}
	if limitMB <= 0 {
		return shape{}, fmt.Errorf("the memory limit must be known, got %v MiB", limitMB)
	}
	r := rand.New(rand.NewPCG(seed, 0x9e3779b97f4a7c15))
	s := shape{Scenario: scenario, Family: familyName, Seed: seed, Truth: truth, LimitMB: limitMB,
		BaseMB: f.base.draw(r), NoiseMB: f.noise.draw(r)}
	switch scenario {
	case "ramp":
		s.SlopeMB = f.slope.draw(r)
	case "slow-leak":
		s.SlopeMB = f.leak.draw(r)
	case "ramp-recover":
		s.SlopeMB = f.slope.draw(r)
		s.PlateauMB = f.plateau.draw(r) * limitMB
	case "sawtooth":
		s.AmpMB = f.amplitude.draw(r)
		s.PeriodMin = f.period.draw(r)
		// A sawtooth must stay clear of the limit, or it is not a negative.
		s.AmpMB = math.Min(s.AmpMB, 0.75*limitMB-s.BaseMB)
	case "step":
		s.StepAtMin = f.stepAfter.draw(r)
	case "noisy-flat":
		s.NoiseMB = f.flatNoise.draw(r)
	}
	return s, nil
}

// target is the working set the lab should hold after elapsed, in MiB.
func (s shape) target(elapsed time.Duration) float64 {
	m := elapsed.Minutes()
	var v float64
	switch s.Scenario {
	case "ramp", "slow-leak":
		v = s.BaseMB + s.SlopeMB*m
	case "ramp-recover":
		v = math.Min(s.BaseMB+s.SlopeMB*m, s.PlateauMB)
	case "sawtooth":
		phase := math.Mod(m, s.PeriodMin) / s.PeriodMin
		v = s.BaseMB + s.AmpMB*phase
	case "step":
		v = s.BaseMB
		if m >= s.StepAtMin {
			// Past the limit in one step: the kill comes with no approach.
			v = s.LimitMB * 1.25
		}
	case "noisy-flat":
		v = s.BaseMB
	}
	return math.Max(0, v+s.NoiseMB*jitter(s.Seed, uint64(elapsed/noiseTick)))
}

// jitter is a deterministic value in [-1, 1] for a seed and a tick
// (splitmix64), so the noise replays exactly.
func jitter(seed, tick uint64) float64 {
	z := seed + tick*0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	z ^= z >> 31
	return float64(z)/float64(math.MaxUint64)*2 - 1
}
