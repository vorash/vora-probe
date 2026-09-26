package main

import (
	"testing"
	"time"
)

const limitMB = 256

// sweep samples a shape every scrape interval over d.
func sweep(s shape, d time.Duration) (values []float64) {
	for t := time.Duration(0); t <= d; t += 15 * time.Second {
		values = append(values, s.target(t))
	}
	return values
}

func firstCrossing(s shape, d time.Duration) (time.Duration, bool) {
	for t := time.Duration(0); t <= d; t += 15 * time.Second {
		if s.target(t) >= s.LimitMB {
			return t, true
		}
	}
	return 0, false
}

func eachShape(t *testing.T, scenario string, check func(t *testing.T, s shape)) {
	t.Helper()
	for _, fam := range []string{"dev", "held-out"} {
		for seed := uint64(1); seed <= 25; seed++ {
			s, err := newShape(scenario, fam, seed, limitMB)
			if err != nil {
				t.Fatalf("%s/%s/%d: %v", scenario, fam, seed, err)
			}
			check(t, s)
		}
	}
}

// Every scenario must have the ground truth it is recorded with, for every
// seed in both families; a "negative" that brushes the limit, or a "positive"
// that never reaches it, would make a fixture lie.
func TestEveryScenarioHasTheGroundTruthItClaims(t *testing.T) {
	eachShape(t, "ramp", func(t *testing.T, s shape) {
		if at, ok := firstCrossing(s, 2*time.Hour); !ok || at < 10*time.Minute {
			t.Errorf("ramp %s/%d: crosses at %s (%t), want a warned crossing within 2h", s.Family, s.Seed, at, ok)
		}
	})
	eachShape(t, "slow-leak", func(t *testing.T, s shape) {
		if at, ok := firstCrossing(s, 6*time.Hour); !ok || at < 90*time.Minute {
			t.Errorf("slow-leak %s/%d: crosses at %s (%t), want a long lead, under the 6h retention", s.Family, s.Seed, at, ok)
		}
	})
	for _, negative := range []string{"ramp-recover", "sawtooth", "noisy-flat"} {
		eachShape(t, negative, func(t *testing.T, s shape) {
			for _, v := range sweep(s, 4*time.Hour) {
				if v >= 0.9*s.LimitMB {
					t.Fatalf("%s %s/%d reaches %.0f MiB, within 10%% of the %v MiB limit: not a negative", negative, s.Family, s.Seed, v, s.LimitMB)
				}
			}
		})
	}
	eachShape(t, "step", func(t *testing.T, s shape) {
		stepAt := time.Duration(s.StepAtMin * float64(time.Minute))
		for tt := time.Duration(0); tt < stepAt; tt += 15 * time.Second {
			if v := s.target(tt); v > s.BaseMB+s.NoiseMB {
				t.Fatalf("step %s/%d: %.0f MiB before the step; a step must give no warning", s.Family, s.Seed, v)
			}
		}
		if at, ok := firstCrossing(s, stepAt+time.Minute); !ok || at < stepAt {
			t.Errorf("step %s/%d: crosses at %s, want at the step %s", s.Family, s.Seed, at, stepAt)
		}
	})
}

// A sawtooth must actually fall, or a forecast refusing it would be refusing
// a ramp.
func TestTheSawtoothFalls(t *testing.T) {
	eachShape(t, "sawtooth", func(t *testing.T, s shape) {
		v := sweep(s, time.Hour)
		drops := 0
		for i := 1; i < len(v); i++ {
			if v[i] < v[i-1]-s.AmpMB/2 {
				drops++
			}
		}
		if drops < 5 {
			t.Errorf("sawtooth %s/%d: %d collections in an hour, want a repeating cycle", s.Family, s.Seed, drops)
		}
	})
}

// The held-out split measures generalisation only if its shapes come from
// ranges the dev split never saw.
func TestTheFamiliesDoNotOverlap(t *testing.T) {
	dev, held := families["dev"], families["held-out"]
	for name, pair := range map[string][2]span{
		"slope": {dev.slope, held.slope}, "leak": {dev.leak, held.leak}, "plateau": {dev.plateau, held.plateau},
		"amplitude": {dev.amplitude, held.amplitude}, "period": {dev.period, held.period},
		"stepAfter": {dev.stepAfter, held.stepAfter}, "flatNoise": {dev.flatNoise, held.flatNoise},
	} {
		if pair[0].hi > pair[1].lo {
			t.Errorf("%s: dev reaches %v, into held-out from %v", name, pair[0].hi, pair[1].lo)
		}
	}
}

// A scenario must replay exactly: its ground truth is recomputed from the seed.
func TestAScenarioReplaysExactly(t *testing.T) {
	a, _ := newShape("noisy-flat", "dev", 7, limitMB)
	b, _ := newShape("noisy-flat", "dev", 7, limitMB)
	c, _ := newShape("noisy-flat", "dev", 8, limitMB)
	va, vb, vc := sweep(a, 20*time.Minute), sweep(b, 20*time.Minute), sweep(c, 20*time.Minute)
	for i := range va {
		if va[i] != vb[i] {
			t.Fatalf("the same seed diverged at sample %d: %v vs %v", i, va[i], vb[i])
		}
	}
	same := true
	for i := range va {
		same = same && va[i] == vc[i]
	}
	if same {
		t.Fatal("different seeds produced the same shape")
	}
}

func TestAScenarioRefusesWhatItCannotDraw(t *testing.T) {
	for name, err := range map[string]error{
		"unknown scenario": func() error { _, err := newShape("leak", "dev", 1, limitMB); return err }(),
		"unknown family":   func() error { _, err := newShape("ramp", "test", 1, limitMB); return err }(),
		"unknown limit":    func() error { _, err := newShape("ramp", "dev", 1, 0); return err }(),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The follower moves the held working set both ways; shrinking is what makes
// a sawtooth visible at all.
func TestTheFollowerGrowsAndShrinks(t *testing.T) {
	s := &state{dropped: map[string]bool{}}
	s.resize(5)
	if s.heldMB != 5 || len(s.held) != 5 {
		t.Fatalf("held %d MiB in %d blocks, want 5 in 5", s.heldMB, len(s.held))
	}
	s.resize(2)
	if s.heldMB != 2 || len(s.held) != 2 {
		t.Fatalf("held %d MiB in %d blocks after shrinking, want 2", s.heldMB, len(s.held))
	}
}
