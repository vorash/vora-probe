package evaluation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mib = 1 << 20

var start = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// synthetic builds a case sampled every 15s for d, valued by f(minutes).
func synthetic(id string, d time.Duration, f func(m float64) float64) ForecastCase {
	c := ForecastCase{SchemaVersion: "probe/v1", ID: id, Split: SplitDev, Entity: "memory-test",
		Metric: "container_memory_working_set_bytes", Resolution: "15s", LimitBytes: 256 * mib}
	for t := time.Duration(0); t <= d; t += 15 * time.Second {
		c.Samples = append(c.Samples, ForecastSample{At: start.Add(t), Value: f(t.Minutes())})
	}
	return c
}

func truth(id, kind string, killedAfter time.Duration) ForecastTruth {
	t := ForecastTruth{Case: id, Truth: kind}
	if killedAfter > 0 {
		at := start.Add(killedAfter)
		t.KilledAt = &at
	}
	return t
}

func wobble(m float64) float64 { return []float64{1, -1, 0.5, -0.5, 0}[int(m*4)%5] * mib }

// The acceptance shapes of #14, scored end to end through a watch replay: a
// ramp is caught with lead time and its band holds the kill; a sawtooth and a
// flat line stay silent; a near miss is opened and then withdrawn before its
// predicted crossing; a step gets no lead-time claim.
func TestTheWatchReplayScoresTheAcceptanceShapes(t *testing.T) {
	// 60 MiB + 3 MiB/min reaches 256 MiB at about 65 minutes.
	ramp := synthetic("ramp", 65*time.Minute, func(m float64) float64 { return 60*mib + 3*m*mib + wobble(m) })
	sawtooth := synthetic("sawtooth", time.Hour, func(m float64) float64 {
		return 60*mib + 30*mib*(m-3*float64(int(m/3)))/3 + wobble(m)
	})
	flat := synthetic("flat", time.Hour, func(m float64) float64 { return 80*mib + 4*wobble(m) })
	// Climbs at 3 MiB/min to a plateau at 190 MiB and stays there.
	recover := synthetic("recover", 2*time.Hour, func(m float64) float64 {
		return min(60*mib+3*m*mib, 190*mib) + wobble(m)
	})
	step := synthetic("step", 20*time.Minute, func(m float64) float64 {
		if m >= 19.9 {
			return 300 * mib
		}
		return 80*mib + wobble(m)
	})
	cases := []ForecastCase{ramp, sawtooth, flat, recover, step}
	truths := map[string]ForecastTruth{
		"ramp":     truth("ramp", TruthPositive, 65*time.Minute+20*time.Second),
		"sawtooth": truth("sawtooth", TruthNegative, 0),
		"flat":     truth("flat", TruthNegative, 0),
		"recover":  truth("recover", TruthNegative, 0),
		"step":     truth("step", TruthUnforeseeable, 20*time.Minute),
	}
	var runs []ForecastRun
	for _, c := range cases {
		runs = append(runs, ReplayForecast(c, DefaultWatchPolicy()))
	}
	s, err := ScoreForecasts(runs, truths)
	if err != nil {
		t.Fatalf("score: %v", err)
	}
	if s.Detected != 1 || len(s.LeadTimes) != 1 || s.LeadTimes[0] < 10*time.Minute {
		t.Fatalf("the ramp must be caught with real lead time: %+v", s)
	}
	if s.BandHeld != 1 {
		t.Fatalf("the ramp's first band must hold its kill: %+v", s)
	}
	if s.FalseAlarms != 0 {
		t.Fatalf("no negative may end with a forecast open: %+v (runs %+v)", s, runs)
	}
	if s.OpenedThenWithdrawn != 1 || s.WithdrawnBeforeCrossing != 1 {
		t.Fatalf("the near miss must be opened and withdrawn before its predicted crossing: %+v", s)
	}
	if s.LeadTimeClaims != 0 {
		t.Fatalf("a step gives no warning, and no lead time may be claimed for it: %+v", s)
	}
	for _, r := range runs {
		if (r.Case == "sawtooth" || r.Case == "flat") && r.Opened != 0 {
			t.Fatalf("%s opened %d forecasts; a shape that is not a trend must stay silent", r.Case, r.Opened)
		}
	}
}

// A watch only knows what had been sampled by each tick. A replay that looked
// ahead would report lead times no live watch could have had.
func TestAReplayNeverLooksAhead(t *testing.T) {
	ramp := synthetic("ramp", 65*time.Minute, func(m float64) float64 { return 60*mib + 3*m*mib + wobble(m) })
	run := ReplayForecast(ramp, DefaultWatchPolicy())
	if run.First == nil || run.First.At.After(*run.FirstAt) {
		t.Fatalf("the first forecast was fitted on samples after its tick: %+v", run)
	}
}

func TestScoringNeedsEveryAnswerKey(t *testing.T) {
	if _, err := ScoreForecasts([]ForecastRun{{Case: "orphan"}}, map[string]ForecastTruth{}); err == nil {
		t.Fatal("a run without an answer key must not be scored")
	}
}

// A case is the input foresight sees; its answer key lives beside it and is
// read only by the harness. A case file that carried the answer would let
// anything that reads cases learn it, so unknown fields are refused.
func TestACaseCannotCarryItsAnswer(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "ramp-dev-1")
	os.MkdirAll(caseDir, 0o700)
	c := synthetic("ramp-dev-1", 20*time.Minute, func(m float64) float64 { return 60*mib + m*mib })
	raw, _ := json.Marshal(c)
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	fields["truth"] = "positive"
	raw, _ = json.Marshal(fields)
	os.WriteFile(filepath.Join(caseDir, "series.json"), raw, 0o600)
	if _, err := LoadForecastCases(dir); err == nil || !strings.Contains(err.Error(), "truth") {
		t.Fatalf("a case carrying its answer loaded: %v", err)
	}
}

func TestATamperedCaseFailsValidation(t *testing.T) {
	c := synthetic("ramp-dev-1", 20*time.Minute, func(m float64) float64 { return 60*mib + m*mib })
	digest, err := c.ComputeDigest()
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	c.Digest = digest
	if err := c.Validate(SplitDev); err != nil {
		t.Fatalf("a signed case must validate: %v", err)
	}
	c.Samples[3].Value += mib
	if err := c.Validate(SplitDev); err == nil {
		t.Fatal("a series edited without re-freezing its digest must fail validation")
	}
}

func forecastRoot() string { return filepath.Join("..", "test", "fixtures", "forecast") }

// TestForecastCaseIntegrity verifies every recorded case. After recording or
// deliberately editing a case, re-freeze with:
//
//	go test ./evaluation -run TestForecastCaseIntegrity -update
func TestForecastCaseIntegrity(t *testing.T) {
	found := 0
	for _, split := range []string{SplitDev, SplitHeldOut} {
		dir := filepath.Join(forecastRoot(), split)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		cases, err := LoadForecastCases(dir)
		if err != nil {
			t.Fatalf("%s: %v", split, err)
		}
		for _, c := range cases {
			found++
			if *update {
				digest, err := c.ComputeDigest()
				if err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
				c.Digest = digest
				raw, _ := json.MarshalIndent(c, "", "  ")
				if err := os.WriteFile(filepath.Join(dir, c.ID, "series.json"), append(raw, '\n'), 0o644); err != nil {
					t.Fatalf("%s: %v", c.ID, err)
				}
			}
			if err := c.Validate(split); err != nil {
				t.Errorf("%s/%s: %v", split, c.ID, err)
			}
			truth, err := LoadForecastTruth(filepath.Join(dir, c.ID))
			if err != nil {
				t.Errorf("%s/%s: the answer key is missing or invalid: %v", split, c.ID, err)
				continue
			}
			if truth.Case != c.ID || truth.Family != split {
				t.Errorf("%s/%s: the answer key is for %s/%s", split, c.ID, truth.Family, truth.Case)
			}
			// A positive or unforeseeable scenario that was never killed, or a
			// negative that was, means the recording did not show what its
			// scenario claims, and scoring against it would be wrong.
			killed := truth.KilledAt != nil
			if (truth.Truth == TruthNegative) == killed {
				t.Errorf("%s/%s: a %s scenario with killed=%t; the recording does not match its ground truth", split, c.ID, truth.Truth, killed)
			}
		}
	}
	if found == 0 {
		t.Fatal("no forecast cases found; the suite exists only once cases are recorded")
	}
}
