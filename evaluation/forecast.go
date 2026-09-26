package evaluation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// The forecast suite (vorash/vora-probe#14).
//
// A forecast case is a working-set series recorded from a lab scenario, with the
// container's limit: exactly what foresight would see. Its ground truth (the
// scenario, its drawn parameters, and when the container was killed) is in a
// separate file that only the harness reads, so nothing under evaluation can
// learn the answer from the input.
//
// The harness replays each case the way a watch loop will, tick by tick over a
// trailing window, and scores the result as counts: detections and their lead
// times, false alarms, forecasts opened and then withdrawn, lead-time claims on
// failures that gave no warning, and how often the band held the crossing. It
// makes no statistical claims.

// ForecastCase is one recorded series.
type ForecastCase struct {
	SchemaVersion string           `json:"schema_version"`
	ID            string           `json:"id"`
	Split         string           `json:"split"`
	Entity        string           `json:"entity"`
	Metric        string           `json:"metric"`
	Resolution    string           `json:"resolution"`
	LimitBytes    float64          `json:"limit_bytes"`
	Samples       []ForecastSample `json:"samples"`
	Digest        string           `json:"digest"`
}

type ForecastSample struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// ForecastTruth is the answer key. Only the harness loads it.
type ForecastTruth struct {
	SchemaVersion string          `json:"schema_version"`
	Case          string          `json:"case"`
	Scenario      string          `json:"scenario"`
	Family        string          `json:"family"`
	Seed          uint64          `json:"seed"`
	Truth         string          `json:"truth"`
	Params        json.RawMessage `json:"params"`
	KilledAt      *time.Time      `json:"killed_at"`
	KillReason    *string         `json:"kill_reason"`
	RecordedFrom  time.Time       `json:"recorded_from"`
	RecordedTo    time.Time       `json:"recorded_to"`
}

const (
	TruthPositive      = "positive"
	TruthNegative      = "negative"
	TruthUnforeseeable = "unforeseeable"
)

// ComputeDigest signs the case with its digest field empty, so any edit to the
// series or the limit fails validation until it is deliberately re-frozen.
func (c ForecastCase) ComputeDigest() (string, error) {
	c.Digest = ""
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return gateway.Digest(raw), nil
}

func (c ForecastCase) Validate(split string) error {
	if c.Split != split {
		return fmt.Errorf("case %s is in %s but says it is %s", c.ID, split, c.Split)
	}
	if c.LimitBytes <= 0 || len(c.Samples) == 0 {
		return fmt.Errorf("case %s has no limit or no samples", c.ID)
	}
	for i := 1; i < len(c.Samples); i++ {
		if !c.Samples[i].At.After(c.Samples[i-1].At) {
			return fmt.Errorf("case %s: samples out of order at %d", c.ID, i)
		}
	}
	want, err := c.ComputeDigest()
	if err != nil {
		return err
	}
	if c.Digest != want {
		return fmt.Errorf("case %s: digest %q does not match its content (%s); re-freeze deliberately with -update", c.ID, c.Digest, want)
	}
	return nil
}

// Series is the case as the derivation takes it.
func (c ForecastCase) Series() []investigation.Sample {
	out := make([]investigation.Sample, len(c.Samples))
	for i, s := range c.Samples {
		out[i] = investigation.Sample{At: s.At, Value: s.Value}
	}
	return out
}

// LoadForecastCases reads every case under a split directory, sorted by ID.
// Unknown fields are refused, so ground truth cannot be smuggled into a case.
func LoadForecastCases(splitDir string) ([]ForecastCase, error) {
	entries, err := os.ReadDir(splitDir)
	if err != nil {
		return nil, err
	}
	var out []ForecastCase
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(splitDir, e.Name(), "series.json"))
		if err != nil {
			return nil, err
		}
		var c ForecastCase
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// LoadForecastTruth reads one case's answer key.
func LoadForecastTruth(caseDir string) (ForecastTruth, error) {
	raw, err := os.ReadFile(filepath.Join(caseDir, "ground-truth.json"))
	if err != nil {
		return ForecastTruth{}, err
	}
	var t ForecastTruth
	if err := json.Unmarshal(raw, &t); err != nil {
		return ForecastTruth{}, err
	}
	switch t.Truth {
	case TruthPositive, TruthNegative, TruthUnforeseeable:
	default:
		return ForecastTruth{}, fmt.Errorf("%s: truth %q is not positive, negative or unforeseeable", caseDir, t.Truth)
	}
	return t, nil
}

// WatchPolicy is how a watch loop looks at a series: every Every, a forecast
// over the trailing Window.
type WatchPolicy struct {
	Window   time.Duration
	Every    time.Duration
	Forecast investigation.ForecastPolicy
}

func DefaultWatchPolicy() WatchPolicy {
	return WatchPolicy{Window: 30 * time.Minute, Every: time.Minute, Forecast: investigation.DefaultForecastPolicy()}
}

// ForecastRun is what a watch would have done over one case.
type ForecastRun struct {
	Case  string `json:"case"`
	Ticks int    `json:"ticks"`
	// Opened counts forecasts raised; Withdrawn those later taken back because
	// the trend stopped. A forecast still open at the end was never withdrawn.
	Opened    int  `json:"opened"`
	Withdrawn int  `json:"withdrawn"`
	OpenAtEnd bool `json:"open_at_end"`
	// Realized: an open forecast whose series reached the limit. That is the
	// forecast coming true, not the trend stopping, so it is not a withdrawal.
	Realized bool `json:"realized"`
	// First is the first forecast raised, and WithdrawnAt when it was taken
	// back, if it was.
	First       *investigation.Forecast `json:"first,omitempty"`
	FirstAt     *time.Time              `json:"first_at,omitempty"`
	WithdrawnAt *time.Time              `json:"withdrawn_at,omitempty"`
}

// ReplayForecast runs the forecast over a case as a watch loop would: it sees
// only what had been sampled by each tick, never the rest of the series.
func ReplayForecast(c ForecastCase, p WatchPolicy) ForecastRun {
	run := ForecastRun{Case: c.ID}
	series := c.Series()
	if len(series) == 0 {
		return run
	}
	open := false
	end := series[len(series)-1].At
	for tick := series[0].At.Add(p.Every); !tick.After(end); tick = tick.Add(p.Every) {
		var window []investigation.Sample
		for _, s := range series {
			if s.At.After(tick.Add(-p.Window)) && !s.At.After(tick) {
				window = append(window, s)
			}
		}
		run.Ticks++
		f := investigation.ForecastExhaustion(window, c.LimitBytes, true, p.Forecast)
		if open && reachedLimit(f) {
			run.Realized = true
			break
		}
		raised := f.Outcome == investigation.ForecastWithinHorizon
		switch {
		case raised && !open:
			open = true
			run.Opened++
			if run.First == nil {
				at, forecast := tick, f
				run.First, run.FirstAt = &forecast, &at
			}
		case !raised && open:
			open = false
			run.Withdrawn++
			if run.WithdrawnAt == nil {
				at := tick
				run.WithdrawnAt = &at
			}
		}
	}
	run.OpenAtEnd = open
	return run
}

// reachedLimit is a refusal whose only reason is that the series is at its
// limit: the forecast was right, and there is nothing left to forecast.
func reachedLimit(f investigation.Forecast) bool {
	for _, r := range f.Refusals {
		if r == investigation.RefuseAtOrOverLimit {
			return true
		}
	}
	return false
}

// ForecastScore is the suite's result for a set of cases. Counts only.
type ForecastScore struct {
	Cases         int `json:"cases"`
	Positives     int `json:"positives"`
	Negatives     int `json:"negatives"`
	Unforeseeable int `json:"unforeseeable"`

	// Detected: positives with a forecast raised before the kill.
	Detected  int             `json:"detected"`
	LeadTimes []time.Duration `json:"lead_times"`
	// BandHeld counts detections whose first band contained the kill.
	BandHeld int `json:"band_held"`
	// FalseAlarms: negatives with a forecast still open at the end.
	FalseAlarms int `json:"false_alarms"`
	// OpenedThenWithdrawn: negatives whose every forecast was withdrawn,
	// reported apart from false alarms (#14, open decision 3), and how many of
	// those were withdrawn before their predicted crossing.
	OpenedThenWithdrawn     int `json:"opened_then_withdrawn"`
	WithdrawnBeforeCrossing int `json:"withdrawn_before_crossing"`
	// LeadTimeClaims: failures that gave no warning, yet had a forecast
	// raised before them. Must be zero.
	LeadTimeClaims int `json:"lead_time_claims"`
}

// ScoreForecasts scores runs against their answer keys, matched by case.
func ScoreForecasts(runs []ForecastRun, truths map[string]ForecastTruth) (ForecastScore, error) {
	var s ForecastScore
	for _, run := range runs {
		t, ok := truths[run.Case]
		if !ok {
			return ForecastScore{}, fmt.Errorf("no answer key for %s", run.Case)
		}
		s.Cases++
		raisedBeforeKill := run.FirstAt != nil && t.KilledAt != nil && run.FirstAt.Before(*t.KilledAt)
		switch t.Truth {
		case TruthPositive:
			s.Positives++
			if !raisedBeforeKill {
				continue
			}
			s.Detected++
			s.LeadTimes = append(s.LeadTimes, t.KilledAt.Sub(*run.FirstAt))
			earliest := run.FirstAt.Add(run.First.Earliest)
			latest := run.FirstAt.Add(run.First.Latest)
			if !t.KilledAt.Before(earliest) && !t.KilledAt.After(latest) {
				s.BandHeld++
			}
		case TruthNegative:
			s.Negatives++
			switch {
			case run.OpenAtEnd:
				s.FalseAlarms++
			case run.Opened > 0:
				s.OpenedThenWithdrawn++
				if run.WithdrawnAt.Before(run.FirstAt.Add(run.First.ETA)) {
					s.WithdrawnBeforeCrossing++
				}
			}
		case TruthUnforeseeable:
			s.Unforeseeable++
			if raisedBeforeKill {
				s.LeadTimeClaims++
			}
		}
	}
	sort.Slice(s.LeadTimes, func(i, j int) bool { return s.LeadTimes[i] < s.LeadTimes[j] })
	return s, nil
}

// ForecastSuiteResult is one split's replay and score.
type ForecastSuiteResult struct {
	Split   string        `json:"split"`
	Version string        `json:"version"`
	Policy  WatchPolicy   `json:"policy"`
	Runs    []ForecastRun `json:"runs"`
	Score   ForecastScore `json:"score"`
}

// RunForecastSuite replays and scores every case of one split. Each case is
// validated first; the answer keys are loaded only for scoring, after every
// replay has run.
func RunForecastSuite(root, split string, p WatchPolicy) (ForecastSuiteResult, error) {
	dir := filepath.Join(root, split)
	cases, err := LoadForecastCases(dir)
	if err != nil {
		return ForecastSuiteResult{}, err
	}
	result := ForecastSuiteResult{Split: split, Version: investigation.ForecastVersion, Policy: p}
	for _, c := range cases {
		if err := c.Validate(split); err != nil {
			return ForecastSuiteResult{}, err
		}
		result.Runs = append(result.Runs, ReplayForecast(c, p))
	}
	truths := map[string]ForecastTruth{}
	for _, c := range cases {
		t, err := LoadForecastTruth(filepath.Join(dir, c.ID))
		if err != nil {
			return ForecastSuiteResult{}, err
		}
		truths[c.ID] = t
	}
	result.Score, err = ScoreForecasts(result.Runs, truths)
	return result, err
}
