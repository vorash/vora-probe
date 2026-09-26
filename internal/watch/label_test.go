package watch

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

func forecastRecord(closed string) intake.Record {
	return intake.Record{
		Incident: investigation.Incident{Service: "memory-test", Trigger: investigation.TriggerForecast, StartedAt: t0},
		Forecast: &intake.ForecastState{Target: "memory-test", Closed: closed},
	}
}

func alertAt(service string, after time.Duration) intake.Record {
	return intake.Record{Incident: investigation.Incident{Service: service, Trigger: investigation.TriggerAlert, StartedAt: t0.Add(after)}}
}

// Every outcome a forecast can have, labelled by code. An alert is a label only
// for the same target and only inside the horizon; before the horizon passes,
// an unrealized forecast is not yet knowable, because an alert may still come.
func TestForecastsAreLabelledByWhatHappened(t *testing.T) {
	horizon := 2 * time.Hour
	after := t0.Add(3 * time.Hour)
	cases := []struct {
		name     string
		forecast intake.Record
		others   []intake.Record
		now      time.Time
		want     string
	}{
		{"realized", forecastRecord(intake.ForecastRealized), nil, t0.Add(time.Hour), LabelTruePositive},
		{"an alert for the target within the horizon", forecastRecord(""), []intake.Record{alertAt("memory-test", 90*time.Minute)}, t0.Add(100 * time.Minute), LabelTruePositive},
		{"an alert for another service", forecastRecord(""), []intake.Record{alertAt("checkout-api", 30*time.Minute)}, after, LabelFalseAlarm},
		{"an alert after the horizon", forecastRecord(""), []intake.Record{alertAt("memory-test", 3*time.Hour)}, after, LabelFalseAlarm},
		{"open past the horizon, nothing happened", forecastRecord(""), nil, after, LabelFalseAlarm},
		{"withdrawn, nothing happened", forecastRecord(intake.ForecastWithdrawn), nil, after, LabelWithdrawn},
		{"withdrawn, then it failed", forecastRecord(intake.ForecastWithdrawn), []intake.Record{alertAt("memory-test", time.Hour)}, t0.Add(70 * time.Minute), LabelMissedAfterWithdrawal},
		{"not knowable yet", forecastRecord(""), nil, t0.Add(time.Hour), ""},
		{"withdrawn, not knowable yet", forecastRecord(intake.ForecastWithdrawn), nil, t0.Add(time.Hour), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			all := append([]intake.Record{c.forecast}, c.others...)
			if got := Outcome(c.forecast, all, c.now, horizon); got != c.want {
				t.Fatalf("label %q, want %q", got, c.want)
			}
		})
	}
}

// Labels are written by the watch itself as outcomes become knowable, persisted
// in the log, and never rewritten: that is what makes watching turn into
// labelled history.
func TestTheWatchLabelsItsForecastsAndTheLabelsPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "incidents.jsonl")
	curves := map[string]func(float64) float64{"memory-test": ramp}
	h := newHarness(t, path, []string{"memory-test"}, curves, 10)
	h.run(t, 31, 70) // opens, then is realized at the limit
	r := h.in.List()[0]
	if r.Forecast.Label != LabelTruePositive || r.Forecast.LabeledAt == nil {
		t.Fatalf("label %q, want true_positive recorded", r.Forecast.Label)
	}
	h.in.Close()

	h2 := newHarness(t, path, []string{"memory-test"}, curves, 10)
	defer h2.in.Close()
	if got := h2.in.List()[0].Forecast.Label; got != LabelTruePositive {
		t.Fatalf("after a restart the label is %q", got)
	}
	if err := h2.in.LabelForecast(r.Incident.ID, LabelFalseAlarm); err != nil {
		t.Fatalf("relabel: %v", err)
	}
	if got := h2.in.List()[0].Forecast.Label; got != LabelTruePositive {
		t.Fatalf("a label was rewritten to %q; an outcome is recorded once", got)
	}
}
