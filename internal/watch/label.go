package watch

import (
	"time"

	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/investigation"
)

// Shadow labelling (vorash/vora-probe#14).
//
// There is no history of incidents to learn from, so every forecast labels
// itself once its outcome is knowable, by code, with no human in the loop. An
// alert that P1 intake receives for the same target is a free label, which is
// why intake came first.

const (
	// LabelTruePositive: the forecast was realized, or an alert for the same
	// target arrived within its horizon.
	LabelTruePositive = "true_positive"
	// LabelFalseAlarm: the horizon passed with no crossing and no alert.
	LabelFalseAlarm = "false_alarm"
	// LabelWithdrawn: taken back when the trend stopped, and nothing failed.
	// Kept apart from false alarms and successes (#14, open decision 3).
	LabelWithdrawn = "withdrawn"
	// LabelMissedAfterWithdrawal: withdrawn, and then the target failed
	// within the horizon anyway.
	LabelMissedAfterWithdrawal = "missed_after_withdrawal"
)

// Outcome labels one forecast incident against every other incident intake
// has seen, as of now. It returns "" while the outcome is not yet knowable.
func Outcome(forecast intake.Record, all []intake.Record, now time.Time, horizon time.Duration) string {
	fs := forecast.Forecast
	if fs == nil {
		return ""
	}
	opened := forecast.Incident.StartedAt
	deadline := opened.Add(horizon)
	alerted := false
	for _, r := range all {
		if r.Incident.Trigger == investigation.TriggerAlert && r.Incident.Service == fs.Target &&
			!r.Incident.StartedAt.Before(opened) && !r.Incident.StartedAt.After(deadline) {
			alerted = true
		}
	}
	switch {
	case fs.Closed == intake.ForecastRealized:
		return LabelTruePositive
	case fs.Closed == intake.ForecastWithdrawn && alerted:
		return LabelMissedAfterWithdrawal
	case alerted:
		return LabelTruePositive
	case now.Before(deadline):
		// An alert may still come; a withdrawn forecast may still be followed
		// by a failure. Not knowable yet.
		return ""
	case fs.Closed == intake.ForecastWithdrawn:
		return LabelWithdrawn
	default:
		return LabelFalseAlarm
	}
}

// label records the outcome of every forecast whose outcome has become
// knowable. It runs every tick, in shadow mode and live.
func (w *Watcher) label(now time.Time) {
	all := w.cfg.Intake.List()
	for _, r := range all {
		if r.Forecast == nil || r.Forecast.Label != "" {
			continue
		}
		if l := Outcome(r, all, now, w.cfg.Forecast.Horizon); l != "" {
			if err := w.cfg.Intake.LabelForecast(r.Incident.ID, l); err != nil {
				w.cfg.Logf("vora-probe watch: could not label %s: %v", r.Incident.ID, err)
			}
		}
	}
}
