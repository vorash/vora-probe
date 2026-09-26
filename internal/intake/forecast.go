package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// Forecast incidents (vorash/vora-probe#14).
//
// A forecast opens an incident before anything has failed. It goes through the
// same log, queue, rate limits and delivery as an alert, with the trigger
// "forecast". One target has at most one open forecast. It is revised while the
// trend holds, withdrawn when the trend stops, and realized when the limit is
// reached. Its state is in the log, so a restarted watch neither forgets an open
// forecast nor opens it twice.

// ForecastState is the forecast behind a forecast-opened incident.
type ForecastState struct {
	Target    string                 `json:"target"`
	Current   investigation.Forecast `json:"current"`
	Revisions int                    `json:"revisions"`
	// Closed is "" while open, then "withdrawn" or "realized".
	Closed   string     `json:"closed,omitempty"`
	ClosedAt *time.Time `json:"closed_at,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	// Label is the forecast's outcome, set by code once it is knowable. It is
	// what turns watching into labelled history.
	Label     string     `json:"label,omitempty"`
	LabeledAt *time.Time `json:"labeled_at,omitempty"`
}

const (
	ForecastWithdrawn = "withdrawn"
	ForecastRealized  = "realized"
)

func forecastGroup(target string) string { return "forecast:" + target }

// OpenForecast opens an incident for a forecast on target, unless one is
// already open, in which case that one is returned as a duplicate. namespace
// only labels the record; the investigation's scope is the gateway's.
func (in *Intake) OpenForecast(target, namespace string, f investigation.Forecast) (Received, error) {
	if f.Outcome != investigation.ForecastWithinHorizon {
		return Received{}, fmt.Errorf("only a forecast within the horizon opens an incident, not %q", f.Outcome)
	}
	now := in.cfg.Now().UTC()
	in.mu.Lock()
	defer in.mu.Unlock()
	if open, ok := in.openByGroup[forecastGroup(target)]; ok {
		return Received{Outcome: OutcomeDuplicate, IncidentID: open.Incident.ID}, nil
	}
	sum := sha256.Sum256([]byte(target + "|" + f.At.UTC().Format(time.RFC3339Nano)))
	window := gateway.Window{Start: f.At.Add(-in.cfg.Lookback), End: f.At}
	if window.End.Sub(window.Start) > gateway.MaxWindow {
		window.Start = window.End.Add(-gateway.MaxWindow)
	}
	incident := investigation.Incident{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "INC-forecast-" + hex.EncodeToString(sum[:])[:12],
		Environment:   in.cfg.Environment,
		Service:       target,
		Symptom:       "memory forecast: " + f.Statement(),
		Trigger:       investigation.TriggerForecast,
		StartedAt:     f.At.UTC(),
		Window:        window,
		Status:        investigation.IncidentOpen,
	}
	if err := incident.Validate(); err != nil {
		return Received{}, fmt.Errorf("forecast does not make a valid incident: %w", err)
	}
	record := &Record{
		Incident:    incident,
		Fingerprint: hex.EncodeToString(sum[:]),
		GroupKey:    forecastGroup(target),
		Alertname:   "ExhaustionForecast",
		Namespace:   namespace,
		Entity:      namespace + "/" + target,
		Alert:       AlertFiring,
		ReceivedAt:  now,
		UpdatedAt:   now,
		Forecast:    &ForecastState{Target: target, Current: f},
	}
	if err := in.commit(change{Kind: changeForecastOpened, At: now, ID: incident.ID, Record: record}); err != nil {
		return Received{}, err
	}
	return Received{Outcome: OutcomeOpened, IncidentID: incident.ID}, nil
}

// ReviseForecast records a revised forecast for target's open incident.
func (in *Intake) ReviseForecast(target string, f investigation.Forecast) (string, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	open, ok := in.openByGroup[forecastGroup(target)]
	if !ok {
		return "", fmt.Errorf("no open forecast for %s", target)
	}
	return open.Incident.ID, in.commit(change{Kind: changeForecastRevised, At: in.cfg.Now().UTC(), ID: open.Incident.ID, Forecast: &f})
}

// CloseForecast withdraws or realizes target's open forecast. Closing it
// resolves the incident the way an alert's resolution would, so the thread
// hears about it and the group is free to open again.
func (in *Intake) CloseForecast(target, how, reason string) (string, error) {
	if how != ForecastWithdrawn && how != ForecastRealized {
		return "", fmt.Errorf("a forecast closes as %s or %s, not %q", ForecastWithdrawn, ForecastRealized, how)
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	open, ok := in.openByGroup[forecastGroup(target)]
	if !ok {
		return "", fmt.Errorf("no open forecast for %s", target)
	}
	return open.Incident.ID, in.commit(change{Kind: changeForecastClosed, At: in.cfg.Now().UTC(), ID: open.Incident.ID, Closed: how, Reason: reason})
}

// OpenForecasts returns the open forecast incidents, oldest first, so a
// restarted watch knows which targets it is already watching over.
func (in *Intake) OpenForecasts() []Record {
	in.mu.Lock()
	defer in.mu.Unlock()
	var out []Record
	for _, r := range in.records {
		if r.Forecast != nil && r.Forecast.Closed == "" {
			out = append(out, copyRecord(r))
		}
	}
	return out
}

// LabelForecast records a forecast's outcome. A forecast is labelled once.
func (in *Intake) LabelForecast(id, label string) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	r, ok := in.byID[id]
	if !ok || r.Forecast == nil {
		return fmt.Errorf("no forecast incident %s", id)
	}
	if r.Forecast.Label != "" {
		return nil
	}
	return in.commit(change{Kind: changeForecastLabeled, At: in.cfg.Now().UTC(), ID: id, Reason: label})
}
