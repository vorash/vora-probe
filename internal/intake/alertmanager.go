// Package intake turns Alertmanager webhook notifications into incidents.
//
// Intake decides what a notification means (a new incident, a repeat of one
// already open, a heartbeat, a resolution) and nothing else. It never starts
// model work: a receiver that blocked on an investigation would make
// Alertmanager time out and retry, and a retry is a duplicate.
package intake

import (
	"encoding/json"
	"fmt"
	"time"
)

// Notification is the Alertmanager webhook payload, version 4. Fields Probe does
// not use are still decoded where they carry identity, and unknown fields are
// tolerated: the payload is Alertmanager's contract, not Probe's, and it grows
// (notification_reason is a recent addition).
type Notification struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"groupKey"`
	TruncatedAlerts   int               `json:"truncatedAlerts"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"groupLabels"`
	CommonLabels      map[string]string `json:"commonLabels"`
	CommonAnnotations map[string]string `json:"commonAnnotations"`
	ExternalURL       string            `json:"externalURL"`
	Alerts            []Alert           `json:"alerts"`
}

// Alert is one alert inside a notification. A firing alert's EndsAt is
// Alertmanager's zero time, not the moment it will end.
type Alert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

const (
	StatusFiring   = "firing"
	StatusResolved = "resolved"
)

// Parse decodes and checks a notification. It refuses what it cannot act on
// rather than guessing: a notification without a group key cannot be
// deduplicated, and one without alerts has no start time to anchor a window.
func Parse(raw []byte) (Notification, error) {
	var n Notification
	if err := json.Unmarshal(raw, &n); err != nil {
		return Notification{}, fmt.Errorf("notification is not valid JSON: %w", err)
	}
	if n.Version != "4" {
		return Notification{}, fmt.Errorf("notification version %q is not supported, want \"4\"", n.Version)
	}
	if n.GroupKey == "" {
		return Notification{}, fmt.Errorf("notification has no groupKey")
	}
	if n.Status != StatusFiring && n.Status != StatusResolved {
		return Notification{}, fmt.Errorf("notification status %q is neither %s nor %s", n.Status, StatusFiring, StatusResolved)
	}
	if len(n.Alerts) == 0 {
		return Notification{}, fmt.Errorf("notification carries no alerts")
	}
	for i, a := range n.Alerts {
		if a.StartsAt.IsZero() {
			return Notification{}, fmt.Errorf("alert %d has no startsAt", i)
		}
	}
	return n, nil
}

// label reads a label from the alert, falling back to the group's common
// labels, which Alertmanager may hoist out of the individual alerts.
func (n Notification) label(a Alert, name string) string {
	if v := a.Labels[name]; v != "" {
		return v
	}
	return n.CommonLabels[name]
}

func (n Notification) annotation(a Alert, name string) string {
	if v := a.Annotations[name]; v != "" {
		return v
	}
	return n.CommonAnnotations[name]
}
