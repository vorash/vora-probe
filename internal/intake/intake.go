package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// Outcome is what a notification meant. Every notification has one, including
// the ones that start nothing: an alert that is neither investigated nor
// recorded is an alert that was lost.
type Outcome string

const (
	// OutcomeOpened: a new incident, to be investigated.
	OutcomeOpened Outcome = "opened"
	// OutcomeDuplicate: a repeat of an incident already recorded; the payload
	// is appended to it and nothing new is started.
	OutcomeDuplicate Outcome = "duplicate"
	// OutcomeHeartbeat: an always-firing liveness alert. Recorded, never
	// investigated.
	OutcomeHeartbeat Outcome = "heartbeat"
	// OutcomeResolved: the group resolved, and its open incident is closed.
	OutcomeResolved Outcome = "resolved"
	// OutcomeIgnored: a resolution with no open incident to close.
	OutcomeIgnored Outcome = "ignored"
	// OutcomeUnmapped: firing, but no label names a service, so there is no
	// incident Probe could investigate. Recorded so it is visible, not dropped.
	OutcomeUnmapped Outcome = "unmapped"
)

// AlertState is the alert side of an incident's life, independent of how its
// investigation went.
type AlertState string

const (
	AlertFiring   AlertState = "firing"
	AlertResolved AlertState = "resolved"
)

// Record is an incident as intake knows it: the investigation's incident plus
// the alert identity it came from.
type Record struct {
	Incident investigation.Incident `json:"incident"`
	// Fingerprint is the dedupe key of the notification that opened it.
	Fingerprint string `json:"fingerprint"`
	GroupKey    string `json:"group_key"`
	Alertname   string `json:"alertname,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	// Entity is the pod or instance the alert names, when it names one. It is
	// what a per-host rate limit keys on; the incident's service stays the
	// investigation's subject.
	Entity     string     `json:"entity,omitempty"`
	Alert      AlertState `json:"alert"`
	ReceivedAt time.Time  `json:"received_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
	// Notifications are every payload attributed to this incident, redacted,
	// in arrival order.
	Notifications []Delivery `json:"notifications"`
}

// Delivery is one notification as received.
type Delivery struct {
	At      time.Time       `json:"at"`
	Outcome Outcome         `json:"outcome"`
	Payload json.RawMessage `json:"payload"`
}

// Received is the answer to one notification.
type Received struct {
	Outcome Outcome `json:"outcome"`
	// IncidentID is set whenever the notification was attributed to an
	// incident.
	IncidentID string `json:"incident_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Config is the mapping from alert labels to an incident. It is explicit on
// purpose: which label names the service is a property of the alerting rules,
// and guessing it would investigate the wrong thing.
type Config struct {
	// Environment is the incident environment when an alert carries no
	// environment label.
	Environment string
	// ServiceLabels are tried in order; the first present names the service.
	ServiceLabels []string
	// Lookback is how far before the alert's start the evidence window opens.
	// The window is additionally capped at gateway.MaxWindow.
	Lookback time.Duration
	Now      func() time.Time
}

// DefaultConfig maps the labels kube-prometheus and the lab's rules use.
func DefaultConfig() Config {
	return Config{
		Environment:   "lab",
		ServiceLabels: []string{"service", "app", "app_kubernetes_io_name", "container", "deployment"},
		Lookback:      30 * time.Minute,
	}
}

// Intake holds the incidents intake has seen. It is safe for concurrent use:
// Alertmanager may deliver several groups at once.
type Intake struct {
	cfg Config

	mu sync.Mutex
	// records in the order they were opened; the indexes point into it.
	records       []*Record
	byID          map[string]*Record
	byFingerprint map[string]*Record
	openByGroup   map[string]*Record
	// Heartbeats arrive on every repeat interval for as long as alerting is
	// up, so only their count and last arrival are kept.
	heartbeats    int
	lastHeartbeat time.Time
	unmapped      []Delivery
}

func New(cfg Config) *Intake {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Intake{
		cfg:           cfg,
		byID:          map[string]*Record{},
		byFingerprint: map[string]*Record{},
		openByGroup:   map[string]*Record{},
	}
}

// Receive decides what a notification means and records it. raw is the
// payload as received; it is kept redacted, never as sent.
func (in *Intake) Receive(n Notification, raw []byte) (Received, error) {
	now := in.cfg.Now().UTC()
	payload, _ := gateway.RedactRaw(json.RawMessage(raw))

	in.mu.Lock()
	defer in.mu.Unlock()

	// Resolution is decided before dedupe. A resolved notification's
	// fingerprint is built from its end time, so it never matches the firing
	// one; deduping first would treat every resolution as a new alert.
	if n.Status == StatusResolved {
		open, ok := in.openByGroup[n.GroupKey]
		if !ok {
			return Received{Outcome: OutcomeIgnored, Reason: "resolved group has no open incident"}, nil
		}
		open.Alert = AlertResolved
		open.ResolvedAt = &now
		open.UpdatedAt = now
		open.Notifications = append(open.Notifications, Delivery{At: now, Outcome: OutcomeResolved, Payload: payload})
		delete(in.openByGroup, n.GroupKey)
		return Received{Outcome: OutcomeResolved, IncidentID: open.Incident.ID}, nil
	}

	alerts := slices.DeleteFunc(slices.Clone(n.Alerts), func(a Alert) bool { return isHeartbeat(n, a) })
	if len(alerts) == 0 {
		in.heartbeats++
		in.lastHeartbeat = now
		return Received{Outcome: OutcomeHeartbeat, Reason: "heartbeat alerts are recorded, never investigated"}, nil
	}
	n.Alerts = alerts

	fp := Fingerprint(n)
	existing, seen := in.byFingerprint[fp]
	if !seen {
		// A group that is already open absorbs the notification even when its
		// earliest alert changed: two investigations of one alert group is what
		// dedupe exists to prevent.
		existing, seen = in.openByGroup[n.GroupKey]
	}
	if seen {
		existing.UpdatedAt = now
		existing.Notifications = append(existing.Notifications, Delivery{At: now, Outcome: OutcomeDuplicate, Payload: payload})
		return Received{Outcome: OutcomeDuplicate, IncidentID: existing.Incident.ID}, nil
	}

	record, err := in.normalize(n, fp, now)
	if err != nil {
		in.unmapped = append(in.unmapped, Delivery{At: now, Outcome: OutcomeUnmapped, Payload: payload})
		return Received{Outcome: OutcomeUnmapped, Reason: err.Error()}, nil
	}
	record.Notifications = []Delivery{{At: now, Outcome: OutcomeOpened, Payload: payload}}
	in.records = append(in.records, record)
	in.byID[record.Incident.ID] = record
	in.byFingerprint[fp] = record
	in.openByGroup[n.GroupKey] = record
	return Received{Outcome: OutcomeOpened, IncidentID: record.Incident.ID}, nil
}

// Fingerprint is the dedupe key: the group, its status, and the first start
// (firing) or last end (resolved) among its alerts. Alertmanager re-sends a
// group on every repeat interval with the same alerts, so a repeat has the same
// key; a group that resolves and fires again starts later, so it does not.
func Fingerprint(n Notification) string {
	var anchor time.Time
	for _, a := range n.Alerts {
		t := a.StartsAt
		if n.Status == StatusResolved {
			t = a.EndsAt
		}
		switch {
		case anchor.IsZero():
			anchor = t
		case n.Status == StatusResolved && t.After(anchor):
			anchor = t
		case n.Status != StatusResolved && t.Before(anchor):
			anchor = t
		}
	}
	sum := sha256.Sum256([]byte(n.GroupKey + "|" + n.Status + "|" + anchor.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:])
}

func isHeartbeat(n Notification, a Alert) bool {
	return n.label(a, "alertname") == "Watchdog" || n.label(a, "severity") == "heartbeat"
}

// normalize builds the incident from the earliest alert in the group, which is
// the one whose start anchors the evidence window.
func (in *Intake) normalize(n Notification, fp string, now time.Time) (*Record, error) {
	first := n.Alerts[0]
	for _, a := range n.Alerts[1:] {
		if a.StartsAt.Before(first.StartsAt) {
			first = a
		}
	}
	service := ""
	for _, name := range in.cfg.ServiceLabels {
		if service = n.label(first, name); service != "" {
			break
		}
	}
	if service == "" {
		return nil, fmt.Errorf("no service label (tried %v)", in.cfg.ServiceLabels)
	}
	environment := n.label(first, "environment")
	if environment == "" {
		environment = n.label(first, "env")
	}
	if environment == "" {
		environment = in.cfg.Environment
	}
	alertname := n.label(first, "alertname")
	symptom := n.annotation(first, "summary")
	if symptom == "" {
		symptom = n.annotation(first, "description")
	}
	if symptom == "" {
		symptom = alertname
	}
	if symptom == "" {
		symptom = "alert fired"
	}
	// Alert text is written by whoever wrote the rule and travels to the
	// planner as the incident's symptom, so it is redacted and bounded like
	// any other untrusted text.
	symptom, _ = gateway.RedactText(symptom)
	if len(symptom) > maxSymptomBytes {
		cut := maxSymptomBytes
		for cut > 0 && !utf8.RuneStart(symptom[cut]) {
			cut--
		}
		symptom = symptom[:cut] + " (truncated)"
	}

	started := first.StartsAt.UTC()
	window := gateway.Window{Start: started.Add(-in.cfg.Lookback), End: now}
	if limit := window.Start.Add(gateway.MaxWindow); window.End.After(limit) {
		window.End = limit
	}
	if !window.End.After(started) {
		// A start in the future (clock skew between Alertmanager and Probe)
		// still gets a window that contains it.
		window.End = started.Add(time.Minute)
	}

	incident := investigation.Incident{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "INC-alert-" + fp[:12],
		Environment:   environment,
		Service:       service,
		Symptom:       symptom,
		Trigger:       investigation.TriggerAlert,
		StartedAt:     started,
		Window:        window,
		Status:        investigation.IncidentOpen,
	}
	if err := incident.Validate(); err != nil {
		return nil, fmt.Errorf("alert does not make a valid incident: %w", err)
	}
	entity := n.label(first, "pod")
	if entity == "" {
		entity = n.label(first, "instance")
	}
	return &Record{
		Incident:    incident,
		Fingerprint: fp,
		GroupKey:    n.GroupKey,
		Alertname:   alertname,
		Severity:    n.label(first, "severity"),
		Namespace:   n.label(first, "namespace"),
		Entity:      entity,
		Alert:       AlertFiring,
		ReceivedAt:  now,
		UpdatedAt:   now,
	}, nil
}

const maxSymptomBytes = 512

// Get returns a copy of one incident.
func (in *Intake) Get(id string) (Record, bool) {
	in.mu.Lock()
	defer in.mu.Unlock()
	r, ok := in.byID[id]
	if !ok {
		return Record{}, false
	}
	return copyRecord(r), true
}

// List returns copies of every incident, oldest first.
func (in *Intake) List() []Record {
	in.mu.Lock()
	defer in.mu.Unlock()
	out := make([]Record, 0, len(in.records))
	for _, r := range in.records {
		out = append(out, copyRecord(r))
	}
	return out
}

// Heartbeats returns how many heartbeat notifications arrived, and when the
// last one did. A heartbeat that stops arriving means alerting itself is down.
func (in *Intake) Heartbeats() (int, time.Time) {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.heartbeats, in.lastHeartbeat
}

// Unmapped returns the firing notifications no incident could be built from.
func (in *Intake) Unmapped() []Delivery {
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.unmapped)
}

func copyRecord(r *Record) Record {
	c := *r
	c.Notifications = slices.Clone(r.Notifications)
	if r.ResolvedAt != nil {
		at := *r.ResolvedAt
		c.ResolvedAt = &at
	}
	return c
}
