package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	// Investigation is what became of the incident after intake. An incident
	// is never just dropped: held back by a rate limit is a state too.
	Investigation Investigation `json:"investigation"`
	// Post is the incident's message in chat, once there is one. Its ts is
	// what makes delivery idempotent: a retry that finds it does not post
	// again, and resolutions go into its thread.
	Post *Post `json:"post,omitempty"`
	// Forecast is set on an incident a forecast opened (trigger "forecast").
	Forecast *ForecastState `json:"forecast,omitempty"`
}

// Post records one incident's outbound message.
type Post struct {
	Channel      string     `json:"channel,omitempty"`
	TS           string     `json:"ts,omitempty"`
	PostedAt     *time.Time `json:"posted_at,omitempty"`
	ResolutionTS string     `json:"resolution_ts,omitempty"`
	// RevisionsPosted is how many of a forecast's revisions the thread has
	// heard about, so a revision is posted once whatever triggers it.
	RevisionsPosted int `json:"revisions_posted,omitempty"`
	Attempts        int `json:"attempts,omitempty"`
	// Error is the last failure. Delivery failing never fails the
	// investigation: the report is already on disk.
	Error string `json:"error,omitempty"`
}

// InvestigationState is where an incident is in the queue.
type InvestigationState string

const (
	InvestigationPending      InvestigationState = ""
	InvestigationQueued       InvestigationState = "queued"
	InvestigationRateLimited  InvestigationState = "rate_limited"
	InvestigationRunning      InvestigationState = "investigating"
	InvestigationConcluded    InvestigationState = "concluded"
	InvestigationNotConcluded InvestigationState = "not_concluded"
	// InvestigationError: the run could not even produce a report, for
	// example because its journal could not be opened.
	InvestigationError InvestigationState = "error"
)

// Investigation records one incident's investigation, as the server saw it.
type Investigation struct {
	State InvestigationState `json:"state,omitempty"`
	// Attempt numbers the runs of one incident. A run interrupted by a restart
	// is retried as the next attempt, so its journal is kept, not overwritten.
	Attempt   int                     `json:"attempt,omitempty"`
	Reason    string                  `json:"reason,omitempty"`
	RunStatus investigation.RunStatus `json:"run_status,omitempty"`
	Report    string                  `json:"report,omitempty"`
	StartedAt *time.Time              `json:"started_at,omitempty"`
	EndedAt   *time.Time              `json:"ended_at,omitempty"`
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
	// log is where changes are written before they are applied; nil keeps
	// intake in memory only.
	log *os.File
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
// payload as received; it is kept redacted, never as sent. When intake has a
// log, the change is written before it is applied or acknowledged, so a
// notification that was answered is never lost: if the write fails, the sender
// gets an error and retries.
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
		err := in.commit(change{Kind: changeResolved, At: now, ID: open.Incident.ID,
			Delivery: &Delivery{At: now, Outcome: OutcomeResolved, Payload: payload}})
		if err != nil {
			return Received{}, err
		}
		return Received{Outcome: OutcomeResolved, IncidentID: open.Incident.ID}, nil
	}

	alerts := slices.DeleteFunc(slices.Clone(n.Alerts), func(a Alert) bool { return isHeartbeat(n, a) })
	if len(alerts) == 0 {
		if err := in.commit(change{Kind: changeHeartbeat, At: now}); err != nil {
			return Received{}, err
		}
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
		err := in.commit(change{Kind: changeDuplicate, At: now, ID: existing.Incident.ID,
			Delivery: &Delivery{At: now, Outcome: OutcomeDuplicate, Payload: payload}})
		if err != nil {
			return Received{}, err
		}
		return Received{Outcome: OutcomeDuplicate, IncidentID: existing.Incident.ID}, nil
	}

	record, err := in.normalize(n, fp, now)
	if err != nil {
		if err := in.commit(change{Kind: changeUnmapped, At: now,
			Delivery: &Delivery{At: now, Outcome: OutcomeUnmapped, Payload: payload}}); err != nil {
			return Received{}, err
		}
		return Received{Outcome: OutcomeUnmapped, Reason: err.Error()}, nil
	}
	record.Notifications = []Delivery{{At: now, Outcome: OutcomeOpened, Payload: payload}}
	if err := in.commit(change{Kind: changeOpened, At: now, ID: record.Incident.ID, Record: record}); err != nil {
		return Received{}, err
	}
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
		Severity:      n.label(first, "severity"),
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

// SetInvestigation records what became of an incident's investigation, and the
// incident status that follows from it when status is set. It is the one way
// the server changes a record, so every such change is in the log.
func (in *Intake) SetInvestigation(id string, inv Investigation, status investigation.IncidentStatus) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if _, ok := in.byID[id]; !ok {
		return fmt.Errorf("no incident %s", id)
	}
	return in.commit(change{Kind: changeInvestigation, At: in.cfg.Now().UTC(), ID: id, Investigation: &inv, Status: status})
}

// SetPost records the state of an incident's outbound message.
func (in *Intake) SetPost(id string, post Post) error {
	in.mu.Lock()
	defer in.mu.Unlock()
	if _, ok := in.byID[id]; !ok {
		return fmt.Errorf("no incident %s", id)
	}
	return in.commit(change{Kind: changePost, At: in.cfg.Now().UTC(), ID: id, Post: &post})
}

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
	c.ResolvedAt = copyTime(r.ResolvedAt)
	c.Investigation.StartedAt = copyTime(r.Investigation.StartedAt)
	c.Investigation.EndedAt = copyTime(r.Investigation.EndedAt)
	if r.Post != nil {
		post := *r.Post
		post.PostedAt = copyTime(r.Post.PostedAt)
		c.Post = &post
	}
	if r.Forecast != nil {
		fs := *r.Forecast
		fs.ClosedAt = copyTime(r.Forecast.ClosedAt)
		fs.LabeledAt = copyTime(r.Forecast.LabeledAt)
		c.Forecast = &fs
	}
	return c
}

func copyTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	at := *t
	return &at
}
