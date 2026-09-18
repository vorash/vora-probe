// Package gateway owns the infrastructure contract Probe is allowed to speak.
//
// The contract is deliberately narrow. Probe never accepts an executable, URL
// or shell command from a model: a model may only name one of these actions,
// and everything absent from AllowedActions is denied by default. Payloads are
// typed so that evidence can be reasoned about structurally instead of by
// scraping text.
//
// This package intentionally depends on nothing else in the repository so that
// it can act as the dependency root for both the investigation domain and the
// tool gateway.
package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the contract version shared by fixtures, records and
// persisted artifacts. A mismatch is an error, never an implicit upgrade.
const SchemaVersion = "probe/v1"

// Window is a half-open UTC evidence window. Probe only ever asks for fixed
// windows: relative windows such as "last 15m" would make replay non-reproducible.
type Window struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (w Window) Validate(max time.Duration) error {
	if w.Start.IsZero() || w.End.IsZero() {
		return fmt.Errorf("window bounds must be set")
	}
	if !w.End.After(w.Start) {
		return fmt.Errorf("window end %s must be after start %s", w.End, w.Start)
	}
	if span := w.End.Sub(w.Start); span > max {
		return fmt.Errorf("window span %s exceeds maximum %s", span, max)
	}
	return nil
}

// ActionKind enumerates every infrastructure operation Probe may request.
type ActionKind string

const (
	ActionMetricsQuery          ActionKind = "metrics.query"
	ActionKubernetesContainers  ActionKind = "kubernetes.containers"
	ActionKubernetesEvents      ActionKind = "kubernetes.events"
	ActionKubernetesDeployments ActionKind = "kubernetes.deployments"
)

// AllowedActions is exhaustive: absence means denial.
var AllowedActions = []ActionKind{
	ActionMetricsQuery,
	ActionKubernetesContainers,
	ActionKubernetesEvents,
	ActionKubernetesDeployments,
}

// AllowedMetrics bounds metrics.query. A free-form metric name would turn the
// gateway into an arbitrary PromQL surface.
var AllowedMetrics = []string{
	"container_memory_working_set_bytes",
	"container_spec_memory_limit_bytes",
	"container_cpu_usage_ratio",
	"request_latency_p99_seconds",
	"request_error_rate",
	"db_query_count",
}

// MechanismMetrics are the metric names that can explain *how* a fault
// produced impact. They are distinct from symptom metrics, which only describe
// the impact itself. The claims policy uses this distinction to refuse
// "the deployment caused it" conclusions built on symptom evidence alone.
var MechanismMetrics = []string{"db_query_count"}

// SymptomMetrics describe impact only.
var SymptomMetrics = []string{"request_latency_p99_seconds", "request_error_rate"}

func equalsOneOf(v string, allowed []string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func ActionAllowed(kind ActionKind) bool {
	for _, k := range AllowedActions {
		if k == kind {
			return true
		}
	}
	return false
}

func MetricAllowed(metric string) bool { return equalsOneOf(metric, AllowedMetrics) }

func MechanismMetric(metric string) bool { return equalsOneOf(metric, MechanismMetrics) }

func SymptomMetric(metric string) bool { return equalsOneOf(metric, SymptomMetrics) }

// Action is a bounded, typed request. Everything Probe does to the outside
// world is one of these.
type Action struct {
	Kind       ActionKind `json:"kind"`
	Entity     string     `json:"entity"`
	Reason     string     `json:"reason"`
	Metric     string     `json:"metric,omitempty"`
	Window     *Window    `json:"window,omitempty"`
	Resolution string     `json:"resolution,omitempty"`
}

// MaxWindow bounds a single evidence request. Wider windows are the controller's
// job to split, not the model's job to widen.
const MaxWindow = time.Hour

func (a Action) Validate() error {
	if !ActionAllowed(a.Kind) {
		return fmt.Errorf("action %q is not allowed", a.Kind)
	}
	if a.Entity == "" {
		return fmt.Errorf("action %q requires an entity", a.Kind)
	}
	if len(a.Entity) > 253 {
		return fmt.Errorf("entity %q exceeds 253 bytes", a.Entity)
	}
	if a.Reason == "" {
		return fmt.Errorf("action %q requires a reason", a.Kind)
	}
	if len(a.Reason) > 1024 {
		return fmt.Errorf("reason exceeds 1024 bytes")
	}
	switch a.Kind {
	case ActionMetricsQuery:
		if !MetricAllowed(a.Metric) {
			return fmt.Errorf("metric %q is not allowed", a.Metric)
		}
		if a.Window == nil {
			return fmt.Errorf("metrics.query requires a window")
		}
		if a.Resolution == "" {
			return fmt.Errorf("metrics.query requires a resolution")
		}
	case ActionKubernetesEvents:
		if a.Metric != "" {
			return fmt.Errorf("kubernetes.events does not take a metric")
		}
		if a.Window == nil {
			return fmt.Errorf("kubernetes.events requires a window")
		}
	default:
		if a.Metric != "" || a.Window != nil || a.Resolution != "" {
			return fmt.Errorf("action %q takes no metric, window or resolution", a.Kind)
		}
	}
	if a.Window != nil {
		return a.Window.Validate(MaxWindow)
	}
	return nil
}

// Key is the canonical identity of a request, used to match recorded evidence
// during offline replay.
func (a Action) Key() string {
	start, end := "", ""
	if a.Window != nil {
		start = a.Window.Start.UTC().Format(time.RFC3339)
		end = a.Window.End.UTC().Format(time.RFC3339)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s", a.Kind, a.Entity, a.Metric, start, end, a.Resolution)
}

func (a Action) String() string {
	if a.Metric != "" {
		return fmt.Sprintf("%s(%s, %s)", a.Kind, a.Entity, a.Metric)
	}
	return fmt.Sprintf("%s(%s)", a.Kind, a.Entity)
}

// ResponseStatus says whether the request produced usable data at all.
type ResponseStatus string

const (
	StatusOK          ResponseStatus = "ok"
	StatusPartial     ResponseStatus = "partial"
	StatusUnavailable ResponseStatus = "unavailable"
)

// Completeness is always recorded. A truncated or unavailable result is never
// silently treated as complete: it becomes an explicit coverage limitation in
// the report.
type Completeness string

const (
	Complete    Completeness = "complete"
	Truncated   Completeness = "truncated"
	Redacted    Completeness = "redacted"
	Incomplete  Completeness = "incomplete"
	Unavailable Completeness = "unavailable"
)

func (c Completeness) Valid() bool {
	switch c {
	case Complete, Truncated, Redacted, Incomplete, Unavailable:
		return true
	}
	return false
}

// QueryMeta records exactly what was asked so every observation can be
// reproduced or argued with later.
type QueryMeta struct {
	Datasource string            `json:"datasource"`
	Query      string            `json:"query"`
	Params     map[string]string `json:"params,omitempty"`
	Resolution string            `json:"resolution,omitempty"`
}

// Response is a recorded or collected infrastructure answer. Payload is decoded
// into a typed structure according to Kind.
type Response struct {
	SchemaVersion string          `json:"schema_version"`
	Kind          ActionKind      `json:"kind"`
	Entity        string          `json:"entity"`
	Status        ResponseStatus  `json:"status"`
	Completeness  Completeness    `json:"completeness"`
	RetrievedAt   time.Time       `json:"retrieved_at"`
	Query         QueryMeta       `json:"query"`
	Reason        string          `json:"reason,omitempty"`
	Digest        string          `json:"digest"`
	Payload       json.RawMessage `json:"payload,omitempty"`
}

func (r Response) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("response schema_version %q, want %q", r.SchemaVersion, SchemaVersion)
	}
	if !ActionAllowed(r.Kind) {
		return fmt.Errorf("response kind %q is not allowed", r.Kind)
	}
	switch r.Status {
	case StatusOK, StatusPartial, StatusUnavailable:
	default:
		return fmt.Errorf("response status %q is invalid", r.Status)
	}
	if !r.Completeness.Valid() {
		return fmt.Errorf("response completeness %q is invalid", r.Completeness)
	}
	if r.Status == StatusUnavailable && r.Completeness != Unavailable {
		return fmt.Errorf("unavailable response must have unavailable completeness")
	}
	if r.Status == StatusUnavailable && r.Payload != nil {
		return fmt.Errorf("unavailable response must not carry a payload")
	}
	if r.RetrievedAt.IsZero() {
		return fmt.Errorf("response retrieved_at must be set")
	}
	if r.Digest != Digest(r.Payload) {
		return fmt.Errorf("response digest does not match payload")
	}
	return nil
}

// Digest is the content digest recorded for every payload, so that a report can
// be argued against the exact bytes it was produced from. Formatting is
// canonicalised away: a payload that is merely re-indented keeps its digest,
// while any change in content changes it.
func Digest(payload []byte) string {
	canonical := payload
	if len(payload) > 0 {
		var buf bytes.Buffer
		if err := json.Compact(&buf, payload); err == nil {
			canonical = buf.Bytes()
		}
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r Response) decode() error {
	if r.Status != StatusOK && r.Status != StatusPartial {
		return fmt.Errorf("response for %s is %s: %s", r.Kind, r.Status, r.Reason)
	}
	if len(r.Payload) == 0 {
		return fmt.Errorf("response for %s carries no payload", r.Kind)
	}
	return nil
}

func (r Response) MetricSeries() (MetricSeries, error) {
	var v MetricSeries
	if err := r.decode(); err != nil {
		return v, err
	}
	return v, json.Unmarshal(r.Payload, &v)
}

func (r Response) Pods() (PodList, error) {
	var v PodList
	if err := r.decode(); err != nil {
		return v, err
	}
	return v, json.Unmarshal(r.Payload, &v)
}

func (r Response) Events() (EventList, error) {
	var v EventList
	if err := r.decode(); err != nil {
		return v, err
	}
	return v, json.Unmarshal(r.Payload, &v)
}

func (r Response) Deployments() (DeploymentList, error) {
	var v DeploymentList
	if err := r.decode(); err != nil {
		return v, err
	}
	return v, json.Unmarshal(r.Payload, &v)
}

// MetricSeries is the payload of metrics.query.
type MetricSeries struct {
	Metric  string         `json:"metric"`
	Unit    string         `json:"unit"`
	Samples []MetricSample `json:"samples"`
}

type MetricSample struct {
	At    time.Time `json:"at"`
	Value float64   `json:"value"`
}

// PodList is the payload of kubernetes.pods.
type PodList struct {
	Namespace string `json:"namespace"`
	Pods      []Pod  `json:"pods"`
}

type Pod struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Phase      string            `json:"phase"`
	Node       string            `json:"node,omitempty"`
	StartTime  time.Time         `json:"start_time"`
	Containers []ContainerStatus `json:"containers"`
}

// ContainerStatus carries the termination history that distinguishes an
// evidenced memory-limit kill from an unproven memory problem.
type ContainerStatus struct {
	Name                 string     `json:"name"`
	Ready                bool       `json:"ready"`
	RestartCount         int        `json:"restart_count"`
	State                string     `json:"state"`
	Reason               string     `json:"reason,omitempty"`
	LastTerminatedAt     *time.Time `json:"last_terminated_at,omitempty"`
	LastTerminatedReason string     `json:"last_terminated_reason,omitempty"`
	LastExitCode         *int       `json:"last_exit_code,omitempty"`
}

// EventList is the payload of kubernetes.events.
type EventList struct {
	Namespace string  `json:"namespace"`
	Events    []Event `json:"events"`
}

type Event struct {
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	InvolvedObject string    `json:"involved_object"`
	Count          int       `json:"count"`
	FirstSeen      time.Time `json:"first_seen"`
	LastSeen       time.Time `json:"last_seen"`
}

// DeploymentList is the payload of kubernetes.deployments. Rollout timestamps
// are the only change context this slice collects: repository and diff
// evidence is deliberately deferred.
type DeploymentList struct {
	Namespace   string       `json:"namespace"`
	Deployments []Deployment `json:"deployments"`
}

type Deployment struct {
	Name               string    `json:"name"`
	Namespace          string    `json:"namespace"`
	Image              string    `json:"image,omitempty"`
	Replicas           int       `json:"replicas"`
	AvailableReplicas  int       `json:"available_replicas"`
	RolloutCompletedAt time.Time `json:"rollout_completed_at"`
}
