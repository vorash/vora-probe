package investigation

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
)

// SampleFact is one measurement, kept with the observation it came from.
type SampleFact struct {
	ObsID string
	At    time.Time
	Value float64
}

// RestartFact is the termination history of one container.
type RestartFact struct {
	ObsID                string
	Pod                  string
	Container            string
	Count                int
	Ready                bool
	State                string
	LastTerminatedAt     *time.Time
	LastTerminatedReason string
	LastExitCode         *int
}

func (r RestartFact) OOMKilled() bool {
	if strings.EqualFold(r.LastTerminatedReason, "OOMKilled") {
		return true
	}
	return r.LastExitCode != nil && *r.LastExitCode == 137
}

type EventFact struct {
	ObsID          string
	Type           string
	Reason         string
	Message        string
	InvolvedObject string
	Count          int
	LastSeen       time.Time
}

func (e EventFact) Mentions(needles ...string) bool {
	hay := strings.ToLower(e.Reason + " " + e.Message)
	for _, n := range needles {
		if strings.Contains(hay, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

type RolloutFact struct {
	ObsID             string
	Name              string
	Image             string
	CompletedAt       time.Time
	Replicas          int
	AvailableReplicas int
}

// CoverageGap is evidence that was requested but is missing, truncated or
// otherwise unusable. Gaps are reported, never smoothed over.
type CoverageGap struct {
	ObsID        string
	Action       gateway.ActionKind
	Metric       string
	Completeness Completeness
	Reason       string
}

func (g CoverageGap) String() string {
	target := string(g.Action)
	if g.Metric != "" {
		target += " " + g.Metric
	}
	if g.Reason != "" {
		return target + ": " + string(g.Completeness) + " (" + g.Reason + ")"
	}
	return target + ": " + string(g.Completeness)
}

// Facts is the deterministic, evidence-linked view of one entity. Every value
// carries the observation it was read from, so a claim built on Facts can always
// be traced back to stored evidence.
type Facts struct {
	Entity     string
	Memory     []SampleFact
	MemorySpec []SampleFact
	CPU        []SampleFact
	Latency    []SampleFact
	Errors     []SampleFact
	QueryCount []SampleFact
	Restarts   []RestartFact
	Events     []EventFact
	Rollouts   []RolloutFact
	Gaps       []CoverageGap
}

// BuildFacts converts normalized observations into Facts for one entity.
// Observations for other entities are ignored: an unrelated service's memory
// trend must not leak into this incident.
func BuildFacts(entity string, obs []Observation) Facts {
	f := Facts{Entity: entity}
	for _, o := range obs {
		if !matchesEntity(o.Entity, entity) {
			continue
		}
		if o.Type == ObsDerived {
			// Derived observations are computed from facts, so feeding them back
			// into BuildFacts would be circular and would register a gap for the
			// payload they deliberately do not carry.
			continue
		}
		switch o.Completeness {
		case Complete, Redacted:
		default:
			f.Gaps = append(f.Gaps, CoverageGap{
				ObsID:        o.ID,
				Action:       o.Action,
				Metric:       metricOf(o),
				Completeness: o.Completeness,
				Reason:       o.Statement,
			})
			continue
		}
		switch o.Action {
		case gateway.ActionMetricsQuery:
			series, err := gateway.Response{Status: gateway.StatusOK, Payload: o.Payload}.MetricSeries()
			if err != nil {
				f.Gaps = append(f.Gaps, CoverageGap{ObsID: o.ID, Action: o.Action, Completeness: Incomplete, Reason: err.Error()})
				continue
			}
			samples := make([]SampleFact, 0, len(series.Samples))
			for _, s := range series.Samples {
				samples = append(samples, SampleFact{ObsID: o.ID, At: s.At.UTC(), Value: s.Value})
			}
			switch series.Metric {
			case "container_memory_working_set_bytes":
				f.Memory = append(f.Memory, samples...)
			case "container_spec_memory_limit_bytes":
				f.MemorySpec = append(f.MemorySpec, samples...)
			case "container_cpu_usage_ratio":
				f.CPU = append(f.CPU, samples...)
			case "request_latency_p99_seconds":
				f.Latency = append(f.Latency, samples...)
			case "request_error_rate":
				f.Errors = append(f.Errors, samples...)
			case "db_query_count":
				f.QueryCount = append(f.QueryCount, samples...)
			}
		case gateway.ActionKubernetesContainers:
			pods, err := gateway.Response{Status: gateway.StatusOK, Payload: o.Payload}.Pods()
			if err != nil {
				f.Gaps = append(f.Gaps, CoverageGap{ObsID: o.ID, Action: o.Action, Completeness: Incomplete, Reason: err.Error()})
				continue
			}
			for _, p := range pods.Pods {
				if !matchesEntity(p.Name, entity) {
					continue
				}
				for _, c := range p.Containers {
					f.Restarts = append(f.Restarts, RestartFact{
						ObsID:                o.ID,
						Pod:                  p.Name,
						Container:            c.Name,
						Count:                c.RestartCount,
						Ready:                c.Ready,
						State:                c.State,
						LastTerminatedAt:     c.LastTerminatedAt,
						LastTerminatedReason: c.LastTerminatedReason,
						LastExitCode:         c.LastExitCode,
					})
				}
			}
		case gateway.ActionKubernetesEvents:
			events, err := gateway.Response{Status: gateway.StatusOK, Payload: o.Payload}.Events()
			if err != nil {
				f.Gaps = append(f.Gaps, CoverageGap{ObsID: o.ID, Action: o.Action, Completeness: Incomplete, Reason: err.Error()})
				continue
			}
			for _, e := range events.Events {
				if e.InvolvedObject != "" && !matchesEntity(e.InvolvedObject, entity) {
					continue
				}
				f.Events = append(f.Events, EventFact{
					ObsID:          o.ID,
					Type:           e.Type,
					Reason:         e.Reason,
					Message:        e.Message,
					InvolvedObject: e.InvolvedObject,
					Count:          e.Count,
					LastSeen:       e.LastSeen.UTC(),
				})
			}
		case gateway.ActionKubernetesDeployments:
			deployments, err := gateway.Response{Status: gateway.StatusOK, Payload: o.Payload}.Deployments()
			if err != nil {
				f.Gaps = append(f.Gaps, CoverageGap{ObsID: o.ID, Action: o.Action, Completeness: Incomplete, Reason: err.Error()})
				continue
			}
			for _, d := range deployments.Deployments {
				if !matchesEntity(d.Name, entity) {
					continue
				}
				f.Rollouts = append(f.Rollouts, RolloutFact{
					ObsID:             o.ID,
					Name:              d.Name,
					Image:             d.Image,
					CompletedAt:       d.RolloutCompletedAt.UTC(),
					Replicas:          d.Replicas,
					AvailableReplicas: d.AvailableReplicas,
				})
			}
		}
	}
	return f
}

func metricOf(o Observation) string {
	if o.Query.Params == nil {
		return ""
	}
	return o.Query.Params["metric"]
}

// seriesOf decodes a metrics.query observation's payload. It is guarded on the
// action kind because json.Unmarshal silently ignores unknown fields, so a pod
// list would otherwise decode into an empty series without error.
func seriesOf(o Observation) (gateway.MetricSeries, bool) {
	if o.Action != gateway.ActionMetricsQuery || len(o.Payload) == 0 {
		return gateway.MetricSeries{}, false
	}
	var s gateway.MetricSeries
	if err := json.Unmarshal(o.Payload, &s); err != nil {
		return gateway.MetricSeries{}, false
	}
	return s, true
}

func matchesEntity(name, entity string) bool {
	if name == "" || entity == "" {
		return false
	}
	return name == entity || strings.HasPrefix(name, entity+"-")
}

// MemorySamples projects the memory facts onto the calc layer.
func (f Facts) MemorySamples() []Sample { return samples(f.Memory) }

func (f Facts) CPUSamples() []Sample { return samples(f.CPU) }

func (f Facts) LatencySamples() []Sample { return samples(f.Latency) }

func (f Facts) QueryCountSamples() []Sample { return samples(f.QueryCount) }

func samples(in []SampleFact) []Sample {
	out := make([]Sample, 0, len(in))
	for _, s := range in {
		out = append(out, Sample{At: s.At, Value: s.Value})
	}
	return out
}

// PeakMemory is the highest observed working set. It exists even when the
// container limit is unknown.
func (f Facts) PeakMemory() (SampleFact, bool) {
	var peak SampleFact
	found := false
	for _, s := range f.Memory {
		if !found || s.Value > peak.Value {
			peak, found = s, true
		}
	}
	return peak, found
}

// MemoryLimit is the configured container memory limit, if it was collected.
func (f Facts) MemoryLimit() (SampleFact, bool) {
	var last SampleFact
	found := false
	for _, s := range f.MemorySpec {
		if !found || s.At.After(last.At) {
			last, found = s, true
		}
	}
	return last, found
}

// OOMTerminations are containers whose last termination is a memory-limit kill.
func (f Facts) OOMTerminations() []RestartFact {
	var out []RestartFact
	for _, r := range f.Restarts {
		if r.OOMKilled() {
			out = append(out, r)
		}
	}
	return out
}

// OOMEvents are Kubernetes events that name an out-of-memory kill.
func (f Facts) OOMEvents() []EventFact {
	var out []EventFact
	for _, e := range f.Events {
		if e.Mentions("OOMKilling", "OOMKilled") {
			out = append(out, e)
		}
	}
	return out
}

// ProbeFailures are liveness or readiness probe failures.
func (f Facts) ProbeFailures() []EventFact {
	var out []EventFact
	for _, e := range f.Events {
		if e.Mentions("Unhealthy", "probe failed", "Liveness probe", "Readiness probe") {
			out = append(out, e)
		}
	}
	return out
}

// NonOOMTerminations are containers that terminated for a stated reason other
// than a memory-limit kill.
func (f Facts) NonOOMTerminations() []RestartFact {
	var out []RestartFact
	for _, r := range f.Restarts {
		if r.OOMKilled() {
			continue
		}
		if r.LastTerminatedReason != "" || r.LastExitCode != nil {
			out = append(out, r)
		}
	}
	return out
}

// RestartCount is the highest restart count seen for the entity.
func (f Facts) RestartCount() (int, bool) {
	best, found := 0, false
	for _, r := range f.Restarts {
		if !found || r.Count > best {
			best, found = r.Count, true
		}
	}
	return best, found
}

// LatestRollout is the most recent completed rollout of the entity.
func (f Facts) LatestRollout() (RolloutFact, bool) {
	var latest RolloutFact
	found := false
	for _, r := range f.Rollouts {
		if !found || r.CompletedAt.After(latest.CompletedAt) {
			latest, found = r, true
		}
	}
	return latest, found
}

// ObsIDs collects the distinct observation IDs backing a set of facts, for
// citation in claims.
func ObsIDs(ids ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
