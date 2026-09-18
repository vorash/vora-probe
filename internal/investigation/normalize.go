package investigation

import (
	"fmt"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
)

// ObservationFromResponse turns one recorded or collected answer into a
// normalized observation.
//
// The statement is rendered here, in code, from the payload. A model never
// authors a number that reaches a report, and the same answer always renders to
// the same sentence.
func ObservationFromResponse(id string, a gateway.Action, r gateway.Response, retrievedAt time.Time) (Observation, error) {
	if err := a.Validate(); err != nil {
		return Observation{}, fmt.Errorf("observation %s: %w", id, err)
	}
	if err := r.Validate(); err != nil {
		return Observation{}, fmt.Errorf("observation %s: %w", id, err)
	}
	if r.Kind != a.Kind {
		return Observation{}, fmt.Errorf("observation %s: response kind %q does not match request kind %q", id, r.Kind, a.Kind)
	}

	o := Observation{
		SchemaVersion: gateway.SchemaVersion,
		ID:            id,
		Type:          observationType(a.Kind),
		Action:        a.Kind,
		Source:        r.Query.Datasource,
		Entity:        a.Entity,
		Window:        observationWindow(a, r),
		RetrievedAt:   retrievedAt.UTC(),
		Query:         withMetric(a, r.Query),
		Digest:        r.Digest,
		Completeness:  r.Completeness,
		Payload:       r.Payload,
	}
	if r.Status != gateway.StatusOK && r.Status != gateway.StatusPartial {
		o.Type = observationType(a.Kind)
		o.Statement = fmt.Sprintf("%s is unavailable: %s", target(a), r.Reason)
		return o, nil
	}

	statement, err := renderStatement(a, r)
	if err != nil {
		return Observation{}, fmt.Errorf("observation %s: %w", id, err)
	}
	o.Statement = statement
	return o, nil
}

func observationType(k gateway.ActionKind) ObservationType {
	switch k {
	case gateway.ActionMetricsQuery:
		return ObsMetric
	case gateway.ActionKubernetesContainers:
		return ObsK8sContainerState
	case gateway.ActionKubernetesEvents:
		return ObsK8sEvent
	case gateway.ActionKubernetesDeployments:
		return ObsK8sDeployment
	default:
		return ObsK8sEvent
	}
}

func observationWindow(a gateway.Action, r gateway.Response) Window {
	if a.Window != nil {
		return *a.Window
	}
	// Snapshot queries have no requested window. Recording the retrieval instant
	// as a point window keeps the omission visible instead of implied.
	return Window{Start: r.RetrievedAt.UTC(), End: r.RetrievedAt.UTC()}
}

func withMetric(a gateway.Action, q gateway.QueryMeta) gateway.QueryMeta {
	if a.Metric == "" {
		return q
	}
	if q.Params == nil {
		q.Params = map[string]string{}
	}
	q.Params["metric"] = a.Metric
	return q
}

func target(a gateway.Action) string {
	if a.Metric != "" {
		return a.Metric + " for " + a.Entity
	}
	return string(a.Kind) + " for " + a.Entity
}

func renderStatement(a gateway.Action, r gateway.Response) (string, error) {
	switch a.Kind {
	case gateway.ActionMetricsQuery:
		series, err := r.MetricSeries()
		if err != nil {
			return "", err
		}
		st, err := Summarize(metricSamples(series))
		if err != nil {
			return fmt.Sprintf("%s for %s returned no samples over %s", a.Metric, a.Entity, FormatDuration(a.Window.End.Sub(a.Window.Start))), nil
		}
		return fmt.Sprintf(
			"%s for %s: %d samples over %s, %.1f%% change (first %s, last %s, min %s, max %s)",
			a.Metric, a.Entity, st.Count, FormatDuration(st.Span), PercentChange(st.First, st.Last),
			FormatFloat(st.First, 3), FormatFloat(st.Last, 3), FormatFloat(st.Min, 3), FormatFloat(st.Max, 3)), nil
	case gateway.ActionKubernetesContainers:
		pods, err := r.Pods()
		if err != nil {
			return "", err
		}
		return renderContainers(a, pods), nil
	case gateway.ActionKubernetesEvents:
		events, err := r.Events()
		if err != nil {
			return "", err
		}
		return renderEvents(a, events), nil
	case gateway.ActionKubernetesDeployments:
		deployments, err := r.Deployments()
		if err != nil {
			return "", err
		}
		return renderDeployments(a, deployments), nil
	default:
		return string(a.Kind) + " for " + a.Entity + " returned a result", nil
	}
}

func metricSamples(s gateway.MetricSeries) []Sample {
	out := make([]Sample, 0, len(s.Samples))
	for _, v := range s.Samples {
		out = append(out, Sample{At: v.At, Value: v.Value})
	}
	return out
}

func renderContainers(a gateway.Action, pods gateway.PodList) string {
	var parts []string
	for _, p := range pods.Pods {
		if !matchesEntity(p.Name, a.Entity) {
			continue
		}
		for _, c := range p.Containers {
			desc := fmt.Sprintf("%s/%s restarted %d times, ready=%t, state %s", p.Name, c.Name, c.RestartCount, c.Ready, c.State)
			if c.Reason != "" {
				desc += " (" + c.Reason + ")"
			}
			if c.LastTerminatedReason != "" || c.LastExitCode != nil {
				term := "last termination"
				if c.LastTerminatedAt != nil {
					term += " at " + c.LastTerminatedAt.UTC().Format(time.RFC3339)
				}
				if c.LastTerminatedReason != "" {
					term += " reason " + c.LastTerminatedReason
				}
				if c.LastExitCode != nil {
					term += fmt.Sprintf(" exit %d", *c.LastExitCode)
				}
				desc += "; " + term
			}
			parts = append(parts, desc)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no containers matching %s were returned", a.Entity)
	}
	return joinBounded(parts, "; ")
}

func renderEvents(a gateway.Action, events gateway.EventList) string {
	var parts []string
	for _, e := range events.Events {
		if e.InvolvedObject != "" && !matchesEntity(e.InvolvedObject, a.Entity) {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s (x%d, last %s): %s",
			e.Reason, e.Count, e.LastSeen.UTC().Format(time.RFC3339), e.Message))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no events matching %s were returned", a.Entity)
	}
	return joinBounded(parts, " | ")
}

func renderDeployments(a gateway.Action, deployments gateway.DeploymentList) string {
	var parts []string
	for _, d := range deployments.Deployments {
		if !matchesEntity(d.Name, a.Entity) {
			continue
		}
		desc := fmt.Sprintf("%s rolled out", d.Name)
		if d.Image != "" {
			desc += " image " + d.Image
		}
		desc += " at " + d.RolloutCompletedAt.UTC().Format(time.RFC3339)
		desc += fmt.Sprintf(" (%d/%d replicas available)", d.AvailableReplicas, d.Replicas)
		parts = append(parts, desc)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("no deployments matching %s were returned", a.Entity)
	}
	return joinBounded(parts, "; ")
}

// maxStatementBytes bounds a rendered statement. Statements are the part of an
// observation that reaches a model and the worker state, so an unusually large
// answer must not be able to inflate either; the omitted count keeps the
// truncation visible.
const maxStatementBytes = 2048

func joinBounded(parts []string, sep string) string {
	var b strings.Builder
	for i, p := range parts {
		extra := len(p)
		if b.Len() > 0 {
			extra += len(sep)
		}
		if b.Len()+extra > maxStatementBytes {
			fmt.Fprintf(&b, "%s(%d further entries omitted: statement length is bounded)", sep, len(parts)-i)
			return b.String()
		}
		if b.Len() > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
	}
	return b.String()
}
