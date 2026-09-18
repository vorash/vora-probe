package models

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

// Task is one closed classification question.
//
// Every arm answers the same task, rendered the same way. Aggregate is the
// code-rendered measurement context for the entity: the arms that can only read
// text need it, and giving it to all of them is what stops the comparison from
// measuring what the model could infer rather than how it labels.
type Task struct {
	Hypothesis  investigation.Hypothesis
	Observation investigation.ObservationSummary
	Aggregate   []string
}

// Render is the canonical textual form of a task. It is used for the baseline
// prompt and, unchanged, for Jev's state, so a difference in answers is a
// difference in the arms and not in how the evidence was described to them.
func (t Task) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HYPOTHESIS\n%s\n", t.Hypothesis.Statement)
	fmt.Fprintf(&b, "fault domain: %s\nclaim kind: %s\n\n", t.Hypothesis.FaultDomain, t.Hypothesis.ClaimKind)

	fmt.Fprintf(&b, "EVIDENCE\n%s\n", t.Observation.Statement)
	fmt.Fprintf(&b, "type: %s, source: %s, completeness: %s\n", t.Observation.Type, t.Observation.Source, t.Observation.Completeness)
	if !t.Observation.Window.Start.IsZero() && !t.Observation.Window.Start.Equal(t.Observation.Window.End) {
		fmt.Fprintf(&b, "window: %s to %s\n",
			t.Observation.Window.Start.UTC().Format("2006-01-02T15:04:05Z"),
			t.Observation.Window.End.UTC().Format("2006-01-02T15:04:05Z"))
	}

	if len(t.Aggregate) > 0 {
		b.WriteString("\nMEASUREMENTS FOR THIS SERVICE\n")
		for _, line := range t.Aggregate {
			fmt.Fprintf(&b, "- %s\n", line)
		}
	}
	return b.String()
}

// Criteria renders the label set as Jev choice criteria.
func Criteria() map[string]string {
	out := make(map[string]string, len(Labels))
	for _, label := range Labels {
		out[label] = LabelDefinitions[label]
	}
	return out
}

// Definitions renders the label set for a text prompt.
func Definitions() string {
	var b strings.Builder
	for _, label := range Labels {
		fmt.Fprintf(&b, "- %s: %s\n", label, LabelDefinitions[label])
	}
	return b.String()
}

// AggregateContext renders the measurements a text-only arm needs, deterministically.
//
// These are the same derivations the report cites, so an arm reading this text
// and an arm reading the structured facts are looking at the same numbers.
func AggregateContext(f investigation.Facts) []string {
	var out []string
	if st, err := investigation.Summarize(f.MemorySamples()); err == nil {
		line := fmt.Sprintf("working set: %d samples over %s, min %s, max %s, mean %s, monotonically increasing: %t",
			st.Count, investigation.FormatDuration(st.Span),
			investigation.FormatBytes(st.Min), investigation.FormatBytes(st.Max),
			investigation.FormatBytes(st.Mean), st.MonotonicIncrease)
		if limit, ok := f.MemoryLimit(); ok && limit.Value > 0 {
			line += fmt.Sprintf(", configured limit %s (%s%% of limit at peak)",
				investigation.FormatBytes(limit.Value), investigation.FormatFloat(st.Max/limit.Value*100, 0))
		} else {
			line += ", no configured limit was collected"
		}
		out = append(out, line)
	}
	if st, err := investigation.Summarize(f.CPUSamples()); err == nil {
		out = append(out, fmt.Sprintf("cpu usage ratio: peak %s, mean %s over %s",
			investigation.FormatFloat(st.Max, 3), investigation.FormatFloat(st.Mean, 3), investigation.FormatDuration(st.Span)))
	}
	if st, err := investigation.Summarize(f.LatencySamples()); err == nil {
		ratio := 0.0
		if st.First > 0 {
			ratio = st.Last / st.First
		}
		out = append(out, fmt.Sprintf("p99 latency: %s samples over %s, first %s, peak %s, last %s, last/first %sx",
			investigation.FormatFloat(float64(st.Count), 0), investigation.FormatDuration(st.Span),
			investigation.FormatFloat(st.First, 3), investigation.FormatFloat(st.Max, 3),
			investigation.FormatFloat(st.Last, 3), investigation.FormatFloat(ratio, 2)))
	}
	if st, err := investigation.Summarize(f.QueryCountSamples()); err == nil {
		out = append(out, fmt.Sprintf("database query volume: %d samples over %s, min %s, max %s, mean %s",
			st.Count, investigation.FormatDuration(st.Span),
			investigation.FormatFloat(st.Min, 0), investigation.FormatFloat(st.Max, 0), investigation.FormatFloat(st.Mean, 0)))
	}
	if count, ok := f.RestartCount(); ok {
		out = append(out, fmt.Sprintf("container restart count: %d", count))
	}
	for _, t := range f.Restarts {
		detail := "no termination reason recorded"
		if t.LastTerminatedReason != "" {
			detail = "last termination reason " + t.LastTerminatedReason
		}
		if t.LastExitCode != nil {
			detail += fmt.Sprintf(", exit code %d", *t.LastExitCode)
		}
		out = append(out, fmt.Sprintf("container %s/%s: %s (%s)", t.Pod, t.Container, detail, t.State))
	}
	for _, e := range f.Events {
		out = append(out, fmt.Sprintf("event %s (x%d): %s", e.Reason, e.Count, e.Message))
	}
	if rollout, ok := f.LatestRollout(); ok {
		out = append(out, fmt.Sprintf("latest rollout %s completed %s (%d/%d replicas available)",
			rollout.Name, rollout.CompletedAt.UTC().Format("2006-01-02T15:04:05Z"),
			rollout.AvailableReplicas, rollout.Replicas))
	}
	for _, g := range f.Gaps {
		out = append(out, "unavailable evidence: "+g.String())
	}
	sort.Strings(out)
	return out
}

// observationRef names an observation inside a prompt or a Jev state without
// handing over the payload.
func observationRef(o investigation.ObservationSummary) string {
	return fmt.Sprintf("%s (%s, %s)", o.ID, o.Type, o.Completeness)
}

// validateLabel rejects anything outside the closed set. An unknown label means
// the arm failed; it does not mean the nearest label.
func validateLabel(label string) (investigation.Relationship, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case LabelSupports:
		return investigation.Supports, nil
	case LabelContradicts:
		return investigation.Contradicts, nil
	case LabelNeutral:
		return investigation.Neutral, nil
	case LabelInsufficientContext:
		return investigation.InsufficientContext, nil
	default:
		return "", fmt.Errorf("label %q is not one of %s", label, strings.Join(Labels, ", "))
	}
}

// callStatus maps a transport outcome. Kept here so both arms report failures the
// same way.
func failed(status investigation.CallStatus, reason string, arm, version, model, hypothesis string, observations int) []investigation.EvaluatorCall {
	return []investigation.EvaluatorCall{{
		SchemaVersion: gateway.SchemaVersion,
		Arm:           arm,
		ArmVersion:    version,
		Model:         model,
		Remote:        true,
		Hypothesis:    hypothesis,
		Observations:  observations,
		Status:        status,
		Reason:        reason,
	}}
}
