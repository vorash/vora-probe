package investigation

import (
	"fmt"

	"github.com/vorash/vora-probe/gateway"
)

// PrefixDerived numbers derived observations. They are recomputed when the
// report is built rather than stored, so their IDs are stable for a given
// evidence set and cannot drift between a run and its replay.
const PrefixDerived = "DRV"

// DeriveObservations produces the numeric claims a report leans on. Each one
// names the observations it was computed from and the calculation version, so a
// reader can recompute it, and none of them is produced by a model.
func DeriveObservations(f Facts, byID map[string]Observation) []Observation {
	ids := NewIDGen()
	var out []Observation

	if st, err := Summarize(f.MemorySamples()); err == nil {
		text := fmt.Sprintf("%s working set ranged %s to %s over %s (%d samples), ending at %s (%s change)",
			f.Entity, FormatBytes(st.Min), FormatBytes(st.Max), FormatDuration(st.Span), st.Count,
			FormatBytes(st.Last), FormatFloat(PercentChange(st.First, st.Last), 1)+"%")
		parents := obsIDsOfSamples(f.Memory)
		if limit, ok := f.MemoryLimit(); ok && limit.Value > 0 {
			text += fmt.Sprintf("; peak is %s%% of the %s limit", FormatFloat(st.Max/limit.Value*100, 0), FormatBytes(limit.Value))
			parents = append(parents, limit.ObsID)
		}
		out = append(out, derived(ids, f.Entity, text, gateway.ActionMetricsQuery, parents))
	}

	if st, err := Summarize(f.CPUSamples()); err == nil {
		out = append(out, derived(ids, f.Entity, fmt.Sprintf(
			"%s cpu usage peaked at %s (mean %s) over %s",
			f.Entity, FormatFloat(st.Max, 3), FormatFloat(st.Mean, 3), FormatDuration(st.Span)),
			gateway.ActionMetricsQuery, obsIDsOfSamples(f.CPU)))
	}

	if count, ok := f.RestartCount(); ok {
		parents := obsIDsOfRestarts(f.Restarts)
		out = append(out, derived(ids, f.Entity, fmt.Sprintf(
			"%s containers have restarted %d times in total", f.Entity, count),
			gateway.ActionKubernetesContainers, parents))
	}

	if st, err := Summarize(f.LatencySamples()); err == nil && st.First > 0 {
		out = append(out, derived(ids, f.Entity, fmt.Sprintf(
			"%s p99 latency changed %sx from %s to %s over %s",
			f.Entity, FormatFloat(st.Ratio(), 2), FormatFloat(st.First, 3), FormatFloat(st.Last, 3), FormatDuration(st.Span)),
			gateway.ActionMetricsQuery, obsIDsOfSamples(f.Latency)))
	}

	return out
}

func derived(ids *IDGen, entity, statement string, action gateway.ActionKind, parents []string) Observation {
	return Observation{
		SchemaVersion: gateway.SchemaVersion,
		ID:            ids.Next(PrefixDerived),
		Type:          ObsDerived,
		Action:        action,
		Source:        "probe.derived",
		Entity:        entity,
		Statement:     statement,
		CalcVersion:   CalcVersion,
		Parents:       ObsIDs(parents...),
		Completeness:  Complete,
	}
}

func obsIDsOfRestarts(restarts []RestartFact) []string {
	var out []string
	for _, r := range restarts {
		out = append(out, r.ObsID)
	}
	return ObsIDs(out...)
}
