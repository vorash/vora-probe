package investigation

import (
	"fmt"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// Deterministic evidence relations.
//
// Every relation here is produced by a rule, not by a model, and carries the
// reason for the label. The rules are conservative in one direction on purpose:
// an observation only supports a hypothesis when it bears on the mechanism the
// hypothesis names. "The rollout was nearby" and "latency went up" are recorded,
// but as insufficient context for a causal claim, not as support for one.
// restartContext makes sure restart evidence that a rule did not use still
// appears in the report. An observation that informed the conclusion but
// produced no relation would otherwise vanish, which is exactly how a report
// ends up looking more certain than its evidence.
func (b *relationBuilder) restartContext(f Facts) {
	for _, t := range f.Restarts {
		if b.seen[t.ObsID] {
			continue
		}
		detail := "no termination reason was recorded"
		switch {
		case t.LastTerminatedReason != "":
			detail = "the last termination reason was " + t.LastTerminatedReason
		case t.LastExitCode != nil:
			detail = fmt.Sprintf("the last exit code was %d", *t.LastExitCode)
		}
		b.add(t.ObsID, InsufficientContext, fmt.Sprintf(
			"%s/%s restarted %d times; %s, so the terminating cause is not established",
			t.Pod, t.Container, t.Count, detail))
	}
}

type relationBuilder struct {
	hypothesis Hypothesis
	policy     ClaimPolicy
	obs        map[string]Observation
	drafts     []RelationDraft
	seen       map[string]bool
}

func (b *relationBuilder) add(obsID string, rel Relationship, reason string) {
	if obsID == "" {
		return
	}
	if b.seen == nil {
		b.seen = map[string]bool{}
	}
	b.seen[obsID] = true
	b.drafts = append(b.drafts, RelationDraft{Observation: obsID, Relationship: rel, Reason: reason})
}

func (b *relationBuilder) memoryLimit(f Facts) {
	for _, t := range f.OOMTerminations() {
		b.add(t.ObsID, Supports, fmt.Sprintf("%s/%s last terminated with reason %s (exit %s) at %s",
			t.Pod, t.Container, t.LastTerminatedReason, exitCode(t.LastExitCode), FormatTime(t.LastTerminatedAt)))
	}
	for _, e := range f.OOMEvents() {
		b.add(e.ObsID, Supports, fmt.Sprintf("kubernetes reported %s (x%d): %s", e.Reason, e.Count, e.Message))
	}
	for _, t := range f.NonOOMTerminations() {
		b.add(t.ObsID, Contradicts, fmt.Sprintf("%s/%s last terminated with reason %s (exit %s), not a memory kill",
			t.Pod, t.Container, t.LastTerminatedReason, exitCode(t.LastExitCode)))
	}
	if st, err := Summarize(f.MemorySamples()); err == nil {
		ids := obsIDsOfSamples(f.Memory)
		switch limit, ok := f.MemoryLimit(); {
		case ok && limit.Value > 0:
			ratio := st.Max / limit.Value
			reason := fmt.Sprintf("peak working set %s is %s%% of the %s limit",
				FormatBytes(st.Max), FormatFloat(ratio*100, 0), FormatBytes(limit.Value))
			if ratio >= b.policy.MemoryLimitRatio {
				b.addAll(ids, Supports, reason)
			} else {
				b.addAll(ids, Contradicts, reason+" and did not approach it")
			}
		default:
			b.addAll(ids, InsufficientContext, fmt.Sprintf("peak working set %s with no configured limit to compare against", FormatBytes(st.Max)))
		}
	}
	for _, g := range f.Gaps {
		if g.Action == gateway.ActionMetricsQuery && g.Metric == "container_memory_working_set_bytes" {
			b.add(g.ObsID, InsufficientContext, "memory usage is unavailable, so the kill mechanism is uncorroborated: "+g.Reason)
		}
	}
	if len(f.CPU) > 0 {
		b.addAll(obsIDsOfSamples(f.CPU), Neutral, "cpu usage does not bear on a memory-limit termination")
	}
}

func (b *relationBuilder) nonMemoryRestart(f Facts) {
	for _, t := range f.OOMTerminations() {
		b.add(t.ObsID, Contradicts, fmt.Sprintf("%s/%s was terminated for exceeding its memory limit", t.Pod, t.Container))
	}
	for _, e := range f.OOMEvents() {
		b.add(e.ObsID, Contradicts, "an out-of-memory event contradicts a non-memory restart: "+e.Message)
	}
	for _, t := range f.NonOOMTerminations() {
		b.add(t.ObsID, Supports, fmt.Sprintf("%s/%s terminated with reason %s (exit %s) at %s",
			t.Pod, t.Container, t.LastTerminatedReason, exitCode(t.LastExitCode), FormatTime(t.LastTerminatedAt)))
	}
	for _, e := range f.ProbeFailures() {
		b.add(e.ObsID, Supports, fmt.Sprintf("probe failures recorded (x%d): %s", e.Count, e.Message))
	}
	if st, err := Summarize(f.MemorySamples()); err == nil {
		reason := fmt.Sprintf("working set peaked at %s", FormatBytes(st.Max))
		if limit, ok := f.MemoryLimit(); ok && limit.Value > 0 {
			reason += fmt.Sprintf(", %s%% of the %s limit", FormatFloat(st.Max/limit.Value*100, 0), FormatBytes(limit.Value))
		}
		b.addAll(obsIDsOfSamples(f.Memory), Neutral, reason)
	}
}

func (b *relationBuilder) memoryLeak(f Facts) {
	st, err := Summarize(f.MemorySamples())
	if err != nil {
		b.addAll(obsIDsOfSamples(f.Memory), InsufficientContext, "no memory usage series to establish growth")
		return
	}
	ids := obsIDsOfSamples(f.Memory)
	growth := st.MonotonicIncrease && st.Count >= b.policy.MinLeakSamples && st.Span >= b.policy.MinLeakSpan
	switch {
	case growth:
		b.addAll(ids, Supports, fmt.Sprintf("working set increased monotonically across %d samples over %s, from %s to %s",
			st.Count, FormatDuration(st.Span), FormatBytes(st.First), FormatBytes(st.Last)))
	case !st.MonotonicIncrease:
		b.addAll(ids, Contradicts, fmt.Sprintf("working set is not monotonically increasing (peak %s, falling back to %s), which is the shape of a restart cycle rather than growth",
			FormatBytes(st.Max), FormatBytes(st.Last)))
	default:
		b.addAll(ids, InsufficientContext, fmt.Sprintf("working set rises but over only %d samples spanning %s, which cannot distinguish growth from a spike",
			st.Count, FormatDuration(st.Span)))
	}
}

func (b *relationBuilder) allocationDefect(f Facts) {
	b.addAll(obsIDsOfSamples(f.Memory), InsufficientContext,
		"working-set measurements describe pressure, not the allocation that produced it")
}

func (b *relationBuilder) deploymentRegression(f Facts) {
	rollout, ok := f.LatestRollout()
	if !ok {
		return
	}
	onset, established := b.policy.impactOnset(f, rollout.CompletedAt)
	mechanism := b.mechanism(f, rollout.CompletedAt)

	switch {
	case !established:
		b.add(rollout.ObsID, InsufficientContext, "a rollout was recorded, but no impact after it was measured")
	case mechanism != nil:
		b.add(rollout.ObsID, Supports, fmt.Sprintf("rollout completed %s before the first impact signal",
			FormatDuration(Delta(rollout.CompletedAt, onset.At))))
		b.add(mechanism.ObsID, Supports, mechanism.Reason)
		b.addAll(obsIDsOfSamples(f.Latency), Supports, fmt.Sprintf("p99 latency first exceeded twice its pre-rollout baseline at %s", FormatTime(&onset.At)))
	case !WithinProximity(rollout.CompletedAt, onset.At, b.policy.MaxDeploymentProximity):
		b.add(rollout.ObsID, Contradicts, fmt.Sprintf("rollout completed %s before the first impact signal, outside the %s proximity bound",
			FormatDuration(Delta(rollout.CompletedAt, onset.At)), FormatDuration(b.policy.MaxDeploymentProximity)))
	default:
		b.add(rollout.ObsID, InsufficientContext, fmt.Sprintf("rollout completed %s before the first impact signal, which is proximity and not causation: no mechanism evidence was found",
			FormatDuration(Delta(rollout.CompletedAt, onset.At))))
		b.addAll(obsIDsOfSamples(f.Latency), InsufficientContext, "latency measures the impact, not the mechanism that produced it")
		if st, err := Summarize(f.QueryCountSamples()); err == nil {
			b.addAll(obsIDsOfSamples(f.QueryCount), Contradicts, fmt.Sprintf("query volume stayed within %s%% of its pre-rollout mean, so the rollout did not change database work",
				FormatFloat(st.Max/st.Mean*100, 0)))
		}
	}
	if len(f.Latency) == 0 {
		b.add(rollout.ObsID, InsufficientContext, "no impact measurement was collected to correlate the rollout with")
	}
}

func (b *relationBuilder) saturation(f Facts) {
	st, err := Summarize(f.CPUSamples())
	if err != nil {
		b.addAll(obsIDsOfSamples(f.CPU), InsufficientContext, "no cpu usage series was collected")
		return
	}
	ids := obsIDsOfSamples(f.CPU)
	if st.Max >= b.policy.CPUSaturationThreshold {
		b.addAll(ids, Supports, fmt.Sprintf("cpu peaked at %s, at or above the %s saturation threshold",
			FormatFloat(st.Max, 3), FormatFloat(b.policy.CPUSaturationThreshold, 2)))
		return
	}
	b.addAll(ids, Contradicts, fmt.Sprintf("cpu peaked at %s, below the %s saturation threshold",
		FormatFloat(st.Max, 3), FormatFloat(b.policy.CPUSaturationThreshold, 2)))
}

func (b *relationBuilder) inconclusive(f Facts) {
	// An inconclusive hypothesis is supported by the absence of a mechanism, not
	// by any single observation, so its evidence is recorded as context only.
	for _, t := range f.Restarts {
		b.add(t.ObsID, InsufficientContext, fmt.Sprintf("%s/%s restarted %d times", t.Pod, t.Container, t.Count))
	}
	if st, err := Summarize(f.LatencySamples()); err == nil {
		b.addAll(obsIDsOfSamples(f.Latency), InsufficientContext, fmt.Sprintf("latency peaked at %s, which establishes impact but not a cause",
			FormatFloat(st.Max, 3)))
	}
}

func (b *relationBuilder) coverageGaps(f Facts) {
	seen := map[string]bool{}
	for _, g := range f.Gaps {
		if seen[g.ObsID] {
			continue
		}
		seen[g.ObsID] = true
		b.add(g.ObsID, InsufficientContext, "requested evidence is unavailable: "+g.String())
	}
}

func (b *relationBuilder) addAll(ids []string, rel Relationship, reason string) {
	for _, id := range ids {
		b.add(id, rel, reason)
	}
}

// mechanism returns the observation that explains how the rollout produced the
// impact, or nil. It is the difference between a correlation and a finding.
func (b *relationBuilder) mechanism(f Facts, since time.Time) *mechanismFact {
	for _, s := range f.QueryCount {
		o, ok := b.obs[s.ObsID]
		if !ok {
			continue
		}
		series, ok := seriesOf(o)
		if !ok {
			continue
		}
		var before, after []Sample
		for _, v := range metricSamples(series) {
			if v.At.After(since) {
				after = append(after, v)
			} else {
				before = append(before, v)
			}
		}
		if len(before) == 0 || len(after) == 0 {
			continue
		}
		bs, err := Summarize(before)
		if err != nil {
			continue
		}
		as, err := Summarize(after)
		if err != nil {
			continue
		}
		if bs.Mean > 0 && as.Max >= bs.Mean*b.policy.ImpactRatio {
			return &mechanismFact{
				ObsID: s.ObsID,
				Reason: fmt.Sprintf("database query volume rose to %s from a pre-rollout mean of %s, which is a mechanism for the latency change",
					FormatFloat(as.Max, 0), FormatFloat(bs.Mean, 0)),
			}
		}
	}
	return nil
}

type mechanismFact struct {
	ObsID  string
	Reason string
}

func obsIDsOfSamples(samples []SampleFact) []string {
	var out []string
	for _, s := range samples {
		out = append(out, s.ObsID)
	}
	return ObsIDs(out...)
}

func exitCode(code *int) string {
	if code == nil {
		return "unrecorded"
	}
	return fmt.Sprintf("%d", *code)
}

func FormatTime(t *time.Time) string {
	if t == nil {
		return "an unrecorded time"
	}
	return t.UTC().Format(time.RFC3339)
}
