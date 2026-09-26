package investigation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// ClaimKind is a precise, checkable assertion. The distinction between them is
// the whole point: "the container was killed for exceeding its memory limit"
// and "the application leaks memory" are different claims with different
// evidence requirements, and only the first is provable in this slice.
type ClaimKind string

const (
	ClaimMemoryLimitTermination ClaimKind = "memory_limit_termination"
	ClaimMemoryLeak             ClaimKind = "memory_leak"
	ClaimAllocationDefect       ClaimKind = "allocation_defect"
	ClaimDeploymentRegression   ClaimKind = "deployment_regression"
	ClaimResourceSaturation     ClaimKind = "resource_saturation"
	ClaimNonMemoryRestart       ClaimKind = "non_memory_restart"
	ClaimUnknownCause           ClaimKind = "unknown_cause"
	// ClaimExhaustionForecast is a statement about the future: the resource
	// reaches its limit within the horizon if the current growth persists. It
	// is only ever stated conditionally, in words code renders.
	ClaimExhaustionForecast ClaimKind = "exhaustion_forecast"
)

// AllClaimKinds is the closed set of assertions Probe understands. Model output
// naming anything else is invalid rather than interpreted.
var AllClaimKinds = []ClaimKind{
	ClaimMemoryLimitTermination,
	ClaimMemoryLeak,
	ClaimAllocationDefect,
	ClaimDeploymentRegression,
	ClaimResourceSaturation,
	ClaimNonMemoryRestart,
	ClaimUnknownCause,
	ClaimExhaustionForecast,
}

// overclaimKinds assert more than this slice collects evidence for. They may be
// reported only in their narrowed, explicitly-unproven form.
var overclaimKinds = []ClaimKind{ClaimMemoryLeak, ClaimAllocationDefect}

func (k ClaimKind) Valid() bool {
	for _, a := range AllClaimKinds {
		if a == k {
			return true
		}
	}
	return false
}

func IsOverclaimKind(k ClaimKind) bool {
	for _, a := range overclaimKinds {
		if a == k {
			return true
		}
	}
	return false
}

// Claim is a candidate assertion, citing the evidence it rests on.
type Claim struct {
	Kind      ClaimKind `json:"kind"`
	Subject   string    `json:"subject"`
	Statement string    `json:"statement"`
	Evidence  []string  `json:"evidence"`
}

// ClaimVerdict is the policy's decision about a claim. Reasons explain a
// refusal; Narrowed is the weaker statement that the evidence does support.
type ClaimVerdict struct {
	Claim         Claim    `json:"claim"`
	Allowed       bool     `json:"allowed"`
	Overclaim     bool     `json:"overclaim"`
	Reasons       []string `json:"reasons,omitempty"`
	Narrowed      string   `json:"narrowed,omitempty"`
	PolicyVersion string   `json:"policy_version"`
}

// ClaimPolicy holds the evidence thresholds. It is deliberately data, not
// prompt text: changing what Probe may assert must be a reviewable code change.
type ClaimPolicy struct {
	MaxDeploymentProximity time.Duration
	MinLeakSamples         int
	MinLeakSpan            time.Duration
	CPUSaturationThreshold float64
	MemoryLimitRatio       float64
	// ImpactRatio is how far above the pre-change baseline a measurement must be
	// before it counts as the impact the incident is about.
	ImpactRatio float64
	// Forecast holds the thresholds an exhaustion forecast must meet, and the
	// reset drop that splits a memory series at restarts for the leak rule.
	Forecast ForecastPolicy
}

func DefaultClaimPolicy() ClaimPolicy {
	return ClaimPolicy{
		MaxDeploymentProximity: 5 * time.Minute,
		MinLeakSamples:         3,
		MinLeakSpan:            10 * time.Minute,
		CPUSaturationThreshold: 0.85,
		MemoryLimitRatio:       0.9,
		ImpactRatio:            2.0,
		Forecast:               DefaultForecastPolicy(),
	}
}

// Evaluate decides whether a claim may be asserted given the retained evidence.
// The policy runs after the model and is not influenced by it.
func (p ClaimPolicy) Evaluate(c Claim, f Facts, obs map[string]Observation) ClaimVerdict {
	v := ClaimVerdict{Claim: c, PolicyVersion: ClaimPolicyVersion}
	if !c.Kind.Valid() {
		v.Reasons = append(v.Reasons, "unknown claim kind "+string(c.Kind))
	}
	for _, id := range c.Evidence {
		if _, ok := obs[id]; !ok {
			v.Reasons = append(v.Reasons, "cites evidence "+id+" which is not in the retained evidence set")
		}
	}
	switch c.Kind {
	case ClaimMemoryLimitTermination:
		p.evalMemoryLimit(&v, c, f)
	case ClaimMemoryLeak:
		p.evalMemoryLeak(&v, c, f)
	case ClaimAllocationDefect:
		v.Reasons = append(v.Reasons, "no allocation- or profile-level evidence is collected in this slice")
		v.Narrowed = "the memory pressure is evidenced; the allocation defect is not"
	case ClaimDeploymentRegression:
		p.evalDeployment(&v, c, f, obs)
	case ClaimResourceSaturation:
		p.evalSaturation(&v, c, f)
	case ClaimNonMemoryRestart:
		p.evalNonMemoryRestart(&v, c, f)
	case ClaimUnknownCause:
		// "Inconclusive" is always an admissible result.
	case ClaimExhaustionForecast:
		p.evalExhaustionForecast(&v, c, f)
	}
	v.Allowed = len(v.Reasons) == 0
	v.Overclaim = IsOverclaimKind(c.Kind) && !v.Allowed
	if !v.Allowed && v.Narrowed == "" {
		v.Narrowed = "the retained evidence does not support this statement"
	}
	return v
}

func (p ClaimPolicy) evalMemoryLimit(v *ClaimVerdict, c Claim, f Facts) {
	terms := f.OOMTerminations()
	events := f.OOMEvents()
	if len(terms) == 0 && len(events) == 0 {
		v.Reasons = append(v.Reasons, "no container termination or event evidences a memory-limit kill")
		v.Narrowed = "the container restarted; the terminating cause is not established"
		return
	}
	if len(f.Memory) == 0 {
		v.Reasons = append(v.Reasons, "memory usage evidence is unavailable, so the kill mechanism is uncorroborated")
		v.Narrowed = "the container is evidenced as OOMKilled; its memory usage approaching the limit is not evidenced"
		return
	}
	if limit, ok := f.MemoryLimit(); ok && limit.Value > 0 {
		if peak, ok := f.PeakMemory(); ok && peak.Value < limit.Value*p.MemoryLimitRatio {
			v.Reasons = append(v.Reasons, fmt.Sprintf(
				"peak working set %s is below %s%% of the %s limit, which contradicts limit exhaustion",
				FormatBytes(peak.Value), FormatFloat(p.MemoryLimitRatio*100, 0), FormatBytes(limit.Value)))
			v.Narrowed = "the container is evidenced as OOMKilled, but its working set did not approach the configured limit"
		}
	}
	establishing := append(obsIDsOfTerms(terms), obsIDsOfEvents(events)...)
	if !citesAny(c.Evidence, establishing) {
		v.Reasons = append(v.Reasons, "claim does not cite the termination or event that establishes the memory-limit kill")
	}
}

func (p ClaimPolicy) evalMemoryLeak(v *ClaimVerdict, c Claim, f Facts) {
	st, err := Summarize(f.MemorySamples())
	if err != nil {
		v.Reasons = append(v.Reasons, "no memory usage series to establish growth")
		v.Narrowed = "memory exhaustion is evidenced; sustained growth is not"
		return
	}
	if st.Count < p.MinLeakSamples {
		v.Reasons = append(v.Reasons, fmt.Sprintf(
			"memory series has %d samples; at least %d are required to establish sustained growth",
			st.Count, p.MinLeakSamples))
		v.Narrowed = "memory exhaustion is evidenced; sustained growth is not"
		return
	}
	if st.Span < p.MinLeakSpan {
		v.Reasons = append(v.Reasons, fmt.Sprintf(
			"memory series spans %s; at least %s is required to distinguish growth from a spike",
			FormatDuration(st.Span), FormatDuration(p.MinLeakSpan)))
		v.Narrowed = "memory rose over a short window, which may be a spike rather than a leak"
		return
	}
	// One climb cannot tell a leak from a workload that needs more memory: both
	// grow until something stops them. A leak is what persists: after a
	// restart frees everything, the growth resumes. So the series is split at
	// its resets, and every segment must itself be sustained growth.
	segments := splitAtResets(f.MemorySamples(), p.Forecast.ResetDrop)
	if len(segments) < 2 {
		v.Reasons = append(v.Reasons, "one continuous climb cannot tell a leak from workload growth; a leak must be seen to resume after a restart")
		if growing(segments[0]) {
			v.Narrowed = fmt.Sprintf("memory grew for %s; whether it is a leak is not established", FormatDuration(st.Span))
		} else {
			v.Narrowed = "memory fluctuated rather than grew"
		}
		return
	}
	for i, seg := range segments {
		ss, _ := Summarize(seg)
		if ss.Count < p.MinLeakSamples || ss.Span < p.MinLeakSpan || !growing(seg) {
			v.Reasons = append(v.Reasons, fmt.Sprintf(
				"segment %d of %d (between restarts) is %d samples over %s and does not show sustained growth, so growth is not seen to resume",
				i+1, len(segments), ss.Count, FormatDuration(ss.Span)))
			v.Narrowed = "memory rose and fell with the restarts; a leak that persists across them is not established"
			return
		}
	}
	v.Narrowed = fmt.Sprintf("memory grew again after each of %d restarts over %s; allocation-level cause unproven",
		len(segments)-1, FormatDuration(st.Span))
}

// splitAtResets cuts a series where a sample falls by more than drop of the one
// before it: a restart freeing the working set.
func splitAtResets(in []Sample, drop float64) [][]Sample {
	s := append([]Sample(nil), in...)
	sort.SliceStable(s, func(i, j int) bool { return s[i].At.Before(s[j].At) })
	var out [][]Sample
	start := 0
	for i := 1; i < len(s); i++ {
		if prev := s[i-1].Value; prev > 0 && (prev-s[i].Value)/prev > drop {
			out = append(out, s[start:i])
			start = i
		}
	}
	return append(out, s[start:])
}

// growing is a segment that ends higher than it starts with a positive trend.
func growing(seg []Sample) bool {
	st, err := Summarize(seg)
	return err == nil && st.Count >= 2 && st.Last > st.First && st.SlopePerSecond > 0
}

// evalExhaustionForecast admits a forecast only when forecast/v1 makes one
// from the retained series and limit. Its statement is rendered here, never
// taken from the planner: a forecast is always conditional, and "the service
// will crash" is not a statement the evidence can support.
func (p ClaimPolicy) evalExhaustionForecast(v *ClaimVerdict, c Claim, f Facts) {
	limit, known := f.MemoryLimit()
	fc := ForecastExhaustion(f.MemorySamples(), limit.Value, known, p.Forecast)
	switch fc.Outcome {
	case ForecastRefused:
		for _, r := range fc.Reasons {
			v.Reasons = append(v.Reasons, "no forecast: "+r)
		}
		v.Narrowed = "a crossing of the memory limit is not foreseeable from the retained evidence"
		return
	case ForecastBeyondHorizon:
		v.Reasons = append(v.Reasons, fmt.Sprintf("at the current rate the limit is reached in %s, beyond the %s horizon",
			FormatDuration(fc.ETA), FormatDuration(p.Forecast.Horizon)))
		v.Narrowed = fmt.Sprintf("memory is growing, but does not reach its limit within %s", FormatDuration(p.Forecast.Horizon))
		return
	}
	v.Claim.Statement = fmt.Sprintf("%s: memory %s", c.Subject, strings.TrimPrefix(fc.Statement(), "at the current rate of growth the series "))
	if !citesAny(c.Evidence, obsIDsOfSamples(f.Memory)) || !citesAny(c.Evidence, []string{limit.ObsID}) {
		v.Reasons = append(v.Reasons, "a forecast must cite both the memory series and the limit it is measured against")
	}
}

func (p ClaimPolicy) evalDeployment(v *ClaimVerdict, c Claim, f Facts, obs map[string]Observation) {
	rollout, ok := f.LatestRollout()
	if !ok {
		v.Reasons = append(v.Reasons, "no rollout evidence in the window")
		v.Narrowed = "no deployment change was evidenced for this entity"
		return
	}
	symptom, ok := p.impactOnset(f, rollout.CompletedAt)
	if !ok {
		v.Reasons = append(v.Reasons, "no measured impact after the rollout to correlate it with")
		v.Narrowed = "a rollout was recorded, with no measured impact to attribute to it"
		return
	}
	if !WithinProximity(rollout.CompletedAt, symptom.At, p.MaxDeploymentProximity) {
		v.Reasons = append(v.Reasons, fmt.Sprintf(
			"rollout completed %s before the first impact signal, outside the %s proximity bound",
			FormatDuration(Delta(rollout.CompletedAt, symptom.At)), FormatDuration(p.MaxDeploymentProximity)))
		v.Narrowed = "the rollout is not close enough in time to the impact to be a candidate cause"
		return
	}
	if !citesAny(c.Evidence, []string{rollout.ObsID}) {
		v.Reasons = append(v.Reasons, "claim does not cite the rollout evidence")
	}
	if !p.citesMechanism(c.Evidence, obs, rollout.CompletedAt) {
		v.Reasons = append(v.Reasons, "temporal proximity alone does not establish the deployment as a cause: no mechanism evidence (a log, trace or changed query-volume metric) is cited")
		v.Narrowed = fmt.Sprintf("rollout %s completed %s before the first impact signal; whether it caused the impact is not established",
			rollout.Name, FormatDuration(Delta(rollout.CompletedAt, symptom.At)))
	}
}

// impactOnset finds the first measurement after the change point that is
// materially above the pre-change baseline. The first sample of the window is
// the baseline, not the impact; conflating the two would make every rollout
// look causal.
func (p ClaimPolicy) impactOnset(f Facts, changeAt time.Time) (SampleFact, bool) {
	samples := append(append([]SampleFact{}, f.Latency...), f.Errors...)
	if len(samples) < 2 {
		return SampleFact{}, false
	}
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].At.Before(samples[j].At) })

	var sum float64
	var n int
	for _, s := range samples {
		if !s.At.After(changeAt) {
			sum += s.Value
			n++
		}
	}
	if n == 0 {
		return SampleFact{}, false
	}
	baseline := sum / float64(n)
	if baseline == 0 {
		return SampleFact{}, false
	}
	threshold := baseline * p.ImpactRatio
	for _, s := range samples {
		if s.At.After(changeAt) && s.Value >= threshold {
			return s, true
		}
	}
	return SampleFact{}, false
}

func (p ClaimPolicy) evalSaturation(v *ClaimVerdict, c Claim, f Facts) {
	if len(f.CPU) == 0 {
		v.Reasons = append(v.Reasons, "cpu usage evidence is unavailable")
		v.Narrowed = "cpu saturation is not established because cpu usage was not observed"
		return
	}
	st, err := Summarize(f.CPUSamples())
	if err != nil {
		v.Reasons = append(v.Reasons, err.Error())
		return
	}
	if st.Max < p.CPUSaturationThreshold {
		v.Reasons = append(v.Reasons, fmt.Sprintf("peak cpu %s is below the %s saturation threshold",
			FormatFloat(st.Max, 3), FormatFloat(p.CPUSaturationThreshold, 2)))
		v.Narrowed = fmt.Sprintf("cpu peaked at %s, which is not saturation", FormatFloat(st.Max, 3))
	}
}

func (p ClaimPolicy) evalNonMemoryRestart(v *ClaimVerdict, c Claim, f Facts) {
	if terms := f.OOMTerminations(); len(terms) > 0 {
		v.Reasons = append(v.Reasons, "evidence includes a memory-limit kill, so this restart is not a non-memory restart")
		v.Narrowed = "the restart follows a container termination for exceeding its memory limit"
		return
	}
	if events := f.OOMEvents(); len(events) > 0 {
		v.Reasons = append(v.Reasons, "evidence includes an out-of-memory event, so this restart is not a non-memory restart")
		v.Narrowed = "the restart follows an out-of-memory event on the same pod"
		return
	}
	terms := f.NonOOMTerminations()
	probes := f.ProbeFailures()
	if len(terms) == 0 && len(probes) == 0 {
		v.Reasons = append(v.Reasons, "no termination reason or probe failure is evidenced")
		v.Narrowed = "the container restarted; the terminating cause is not established"
		return
	}
	establishing := append(obsIDsOfTerms(terms), obsIDsOfEvents(probes)...)
	if !citesAny(c.Evidence, establishing) {
		v.Reasons = append(v.Reasons, "claim does not cite the termination reason or probe failure it rests on")
	}
}

// AllowRemediation reports whether a verdict is strong enough to carry a
// recommendation. Inconclusive results never qualify, and remediation is never
// executed in this slice.
func AllowRemediation(v ClaimVerdict) bool {
	if !v.Allowed || v.Overclaim {
		return false
	}
	return v.Claim.Kind != ClaimUnknownCause
}

func citesAny(cited, establishing []string) bool {
	for _, c := range cited {
		for _, e := range establishing {
			if c == e {
				return true
			}
		}
	}
	return false
}

// citesMechanism reports whether the claim cites evidence that explains *how*
// the impact happened, as opposed to evidence that only measures the impact.
func (p ClaimPolicy) citesMechanism(cited []string, obs map[string]Observation, since time.Time) bool {
	for _, id := range cited {
		o, ok := obs[id]
		if !ok {
			continue
		}
		switch o.Type {
		case ObsLog, ObsTrace:
			return true
		case ObsMetric:
			if o.Action != gateway.ActionMetricsQuery || !gateway.MechanismMetric(metricOf(o)) {
				continue
			}
			if p.mechanismChanged(o, since) {
				return true
			}
		}
	}
	return false
}

// mechanismChanged requires a mechanism metric to actually differ across the
// change point. A flat query-volume series is not a mechanism for a deployment
// regression, and without this check merely citing any mechanism-shaped metric
// would launder proximity into causation.
func (p ClaimPolicy) mechanismChanged(o Observation, since time.Time) bool {
	series, ok := seriesOf(o)
	if !ok {
		return false
	}
	var before, after []Sample
	for _, s := range metricSamples(series) {
		if s.At.After(since) {
			after = append(after, s)
		} else {
			before = append(before, s)
		}
	}
	if len(before) == 0 || len(after) == 0 {
		return false
	}
	b, err := Summarize(before)
	if err != nil {
		return false
	}
	a, err := Summarize(after)
	if err != nil {
		return false
	}
	if b.Mean == 0 {
		return false
	}
	return a.Max >= b.Mean*p.ImpactRatio
}

func obsIDsOfTerms(terms []RestartFact) []string {
	var out []string
	for _, t := range terms {
		out = append(out, t.ObsID)
	}
	return ObsIDs(out...)
}

func obsIDsOfEvents(events []EventFact) []string {
	var out []string
	for _, e := range events {
		out = append(out, e.ObsID)
	}
	return ObsIDs(out...)
}
