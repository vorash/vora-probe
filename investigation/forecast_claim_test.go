package investigation_test

import (
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// forecastEvidence is a working-set series over the lab window, valued by f,
// and, when limit > 0, the container's limit.
func forecastEvidence(t *testing.T, f func(i int) float64, limit float64) (investigation.Facts, map[string]investigation.Observation, []string) {
	t.Helper()
	entity := "payment-api"
	var samples []gateway.MetricSample
	for i := range 30 {
		samples = append(samples, gateway.MetricSample{At: at(12, 0).Add(time.Duration(i) * time.Minute), Value: f(i)})
	}
	memory := metricObs(t, "OBS-0001", entity, "container_memory_working_set_bytes", samples...)
	if limit <= 0 {
		return build(t, entity, memory)
	}
	spec := metricObs(t, "OBS-0002", entity, "container_spec_memory_limit_bytes", sample(12, 29, limit))
	return build(t, entity, memory, spec)
}

func forecastClaim(t *testing.T, facts investigation.Facts, byID map[string]investigation.Observation, cited []string) investigation.ClaimVerdict {
	t.Helper()
	return investigation.DefaultClaimPolicy().Evaluate(investigation.Claim{
		Kind:      investigation.ClaimExhaustionForecast,
		Subject:   "payment-api",
		Statement: "payment-api will crash in 40 minutes",
		Evidence:  cited,
	}, facts, byID)
}

// A forecast the evidence supports is admitted, and stated only the way the
// evidence allows: conditionally, in words code renders. The planner's "will
// crash" never reaches the report.
func TestAnExhaustionForecastIsAdmittedOnlyInItsConditionalForm(t *testing.T) {
	facts, byID, ids := forecastEvidence(t, func(i int) float64 { return 100*mib + float64(i)*mib }, 200*mib)
	v := forecastClaim(t, facts, byID, ids)
	if !v.Allowed {
		t.Fatalf("a steady climb toward a known limit should be forecast: %v", v.Reasons)
	}
	for _, want := range []string{"payment-api", "reaches its limit", "if the growth persists"} {
		if !strings.Contains(v.Claim.Statement, want) {
			t.Fatalf("statement %q is missing %q", v.Claim.Statement, want)
		}
	}
	if strings.Contains(v.Claim.Statement, "crash") {
		t.Fatalf("the planner's unconditional statement survived: %q", v.Claim.Statement)
	}
	if v.PolicyVersion != "claims/v2" {
		t.Fatalf("policy version %q", v.PolicyVersion)
	}
}

// Each refusal is a forecast the evidence cannot carry. Every one keeps a
// narrowed statement, so the report says what is known instead.
func TestAnExhaustionForecastIsRefusedWhenTheEvidenceCannotCarryIt(t *testing.T) {
	ramp := func(i int) float64 { return 100*mib + float64(i)*mib }
	cases := []struct {
		name   string
		f      func(int) float64
		limit  float64
		reason string
	}{
		{"the limit was not collected", ramp, 0, "the limit is unknown"},
		{"memory is flat", func(int) float64 { return 100 * mib }, 200 * mib, "not growing"},
		{"a sawtooth", func(i int) float64 { return 100*mib + float64(i%6)*8*mib }, 256 * mib, "cycles rather than grows"},
		{"the crossing is beyond the horizon", func(i int) float64 { return 100*mib + float64(i)*mib/50 }, 256 * mib, "beyond the"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts, byID, ids := forecastEvidence(t, c.f, c.limit)
			v := forecastClaim(t, facts, byID, ids)
			if v.Allowed {
				t.Fatalf("admitted a forecast the evidence cannot carry: %q", v.Claim.Statement)
			}
			if !strings.Contains(strings.Join(v.Reasons, "; "), c.reason) {
				t.Fatalf("reasons %v, want one about %q", v.Reasons, c.reason)
			}
			if v.Narrowed == "" {
				t.Fatal("a refused forecast must say what is known instead")
			}
		})
	}
}

// A forecast rests on two pieces of evidence: the growth and the limit it is
// measured against. Citing only the growth is a crossing of nothing.
func TestAnExhaustionForecastMustCiteTheLimit(t *testing.T) {
	facts, byID, _ := forecastEvidence(t, func(i int) float64 { return 100*mib + float64(i)*mib }, 200*mib)
	v := forecastClaim(t, facts, byID, []string{"OBS-0001"})
	if v.Allowed {
		t.Fatal("a forecast that does not cite its limit was admitted")
	}
}

// A forecast never carries a recommendation. It is a hypothesis about the
// future, and "raise the limit" or "roll back" are exactly the reflexes the
// plan forbids on proximity or trend alone.
func TestAForecastReportRecommendsNothing(t *testing.T) {
	facts, byID, ids := forecastEvidence(t, func(i int) float64 { return 100*mib + float64(i)*mib }, 200*mib)
	v := forecastClaim(t, facts, byID, ids)
	if !v.Allowed {
		t.Fatalf("setup: %v", v.Reasons)
	}
	var obs []investigation.Observation
	for _, id := range ids {
		obs = append(obs, byID[id])
	}
	env := investigation.StepEnvelope{
		SchemaVersion: gateway.SchemaVersion,
		Incident: investigation.Incident{SchemaVersion: gateway.SchemaVersion, ID: "INC-f", Environment: "lab",
			Service: "payment-api", Symptom: "memory growing toward its limit", Trigger: investigation.TriggerForecast,
			StartedAt: at(12, 30), Window: gateway.Window{Start: at(12, 0), End: at(12, 30)}, Status: investigation.IncidentInvestigating},
		Run:          investigation.Run{ID: "RUN-f", Status: investigation.RunCompleted},
		Observations: obs,
		Hypotheses: []investigation.Hypothesis{{ID: "HYP-0001", Statement: "payment-api will crash",
			ClaimKind: investigation.ClaimExhaustionForecast, FaultDomain: investigation.DomainKubernetes}},
	}
	for _, id := range ids {
		env.Relations = append(env.Relations, investigation.Relation{ID: "REL-" + id, Observation: id, Hypothesis: "HYP-0001",
			Relationship: investigation.Supports, Evaluator: investigation.DeterministicArm})
	}
	report, err := investigation.BuildReport(&env, investigation.DefaultClaimPolicy(), at(12, 31))
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if report.Leading == nil || report.Leading.Kind != investigation.ClaimExhaustionForecast {
		t.Fatalf("leading = %+v, want the forecast", report.Leading)
	}
	if report.Recommendation != nil {
		t.Fatalf("a forecast report recommended %q", report.Recommendation.Action)
	}
	if strings.Contains(report.Leading.Statement, "crash") {
		t.Fatalf("the report states the planner's words: %q", report.Leading.Statement)
	}
}

// The deterministic arm labels a forecast hypothesis with the same derivation
// the claims policy admits it with. If the two disagreed, a report could show
// the series supporting a forecast it then refused, or the reverse.
func TestForecastLabelsAgreeWithTheVerdict(t *testing.T) {
	cases := []struct {
		name  string
		f     func(int) float64
		limit float64
		want  investigation.Relationship
	}{
		{"a climb toward the limit", func(i int) float64 { return 100*mib + float64(i)*mib }, 200 * mib, investigation.Supports},
		{"flat", func(int) float64 { return 100 * mib }, 200 * mib, investigation.Contradicts},
		{"beyond the horizon", func(i int) float64 { return 100*mib + float64(i)*mib/50 }, 256 * mib, investigation.Contradicts},
		{"no limit", func(i int) float64 { return 100*mib + float64(i)*mib }, 0, investigation.InsufficientContext},
	}
	h := investigation.Hypothesis{ID: "HYP-0001", ClaimKind: investigation.ClaimExhaustionForecast}
	arm := investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts, byID, ids := forecastEvidence(t, c.f, c.limit)
			drafts, _, err := arm.Label(h, facts, byID)
			if err != nil {
				t.Fatalf("label: %v", err)
			}
			var memory investigation.Relationship
			for _, d := range drafts {
				if d.Observation == "OBS-0001" {
					memory = d.Relationship
				}
			}
			if memory != c.want {
				t.Fatalf("the memory series is labelled %q, want %q (%+v)", memory, c.want, drafts)
			}
			allowed := forecastClaim(t, facts, byID, ids).Allowed
			if allowed != (memory == investigation.Supports) {
				t.Fatalf("the verdict (allowed=%t) disagrees with the label %q", allowed, memory)
			}
		})
	}
}
