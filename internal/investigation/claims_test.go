package investigation_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

var (
	labWindow = gateway.Window{
		Start: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 9, 18, 12, 30, 0, 0, time.UTC),
	}
	retrieved = time.Date(2026, 9, 18, 12, 31, 0, 0, time.UTC)
)

func metricResp(t *testing.T, entity, metric string, samples ...gateway.MetricSample) gateway.Response {
	t.Helper()
	payload, err := json.Marshal(gateway.MetricSeries{Metric: metric, Unit: "unit", Samples: samples})
	if err != nil {
		t.Fatalf("marshal metric series: %v", err)
	}
	return gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          gateway.ActionMetricsQuery,
		Entity:        entity,
		Status:        gateway.StatusOK,
		Completeness:  gateway.Complete,
		RetrievedAt:   retrieved,
		Query:         gateway.QueryMeta{Datasource: "prometheus", Query: metric, Resolution: "60s", Params: map[string]string{"metric": metric}},
		Digest:        gateway.Digest(payload),
		Payload:       payload,
	}
}

func metricObs(t *testing.T, id, entity, metric string, samples ...gateway.MetricSample) investigation.Observation {
	t.Helper()
	a := gateway.Action{Kind: gateway.ActionMetricsQuery, Entity: entity, Reason: "test", Metric: metric, Window: &labWindow, Resolution: "60s"}
	return obs(t, id, a, metricResp(t, entity, metric, samples...))
}

func containerObs(t *testing.T, id, entity string, status gateway.ContainerStatus) investigation.Observation {
	t.Helper()
	payload, err := json.Marshal(gateway.PodList{
		Namespace: "lab",
		Pods: []gateway.Pod{{
			Name:      entity + "-abc123",
			Namespace: "lab",
			Phase:     "Running",
			StartTime: labWindow.Start,
			Containers: []gateway.ContainerStatus{
				status,
			},
		}},
	})
	if err != nil {
		t.Fatalf("marshal pod list: %v", err)
	}
	a := gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: entity, Reason: "test"}
	r := gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          gateway.ActionKubernetesContainers,
		Entity:        entity,
		Status:        gateway.StatusOK,
		Completeness:  gateway.Complete,
		RetrievedAt:   retrieved,
		Query:         gateway.QueryMeta{Datasource: "kubernetes"},
		Digest:        gateway.Digest(payload),
		Payload:       payload,
	}
	return obs(t, id, a, r)
}

func eventObs(t *testing.T, id, entity string, event gateway.Event) investigation.Observation {
	t.Helper()
	payload, err := json.Marshal(gateway.EventList{Namespace: "lab", Events: []gateway.Event{event}})
	if err != nil {
		t.Fatalf("marshal event list: %v", err)
	}
	a := gateway.Action{Kind: gateway.ActionKubernetesEvents, Entity: entity, Reason: "test", Window: &labWindow}
	r := gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          gateway.ActionKubernetesEvents,
		Entity:        entity,
		Status:        gateway.StatusOK,
		Completeness:  gateway.Complete,
		RetrievedAt:   retrieved,
		Query:         gateway.QueryMeta{Datasource: "kubernetes"},
		Digest:        gateway.Digest(payload),
		Payload:       payload,
	}
	return obs(t, id, a, r)
}

func deploymentObs(t *testing.T, id, entity string, at time.Time) investigation.Observation {
	t.Helper()
	payload, err := json.Marshal(gateway.DeploymentList{
		Namespace: "lab",
		Deployments: []gateway.Deployment{{
			Name:               entity,
			Namespace:          "lab",
			Replicas:           4,
			AvailableReplicas:  4,
			RolloutCompletedAt: at,
		}},
	})
	if err != nil {
		t.Fatalf("marshal deployment list: %v", err)
	}
	a := gateway.Action{Kind: gateway.ActionKubernetesDeployments, Entity: entity, Reason: "test"}
	r := gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          gateway.ActionKubernetesDeployments,
		Entity:        entity,
		Status:        gateway.StatusOK,
		Completeness:  gateway.Complete,
		RetrievedAt:   retrieved,
		Query:         gateway.QueryMeta{Datasource: "kubernetes"},
		Digest:        gateway.Digest(payload),
		Payload:       payload,
	}
	return obs(t, id, a, r)
}

func obs(t *testing.T, id string, a gateway.Action, r gateway.Response) investigation.Observation {
	t.Helper()
	o, err := investigation.ObservationFromResponse(id, a, r, r.RetrievedAt)
	if err != nil {
		t.Fatalf("normalize %s: %v", id, err)
	}
	return o
}

func at(h, m int) time.Time {
	return time.Date(2026, 9, 18, h, m, 0, 0, time.UTC)
}

func sample(h, m int, v float64) gateway.MetricSample {
	return gateway.MetricSample{At: at(h, m), Value: v}
}

func oomContainer() gateway.ContainerStatus {
	terminated := at(12, 21)
	code := 137
	return gateway.ContainerStatus{
		Name:                 "app",
		RestartCount:         7,
		State:                "waiting",
		Reason:               "CrashLoopBackOff",
		LastTerminatedAt:     &terminated,
		LastTerminatedReason: "OOMKilled",
		LastExitCode:         &code,
	}
}

// build assembles facts and the citation index from observations for one entity.
func build(t *testing.T, entity string, obsList ...investigation.Observation) (investigation.Facts, map[string]investigation.Observation, []string) {
	t.Helper()
	byID := map[string]investigation.Observation{}
	ids := make([]string, 0, len(obsList))
	for _, o := range obsList {
		byID[o.ID] = o
		ids = append(ids, o.ID)
	}
	return investigation.BuildFacts(entity, obsList), byID, ids
}

func evaluate(t *testing.T, kind investigation.ClaimKind, subject string, cited []string, facts investigation.Facts, byID map[string]investigation.Observation) investigation.ClaimVerdict {
	t.Helper()
	return investigation.DefaultClaimPolicy().Evaluate(investigation.Claim{
		Kind:      kind,
		Subject:   subject,
		Statement: string(kind),
		Evidence:  cited,
	}, facts, byID)
}

func TestMemoryLimitTerminationAllowed(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())
	memory := metricObs(t, "OBS-0002", entity, "container_memory_working_set_bytes",
		sample(12, 0, 188743680), sample(12, 20, 553648128), sample(12, 25, 190840832))
	limit := metricObs(t, "OBS-0003", entity, "container_spec_memory_limit_bytes", sample(12, 30, 536870912))

	facts, byID, ids := build(t, entity, termination, memory, limit)
	v := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID)
	if !v.Allowed {
		t.Fatalf("memory-limit termination should be admissible: %v", v.Reasons)
	}
	if v.Overclaim {
		t.Fatal("an evidenced memory-limit termination is not an overclaim")
	}
	if !investigation.AllowRemediation(v) {
		t.Fatal("a fully evidenced claim should be strong enough to carry a recommendation")
	}
}

func TestMemoryLimitTerminationRefusedWithoutMemoryEvidence(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())

	facts, byID, ids := build(t, entity, termination)
	v := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("a kill with no memory evidence must not be asserted as limit exhaustion")
	}
	if v.Narrowed == "" {
		t.Fatal("a refused claim must carry a narrowed statement")
	}
}

func TestMemoryLimitTerminationRefusedBelowLimit(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())
	memory := metricObs(t, "OBS-0002", entity, "container_memory_working_set_bytes", sample(12, 20, 209715200))
	limit := metricObs(t, "OBS-0003", entity, "container_spec_memory_limit_bytes", sample(12, 30, 536870912))

	facts, byID, ids := build(t, entity, termination, memory, limit)
	v := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("a working set far below the limit must not be reported as limit exhaustion")
	}
}

func TestMemoryLeakRefusedOnSawtooth(t *testing.T) {
	entity := "payment-api"
	memory := metricObs(t, "OBS-0001", entity, "container_memory_working_set_bytes",
		sample(12, 0, 188743680), sample(12, 5, 204472320), sample(12, 10, 251658240),
		sample(12, 15, 429916160), sample(12, 20, 553648128), sample(12, 25, 190840832),
		sample(12, 30, 209715200))

	facts, byID, ids := build(t, entity, memory)
	v := evaluate(t, investigation.ClaimMemoryLeak, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("a sawtooth series caused by restarts does not evidence a leak")
	}
	if !v.Overclaim {
		t.Fatal("a refused leak claim must be flagged as an overclaim")
	}
	if v.Narrowed == "" {
		t.Fatal("a refused leak claim must carry a narrowed statement")
	}
}

func TestMemoryLeakAllowedOnSustainedGrowth(t *testing.T) {
	entity := "payment-api"
	var samples []gateway.MetricSample
	for i := range 11 {
		samples = append(samples, gateway.MetricSample{At: at(12, 0).Add(time.Duration(i) * 5 * time.Minute), Value: float64(1000 + i*100)})
	}
	memory := metricObs(t, "OBS-0001", entity, "container_memory_working_set_bytes", samples...)

	facts, byID, ids := build(t, entity, memory)
	v := evaluate(t, investigation.ClaimMemoryLeak, entity, ids, facts, byID)
	if !v.Allowed {
		t.Fatalf("sustained monotonic growth should be admissible: %v", v.Reasons)
	}
	if v.Narrowed == "" {
		t.Fatal("even an admissible leak claim must state that the allocation-level cause is unproven")
	}
}

func TestAllocationDefectAlwaysRefused(t *testing.T) {
	entity := "payment-api"
	memory := metricObs(t, "OBS-0001", entity, "container_memory_working_set_bytes", sample(12, 0, 1000), sample(12, 30, 9000))
	facts, byID, ids := build(t, entity, memory)
	v := evaluate(t, investigation.ClaimAllocationDefect, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("no allocation-level evidence is collected in this slice")
	}
	if !v.Overclaim {
		t.Fatal("an allocation defect is an overclaim in this slice")
	}
}

func TestDeploymentRegressionRefusedOnProximityAlone(t *testing.T) {
	entity := "checkout-api"
	rollout := deploymentObs(t, "OBS-0001", entity, at(12, 12))
	latency := metricObs(t, "OBS-0002", entity, "request_latency_p99_seconds",
		sample(12, 0, 0.22), sample(12, 5, 0.24), sample(12, 10, 0.23),
		sample(12, 15, 1.9), sample(12, 20, 3.8), sample(12, 25, 4.1), sample(12, 30, 3.9))

	facts, byID, ids := build(t, entity, rollout, latency)
	v := evaluate(t, investigation.ClaimDeploymentRegression, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("temporal proximity alone must not establish a deployment as the cause")
	}
	if v.Narrowed == "" {
		t.Fatal("a refused deployment claim must describe the proximity without asserting causation")
	}
}

func TestDeploymentRegressionAllowedWithChangedMechanism(t *testing.T) {
	entity := "checkout-api"
	rollout := deploymentObs(t, "OBS-0001", entity, at(12, 12))
	latency := metricObs(t, "OBS-0002", entity, "request_latency_p99_seconds",
		sample(12, 0, 0.22), sample(12, 5, 0.24), sample(12, 10, 0.23),
		sample(12, 15, 1.9), sample(12, 20, 3.8), sample(12, 25, 4.1), sample(12, 30, 3.9))
	queries := metricObs(t, "OBS-0003", entity, "db_query_count",
		sample(12, 0, 1200), sample(12, 5, 1190), sample(12, 10, 1210),
		sample(12, 15, 3400), sample(12, 20, 3500), sample(12, 25, 3480), sample(12, 30, 3510))

	facts, byID, ids := build(t, entity, rollout, latency, queries)
	v := evaluate(t, investigation.ClaimDeploymentRegression, entity, ids, facts, byID)
	if !v.Allowed {
		t.Fatalf("a close rollout plus a changed query-volume mechanism should be admissible: %v", v.Reasons)
	}
}

func TestDeploymentRegressionRefusedWhenMechanismIsFlat(t *testing.T) {
	entity := "checkout-api"
	rollout := deploymentObs(t, "OBS-0001", entity, at(12, 12))
	latency := metricObs(t, "OBS-0002", entity, "request_latency_p99_seconds",
		sample(12, 0, 0.22), sample(12, 10, 0.23), sample(12, 20, 3.8), sample(12, 30, 3.9))
	queries := metricObs(t, "OBS-0003", entity, "db_query_count",
		sample(12, 0, 1200), sample(12, 10, 1210), sample(12, 20, 1188), sample(12, 30, 1200))

	facts, byID, ids := build(t, entity, rollout, latency, queries)
	v := evaluate(t, investigation.ClaimDeploymentRegression, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("citing a flat mechanism-shaped metric must not launder proximity into causation")
	}
}

func TestResourceSaturation(t *testing.T) {
	entity := "payment-api"
	hot := metricObs(t, "OBS-0001", entity, "container_cpu_usage_ratio", sample(12, 0, 0.4), sample(12, 30, 0.97))
	facts, byID, ids := build(t, entity, hot)
	if v := evaluate(t, investigation.ClaimResourceSaturation, entity, ids, facts, byID); !v.Allowed {
		t.Fatalf("sustained cpu above the threshold should be admissible: %v", v.Reasons)
	}

	cold := metricObs(t, "OBS-0001", entity, "container_cpu_usage_ratio", sample(12, 0, 0.21), sample(12, 30, 0.26))
	facts, byID, ids = build(t, entity, cold)
	if v := evaluate(t, investigation.ClaimResourceSaturation, entity, ids, facts, byID); v.Allowed {
		t.Fatal("cpu at 0.26 must not be reported as saturation")
	}
}

func TestNonMemoryRestartRefusedWhenOOMEvidenced(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())
	probe := eventObs(t, "OBS-0002", entity, gateway.Event{
		Type: "Warning", Reason: "Unhealthy", Message: "Readiness probe failed: connection refused",
		InvolvedObject: entity + "-abc123", Count: 4, FirstSeen: at(12, 21), LastSeen: at(12, 29),
	})

	facts, byID, ids := build(t, entity, termination, probe)
	v := evaluate(t, investigation.ClaimNonMemoryRestart, entity, ids, facts, byID)
	if v.Allowed {
		t.Fatal("a probe failure alongside an evidenced memory kill must not be reported as the restart cause")
	}
}

func TestNonMemoryRestartAllowed(t *testing.T) {
	entity := "inventory-api"
	terminated := at(12, 14)
	code := 1
	termination := containerObs(t, "OBS-0001", entity, gateway.ContainerStatus{
		Name: "app", RestartCount: 5, State: "running",
		LastTerminatedAt: &terminated, LastTerminatedReason: "Error", LastExitCode: &code,
	})
	probe := eventObs(t, "OBS-0002", entity, gateway.Event{
		Type: "Warning", Reason: "Unhealthy", Message: "Liveness probe failed: connection refused",
		InvolvedObject: entity + "-abc123", Count: 6, FirstSeen: at(12, 13), LastSeen: at(12, 29),
	})

	facts, byID, ids := build(t, entity, termination, probe)
	v := evaluate(t, investigation.ClaimNonMemoryRestart, entity, ids, facts, byID)
	if !v.Allowed {
		t.Fatalf("exit 1 with repeated probe failures should be admissible: %v", v.Reasons)
	}
}

func TestUnknownEvidenceIsRefused(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())
	facts, byID, _ := build(t, entity, termination)
	v := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, []string{"OBS-9999"}, facts, byID)
	if v.Allowed {
		t.Fatal("a claim citing an invented evidence ID must be refused")
	}
}

func TestUnknownCauseAlwaysAdmissible(t *testing.T) {
	facts, byID, _ := build(t, "payment-api")
	v := evaluate(t, investigation.ClaimUnknownCause, "payment-api", nil, facts, byID)
	if !v.Allowed {
		t.Fatalf("inconclusive must always be an admissible result: %v", v.Reasons)
	}
	if investigation.AllowRemediation(v) {
		t.Fatal("an inconclusive verdict must never carry a remediation recommendation")
	}
}

func TestUnknownClaimKindRefused(t *testing.T) {
	facts, byID, _ := build(t, "payment-api")
	v := evaluate(t, investigation.ClaimKind("kubectl_delete_namespace"), "payment-api", nil, facts, byID)
	if v.Allowed {
		t.Fatal("an unrecognised claim kind must be refused")
	}
}

func TestPolicyIsDeterministic(t *testing.T) {
	entity := "payment-api"
	termination := containerObs(t, "OBS-0001", entity, oomContainer())
	memory := metricObs(t, "OBS-0002", entity, "container_memory_working_set_bytes",
		sample(12, 0, 188743680), sample(12, 20, 553648128), sample(12, 25, 190840832))
	limit := metricObs(t, "OBS-0003", entity, "container_spec_memory_limit_bytes", sample(12, 30, 536870912))
	facts, byID, ids := build(t, entity, termination, memory, limit)

	first := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID)
	for i := range 25 {
		again := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("iteration %d produced a different verdict", i)
		}
	}
}
