package worker_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/worker"
)

func engine() *investigation.Engine {
	at := time.Date(2026, 9, 18, 12, 31, 0, 0, time.UTC)
	return &investigation.Engine{
		Policy: gateway.DefaultPolicy(),
		Claims: investigation.DefaultClaimPolicy(),
		Now:    func() time.Time { return at },
	}
}

func envelope() investigation.StepEnvelope {
	started := time.Date(2026, 9, 18, 12, 31, 0, 0, time.UTC)
	budget := investigation.DefaultBudgets()
	return investigation.StepEnvelope{
		SchemaVersion: gateway.SchemaVersion,
		Incident: investigation.Incident{
			SchemaVersion: gateway.SchemaVersion,
			ID:            "INC-9001", Environment: "lab", Service: "payment-api",
			Symptom: "restarts", Trigger: investigation.TriggerManual, StartedAt: started,
			Window: gateway.Window{Start: started.Add(-time.Hour), End: started},
			Status: investigation.IncidentOpen,
		},
		Run: investigation.Run{
			SchemaVersion: gateway.SchemaVersion, ID: "RUN-INC-9001-001", IncidentID: "INC-9001",
			Attempt: 1, StartedAt: started, Status: investigation.RunActive,
			Budgets: budget, Used: investigation.BudgetState{StartedAt: started},
		},
	}
}

func TestStepEmitsExactlyOneRequest(t *testing.T) {
	input, err := json.Marshal(investigation.WorkerInput{State: envelope()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	budget := investigation.DefaultBudgets()
	out, err := worker.Step(engine(), input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	var result investigation.StepResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Kind != investigation.ResultModelRequest {
		t.Fatalf("kind = %q, want a model request", result.Kind)
	}
	if result.ModelRequest == nil || result.InfraRequest != nil || result.Report != nil {
		t.Fatal("a step result must carry exactly one of a request or a report")
	}
}

func TestStepRefusesAnOversizeStateEnvelope(t *testing.T) {
	env := envelope()
	env.Observations = []investigation.Observation{{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "OBS-0001",
		Statement:     strings.Repeat("x", 4096),
		Type:          investigation.ObsDerived,
		Action:        gateway.ActionMetricsQuery,
		Entity:        "payment-api",
		Completeness:  investigation.Complete,
	}}
	input, err := json.Marshal(investigation.WorkerInput{State: env})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := worker.Step(engine(), input, 512, 1<<20); err == nil {
		t.Fatal("an oversize state envelope must be refused, not grown")
	}
}

func TestStepRefusesAnOversizeResponse(t *testing.T) {
	payload := json.RawMessage(`{"namespace":"lab","pods":[{"name":"` + strings.Repeat("a", 4096) + `"}]}`)
	action := gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "payment-api", Reason: "check"}
	response := gateway.Response{
		SchemaVersion: gateway.SchemaVersion, Kind: action.Kind, Entity: action.Entity,
		Status: gateway.StatusOK, Completeness: gateway.Complete, RetrievedAt: time.Now().UTC(),
		Digest: gateway.Digest(payload), Payload: payload,
	}
	input, err := json.Marshal(investigation.WorkerInput{
		State:   envelope(),
		Pending: &investigation.Pending{Kind: investigation.PendingInfra, Action: &action, Response: &response},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := worker.Step(engine(), input, 1<<20, 1024); err == nil {
		t.Fatal("a response over the tool response budget must be refused")
	}
}

func TestStepRefusesUnknownFields(t *testing.T) {
	input := []byte(`{"state":{"schema_version":"probe/v1"},"unexpected":true}`)
	if _, err := worker.Step(engine(), input, 1<<20, 1<<20); err == nil {
		t.Fatal("an unknown field must be refused rather than ignored")
	}
}

func TestStepRefusesMalformedInput(t *testing.T) {
	if _, err := worker.Step(engine(), []byte("not json"), 1<<20, 1<<20); err == nil {
		t.Fatal("malformed input must be refused")
	}
}

func TestStepRefusesAnUndescribedResultKind(t *testing.T) {
	input, err := json.Marshal(investigation.WorkerInput{
		State:   envelope(),
		Pending: &investigation.Pending{Kind: "something_else"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := worker.Step(engine(), input, 1<<20, 1<<20); err == nil {
		t.Fatal("a pending result that is neither a model nor an infrastructure answer must be refused")
	}
}

// The worker is invoked once per transition, so its state must round-trip
// through serialization without losing anything the next transition needs.
func TestStateRoundTripsAcrossInvocations(t *testing.T) {
	budget := investigation.DefaultBudgets()
	input, err := json.Marshal(investigation.WorkerInput{State: envelope()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := worker.Step(engine(), input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	var first investigation.StepResult
	if err := json.Unmarshal(out, &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The first turn allocates nothing yet, so it has nothing to carry.
	if len(first.Envelope.Counters) != 0 {
		t.Fatalf("an empty first turn should not invent counters, got %v", first.Envelope.Counters)
	}

	plan := investigation.ModelResponse{
		SchemaVersion: gateway.SchemaVersion,
		Reason:        "collect the termination history",
		Hypotheses: []investigation.HypothesisSpec{
			{Statement: "limit reached", FaultDomain: investigation.DomainKubernetes, ClaimKind: investigation.ClaimMemoryLimitTermination},
			{Statement: "probe fails", FaultDomain: investigation.DomainKubernetes, ClaimKind: investigation.ClaimNonMemoryRestart},
		},
		NextAction: &gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "payment-api", Reason: "check"},
	}
	second, err := json.Marshal(investigation.WorkerInput{
		State:   first.Envelope,
		Pending: &investigation.Pending{Kind: investigation.PendingModel, Model: &plan},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out2, err := worker.Step(engine(), second, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	if err != nil {
		t.Fatalf("step: %v", err)
	}
	var result investigation.StepResult
	if err := json.Unmarshal(out2, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.Kind != investigation.ResultInfraRequest {
		t.Fatalf("kind = %q, want an infrastructure request", result.Kind)
	}
	if len(result.Envelope.Hypotheses) != 2 {
		t.Fatalf("hypotheses = %d, want 2 preserved across invocations", len(result.Envelope.Hypotheses))
	}
	if result.Envelope.Hypotheses[0].ID != "HYP-0001" || result.Envelope.Hypotheses[1].ID != "HYP-0002" {
		t.Fatalf("hypothesis ids must be stable: %s, %s",
			result.Envelope.Hypotheses[0].ID, result.Envelope.Hypotheses[1].ID)
	}
	if result.Envelope.Counters[investigation.PrefixHypothesis] != 2 {
		t.Fatalf("the state must carry the id counters, otherwise a fresh worker would renumber evidence: %v",
			result.Envelope.Counters)
	}
}

func TestRunReadsAndWritesOneLine(t *testing.T) {
	budget := investigation.DefaultBudgets()
	input, err := json.Marshal(investigation.WorkerInput{State: envelope()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out bytes.Buffer
	if err := worker.Run(engine(), bytes.NewReader(input), &out, budget.MaxEnvelopeBytes, budget.MaxResponseBytes); err != nil {
		t.Fatalf("run: %v", err)
	}
	trimmed := strings.TrimSpace(out.String())
	if strings.Count(trimmed, "\n") != 0 {
		t.Fatalf("the worker must emit exactly one result, got %q", trimmed)
	}
	var result investigation.StepResult
	if err := json.Unmarshal([]byte(trimmed), &result); err != nil {
		t.Fatalf("the emitted result must be valid json: %v", err)
	}
}
