package models

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// fakeTransport records the request and returns a canned provider envelope.
type fakeTransport struct {
	status     int
	body       []byte
	err        error
	gotURL     string
	gotHeaders map[string]string
	gotBody    []byte
}

func (f *fakeTransport) Do(_ context.Context, _ string, url string, headers map[string]string, body []byte, _ int64) (int, []byte, error) {
	f.gotURL, f.gotHeaders, f.gotBody = url, headers, body
	return f.status, f.body, f.err
}

func completion(content string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"model": "gpt-4o-mini",
		"choices": []map[string]any{
			{"message": map[string]string{"role": "assistant", "content": content}},
		},
	})
	return raw
}

func plannerRequest() investigation.ModelRequest {
	return investigation.ModelRequest{
		SchemaVersion: gateway.SchemaVersion,
		Phase:         investigation.PhasePlan,
		Incident: investigation.Incident{
			SchemaVersion: gateway.SchemaVersion,
			ID:            "INC-1",
			Environment:   "lab",
			Service:       "memory-test",
			Symptom:       "container restarts",
			StartedAt:     time.Date(2026, 9, 18, 16, 30, 0, 0, time.UTC),
		},
		AllowedActions: gateway.AllowedActions,
		AllowedMetrics: gateway.AllowedMetrics,
		Budget:         investigation.BudgetsLeft{ModelCallsRemaining: 20, InfraCallsRemaining: 50, SecondsRemaining: 600},
	}
}

func newPlanner(t *testing.T, ft *fakeTransport) LivePlanner {
	t.Helper()
	return LivePlanner{
		Endpoint:         Endpoint{BaseURL: "https://planner.invalid/v1", APIKey: "secret", Model: "gpt-4o-mini"},
		Transport:        ft,
		MaxResponseBytes: 1 << 20,
	}
}

// The planner's output must satisfy the same contract the engine enforces, or a
// live run would fail on the first step with a rejected response.
func TestLivePlannerProducesAValidPlannerTurn(t *testing.T) {
	content := `{"hypotheses":[
		{"statement":"the container was killed for exceeding its memory limit","fault_domain":"kubernetes","claim_kind":"memory_limit_termination"},
		{"statement":"the application leaks memory across restarts","fault_domain":"application","claim_kind":"memory_leak"}],
		"next_action":{"kind":"metrics.query","entity":"memory-test","reason":"measure the working set",
			"metric":"container_memory_working_set_bytes",
			"window":{"start":"2026-09-18T16:00:00Z","end":"2026-09-18T16:30:00Z"},
			"resolution":"30s"},
		"reason":"two competing hypotheses; measure memory first"}`
	ft := &fakeTransport{status: 200, body: completion(content)}
	planner := newPlanner(t, ft)

	resp, err := planner.Plan(context.Background(), plannerRequest())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if resp.SchemaVersion != gateway.SchemaVersion {
		t.Errorf("schema version = %q, want %q", resp.SchemaVersion, gateway.SchemaVersion)
	}
	if len(resp.Hypotheses) != 2 {
		t.Fatalf("hypotheses = %d, want 2", len(resp.Hypotheses))
	}
	if resp.NextAction == nil || resp.NextAction.Metric != "container_memory_working_set_bytes" {
		t.Fatalf("next action = %+v", resp.NextAction)
	}
	if err := resp.Validate(investigation.PhasePlan); err != nil {
		t.Fatalf("the planner's own output must satisfy the engine contract: %v", err)
	}

	if ft.gotURL != "https://planner.invalid/v1/chat/completions" {
		t.Errorf("url = %q", ft.gotURL)
	}
	if ft.gotHeaders["Authorization"] != "Bearer secret" {
		t.Errorf("authorization header = %q", ft.gotHeaders["Authorization"])
	}
	var sent chatRequest
	if err := json.Unmarshal(ft.gotBody, &sent); err != nil {
		t.Fatal(err)
	}
	// The provider enforces the reply's shape, strictly: lab runs failed on
	// replies that left fields out, which a schema makes impossible.
	if sent.ResponseFormat == nil || sent.ResponseFormat.Type != "json_schema" ||
		sent.ResponseFormat.JSONSchema == nil || !sent.ResponseFormat.JSONSchema.Strict {
		t.Error("the planner must ask for output constrained by a strict JSON schema")
	}
	if sent.Provider != nil {
		t.Error("an endpoint other than OpenRouter must not be sent OpenRouter's routing field")
	}
	if sent.Temperature != 0 {
		t.Errorf("temperature = %v, want 0 for a planner", sent.Temperature)
	}
	if len(sent.Messages) != 2 || !strings.Contains(sent.Messages[0].Content, "Allowed claim kinds") {
		t.Error("the system prompt must state the closed sets")
	}
	if !strings.Contains(sent.Messages[1].Content, "memory-test") {
		t.Error("the user message must carry the incident")
	}
}

// A single hypothesis is exactly what the engine rejects in the plan phase. The
// planner must not paper over it: it returns what the model said and lets the
// engine refuse, so the retry note can carry the real reason.
func TestLivePlannerDoesNotRepairAnInvalidTurn(t *testing.T) {
	content := `{"hypotheses":[{"statement":"only one idea","fault_domain":"kubernetes","claim_kind":"memory_limit_termination"}],"next_action":null,"reason":"done"}`
	ft := &fakeTransport{status: 200, body: completion(content)}
	planner := newPlanner(t, ft)

	resp, err := planner.Plan(context.Background(), plannerRequest())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if err := resp.Validate(investigation.PhasePlan); err == nil {
		t.Fatal("one hypothesis in the plan phase must be rejected by the contract")
	}
}

func TestLivePlannerCarriesTheRetryNote(t *testing.T) {
	ft := &fakeTransport{status: 200, body: completion(`{"hypotheses":[],"next_action":null,"reason":"stop"}`)}
	planner := newPlanner(t, ft)

	req := plannerRequest()
	req.Phase = investigation.PhaseReassess
	req.RetryNote = "planner response rejected: hypothesis 0 fault domain \"nonsense\" is invalid"
	if _, err := planner.Plan(context.Background(), req); err != nil {
		t.Fatalf("plan: %v", err)
	}
	var sent chatRequest
	if err := json.Unmarshal(ft.gotBody, &sent); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sent.Messages[1].Content, "nonsense") {
		t.Error("the rejection reason must be fed back to the model")
	}
}

func TestLivePlannerFailures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   []byte
		err    error
	}{
		{name: "transport error", err: errors.New("connection refused")},
		{name: "http error", status: 429, body: []byte(`{"error":"rate limited"}`)},
		{name: "no choices", status: 200, body: []byte(`{"choices":[]}`)},
		{name: "content is not json", status: 200, body: completion("not json")},
		{name: "unknown field", status: 200, body: completion(`{"hypotheses":[],"next_action":null,"reason":"x","confidence":0.9}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ft := &fakeTransport{status: tc.status, body: tc.body, err: tc.err}
			planner := newPlanner(t, ft)
			if _, err := planner.Plan(context.Background(), plannerRequest()); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestUnconfiguredPlannerFailsLoudly(t *testing.T) {
	planner := LivePlanner{Transport: &fakeTransport{}}
	if _, err := planner.Plan(context.Background(), plannerRequest()); err == nil {
		t.Fatal("an unconfigured planner must fail rather than invent a turn")
	}
}

// The prompt and the contract must agree: every closed set rendered into the
// prompt is the set the engine validates against.
func TestPlannerPromptRendersTheContract(t *testing.T) {
	prompt := PlannerSystemPrompt()
	for _, want := range []string{
		string(investigation.ClaimMemoryLimitTermination),
		string(investigation.DomainExternalDependency),
		string(gateway.ActionMetricsQuery),
		"container_memory_working_set_bytes",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("planner prompt is missing %q", want)
		}
	}
}
