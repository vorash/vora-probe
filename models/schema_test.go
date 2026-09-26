package models

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// The schema is the engine's contract, rendered for the provider. If it drifted
// from the closed sets, the provider would allow what the engine rejects, or
// refuse what it accepts.
func TestThePlannerSchemaIsTheEnginesContract(t *testing.T) {
	schema := PlannerResponseSchema(gateway.AllowedActions, nil)
	hyp := schema["properties"].(map[string]any)["hypotheses"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)
	var kinds []string
	for _, k := range investigation.AllClaimKinds {
		kinds = append(kinds, string(k))
	}
	if got := hyp["claim_kind"].(map[string]any)["enum"].([]string); !slices.Equal(got, kinds) {
		t.Fatalf("claim kinds %v, want the engine's %v", got, kinds)
	}
	if !slices.Contains(hyp["claim_kind"].(map[string]any)["enum"].([]string), "exhaustion_forecast") {
		t.Fatal("the forecast claim kind must be allowed")
	}
	assertStrict(t, "reply", schema)
}

// Strict mode requires every object to require all its properties and allow no
// others; a provider refuses a schema that does not. Checked everywhere.
func assertStrict(t *testing.T, path string, node any) {
	t.Helper()
	m, ok := node.(map[string]any)
	if !ok {
		return
	}
	if props, ok := m["properties"].(map[string]any); ok {
		required, _ := m["required"].([]string)
		for name, child := range props {
			if !slices.Contains(required, name) {
				t.Errorf("%s.%s is not required; strict mode needs every property required (nullable if optional)", path, name)
			}
			assertStrict(t, path+"."+name, child)
		}
		if m["additionalProperties"] != false {
			t.Errorf("%s allows additional properties", path)
		}
	}
	for _, key := range []string{"items"} {
		if child, ok := m[key]; ok {
			assertStrict(t, path+"[]", child)
		}
	}
	if alts, ok := m["anyOf"].([]any); ok {
		for _, alt := range alts {
			assertStrict(t, path, alt)
		}
	}
}

// A schema-conforming reply fills the fields an action kind does not use with
// null. That must still decode strictly and satisfy the engine's contract, or
// the schema would make every non-metric action a rejection.
func TestASchemaConformingReplyWithNullsIsValid(t *testing.T) {
	reply := `{"hypotheses":[
	  {"statement":"killed at its limit","fault_domain":"kubernetes","claim_kind":"memory_limit_termination","evidence_needed":["termination"]},
	  {"statement":"restarts for another reason","fault_domain":"application","claim_kind":"non_memory_restart","evidence_needed":[]}],
	 "next_action":{"kind":"kubernetes.containers","entity":"memory-test","reason":"termination state","metric":null,"window":null,"resolution":null,"filter":null},
	 "reason":"collect the termination state first","read_context":null}`
	var answer plannerAnswer
	if err := decodeStrict([]byte(reply), &answer); err != nil {
		t.Fatalf("decode: %v", err)
	}
	resp := investigation.ModelResponse{SchemaVersion: "probe/v1", Hypotheses: answer.Hypotheses, NextAction: answer.NextAction, Reason: answer.Reason}
	if err := resp.Validate(investigation.PhasePlan); err != nil {
		t.Fatalf("a schema-conforming reply must satisfy the engine: %v", err)
	}
	raw, _ := json.Marshal(PlannerResponseSchema(gateway.AllowedActions, nil))
	if len(raw) == 0 {
		t.Fatal("the schema must serialize")
	}
}

// OpenRouter silently drops a parameter a provider does not support unless told
// to route only to providers that do; every other endpoint must not be sent
// that field at all.
func TestParameterPinningIsForOpenRouterOnly(t *testing.T) {
	for url, want := range map[string]bool{
		"https://openrouter.ai/api/v1":     true,
		"https://api.openrouter.ai/v1":     true,
		"https://api.openai.com/v1":        false,
		"https://notopenrouter.ai.evil/v1": false,
		"https://openrouter.ai.example/v1": false,
		"http://127.0.0.1:3":               false,
	} {
		if got := requiresParameterPinning(url); got != want {
			t.Errorf("%s: pinning %t, want %t", url, got, want)
		}
	}
}

// The schema offers exactly the actions this incident was offered, and a log
// query can only name a filter from the closed set.
func TestTheSchemaFollowsTheOfferedActions(t *testing.T) {
	low := PlannerResponseSchema(gateway.ActionsFor(""), nil)
	action := low["properties"].(map[string]any)["next_action"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if slices.Contains(action["kind"].(map[string]any)["enum"].([]string), string(gateway.ActionLogsQuery)) {
		t.Fatal("a low-severity incident's schema allows logs.query")
	}
	high := PlannerResponseSchema(gateway.ActionsFor("critical"), nil)
	action = high["properties"].(map[string]any)["next_action"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["properties"].(map[string]any)
	if !slices.Contains(action["kind"].(map[string]any)["enum"].([]string), string(gateway.ActionLogsQuery)) {
		t.Fatal("a critical incident's schema must allow logs.query")
	}
	filters := action["filter"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["enum"].([]string)
	if !slices.Equal(filters, gateway.LogFilterNames()) {
		t.Fatalf("filters %v, want the closed set %v", filters, gateway.LogFilterNames())
	}
	assertStrict(t, "reply", high)
}

// The planner sees the catalog and the bodies it read, framed as reference it
// cannot cite; its schema offers only packages it has not read yet.
func TestContextIsPresentedAsReferenceAndOfferedOnce(t *testing.T) {
	req := plannerRequest()
	req.ContextCatalog = []investigation.ContextSummary{{Name: "topology", Description: "what calls what"}, {Name: "quirks", Description: "known oddities"}}
	req.Contexts = []investigation.Context{{Name: "topology", Body: "checkout-api calls payments-api"}}
	prompt := renderPlannerRequest(req)
	for _, want := range []string{"CONTEXT PACKAGES (reference, never evidence)", "- topology: what calls what [read]", "cannot be cited", "checkout-api calls payments-api"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the prompt is missing %q:\n%s", want, prompt)
		}
	}
	schema := PlannerResponseSchema(req.AllowedActions, contextNames(req))
	read := schema["properties"].(map[string]any)["read_context"].(map[string]any)["anyOf"].([]any)[0].(map[string]any)["enum"].([]string)
	if !slices.Equal(read, []string{"quirks"}) {
		t.Fatalf("read_context offers %v, want only the unread package", read)
	}
	if none := PlannerResponseSchema(req.AllowedActions, nil)["properties"].(map[string]any)["read_context"].(map[string]any); none["type"] != "null" {
		t.Fatalf("with no packages, read_context must be null only: %v", none)
	}
}
