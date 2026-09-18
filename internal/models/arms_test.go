package models_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/models"
)

// stubTransport records what the arm sent and returns a canned answer, so the
// real clients are exercised without a network or a credential.
type stubTransport struct {
	urls     []string
	bodies   [][]byte
	headers  []map[string]string
	status   int
	response []byte
	err      error
}

func (s *stubTransport) Do(_ context.Context, _ string, url string, headers map[string]string, body []byte, _ int64) (int, []byte, error) {
	s.urls = append(s.urls, url)
	s.bodies = append(s.bodies, body)
	s.headers = append(s.headers, headers)
	if s.err != nil {
		return 0, nil, s.err
	}
	status := s.status
	if status == 0 {
		status = 200
	}
	return status, s.response, nil
}

func observation(t *testing.T) investigation.Observation {
	t.Helper()
	payload, err := json.Marshal(gateway.MetricSeries{
		Metric: "container_memory_working_set_bytes",
		Unit:   "bytes",
		Samples: []gateway.MetricSample{
			{At: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC), Value: 188743680},
			{At: time.Date(2026, 9, 18, 12, 20, 0, 0, time.UTC), Value: 553648128},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	window := gateway.Window{
		Start: time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 9, 18, 12, 30, 0, 0, time.UTC),
	}
	action := gateway.Action{
		Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "measure memory",
		Metric: "container_memory_working_set_bytes", Window: &window, Resolution: "60s",
	}
	response := gateway.Response{
		SchemaVersion: gateway.SchemaVersion, Kind: action.Kind, Entity: action.Entity,
		Status: gateway.StatusOK, Completeness: gateway.Complete, RetrievedAt: window.End,
		Query:   gateway.QueryMeta{Datasource: "prometheus", Query: "container_memory_working_set_bytes", Params: map[string]string{"metric": action.Metric}},
		Digest:  gateway.Digest(payload),
		Payload: payload,
	}
	o, err := investigation.ObservationFromResponse("OBS-0001", action, response, window.End)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return o
}

func inputs(t *testing.T) (investigation.Hypothesis, investigation.Facts, map[string]investigation.Observation) {
	t.Helper()
	o := observation(t)
	byID := map[string]investigation.Observation{o.ID: o}
	facts := investigation.BuildFacts("payment-api", []investigation.Observation{o})
	hypothesis := investigation.Hypothesis{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "HYP-0001",
		Statement:     "payment-api exceeded its container memory limit and was terminated",
		FaultDomain:   investigation.DomainKubernetes,
		ClaimKind:     investigation.ClaimMemoryLimitTermination,
	}
	return hypothesis, facts, byID
}

func chatResponse(content string) []byte {
	raw, _ := json.Marshal(map[string]any{
		"id":      "chatcmpl-1",
		"object":  "chat.completion",
		"created": 1,
		"model":   "gpt-4o-mini-2024-07-18",
		"choices": []map[string]any{
			{"index": 0, "message": map[string]string{"role": "assistant", "content": content}, "finish_reason": "stop"},
		},
		"usage": map[string]int{"prompt_tokens": 120, "completion_tokens": 18, "total_tokens": 138},
	})
	return raw
}

func TestBaselineArmRecordsWhatActuallyAnswered(t *testing.T) {
	transport := &stubTransport{response: chatResponse(`{"labels":[{"observation":"OBS-0001","label":"supports","reason":"working set reached the limit"}]}`)}
	arm := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", APIKey: "secret", Model: "gpt-4o-mini", MaxOutputTokens: 256},
		Transport: transport,
		Now:       func() time.Time { return time.Date(2026, 9, 18, 12, 32, 0, 0, time.UTC) },
	}
	h, facts, obs := inputs(t)
	drafts, calls, err := arm.Label(h, facts, obs)
	if err != nil {
		t.Fatalf("label: %v", err)
	}
	if len(drafts) != 1 || drafts[0].Relationship != investigation.Supports {
		t.Fatalf("unexpected drafts: %+v", drafts)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	call := calls[0]
	if call.Model != "gpt-4o-mini-2024-07-18" {
		t.Errorf("the served model must be recorded, not the requested one: %q", call.Model)
	}
	if !call.Remote {
		t.Error("a model call must be marked remote so it is charged to the model budget")
	}
	if call.PromptTokens != 120 || call.CompletionTokens != 18 {
		t.Errorf("usage not recorded: %+v", call)
	}
	if call.ArmVersion != models.BaselinePromptVersion {
		t.Errorf("the prompt version must be recorded: %q", call.ArmVersion)
	}
	if len(transport.urls) != 1 || !strings.HasSuffix(transport.urls[0], "/chat/completions") {
		t.Errorf("unexpected endpoint: %v", transport.urls)
	}
	if got := transport.headers[0]["Authorization"]; got != "Bearer secret" {
		t.Errorf("authorization header = %q", got)
	}
	// One call for the whole hypothesis, not one per observation.
	if len(transport.bodies) != 1 {
		t.Errorf("the arm should batch its questions, sent %d requests", len(transport.bodies))
	}
	if body := string(transport.bodies[0]); !strings.Contains(body, "insufficient_context") {
		t.Error("the prompt must carry the closed label set")
	}
}

func TestBaselineArmRefusesPartialCoverage(t *testing.T) {
	// Two observations, one labelled: dropping evidence must fail the arm.
	o := observation(t)
	second := o
	second.ID = "OBS-0002"
	byID := map[string]investigation.Observation{o.ID: o, second.ID: second}
	facts := investigation.BuildFacts("payment-api", []investigation.Observation{o, second})
	arm := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", Model: "m"},
		Transport: &stubTransport{response: chatResponse(`{"labels":[{"observation":"OBS-0001","label":"supports","reason":"ok"}]}`)},
	}
	drafts, calls, err := arm.Label(investigation.Hypothesis{ID: "HYP-0001"}, facts, byID)
	if err == nil {
		t.Fatal("an answer that leaves evidence unlabelled must fail the arm")
	}
	if !strings.Contains(err.Error(), "unlabelled") {
		t.Fatalf("the error should say what was missing, got %v", err)
	}
	if len(drafts) != 0 {
		t.Fatalf("a failed arm must not contribute labels: %+v", drafts)
	}
	if len(calls) != 1 || calls[0].Status != investigation.CallInvalid {
		t.Fatalf("the failure must be recorded as an invalid response: %+v", calls)
	}
}

func TestBaselineArmRefusesInventedEvidenceIds(t *testing.T) {
	arm := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", Model: "m"},
		Transport: &stubTransport{response: chatResponse(`{"labels":[{"observation":"OBS-9999","label":"supports","reason":"ok"}]}`)},
	}
	h, facts, obs := inputs(t)
	if _, _, err := arm.Label(h, facts, obs); err == nil {
		t.Fatal("labelling evidence that was not provided must fail the arm")
	}
}

func TestBaselineArmRefusesLabelsOutsideTheSet(t *testing.T) {
	arm := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", Model: "m"},
		Transport: &stubTransport{response: chatResponse(`{"labels":[{"observation":"OBS-0001","label":"probably","reason":"ok"}]}`)},
	}
	h, facts, obs := inputs(t)
	_, calls, err := arm.Label(h, facts, obs)
	if err == nil {
		t.Fatal("an unknown label must fail the arm rather than be rounded to the nearest one")
	}
	if len(calls) != 1 || calls[0].Status != investigation.CallInvalid {
		t.Fatalf("unexpected call record: %+v", calls)
	}
}

func TestBaselineArmRecordsHTTPFailure(t *testing.T) {
	arm := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", Model: "m"},
		Transport: &stubTransport{status: 429, response: []byte(`{"error":"rate limited"}`)},
	}
	h, facts, obs := inputs(t)
	_, calls, err := arm.Label(h, facts, obs)
	if err == nil {
		t.Fatal("a non-2xx response must fail the arm")
	}
	if calls[0].Status != investigation.CallFailed || !strings.Contains(calls[0].Reason, "429") {
		t.Fatalf("the failure must be recorded with its status: %+v", calls[0])
	}
}

func TestBaselineArmIsBlockedWithoutAnEndpoint(t *testing.T) {
	arm := models.BaselineArm{Transport: &stubTransport{}}
	h, facts, obs := inputs(t)
	drafts, calls, err := arm.Label(h, facts, obs)
	if err != nil {
		t.Fatalf("an unconfigured arm is blocked, not an error: %v", err)
	}
	if len(drafts) != 0 {
		t.Fatal("a blocked arm must produce no labels")
	}
	if calls[0].Status == investigation.CallOK {
		t.Fatalf("a blocked arm must record a failure: %+v", calls[0])
	}
	if !strings.Contains(calls[0].Reason, "VORA_PROBE_MODEL_BASE_URL") {
		t.Fatalf("a blocked arm should say what is missing, got %q", calls[0].Reason)
	}
}

func jevResponse(choice string, confidence float64) []byte {
	raw, _ := json.Marshal(map[string]any{
		"model": "jev-latest",
		"answers": map[string]any{
			"relation:OBS-0001": map[string]any{
				"type":       "choice",
				"choice":     choice,
				"confidence": confidence,
				"probabilities": map[string]float64{
					"contradicts": 0.82, "supports": 0.05, "neutral": 0.10, "insufficient_context": 0.03,
				},
			},
		},
		"usage": map[string]any{"input_tokens": 210, "output_tokens": 6},
	})
	return raw
}

func TestJevArmClassifiesWithAChoiceQuestion(t *testing.T) {
	transport := &stubTransport{response: jevResponse("contradicts", 0.82)}
	arm := models.JevArm{
		Endpoint:  models.Endpoint{BaseURL: "https://api.typesafe.ai", APIKey: "jevkey", Model: "jev-latest"},
		Transport: transport,
	}
	h, facts, obs := inputs(t)
	drafts, calls, err := arm.Label(h, facts, obs)
	if err != nil {
		t.Fatalf("label: %v", err)
	}
	if len(drafts) != 1 || drafts[0].Relationship != investigation.Contradicts {
		t.Fatalf("unexpected drafts: %+v", drafts)
	}
	if len(transport.urls) != 1 || !strings.HasSuffix(transport.urls[0], "/v1/systemone") {
		t.Fatalf("unexpected endpoint: %v", transport.urls)
	}
	if got := transport.headers[0]["Authorization"]; got != "Bearer jevkey" {
		t.Errorf("authorization header = %q", got)
	}
	body := string(transport.bodies[0])
	for _, want := range []string{`"questions"`, `"type":"choice"`, `"criteria"`, "Temporal proximity is not a mechanism", "insufficient_context"} {
		if !strings.Contains(body, want) {
			t.Errorf("the Jev request should contain %q", want)
		}
	}
	// One request carrying every question, so the arm's call count does not
	// depend on how many observations the loop happens to collect.
	if len(transport.bodies) != 1 {
		t.Errorf("the arm should batch its questions, sent %d requests", len(transport.bodies))
	}
	call := calls[0]
	if call.PromptTokens != 210 || call.CompletionTokens != 6 {
		t.Errorf("usage not recorded: %+v", call)
	}
	if !call.Remote || call.ArmVersion != models.JevSchemaVersion {
		t.Errorf("unexpected call record: %+v", call)
	}
	// The distribution-derived confidence is retained as classification metadata,
	// worded so it cannot read as a probability about the incident.
	if !strings.Contains(call.Reason, "concentration of the answer distribution") {
		t.Errorf("confidence metadata must be labelled as such, got %q", call.Reason)
	}
}

func TestJevArmRefusesAMissingAnswer(t *testing.T) {
	arm := models.JevArm{
		Endpoint:  models.Endpoint{BaseURL: "https://api.typesafe.ai", Model: "jev-latest"},
		Transport: &stubTransport{response: []byte(`{"model":"jev-latest","answers":{},"usage":{}}`)},
	}
	h, facts, obs := inputs(t)
	_, calls, err := arm.Label(h, facts, obs)
	if err == nil {
		t.Fatal("a response with no answer for the question must fail the arm")
	}
	if !strings.Contains(err.Error(), "OBS-0001") {
		t.Fatalf("the error should name the unanswered evidence, got %v", err)
	}
	if calls[0].Status != investigation.CallInvalid {
		t.Fatalf("unexpected call record: %+v", calls[0])
	}
}

func TestJevArmRefusesANonChoiceAnswer(t *testing.T) {
	arm := models.JevArm{
		Endpoint: models.Endpoint{BaseURL: "https://api.typesafe.ai", Model: "jev-latest"},
		Transport: &stubTransport{response: []byte(
			`{"model":"jev-latest","answers":{"relation:OBS-0001":{"type":"noul","choice":"yes","confidence":0.9}},"usage":{}}`)},
	}
	h, facts, obs := inputs(t)
	if _, _, err := arm.Label(h, facts, obs); err == nil {
		t.Fatal("a non-choice answer must fail the arm")
	}
}

func TestJevArmIsBlockedWithoutAnEndpoint(t *testing.T) {
	arm := models.JevArm{Transport: &stubTransport{}}
	h, facts, obs := inputs(t)
	drafts, calls, err := arm.Label(h, facts, obs)
	if err != nil {
		t.Fatalf("an unconfigured arm is blocked, not an error: %v", err)
	}
	if len(drafts) != 0 {
		t.Fatal("a blocked arm must produce no labels")
	}
	if !strings.Contains(calls[0].Reason, "VORA_PROBE_JEV_BASE_URL") {
		t.Fatalf("a blocked arm should say what is missing, got %q", calls[0].Reason)
	}
}

// The two arms must answer the same question. The label set and its definitions
// are rendered into both from one source, so a difference in answers is a
// difference in the arms and not in how they were asked.
func TestBothArmsShareTheLabelSet(t *testing.T) {
	baselineTransport := &stubTransport{response: chatResponse(`{"labels":[{"observation":"OBS-0001","label":"supports","reason":"ok"}]}`)}
	jevTransport := &stubTransport{response: jevResponse("supports", 0.9)}
	baseline := models.BaselineArm{
		Endpoint:  models.Endpoint{BaseURL: "https://models.example/v1", Model: "m"},
		Transport: baselineTransport,
	}
	jev := models.JevArm{
		Endpoint:  models.Endpoint{BaseURL: "https://api.typesafe.ai", Model: "jev-latest"},
		Transport: jevTransport,
	}
	h, facts, obs := inputs(t)
	if _, _, err := baseline.Label(h, facts, obs); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	if _, _, err := jev.Label(h, facts, obs); err != nil {
		t.Fatalf("jev: %v", err)
	}
	if len(models.Labels) != 4 {
		t.Fatalf("the label set is closed at four, got %v", models.Labels)
	}
	baselinePrompt := string(baselineTransport.bodies[0])
	jevRequest := string(jevTransport.bodies[0])
	for _, label := range models.Labels {
		definition := models.LabelDefinitions[label]
		if !strings.Contains(baselinePrompt, label) {
			t.Errorf("the baseline prompt omits the label %q", label)
		}
		if !strings.Contains(baselinePrompt, definition) {
			t.Errorf("the baseline prompt omits the definition of %q", label)
		}
		if !strings.Contains(jevRequest, label) {
			t.Errorf("the Jev request omits the label %q", label)
		}
		if !strings.Contains(jevRequest, definition) {
			t.Errorf("the Jev request omits the definition of %q", label)
		}
	}
}

func TestConfigFromEnvReportsWhatIsConfigured(t *testing.T) {
	t.Setenv("VORA_PROBE_MODEL_BASE_URL", "")
	t.Setenv("VORA_PROBE_JEV_BASE_URL", "")
	cfg := models.ConfigFromEnv()
	if cfg.Baseline.Configured() || cfg.Jev.Configured() {
		t.Fatal("absent configuration must report as not configured, so the arm is blocked rather than attempted")
	}
	t.Setenv("VORA_PROBE_MODEL_BASE_URL", "https://models.example/v1")
	cfg = models.ConfigFromEnv()
	if !cfg.Baseline.Configured() || cfg.Jev.Configured() {
		t.Fatal("only the configured arm should report as configured")
	}
	if strings.Contains(cfg.Baseline.Redacted(), "secret") && cfg.Baseline.APIKey == "" {
		t.Fatal("redaction must not invent a secret")
	}
}
