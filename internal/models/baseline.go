package models

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

// BaselinePromptVersion identifies the prompt and the response schema. It is
// stamped on every relation the arm produces, so a benchmark records which
// question was asked and not only which model answered.
const BaselinePromptVersion = "relations-prompt/v1"

// BaselineArm is the LLM-only arm: an OpenAI-compatible chat completions
// endpoint, one call per hypothesis covering every piece of pending evidence.
//
// Batching is deliberate. One call per observation would multiply the cost of a
// comparison by the number of observations and, worse, would make the arm's
// model-call count an artefact of how the loop happens to be structured rather
// than a property of the arm.
type BaselineArm struct {
	Endpoint  Endpoint
	Transport Transport
	Now       func() time.Time
	// MaxResponseBytes bounds one answer.
	MaxResponseBytes int64
}

func (a BaselineArm) Arm() string { return investigation.BaselineArm }

func (a BaselineArm) ArmVersion() string { return BaselinePromptVersion }

func (a BaselineArm) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

func (a BaselineArm) Label(h investigation.Hypothesis, f investigation.Facts, obs map[string]investigation.Observation) ([]investigation.RelationDraft, []investigation.EvaluatorCall, error) {
	if !a.Endpoint.Configured() {
		return nil, failed(investigation.CallFailed,
			"baseline arm is not configured: set VORA_PROBE_MODEL_BASE_URL", a.Arm(), a.ArmVersion(), a.Endpoint.Model, h.ID, len(obs)), nil
	}
	sorted := sortedSummaries(obs)
	if len(sorted) == 0 {
		return nil, nil, nil
	}
	transport := a.Transport
	if transport == nil {
		transport = NewHTTPTransport(a.Endpoint.Timeout)
	}

	started := a.now()
	drafts, call, err := a.classify(context.Background(), transport, h, sorted, AggregateContext(f))
	call.LatencyMS = a.now().Sub(started).Milliseconds()
	if err != nil {
		return nil, []investigation.EvaluatorCall{call}, err
	}
	return drafts, []investigation.EvaluatorCall{call}, nil
}

func (a BaselineArm) classify(ctx context.Context, transport Transport, h investigation.Hypothesis, summaries []investigation.ObservationSummary, aggregate []string) ([]investigation.RelationDraft, investigation.EvaluatorCall, error) {
	call := investigation.EvaluatorCall{
		SchemaVersion: gateway.SchemaVersion,
		Arm:           a.Arm(),
		ArmVersion:    a.ArmVersion(),
		Model:         a.Endpoint.Model,
		Remote:        true,
		Hypothesis:    h.ID,
		Observations:  len(summaries),
		Status:        investigation.CallOK,
	}
	body, err := json.Marshal(chatRequest{
		Model: a.Endpoint.Model,
		Messages: []chatMessage{
			{Role: "system", Content: baselineSystemPrompt},
			{Role: "user", Content: renderBatch(h, summaries, aggregate)},
		},
		MaxTokens:      a.Endpoint.MaxOutputTokens,
		Temperature:    0,
		ResponseFormat: &chatResponseFormat{Type: "json_object"},
	})
	if err != nil {
		return nil, call, err
	}
	headers := map[string]string{}
	if a.Endpoint.APIKey != "" {
		headers["Authorization"] = "Bearer " + a.Endpoint.APIKey
	}
	status, raw, err := transport.Do(ctx, "POST", strings.TrimRight(a.Endpoint.BaseURL, "/")+"/chat/completions", headers, body, a.MaxResponseBytes)
	if err != nil {
		call.Status = investigation.CallFailed
		call.Reason = err.Error()
		return nil, call, err
	}
	if status < 200 || status > 299 {
		call.Status = investigation.CallFailed
		call.Reason = fmt.Sprintf("endpoint returned %d: %s", status, snippet(raw, 200))
		return nil, call, fmt.Errorf("%s", call.Reason)
	}

	// The provider envelope is decoded leniently: OpenAI-compatible services
	// return many fields Probe does not care about, and rejecting the response
	// over them would fail the arm for the wrong reason. Our own contract inside
	// it is decoded strictly.
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		call.Status = investigation.CallInvalid
		call.Reason = err.Error()
		return nil, call, err
	}
	if len(parsed.Choices) == 0 {
		call.Status = investigation.CallInvalid
		call.Reason = "endpoint returned no choices"
		return nil, call, fmt.Errorf("%s", call.Reason)
	}
	if parsed.Model != "" {
		// Record what answered, not what was requested: a provider may serve a
		// different snapshot than the one asked for.
		call.Model = parsed.Model
	}
	call.PromptTokens = parsed.Usage.PromptTokens
	call.CompletionTokens = parsed.Usage.CompletionTokens

	var answer struct {
		Labels []labelled `json:"labels"`
	}
	if err := decodeStrict([]byte(parsed.Choices[0].Message.Content), &answer); err != nil {
		call.Status = investigation.CallInvalid
		call.Reason = err.Error()
		return nil, call, err
	}

	// Every observation must come back exactly once. A model that quietly drops
	// the inconvenient evidence is the failure mode this repository exists to
	// prevent, so a partial answer is a failed arm.
	drafts, err := validateCoverage(answer.Labels, summaries)
	if err != nil {
		call.Status = investigation.CallInvalid
		call.Reason = err.Error()
		return nil, call, err
	}
	return drafts, call, nil
}

// labelled is one answer from an arm, before validation.
type labelled struct {
	Observation string `json:"observation"`
	Label       string `json:"label"`
	Reason      string `json:"reason"`
}

// validateCoverage turns raw answers into drafts, refusing partial or invented
// coverage.
func validateCoverage(answers []labelled, summaries []investigation.ObservationSummary) ([]investigation.RelationDraft, error) {
	byID := map[string]investigation.ObservationSummary{}
	for _, s := range summaries {
		byID[s.ID] = s
	}
	seen := map[string]bool{}
	drafts := make([]investigation.RelationDraft, 0, len(summaries))
	for _, a := range answers {
		if _, ok := byID[a.Observation]; !ok {
			return nil, fmt.Errorf("arm labelled %q, which is not one of the evidence ids it was given", a.Observation)
		}
		if seen[a.Observation] {
			return nil, fmt.Errorf("arm labelled %q more than once", a.Observation)
		}
		seen[a.Observation] = true
		if strings.TrimSpace(a.Reason) == "" {
			return nil, fmt.Errorf("arm labelled %q without a reason", a.Observation)
		}
		relationship, err := validateLabel(a.Label)
		if err != nil {
			return nil, fmt.Errorf("for %s: %w", a.Observation, err)
		}
		drafts = append(drafts, investigation.RelationDraft{
			Observation:  a.Observation,
			Relationship: relationship,
			Reason:       a.Reason,
		})
	}
	var missing []string
	for _, s := range summaries {
		if !seen[s.ID] {
			missing = append(missing, s.ID)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("arm left %d of %d observations unlabelled: %s",
			len(missing), len(summaries), strings.Join(missing, ", "))
	}
	// Preserve the caller's order so relation ids stay stable across runs.
	return drafts, nil
}

func sortedSummaries(obs map[string]investigation.Observation) []investigation.ObservationSummary {
	summaries := make([]investigation.ObservationSummary, 0, len(obs))
	for _, o := range obs {
		summaries = append(summaries, o.Summary())
	}
	// Map iteration order is not stable, and a report that changes between runs
	// is not checkable.
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].ID < summaries[j].ID })
	return summaries
}

func renderBatch(h investigation.Hypothesis, summaries []investigation.ObservationSummary, aggregate []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HYPOTHESIS\n%s\n", h.Statement)
	fmt.Fprintf(&b, "fault domain: %s\nclaim kind: %s\n", h.FaultDomain, h.ClaimKind)
	if len(aggregate) > 0 {
		b.WriteString("\nMEASUREMENTS FOR THIS SERVICE\n")
		for _, line := range aggregate {
			fmt.Fprintf(&b, "- %s\n", line)
		}
	}
	b.WriteString("\nEVIDENCE TO LABEL\n")
	for _, s := range summaries {
		fmt.Fprintf(&b, "\n[%s] %s\ntype: %s, source: %s, completeness: %s\n",
			s.ID, s.Statement, s.Type, s.Source, s.Completeness)
	}
	return b.String()
}

var baselineSystemPrompt = `You label how each piece of infrastructure evidence bears on one hypothesis about an incident.

Choose exactly one label per piece of evidence, from this closed set:
` + Definitions() + `
Rules:
` + Rules + `

Answer with JSON only, with one entry per evidence id:
{"labels": [{"observation": "<id>", "label": "<one of the four labels>", "reason": "<one sentence>"}]}`

type chatRequest struct {
	Model          string              `json:"model"`
	Messages       []chatMessage       `json:"messages"`
	MaxTokens      int                 `json:"max_tokens,omitempty"`
	Temperature    float64             `json:"temperature"`
	ResponseFormat *chatResponseFormat `json:"response_format,omitempty"`
}

type chatResponseFormat struct {
	Type string `json:"type"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}
