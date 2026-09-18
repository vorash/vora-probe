package gateway_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
)

func window(start, end time.Time) *gateway.Window { return &gateway.Window{Start: start, End: end} }

var (
	start = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	end   = time.Date(2026, 9, 18, 12, 30, 0, 0, time.UTC)
)

func TestActionValidateAcceptsTheAllowedSet(t *testing.T) {
	actions := []gateway.Action{
		{Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "reason", Metric: "container_memory_working_set_bytes", Window: window(start, end), Resolution: "60s"},
		{Kind: gateway.ActionKubernetesContainers, Entity: "payment-api", Reason: "reason"},
		{Kind: gateway.ActionKubernetesEvents, Entity: "payment-api", Reason: "reason", Window: window(start, end)},
		{Kind: gateway.ActionKubernetesDeployments, Entity: "payment-api", Reason: "reason"},
	}
	for _, a := range actions {
		if err := a.Validate(); err != nil {
			t.Errorf("%s should be valid: %v", a, err)
		}
	}
}

func TestActionValidateDeniesEverythingElse(t *testing.T) {
	base := gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "payment-api", Reason: "reason"}
	cases := []struct {
		name   string
		mutate func(*gateway.Action)
	}{
		{"write action", func(a *gateway.Action) { a.Kind = gateway.ActionKind("kubernetes.delete") }},
		{"exec action", func(a *gateway.Action) { a.Kind = gateway.ActionKind("kubernetes.exec") }},
		{"shell action", func(a *gateway.Action) { a.Kind = gateway.ActionKind("shell.exec") }},
		{"unlisted metric", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "reason", Metric: "container_memory_failcnt", Window: window(start, end), Resolution: "60s"}
		}},
		{"metric without window", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "reason", Metric: "container_cpu_usage_ratio", Resolution: "60s"}
		}},
		{"missing resolution", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "reason", Metric: "container_cpu_usage_ratio", Window: window(start, end)}
		}},
		{"events without window", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionKubernetesEvents, Entity: "payment-api", Reason: "reason"}
		}},
		{"metric on a non-metric action", func(a *gateway.Action) { a.Metric = "container_cpu_usage_ratio" }},
		{"window on a snapshot action", func(a *gateway.Action) { a.Window = window(start, end) }},
		{"empty entity", func(a *gateway.Action) { a.Entity = "" }},
		{"empty reason", func(a *gateway.Action) { a.Reason = "" }},
		{"inverted window", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionKubernetesEvents, Entity: "payment-api", Reason: "reason", Window: window(end, start)}
		}},
		{"window wider than the maximum", func(a *gateway.Action) {
			*a = gateway.Action{Kind: gateway.ActionKubernetesEvents, Entity: "payment-api", Reason: "reason", Window: window(start, start.Add(3*time.Hour))}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := base
			c.mutate(&a)
			if err := a.Validate(); err == nil {
				t.Fatalf("%s should be denied", c.name)
			}
		})
	}
}

func TestAllowedActionsContainNoMutation(t *testing.T) {
	for _, k := range gateway.AllowedActions {
		for _, forbidden := range []string{"delete", "patch", "create", "update", "exec", "apply", "write"} {
			if strings.Contains(string(k), forbidden) {
				t.Errorf("allowed action %q looks like a mutation", k)
			}
		}
	}
}

func TestActionKeyIsCanonical(t *testing.T) {
	a := gateway.Action{Kind: gateway.ActionMetricsQuery, Entity: "payment-api", Reason: "r", Metric: "container_cpu_usage_ratio", Window: window(start, end), Resolution: "60s"}
	b := a
	b.Reason = "a different reason"
	if a.Key() != b.Key() {
		t.Fatal("the reason must not change a request's identity")
	}
	c := a
	c.Window = window(start, end.Add(time.Minute))
	if a.Key() == c.Key() {
		t.Fatal("a different window is a different request")
	}
}

func TestDigestIsStableAndSensitive(t *testing.T) {
	one := gateway.Digest([]byte(`{"a":1}`))
	two := gateway.Digest([]byte(`{"a":1}`))
	if one != two {
		t.Fatal("digest is not stable")
	}
	if one == gateway.Digest([]byte(`{"a":2}`)) {
		t.Fatal("digest does not change with the payload")
	}
	if !strings.HasPrefix(one, "sha256:") {
		t.Fatalf("unexpected digest format %q", one)
	}
}

func TestResponseValidate(t *testing.T) {
	payload := json.RawMessage(`{"metric":"container_cpu_usage_ratio","unit":"ratio","samples":[{"at":"2026-09-18T12:00:00Z","value":0.2}]}`)
	ok := gateway.Response{
		SchemaVersion: gateway.SchemaVersion,
		Kind:          gateway.ActionMetricsQuery,
		Entity:        "payment-api",
		Status:        gateway.StatusOK,
		Completeness:  gateway.Complete,
		RetrievedAt:   end,
		Digest:        gateway.Digest(payload),
		Payload:       payload,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}

	cases := map[string]func(*gateway.Response){
		"digest mismatch":       func(r *gateway.Response) { r.Digest = gateway.Digest([]byte("other")) },
		"missing retrieved_at":  func(r *gateway.Response) { r.RetrievedAt = time.Time{} },
		"unknown completeness":  func(r *gateway.Response) { r.Completeness = "probably" },
		"unknown status":        func(r *gateway.Response) { r.Status = "maybe" },
		"unavailable with body": func(r *gateway.Response) { r.Status = gateway.StatusUnavailable },
		"unavailable not marked": func(r *gateway.Response) {
			r.Status = gateway.StatusUnavailable
			r.Payload = nil
			r.Digest = gateway.Digest(nil)
		},
		"wrong schema version": func(r *gateway.Response) { r.SchemaVersion = "probe/v2" },
		"disallowed kind":      func(r *gateway.Response) { r.Kind = gateway.ActionKind("kubernetes.delete") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := ok
			mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("%s should be rejected", name)
			}
		})
	}
}
