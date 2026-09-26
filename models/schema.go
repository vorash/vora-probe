package models

import (
	"net/url"
	"strings"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// PlannerResponseSchema is the planner reply as a strict JSON Schema, built from
// the same closed sets the engine enforces, so the provider refuses to produce
// a reply the engine would reject: an unknown claim kind, a missing field, an
// action outside the allowlist.
//
// Strict mode needs every property required and no others allowed, so a field
// an action kind does not use is present as null rather than omitted. The
// engine's own validation still runs on every reply: the schema narrows what
// can arrive, it does not replace the contract.
func PlannerResponseSchema() map[string]any {
	str := map[string]any{"type": "string"}
	nullable := func(s map[string]any) map[string]any {
		return map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
	}
	object := func(props map[string]any) map[string]any {
		required := make([]string, 0, len(props))
		for _, name := range sortedKeys(props) {
			required = append(required, name)
		}
		return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	}
	enum := func(values []string) map[string]any { return map[string]any{"type": "string", "enum": values} }

	var domains, kinds, actions []string
	for _, d := range investigation.AllFaultDomains {
		domains = append(domains, string(d))
	}
	for _, k := range investigation.AllClaimKinds {
		kinds = append(kinds, string(k))
	}
	for _, a := range gateway.AllowedActions {
		actions = append(actions, string(a))
	}
	hypothesis := object(map[string]any{
		"statement":       str,
		"fault_domain":    enum(domains),
		"claim_kind":      enum(kinds),
		"evidence_needed": map[string]any{"type": "array", "items": str},
	})
	action := object(map[string]any{
		"kind":       enum(actions),
		"entity":     str,
		"reason":     str,
		"metric":     nullable(enum(gateway.AllowedMetrics)),
		"window":     nullable(object(map[string]any{"start": str, "end": str})),
		"resolution": nullable(str),
	})
	return object(map[string]any{
		"hypotheses":  map[string]any{"type": "array", "items": hypothesis},
		"next_action": nullable(action),
		"reason":      str,
	})
}

// requiresParameterPinning reports whether the endpoint is OpenRouter, which
// silently drops a request parameter a provider does not support unless it is
// told to route only to providers that do. Without that, a strict schema could
// quietly become free text. Other endpoints reject the routing field, so it is
// sent to OpenRouter alone.
func requiresParameterPinning(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	return host == "openrouter.ai" || strings.HasSuffix(host, ".openrouter.ai")
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
