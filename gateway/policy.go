package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Tool output is untrusted. It can carry credentials, kubeconfigs and text
// written to look like instructions to a model. Redaction is applied before
// anything is persisted or sent to a model, and the fact that it happened is
// recorded rather than hidden.
var secretPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)(authorization:\s*(?:bearer|basic)\s+)\S+`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)("?(?:password|passwd|token|api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?key)"?\s*[:=]\s*)("[^"]*"|[^\s,;}]+)`), "${1}[REDACTED]"},
	{regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----)`), "${1}[REDACTED]${2}"},
	{regexp.MustCompile(`(?i)((?:client-key-data|client-certificate-data|kubeconfig)\s*[:=]\s*)\S+`), "${1}[REDACTED]"},
}

// RedactText replaces secret-bearing spans. It reports whether anything
// changed, so the caller can mark the evidence as redacted rather than
// pretending it is untouched.
func RedactText(s string) (string, bool) {
	out := s
	for _, p := range secretPatterns {
		out = p.re.ReplaceAllString(out, p.replacement)
	}
	return out, out != s
}

// secretKey matches the names of fields whose whole value is a secret.
var secretKey = regexp.MustCompile(`(?i)^(password|passwd|token|api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?key|kubeconfig|client-key-data|client-certificate-data)$`)

// RedactRaw redacts a JSON payload. It works on the decoded structure, so a
// secret at the end of a string value, as in a log line ending "password=x",
// is redacted without breaking the JSON around it. Redacting the raw text
// would eat the closing quote, and the whole payload would be lost. A payload
// that is not JSON falls back to text redaction, and is dropped if that cannot
// keep it valid.
func RedactRaw(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err == nil && !dec.More() {
		redacted, changed := redactValue(v, "")
		if !changed {
			return raw, false
		}
		out, err := json.Marshal(redacted)
		if err != nil {
			return nil, true
		}
		return out, true
	}
	text, changed := RedactText(string(raw))
	if !changed {
		return raw, false
	}
	if !json.Valid([]byte(text)) {
		// A payload we cannot keep valid is dropped rather than persisted in a
		// form that no longer parses.
		return nil, true
	}
	return json.RawMessage(text), true
}

// redactValue redacts every string in a decoded JSON value. A value under a
// secret-bearing key is replaced whole, whatever it looks like.
func redactValue(v any, key string) (any, bool) {
	switch t := v.(type) {
	case string:
		if key != "" && secretKey.MatchString(key) {
			return "[REDACTED]", t != "[REDACTED]"
		}
		return RedactText(t)
	case map[string]any:
		changed := false
		for k, child := range t {
			if r, did := redactValue(child, k); did {
				t[k], changed = r, true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, child := range t {
			if r, did := redactValue(child, key); did {
				t[i], changed = r, true
			}
		}
		return t, changed
	default:
		return v, false
	}
}

// RedactResponse redacts the parts of an answer that reach storage and models.
// The digest is deliberately left as the digest of the original payload: it
// identifies the evidence as retrieved, and Completeness records that what is
// retained is a redacted form.
func RedactResponse(r Response) Response {
	changed := false
	if payload, did := RedactRaw(r.Payload); did {
		r.Payload = payload
		changed = true
	}
	if query, did := RedactText(r.Query.Query); did {
		r.Query.Query = query
		changed = true
	}
	if reason, did := RedactText(r.Reason); did {
		r.Reason = reason
		changed = true
	}
	for k, v := range r.Query.Params {
		if redacted, did := RedactText(v); did {
			r.Query.Params[k] = redacted
			changed = true
		}
	}
	if changed && r.Completeness == Complete {
		r.Completeness = Redacted
	}
	return r
}

// Policy authorizes requests and bounds what comes back. It is the only place
// that decides whether Probe may talk to something, and it applies its own
// checks on top of the contract's structural validation so that withdrawing a
// permission never depends on the contract changing.
type Policy struct {
	// MaxResponseBytes caps a single answer. A larger answer is refused rather
	// than truncated silently.
	MaxResponseBytes int64
	// DeniedKinds withdraws an action that the contract still allows.
	DeniedKinds []ActionKind
	// AllowedEntities scopes requests to particular services. Empty means any.
	AllowedEntities []string
}

func DefaultPolicy() Policy { return Policy{MaxResponseBytes: 2 << 20} }

// Authorize applies the allowlist, the deny list and the entity scope.
// Everything absent from AllowedActions and AllowedMetrics is denied, whatever
// asked for it.
func (p Policy) Authorize(a Action) error {
	if err := a.Validate(); err != nil {
		return &Denied{Reason: err.Error()}
	}
	for _, denied := range p.DeniedKinds {
		if denied == a.Kind {
			return &Denied{Reason: fmt.Sprintf("action %q is withdrawn by policy", a.Kind)}
		}
	}
	if len(p.AllowedEntities) > 0 {
		allowed := false
		for _, entity := range p.AllowedEntities {
			if entity == a.Entity {
				allowed = true
				break
			}
		}
		if !allowed {
			return &Denied{Reason: fmt.Sprintf("entity %q is outside the investigated scope", a.Entity)}
		}
	}
	return nil
}

// Accept checks that an answer corresponds to the request that produced it,
// validates it, and enforces the response size bound.
func (p Policy) Accept(a Action, r Response, encodedSize int64) error {
	if err := p.Authorize(a); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("response for %s: %w", a, err)
	}
	if r.Kind != a.Kind {
		return fmt.Errorf("response kind %q does not match request kind %q", r.Kind, a.Kind)
	}
	if r.Entity != a.Entity {
		return fmt.Errorf("response entity %q does not match request entity %q", r.Entity, a.Entity)
	}
	if encodedSize > p.MaxResponseBytes {
		return fmt.Errorf("response of %d bytes exceeds the %d byte limit", encodedSize, p.MaxResponseBytes)
	}
	return nil
}

// Denied is the error returned when a request is refused by policy. It is
// distinguishable from a transport failure because the two are reported
// differently: a denial is an attempted policy violation, a failure is bad luck.
type Denied struct {
	Reason string
}

func (d *Denied) Error() string {
	return "denied by policy: " + strings.TrimSpace(d.Reason)
}

func IsDenied(err error) bool {
	var d *Denied
	return errors.As(err, &d)
}
