package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Transport is the seam every arm uses, so tests can exercise an arm without a
// network and without a credential.
type Transport interface {
	Do(ctx context.Context, method, url string, headers map[string]string, body []byte, maxResponseBytes int64) (status int, response []byte, err error)
}

// HTTPTransport is the real transport. It refuses redirects, because a redirect
// is an unrequested destination that policy never approved.
type HTTPTransport struct {
	Client *http.Client
}

func NewHTTPTransport(timeout time.Duration) *HTTPTransport {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &HTTPTransport{Client: &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are refused: the destination was not approved by policy")
		},
	}}
}

func (t *HTTPTransport) Do(ctx context.Context, method, url string, headers map[string]string, body []byte, maxResponseBytes int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := t.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	limit := maxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	// A response over the limit is refused rather than truncated: a partially
	// read label is worse than no label.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if int64(len(raw)) > limit {
		return resp.StatusCode, nil, fmt.Errorf("response exceeds the %d byte limit", limit)
	}
	return resp.StatusCode, raw, nil
}

// decodeStrict unmarshals into a typed value, rejecting unknown fields so that a
// provider changing its response shape is a loud failure rather than a silently
// zero-valued label.
func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("response does not match the expected schema: %w", err)
	}
	return nil
}

func snippet(raw []byte, max int) string {
	s := strings.TrimSpace(string(raw))
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
