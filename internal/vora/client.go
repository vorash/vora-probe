// Package vora is Probe's client for Vora's public API.
//
// It is deliberately narrow: the four routes Probe needs, typed, against the
// deployed service. It does not import Vora's module — that would couple the two
// release cadences, which the two-repository split exists to avoid — so the wire
// types here mirror the proto field names and protojson's conventions (camelCase
// fields, 64-bit integers as strings, bytes as base64).
//
// The only subtle part of this package is exit handling, and it is subtle enough
// to be worth stating up front: protojson omits fields holding their default
// value, so a *successful* execution arrives as `{"exit":{"reason":"EXITED"}}`
// with no `exitCode` at all. An execution whose exit chunk never arrives is a
// different thing — the run was interrupted — and must never be read as success.
// Exit is therefore a pointer, and nil means interrupted.
package vora

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxResponseBytes bounds one answer. Vora's own limit is larger; this is
// the client refusing to buffer without a bound.
const DefaultMaxResponseBytes = 2 << 20

type Config struct {
	// BaseURL is the vora-api base URL, for example https://vora-mini.example.ts.net:9300.
	BaseURL string
	// APIKey is a scoped key. Probe's is sandbox-scoped and tenant-bound, so it
	// cannot reach the admin routes even if it tried.
	APIKey  string
	Timeout time.Duration
	Client  *http.Client
	// MaxResponseBytes bounds a single non-streaming response.
	MaxResponseBytes int64
}

func (c Config) validate() error {
	if strings.TrimSpace(c.BaseURL) == "" {
		return fmt.Errorf("vora: BaseURL is required")
	}
	if strings.TrimSpace(c.APIKey) == "" {
		return fmt.Errorf("vora: APIKey is required")
	}
	return nil
}

// Client talks to vora-api over HTTP.
type Client struct {
	cfg  Config
	http *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		client = &http.Client{
			Timeout: timeout,
			// A redirect would be an unapproved destination.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return fmt.Errorf("vora: redirects are refused")
			},
		}
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	return &Client{cfg: cfg, http: client}, nil
}

// SandboxSpec is the subset of v1.SandboxSpec Probe sets. Everything omitted
// stays at the server's default, which is the point: Probe does not get to widen
// a sandbox's resources or network by accident.
type SandboxSpec struct {
	TenantID   string          `json:"tenantId,omitempty"`
	Image      string          `json:"image"`
	Backend    string          `json:"backend,omitempty"`
	Env        []string        `json:"env,omitempty"`
	Resources  *ResourceLimits `json:"resources,omitempty"`
	Network    *NetworkPolicy  `json:"network,omitempty"`
	TTLSeconds int64           `json:"ttlSeconds,omitempty,string"`
}

type ResourceLimits struct {
	CPUMillis   int64 `json:"cpuMillis,omitempty,string"`
	MemoryBytes int64 `json:"memoryBytes,omitempty,string"`
	PIDs        int64 `json:"pids,omitempty,string"`
}

type NetworkPolicy struct {
	// Mode is a v1.NetworkMode name. Probe only ever asks for NETWORK_NONE.
	Mode string `json:"mode"`
}

// NetworkNone is the only mode Probe uses. A worker that needs no network cannot
// exfiltrate anything, so the capability is removed rather than policed.
const NetworkNone = "NETWORK_NONE"

type Sandbox struct {
	ID   string      `json:"id"`
	Spec SandboxSpec `json:"spec"`
}

// ExecRequest is the subset of v1.ExecRequest Probe sets.
type ExecRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	Env     []string `json:"env,omitempty"`
	// Stdin is the bounded step envelope. It rides in the request as base64,
	// which is how protojson carries bytes.
	Stdin          []byte `json:"-"`
	TimeoutSeconds int64  `json:"timeoutSeconds,omitempty,string"`
}

// Exit is how an execution finished. Code is only meaningful when the exit chunk
// arrived, which is why ExecResult holds a pointer to it.
type Exit struct {
	Code   int32  `json:"exitCode"`
	Reason string `json:"reason"`
}

// ExecResult is the collected output of one execution.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	// Exit is nil when no exit chunk arrived. That is an interruption, not a
	// success: the plan requires that a missing exit be treated as interrupted,
	// and this type makes the distinction impossible to overlook.
	Exit *Exit
}

// Succeeded reports a clean, zero exit. An interrupted execution is not a success
// even though it produced no error status of its own.
func (r ExecResult) Succeeded() bool { return r.Exit != nil && r.Exit.Code == 0 }

func (r ExecResult) String() string {
	if r.Exit == nil {
		return "interrupted (no exit was reported)"
	}
	return fmt.Sprintf("exit %d (%s)", r.Exit.Code, r.Exit.Reason)
}

func (c *Client) CreateSandbox(ctx context.Context, spec SandboxSpec) (Sandbox, error) {
	body, err := json.Marshal(spec)
	if err != nil {
		return Sandbox{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/sandboxes", body)
	if err != nil {
		return Sandbox{}, err
	}
	defer resp.Body.Close()
	raw, err := c.readBounded(resp)
	if err != nil {
		return Sandbox{}, err
	}
	if err := statusError("create sandbox", resp.StatusCode, raw); err != nil {
		return Sandbox{}, err
	}
	var sandbox Sandbox
	if err := json.Unmarshal(raw, &sandbox); err != nil {
		return Sandbox{}, fmt.Errorf("vora: create sandbox response: %w", err)
	}
	if sandbox.ID == "" {
		return Sandbox{}, fmt.Errorf("vora: create sandbox returned no id: %s", snippet(raw))
	}
	return sandbox, nil
}

func (c *Client) DestroySandbox(ctx context.Context, id string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/v1/sandboxes/"+id, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := c.readBounded(resp)
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return statusError("destroy sandbox", resp.StatusCode, raw)
}

// Exec runs one command and collects its output.
//
// A stream that ends without an exit chunk yields a nil Exit and no error: the
// call itself worked, and the execution's fate is reported rather than thrown.
// Conflating the two would let an interrupted run look like a clean one.
func (c *Client) Exec(ctx context.Context, id string, req ExecRequest) (ExecResult, error) {
	body, err := json.Marshal(execRequestWire{
		Command:        req.Command,
		Args:           req.Args,
		Cwd:            req.Cwd,
		Env:            req.Env,
		Stdin:          encodeBytes(req.Stdin),
		TimeoutSeconds: req.TimeoutSeconds,
	})
	if err != nil {
		return ExecResult{}, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/v1/sandboxes/"+id+"/exec", body)
	if err != nil {
		return ExecResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := c.readBounded(resp)
		return ExecResult{}, statusError("exec", resp.StatusCode, raw)
	}

	var result ExecResult
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), int(c.cfg.MaxResponseBytes))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var chunk execChunkWire
		if err := json.Unmarshal(line, &chunk); err != nil {
			return result, fmt.Errorf("vora: exec stream is not valid ndjson: %w", err)
		}
		if chunk.Exit != nil {
			// The chunk's presence is the signal. Its code defaults to zero and
			// protojson omits it, so it must not be inferred from the field.
			result.Exit = &Exit{Code: chunk.Exit.Code, Reason: chunk.Exit.Reason}
			continue
		}
		if len(chunk.Stdout) > 0 {
			result.Stdout = append(result.Stdout, chunk.Stdout...)
		}
		if len(chunk.Stderr) > 0 {
			result.Stderr = append(result.Stderr, chunk.Stderr...)
		}
	}
	if err := scanner.Err(); err != nil {
		// A truncated stream leaves Exit nil, which reads as interrupted.
		return result, fmt.Errorf("vora: exec stream ended early: %w", err)
	}
	return result, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

func (c *Client) readBounded(resp *http.Response) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > c.cfg.MaxResponseBytes {
		return nil, fmt.Errorf("vora: response exceeds the %d byte limit", c.cfg.MaxResponseBytes)
	}
	return raw, nil
}

// execRequestWire mirrors v1.ExecRequest on the wire.
type execRequestWire struct {
	Command        string   `json:"command"`
	Args           []string `json:"args,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	Env            []string `json:"env,omitempty"`
	Stdin          string   `json:"stdin,omitempty"`
	TimeoutSeconds int64    `json:"timeoutSeconds,omitempty,string"`
}

// execChunkWire mirrors v1.ExecChunk. Its fields are a oneof on the wire but flat
// in JSON, so presence is what distinguishes them.
type execChunkWire struct {
	Stdout []byte    `json:"stdout,omitempty"`
	Stderr []byte    `json:"stderr,omitempty"`
	Exit   *exitWire `json:"exit,omitempty"`
}

type exitWire struct {
	Code   int32  `json:"exitCode,omitempty"`
	Reason string `json:"reason,omitempty"`
}

func encodeBytes(in []byte) string {
	if len(in) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(in)
}

// DecodeBytes is the counterpart for callers that need to decode protojson bytes.
func DecodeBytes(in string) ([]byte, error) {
	if in == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(in)
}

func statusError(what string, status int, raw []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("vora: %s returned %d: %s", what, status, snippet(raw))
}

func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// ParseTTL is a small helper so callers do not have to remember that the wire
// format is a string.
func ParseTTL(seconds int64) string { return strconv.FormatInt(seconds, 10) }
