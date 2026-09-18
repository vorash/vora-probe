package vora_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vorash/vora-probe/internal/vora"
)

func newClient(t *testing.T, handler http.Handler) (*vora.Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := vora.NewClient(vora.Config{BaseURL: server.URL, APIKey: "scoped-key"})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client, server
}

func requireAuth(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer scoped-key" {
		t.Errorf("authorization header = %q", got)
	}
}

// TestExecZeroExitHasNoCodeField is the regression guard for the protocol detail
// that would otherwise read as a failure: protojson omits fields holding their
// default, so a successful run arrives with no exitCode at all.
func TestExecZeroExitHasNoCodeField(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r)
		w.Header().Set("Content-Type", "application/x-ndjson")
		// Note: {"exit":{"reason":"EXITED"}} — exactly what the real service sends.
		fmt.Fprint(w, `{"stdout":"`+base64.StdEncoding.EncodeToString([]byte("done\n"))+`"}`+"\n")
		fmt.Fprint(w, `{"exit":{"reason":"EXITED"}}`+"\n")
	}))

	result, err := client.Exec(context.Background(), "sbx_1", vora.ExecRequest{Command: "true"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.Exit == nil {
		t.Fatal("an exit chunk arrived, so Exit must not be nil")
	}
	if result.Exit.Code != 0 {
		t.Fatalf("exit code = %d, want 0", result.Exit.Code)
	}
	if !result.Succeeded() {
		t.Fatal("a zero exit reported without an exitCode field is a success")
	}
	if string(result.Stdout) != "done\n" {
		t.Fatalf("stdout = %q", result.Stdout)
	}
}

// TestExecMissingExitIsInterrupted is the other half: a stream that ends with no
// exit chunk is an interruption, and must never be read as success.
func TestExecMissingExitIsInterrupted(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprint(w, `{"stdout":"`+base64.StdEncoding.EncodeToString([]byte("partial"))+`"}`+"\n")
	}))

	result, err := client.Exec(context.Background(), "sbx_1", vora.ExecRequest{Command: "true"})
	if err != nil {
		t.Fatalf("a stream without an exit is not a transport error: %v", err)
	}
	if result.Exit != nil {
		t.Fatalf("no exit chunk arrived, so Exit must be nil, got %+v", result.Exit)
	}
	if result.Succeeded() {
		t.Fatal("an interrupted execution must never report success")
	}
	if !strings.Contains(result.String(), "interrupted") {
		t.Fatalf("String should say interrupted, got %q", result.String())
	}
	if string(result.Stdout) != "partial" {
		t.Fatalf("output before the interruption should be kept, got %q", result.Stdout)
	}
}

func TestExecNonZeroExitAndSeparateStreams(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := base64.StdEncoding.EncodeToString([]byte("OUT\n"))
		errOut := base64.StdEncoding.EncodeToString([]byte("ERR\n"))
		fmt.Fprint(w, `{"stdout":"`+out+`"}`+"\n")
		fmt.Fprint(w, `{"stderr":"`+errOut+`"}`+"\n")
		fmt.Fprint(w, `{"exit":{"exitCode":7,"reason":"EXITED"}}`+"\n")
	}))

	result, err := client.Exec(context.Background(), "sbx_1", vora.ExecRequest{Command: "sh"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if result.Exit == nil || result.Exit.Code != 7 {
		t.Fatalf("exit = %+v, want code 7", result.Exit)
	}
	if result.Succeeded() {
		t.Fatal("a non-zero exit is not a success")
	}
	if string(result.Stdout) != "OUT\n" || string(result.Stderr) != "ERR\n" {
		t.Fatalf("streams not separated: stdout=%q stderr=%q", result.Stdout, result.Stderr)
	}
}

func TestExecCarriesTheEnvelopeOnStdin(t *testing.T) {
	envelope := []byte(`{"schema_version":"probe/v1","state":{"step":3}}`)
	var seen map[string]any
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Errorf("decode request: %v", err)
		}
		fmt.Fprint(w, `{"exit":{"reason":"EXITED"}}`+"\n")
	}))

	if _, err := client.Exec(context.Background(), "sbx_1", vora.ExecRequest{
		Command: "sh", Args: []string{"-c", "cat"}, Cwd: "/", Stdin: envelope, TimeoutSeconds: 30,
	}); err != nil {
		t.Fatalf("exec: %v", err)
	}
	encoded, _ := seen["stdin"].(string)
	decoded, err := vora.DecodeBytes(encoded)
	if err != nil {
		t.Fatalf("decode stdin: %v", err)
	}
	if string(decoded) != string(envelope) {
		t.Fatalf("envelope round-trip failed: %q", decoded)
	}
	// 64-bit fields travel as strings in protojson.
	if got, ok := seen["timeoutSeconds"].(string); !ok || got != "30" {
		t.Fatalf("timeoutSeconds = %#v, want the string \"30\"", seen["timeoutSeconds"])
	}
}

func TestCreateSandboxSendsOnlyWhatProbeSets(t *testing.T) {
	var spec map[string]any
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/sandboxes" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			t.Errorf("decode: %v", err)
		}
		fmt.Fprint(w, `{"id":"sbx_abc","spec":{"image":"img"}}`)
	}))

	sandbox, err := client.CreateSandbox(context.Background(), vora.SandboxSpec{
		TenantID: "probe",
		Image:    "ghcr.io/vorash/vora-python@sha256:deadbeef",
		Network:  &vora.NetworkPolicy{Mode: vora.NetworkNone},
		Resources: &vora.ResourceLimits{
			CPUMillis: 1000, MemoryBytes: 512 << 20, PIDs: 64,
		},
		TTLSeconds: 600,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if sandbox.ID != "sbx_abc" {
		t.Fatalf("id = %q", sandbox.ID)
	}
	if ok, _ := spec["network"].(map[string]any)["mode"].(string); ok != vora.NetworkNone {
		t.Fatalf("network mode = %#v, want %s", spec["network"], vora.NetworkNone)
	}
	resources, _ := spec["resources"].(map[string]any)
	if resources["memoryBytes"] != "536870912" {
		t.Fatalf("memoryBytes = %#v, want the string \"536870912\"", resources["memoryBytes"])
	}
	if spec["ttlSeconds"] != "600" {
		t.Fatalf("ttlSeconds = %#v, want the string \"600\"", spec["ttlSeconds"])
	}
	// Nothing Probe did not ask for should be present.
	for _, forbidden := range []string{"brokerAliases", "allowedDomains"} {
		if _, ok := spec["network"].(map[string]any)[forbidden]; ok {
			t.Errorf("spec carries %s, which Probe never sets", forbidden)
		}
	}
}

func TestDestroyIsIdempotent(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}))
	if err := client.DestroySandbox(context.Background(), "sbx_gone"); err != nil {
		t.Fatalf("destroying an already-absent sandbox should not fail the caller: %v", err)
	}
}

func TestCreateSurfacesHTTPFailure(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid or missing API key"}`, http.StatusUnauthorized)
	}))
	_, err := client.CreateSandbox(context.Background(), vora.SandboxSpec{Image: "img"})
	if err == nil {
		t.Fatal("a 401 must be an error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should carry the status, got %v", err)
	}
}

func TestCreateRefusesAnEmptyID(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"spec":{"image":"img"}}`)
	}))
	if _, err := client.CreateSandbox(context.Background(), vora.SandboxSpec{Image: "img"}); err == nil {
		t.Fatal("a sandbox with no id cannot be used and must not be returned")
	}
}

func TestClientRequiresCredentials(t *testing.T) {
	if _, err := vora.NewClient(vora.Config{BaseURL: "https://example.invalid"}); err == nil {
		t.Fatal("a client with no key must not be constructed")
	}
	if _, err := vora.NewClient(vora.Config{APIKey: "k"}); err == nil {
		t.Fatal("a client with no base URL must not be constructed")
	}
}

func TestExecSurfacesStreamFailure(t *testing.T) {
	client, _ := newClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprint(w, `{"stdout":"bm90IGpzb24gYWZ0ZXIgdGhpcyBoZWFkZXI="}`+"\n")
		fmt.Fprint(w, "this is not json\n")
	}))
	result, err := client.Exec(context.Background(), "sbx_1", vora.ExecRequest{Command: "cat"})
	if err == nil {
		t.Fatal("a malformed chunk must be reported")
	}
	if result.Exit != nil {
		t.Fatal("a malformed stream must not be treated as a completed execution")
	}
}
