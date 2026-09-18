//go:build integration

// Integration test against a real vora-api. It is excluded from `make check`
// because it needs a live control plane and a scoped key:
//
//	ssh -N -L 9300:127.0.0.1:9300 mini-vora &
//	VORA_API_BASE_URL=http://127.0.0.1:9300 \
//	VORA_API_KEY="$(cat ~/.config/vora-probe/api-key)" \
//	go test -tags=integration ./internal/vora/ -v
//
// It creates and destroys its own sandbox, and asserts the two things the unit
// tests can only imitate: that stdin really arrives, and that a zero exit really
// arrives with no exitCode field.
package vora_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/vora"
)

// voraPythonImage is the digest-pinned image the mini-PC already holds.
const voraPythonImage = "ghcr.io/vorash/vora-python@sha256:c906b8becc5a3517beca5c48d8a6982c0ee91f19b992770975719408a8164139"

func liveClient(t *testing.T) *vora.Client {
	t.Helper()
	base := os.Getenv("VORA_API_BASE_URL")
	key := os.Getenv("VORA_API_KEY")
	if base == "" || key == "" {
		t.Skip("set VORA_API_BASE_URL and VORA_API_KEY to run the integration suite")
	}
	client, err := vora.NewClient(vora.Config{BaseURL: base, APIKey: key, Timeout: 60 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestLiveSandboxLifecycleAndStdin(t *testing.T) {
	client := liveClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sandbox, err := client.CreateSandbox(ctx, vora.SandboxSpec{
		TenantID: "probe",
		Image:    voraPythonImage,
		Network:  &vora.NetworkPolicy{Mode: vora.NetworkNone},
		Resources: &vora.ResourceLimits{
			CPUMillis: 1000, MemoryBytes: 512 << 20, PIDs: 64,
		},
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("created %s", sandbox.ID)
	t.Cleanup(func() {
		destroyCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := client.DestroySandbox(destroyCtx, sandbox.ID); err != nil {
			t.Errorf("destroy %s: %v", sandbox.ID, err)
		} else {
			t.Logf("destroyed %s", sandbox.ID)
		}
	})

	envelope := `{"schema_version":"probe/v1","state":{"step":3}}`

	t.Run("stdin arrives byte for byte", func(t *testing.T) {
		result, err := client.Exec(ctx, sandbox.ID, vora.ExecRequest{
			Command: "cat", Cwd: "/", Stdin: []byte(envelope), TimeoutSeconds: 30,
		})
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if !result.Succeeded() {
			t.Fatalf("cat should succeed, got %s (stderr=%s)", result, result.Stderr)
		}
		if string(result.Stdout) != envelope {
			t.Fatalf("stdin did not round-trip:\n want %q\n got  %q", envelope, result.Stdout)
		}
	})

	t.Run("zero exit arrives with no exitCode field", func(t *testing.T) {
		result, err := client.Exec(ctx, sandbox.ID, vora.ExecRequest{Command: "true", Cwd: "/", TimeoutSeconds: 30})
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if result.Exit == nil {
			t.Fatal("a real zero exit must still produce an Exit, not an interruption")
		}
		if result.Exit.Code != 0 || !result.Succeeded() {
			t.Fatalf("exit = %+v, want a successful zero exit", result.Exit)
		}
		t.Logf("exit reason as reported by the service: %q", result.Exit.Reason)
	})

	t.Run("non-zero exit and separate streams", func(t *testing.T) {
		result, err := client.Exec(ctx, sandbox.ID, vora.ExecRequest{
			Command: "sh", Args: []string{"-c", "echo OUT; echo ERR >&2; exit 7"}, Cwd: "/", TimeoutSeconds: 30,
		})
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if result.Exit == nil || result.Exit.Code != 7 {
			t.Fatalf("exit = %+v, want 7", result.Exit)
		}
		if string(result.Stdout) != "OUT\n" || string(result.Stderr) != "ERR\n" {
			t.Fatalf("streams not separated: stdout=%q stderr=%q", result.Stdout, result.Stderr)
		}
	})

	t.Run("network is denied", func(t *testing.T) {
		result, err := client.Exec(ctx, sandbox.ID, vora.ExecRequest{
			Command: "sh", Args: []string{"-c", "getent hosts github.com || echo no-dns"}, Cwd: "/", TimeoutSeconds: 30,
		})
		if err != nil {
			t.Fatalf("exec: %v", err)
		}
		if string(result.Stdout) != "no-dns\n" {
			t.Fatalf("NetworkNone should deny DNS, got %q", result.Stdout)
		}
	})
}
