//go:build integration

// The live controller leg, validated against a real vora-api and the released
// worker image. It is excluded from `make check` because it needs a live control
// plane and a scoped key:
//
//	ssh -N -L 9300:127.0.0.1:9300 mini-vora &
//	VORA_API_BASE_URL=http://127.0.0.1:9300 \
//	VORA_API_KEY="$(cat ~/.config/vora-probe/api-key)" \
//	go test -tags=integration ./internal/probe/ -run TestLiveInvestigation -v
//
// The run creates and destroys its own sandbox. What only a live cluster can
// prove is that stdin really arrives, that a zero exit really comes back with no
// exitCode field, and that the controller's artifacts outlive the sandbox.
package probe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/internal/vora"
	"github.com/vorash/vora-probe/investigation"
)

// defaultWorkerImage is the released worker image, by digest. A tag would make the
// run unreproducible, which is the opposite of what a live validation is for.
const defaultWorkerImage = "ghcr.io/vorash/vora-probe-worker@sha256:e33a918863c6e340b67872907c2e92f49bb0a03f73544c4e60bdbf0ab142e38a"

func liveClient(t *testing.T) *vora.Client {
	t.Helper()
	base := os.Getenv("VORA_API_BASE_URL")
	key := os.Getenv("VORA_API_KEY")
	if base == "" || key == "" {
		t.Skip("set VORA_API_BASE_URL and VORA_API_KEY to run the live investigation")
	}
	client, err := vora.NewClient(vora.Config{BaseURL: base, APIKey: key, Timeout: 120 * time.Second})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client
}

func TestLiveInvestigation(t *testing.T) {
	client := liveClient(t)
	image := os.Getenv("VORA_PROBE_WORKER_IMAGE")
	if image == "" {
		image = defaultWorkerImage
	}
	// The worker image is distroless and has no shell on purpose, but vora's
	// gVisor backend starts every sandbox with `/bin/sh -c 'sleep 86400'`
	// (internal/runtime/gvisor/bundle.go), which such an image cannot satisfy.
	// bwrap does not need a shell, so a distroless worker must name it.
	backend := os.Getenv("VORA_PROBE_WORKER_BACKEND")
	if backend == "" {
		backend = "bwrap"
	}
	dir := filepath.Join(fixtures.Root(), "oom", "oom-positive")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	live, err := Investigate(ctx, LiveOptions{
		Client:    client,
		BundleDir: dir,
		OutDir:    t.TempDir(),
		Image:     image,
		Backend:   backend,
	})
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}
	if !live.SandboxDestroyed {
		t.Fatal("the live sandbox was not destroyed")
	}
	if live.Report.Run.Status != investigation.RunCompleted {
		t.Fatalf("run status = %q, want completed (%s)", live.Report.Run.Status, live.Report.Run.Reason)
	}
	t.Logf("sandbox %s ran %d steps over the sandbox boundary", live.SandboxID, live.Steps)

	// A live run must reach the same verdict as the offline replay. Only the
	// worker's location changed, so the substance may not.
	replay, err := Replay(ctx, ReplayOptions{BundleDir: dir, OutDir: t.TempDir()})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if live.Report.Leading == nil || replay.Report.Leading == nil {
		t.Fatal("both runs must state a leading finding")
	}
	if live.Report.Leading.Kind != replay.Report.Leading.Kind {
		t.Fatalf("live leading claim %q != replay %q", live.Report.Leading.Kind, replay.Report.Leading.Kind)
	}
	if a, b := claimVerdicts(live.Report), claimVerdicts(replay.Report); !equalVerdicts(a, b) {
		t.Fatalf("live and replay disagree on the claims: live=%v replay=%v", a, b)
	}

	// The controller's artifacts are durable: they are written to controller-owned
	// storage and outlive the sandbox that produced them.
	if _, err := os.Stat(live.ReportJSONPath); err != nil {
		t.Fatalf("report.json did not survive the sandbox: %v", err)
	}

	events := readJournal(t, live.JournalPath)
	if events[0].Kind != store.EventRunStarted {
		t.Fatalf("journal must open with run_started, got %q", events[0].Kind)
	}
	created, destroyed := -1, -1
	for i, e := range events {
		if e.Kind != store.EventSandbox {
			continue
		}
		var payload sandboxEvent
		if err := json.Unmarshal(e.Payload, &payload); err != nil {
			t.Fatalf("sandbox event %d: %v", i, err)
		}
		switch payload.Phase {
		case "created":
			created = i
			if payload.Network != vora.NetworkNone {
				t.Errorf("the live sandbox was not network-denied: %q", payload.Network)
			}
		case "destroyed":
			destroyed = i
		}
	}
	if created < 0 || destroyed < 0 {
		t.Fatalf("the sandbox's life was not journaled: created=%d destroyed=%d", created, destroyed)
	}
}
