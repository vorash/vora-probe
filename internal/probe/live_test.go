package probe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/internal/vora"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/worker"
)

func defaultEngine() *investigation.Engine {
	return &investigation.Engine{Policy: gateway.DefaultPolicy(), Claims: investigation.DefaultClaimPolicy()}
}

// stdoutChunk / exitChunk build the NDJSON the exec route streams. They return
// strings rather than errors because a map of strings cannot fail to marshal, and
// they are called from the fake service's handler goroutine where a testing.T
// would be unsafe.
func stdoutChunk(s string) string {
	raw, _ := json.Marshal(map[string]string{"stdout": base64.StdEncoding.EncodeToString([]byte(s))})
	return string(raw)
}

func stderrChunk(s string) string {
	raw, _ := json.Marshal(map[string]string{"stderr": base64.StdEncoding.EncodeToString([]byte(s))})
	return string(raw)
}

// exitChunk omits exitCode for a zero exit, exactly as protojson does. This is the
// quirk the exit-presence design exists for.
func exitChunk(code int, reason string) string {
	exit := map[string]any{"reason": reason}
	if code != 0 {
		exit["exitCode"] = code
	}
	raw, _ := json.Marshal(map[string]any{"exit": exit})
	return string(raw)
}

// TestOneResultLine pins the output half of the step protocol. Each rejection is
// a failure the plan names: an oversized or malformed answer must be reported,
// never trimmed into something plausible.
func TestOneResultLine(t *testing.T) {
	cases := []struct {
		name    string
		stdout  string
		max     int64
		want    string
		wantErr string
	}{
		{name: "one line", stdout: "{\"kind\":\"final\"}\n", max: 1024, want: "{\"kind\":\"final\"}"},
		{name: "blank lines around one line", stdout: "\n{\"kind\":\"final\"}\n\n", max: 1024, want: "{\"kind\":\"final\"}"},
		{name: "empty", stdout: "", max: 1024, wantErr: "no result line"},
		{name: "whitespace only", stdout: "\n  \n", max: 1024, wantErr: "no result line"},
		{name: "two lines", stdout: "{\"a\":1}\n{\"b\":2}\n", max: 1024, wantErr: "2 result lines"},
		{name: "not json", stdout: "not json\n", max: 1024, wantErr: "not valid JSON"},
		{name: "oversized", stdout: strings.Repeat("x", 33) + "\n", max: 32, wantErr: "exceeds the 32 byte step budget"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := oneResultLine([]byte(tc.stdout), tc.max)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("result = %q, want %q", got, tc.want)
			}
		})
	}
}

// execClient serves one exec call with fixed chunks, whatever they are.
func execClient(t *testing.T, chunks ...string) *vora.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sandboxes/sb-1/exec" {
			t.Errorf("unexpected request path %s", r.URL.Path)
		}
		for _, c := range chunks {
			fmt.Fprintln(w, c)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := vora.NewClient(vora.Config{BaseURL: srv.URL, APIKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestSandboxWorkerExecProtocol(t *testing.T) {
	budget := investigation.DefaultBudgets()
	result := `{"schema_version":"probe/v1","kind":"final","reason":"done"}`

	t.Run("zero exit arrives with no exitCode field", func(t *testing.T) {
		w, err := NewSandboxWorker(SandboxWorkerConfig{
			Client:    execClient(t, stdoutChunk(result), exitChunk(0, "EXITED")),
			SandboxID: "sb-1", Budgets: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		got, err := w.Step(context.Background(), []byte(`{"state":{}}`))
		if err != nil {
			t.Fatalf("step: %v", err)
		}
		if string(got) != result {
			t.Fatalf("result = %q, want %q", got, result)
		}
	})

	t.Run("missing exit is an interruption, not a success", func(t *testing.T) {
		w, err := NewSandboxWorker(SandboxWorkerConfig{
			Client: execClient(t, stdoutChunk(result)), SandboxID: "sb-1", Budgets: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Step(context.Background(), []byte(`{"state":{}}`))
		if !errors.Is(err, ErrInterrupted) {
			t.Fatalf("error = %v, want ErrInterrupted", err)
		}
	})

	t.Run("non-zero exit carries stderr", func(t *testing.T) {
		w, err := NewSandboxWorker(SandboxWorkerConfig{
			Client:    execClient(t, stderrChunk("boom\n"), exitChunk(7, "EXITED")),
			SandboxID: "sb-1", Budgets: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Step(context.Background(), []byte(`{"state":{}}`))
		if err == nil || !strings.Contains(err.Error(), "exited 7") || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("error = %v, want exit 7 and stderr", err)
		}
	})

	t.Run("multiple result lines are refused", func(t *testing.T) {
		w, err := NewSandboxWorker(SandboxWorkerConfig{
			Client:    execClient(t, stdoutChunk(result+"\n"+result), exitChunk(0, "EXITED")),
			SandboxID: "sb-1", Budgets: budget,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Step(context.Background(), []byte(`{"state":{}}`))
		if err == nil || !strings.Contains(err.Error(), "2 result lines") {
			t.Fatalf("error = %v, want a two-line refusal", err)
		}
	})

	t.Run("oversized envelope is refused before the sandbox is asked", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("an oversized envelope must never reach the sandbox")
		}))
		t.Cleanup(srv.Close)
		client, err := vora.NewClient(vora.Config{BaseURL: srv.URL, APIKey: "test"})
		if err != nil {
			t.Fatal(err)
		}
		w, err := NewSandboxWorker(SandboxWorkerConfig{
			Client: client, SandboxID: "sb-1",
			Budgets: investigation.Budgets{MaxEnvelopeBytes: 4, MaxResponseBytes: 4},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.Step(context.Background(), []byte("123456789"))
		if err == nil || !strings.Contains(err.Error(), "step budget") {
			t.Fatalf("error = %v, want a step-budget refusal", err)
		}
	})
}

// TestReplayRunsTheWorkerThroughTheInjectedRunner is what makes the port a port:
// the loop must actually call the runner it is given.
func TestReplayRunsTheWorkerThroughTheInjectedRunner(t *testing.T) {
	budget := investigation.DefaultBudgets()
	engine := defaultEngine()
	var calls int
	runner := func(ctx context.Context, input []byte) ([]byte, error) {
		calls++
		return worker.Step(engine, input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
	}
	result, err := Replay(context.Background(), ReplayOptions{
		BundleDir: filepath.Join(fixtures.Root(), "oom", "oom-positive"),
		OutDir:    t.TempDir(),
		Budget:    budget,
		Engine:    engine,
		Runner:    runner,
	})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if calls == 0 {
		t.Fatal("the injected runner was never called")
	}
	if result.Report.Run.Status != investigation.RunCompleted {
		t.Fatalf("run status = %q, want completed", result.Report.Run.Status)
	}
}

// fakeVoraAPI is the smallest service that behaves like vora-api for this leg: it
// creates a sandbox, runs the real worker protocol on stdin, and destroys the
// sandbox. It lets the whole controller be tested offline, including the parts a
// live test cannot force — a malformed answer, a missing exit.
type fakeVoraAPI struct {
	mu          sync.Mutex
	created     int
	destroyed   int
	networkMode string
	// execBody produces the NDJSON the exec route streams. Nil means run the
	// real worker, which is the faithful path.
	execBody func(input []byte) string
}

func (f *fakeVoraAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	budget := investigation.DefaultBudgets()
	engine := defaultEngine()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		var spec vora.SandboxSpec
		if err := json.NewDecoder(r.Body).Decode(&spec); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.created++
		if spec.Network != nil {
			f.networkMode = spec.Network.Mode
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "sb-1", "spec": spec})
	})
	mux.HandleFunc("/v1/sandboxes/sb-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		f.mu.Lock()
		f.destroyed++
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/v1/sandboxes/sb-1/exec", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stdin string `json:"stdin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		input, err := base64.StdEncoding.DecodeString(req.Stdin)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if f.execBody != nil {
			fmt.Fprint(w, f.execBody(input))
			return
		}
		out, err := worker.Step(engine, input, budget.MaxEnvelopeBytes, budget.MaxResponseBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, stdoutChunk(string(out)))
		fmt.Fprintln(w, exitChunk(0, "EXITED"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeVoraAPI) client(t *testing.T) *vora.Client {
	t.Helper()
	client, err := vora.NewClient(vora.Config{BaseURL: f.server(t).URL, APIKey: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func (f *fakeVoraAPI) counts() (created, destroyed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.created, f.destroyed
}

func readJournal(t *testing.T, path string) []store.Event {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	var events []store.Event
	for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e store.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal line %d: %v", i, err)
		}
		events = append(events, e)
	}
	return events
}

const fakeWorkerImage = "example.invalid/vora-probe-worker@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func liveOptions(t *testing.T, fake *fakeVoraAPI, out string) LiveOptions {
	t.Helper()
	return LiveOptions{
		Client:    fake.client(t),
		BundleDir: filepath.Join(fixtures.Root(), "oom", "oom-positive"),
		OutDir:    out,
		Image:     fakeWorkerImage,
		Engine:    defaultEngine(),
	}
}

// TestInvestigateThroughAFakeSandbox runs the whole controller leg offline. The
// fake service creates a sandbox, streams the real worker's output on stdin, and
// is destroyed; the run must reproduce the replay verdict, journal the sandbox's
// whole life inside the run bracket, and leave durable artifacts behind.
func TestInvestigateThroughAFakeSandbox(t *testing.T) {
	dir := filepath.Join(fixtures.Root(), "oom", "oom-positive")
	fake := &fakeVoraAPI{}
	live, err := Investigate(context.Background(), liveOptions(t, fake, t.TempDir()))
	if err != nil {
		t.Fatalf("investigate: %v", err)
	}

	if !live.SandboxDestroyed {
		t.Fatal("the sandbox was not destroyed")
	}
	if live.SandboxID != "sb-1" {
		t.Fatalf("sandbox id = %q, want sb-1", live.SandboxID)
	}
	created, destroyed := fake.counts()
	if created != 1 || destroyed != 1 {
		t.Fatalf("create/destroy = %d/%d, want 1/1", created, destroyed)
	}
	if fake.networkMode != vora.NetworkNone {
		t.Fatalf("sandbox network = %q, want %q", fake.networkMode, vora.NetworkNone)
	}
	if live.Report.Run.Status != investigation.RunCompleted {
		t.Fatalf("run status = %q, want completed (%s)", live.Report.Run.Status, live.Report.Run.Reason)
	}

	replay, err := Replay(context.Background(), ReplayOptions{BundleDir: dir, OutDir: t.TempDir(), Engine: defaultEngine()})
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

	// The artifacts are the controller's, and they outlive the sandbox it just
	// destroyed.
	if _, err := os.Stat(live.ReportJSONPath); err != nil {
		t.Fatalf("report.json did not survive the sandbox: %v", err)
	}
	if _, err := os.Stat(live.ReportMarkdownPath); err != nil {
		t.Fatalf("report.md did not survive the sandbox: %v", err)
	}

	events := readJournal(t, live.JournalPath)
	if events[0].Kind != store.EventRunStarted {
		t.Fatalf("journal must open with run_started, got %q", events[0].Kind)
	}
	if last := events[len(events)-1]; last.Kind != store.EventRunFinished {
		t.Fatalf("journal must close with run_finished, got %q", last.Kind)
	}
	createdIdx, destroyedIdx, finishedIdx := -1, -1, -1
	for i, e := range events {
		switch e.Kind {
		case store.EventRunFinished:
			finishedIdx = i
		case store.EventSandbox:
			var payload sandboxEvent
			if err := json.Unmarshal(e.Payload, &payload); err != nil {
				t.Fatalf("sandbox event %d: %v", i, err)
			}
			switch payload.Phase {
			case "created":
				createdIdx = i
				if payload.Network != vora.NetworkNone {
					t.Errorf("sandbox created event reports network %q", payload.Network)
				}
			case "destroyed":
				destroyedIdx = i
			}
		}
	}
	if createdIdx < 0 || destroyedIdx < 0 {
		t.Fatalf("the sandbox's life was not journaled: created=%d destroyed=%d", createdIdx, destroyedIdx)
	}
	if !(createdIdx < destroyedIdx && destroyedIdx < finishedIdx) {
		t.Fatalf("sandbox events are out of order: created=%d destroyed=%d finished=%d", createdIdx, destroyedIdx, finishedIdx)
	}
}

// TestInvestigateDestroysTheSandboxWhenTheWorkerMisbehaves is the failure path
// the plan names: a malformed answer stops the run, and the sandbox still goes
// away. A leaked sandbox would poison the next attempt.
func TestInvestigateDestroysTheSandboxWhenTheWorkerMisbehaves(t *testing.T) {
	fake := &fakeVoraAPI{execBody: func([]byte) string {
		return stdoutChunk("this is not a result line") + "\n" + exitChunk(0, "EXITED") + "\n"
	}}
	live, err := Investigate(context.Background(), liveOptions(t, fake, t.TempDir()))
	if err == nil {
		t.Fatal("a malformed worker answer must fail the run")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("error = %v, want a malformed-answer refusal", err)
	}
	if !live.SandboxDestroyed {
		t.Fatal("the sandbox must be destroyed even when the run fails")
	}
	created, destroyed := fake.counts()
	if created != 1 || destroyed != 1 {
		t.Fatalf("create/destroy = %d/%d, want 1/1", created, destroyed)
	}
	for _, e := range readJournal(t, live.JournalPath) {
		if e.Kind == store.EventRunFinished {
			t.Fatal("an interrupted run must not be journaled as finished")
		}
	}
}

// TestInvestigateTreatsAMissingExitAsInterrupted carries the exit-presence rule
// all the way through the controller: a stream with no exit chunk must not read
// as a completed investigation.
func TestInvestigateTreatsAMissingExitAsInterrupted(t *testing.T) {
	fake := &fakeVoraAPI{execBody: func([]byte) string {
		return stdoutChunk(`{"schema_version":"probe/v1","kind":"final"}`) + "\n"
	}}
	live, err := Investigate(context.Background(), liveOptions(t, fake, t.TempDir()))
	if !errors.Is(err, ErrInterrupted) {
		t.Fatalf("error = %v, want ErrInterrupted", err)
	}
	if !live.SandboxDestroyed {
		t.Fatal("the sandbox must be destroyed even when the worker is interrupted")
	}
}

func claimVerdicts(r investigation.Report) map[string]bool {
	out := make(map[string]bool, len(r.Claims))
	for _, c := range r.Claims {
		out[string(c.Kind)] = c.Allowed
	}
	return out
}

func equalVerdicts(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
