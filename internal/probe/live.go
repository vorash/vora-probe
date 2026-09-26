package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/internal/vora"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// The live controller leg.
//
// Replay runs the worker in this process. The live controller runs the same
// binary inside a Vora sandbox and drives it one step at a time over the public
// exec API: a bounded envelope on stdin, exactly one result line on stdout. The
// investigation loop, the fixtures and the report are unchanged, so a live run
// is comparable to a replay rather than merely similar to it.
//
// The one thing that is easy to get wrong is exit handling, and it is the reason
// this leg exists at all: protojson omits a zero exit code, so a present exit
// chunk with no code means success while an absent exit chunk means the
// execution was interrupted. Reading those as the same thing would let a
// truncated run look clean.

// ErrInterrupted marks an execution that ended without an exit chunk. It is the
// one failure the plan insists must never be read as success.
var ErrInterrupted = errors.New("worker execution was interrupted")

// DefaultWorkerCommand is the fixed exec command the released worker image
// carries as its entrypoint. The controller never takes an executable from
// worker output, so this is configuration, not a negotiation.
const DefaultWorkerCommand = "/usr/local/bin/vora-probe-worker"

// DefaultWorkerCwd matches the image's WORKDIR.
const DefaultWorkerCwd = "/workspace"

// DefaultSandboxResources bound the worker sandbox. The worker is a pure
// transition function and needs almost nothing, but vora-api requires a positive
// memory bound, and an unbounded sandbox is not something this controller is
// willing to ask for.
func DefaultSandboxResources() *vora.ResourceLimits {
	return &vora.ResourceLimits{CPUMillis: 1000, MemoryBytes: 512 << 20, PIDs: 64}
}

// SandboxWorker runs one worker step inside a Vora sandbox. It is a StepRunner,
// so the investigation loop cannot tell whether a step ran in-process or across
// the sandbox boundary.
type SandboxWorker struct {
	client      *vora.Client
	sandboxID   string
	command     string
	cwd         string
	stepTimeout time.Duration
	// maxStep bounds both directions of one step. It mirrors worker.Step's own
	// envelope-plus-response budget, so the controller refuses an oversized
	// envelope before the sandbox ever sees it.
	maxStep int64
}

type SandboxWorkerConfig struct {
	Client      *vora.Client
	SandboxID   string
	Command     string
	Cwd         string
	StepTimeout time.Duration
	Budgets     investigation.Budgets
}

func NewSandboxWorker(cfg SandboxWorkerConfig) (*SandboxWorker, error) {
	if cfg.Client == nil {
		return nil, errors.New("a vora client is required")
	}
	if cfg.SandboxID == "" {
		return nil, errors.New("a sandbox id is required")
	}
	limit := cfg.Budgets.MaxEnvelopeBytes + cfg.Budgets.MaxResponseBytes
	if limit <= 0 {
		return nil, errors.New("positive envelope and response budgets are required")
	}
	command := cfg.Command
	if command == "" {
		command = DefaultWorkerCommand
	}
	cwd := cfg.Cwd
	if cwd == "" {
		cwd = DefaultWorkerCwd
	}
	timeout := cfg.StepTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &SandboxWorker{
		client:      cfg.Client,
		sandboxID:   cfg.SandboxID,
		command:     command,
		cwd:         cwd,
		stepTimeout: timeout,
		maxStep:     limit,
	}, nil
}

func (w *SandboxWorker) SandboxID() string { return w.sandboxID }

// Step sends the bounded envelope on stdin and collects the single result line.
func (w *SandboxWorker) Step(ctx context.Context, input []byte) ([]byte, error) {
	if int64(len(input)) > w.maxStep {
		return nil, fmt.Errorf("worker input of %d bytes exceeds the %d byte step budget", len(input), w.maxStep)
	}
	result, err := w.client.Exec(ctx, w.sandboxID, vora.ExecRequest{
		Command:        w.command,
		Cwd:            w.cwd,
		Stdin:          input,
		TimeoutSeconds: int64(w.stepTimeout.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	if result.Exit == nil {
		return nil, fmt.Errorf("%w: the sandbox reported no exit for %s", ErrInterrupted, w.command)
	}
	if result.Exit.Code != 0 {
		return nil, fmt.Errorf("worker %s exited %d: %s", w.command, result.Exit.Code, firstLine(result.Stderr))
	}
	return oneResultLine(result.Stdout, w.maxStep)
}

// oneResultLine enforces the output half of the step protocol: exactly one
// non-empty, valid JSON line, within budget. Anything else is a protocol
// violation to be reported, not data to be trimmed into shape.
func oneResultLine(stdout []byte, maxBytes int64) ([]byte, error) {
	if int64(len(stdout)) > maxBytes {
		return nil, fmt.Errorf("worker output of %d bytes exceeds the %d byte step budget", len(stdout), maxBytes)
	}
	var lines [][]byte
	for _, line := range strings.Split(string(stdout), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, []byte(trimmed))
		}
	}
	switch len(lines) {
	case 0:
		return nil, errors.New("worker produced no result line")
	case 1:
	default:
		return nil, fmt.Errorf("worker produced %d result lines, want exactly one", len(lines))
	}
	if !json.Valid(lines[0]) {
		return nil, errors.New("worker result line is not valid JSON")
	}
	return lines[0], nil
}

func firstLine(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

// LiveOptions configures one investigation whose worker steps run inside a Vora
// sandbox. The evidence still comes from the fixture gateway: step 4 proves the
// transport, not the lab, so a live run must reproduce the replay report. Only
// the worker's location differs.
type LiveOptions struct {
	Client    *vora.Client
	BundleDir string
	OutDir    string
	Attempt   int
	Budget    investigation.Budgets
	Engine    *investigation.Engine
	MaxSteps  int
	// Image must be digest-pinned. A mutable tag would make a run
	// unreproducible, which is the opposite of what a live run is for.
	Image       string
	Backend     string
	Command     string
	Cwd         string
	Resources   *vora.ResourceLimits
	TTLSeconds  int64
	StepTimeout time.Duration
	OnEnvelope  func(investigation.StepEnvelope)
	// Gateway overrides where evidence comes from. Nil means the frozen fixture,
	// which is what step 4 validated; a live investigation injects the lab
	// adapter and reads the same port.
	Gateway gateway.Gateway
	// Planner overrides how the next step is chosen. Nil means the recorded
	// fixture turns; a live investigation injects a model-driven planner.
	Planner models.Planner
	// Incident, when set, is the subject of the run and BundleDir is not read.
	// A live lab run has no fixture to load it from.
	Incident *investigation.Incident
}

type LiveResult struct {
	ReplayResult
	SandboxID        string
	SandboxDestroyed bool
}

// Investigate runs the same loop as Replay with one difference: every worker
// step is a fixed-command exec inside a fresh, network-denied Vora sandbox. The
// sandbox is destroyed on every exit path, and the controller's journal and
// report survive it.
func Investigate(ctx context.Context, opts LiveOptions) (LiveResult, error) {
	if opts.Client == nil {
		return LiveResult{}, errors.New("a vora client is required")
	}
	if opts.Image == "" {
		return LiveResult{}, errors.New("a digest-pinned worker image is required")
	}
	if opts.OutDir == "" {
		opts.OutDir = ".probe"
	}
	if opts.Attempt <= 0 {
		opts.Attempt = 1
	}
	budget := opts.Budget
	if budget.MaxSteps == 0 {
		budget = investigation.DefaultBudgets()
	}
	engine := opts.Engine
	if engine == nil {
		engine = &investigation.Engine{Policy: gateway.DefaultPolicy(), Claims: investigation.DefaultClaimPolicy()}
	}

	// An incident comes from run configuration or from a fixture. A live lab run
	// has no fixture; the step-4 transport check still uses one, because its
	// evidence is frozen on purpose.
	var (
		incident investigation.Incident
		bundle   *fixtures.Bundle
	)
	if opts.Incident != nil {
		incident = *opts.Incident
	} else {
		loaded, err := loadBundle(opts.BundleDir)
		if err != nil {
			return LiveResult{}, err
		}
		bundle, incident = &loaded, loaded.Incident
	}
	now := wallClock
	engine.Now = now
	planner := opts.Planner
	if planner == nil {
		if bundle == nil {
			return LiveResult{}, errors.New("a recorded planner needs a fixture bundle; supply Planner or BundleDir")
		}
		planner = models.NewRecordedPlanner(plannerTurns(*bundle))
	}
	// Evidence comes from the fixture unless a live adapter is supplied.
	gw := opts.Gateway
	if gw == nil {
		if bundle == nil {
			return LiveResult{}, errors.New("the fixture gateway needs a bundle; supply Gateway or BundleDir")
		}
		fixture, err := openFixtureGateway(engine, *bundle, now)
		if err != nil {
			return LiveResult{}, err
		}
		gw = fixture
	}
	lock, err := store.AcquireLock(opts.OutDir, "probe")
	if err != nil {
		return LiveResult{}, err
	}
	defer lock.Release()

	runID := fmt.Sprintf("RUN-%s-%03d", incident.ID, opts.Attempt)
	runDir := filepath.Join(opts.OutDir, runID)
	journal, err := store.OpenJournal(runDir, runID)
	if err != nil {
		return LiveResult{}, err
	}
	defer journal.Close()

	var (
		worker    *SandboxWorker
		destroyed bool
	)
	onCreate := func(createCtx context.Context) (StepRunner, error) {
		resources := opts.Resources
		if resources == nil {
			resources = DefaultSandboxResources()
		}
		sandbox, err := opts.Client.CreateSandbox(createCtx, vora.SandboxSpec{
			TenantID:   "probe",
			Image:      opts.Image,
			Backend:    opts.Backend,
			Network:    &vora.NetworkPolicy{Mode: vora.NetworkNone},
			Resources:  resources,
			TTLSeconds: ttlSeconds(opts.TTLSeconds, budget),
		})
		if err != nil {
			return nil, err
		}
		if err := journal.Append(store.Event{
			RunID: runID, IncidentID: incident.ID, Kind: store.EventSandbox,
			At:      now(),
			Payload: mustJSON(sandboxEvent{Phase: "created", Sandbox: sandbox.ID, Image: opts.Image, Tenant: "probe", Network: vora.NetworkNone}),
		}); err != nil {
			// Do not leak the sandbox just because the journal write failed.
			_ = opts.Client.DestroySandbox(context.WithoutCancel(createCtx), sandbox.ID)
			return nil, err
		}
		worker, err = NewSandboxWorker(SandboxWorkerConfig{
			Client:      opts.Client,
			SandboxID:   sandbox.ID,
			Command:     opts.Command,
			Cwd:         opts.Cwd,
			StepTimeout: opts.StepTimeout,
			Budgets:     budget,
		})
		if err != nil {
			return nil, err
		}
		return worker.Step, nil
	}
	onDestroy := func(destroyCtx context.Context) {
		if worker == nil {
			return
		}
		id := worker.SandboxID()
		if err := opts.Client.DestroySandbox(destroyCtx, id); err != nil {
			// A leaked sandbox is worth a journal entry even though the teardown
			// path has nowhere to return an error to.
			_ = journal.Append(store.Event{
				RunID: runID, IncidentID: incident.ID, Kind: store.EventSandbox,
				At:      now(),
				Payload: mustJSON(sandboxEvent{Phase: "destroy_failed", Sandbox: id, Reason: err.Error()}),
			})
			return
		}
		destroyed = true
		_ = journal.Append(store.Event{
			RunID: runID, IncidentID: incident.ID, Kind: store.EventSandbox,
			At:      now(),
			Payload: mustJSON(sandboxEvent{Phase: "destroyed", Sandbox: id}),
		})
	}

	res, err := runLoop(ctx, runConfig{
		engine:     engine,
		planner:    planner,
		gateway:    gw,
		journal:    journal,
		now:        now,
		budget:     budget,
		attempt:    opts.Attempt,
		runID:      runID,
		runDir:     runDir,
		incident:   incident,
		maxSteps:   opts.MaxSteps,
		onEnvelope: opts.OnEnvelope,
		onCreate:   onCreate,
		onDestroy:  onDestroy,
	})

	live := LiveResult{
		SandboxDestroyed: destroyed,
		// The journal path is returned even when the run fails: an interrupted run
		// is exactly the one an operator needs to read.
		ReplayResult: ReplayResult{JournalPath: journal.Path()},
	}
	if worker != nil {
		live.SandboxID = worker.SandboxID()
	}
	if err != nil && !errors.Is(err, ErrNotConcluded) {
		return live, err
	}
	live.ReplayResult = ReplayResult{
		Report:             res.report,
		JournalPath:        journal.Path(),
		ReportJSONPath:     res.reportJSONPath,
		ReportMarkdownPath: res.reportMarkdownPath,
		PlannerTurns:       recordedTurns(planner),
		InfraCalls:         gw.Executed(),
		Steps:              res.steps,
	}
	return live, err
}

// wallClock is a live run's time source. Replay freezes time so two replays are
// byte-identical; a live run must not, because the sandbox runs the worker with
// its own clock and measures the wall-clock budget against Run.Used.StartedAt. A
// frozen start older than the budget would read as exhausted on the first step,
// which is a real failure this leg found: fixtures recorded hours before a run
// would otherwise stop before doing any work.
func wallClock() time.Time { return time.Now().UTC() }

// recordedTurns reports how many recorded planner turns were consumed. A live
// planner has no such counter, and reporting zero is honest rather than
// inventing a number.
func recordedTurns(p models.Planner) int {
	if rp, ok := p.(*models.RecordedPlanner); ok {
		return rp.Consumed()
	}
	return 0
}

// ttlSeconds keeps the sandbox alive past the run's own wall-clock budget, so it
// is the controller that reaps it rather than a TTL expiring mid-step.
func ttlSeconds(configured int64, budget investigation.Budgets) int64 {
	if configured > 0 {
		return configured
	}
	return int64(budget.MaxDurationSeconds) + 300
}

// sandboxEvent is the journal payload that correlates a run with its sandbox.
type sandboxEvent struct {
	Phase   string `json:"phase"`
	Sandbox string `json:"sandbox"`
	Image   string `json:"image,omitempty"`
	Tenant  string `json:"tenant,omitempty"`
	Network string `json:"network,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
