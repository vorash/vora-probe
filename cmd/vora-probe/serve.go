package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/intake"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/internal/serve"
	"github.com/vorash/vora-probe/internal/vora"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// serveConfig is the investigate config plus the server's own settings. The
// lab, budget, evaluator and worker blocks mean exactly what they mean for one
// investigation; the incident block is not used, because incidents arrive as
// alerts.
type serveConfig struct {
	investigateConfig
	Serve struct {
		// Listen defaults to loopback. Exposing the receiver is a deployment
		// decision, made where it is deployed.
		Listen        string   `json:"listen"`
		TokenFile     string   `json:"token_file"`
		Environment   string   `json:"environment"`
		ServiceLabels []string `json:"service_labels"`
		RateLimit     *struct {
			Window    string `json:"window"`
			PerGroup  int    `json:"per_group"`
			PerEntity int    `json:"per_entity"`
		} `json:"rate_limit"`
	} `json:"serve"`
}

// defaultListen avoids every port Vora already binds on the lab host (9101,
// 9200, 9300, 9301, 9443, 6443).
const defaultListen = "127.0.0.1:9480"

func serveCommand(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the serve config JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("serve needs --config <file>")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	var cfg serveConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("config %s: %w", *configPath, err)
	}
	if cfg.Serve.TokenFile == "" {
		return errors.New("serve.token_file is required: the receiver never runs without a bearer token")
	}
	token := mustReadSecret(cfg.Serve.TokenFile, "serve bearer token")

	// Planning needs a model. Without one every run would fail the same way, so
	// the server refuses to start rather than accept alerts it cannot act on.
	endpoint := models.ConfigFromEnv().Baseline
	if !endpoint.Configured() {
		return errors.New("serve needs a planner endpoint: set VORA_PROBE_MODEL_BASE_URL (and the key and model)")
	}
	planner := models.LivePlanner{Endpoint: endpoint, MaxResponseBytes: 1 << 20}

	arm, err := evaluatorArm(cfg.Evaluator)
	if err != nil {
		return err
	}
	budget := cfg.budget()
	outDir := cfg.OutDir
	if outDir == "" {
		outDir = filepath.Join(".probe", "serve")
	}
	newEngine := func() *investigation.Engine {
		return &investigation.Engine{Policy: gateway.DefaultPolicy(), Claims: investigation.DefaultClaimPolicy(), Relations: arm}
	}

	investigate, mode, err := investigator(cfg, planner, budget, outDir, newEngine)
	if err != nil {
		return err
	}

	intakeCfg := intake.DefaultConfig()
	if cfg.Serve.Environment != "" {
		intakeCfg.Environment = cfg.Serve.Environment
	}
	if len(cfg.Serve.ServiceLabels) > 0 {
		intakeCfg.ServiceLabels = cfg.Serve.ServiceLabels
	}
	in := intake.New(intakeCfg)

	limits := serve.DefaultLimits()
	if rl := cfg.Serve.RateLimit; rl != nil {
		if limits.Window, err = parseDuration(rl.Window, limits.Window); err != nil {
			return fmt.Errorf("serve.rate_limit.window: %w", err)
		}
		if rl.PerGroup > 0 {
			limits.PerGroup = rl.PerGroup
		}
		if rl.PerEntity > 0 {
			limits.PerEntity = rl.PerEntity
		}
	}
	server, err := serve.New(serve.Config{
		Intake:      in,
		Investigate: investigate,
		Limits:      limits,
		// The deadline is the run's own wall-clock budget: a stalled planner
		// is closed with a report at the same point the engine would stop.
		Timeout: time.Duration(budget.MaxDurationSeconds) * time.Second,
	})
	if err != nil {
		return err
	}
	handler, err := intake.Handler(in, token, server.Accept)
	if err != nil {
		return err
	}

	listen := cfg.Serve.Listen
	if listen == "" {
		listen = defaultListen
	}
	httpServer := &http.Server{
		Addr:              listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	worker := make(chan error, 1)
	go func() { worker <- server.Run(ctx) }()
	listener := make(chan error, 1)
	go func() { listener <- httpServer.ListenAndServe() }()
	fmt.Printf("vora-probe serve: listening on %s, worker %s, reports in %s\n", listen, mode, outDir)

	select {
	case err := <-listener:
		stop()
		<-worker
		return err
	case <-ctx.Done():
	}
	// Stop accepting first, then let the worker close the run in progress; that
	// run is abandoned with a report like any other the controller cannot
	// finish. Incidents still queued are in memory only until the incident
	// store (P1.3) persists them.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	<-worker
	if queued := server.Queued(); len(queued) > 0 {
		fmt.Fprintf(os.Stderr, "vora-probe serve: stopped with %d incidents still queued: %v\n", len(queued), queued)
	}
	return nil
}

// investigator binds the ports for one investigation. The worker runs in-process
// unless the config names a Vora API, in which case every step runs in a
// network-denied sandbox, the hardened mode.
func investigator(cfg serveConfig, planner models.Planner, budget investigation.Budgets, outDir string, newEngine func() *investigation.Engine) (serve.Investigator, string, error) {
	if cfg.Vora.BaseURL == "" {
		return func(ctx context.Context, incident investigation.Incident) (probe.ReplayResult, error) {
			gw, err := cfg.labGateway()
			if err != nil {
				return probe.ReplayResult{}, err
			}
			return probe.Run(ctx, probe.RunOptions{
				Incident: incident, Planner: planner, Gateway: gw, Engine: newEngine(), OutDir: outDir, Budget: budget,
			})
		}, "in-process", nil
	}

	if cfg.Worker.Image == "" {
		return nil, "", errors.New("worker.image is required when a Vora API is configured")
	}
	stepTimeout, err := parseDuration(cfg.Worker.StepTimeout, 60*time.Second)
	if err != nil {
		return nil, "", err
	}
	client, err := vora.NewClient(vora.Config{
		BaseURL: cfg.Vora.BaseURL,
		APIKey:  mustReadSecret(cfg.Vora.APIKeyFile, "vora api key"),
		Timeout: 120 * time.Second,
	})
	if err != nil {
		return nil, "", err
	}
	return func(ctx context.Context, incident investigation.Incident) (probe.ReplayResult, error) {
		gw, err := cfg.labGateway()
		if err != nil {
			return probe.ReplayResult{}, err
		}
		result, err := probe.Investigate(ctx, probe.LiveOptions{
			Client: client, Incident: &incident, OutDir: outDir, Budget: budget,
			Image: cfg.Worker.Image, Backend: cfg.Worker.Backend, Command: cfg.Worker.Command, Cwd: cfg.Worker.Cwd,
			TTLSeconds: cfg.Worker.TTLSeconds, StepTimeout: stepTimeout,
			Engine: newEngine(), Gateway: gw, Planner: planner,
		})
		return result.ReplayResult, err
	}, "in a Vora sandbox", nil
}
