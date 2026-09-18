package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/live"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/internal/vora"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// investigate runs one investigation against the live lab: the worker inside a
// Vora sandbox, evidence from Prometheus and the Kubernetes API, and planning by
// a model.
//
// The config is JSON and local. Credentials are never in it — only paths to the
// files that hold them — so a config can be shared without leaking a key, and
// the secrets stay where the operator already keeps them.
type investigateConfig struct {
	Vora struct {
		BaseURL    string `json:"base_url"`
		APIKeyFile string `json:"api_key_file"`
	} `json:"vora"`

	Worker struct {
		Image       string `json:"image"`
		Backend     string `json:"backend"`
		Command     string `json:"command"`
		Cwd         string `json:"cwd"`
		TTLSeconds  int64  `json:"ttl_seconds"`
		StepTimeout string `json:"step_timeout"`
	} `json:"worker"`

	Lab struct {
		PrometheusURL string `json:"prometheus_url"`
		Namespace     string `json:"namespace"`
		Kubernetes    struct {
			Server    string `json:"server"`
			TokenFile string `json:"token_file"`
			CAFile    string `json:"ca_file"`
		} `json:"kubernetes"`
	} `json:"lab"`

	Incident struct {
		ID          string `json:"id"`
		Environment string `json:"environment"`
		Service     string `json:"service"`
		Symptom     string `json:"symptom"`
		StartedAt   string `json:"started_at"`
		Trigger     string `json:"trigger"`
		Window      struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"window"`
	} `json:"incident"`

	Budget *struct {
		MaxDurationSeconds int   `json:"max_duration_seconds"`
		MaxInfraCalls      int   `json:"max_infra_calls"`
		MaxModelCalls      int   `json:"max_model_calls"`
		MaxResponseBytes   int64 `json:"max_response_bytes"`
		MaxEnvelopeBytes   int64 `json:"max_envelope_bytes"`
		MaxSteps           int   `json:"max_steps"`
	} `json:"budget"`

	Evaluator string `json:"evaluator"`
	OutDir    string `json:"out"`
}

func investigate(args []string) error {
	flags := flag.NewFlagSet("investigate", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the lab config JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" {
		return errors.New("investigate needs --config <file>")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	var cfg investigateConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return fmt.Errorf("config %s: %w", *configPath, err)
	}

	client, err := vora.NewClient(vora.Config{
		BaseURL: cfg.Vora.BaseURL,
		APIKey:  mustReadSecret(cfg.Vora.APIKeyFile, "vora api key"),
		Timeout: 120 * time.Second,
	})
	if err != nil {
		return err
	}

	gatewayAdapter, err := live.New(live.Config{
		PrometheusURL: cfg.Lab.PrometheusURL,
		Namespace:     cfg.Lab.Namespace,
		Kubernetes: live.KubernetesConfig{
			Server: cfg.Lab.Kubernetes.Server,
			Token:  mustReadSecret(cfg.Lab.Kubernetes.TokenFile, "kubernetes token"),
			CAFile: cfg.Lab.Kubernetes.CAFile,
		},
		Policy: gateway.DefaultPolicy(),
	})
	if err != nil {
		return err
	}

	// A live run plans with a model. This is the same OpenAI-compatible endpoint
	// the baseline arm uses, so one credential configures both.
	planner := models.LivePlanner{Endpoint: models.ConfigFromEnv().Baseline, MaxResponseBytes: 1 << 20}

	arm, err := evaluatorArm(cfg.Evaluator)
	if err != nil {
		return err
	}
	incident, err := cfg.incidentValue()
	if err != nil {
		return err
	}
	budget := investigation.DefaultBudgets()
	if cfg.Budget != nil {
		if cfg.Budget.MaxDurationSeconds > 0 {
			budget.MaxDurationSeconds = cfg.Budget.MaxDurationSeconds
		}
		if cfg.Budget.MaxInfraCalls > 0 {
			budget.MaxInfraCalls = cfg.Budget.MaxInfraCalls
		}
		if cfg.Budget.MaxModelCalls > 0 {
			budget.MaxModelCalls = cfg.Budget.MaxModelCalls
		}
		if cfg.Budget.MaxResponseBytes > 0 {
			budget.MaxResponseBytes = cfg.Budget.MaxResponseBytes
		}
		if cfg.Budget.MaxEnvelopeBytes > 0 {
			budget.MaxEnvelopeBytes = cfg.Budget.MaxEnvelopeBytes
		}
		if cfg.Budget.MaxSteps > 0 {
			budget.MaxSteps = cfg.Budget.MaxSteps
		}
	}

	stepTimeout, err := parseDuration(cfg.Worker.StepTimeout, 60*time.Second)
	if err != nil {
		return err
	}
	outDir := cfg.OutDir
	if outDir == "" {
		outDir = filepath.Join(".probe", "live")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budget.MaxDurationSeconds+120)*time.Second)
	defer cancel()

	result, err := probe.Investigate(ctx, probe.LiveOptions{
		Client:      client,
		Incident:    &incident,
		OutDir:      outDir,
		Budget:      budget,
		Image:       cfg.Worker.Image,
		Backend:     cfg.Worker.Backend,
		Command:     cfg.Worker.Command,
		Cwd:         cfg.Worker.Cwd,
		TTLSeconds:  cfg.Worker.TTLSeconds,
		StepTimeout: stepTimeout,
		Engine: &investigation.Engine{
			Policy:    gateway.DefaultPolicy(),
			Claims:    investigation.DefaultClaimPolicy(),
			Relations: arm,
		},
		Gateway: gatewayAdapter,
		Planner: planner,
	})
	// The report is written even when the run fails; print what exists and let
	// the error speak for itself.
	fmt.Printf("run %s\n", incident.ID)
	fmt.Printf("  sandbox:      %s (destroyed: %t)\n", result.SandboxID, result.SandboxDestroyed)
	fmt.Printf("  journal:      %s\n", result.JournalPath)
	if result.Report.Run.Status != "" {
		fmt.Printf("  status:       %s (%s)\n", result.Report.Run.Status, result.Report.Run.Reason)
		fmt.Printf("  infra calls:  %d, planner turns: %d, steps: %d\n", result.InfraCalls, result.PlannerTurns, result.Steps)
	}
	if result.ReportJSONPath != "" {
		fmt.Printf("  report:       %s\n", result.ReportJSONPath)
		fmt.Printf("  markdown:     %s\n", result.ReportMarkdownPath)
	}
	if result.Report.Leading != nil {
		fmt.Printf("  leading:      %s (allowed: %t)\n", result.Report.Leading.Kind, result.Report.Leading.Allowed)
	}
	return err
}

func (c investigateConfig) incidentValue() (investigation.Incident, error) {
	started, err := time.Parse(time.RFC3339, c.Incident.StartedAt)
	if err != nil {
		return investigation.Incident{}, fmt.Errorf("incident.started_at: %w", err)
	}
	incident := investigation.Incident{
		SchemaVersion: gateway.SchemaVersion,
		ID:            c.Incident.ID,
		Environment:   c.Incident.Environment,
		Service:       c.Incident.Service,
		Symptom:       c.Incident.Symptom,
		Trigger:       investigation.Trigger(c.Incident.Trigger),
		StartedAt:     started.UTC(),
		Status:        investigation.IncidentInvestigating,
	}
	if c.Incident.Trigger == "" {
		incident.Trigger = investigation.TriggerCLI
	}
	if c.Incident.Window.Start != "" {
		if incident.Window.Start, err = time.Parse(time.RFC3339, c.Incident.Window.Start); err != nil {
			return investigation.Incident{}, fmt.Errorf("incident.window.start: %w", err)
		}
	}
	if c.Incident.Window.End != "" {
		if incident.Window.End, err = time.Parse(time.RFC3339, c.Incident.Window.End); err != nil {
			return investigation.Incident{}, fmt.Errorf("incident.window.end: %w", err)
		}
	}
	if incident.Window.Start.IsZero() {
		incident.Window.Start = incident.StartedAt.Add(-30 * time.Minute)
	}
	if incident.Window.End.IsZero() {
		incident.Window.End = incident.StartedAt
	}
	return incident, nil
}

func mustReadSecret(path, what string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vora-probe: cannot read %s from %s: %v\n", what, path, err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(raw))
}

func parseDuration(raw string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, err
	}
	return d, nil
}
