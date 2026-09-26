package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

// ask is an investigation whose incident a human wrote: a question about one
// service over a recent window (#13, P3.1). It is not a chat. It runs the same
// bounded loop, the same allowlist and the same claims policy as an alert, and
// prints the report.
func ask(args []string) error {
	flags := flag.NewFlagSet("ask", flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the lab config JSON")
	service := flags.String("service", "", "the service to investigate")
	since := flags.Duration("since", 30*time.Minute, "how far back to look (at most 1h)")
	severity := flags.String("severity", "", "incident severity; logs are offered only for critical, high or warning")
	env := flags.String("env", "", "environment (default: the config's incident environment, or lab)")
	var question []string
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			return err
		}
		args = flags.Args()
		if len(args) > 0 {
			question, args = append(question, args[0]), args[1:]
		}
	}
	if *configPath == "" || *service == "" || len(question) == 0 {
		return errors.New(`ask needs --config <lab.json> --service <name> "<question>"`)
	}
	cfg, err := loadInvestigateConfig(*configPath)
	if err != nil {
		return err
	}
	environment := *env
	if environment == "" {
		environment = cfg.Incident.Environment
	}
	incident, err := askIncident(strings.Join(question, " "), *service, environment, *severity, *since, time.Now().UTC())
	if err != nil {
		return err
	}

	endpoint := models.ConfigFromEnv().Baseline
	if !endpoint.Configured() {
		return errors.New("ask needs a planner endpoint: set VORA_PROBE_MODEL_BASE_URL (and the key and model)")
	}
	arm, err := evaluatorArm(cfg.Evaluator)
	if err != nil {
		return err
	}
	budget := cfg.budget()
	outDir := cfg.OutDir
	if outDir == "" {
		outDir = filepath.Join(".probe", "ask")
	}
	newEngine := func() *investigation.Engine {
		return &investigation.Engine{Policy: gateway.DefaultPolicy(), Claims: investigation.DefaultClaimPolicy(), Relations: arm}
	}
	run, _, err := investigator(cfg, models.PlannerFromConfig(models.ConfigFromEnv()), budget, outDir, newEngine)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(budget.MaxDurationSeconds)*time.Second)
	defer cancel()
	result, err := run(ctx, incident, 1)
	if result.ReportMarkdownPath != "" {
		fmt.Print(result.Report.Markdown())
		fmt.Fprintf(os.Stderr, "report: %s\n        %s\njournal: %s\n", result.ReportMarkdownPath, result.ReportJSONPath, result.JournalPath)
	}
	// A run that did not conclude still printed its report; the error sets
	// the exit status so a script cannot read it as a finding.
	return err
}

const maxQuestionBytes = 512

// askIncident turns a question into the incident a run investigates. The
// question is the symptom, and it reaches the planner, so it is redacted and
// bounded like alert text; the window ends now and is capped at the evidence
// bound.
func askIncident(question, service, environment, severity string, since time.Duration, now time.Time) (investigation.Incident, error) {
	question = strings.TrimSpace(question)
	if question == "" {
		return investigation.Incident{}, errors.New("a question is required")
	}
	if since <= 0 || since > gateway.MaxWindow {
		return investigation.Incident{}, fmt.Errorf("--since must be between 0 and %s, got %s", gateway.MaxWindow, since)
	}
	if environment == "" {
		environment = "lab"
	}
	symptom, _ := gateway.RedactText(question)
	if len(symptom) > maxQuestionBytes {
		cut := maxQuestionBytes
		for cut > 0 && !utf8.RuneStart(symptom[cut]) {
			cut--
		}
		symptom = symptom[:cut] + " (truncated)"
	}
	sum := sha256.Sum256([]byte(service + "|" + question + "|" + now.Format(time.RFC3339Nano)))
	incident := investigation.Incident{
		SchemaVersion: gateway.SchemaVersion,
		ID:            "INC-ask-" + hex.EncodeToString(sum[:])[:12],
		Environment:   environment,
		Service:       service,
		Symptom:       symptom,
		Trigger:       investigation.TriggerCLI,
		StartedAt:     now,
		Window:        gateway.Window{Start: now.Add(-since), End: now},
		Status:        investigation.IncidentInvestigating,
		Severity:      severity,
	}
	return incident, incident.Validate()
}
