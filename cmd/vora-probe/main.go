// Command vora-probe is the manual entry point for an investigation.
//
// Steps 1 and 2 run entirely offline: `vora-probe replay` exercises the whole
// loop against a frozen fixture with recorded model responses, no credentials
// and no network. `vora-probe investigate` arrives with the live lab in step 5.
//
// The binary stays standalone rather than becoming a `vora` subcommand: probe
// consumes Vora's public API, so folding it in would invert the dependency and
// couple the two release cadences for no user-visible gain.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

const usage = `vora-probe investigates a service read-only and explains what it found.

usage:
  vora-probe replay <fixture-dir> [--out DIR] [--attempt N] [--evaluator ARM] [--json]
        run a full investigation against a frozen fixture
  vora-probe evaluate [--suite relations] [--split dev|held-out|all]
                      [--evaluators deterministic,baseline,jev] [--repeats N] [--loop] [--out DIR] [--json]
        compare evidence-relation evaluators; arms without a configured endpoint
        are reported as blocked rather than substituted
  vora-probe investigate --config <lab.json>
        run an investigation against the live lab: the worker in a Vora sandbox,
        Prometheus and Kubernetes evidence, and model-driven planning
  vora-probe verify [<fixtures-root>]
        check fixture integrity and the hidden answer keys
  vora-probe version

endpoints are run configuration, not build-time constants:
  VORA_PROBE_MODEL_BASE_URL, VORA_PROBE_MODEL_API_KEY, VORA_PROBE_MODEL, VORA_PROBE_MODEL_MAX_OUTPUT_TOKENS
  VORA_PROBE_JEV_BASE_URL, VORA_PROBE_JEV_API_KEY, VORA_PROBE_JEV_MODEL
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "vora-probe:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("a command is required")
	}
	switch args[0] {
	case "replay":
		return replay(args[1:])
	case "evaluate":
		return evaluate(args[1:])
	case "investigate":
		return investigate(args[1:])
	case "verify":
		return verify(args[1:])
	case "version":
		fmt.Println("vora-probe", "probe/v1")
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// evaluatorArm resolves --evaluator to the arm the engine should use.
func evaluatorArm(name string) (investigation.RelationEvaluator, error) {
	if name == "" || name == investigation.DeterministicArm {
		return investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()}, nil
	}
	cfg := models.ConfigFromEnv()
	switch name {
	case investigation.BaselineArm:
		if !cfg.Baseline.Configured() {
			return nil, fmt.Errorf("evaluator %q needs VORA_PROBE_MODEL_BASE_URL", name)
		}
		return models.BaselineArm{Endpoint: cfg.Baseline, MaxResponseBytes: 1 << 20}, nil
	case investigation.JevArm:
		if !cfg.Jev.Configured() {
			return nil, fmt.Errorf("evaluator %q needs VORA_PROBE_JEV_BASE_URL", name)
		}
		return models.JevArm{Endpoint: cfg.Jev, MaxResponseBytes: 1 << 20}, nil
	default:
		return nil, fmt.Errorf("unknown evaluator %q; known: %s, %s, %s",
			name, investigation.DeterministicArm, investigation.BaselineArm, investigation.JevArm)
	}
}

func replay(args []string) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	out := flags.String("out", ".probe", "directory for the journal and report artifacts")
	attempt := flags.Int("attempt", 1, "attempt number recorded on the run")
	evaluator := flags.String("evaluator", investigation.DeterministicArm, "evidence-relation arm: deterministic, baseline or jev")
	asJSON := flags.Bool("json", false, "print the report JSON instead of a summary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	// Accept the fixture path before the flags as well as after them.
	positional := flags.Args()
	if len(positional) > 1 {
		if err := flags.Parse(positional[1:]); err != nil {
			return err
		}
		positional = positional[:1]
	}
	if len(positional) != 1 {
		return fmt.Errorf("replay needs exactly one fixture directory")
	}

	arm, err := evaluatorArm(*evaluator)
	if err != nil {
		return err
	}
	result, err := probe.Replay(context.Background(), probe.ReplayOptions{
		BundleDir: positional[0],
		OutDir:    *out,
		Attempt:   *attempt,
		Engine: &investigation.Engine{
			Policy:    gateway.DefaultPolicy(),
			Claims:    investigation.DefaultClaimPolicy(),
			Relations: arm,
		},
	})
	// A run that did not conclude still has a report, and it is printed; the
	// error then makes the exit status say it was not a finding.
	if err != nil && !errors.Is(err, probe.ErrNotConcluded) {
		return err
	}
	runErr := err

	if *asJSON {
		raw, err := json.MarshalIndent(result.Report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return runErr
	}

	report := result.Report
	fmt.Printf("%s  %s (%s, arm %s)\n", report.Incident.ID, report.Incident.Service, report.Run.Status, report.Arm)
	fmt.Printf("steps %d, infrastructure calls %d, planner turns %d, model calls %d\n",
		result.Steps, result.InfraCalls, result.PlannerTurns, report.Run.Used.ModelCalls)
	if report.Leading != nil {
		fmt.Printf("leading claim: %s (%s)\n", report.Leading.Kind, allowedLabel(report.Leading.Allowed))
	}
	fmt.Printf("supporting %d, contradicting %d, insufficient context %d\n",
		len(report.Supporting), len(report.Contradicting), len(report.InsufficientContext))
	if report.Recommendation != nil {
		fmt.Printf("recommendation: %s\n", report.Recommendation.Action)
		fmt.Printf("execution: %s\n", report.Recommendation.Status)
	} else {
		fmt.Println("recommendation: none")
	}
	fmt.Printf("report: %s\n        %s\njournal: %s\n",
		result.ReportMarkdownPath, result.ReportJSONPath, result.JournalPath)
	return runErr
}

func allowedLabel(allowed bool) string {
	if allowed {
		return "admissible"
	}
	return "refused"
}

func verify(args []string) error {
	root := filepath.Join(fixtures.Root(), "oom")
	if len(args) > 0 {
		root = args[0]
	}
	dirs, err := fixtures.Cases(root)
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		bundle, err := fixtures.Load(dir)
		if err != nil {
			return err
		}
		if err := fixtures.Verify(bundle); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		truth, err := fixtures.LoadTruth(dir)
		if err != nil {
			return err
		}
		if err := fixtures.VerifyTruth(truth); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		fmt.Printf("ok  %-36s %d recorded answers, leading claim %s\n",
			filepath.Base(dir), len(bundle.Evidence), truth.Expected.LeadingClaim)
	}
	return nil
}
