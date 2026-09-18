package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/evaluation"
	"github.com/vorash/vora-probe/internal/models"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/test/fixtures"
)

// evaluate compares evidence-relation evaluators.
//
// Arms whose endpoint is not configured are reported as blocked. The run still
// produces a comparison: the deterministic arm answers, and the blocked arms say
// so, which is a more honest output than an error that hides the result.
func evaluate(args []string) error {
	flags := flag.NewFlagSet("evaluate", flag.ContinueOnError)
	suite := flags.String("suite", "relations", "suite to run")
	split := flags.String("split", "all", "dev, held-out or all")
	evaluators := flags.String("evaluators", "", "comma-separated arms; default is every arm")
	repeats := flags.Int("repeats", 3, "times each case is asked")
	loop := flags.Bool("loop", false, "also compare whole-loop outcomes over the OOM fixtures")
	out := flags.String("out", ".probe/evaluation", "directory for the comparison report")
	asJSON := flags.Bool("json", false, "print the report JSON instead of a summary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *suite != "relations" {
		return fmt.Errorf("unknown suite %q", *suite)
	}
	if *repeats < 1 {
		return fmt.Errorf("--repeats must be at least 1")
	}

	root := filepath.Join(fixtures.Root(), "relations")
	dev, heldOut, err := evaluation.LoadSplits(root)
	if err != nil {
		return err
	}
	cases := append(append([]evaluation.Case{}, dev...), heldOut...)
	switch *split {
	case "dev":
		cases = dev
	case "held-out":
		cases = heldOut
	case "all":
	default:
		return fmt.Errorf("--split must be dev, held-out or all")
	}

	cfg := models.ConfigFromEnv()
	now := func() time.Time { return time.Now().UTC() }
	set, err := evaluation.BuildArms(cfg, nil, now).Select(splitList(*evaluators))
	if err != nil {
		return err
	}

	outcomes, err := evaluation.RunSuite(context.Background(), evaluation.SuiteOptions{
		Cases: cases, Arms: set.Arms, Repeat: *repeats, Now: now,
	})
	if err != nil {
		return err
	}

	prices := map[string]evaluation.TokenPrice{}
	var loopSummaries []evaluation.LoopSummary
	if *loop {
		if err := os.MkdirAll(*out, 0o700); err != nil {
			return err
		}
		loopSummaries, err = evaluation.RunLoop(context.Background(), evaluation.LoopOptions{
			FixtureRoot: filepath.Join(fixtures.Root(), "oom"),
			Arms:        set.Arms,
			Repeat:      *repeats,
			OutDir:      filepath.Join(*out, "loop"),
		})
		if err != nil {
			return err
		}
	}

	report := evaluation.Build(*suite, models.Version, set.Infos, outcomes, prices, loopSummaries, *repeats)
	if *asJSON {
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	}

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	jsonPath, err := store.WriteArtifact(*out, "comparison.json", append(raw, '\n'))
	if err != nil {
		return err
	}
	mdPath, err := store.WriteArtifact(*out, "comparison.md", []byte(report.Markdown()))
	if err != nil {
		return err
	}

	fmt.Printf("suite %s, label version %s, %d cases, %d repeats\n", report.Suite, report.LabelVersion, len(cases), *repeats)
	fmt.Println()
	fmt.Printf("%-14s %-9s %-8s %-10s %-8s %s\n", "arm", "valid", "agreed", "agreement", "unsupported", "status")
	for _, s := range report.Fixed {
		status := "ok"
		if s.Blocked != "" {
			status = "blocked (not measured)"
		} else if s.Failures > 0 {
			status = fmt.Sprintf("%d failures", s.Failures)
		}
		fmt.Printf("%-14s %-9d %-8d %-10s %-8d %s\n",
			s.Arm, s.ValidRuns, s.Agreements, fmt.Sprintf("%.0f%%", s.AgreementRate*100), s.Unsupported, status)
	}
	for _, l := range report.Loop {
		fmt.Printf("loop %-9s runs=%d leading-correct=%d unsafe=%d traceability-failures=%d\n",
			l.Arm, l.Runs, l.LeadingCorrect, l.UnsafeRecommendations, l.TraceabilityFailures)
	}
	fmt.Println()
	for _, info := range set.Infos {
		if info.Blocked != "" {
			fmt.Printf("note: arm %s is blocked and produced no result: %s\n", info.Arm, info.Blocked)
		}
	}
	fmt.Printf("report: %s\n        %s\n", mdPath, jsonPath)
	return nil
}

func splitList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
