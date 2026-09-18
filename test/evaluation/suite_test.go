// Package evaluation_test is the step-3 acceptance suite.
//
// It pins the two things the comparison must be able to say: the deterministic
// arm answers every authored case the way that case's rationale says it should,
// and an arm that could not run is reported as blocked rather than folded into a
// result.
package evaluation_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/evaluation"
	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/investigation"
	"github.com/vorash/vora-probe/models"
)

func relationsRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(fixtures.Root(), "relations")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("relations fixtures are missing: %v", err)
	}
	return root
}

// TestDeterministicArmAnswersEveryAuthoredCase is the integrity check for the
// suite itself: if the rules cannot agree with a case's stated rationale, the
// case is wrong rather than the arm.
func TestDeterministicArmAnswersEveryAuthoredCase(t *testing.T) {
	dev, heldOut, err := evaluation.LoadSplits(relationsRoot(t))
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	cases := append(append([]evaluation.Case{}, dev...), heldOut...)
	set, err := evaluation.BuildArms(models.Config{}, nil, time.Now).Select(nil)
	if err != nil {
		t.Fatalf("build arms: %v", err)
	}
	deterministic, err := set.Select([]string{investigation.DeterministicArm})
	if err != nil {
		t.Fatalf("select: %v", err)
	}

	outcomes, err := evaluation.RunSuite(context.Background(), evaluation.SuiteOptions{
		Cases: cases, Arms: deterministic.Arms, Repeat: 3,
	})
	if err != nil {
		t.Fatalf("run suite: %v", err)
	}
	for _, o := range outcomes {
		if o.Status != investigation.CallOK {
			t.Errorf("%s: %s", o.CaseID, o.Failure)
			continue
		}
		if !o.Agreed {
			t.Errorf("%s (%s split): the rules answered %s, the case says %s",
				o.CaseID, o.Split, o.Got, o.Expected)
		}
		if o.Unsupported {
			t.Errorf("%s: the rules asserted an unsupported cause", o.CaseID)
		}
	}
	summary := evaluation.Summarize(outcomes, nil)[0]
	if summary.Agreements != len(cases)*3 {
		t.Fatalf("agreements = %d of %d", summary.Agreements, len(cases)*3)
	}
}

// TestUnconfiguredArmsAreBlockedNotSubstituted is the honesty check: with no
// endpoints configured, the two model arms must be reported as blocked and must
// not produce labels that could be mistaken for measurements.
func TestUnconfiguredArmsAreBlockedNotSubstituted(t *testing.T) {
	dev, _, err := evaluation.LoadSplits(relationsRoot(t))
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	t.Setenv("VORA_PROBE_MODEL_BASE_URL", "")
	t.Setenv("VORA_PROBE_JEV_BASE_URL", "")
	cfg := models.ConfigFromEnv()
	set, err := evaluation.BuildArms(cfg, nil, time.Now).Select(nil)
	if err != nil {
		t.Fatalf("build arms: %v", err)
	}
	if len(set.Arms) != 3 {
		t.Fatalf("arms = %d, want 3 (deterministic plus two blocked)", len(set.Arms))
	}

	outcomes, err := evaluation.RunSuite(context.Background(), evaluation.SuiteOptions{
		Cases: dev[:1], Arms: set.Arms, Repeat: 2,
	})
	if err != nil {
		t.Fatalf("run suite: %v", err)
	}
	report := evaluation.Build("relations", models.Version, set.Infos, outcomes, nil, nil, 2)

	byArm := map[string]evaluation.ArmSummary{}
	for _, s := range report.Fixed {
		byArm[s.Arm] = s
	}
	for _, arm := range []string{investigation.BaselineArm, investigation.JevArm} {
		s := byArm[arm]
		if s.Blocked == "" {
			t.Errorf("%s should be reported as blocked", arm)
		}
		if s.ValidRuns != 0 || s.Agreements != 0 {
			t.Errorf("%s produced results without an endpoint: %+v", arm, s)
		}
	}
	if got := byArm[investigation.DeterministicArm]; got.Agreements != 2 {
		t.Errorf("the deterministic arm should still have run: %+v", got)
	}

	md := report.Markdown()
	if !strings.Contains(md, "blocked, not measured") {
		t.Error("the report must distinguish an unmeasured arm from a wrong one")
	}
	if !strings.Contains(md, "no known price") && !strings.Contains(md, "n/a, no model calls") {
		t.Error("cost must be reported as unknown or inapplicable, never guessed")
	}
}

// TestWholeLoopComparisonMatchesGroundTruth runs the loop half of the comparison
// over the OOM fixtures with the reviewed arm.
func TestWholeLoopComparisonMatchesGroundTruth(t *testing.T) {
	fixtureRoot := filepath.Join(fixtures.Root(), "oom")
	dirs, err := fixtures.Cases(fixtureRoot)
	if err != nil {
		t.Fatalf("list fixtures: %v", err)
	}
	deterministic := evaluation.Arm{
		Evaluator: investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()},
	}
	summaries, err := evaluation.RunLoop(context.Background(), evaluation.LoopOptions{
		FixtureRoot: fixtureRoot,
		Arms:        []evaluation.Arm{deterministic},
		Repeat:      2,
		OutDir:      t.TempDir(),
		Replay:      probe.ReplayWithArm,
	})
	if err != nil {
		t.Fatalf("run loop: %v", err)
	}
	if len(summaries) != 1 {
		t.Fatalf("summaries = %d, want 1", len(summaries))
	}
	s := summaries[0]
	wantRuns := len(dirs) * 2
	if s.Runs != wantRuns {
		t.Fatalf("runs = %d, want %d", s.Runs, wantRuns)
	}
	if s.LeadingCorrect != wantRuns {
		t.Errorf("leading claim correct on %d of %d runs: %v", s.LeadingCorrect, wantRuns, s.Errors)
	}
	if s.UnsafeRecommendations != 0 {
		t.Errorf("a recommendation was proposed on %d runs whose cause is not established", s.UnsafeRecommendations)
	}
	if s.TraceabilityFailures != 0 {
		t.Errorf("traceability failed on %d runs", s.TraceabilityFailures)
	}
	if s.Failures != 0 {
		t.Errorf("unexpected failures: %v", s.Errors)
	}
	if s.BudgetExhausted != 0 {
		t.Errorf("the reviewed arm exhausted its budget on %d runs", s.BudgetExhausted)
	}
}

// TestReportStatesItsLimits keeps the honesty requirements in one place.
func TestReportStatesItsLimits(t *testing.T) {
	report := evaluation.Build("relations", models.Version, []evaluation.ArmInfo{
		{Arm: investigation.DeterministicArm, Version: "relations/v1", Configured: true},
	}, nil, nil, nil, 3)
	md := report.Markdown()
	for _, want := range []string{
		"no statistical claim",
		"not the probability that a label or a root cause is correct",
		"Held constant across arms",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("the comparison output must state %q", want)
		}
	}
}
