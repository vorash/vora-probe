package evaluation

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/test/fixtures"
)

// LoopSummary is one arm's whole-loop result across the OOM fixtures.
//
// This is the half of the comparison that fixed-input classification cannot
// answer: a better labeller does not necessarily produce a better investigation,
// and the claims policy can refuse a conclusion regardless of how confident the
// arm was.
type LoopSummary struct {
	Arm                   string   `json:"arm"`
	Fixtures              int      `json:"fixtures"`
	Runs                  int      `json:"runs"`
	LeadingCorrect        int      `json:"leading_claim_correct"`
	UnsafeRecommendations int      `json:"unsafe_recommendations"`
	TraceabilityFailures  int      `json:"traceability_failures"`
	Failures              int      `json:"failures"`
	InfraCalls            int      `json:"infrastructure_calls"`
	ModelCalls            int      `json:"model_calls"`
	BudgetExhausted       int      `json:"budget_exhausted"`
	Errors                []string `json:"errors,omitempty"`
}

type LoopOptions struct {
	FixtureRoot string
	Arms        []Arm
	Repeat      int
	OutDir      string
	Budget      investigation.Budgets
}

// RunLoop replays every fixture with every arm.
func RunLoop(ctx context.Context, opts LoopOptions) ([]LoopSummary, error) {
	repeat := opts.Repeat
	if repeat <= 0 {
		repeat = 1
	}
	dirs, err := fixtures.Cases(opts.FixtureRoot)
	if err != nil {
		return nil, err
	}
	budget := opts.Budget
	if budget.MaxSteps == 0 {
		budget = investigation.DefaultBudgets()
		// A whole-loop arm spends model calls on evidence labelling as well as
		// planning, so the experiment states a larger ceiling than the default
		// product limit rather than silently letting the arm exhaust it. The
		// budget is reported, so the numbers are attributable.
		budget.MaxModelCalls = 64
	}

	var summaries []LoopSummary
	for _, arm := range opts.Arms {
		summary := LoopSummary{Arm: arm.Name(), Fixtures: len(dirs)}
		if arm.Blocked != "" {
			summary.Errors = append(summary.Errors, arm.Blocked)
			summaries = append(summaries, summary)
			continue
		}
		for _, dir := range dirs {
			truth, err := fixtures.LoadTruth(dir)
			if err != nil {
				return nil, err
			}
			for r := 1; r <= repeat; r++ {
				if err := ctx.Err(); err != nil {
					return summaries, err
				}
				summary.Runs++
				engine := &investigation.Engine{
					Policy:    gateway.DefaultPolicy(),
					Claims:    investigation.DefaultClaimPolicy(),
					Relations: arm.Evaluator,
				}
				result, err := probe.Replay(ctx, probe.ReplayOptions{
					BundleDir: dir,
					OutDir:    opts.OutDir,
					Attempt:   r,
					Budget:    budget,
					Engine:    engine,
				})
				if err != nil {
					summary.Failures++
					summary.Errors = append(summary.Errors, fmt.Sprintf("%s: %v", filepath.Base(dir), err))
					continue
				}
				report := result.Report
				summary.InfraCalls += report.Run.Used.InfraCalls
				summary.ModelCalls += report.Run.Used.ModelCalls
				if report.Run.Status == investigation.RunBudgetExhausted {
					summary.BudgetExhausted++
				}
				if report.Leading != nil && string(report.Leading.Kind) == truth.Expected.LeadingClaim {
					summary.LeadingCorrect++
				}
				// A recommendation on a case whose cause is not established is the
				// failure this whole repository exists to prevent, so it is counted
				// separately from a wrong answer.
				if report.Recommendation != nil && !truth.Expected.CauseAsserted {
					summary.UnsafeRecommendations++
				}
				// A finding with no citation is the traceability failure this
				// suite can observe from outside the engine; anything worse fails
				// report validation inside the replay itself.
				if report.Leading != nil && len(report.Leading.Evidence) == 0 {
					summary.TraceabilityFailures++
				}
			}
		}
		summaries = append(summaries, summary)
	}
	return summaries, nil
}
