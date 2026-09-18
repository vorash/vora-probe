package evaluation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
)

// Report is the comparison output.
//
// It reports counts and spreads, never significance. With a handful of authored
// cases, "the baseline agreed with the expected label on 9 of 12 attempts and the
// deterministic rules on 12 of 12" is a fact; "the baseline is significantly
// worse" would not be.
type Report struct {
	SchemaVersion string          `json:"schema_version"`
	GeneratedAt   time.Time       `json:"generated_at"`
	Suite         string          `json:"suite"`
	LabelVersion  string          `json:"label_version"`
	HeldConstant  []string        `json:"held_constant"`
	Arms          []ArmInfo       `json:"arms"`
	Fixed         []ArmSummary    `json:"fixed_input"`
	Confusion     []ConfusionView `json:"confusion"`
	Unstable      []UnstableCase  `json:"unstable_cases,omitempty"`
	Loop          []LoopSummary   `json:"whole_loop,omitempty"`
	Notes         []string        `json:"notes"`
}

// ArmInfo records how each arm was configured, including the arms that could not
// run. A blocked arm is part of the result, not an omission.
type ArmInfo struct {
	Arm        string `json:"arm"`
	Version    string `json:"version"`
	Model      string `json:"model,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Configured bool   `json:"configured"`
	Blocked    string `json:"blocked,omitempty"`
	PriceKnown bool   `json:"price_known"`
}

type ConfusionView struct {
	Arm    string   `json:"arm"`
	Labels []string `json:"labels"`
	Counts [][]int  `json:"counts"`
}

// UnstableCase is a case where repeats disagreed with each other. Instability is
// reported separately from disagreement with the expected label: an arm that
// answers differently each run is unusable even when its average looks fine.
type UnstableCase struct {
	Arm       string `json:"arm"`
	CaseID    string `json:"case_id"`
	Split     string `json:"split"`
	Disagreed int    `json:"disagreements"`
	Attempts  int    `json:"attempts"`
}

// Build assembles the report from fixed-input outcomes and optional loop results.
func Build(suite, labelVersion string, arms []ArmInfo, outcomes []Outcome, prices map[string]TokenPrice, loop []LoopSummary, attemptsPerCase int) Report {
	report := Report{
		SchemaVersion: gateway.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Suite:         suite,
		LabelVersion:  labelVersion,
		Arms:          arms,
		Fixed:         Summarize(outcomes, prices),
		Loop:          loop,
		HeldConstant: []string{
			"planner and its recorded turns",
			"evidence, normalized by the same code path as a live run",
			"label definitions and label version",
			"claims policy, which runs after the arm and cannot be overridden by it",
		},
	}
	for _, s := range report.Fixed {
		report.Confusion = append(report.Confusion, ConfusionView{Arm: s.Arm, Labels: labels, Counts: s.Confusion})
	}

	byArmCase := map[string]map[string]int{}
	for _, o := range outcomes {
		if byArmCase[o.Arm] == nil {
			byArmCase[o.Arm] = map[string]int{}
		}
		if !o.Agreed && o.Status == "ok" {
			byArmCase[o.Arm][o.CaseID]++
		}
	}
	splitOf := map[string]string{}
	for _, o := range outcomes {
		splitOf[o.CaseID] = o.Split
	}
	for arm, cases := range byArmCase {
		for id, disagreed := range cases {
			if disagreed > 1 {
				report.Unstable = append(report.Unstable, UnstableCase{
					Arm: arm, CaseID: id, Split: splitOf[id],
					Disagreed: disagreed, Attempts: attemptsPerCase,
				})
			}
		}
	}
	sort.Slice(report.Unstable, func(i, j int) bool {
		if report.Unstable[i].Arm != report.Unstable[j].Arm {
			return report.Unstable[i].Arm < report.Unstable[j].Arm
		}
		return report.Unstable[i].CaseID < report.Unstable[j].CaseID
	})

	for _, arm := range arms {
		if arm.Blocked != "" {
			report.Notes = append(report.Notes, fmt.Sprintf(
				"arm %s is blocked and produced no result: %s", arm.Arm, arm.Blocked))
		}
		if !arm.PriceKnown {
			report.Notes = append(report.Notes, fmt.Sprintf(
				"arm %s has no known price, so no cost is reported for it", arm.Arm))
		}
	}
	report.Notes = append(report.Notes,
		"confidence returned by a model is the concentration of its answer distribution; it is not the probability that a label or a root cause is correct",
		"counts and spreads only: with this many authored cases, no statistical claim is supported",
	)
	return report
}

// Markdown renders the comparison for a reader who will not open the JSON.
func (r Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Evaluator comparison: %s\n\n", r.Suite)
	fmt.Fprintf(&b, "- generated: %s\n- label version: %s\n- schema: %s\n\n", r.GeneratedAt.Format(time.RFC3339), r.LabelVersion, r.SchemaVersion)

	b.WriteString("## Held constant across arms\n\n")
	for _, line := range r.HeldConstant {
		fmt.Fprintf(&b, "- %s\n", line)
	}
	b.WriteString("\n## Arms\n\n")
	b.WriteString("| arm | version | model | endpoint | configured | blocked | price known |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- |\n")
	for _, a := range r.Arms {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %t | %s | %t |\n",
			a.Arm, a.Version, emptyDash(a.Model), emptyDash(a.Endpoint), a.Configured, emptyDash(a.Blocked), a.PriceKnown)
	}
	b.WriteString("\n")

	if len(r.Fixed) > 0 {
		b.WriteString("## Fixed-input classification\n\n")
		b.WriteString("| arm | status | cases | attempts | valid | failures | agreed | agreement | unsupported supports | insufficient-context accuracy | prompt tokens | completion tokens | ms | cost |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, s := range r.Fixed {
			fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %s | %d | %s | %d | %s | %d | %d | %d | %s |\n",
				s.Arm, status(s), s.Cases, s.Attempts, s.ValidRuns, failures(s), s.Agreements,
				percent(s.AgreementRate), s.Unsupported, insufficientRate(s), s.PromptTokens,
				s.CompletionTokens, s.LatencyMS, cost(s))
		}
		b.WriteString("\n")
	}

	if len(r.Confusion) > 0 {
		b.WriteString("## Confusion counts (expected down, answered across)\n\n")
		for _, c := range r.Confusion {
			fmt.Fprintf(&b, "**%s**\n\n", c.Arm)
			b.WriteString("| expected \\ answered | " + strings.Join(c.Labels, " | ") + " |\n")
			b.WriteString("| --- |" + strings.Repeat(" --- |", len(c.Labels)) + "\n")
			for i, label := range c.Labels {
				cells := make([]string, 0, len(c.Labels))
				for _, v := range c.Counts[i] {
					cells = append(cells, fmt.Sprintf("%d", v))
				}
				fmt.Fprintf(&b, "| %s | %s |\n", label, strings.Join(cells, " | "))
			}
			b.WriteString("\n")
		}
	}

	if len(r.Unstable) > 0 {
		b.WriteString("## Unstable cases\n\n")
		b.WriteString("| arm | case | split | disagreed | attempts |\n")
		b.WriteString("| --- | --- | --- | --- | --- |\n")
		for _, u := range r.Unstable {
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %d |\n", u.Arm, u.CaseID, u.Split, u.Disagreed, u.Attempts)
		}
		b.WriteString("\n")
	} else if len(r.Fixed) > 0 {
		b.WriteString("## Unstable cases\n\nNo case produced different answers across repeats.\n\n")
	}

	if len(r.Loop) > 0 {
		b.WriteString("## Whole-loop outcomes\n\n")
		b.WriteString("| arm | fixtures | runs | leading claim correct | unsafe recommendation | traceability failures | failures | infrastructure calls | model calls |\n")
		b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
		for _, l := range r.Loop {
			fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				l.Arm, l.Fixtures, l.Runs, l.LeadingCorrect, l.UnsafeRecommendations,
				l.TraceabilityFailures, l.Failures, l.InfraCalls, l.ModelCalls)
		}
		b.WriteString("\n")
	}

	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "- %s\n", n)
		}
	}
	return b.String()
}

func percent(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }

func insufficientRate(s ArmSummary) string {
	if s.InsufficientExp == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d", s.InsufficientOK, s.InsufficientExp)
}

// status distinguishes "not measured" from "measured and wrong". A blocked arm
// must never read as a bad arm.
func status(s ArmSummary) string {
	switch {
	case s.Blocked != "":
		return "blocked, not measured"
	case s.Failures > 0:
		return fmt.Sprintf("measured, %d failures", s.Failures)
	default:
		return "measured"
	}
}

// failures is blank for a blocked arm: it was never measured, so a count of
// attempted-and-blocked runs would read as a count of wrong answers.
func failures(s ArmSummary) string {
	if s.Blocked != "" {
		return "-"
	}
	return fmt.Sprintf("%d", s.Failures)
}

func cost(s ArmSummary) string {
	if !s.Remote {
		return "n/a, no model calls"
	}
	if s.EstimatedCostUSD == nil {
		return "unknown"
	}
	return fmt.Sprintf("$%.4f", *s.EstimatedCostUSD)
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
