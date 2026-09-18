package evaluation

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/vorash/vora-probe/investigation"
)

// Arm is a named relation evaluator plus how it is reported.
type Arm struct {
	Evaluator investigation.RelationEvaluator
	// Blocked is set when the arm cannot run at all, for example because its
	// endpoint is not configured. A blocked arm is reported as blocked; it is
	// never quietly replaced by another arm.
	Blocked string
	// CostPerMillionTokens is USD per million tokens, used only when known.
	CostPerMillionTokens *TokenPrice
}

func (a Arm) Name() string {
	if a.Evaluator == nil {
		return "unconfigured"
	}
	return a.Evaluator.Arm()
}

// Outcome is one arm answering one case once.
type Outcome struct {
	CaseID      string                        `json:"case_id"`
	Split       string                        `json:"split"`
	Repeat      int                           `json:"repeat"`
	Arm         string                        `json:"arm"`
	ArmVersion  string                        `json:"arm_version"`
	Expected    string                        `json:"expected"`
	Got         string                        `json:"got"`
	Agreed      bool                          `json:"agreed"`
	Unsupported bool                          `json:"unsupported_support"`
	Reason      string                        `json:"reason,omitempty"`
	Status      investigation.CallStatus      `json:"status"`
	Calls       []investigation.EvaluatorCall `json:"calls,omitempty"`
	DurationMS  int64                         `json:"duration_ms"`
	Failure     string                        `json:"failure,omitempty"`
}

// SuiteOptions configures a fixed-input run.
type SuiteOptions struct {
	Cases  []Case
	Arms   []Arm
	Repeat int
	Now    func() time.Time
}

// RunSuite asks every arm every case, Repeat times, at fixed input.
//
// Repetition is for variance, not for significance: with authored cases, running
// three times shows whether an arm is stable, and nothing more than that.
func RunSuite(ctx context.Context, opts SuiteOptions) ([]Outcome, error) {
	repeat := opts.Repeat
	if repeat <= 0 {
		repeat = 1
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	var outcomes []Outcome
	for _, arm := range opts.Arms {
		for _, c := range opts.Cases {
			for r := 1; r <= repeat; r++ {
				if err := ctx.Err(); err != nil {
					return outcomes, err
				}
				outcomes = append(outcomes, runCase(arm, c, r, now))
			}
		}
	}
	return outcomes, nil
}

func runCase(arm Arm, c Case, repeat int, now func() time.Time) Outcome {
	base := Outcome{
		CaseID:     c.ID,
		Split:      c.Split,
		Repeat:     repeat,
		Arm:        arm.Name(),
		ArmVersion: armVersion(arm),
		Expected:   c.Expected,
	}
	if arm.Blocked != "" {
		base.Status = investigation.CallFailed
		base.Failure = arm.Blocked
		return base
	}

	observations, err := c.Observations()
	if err != nil {
		base.Status = investigation.CallInvalid
		base.Failure = err.Error()
		return base
	}
	hypothesis := c.AsHypothesis()
	byID := map[string]investigation.Observation{}
	for _, o := range observations {
		byID[o.ID] = o
	}
	facts := investigation.BuildFacts(c.Entity, observations)

	started := now()
	drafts, calls, err := arm.Evaluator.Label(hypothesis, facts, byID)
	base.DurationMS = now().Sub(started).Milliseconds()
	base.Calls = calls
	if err != nil {
		base.Status = investigation.CallFailed
		base.Failure = err.Error()
		return base
	}
	// The arm must label every piece of evidence it was given: silently skipping
	// the inconvenient ones is the failure mode this repository exists to catch.
	labelled := map[string]investigation.RelationDraft{}
	for _, d := range drafts {
		if _, ok := byID[d.Observation]; !ok {
			base.Status = investigation.CallInvalid
			base.Failure = fmt.Sprintf("the arm labelled %q, which was not among the evidence it was given", d.Observation)
			return base
		}
		labelled[d.Observation] = d
	}
	for id := range byID {
		if _, ok := labelled[id]; !ok {
			base.Status = investigation.CallInvalid
			base.Failure = fmt.Sprintf("the arm left %s unlabelled", id)
			return base
		}
	}

	target, ok := labelled[c.Target]
	if !ok {
		base.Status = investigation.CallInvalid
		base.Failure = fmt.Sprintf("the arm did not label the target observation %s", c.Target)
		return base
	}
	base.Status = investigation.CallOK
	base.Got = CanonicalLabel(target.Relationship)
	base.Reason = target.Reason
	base.Agreed = base.Got == base.Expected
	base.Unsupported = base.Got == "supports" && c.Expected != "supports"
	return base
}

func armVersion(arm Arm) string {
	if arm.Evaluator == nil {
		return ""
	}
	return arm.Evaluator.ArmVersion()
}

// Confusion is the full count matrix, not a summary statistic. With small
// authored suites the matrix is the result.
type Confusion struct {
	Labels [][]int
	Index  map[string]int
	Order  []string
}

func NewConfusion() Confusion {
	order := append([]string{}, labels...)
	index := make(map[string]int, len(order))
	for i, l := range order {
		index[l] = i
	}
	matrix := make([][]int, len(order))
	for i := range matrix {
		matrix[i] = make([]int, len(order))
	}
	return Confusion{Labels: matrix, Index: index, Order: order}
}

func (c Confusion) Add(expected, got string) {
	i, ok := c.Index[expected]
	if !ok {
		return
	}
	j, ok := c.Index[got]
	if !ok {
		return
	}
	c.Labels[i][j]++
}

// ArmSummary is one arm's results.
type ArmSummary struct {
	Arm              string  `json:"arm"`
	ArmVersion       string  `json:"arm_version"`
	Blocked          string  `json:"blocked,omitempty"`
	Cases            int     `json:"cases"`
	Repeats          int     `json:"repeats"`
	Attempts         int     `json:"attempts"`
	Agreements       int     `json:"agreements"`
	AgreementRate    float64 `json:"agreement_rate"`
	Unsupported      int     `json:"unsupported_supports"`
	Failures         int     `json:"failures"`
	ValidRuns        int     `json:"valid_runs"`
	InsufficientExp  int     `json:"insufficient_expected"`
	InsufficientOK   int     `json:"insufficient_answered_correctly"`
	PromptTokens     int     `json:"prompt_tokens"`
	CompletionTokens int     `json:"completion_tokens"`
	LatencyMS        int64   `json:"latency_ms"`
	// Remote records whether the arm reached a model service at all. The
	// deterministic arm does not, so a zero token count for it means "no model
	// calls" rather than "a model call that cost nothing".
	Remote           bool     `json:"remote"`
	EstimatedCostUSD *float64 `json:"estimated_cost_usd,omitempty"`
	Confusion        [][]int  `json:"confusion"`
	// confusion accumulates unexported, so it never appears twice in the JSON.
	confusion Confusion
	// DisagreementsPerCase counts how many of the repeats disagreed, which shows
	// whether an arm is unstable rather than merely wrong.
	DisagreementsPerCase map[string]int `json:"disagreements_per_case,omitempty"`
	Errors               []string       `json:"errors,omitempty"`

	seenCases map[string]bool
}

// Summarize reduces outcomes to per-arm counts. Cost is filled in only for arms
// whose price is known; an unknown price is reported as absent rather than
// guessed.
func Summarize(outcomes []Outcome, prices map[string]TokenPrice) []ArmSummary {
	byArm := map[string]*ArmSummary{}
	order := []string{}
	for _, o := range outcomes {
		s, ok := byArm[o.Arm]
		if !ok {
			s = &ArmSummary{
				Arm: o.Arm, ArmVersion: o.ArmVersion,
				Confusion:            [][]int{},
				DisagreementsPerCase: map[string]int{},
				seenCases:            map[string]bool{},
			}
			s.confusion = NewConfusion()
			byArm[o.Arm] = s
			order = append(order, o.Arm)
		}
		if s.Blocked == "" && o.Failure != "" && o.Status == investigation.CallFailed {
			s.Blocked = o.Failure
			s.Errors = append(s.Errors, o.Failure)
		}
		s.Attempts++
		s.seenCases[o.CaseID] = true
		s.confusion.Add(o.Expected, o.Got)
		if o.Status == investigation.CallOK {
			s.ValidRuns++
		} else {
			s.Failures++
			if o.Failure != "" {
				s.Errors = append(s.Errors, o.Failure)
			}
		}
		if o.Agreed {
			s.Agreements++
		}
		if o.Unsupported {
			s.Unsupported++
		}
		if o.Expected == "insufficient_context" {
			s.InsufficientExp++
			if o.Got == "insufficient_context" {
				s.InsufficientOK++
			}
		}
		if !o.Agreed && o.Status == investigation.CallOK {
			s.DisagreementsPerCase[o.CaseID]++
		}
		for _, call := range o.Calls {
			s.PromptTokens += call.PromptTokens
			s.CompletionTokens += call.CompletionTokens
			if call.Remote {
				s.Remote = true
			}
		}
		s.LatencyMS += o.DurationMS
	}
	sort.Strings(order)
	summaries := make([]ArmSummary, 0, len(order))
	for _, name := range order {
		s := byArm[name]
		if s.Attempts > 0 {
			s.AgreementRate = float64(s.Agreements) / float64(s.Attempts)
		}
		s.Cases = len(s.seenCases)
		s.Confusion = s.confusion.Labels
		s.Errors = dedupe(s.Errors)
		if price, ok := prices[name]; ok {
			cost := price.Cost(s.PromptTokens, s.CompletionTokens)
			s.EstimatedCostUSD = &cost
		}
		summaries = append(summaries, *s)
	}
	return summaries
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// RecordedTransport answers from a fixed table, so the arms can be tested and the
// harness demonstrated without a credential. It is test and dry-run only; a live
// run uses HTTPTransport.
type RecordedTransport struct {
	Responses map[string][]byte
	Status    int
}

func (t *RecordedTransport) Do(_ context.Context, _, url string, _ map[string]string, _ []byte, _ int64) (int, []byte, error) {
	if raw, ok := t.Responses[url]; ok {
		status := t.Status
		if status == 0 {
			status = 200
		}
		return status, raw, nil
	}
	return 404, []byte(`{"error":"not recorded"}`), nil
}
