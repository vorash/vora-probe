package evaluation

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
)

var update = flag.Bool("update", false, "re-freeze case payload digests and rewrite the case files")

func Root() string { return filepath.Join("..", "..", "test", "fixtures", "relations") }

// refreeze re-signs every case without validating first, because validation is
// exactly what a changed payload is expected to fail until it is re-signed.
func refreeze(t *testing.T) {
	t.Helper()
	for _, split := range []string{SplitDev, SplitHeldOut} {
		dir := filepath.Join(Root(), split)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", split, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			var c Case
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("decode %s: %v", e.Name(), err)
			}
			Sign(&c)
			if err := WriteCase(dir, c); err != nil {
				t.Fatalf("write %s: %v", e.Name(), err)
			}
		}
	}
}

// TestCaseIntegrity freezes and verifies every case. Run with -update after
// intentionally changing a payload.
func TestCaseIntegrity(t *testing.T) {
	if *update {
		refreeze(t)
	}
	root := Root()
	dev, heldOut, err := LoadSplits(root)
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	if len(dev) < 3 {
		t.Errorf("expected at least three development cases, found %d", len(dev))
	}
	if len(heldOut) < 3 {
		t.Errorf("expected at least three held-out cases, found %d", len(heldOut))
	}
	for _, split := range []string{SplitDev, SplitHeldOut} {
		dir := filepath.Join(root, split)
		cases, err := LoadCases(dir)
		if err != nil {
			t.Fatalf("%s: %v", split, err)
		}
		for _, c := range cases {
			if err := c.Validate(dir); err != nil {
				t.Errorf("%s/%s: %v", split, c.ID, err)
			}
			observations, err := c.Observations()
			if err != nil {
				t.Errorf("%s/%s: %v", split, c.ID, err)
				continue
			}
			found := false
			for _, o := range observations {
				if o.ID == c.Target {
					found = true
				}
			}
			if !found {
				t.Errorf("%s/%s: target %s is not among the normalized observations", split, c.ID, c.Target)
			}
		}
	}
}

// TestCaseIntegrityCatchesTampering proves the digest check is load-bearing.
func TestCaseIntegrityCatchesTampering(t *testing.T) {
	dir := filepath.Join(Root(), SplitDev)
	cases, err := LoadCases(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	c := cases[0]
	if err := c.Validate(dir); err != nil {
		t.Fatalf("baseline case should validate: %v", err)
	}
	c.Evidence[0].Response.Payload = []byte(`{"namespace":"lab","pods":[]}`)
	if err := c.Validate(dir); err == nil {
		t.Fatal("a payload edited without re-freezing its digest must fail validation")
	}
}

// fakeArm is a controllable evaluator, so the harness itself can be tested
// without a model or a network.
type fakeArm struct {
	name    string
	version string
	fail    error
	// labels maps observation id to label. A missing entry leaves an observation
	// unlabelled, which the harness must refuse.
	labels map[string]string
	remote bool
}

func (f fakeArm) Arm() string        { return f.name }
func (f fakeArm) ArmVersion() string { return f.version }

func (f fakeArm) Label(h investigation.Hypothesis, _ investigation.Facts, obs map[string]investigation.Observation) ([]investigation.RelationDraft, []investigation.EvaluatorCall, error) {
	call := investigation.EvaluatorCall{
		SchemaVersion: gateway.SchemaVersion, Arm: f.name, ArmVersion: f.version,
		Remote: f.remote, Hypothesis: h.ID, Observations: len(obs), Status: investigation.CallOK,
	}
	if f.fail != nil {
		call.Status = investigation.CallFailed
		call.Reason = f.fail.Error()
		return nil, []investigation.EvaluatorCall{call}, f.fail
	}
	var drafts []investigation.RelationDraft
	for id := range obs {
		label, ok := f.labels[id]
		if !ok {
			continue
		}
		relationship, err := relationshipFor(label)
		if err != nil {
			return nil, []investigation.EvaluatorCall{call}, err
		}
		drafts = append(drafts, investigation.RelationDraft{Observation: id, Relationship: relationship, Reason: "fake"})
	}
	return drafts, []investigation.EvaluatorCall{call}, nil
}

func relationshipFor(label string) (investigation.Relationship, error) {
	switch label {
	case "supports":
		return investigation.Supports, nil
	case "contradicts":
		return investigation.Contradicts, nil
	case "neutral":
		return investigation.Neutral, nil
	case "insufficient_context":
		return investigation.InsufficientContext, nil
	default:
		return "", &unknownLabel{label}
	}
}

type unknownLabel struct{ label string }

func (e *unknownLabel) Error() string { return "unknown label " + e.label }

// labelCase builds an arm answer for one case: the target gets the wanted label
// and every other piece of evidence is neutral, so a multi-evidence case is
// labelled in full.
func labelCase(t *testing.T, c Case, target string) map[string]string {
	t.Helper()
	observations, err := c.Observations()
	if err != nil {
		t.Fatalf("observations: %v", err)
	}
	labels := map[string]string{}
	for _, o := range observations {
		labels[o.ID] = "neutral"
	}
	labels[c.Target] = target
	return labels
}

func runOne(t *testing.T, c Case, arm Arm, repeat int) []Outcome {
	t.Helper()
	outcomes, err := RunSuite(context.Background(), SuiteOptions{Cases: []Case{c}, Arms: []Arm{arm}, Repeat: repeat, Now: time.Now})
	if err != nil {
		t.Fatalf("run suite: %v", err)
	}
	return outcomes
}

// TestRunSuiteOverEveryCase answers every case the way its rationale says it
// should be answered, and requires a perfect result. A case that cannot be
// answered correctly by its own stated rationale is a bad case.
func TestRunSuiteOverEveryCase(t *testing.T) {
	dev, heldOut, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	for _, c := range append(append([]Case{}, dev...), heldOut...) {
		arm := Arm{Evaluator: fakeArm{name: "fake", version: "v1", labels: labelCase(t, c, c.Expected)}}
		outcomes := runOne(t, c, arm, 3)
		summary := Summarize(outcomes, nil)[0]
		if summary.Agreements != 3 || summary.Failures != 0 {
			t.Errorf("%s: agreed %d/3 with %d failures (%s)", c.ID, summary.Agreements, summary.Failures, outcomes[0].Failure)
		}
		if summary.Unsupported != 0 {
			t.Errorf("%s: an expected answer must not count as an unsupported cause", c.ID)
		}
	}
}

func TestRunSuiteCountsUnsupportedSupports(t *testing.T) {
	dev, heldOut, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	all := append(append([]Case{}, dev...), heldOut...)
	wantUnsupported := 0
	wantAgreed := 0
	var got []Outcome
	for _, c := range all {
		// Answer every target with "supports", whatever the case expects.
		arm := Arm{Evaluator: fakeArm{name: "fake", version: "v1", labels: labelCase(t, c, "supports")}}
		got = append(got, runOne(t, c, arm, 2)...)
		if c.Expected != "supports" {
			wantUnsupported += 2
		} else {
			wantAgreed += 2
		}
	}
	summary := Summarize(got, nil)[0]
	if summary.Unsupported != wantUnsupported {
		t.Errorf("unsupported supports = %d, want %d", summary.Unsupported, wantUnsupported)
	}
	if summary.Agreements != wantAgreed {
		t.Errorf("agreements = %d, want %d", summary.Agreements, wantAgreed)
	}
	if summary.Cases != len(all) || summary.Attempts != len(all)*2 {
		t.Errorf("cases = %d attempts = %d, want %d and %d", summary.Cases, summary.Attempts, len(all), len(all)*2)
	}
}

func TestUnstableArmIsReported(t *testing.T) {
	dev, _, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	c := dev[0]
	// Alternate between the expected label and another one across repeats.
	counter := 0
	arm := Arm{Evaluator: alternatingArm{Case: c, n: &counter}}
	outcomes := runOne(t, c, arm, 4)
	report := Build("relations", "labels/v1", nil, outcomes, nil, nil, 4)
	if len(report.Unstable) != 1 {
		t.Fatalf("an arm that answers differently across repeats must be reported as unstable, got %+v", report.Unstable)
	}
	if report.Unstable[0].CaseID != c.ID || report.Unstable[0].Disagreed != 2 {
		t.Fatalf("unexpected instability record: %+v", report.Unstable[0])
	}
}

// alternatingArm disagrees with the expected label on every other run.
type alternatingArm struct {
	Case Case
	// n is a pointer because the evaluator is passed by value: a value counter
	// would reset on every call and the arm would look stable.
	n *int
}

func (a alternatingArm) Arm() string        { return "flaky" }
func (a alternatingArm) ArmVersion() string { return "v1" }

func (a alternatingArm) Label(h investigation.Hypothesis, _ investigation.Facts, obs map[string]investigation.Observation) ([]investigation.RelationDraft, []investigation.EvaluatorCall, error) {
	*a.n++
	label := a.Case.Expected
	if *a.n%2 == 0 {
		label = "neutral"
		if a.Case.Expected == "neutral" {
			label = "insufficient_context"
		}
	}
	labels := map[string]string{}
	for id := range obs {
		labels[id] = "neutral"
	}
	labels[a.Case.Target] = label
	var drafts []investigation.RelationDraft
	for id, l := range labels {
		rel, err := relationshipFor(l)
		if err != nil {
			return nil, nil, err
		}
		drafts = append(drafts, investigation.RelationDraft{Observation: id, Relationship: rel, Reason: "alternating"})
	}
	return drafts, nil, nil
}

func TestRunSuiteRefusesPartialLabelling(t *testing.T) {
	dev, _, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	var multi Case
	for _, c := range dev {
		if len(c.Evidence) > 1 {
			multi = c
			break
		}
	}
	if multi.ID == "" {
		t.Fatal("expected at least one case with context evidence")
	}
	arm := Arm{Evaluator: fakeArm{name: "fake", version: "v1", labels: map[string]string{multi.Target: "neutral"}}}
	outcomes := runOne(t, multi, arm, 1)
	if outcomes[0].Status == investigation.CallOK {
		t.Fatalf("an arm that leaves evidence unlabelled must not be recorded as valid: %+v", outcomes[0])
	}
	if !strings.Contains(outcomes[0].Failure, "unlabelled") {
		t.Fatalf("the failure should say what was left unlabelled, got %q", outcomes[0].Failure)
	}
}

func TestRunSuiteRefusesInventedEvidence(t *testing.T) {
	dev, _, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	c := dev[0]
	arm := Arm{Evaluator: inventingArm{Case: c}}
	outcomes := runOne(t, c, arm, 1)
	if outcomes[0].Status == investigation.CallOK {
		t.Fatalf("an arm that labels evidence it was not given must not be recorded as valid: %+v", outcomes[0])
	}
}

type inventingArm struct{ Case Case }

func (a inventingArm) Arm() string        { return "inventing" }
func (a inventingArm) ArmVersion() string { return "v1" }

func (a inventingArm) Label(_ investigation.Hypothesis, _ investigation.Facts, obs map[string]investigation.Observation) ([]investigation.RelationDraft, []investigation.EvaluatorCall, error) {
	drafts := []investigation.RelationDraft{{Observation: "OBS-9999", Relationship: investigation.Supports, Reason: "invented"}}
	for id := range obs {
		drafts = append(drafts, investigation.RelationDraft{Observation: id, Relationship: investigation.Neutral, Reason: "real"})
	}
	return drafts, nil, nil
}

func TestCostIsReportedOnlyWhenKnown(t *testing.T) {
	dev, _, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	arm := Arm{Evaluator: fakeArm{name: "baseline", version: "v1", labels: map[string]string{dev[0].Target: "neutral"}, remote: true}}
	outcomes, err := RunSuite(context.Background(), SuiteOptions{Cases: dev[:1], Arms: []Arm{arm}})
	if err != nil {
		t.Fatalf("run suite: %v", err)
	}
	report := Build("relations", "labels/v1", []ArmInfo{{Arm: "baseline", Version: "v1", Configured: true}}, outcomes, nil, nil, 1)
	if report.Fixed[0].EstimatedCostUSD != nil {
		t.Fatal("an unknown price must not produce a cost")
	}
	if !strings.Contains(report.Markdown(), "no known price") {
		t.Fatal("the report should say that the price is unknown")
	}

	priced := Build("relations", "labels/v1", []ArmInfo{{Arm: "baseline", Version: "v1", Configured: true}},
		outcomes, map[string]TokenPrice{"baseline": {USDPerMillionPrompt: 1, USDPerMillionCompletion: 2}}, nil, 1)
	if priced.Fixed[0].EstimatedCostUSD == nil {
		t.Fatal("a known price should produce a cost")
	}
}

func TestReportNeverClaimsSignificance(t *testing.T) {
	dev, _, err := LoadSplits(Root())
	if err != nil {
		t.Fatalf("load splits: %v", err)
	}
	arm := Arm{Evaluator: fakeArm{name: "baseline", version: "v1", labels: map[string]string{dev[0].Target: "neutral"}}}
	outcomes, err := RunSuite(context.Background(), SuiteOptions{Cases: dev[:1], Arms: []Arm{arm}})
	if err != nil {
		t.Fatalf("run suite: %v", err)
	}
	report := Build("relations", "labels/v1", nil, outcomes, nil, nil, 1)
	md := report.Markdown()
	for _, want := range []string{"Held constant", "Confusion counts", "Fixed-input classification"} {
		if !strings.Contains(md, want) {
			t.Errorf("the report should contain %q", want)
		}
	}
	if !strings.Contains(md, "no statistical claim") {
		t.Error("the report must state that it makes no statistical claim")
	}
}
