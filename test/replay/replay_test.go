// Package replay_test is the step-2 acceptance suite: the whole loop, offline,
// against every frozen fixture, judged against the hidden answer key.
//
// These tests are the ones that would catch a regression in the thing Probe
// actually claims to do — refuse conclusions the evidence does not support.
package replay_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vorash/vora-probe/fixtures"
	"github.com/vorash/vora-probe/internal/probe"
	"github.com/vorash/vora-probe/internal/store"
	"github.com/vorash/vora-probe/investigation"
)

func cases(t *testing.T) []string {
	t.Helper()
	dirs, err := fixtures.Cases(filepath.Join(fixtures.Root(), "oom"))
	if err != nil {
		t.Fatalf("list cases: %v", err)
	}
	if len(dirs) < 4 {
		t.Fatalf("expected the four agreed cases, found %d", len(dirs))
	}
	return dirs
}

func replay(t *testing.T, dir string) probe.ReplayResult {
	t.Helper()
	result, err := probe.Replay(context.Background(), probe.ReplayOptions{BundleDir: dir, OutDir: t.TempDir()})
	if err != nil {
		t.Fatalf("replay %s: %v", dir, err)
	}
	return result
}

func TestReplayMeetsGroundTruth(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			result := replay(t, dir)
			truth, err := fixtures.LoadTruth(dir)
			if err != nil {
				t.Fatalf("load ground truth: %v", err)
			}
			report := result.Report

			if report.Run.Status != investigation.RunCompleted {
				t.Fatalf("run status = %q, want completed (%s)", report.Run.Status, report.Run.Reason)
			}
			if report.Leading == nil {
				t.Fatal("a completed run must state a leading finding, even if it is inconclusive")
			}
			if got := string(report.Leading.Kind); got != truth.Expected.LeadingClaim {
				t.Errorf("leading claim = %q, want %q", got, truth.Expected.LeadingClaim)
			}
			if !report.Leading.Allowed {
				t.Errorf("the leading claim must be admissible: %v", report.Leading.Reasons)
			}
			if !truth.Expected.CauseAsserted {
				// An inconclusive finding is a machine verdict. If the planner's
				// candidate text were echoed here, the report would present a cause
				// it explicitly could not establish.
				if !strings.Contains(report.Leading.Statement, "does not establish a cause") {
					t.Errorf("an inconclusive finding must be phrased as such, got %q", report.Leading.Statement)
				}
			}

			verdicts := map[string]investigation.ClaimReport{}
			for _, c := range report.Claims {
				verdicts[string(c.Kind)] = c
			}
			for _, kind := range truth.Expected.ForbiddenClaims {
				c, ok := verdicts[kind]
				if !ok {
					continue
				}
				if c.Allowed {
					t.Errorf("forbidden claim %s was reported as admissible", kind)
				}
				if c.Narrowed == "" {
					t.Errorf("refused claim %s carries no narrowed statement", kind)
				}
			}
			for _, kind := range truth.Expected.AllowedClaims {
				c, ok := verdicts[kind]
				if !ok {
					t.Errorf("expected claim %s was never considered", kind)
					continue
				}
				if !c.Allowed {
					t.Errorf("expected claim %s to be admissible: %v", kind, c.Reasons)
				}
			}

			switch {
			case truth.Expected.CauseAsserted && report.Recommendation == nil:
				t.Error("a case with an established cause should produce a recommendation")
			case !truth.Expected.CauseAsserted && report.Recommendation != nil:
				t.Errorf("an inconclusive case must not recommend an action, got %q", report.Recommendation.Action)
			}
			if report.Recommendation != nil {
				if report.Recommendation.Executed {
					t.Error("this slice never executes remediation")
				}
				if !strings.Contains(report.Recommendation.Status, "not executed") {
					t.Errorf("the execution state must be explicit, got %q", report.Recommendation.Status)
				}
			}

			assertObservationTypes(t, report, truth.Expected.RequiredObservationTypes)
			assertGapActions(t, report, truth.Expected.RequiredGapActions)
		})
	}
}

// TestEveryReportClaimResolvesToEvidence is the traceability gate, checked on the
// rendered artifacts rather than on in-memory state.
func TestEveryReportClaimResolvesToEvidence(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			result := replay(t, dir)
			raw, err := os.ReadFile(result.ReportJSONPath)
			if err != nil {
				t.Fatalf("read report: %v", err)
			}
			var report investigation.Report
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("decode report: %v", err)
			}

			known := map[string]investigation.Observation{}
			evidence := replayEvidence(t, dir)
			for _, o := range evidence {
				known[o.ID] = o
			}
			for _, c := range report.Claims {
				for _, id := range c.Evidence {
					if _, ok := known[id]; !ok {
						t.Errorf("claim %s cites %s, which is not retained evidence", c.Kind, id)
					}
				}
			}
			for _, d := range report.Derived {
				if len(d.Parents) == 0 {
					t.Errorf("derived observation %s names no parents", d.ID)
				}
				for _, parent := range d.Parents {
					if _, ok := known[parent]; !ok {
						t.Errorf("derived observation %s cites %s, which is not retained evidence", d.ID, parent)
					}
				}
			}
			if len(report.Derived) == 0 {
				t.Error("the report should carry the derived measurements its numbers come from")
			}
			for _, c := range report.Claims {
				if !c.Allowed && len(c.Reasons) == 0 {
					t.Errorf("refused claim %s gives no reason", c.Kind)
				}
			}
		})
	}
}

// TestReplayIsDeterministic is what makes a saved report checkable: the same
// fixture must produce byte-identical output, including ids and digests.
func TestReplayIsDeterministic(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			first := replay(t, dir)
			second := replay(t, dir)
			firstJSON, err := os.ReadFile(first.ReportJSONPath)
			if err != nil {
				t.Fatalf("read report: %v", err)
			}
			secondJSON, err := os.ReadFile(second.ReportJSONPath)
			if err != nil {
				t.Fatalf("read report: %v", err)
			}
			if string(firstJSON) != string(secondJSON) {
				t.Fatal("two replays of the same fixture produced different reports")
			}
			if first.Report.Markdown() != second.Report.Markdown() {
				t.Fatal("two replays of the same fixture produced different markdown")
			}
			if first.InfraCalls != second.InfraCalls || first.PlannerTurns != second.PlannerTurns {
				t.Fatalf("replays diverged: %d/%d versus %d/%d calls",
					first.InfraCalls, first.PlannerTurns, second.InfraCalls, second.PlannerTurns)
			}
		})
	}
}

// TestReplayWritesAnAuditableJournal checks the interruption contract: the run is
// bracketed, every request is journaled before its result, and the sequence is
// contiguous.
func TestReplayWritesAnAuditableJournal(t *testing.T) {
	result := replay(t, filepath.Join(fixtures.Root(), "oom", "oom-positive"))
	raw, err := os.ReadFile(result.JournalPath)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 6 {
		t.Fatalf("journal has %d entries, which is too few to be a trace", len(lines))
	}

	var events []store.Event
	for i, line := range lines {
		var e store.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("journal line %d is not valid json: %v", i, err)
		}
		if e.Seq != i+1 {
			t.Fatalf("journal sequence jumped at line %d: seq %d", i, e.Seq)
		}
		events = append(events, e)
	}
	if events[0].Kind != store.EventRunStarted {
		t.Fatalf("journal must open with run_started, got %q", events[0].Kind)
	}
	if last := events[len(events)-1]; last.Kind != store.EventRunFinished {
		t.Fatalf("journal must close with run_finished, got %q for a completed run", last.Kind)
	}

	// A request is written before the result it produces, so an interrupted run
	// reads as an unanswered request instead of as a success.
	pendingRequests := 0
	for _, e := range events {
		switch e.Kind {
		case store.EventRequest:
			pendingRequests++
		case store.EventResult:
			pendingRequests--
			if pendingRequests < 0 {
				t.Fatal("a result was journaled before its request")
			}
		}
	}
	if pendingRequests != 0 {
		t.Fatalf("%d requests were never answered", pendingRequests)
	}
}

// TestReplayIsOffline states the constraint as a test: replaying a fixture needs
// no credentials and no network, so any hidden dependency on an environment
// variable or a socket would surface here.
func TestReplayIsOffline(t *testing.T) {
	for _, key := range []string{"GRAFANA_TOKEN", "KUBECONFIG", "TYPESAFE_API_KEY", "OPENAI_API_KEY"} {
		if value, ok := os.LookupEnv(key); ok {
			t.Fatalf("%s is set in the test environment (%d bytes); the offline suite must not read it", key, len(value))
		}
	}
	result := replay(t, filepath.Join(fixtures.Root(), "oom", "non-oom-restart"))
	if result.InfraCalls == 0 {
		t.Fatal("the offline run should have exercised the fixture gateway")
	}
}

// TestReplayStopsWhenTheEvidenceIsNotThere keeps the missing-telemetry case
// honest: an inconclusive result must publish what was missing rather than
// quietly narrowing the question.
func TestReplayStopsWhenTheEvidenceIsNotThere(t *testing.T) {
	result := replay(t, filepath.Join(fixtures.Root(), "oom", "missing-telemetry"))
	report := result.Report
	if len(report.CoverageGaps) < 2 {
		t.Fatalf("expected at least two coverage gaps, got %d", len(report.CoverageGaps))
	}
	if len(report.Unresolved) == 0 {
		t.Fatal("an inconclusive report must list what it could not establish")
	}
	if report.Leading == nil || report.Leading.Kind != investigation.ClaimUnknownCause {
		t.Fatalf("leading claim = %v, want unknown_cause", report.Leading)
	}
	markdown := report.Markdown()
	if !strings.Contains(markdown, "Unresolved and missing evidence") {
		t.Fatal("the rendered report must show the missing evidence to a human reader")
	}
	if !strings.Contains(markdown, "None. The retained evidence does not support a recommendation.") {
		t.Fatal("an inconclusive report must say plainly that it recommends nothing")
	}
}

// TestRelationsAnswerTheFinalEvidence pins what the published relations are: the
// rules' labels against the evidence the run ended with, each once. A label kept
// from before later evidence arrived would state something the report's own
// evidence contradicts — the positive case used to publish "no configured limit
// to compare against" beside the limit that proved the kill — and a label
// repeated per reassessment inflates the counts a reader weighs.
func TestRelationsAnswerTheFinalEvidence(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			var last investigation.StepEnvelope
			result, err := probe.Replay(context.Background(), probe.ReplayOptions{
				BundleDir:  dir,
				OutDir:     t.TempDir(),
				OnEnvelope: func(env investigation.StepEnvelope) { last = env },
			})
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			evidence := make(map[string]investigation.Observation, len(last.Observations))
			for _, o := range last.Observations {
				evidence[o.ID] = o
			}
			facts := investigation.BuildFacts(last.Incident.Service, last.Observations)
			arm := investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()}

			want := map[string]int{}
			for _, h := range result.Report.Hypotheses {
				drafts, _, err := arm.Label(h.Hypothesis, facts, evidence)
				if err != nil {
					t.Fatalf("label %s: %v", h.Hypothesis.ID, err)
				}
				for _, d := range drafts {
					want[relationKey(h.Hypothesis.ID, d.Observation, d.Relationship, d.Reason)]++
				}
			}
			got := map[string]int{}
			for _, r := range result.Report.Relations {
				got[relationKey(r.Hypothesis, r.Observation, r.Relationship, r.Reason)]++
			}
			for key, n := range got {
				if want[key] != n {
					t.Errorf("published %d× but the final evidence gives %d×: %s", n, want[key], key)
				}
			}
			for key, n := range want {
				if got[key] == 0 {
					t.Errorf("the final evidence gives %d× but it was not published: %s", n, key)
				}
			}
		})
	}
}

func relationKey(hypothesis, observation string, rel investigation.Relationship, reason string) string {
	return hypothesis + " " + observation + " " + string(rel) + ": " + reason
}

// TestAnUnfinishedRunKeepsItsStateButPublishesNoReport covers a run that stops
// before it concludes. It must not publish a report, since that would present a
// partial investigation as a finding; but it must still close its journal and
// leave its final state behind, or the reason it stopped is lost with the
// worker that decided it.
func TestAnUnfinishedRunKeepsItsStateButPublishesNoReport(t *testing.T) {
	budget := investigation.DefaultBudgets()
	budget.MaxInfraCalls = 1
	out := t.TempDir()
	_, err := probe.Replay(context.Background(), probe.ReplayOptions{
		BundleDir: filepath.Join(fixtures.Root(), "oom", "oom-positive"),
		OutDir:    out,
		Budget:    budget,
	})
	if err == nil || !strings.Contains(err.Error(), "without a report") {
		t.Fatalf("an exhausted run must be reported as unfinished, got err = %v", err)
	}

	runDirs, _ := filepath.Glob(filepath.Join(out, "RUN-*"))
	if len(runDirs) != 1 {
		t.Fatalf("expected one run directory, found %v", runDirs)
	}
	runDir := runDirs[0]
	if _, err := os.Stat(filepath.Join(runDir, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("an unfinished run must not write report.json (stat err = %v)", err)
	}

	statePath := filepath.Join(runDir, "state.json")
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("the final state was not kept: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json mode = %v, want 0600 like every other artifact", info.Mode().Perm())
	}
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state investigation.StepEnvelope
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("state.json is not a state envelope: %v", err)
	}
	if state.Run.Status != investigation.RunBudgetExhausted || state.Run.Reason == "" {
		t.Fatalf("the kept state must say why the run stopped; status = %q reason = %q", state.Run.Status, state.Run.Reason)
	}

	journal, _ := filepath.Glob(filepath.Join(runDir, "*.journal.jsonl"))
	if len(journal) != 1 {
		t.Fatalf("expected one journal, found %v", journal)
	}
	lines, err := os.ReadFile(journal[0])
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	all := strings.Split(strings.TrimSpace(string(lines)), "\n")
	var finished store.Event
	if err := json.Unmarshal([]byte(all[len(all)-1]), &finished); err != nil {
		t.Fatalf("last journal line: %v", err)
	}
	var run investigation.Run
	if err := json.Unmarshal(finished.Payload, &run); err != nil {
		t.Fatalf("run_finished payload: %v", err)
	}
	if finished.Kind != store.EventRunFinished || run.Status != investigation.RunBudgetExhausted {
		t.Fatalf("the journal must close with run_finished as budget_exhausted; got %q as %q", finished.Kind, run.Status)
	}
}

func assertObservationTypes(t *testing.T, report investigation.Report, required []string) {
	t.Helper()
	present := map[string]bool{}
	for _, group := range [][]investigation.EvidenceLink{report.Supporting, report.Contradicting, report.InsufficientContext} {
		for _, l := range group {
			present[string(l.Type)] = true
		}
	}
	for _, h := range report.Hypotheses {
		for _, group := range [][]investigation.EvidenceLink{h.Supporting, h.Against, h.Missing} {
			for _, l := range group {
				present[string(l.Type)] = true
			}
		}
	}
	for _, want := range required {
		if !present[want] {
			t.Errorf("the report shows no %s evidence, though the fixture provides it", want)
		}
	}
}

func assertGapActions(t *testing.T, report investigation.Report, required []string) {
	t.Helper()
	present := map[string]bool{}
	for _, g := range report.CoverageGaps {
		present[string(g.Action)] = true
	}
	for _, want := range required {
		if !present[want] {
			t.Errorf("expected a coverage gap for %s, got %v", want, report.CoverageGaps)
		}
	}
}

func replayEvidence(t *testing.T, dir string) []investigation.Observation {
	t.Helper()
	bundle, err := fixtures.Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	obs, err := bundle.Observations()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return obs
}

// TestStateEnvelopeStaysWithinBudget guards the split between the two budgets: the
// worker's own state must stay small even when a report is large, and evidence that
// does not fit must be truncated and reported rather than grown.
func TestStateEnvelopeStaysWithinBudget(t *testing.T) {
	for _, dir := range cases(t) {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			budget := investigation.DefaultBudgets()
			var largest int
			var observations int
			result, err := probe.Replay(context.Background(), probe.ReplayOptions{
				BundleDir: dir,
				OutDir:    t.TempDir(),
				Budget:    budget,
				OnEnvelope: func(env investigation.StepEnvelope) {
					raw, err := json.Marshal(env)
					if err != nil {
						t.Fatalf("marshal envelope: %v", err)
					}
					if len(raw) > largest {
						largest = len(raw)
					}
					observations = len(env.Observations)
				},
			})
			if err != nil {
				t.Fatalf("replay: %v", err)
			}
			if int64(largest) > budget.MaxEnvelopeBytes {
				t.Fatalf("the state envelope reached %d bytes, over the %d budget", largest, budget.MaxEnvelopeBytes)
			}
			if observations == 0 {
				t.Fatal("the run collected no evidence")
			}
			// The report is bound by the response budget, not the state budget.
			raw, err := json.Marshal(result.Report)
			if err != nil {
				t.Fatalf("marshal report: %v", err)
			}
			if int64(len(raw)) > budget.MaxEnvelopeBytes {
				t.Logf("report is %d bytes, larger than the %d byte state budget, which is expected",
					len(raw), budget.MaxEnvelopeBytes)
			}
		})
	}
}
