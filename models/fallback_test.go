package models

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vorash/vora-probe/investigation"
)

const validReply = `{"hypotheses":[
	{"statement":"killed at its limit","fault_domain":"kubernetes","claim_kind":"memory_limit_termination","evidence_needed":[]},
	{"statement":"restarts for another reason","fault_domain":"application","claim_kind":"non_memory_restart","evidence_needed":[]}],
	"next_action":null,"reason":"enough"}`

type stubPlanner struct {
	resp  investigation.ModelResponse
	err   error
	calls int
}

func (s *stubPlanner) Plan(context.Context, investigation.ModelRequest) (investigation.ModelResponse, error) {
	s.calls++
	return s.resp, s.err
}

// A planner endpoint that is down should not end the run when another is
// configured; but the report must say which answered and why the first was
// passed over, and every call must be charged.
func TestTheFallbackAnswersAndSaysWhy(t *testing.T) {
	primary := &stubPlanner{err: errors.New("planner endpoint returned 503")}
	fallback := &stubPlanner{resp: investigation.ModelResponse{Reason: "ok", AnsweredBy: "backup.example gpt", Attempts: 1}}
	resp, err := FallbackPlanner{Planners: []Planner{primary, fallback}}.Plan(context.Background(), plannerRequest())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if resp.AnsweredBy != "backup.example gpt" || resp.Attempts != 2 {
		t.Fatalf("answered by %q in %d attempts, want the fallback in 2", resp.AnsweredBy, resp.Attempts)
	}
	if len(resp.FallbackReasons) != 1 || !strings.Contains(resp.FallbackReasons[0], "503") {
		t.Fatalf("fallback reasons %v, want why the primary was passed over", resp.FallbackReasons)
	}
}

func TestEveryEndpointFailingIsAFailureNamingEach(t *testing.T) {
	a := &stubPlanner{err: errors.New("first down")}
	b := &stubPlanner{err: errors.New("second down")}
	_, err := FallbackPlanner{Planners: []Planner{a, b}}.Plan(context.Background(), plannerRequest())
	if err == nil || !strings.Contains(err.Error(), "first down") || !strings.Contains(err.Error(), "second down") {
		t.Fatalf("error %v, want both failures named", err)
	}
}

// Once the run's deadline has passed, no endpoint can answer in time, and
// calling the next would only spend money.
func TestNoFallbackAfterTheDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &stubPlanner{err: errors.New("timed out")}
	b := &stubPlanner{resp: investigation.ModelResponse{Reason: "late"}}
	cancel()
	if _, err := (FallbackPlanner{Planners: []Planner{a, b}}).Plan(ctx, plannerRequest()); err == nil {
		t.Fatal("a cancelled run must not be planned")
	}
	if b.calls != 0 {
		t.Fatal("the fallback was called after the deadline had passed")
	}
}

// The live planner reports what the provider says answered, which may differ
// from what was asked for when a router picks the model.
func TestTheLivePlannerRecordsWhatAnswered(t *testing.T) {
	ft := &fakeTransport{status: 200, body: completion(validReply)}
	resp, err := newPlanner(t, ft).Plan(context.Background(), plannerRequest())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if resp.AnsweredBy != "planner.invalid gpt-4o-mini" || resp.Attempts != 1 {
		t.Fatalf("answered by %q (%d attempts)", resp.AnsweredBy, resp.Attempts)
	}
}

func TestAFallbackIsConfiguredOnlyWhenNamed(t *testing.T) {
	if _, ok := PlannerFromConfig(Config{Baseline: Endpoint{BaseURL: "https://a"}}).(LivePlanner); !ok {
		t.Fatal("without a fallback endpoint the planner must be the plain live planner")
	}
	if _, ok := PlannerFromConfig(Config{Baseline: Endpoint{BaseURL: "https://a"}, PlannerFallback: Endpoint{BaseURL: "https://b"}}).(FallbackPlanner); !ok {
		t.Fatal("a configured fallback must be used")
	}
}
