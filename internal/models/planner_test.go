package models_test

import (
	"context"
	"errors"
	"testing"

	"github.com/vorash/vora-probe/internal/gateway"
	"github.com/vorash/vora-probe/internal/investigation"
	"github.com/vorash/vora-probe/internal/models"
)

func turns(n int) []investigation.ModelResponse {
	out := make([]investigation.ModelResponse, 0, n)
	for i := range n {
		out = append(out, investigation.ModelResponse{
			SchemaVersion: gateway.SchemaVersion,
			Reason:        "turn",
			NextAction:    nil,
			Hypotheses: []investigation.HypothesisSpec{
				{Statement: "a", FaultDomain: investigation.DomainHost, ClaimKind: investigation.ClaimUnknownCause},
				{Statement: "b", FaultDomain: investigation.DomainHost, ClaimKind: investigation.ClaimUnknownCause},
			},
		})
		out[i].Reason = "turn"
	}
	return out
}

func TestRecordedPlannerReplaysInOrderThenReportsExhaustion(t *testing.T) {
	planner := models.NewRecordedPlanner(turns(2))
	for i := range 2 {
		if _, err := planner.Plan(context.Background(), investigation.ModelRequest{}); err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
	}
	if planner.Consumed() != 2 {
		t.Fatalf("consumed = %d, want 2", planner.Consumed())
	}
	// Exhaustion is reported rather than answered, so a fixture that provides too
	// little planning fails loudly instead of looking like a finished run.
	if _, err := planner.Plan(context.Background(), investigation.ModelRequest{}); !errors.Is(err, models.ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	if planner.Consumed() != 2 {
		t.Fatalf("an exhausted planner must not consume a turn, got %d", planner.Consumed())
	}
}
