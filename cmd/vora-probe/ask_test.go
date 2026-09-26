package main

import (
	"strings"
	"testing"
	"time"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

// A question becomes an ordinary incident: the same contract an alert's meets,
// a window ending now inside the evidence bound, and a symptom that is
// redacted and bounded, because it reaches the planner.
func TestAQuestionBecomesAnOrdinaryBoundedIncident(t *testing.T) {
	now := time.Date(2026, 9, 26, 14, 0, 0, 0, time.UTC)
	inc, err := askIncident("why does checkout-api restart? token=abc123", "checkout-api", "", "", 45*time.Minute, now)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	if err := inc.Validate(); err != nil {
		t.Fatalf("the incident must satisfy the engine's contract: %v", err)
	}
	if strings.Contains(inc.Symptom, "abc123") {
		t.Fatalf("a secret in the question reached the symptom: %q", inc.Symptom)
	}
	if !inc.Window.End.Equal(now) || inc.Window.End.Sub(inc.Window.Start) != 45*time.Minute {
		t.Fatalf("window %s..%s, want the last 45m", inc.Window.Start, inc.Window.End)
	}
	if inc.Environment != "lab" || inc.Trigger != investigation.TriggerCLI || inc.Severity != "" {
		t.Fatalf("incident %+v", inc)
	}
	long, _ := askIncident(strings.Repeat("é", 600), "x", "lab", "", time.Minute, now)
	if len(long.Symptom) > maxQuestionBytes+len(" (truncated)") {
		t.Fatalf("a long question was not bounded: %d bytes", len(long.Symptom))
	}
}

// The window is bounded like every evidence request; a question cannot widen
// it, and asking nothing is refused.
func TestAQuestionCannotWidenTheWindow(t *testing.T) {
	now := time.Now().UTC()
	if _, err := askIncident("why?", "x", "lab", "", 2*time.Hour, now); err == nil {
		t.Fatalf("a window over %s was accepted", gateway.MaxWindow)
	}
	if _, err := askIncident("   ", "x", "lab", "", time.Minute, now); err == nil {
		t.Fatal("an empty question was accepted")
	}
}
