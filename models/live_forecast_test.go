package models

import (
	"strings"
	"testing"

	"github.com/vorash/vora-probe/investigation"
)

// A forecast-triggered incident reaches the planner as a hypothesis about the
// future, with its competitors named, never as a failure to explain; an
// alert-triggered one carries no such note.
func TestAForecastIncidentIsPresentedAsAForecast(t *testing.T) {
	req := investigation.ModelRequest{Incident: investigation.Incident{ID: "INC-f", Service: "payment-api", Trigger: investigation.TriggerForecast}}
	prompt := renderPlannerRequest(req)
	for _, want := range []string{"nothing has failed yet", "exhaustion_forecast", "Never describe the forecast as a failure"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the forecast prompt is missing %q:\n%s", want, prompt)
		}
	}
	req.Incident.Trigger = investigation.TriggerAlert
	if strings.Contains(renderPlannerRequest(req), "FORECAST") {
		t.Fatal("an alert-triggered incident must not be presented as a forecast")
	}
	if !strings.Contains(PlannerSystemPrompt(), "exhaustion_forecast") {
		t.Fatal("the closed set of claim kinds must include the forecast")
	}
}

// A classed incident reaches the planner with its class's competing hypotheses
// and first evidence, as guidance; an unclassed one carries none.
func TestAClassedIncidentCarriesItsGuidance(t *testing.T) {
	req := investigation.ModelRequest{Incident: investigation.Incident{ID: "INC-c", Service: "checkout-api", Class: "crashloop"}}
	prompt := renderPlannerRequest(req)
	for _, want := range []string{"INCIDENT CLASS crashloop", "liveness_probe_restart", "application_crash", "kubernetes.events"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("the prompt is missing %q:\n%s", want, prompt)
		}
	}
	req.Incident.Class = ""
	if strings.Contains(renderPlannerRequest(req), "INCIDENT CLASS") {
		t.Fatal("an unclassed incident must carry no class guidance")
	}
}
