package investigation_test

import (
	"strings"
	"testing"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

func withCatalog(names ...string) investigation.StepEnvelope {
	env := newEnvelope(investigation.DefaultBudgets())
	for _, n := range names {
		env.ContextCatalog = append(env.ContextCatalog, investigation.ContextSummary{Name: n, Description: n})
	}
	return env
}

func readReply(name string, action *gateway.Action) investigation.ModelResponse {
	plan := goodPlan(action)
	plan.ReadContext = name
	return plan
}

// A read is the planner asking the controller for reference. It must name a
// package the run was offered, once, within the per-run bound, and never in
// the same reply as an evidence request.
func TestContextReadsAreBounded(t *testing.T) {
	engine := testEngine(gateway.DefaultPolicy())
	env := withCatalog("topology", "quirks", "owners", "runbook")
	step, _ := engine.Step(investigation.WorkerInput{State: env})

	refused := func(name string, reply investigation.ModelResponse, want string) {
		t.Helper()
		next, err := engine.Step(modelInput(step.Envelope, reply))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if next.Kind != investigation.ResultModelRequest || !strings.Contains(next.ModelRequest.RetryNote, want) {
			t.Fatalf("%s: got %q (%s), want a refusal about %q", name, next.Kind, next.ModelRequest.RetryNote, want)
		}
	}
	refused("not in the catalog", readReply("secrets", nil), "not in the catalog")
	action := &gateway.Action{Kind: gateway.ActionKubernetesContainers, Entity: "payment-api", Reason: "r"}
	refused("read and act at once", readReply("topology", action), "not both")

	// Read three: each is a context request, then the package joins the state.
	for _, name := range []string{"topology", "quirks", "owners"} {
		next, err := engine.Step(modelInput(step.Envelope, readReply(name, nil)))
		if err != nil || next.Kind != investigation.ResultContextRequest || next.ContextRequest != name {
			t.Fatalf("read %s: %q %v", name, next.Kind, err)
		}
		c := investigation.Context{Name: name, Body: "reference", Digest: "sha256:x"}
		step, err = engine.Step(investigation.WorkerInput{State: next.Envelope,
			Pending: &investigation.Pending{Kind: investigation.PendingContext, Context: &c}})
		if err != nil || step.Kind != investigation.ResultModelRequest {
			t.Fatalf("after reading %s: %q %v", name, step.Kind, err)
		}
	}
	refused("read twice", readReply("topology", nil), "already loaded")
	refused("over the bound", readReply("runbook", nil), "at most 3")
	if len(step.ModelRequest.Contexts) != 3 {
		t.Fatalf("the planner sees %d packages, want the 3 read", len(step.ModelRequest.Contexts))
	}
}
