package investigation_test

import (
	"strings"
	"testing"

	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)

func exited(code int, reason string, restarts int) gateway.ContainerStatus {
	terminated := at(12, 21)
	return gateway.ContainerStatus{Name: "app", RestartCount: restarts, State: "waiting", Reason: "CrashLoopBackOff",
		LastTerminatedAt: &terminated, LastTerminatedReason: reason, LastExitCode: &code}
}

func probeEvent(kind string) gateway.Event {
	return gateway.Event{Type: "Warning", Reason: "Unhealthy", Message: kind + " probe failed: HTTP probe failed with statuscode: 503",
		InvolvedObject: "checkout-api-abc123", Count: 6, LastSeen: at(12, 20)}
}

// The kubelet restarting a container over a failing liveness probe is admitted
// when both the failure and the restart are evidenced. The container exits 137
// when the kubelet kills it; that must not read as a memory kill.
func TestALivenessRestartIsAdmittedAndA137KillIsNotAMemoryKill(t *testing.T) {
	entity := "checkout-api"
	killed := containerObs(t, "OBS-0001", entity, exited(137, "Error", 5))
	liveness := eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))
	facts, byID, ids := build(t, entity, killed, liveness)

	if v := evaluate(t, investigation.ClaimLivenessProbeRestart, entity, ids, facts, byID); !v.Allowed {
		t.Fatalf("a liveness failure plus restarts should be admitted: %v", v.Reasons)
	}
	if v := evaluate(t, investigation.ClaimMemoryLimitTermination, entity, ids, facts, byID); v.Allowed {
		t.Fatal("a SIGKILL from the kubelet (exit 137, reason Error) was read as a memory-limit kill")
	}
}

// A readiness failure takes a pod out of service and never restarts it; it
// must not be offered as the reason for restarts.
func TestAReadinessFailureDoesNotExplainRestarts(t *testing.T) {
	entity := "checkout-api"
	restarts := containerObs(t, "OBS-0001", entity, exited(1, "Error", 5))
	readiness := eventObs(t, "OBS-0002", entity, probeEvent("Readiness"))
	facts, byID, ids := build(t, entity, restarts, readiness)
	v := evaluate(t, investigation.ClaimLivenessProbeRestart, entity, ids, facts, byID)
	if v.Allowed || !strings.Contains(v.Narrowed, "do not restart") {
		t.Fatalf("verdict %+v, want refused and narrowed to what readiness failures do", v)
	}
}

// A failing liveness probe beside an application exit is ambiguous both ways:
// neither the probe restart nor the crash may be asserted over the other.
func TestALivenessFailureBesideASelfExitIsNotAProbeRestart(t *testing.T) {
	entity := "checkout-api"
	crash := containerObs(t, "OBS-0001", entity, exited(1, "Error", 5))
	liveness := eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))
	facts, byID, ids := build(t, entity, crash, liveness)
	v := evaluate(t, investigation.ClaimLivenessProbeRestart, entity, ids, facts, byID)
	if v.Allowed || !strings.Contains(v.Narrowed, "which came first is not established") {
		t.Fatalf("verdict %+v, want refused and narrowed", v)
	}
}

func TestALivenessFailureWithoutARestartIsNotARestart(t *testing.T) {
	entity := "checkout-api"
	running := containerObs(t, "OBS-0001", entity, gateway.ContainerStatus{Name: "app", State: "running", Ready: false})
	liveness := eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))
	facts, byID, ids := build(t, entity, running, liveness)
	if v := evaluate(t, investigation.ClaimLivenessProbeRestart, entity, ids, facts, byID); v.Allowed {
		t.Fatal("a failing probe with no restart evidenced was admitted as a restart")
	}
}

// A container that exits by itself with an application code is a crash. With
// a failing liveness probe beside it, which ended it is not established, and the
// claim is narrowed rather than guessed.
func TestAnApplicationCrashNeedsASelfExitAndNoCompetingProbe(t *testing.T) {
	entity := "checkout-api"
	crash := containerObs(t, "OBS-0001", entity, exited(1, "Error", 5))
	facts, byID, ids := build(t, entity, crash)
	if v := evaluate(t, investigation.ClaimApplicationCrash, entity, ids, facts, byID); !v.Allowed {
		t.Fatalf("exit 1 with no probe failure should be a crash: %v", v.Reasons)
	}

	liveness := eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))
	facts, byID, ids = build(t, entity, crash, liveness)
	v := evaluate(t, investigation.ClaimApplicationCrash, entity, ids, facts, byID)
	if v.Allowed || !strings.Contains(v.Narrowed, "which came first is not established") {
		t.Fatalf("verdict %+v, want refused and narrowed", v)
	}

	for _, code := range []int{137, 143} {
		signal := containerObs(t, "OBS-0001", entity, exited(code, "Error", 5))
		facts, byID, ids = build(t, entity, signal)
		if v := evaluate(t, investigation.ClaimApplicationCrash, entity, ids, facts, byID); v.Allowed {
			t.Fatalf("exit %d is a signal, not an application exit, and was admitted as a crash", code)
		}
	}
}

// A memory-limit kill explains the restart; neither restart claim may stand
// beside it.
func TestAMemoryKillRefusesBothRestartClaims(t *testing.T) {
	entity := "checkout-api"
	oom := containerObs(t, "OBS-0001", entity, oomContainer())
	liveness := eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))
	facts, byID, ids := build(t, entity, oom, liveness)
	for _, kind := range []investigation.ClaimKind{investigation.ClaimLivenessProbeRestart, investigation.ClaimApplicationCrash} {
		if v := evaluate(t, kind, entity, ids, facts, byID); v.Allowed {
			t.Fatalf("%s admitted beside an evidenced memory-limit kill", kind)
		}
	}
}

// The rules arm labels restart evidence the way the policy judges it, so a
// report cannot show support for a claim it refuses.
func TestCrashloopLabelsAgreeWithTheVerdicts(t *testing.T) {
	entity := "checkout-api"
	arm := investigation.DeterministicEvaluator{Policy: investigation.DefaultClaimPolicy()}
	cases := []struct {
		name string
		kind investigation.ClaimKind
		obs  []investigation.Observation
	}{
		{"liveness restart", investigation.ClaimLivenessProbeRestart, []investigation.Observation{
			containerObs(t, "OBS-0001", entity, exited(137, "Error", 5)), eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))}},
		{"readiness only", investigation.ClaimLivenessProbeRestart, []investigation.Observation{
			containerObs(t, "OBS-0001", entity, exited(1, "Error", 5)), eventObs(t, "OBS-0002", entity, probeEvent("Readiness"))}},
		{"crash", investigation.ClaimApplicationCrash, []investigation.Observation{
			containerObs(t, "OBS-0001", entity, exited(1, "Error", 5))}},
		{"crash beside liveness", investigation.ClaimApplicationCrash, []investigation.Observation{
			containerObs(t, "OBS-0001", entity, exited(1, "Error", 5)), eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))}},
		{"liveness beside a self-exit", investigation.ClaimLivenessProbeRestart, []investigation.Observation{
			containerObs(t, "OBS-0001", entity, exited(1, "Error", 5)), eventObs(t, "OBS-0002", entity, probeEvent("Liveness"))}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			facts, byID, ids := build(t, entity, c.obs...)
			drafts, _, err := arm.Label(investigation.Hypothesis{ID: "HYP-0001", ClaimKind: c.kind}, facts, byID)
			if err != nil {
				t.Fatalf("label: %v", err)
			}
			supported := false
			for _, d := range drafts {
				if d.Relationship == investigation.Supports {
					supported = true
				}
			}
			allowed := evaluate(t, c.kind, entity, ids, facts, byID).Allowed
			if supported != allowed {
				t.Fatalf("labels support=%t but the verdict allowed=%t: %+v", supported, allowed, drafts)
			}
		})
	}
}

// An alert maps to its class, and the class guides the planner without
// limiting it.
func TestAlertsMapToTheirClass(t *testing.T) {
	for alert, want := range map[string]string{"ContainerRestartLoop": "crashloop", "KubePodCrashLooping": "crashloop", "ContainerOOMKilled": "oom", "DiskFull": ""} {
		if got := investigation.ClassForAlert(alert); got != want {
			t.Errorf("%s -> %q, want %q", alert, got, want)
		}
	}
	class, _ := investigation.ClassNamed("crashloop")
	for _, k := range class.Hypotheses {
		if !k.Valid() {
			t.Errorf("class hypothesis %q is not a claim kind", k)
		}
	}
}
