package investigation

import "github.com/vorash/vora-probe/gateway"

// Incident classes (vorash/vora-probe#13, P2.2).
//
// A class is what an alert usually means, written down: which competing
// hypotheses are worth weighing and which evidence settles them fastest. It is
// guidance for the planner, never a constraint. The claims policy is the same
// for every class, and a class never makes a conclusion admissible.

type Class struct {
	Name       string
	Alertnames []string
	// Hypotheses are the competing explanations worth weighing first.
	Hypotheses []ClaimKind
	// FirstEvidence is what to collect before anything else.
	FirstEvidence []gateway.ActionKind
	Guidance      string
}

var Classes = []Class{
	{
		Name:          "oom",
		Alertnames:    []string{"ContainerOOMKilled", "KubeContainerOOMKilled"},
		Hypotheses:    []ClaimKind{ClaimMemoryLimitTermination, ClaimNonMemoryRestart, ClaimMemoryLeak, ClaimDeploymentRegression},
		FirstEvidence: []gateway.ActionKind{gateway.ActionKubernetesContainers, gateway.ActionMetricsQuery},
		Guidance:      "A memory-limit kill is recorded in the container's termination state; the working set against the limit corroborates it. A kill is not a leak.",
	},
	{
		Name:          "crashloop",
		Alertnames:    []string{"ContainerRestartLoop", "KubePodCrashLooping"},
		Hypotheses:    []ClaimKind{ClaimLivenessProbeRestart, ClaimApplicationCrash, ClaimMemoryLimitTermination, ClaimDeploymentRegression},
		FirstEvidence: []gateway.ActionKind{gateway.ActionKubernetesContainers, gateway.ActionKubernetesEvents},
		Guidance:      "Whether the kubelet killed the container for a failing liveness probe or it exited by itself is in its termination state and the namespace events; metrics show pressure, not why it stopped. A readiness failure never restarts a container.",
	},
}

// ClassForAlert is the class an alert name maps to, or "".
func ClassForAlert(alertname string) string {
	for _, c := range Classes {
		for _, a := range c.Alertnames {
			if a == alertname {
				return c.Name
			}
		}
	}
	return ""
}

// ClassNamed looks a class up by name.
func ClassNamed(name string) (Class, bool) {
	for _, c := range Classes {
		if c.Name == name {
			return c, true
		}
	}
	return Class{}, false
}
