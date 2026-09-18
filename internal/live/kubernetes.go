package live

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vorash/vora-probe/gateway"
)

// The Kubernetes adapter reads object state, never a payload: pod and container
// status (including why a container last terminated), namespace events, and
// deployment rollout times. It is read-only by construction — every request is a
// GET — and the identity it runs under is a namespaced read-only Role.

func (g *Gateway) containers(a gateway.Action) (gateway.Response, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/pods?labelSelector=%s",
		url.PathEscape(g.cfg.Namespace), url.QueryEscape("app="+a.Entity))
	meta := gateway.QueryMeta{
		Datasource: "kubernetes",
		Query:      path,
		Params:     map[string]string{"namespace": g.cfg.Namespace, "entity": a.Entity},
	}

	var list k8sPodList
	if err := g.k8sGet(path, &list); err != nil {
		return gateway.Response{}, err
	}
	if len(list.Items) == 0 {
		return g.response(a, meta, nil, gateway.StatusUnavailable, gateway.Unavailable,
			"no pods match the service in this namespace")
	}
	pods := make([]gateway.Pod, 0, len(list.Items))
	for _, p := range list.Items {
		pods = append(pods, p.convert())
	}
	return g.response(a, meta, gateway.PodList{Namespace: g.cfg.Namespace, Pods: pods}, gateway.StatusOK, gateway.Complete, "")
}

func (g *Gateway) events(a gateway.Action) (gateway.Response, error) {
	path := fmt.Sprintf("/api/v1/namespaces/%s/events?limit=500", url.PathEscape(g.cfg.Namespace))
	meta := gateway.QueryMeta{
		Datasource: "kubernetes",
		Query:      path,
		Params: map[string]string{
			"namespace": g.cfg.Namespace,
			"start":     a.Window.Start.UTC().Format(time.RFC3339),
			"end":       a.Window.End.UTC().Format(time.RFC3339),
		},
	}

	var list k8sEventList
	if err := g.k8sGet(path, &list); err != nil {
		return gateway.Response{}, err
	}
	// An empty event list is a real answer — "nothing happened in this window" —
	// so it is complete, not unavailable. Only an unreadable source is missing.
	out := make([]gateway.Event, 0, len(list.Items))
	for _, e := range list.Items {
		if !e.within(a.Window) {
			continue
		}
		out = append(out, e.convert())
	}
	return g.response(a, meta, gateway.EventList{Namespace: g.cfg.Namespace, Events: out}, gateway.StatusOK, gateway.Complete, "")
}

func (g *Gateway) deployments(a gateway.Action) (gateway.Response, error) {
	// Namespace-wide on purpose: the question a rollout answers is "what changed
	// near the impact", and the unrelated deployment is the whole point of that
	// case. The scope is the namespace, which is all this identity can read.
	path := fmt.Sprintf("/apis/apps/v1/namespaces/%s/deployments", url.PathEscape(g.cfg.Namespace))
	meta := gateway.QueryMeta{
		Datasource: "kubernetes",
		Query:      path,
		Params:     map[string]string{"namespace": g.cfg.Namespace},
	}

	var list k8sDeploymentList
	if err := g.k8sGet(path, &list); err != nil {
		return gateway.Response{}, err
	}
	out := make([]gateway.Deployment, 0, len(list.Items))
	for _, d := range list.Items {
		out = append(out, d.convert())
	}
	return g.response(a, meta, gateway.DeploymentList{Namespace: g.cfg.Namespace, Deployments: out}, gateway.StatusOK, gateway.Complete, "")
}

func (g *Gateway) k8sGet(path string, out any) error {
	headers := map[string]string{"Authorization": "Bearer " + g.cfg.Kubernetes.Token}
	raw, err := g.get(strings.TrimRight(g.cfg.Kubernetes.Server, "/")+path, headers, g.k8s)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("live: kubernetes response is not valid JSON: %w", err)
	}
	return nil
}

// ---- wire shapes ----
//
// Only the fields Probe reads are declared; an API server sends far more, and
// decoding leniently is what keeps this adapter from breaking on an upgrade that
// adds a field.

type k8sPodList struct {
	Items []k8sPod `json:"items"`
}

type k8sPod struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase             string               `json:"phase"`
		StartTime         time.Time            `json:"startTime"`
		ContainerStatuses []k8sContainerStatus `json:"containerStatuses"`
	} `json:"status"`
}

type k8sContainerStatus struct {
	Name                 string            `json:"name"`
	Ready                bool              `json:"ready"`
	RestartCount         int               `json:"restartCount"`
	State                k8sContainerState `json:"state"`
	LastTerminationState k8sContainerState `json:"lastState"`
}

// k8sContainerState is the running/waiting/terminated union. Presence is the
// discriminator, which is why these are pointers.
type k8sContainerState struct {
	Running    *struct{}       `json:"running,omitempty"`
	Waiting    *k8sWaiting     `json:"waiting,omitempty"`
	Terminated *k8sTermination `json:"terminated,omitempty"`
}

type k8sWaiting struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

type k8sTermination struct {
	Reason     string    `json:"reason"`
	ExitCode   int       `json:"exitCode"`
	FinishedAt time.Time `json:"finishedAt"`
}

func (p k8sPod) convert() gateway.Pod {
	pod := gateway.Pod{
		Name:      p.Metadata.Name,
		Namespace: p.Metadata.Namespace,
		Phase:     p.Status.Phase,
		Node:      p.Spec.NodeName,
		StartTime: p.Status.StartTime.UTC(),
	}
	for _, c := range p.Status.ContainerStatuses {
		status := gateway.ContainerStatus{
			Name:         c.Name,
			Ready:        c.Ready,
			RestartCount: c.RestartCount,
			State:        c.State.name(),
			Reason:       c.State.reason(),
		}
		if t := c.LastTerminationState.Terminated; t != nil {
			at := t.FinishedAt.UTC()
			code := t.ExitCode
			status.LastTerminatedAt = &at
			status.LastTerminatedReason = t.Reason
			status.LastExitCode = &code
		}
		pod.Containers = append(pod.Containers, status)
	}
	return pod
}

func (s k8sContainerState) name() string {
	switch {
	case s.Terminated != nil:
		return "terminated"
	case s.Waiting != nil:
		return "waiting"
	case s.Running != nil:
		return "running"
	default:
		return "unknown"
	}
}

func (s k8sContainerState) reason() string {
	switch {
	case s.Terminated != nil:
		return s.Terminated.Reason
	case s.Waiting != nil:
		return s.Waiting.Reason
	default:
		return ""
	}
}

type k8sEventList struct {
	Items []k8sEvent `json:"items"`
}

type k8sEvent struct {
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Message        string    `json:"message"`
	Count          int       `json:"count"`
	FirstTimestamp time.Time `json:"firstTimestamp"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	EventTime      time.Time `json:"eventTime"`
	InvolvedObject struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"involvedObject"`
}

// lastSeen prefers the modern eventTime and falls back to lastTimestamp, so the
// window filter works on either event API version.
func (e k8sEvent) lastSeen() time.Time {
	if !e.EventTime.IsZero() {
		return e.EventTime
	}
	return e.LastTimestamp
}

func (e k8sEvent) within(w *gateway.Window) bool {
	if w == nil {
		return true
	}
	last := e.lastSeen()
	if last.IsZero() {
		return true
	}
	return !last.Before(w.Start) && !last.After(w.End)
}

func (e k8sEvent) convert() gateway.Event {
	out := gateway.Event{
		Type:           e.Type,
		Reason:         e.Reason,
		Message:        e.Message,
		Count:          e.Count,
		InvolvedObject: e.InvolvedObject.Kind + "/" + e.InvolvedObject.Name,
	}
	if !e.FirstTimestamp.IsZero() {
		out.FirstSeen = e.FirstTimestamp.UTC()
	} else if !e.EventTime.IsZero() {
		out.FirstSeen = e.EventTime.UTC()
	}
	out.LastSeen = out.FirstSeen
	if !e.LastTimestamp.IsZero() {
		out.LastSeen = e.LastTimestamp.UTC()
	}
	return out
}

type k8sDeploymentList struct {
	Items []k8sDeployment `json:"items"`
}

type k8sDeployment struct {
	Metadata struct {
		Name              string    `json:"name"`
		Namespace         string    `json:"namespace"`
		CreationTimestamp time.Time `json:"creationTimestamp"`
	} `json:"metadata"`
	Spec struct {
		Template struct {
			Spec struct {
				Containers []struct {
					Image string `json:"image"`
				} `json:"containers"`
			} `json:"spec"`
		} `json:"template"`
	} `json:"spec"`
	Status struct {
		Replicas          int `json:"replicas"`
		AvailableReplicas int `json:"availableReplicas"`
		Conditions        []struct {
			Type           string    `json:"type"`
			Status         string    `json:"status"`
			Reason         string    `json:"reason"`
			LastUpdateTime time.Time `json:"lastUpdateTime"`
		} `json:"conditions"`
	} `json:"status"`
}

func (d k8sDeployment) convert() gateway.Deployment {
	out := gateway.Deployment{
		Name:              d.Metadata.Name,
		Namespace:         d.Metadata.Namespace,
		Replicas:          d.Status.Replicas,
		AvailableReplicas: d.Status.AvailableReplicas,
		// Creation is the floor: a deployment that has never completed a rollout
		// still has a time, and pretending otherwise would drop it from the
		// proximity comparison entirely.
		RolloutCompletedAt: d.Metadata.CreationTimestamp.UTC(),
	}
	if len(d.Spec.Template.Spec.Containers) > 0 {
		out.Image = d.Spec.Template.Spec.Containers[0].Image
	}
	for _, c := range d.Status.Conditions {
		if c.Type == "Progressing" && c.Status == "False" && c.Reason == "NewReplicaSetAvailable" && !c.LastUpdateTime.IsZero() {
			out.RolloutCompletedAt = c.LastUpdateTime.UTC()
		}
	}
	return out
}
