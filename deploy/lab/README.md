# Isolated lab (step 5)

Operator-run lifecycle for the live OOM slice. Nothing here is applied by
`vora-ansible`: their ceiling stays node_exporter, and the cluster is probe's
concern.

The lab is one namespace, `probe-lab`, capped at 2 GiB of limits so a
deliberately OOM-tolerant workload can never pressure the shared host that also
runs the Vora runner.

## Contents

| Path | What it is |
| --- | --- |
| `00-namespace.yaml` | namespace, `ResourceQuota` (2 GiB limits / 1 GiB requests), `LimitRange` defaults |
| `10-rbac.yaml` | `probe-investigator` (read-only, namespaced) and the scrape identities |
| `20-memory-test.yaml` | the workload and `unrelated-api`, the rollout for the misleading case |
| `30-observability.yaml` | Prometheus (cAdvisor + app scrape) and kube-state-metrics |
| `memory-test/` | the workload's source; its own Go module |
| `build-image.sh` | build the workload image and import it into the node |
| `inject.sh` | operator-only fault injection |

## Bring-up

```bash
./build-image.sh                      # build + import the workload image
K='sudo -n k3s kubectl'
$K apply -f 00-namespace.yaml
$K apply -f 10-rbac.yaml
$K apply -f 20-memory-test.yaml
$K apply -f 30-observability.yaml
$K -n probe-lab rollout status deploy/prometheus
```

Smoke test — one cAdvisor series and one app series, through the same ports the
gateway will read:

```bash
$K -n probe-lab port-forward svc/prometheus 9090:9090 &
curl -s 'localhost:9090/api/v1/query' --data-urlencode \
  'query=container_memory_working_set_bytes{pod=~"memory-test-.*"}' | head -c 400
curl -s 'localhost:9090/api/v1/query' --data-urlencode \
  'query=request_latency_p99_seconds{service="memory-test"}' | head -c 400
```

## Why there is no Grafana

The namespace cap is 2 GiB and the workload plus Prometheus plus
kube-state-metrics already use most of it. Grafana is a human convenience and
the first thing to drop; the reports Probe produces are the artifact, not a
dashboard.

## Why memory comes from cAdvisor

The k3s node runs with `--disable metrics-server`, so there is no `kubectl top`
and no metrics API. Container memory and limits come from the kubelet's
`/metrics/cadvisor`, scraped through the API server proxy.

## Scenarios

Faults are injected by the operator with `inject.sh`, never by the
investigator:

| Command | Shape |
| --- | --- |
| `inject.sh oom 512` | working set past the limit → `OOMKilled`, a sawtooth, not a leak |
| `inject.sh ramp` | climbs to ~94% of the limit, holds so it is sampled, then pushes over → `OOMKilled` with corroborating memory evidence |
| `inject.sh non-oom` | failed liveness probe → restarts that are not memory-driven |
| `inject.sh rollout` | a real, unrelated deployment change near an impact |
| `inject.sh drop-metric request_error_rate` | an application metric stops existing |
| `inject.sh reset` | back to idle |

Missing *memory* evidence is not a fault: the controller asks for a fixed window
before the workload existed, and the gateway reports `unavailable`. That keeps
"missing evidence" a property of the query rather than a staged illusion.

## Cleanup

The Prometheus RBAC is cluster-scoped but binds a *namespaced* subject, so
deleting the namespace is not enough — it would leave a dangling grant that a
recreated `probe-lab/prometheus` ServiceAccount would inherit. Delete the
binding and the role explicitly first:

```bash
K='sudo -n k3s kubectl'
$K delete clusterrolebinding probe-lab-prometheus
$K delete clusterrole probe-lab-prometheus
$K delete namespace probe-lab
$K get clusterrole,clusterrolebinding | grep probe-lab || echo 'no probe-lab cluster RBAC left'
```
