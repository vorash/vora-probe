#!/usr/bin/env bash
# Operator-only: run forecast scenarios on the lab and record each as a fixture
# (vorash/vora-probe#14).
#
# For each <family>:<scenario>:<seed> it injects the scenario, waits for the
# container's first kill or the scenario's deadline, and reads the run back:
# the working set and its limit through the lab Prometheus, the kill from the
# pod status, and the drawn parameters (the ground truth) from the pod log.
# Runs are read back as soon as each ends, because the lab Prometheus keeps 6h.
#
# The investigator never runs this and cannot: it injects faults and reads pod
# logs, both outside the investigator's role.
#
# Usage: record-scenarios.sh <fixtures-root> <family:scenario:seed>...
# Example: record-scenarios.sh test/fixtures/forecast dev:step:1 held-out:ramp:1
set -euo pipefail

HOST="${LAB_HOST:-mini-vora}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:?usage: $0 <fixtures-root> <family:scenario:seed>...}"
shift
[ "$#" -gt 0 ] || { echo "no runs given" >&2; exit 2; }

# One ssh connection for the whole series: each new connection may need an
# approval, and a series runs for hours.
ctl="$(mktemp -d)/ssh"
ssh -o ControlMaster=yes -o ControlPath="$ctl" -o ControlPersist=24h -fN "$HOST"
trap 'ssh -o ControlPath="$ctl" -O exit "$HOST" 2>/dev/null || true' EXIT
remote() { ssh -o ControlPath="$ctl" "$HOST" "$@"; }
kube() { remote sudo -n k3s kubectl -n probe-lab "$@"; }

# Deadlines: a positive run ends at its kill, a negative one here. Each stays
# inside the 6h retention, so nothing ages out before it is read back.
deadline_for() {
  case "$1" in
    ramp) echo 7200 ;;
    slow-leak) echo 19800 ;;
    ramp-recover) echo 7200 ;;
    sawtooth|noisy-flat) echo 3600 ;;
    step) echo 2400 ;;
    *) echo "unknown scenario $1" >&2; exit 2 ;;
  esac
}

prom_range() { # query start end
  local q
  q="$(jq -rn --arg q "$1" '$q|@uri')"
  remote "sudo -n k3s kubectl get --raw '/api/v1/namespaces/probe-lab/services/prometheus:9090/proxy/api/v1/query_range?query=$q&start=$2&end=$3&step=15'"
}

record() {
  local family="$1" scenario="$2" seed="$3"
  local id="${scenario}-${family}-${seed}"
  local dir="$root/$family/$id"
  mkdir -p "$dir"
  echo "== $id: injecting"
  remote bash -s -- scenario "$scenario" "$seed" "$family" <"$here/inject.sh"
  kube rollout status deploy/memory-test --timeout=5m >/dev/null
  # The newest pod is the one following the scenario; the old one is going.
  local pod
  pod="$(kube get pods -l app=memory-test --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')"
  local start deadline killed="" reason=""
  start="$(date -u +%s)"
  deadline=$((start + $(deadline_for "$scenario")))
  while [ "$(date -u +%s)" -lt "$deadline" ]; do
    if [ "$(kube get pod "$pod" -o jsonpath='{.status.containerStatuses[0].restartCount}')" != "0" ]; then
      killed="$(kube get pod "$pod" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.finishedAt}')"
      reason="$(kube get pod "$pod" -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}')"
      break
    fi
    sleep 30
  done
  local end
  end="$(date -u +%s)"
  if [ -n "$killed" ]; then
    # Stop at the kill: the restarted container starts the shape over.
    end="$(date -u -d "$killed" +%s)"
  fi
  echo "== $id: recording $pod from $(date -u -d "@$start" +%FT%TZ) to $(date -u -d "@$end" +%FT%TZ) (kill: ${killed:-none} ${reason})"

  local truth
  if [ -n "$killed" ]; then
    truth="$(kube logs "$pod" --previous | sed -n 's/^.* scenario {/{/p' | head -1)"
  else
    truth="$(kube logs "$pod" | sed -n 's/^.* scenario {/{/p' | head -1)"
  fi
  [ -n "$truth" ] || { echo "$id: no scenario line in the pod log" >&2; exit 1; }

  local sel="namespace=\"probe-lab\",pod=\"$pod\",container=\"memory-test\""
  prom_range "container_memory_working_set_bytes{$sel}" "$((start - 60))" "$end" >"$dir/.working_set.json"
  prom_range "container_spec_memory_limit_bytes{$sel}" "$((start - 60))" "$end" >"$dir/.limit.json"

  # The series: the longest cAdvisor series for this container, which is the
  # container that followed the scenario, from the injection to the kill.
  jq --arg id "$id" --arg split "$family" --argjson start "$start" --argjson end "$end" \
    --slurpfile limit "$dir/.limit.json" '
    (.data.result | max_by(.values | length) | .values) as $v
    | {
        schema_version: "probe/v1",
        id: $id,
        split: $split,
        entity: "memory-test",
        metric: "container_memory_working_set_bytes",
        resolution: "15s",
        limit_bytes: ($limit[0].data.result | max_by(.values | length) | .values[-1][1] | tonumber),
        samples: [$v[] | select(.[0] >= $start and .[0] <= $end)
                  | {at: (.[0] | floor | todate), value: (.[1] | tonumber)}],
        digest: ""
      }' "$dir/.working_set.json" >"$dir/series.json"

  jq -n --arg id "$id" --argjson params "$truth" --arg killed "$killed" --arg reason "$reason" \
    --argjson start "$start" --argjson end "$end" '
    {
      schema_version: "probe/v1",
      case: $id,
      scenario: $params.scenario,
      family: $params.family,
      seed: $params.seed,
      truth: $params.truth,
      params: $params,
      killed_at: (if $killed == "" then null else $killed end),
      kill_reason: (if $reason == "" then null else $reason end),
      recorded_from: ($start | todate),
      recorded_to: ($end | todate)
    }' >"$dir/ground-truth.json"
  rm -f "$dir/.working_set.json" "$dir/.limit.json"
  echo "== $id: $(jq '.samples | length' "$dir/series.json") samples, truth $(jq -r .truth "$dir/ground-truth.json")"
}

for run in "$@"; do
  IFS=: read -r family scenario seed <<<"$run"
  record "$family" "$scenario" "$seed"
done

remote bash -s -- reset <"$here/inject.sh"
echo "series done; memory-test reset. Freeze the digests: go test ./evaluation -run TestForecastCaseIntegrity -update"
