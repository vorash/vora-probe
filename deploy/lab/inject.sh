#!/usr/bin/env bash
# Operator-only fault injection.
#
# This script is the boundary the plan draws: the investigator observes, it
# never injects. Nothing here is reachable through the gateway, and the
# controller has no path to it.
#
# Usage: inject.sh <oom|ramp|non-oom|drop-metric|rollout|scenario|reset> [args]
set -euo pipefail

NS=probe-lab
KUBECTL=(sudo -n k3s kubectl -n "$NS")

set_env() {
  # Restarting with a new environment is the fault: the workload reads its
  # parameters at startup, so a patch is a deterministic injection.
  "${KUBECTL[@]}" set env deployment/memory-test "$@"
}

case "${1:-}" in
  oom)
    # Allocate past the container limit at startup. The kernel kills it and the
    # pod restarts into the same kill: a sawtooth, which is not a leak.
    set_env "HOLD_MB=${2:-512}" "RAMP_MB-" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-" "SCENARIO-" "SEED-" "FAMILY-"
    echo "injected: memory-test will OOM with a ${2:-512} MiB working set"
    ;;
  ramp)
    # Climb to a level near the limit, hold it long enough to be scraped, then
    # push past the limit to force the kill. The hold is what makes the
    # corroborating sample reliable instead of a race with the scrape interval.
    set_env "HOLD_MB-" "RAMP_MB=${2:-240}" "RAMP_STEP_MS=${3:-4000}" "RAMP_HOLD_MS=${4:-30000}" "RAMP_PUSH_MB=${5:-64}" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-" "SCENARIO-" "SEED-" "FAMILY-"
    echo "injected: memory-test will ramp to ${2:-240} MiB, hold, then push past the limit"
    ;;
  non-oom)
    # Fail the liveness probe with no memory pressure. Restarts happen; the
    # termination reason is not OOMKilled.
    set_env "HOLD_MB-" "FAIL_LIVENESS_AFTER=15s" "DROP_METRIC-" "SCENARIO-" "SEED-" "FAMILY-"
    echo "injected: memory-test will restart on a failed liveness probe"
    ;;
  drop-metric)
    set_env "DROP_METRIC=${2:-request_error_rate}"
    echo "injected: memory-test stops emitting ${2:-request_error_rate}"
    ;;
  rollout)
    # Roll an unrelated deployment. It really changes, shortly before or after
    # an impact, and is still not a cause.
    stamp="$(date -u +%s)"
    "${KUBECTL[@]}" patch deployment unrelated-api \
      -p "{\"spec\":{\"template\":{\"metadata\":{\"labels\":{\"revision\":\"$stamp\"}}}}}"
    echo "injected: unrelated-api rolled out at $stamp"
    ;;
  scenario)
    # A seeded forecast scenario (vorash/vora-probe#14): the workload follows a
    # working-set shape drawn from the seed and the family. The drawn
    # parameters, the recording's ground truth, are in the pod log.
    name="${2:?usage: inject.sh scenario <ramp|slow-leak|ramp-recover|sawtooth|step|noisy-flat> <seed> [dev|held-out]}"
    seed="${3:?a seed is required, so the shape can be recomputed}"
    family="${4:-dev}"
    set_env "HOLD_MB-" "RAMP_MB-" "RAMP_STEP_MS-" "RAMP_HOLD_MS-" "RAMP_PUSH_MB-" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-" \
      "SCENARIO=$name" "SEED=$seed" "FAMILY=$family"
    echo "injected: memory-test follows scenario $name (seed $seed, family $family)"
    echo "ground truth: sudo -n k3s kubectl -n $NS logs deploy/memory-test | grep '^.* scenario '"
    ;;
  reset)
    set_env "HOLD_MB-" "RAMP_MB-" "RAMP_STEP_MS-" "RAMP_HOLD_MS-" "RAMP_PUSH_MB-" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-" "SCENARIO-" "SEED-" "FAMILY-"
    echo "injected: memory-test reset to idle"
    ;;
  *)
    echo "usage: $0 <oom|ramp|non-oom|drop-metric|rollout|scenario|reset>" >&2
    exit 2
    ;;
esac

# A missing-evidence window is not an injection at all: the controller asks for
# a fixed window before the workload existed, and the gateway reports it
# unavailable. That keeps "missing evidence" a property of the query, not a
# fault the lab pretends to have.
