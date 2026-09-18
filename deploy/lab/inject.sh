#!/usr/bin/env bash
# Operator-only fault injection.
#
# This script is the boundary the plan draws: the investigator observes, it
# never injects. Nothing here is reachable through the gateway, and the
# controller has no path to it.
#
# Usage: inject.sh <oom|non-oom|rollout|reset> [hold-mb]
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
    set_env "HOLD_MB=${2:-512}" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-"
    echo "injected: memory-test will OOM with a ${2:-512} MiB working set"
    ;;
  non-oom)
    # Fail the liveness probe with no memory pressure. Restarts happen; the
    # termination reason is not OOMKilled.
    set_env "HOLD_MB-" "FAIL_LIVENESS_AFTER=15s" "DROP_METRIC-"
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
  reset)
    set_env "HOLD_MB-" "FAIL_LIVENESS_AFTER-" "DROP_METRIC-"
    echo "injected: memory-test reset to idle"
    ;;
  *)
    echo "usage: $0 <oom|non-oom|drop-metric|rollout|reset>" >&2
    exit 2
    ;;
esac

# A missing-evidence window is not an injection at all: the controller asks for
# a fixed window before the workload existed, and the gateway reports it
# unavailable. That keeps "missing evidence" a property of the query, not a
# fault the lab pretends to have.
