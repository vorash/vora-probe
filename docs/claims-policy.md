# Claims policy

Probe's most important behaviour is refusing assertions it cannot support. This
document records what the policy enforces and why, so that a change to it is a
reviewable decision rather than a prompt tweak.

The policy lives in `internal/investigation/claims.go`. It runs *after* the
model and reads only retained evidence, so it cannot be talked out of a
refusal. Its version, `claims/v2`, is stamped on every verdict that appears in a
report.

## Claim kinds

| Kind | Assertion | Admissible when |
| --- | --- | --- |
| `memory_limit_termination` | The container was terminated for exceeding its memory limit. | A termination or event evidences the kill **and** a working-set measurement corroborates it **and** the peak reaches 90% of the configured limit (when the limit is known). |
| `memory_leak` | The application leaks memory. | Growth that **resumes after a restart**: the series is split at its resets, there are at least two segments, and each one is sustained growth (at least 3 samples over at least 10 minutes, rising). A single climb is refused, because it cannot tell a leak from a workload that needs more memory. Even when admitted, the verdict states that the allocation-level cause is unproven. |
| `allocation_defect` | A specific allocation defect exists. | Never in this slice: no allocation or profile evidence is collected. |
| `deployment_regression` | A rollout caused the impact. | The rollout is within 5 minutes of the measured impact onset **and** a mechanism (a log, trace, or a query-volume metric that actually changed across the rollout) is cited. |
| `resource_saturation` | CPU saturation caused the impact. | Peak CPU ratio reaches 0.85. |
| `non_memory_restart` | The restarts are not memory-driven. | A termination reason other than `OOMKilled`, or a probe-failure event, **and** no memory-limit kill is evidenced. |
| `unknown_cause` | The evidence does not establish a cause. | Always. Inconclusive is a valid result. |
| `exhaustion_forecast` | Memory reaches its limit within the horizon *if the current growth persists*. | `forecast/v1` makes a within-horizon forecast from the retained working set and limit, **and** the claim cites both. The statement is rendered by code and is always conditional. The claim never carries a recommendation. |

## The three refusals that matter

**Termination is not a leak, and neither is one climb.** A container killed at
its limit and restarted produces a sawtooth series, not sustained growth. The
two claims require different evidence, and the fixture `oom-positive` exists to
pin that boundary. A single sustained climb is not a leak either: a workload
that needs more memory looks the same until something stops it. A leak is what
persists, so the policy asks to see the growth resume after a restart
(`claims/v2`).

**Proximity is not causation.** A rollout completing shortly before an impact is
the most persuasive false signal in incident response. Two checks stop it: the
impact onset is measured against the pre-rollout baseline rather than taken as
the first sample of the window, and the claim must cite a mechanism that
actually changed across the rollout. Citing a mechanism-shaped metric that stayed
flat is not enough — `TestDeploymentRegressionRefusedWhenMechanismIsFlat` pins
that.

**Missing evidence is reported, not filled in.** A request that returns
`unavailable` or `truncated` becomes a coverage gap on the facts for that
entity. The claim that needed it is refused with a narrowed statement, and the
gap is published in the report. `missing-telemetry` pins this.

## Forecasts are hypotheses about the future

`exhaustion_forecast` is admitted only when the `forecast/v1` derivation makes a
forecast within its horizon. That requires enough samples over a long enough
window, a fit that passes the quality bar, a known limit, significant growth,
and no reset in the window. Otherwise it is refused with the derivation's
reasons, and narrowed to "a crossing of the memory limit is not foreseeable
from the retained evidence", or, when the growth is real but too slow, to
"memory is growing, but does not reach its limit within the horizon".

Its statement is never the planner's. Code renders it, conditionally: "memory
reaches its limit of N in 40m (between 32m and 51m) if the growth persists".
"The service will crash" is not a statement any evidence supports, so it never
reaches a report. A forecast recommends nothing: raising a limit or rolling
back on a trend alone is the reflex this policy exists to refuse. A step change
that gives no warning produces no forecast, and so no lead time is claimed for
it.

## Narrowed statements

Every refusal carries a `narrowed` statement: the weaker thing the evidence does
support. Reports render it beside the refusal, so a reader sees "the container is
evidenced as OOMKilled; its memory usage approaching the limit is not evidenced"
rather than a bare rejection.

## Remediation

`AllowRemediation` returns true only for an admissible, non-overclaim, non-
inconclusive verdict. It gates whether a recommendation may be *proposed*.
Nothing in this slice executes remediation, and
`ground-truth.json` files fail verification if they expect an executed
recommendation.
