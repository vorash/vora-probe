# Claims policy

Probe's most important behaviour is refusing assertions it cannot support. This
document records what the policy enforces and why, so that a change to it is a
reviewable decision rather than a prompt tweak.

The policy lives in `internal/investigation/claims.go`. It runs *after* the
model and reads only retained evidence, so it cannot be talked out of a
refusal. Its version, `claims/v1`, is stamped on every verdict that appears in a
report.

## Claim kinds

| Kind | Assertion | Admissible when |
| --- | --- | --- |
| `memory_limit_termination` | The container was terminated for exceeding its memory limit. | A termination or event evidences the kill **and** a working-set measurement corroborates it **and** the peak reaches 90% of the configured limit (when the limit is known). |
| `memory_leak` | The application leaks memory. | At least 3 samples, spanning at least 10 minutes, monotonically increasing. Even then the verdict states that the allocation-level cause is unproven. |
| `allocation_defect` | A specific allocation defect exists. | Never in this slice: no allocation or profile evidence is collected. |
| `deployment_regression` | A rollout caused the impact. | The rollout is within 5 minutes of the measured impact onset **and** a mechanism (a log, trace, or a query-volume metric that actually changed across the rollout) is cited. |
| `resource_saturation` | CPU saturation caused the impact. | Peak CPU ratio reaches 0.85. |
| `non_memory_restart` | The restarts are not memory-driven. | A termination reason other than `OOMKilled`, or a probe-failure event, **and** no memory-limit kill is evidenced. |
| `unknown_cause` | The evidence does not establish a cause. | Always. Inconclusive is a valid result. |

## The three refusals that matter

**Termination is not a leak.** A container killed at its limit and restarted
produces a sawtooth series, not sustained growth. The two claims require
different evidence, and the fixture `oom-positive` exists to pin that boundary.

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
