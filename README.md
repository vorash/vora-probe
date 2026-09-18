# Vora Probe

Read-only infrastructure investigation with inspectable evidence.

Probe is an independent repository and workload. It consumes Vora's public
sandbox interfaces and owns the investigation domain: observations, hypotheses,
evidence relations, decisions and reports. It never mutates infrastructure.

The work is planned in seven steps, each landing as one reviewed pull request:

| Step | Branch | Scope |
| --- | --- | --- |
| 1 | `feat/contracts-and-fixtures` | Domain records, claims policy, deterministic derivations, frozen OOM fixtures with hidden ground truth |
| 2 | `feat/offline-vertical-slice` | CLI, bounded step protocol, journal, fixture gateway, planner, evidence-linked reports |
| 3 | `feat/model-comparison` | Baseline LLM and Jev evidence-relation evaluators, benchmark harness |
| 4 | `feat/vora-integration` | Immutable worker image, fixed-command exec over the Vora public API |
| 5 | `feat/isolated-live-lab` | Disposable bounded Kubernetes lab with Prometheus and Grafana |
| 6 | `feat/live-evidence-acceptance` | Live evidence collection, acceptance runs and comparison table |

Steps 1 and 2 run entirely offline against recorded fixtures: no credentials, no
network and no live infrastructure are required.

## Status

Step 1 (`feat/contracts-and-fixtures`) is implemented: the domain records, the
claims policy, the deterministic derivation layer, and four frozen OOM fixtures
with hidden ground truth. Steps 2 onwards land as their own reviewed pull
requests; steps 3 onwards are additionally gated on operator-supplied
infrastructure.

## Requirements

Go 1.25 or newer. No third-party dependencies.

## Documentation

- `docs/claims-policy.md` — what Probe may assert, and the evidence each assertion needs.

`docs/architecture.md` (trust boundary, step protocol, limits, benchmark
interpretation) arrives with step 2.

## Licence

MIT — see `LICENSE`.
