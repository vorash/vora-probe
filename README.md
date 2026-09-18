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

Steps 1 and 2 are implemented and run entirely offline:

- **Step 1** — domain records, the claims policy, `calc/v1` derivations and four
  frozen OOM fixtures with hidden ground truth. See `docs/claims-policy.md`.
- **Step 2** — the bounded step protocol, an append-only journal, the fixture
  gateway, the recorded planner, and evidence-linked JSON and Markdown reports.
  See `docs/architecture.md`.

Steps 3 onwards land as their own reviewed pull requests and are gated on
operator-supplied infrastructure and credentials.

## Requirements

Go 1.25 or newer. No third-party dependencies.

## Try it

```bash
go test ./...

go run ./cmd/probe replay test/fixtures/oom/oom-positive --out .probe
go run ./cmd/probe replay test/fixtures/oom/oom-positive --json
go run ./cmd/probe verify
```

`replay` runs a full investigation against a frozen fixture: the same step
protocol, gateway and report path as a live run, with recorded answers in place of
a network. No credentials, no cluster and no model endpoint are involved.

## What it refuses

Probe's most important behaviour is refusing what the evidence does not support.
The four fixtures pin that, and each one fails a specific overclaim:

| Case | What it pins down |
| --- | --- |
| `oom-positive` | An evidenced memory-limit kill is identified, and a leak is refused because the sawtooth series does not show sustained growth. |
| `misleading-deployment-correlation` | A rollout inside the proximity bound with flat memory and unchanged query volume ends inconclusive. Proximity is not causation. |
| `missing-telemetry` | Restarts are evidenced and the terminating cause is not; the report stays inconclusive and publishes its coverage gaps. |
| `non-oom-restart` | A probe-driven restart with memory far below the limit is never reported as an out-of-memory incident. |

## Documentation

- `docs/architecture.md` — trust boundary, step protocol, limits and benchmark interpretation.
- `docs/claims-policy.md` — what Probe may assert, and the evidence each assertion needs.
- `test/fixtures/oom/README.md` — the fixture format and how to re-freeze a change.

## Licence

MIT — see `LICENSE`.
