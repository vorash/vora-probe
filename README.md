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
| 3 | `feat/model-comparison` | Baseline LLM and Jev evidence-relation evaluators, comparison harness |
| 4 | `feat/vora-integration` | Immutable worker image, fixed-command exec over the Vora public API |
| 5 | `feat/isolated-live-lab` | Disposable bounded Kubernetes lab with Prometheus and Grafana |
| 6 | `feat/live-evidence-acceptance` | Live evidence collection, acceptance runs and comparison table |

Steps 1 and 2 run entirely offline against recorded fixtures: no credentials, no
network and no live infrastructure are required.

## Status

Steps 1 and 2 are implemented and run entirely offline:

- **Step 1.** Domain records, the claims policy, `calc/v1` derivations and four
  frozen OOM fixtures with hidden ground truth. See `docs/claims-policy.md`.
- **Step 2.** The bounded step protocol, an append-only journal, the fixture
  gateway, the recorded planner, and evidence-linked JSON and Markdown reports.
  See `docs/architecture.md`.
- **Step 3.** Three evidence-relation arms (deterministic rules, an
  OpenAI-compatible baseline, and Jev) behind one port, a fixed-input
  classification suite with development and held-out splits, and a comparison
  report of counts and spreads. Arms without a configured endpoint are reported
  as blocked, never substituted.

Steps 4 onwards land as their own reviewed pull requests and are gated on
operator-supplied infrastructure.

Alert-driven operation is in progress (#13): `vora-probe serve` receives
Alertmanager webhooks and investigates each new incident, one at a time, under
rate limits and a per-run deadline. See `docs/architecture.md`.

`vora-probe ask --config lab.json --service checkout-api "why does it restart?"`
is an investigation with a question for its incident. It is not a chat. It
runs the same bounded loop, allowlist and claims policy as an alert over the
last `--since` (at most 1h), prints the report, and exits non-zero when the run
does not conclude.

## Requirements

Go 1.25 or newer. No third-party dependencies.

## Using it as a module

The domain is importable. Everything outside `internal/` is a supported surface,
and the layout guard in `test/layout` refuses a build where a public package
reaches into a private one.

```
github.com/vorash/vora-probe
├── gateway/         the infrastructure contract: closed action and metric
│                    allowlists, typed payloads, policy, redaction
├── investigation/   records, claims policy, calc/v1 derivations, the step
│                    engine, evidence relations, the RelationEvaluator port
├── models/          planner and evaluator clients (OpenAI-compatible baseline,
│                    Jev, recorded)
├── evaluation/      the comparison harness: fixed-input suite, repeats,
│                    confusion counts, whole-loop runner
├── worker/          the bounded step protocol
├── fixtures/        loader and integrity checks for fixture bundles
└── internal/        store and the replay driver, private by construction
```

```go
import (
	"github.com/vorash/vora-probe/gateway"
	"github.com/vorash/vora-probe/investigation"
)
```

Tags are `v0.x`: the surface is intended to be stable but is not yet frozen, and
a breaking change will be a minor bump while the module is pre-1.0.

Tagged releases also carry prebuilt `linux/amd64` and `linux/arm64` archives for
`vora-probe` and `vora-probe-worker`, with a `checksums.txt`, plus the worker
image on `ghcr.io/vorash/vora-probe-worker`. Reference the image **by digest**.
The release notes print it.

## Try it

```bash
go test ./...

go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --out .probe
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --json
go run ./cmd/vora-probe verify
```

`replay` runs a full investigation against a frozen fixture: the same step
protocol, gateway and report path as a live run, with recorded answers in place of
a network. No credentials, no cluster and no model endpoint are involved.

Once the Vora CLI grows plugin dispatch (vorash/vora#37), the same entry point is
`vora probe replay …`. The binary stays standalone so it also works where the
`vora` CLI is not installed.

## What it refuses

Probe's most important behaviour is refusing what the evidence does not support.
The fixtures pin that, four per incident class, and each one fails a specific
overclaim:

| Case | What it pins down |
| --- | --- |
| `oom-positive` | An evidenced memory-limit kill is identified, and a leak is refused because the sawtooth series does not show sustained growth. |
| `misleading-deployment-correlation` | A rollout inside the proximity bound with flat memory and unchanged query volume ends inconclusive. Proximity is not causation. |
| `missing-telemetry` | Restarts are evidenced and the terminating cause is not. The report stays inconclusive and publishes its coverage gaps. |
| `non-oom-restart` | A probe-driven restart with memory far below the limit is never reported as an out-of-memory incident. |
| `crashloop/liveness-restart` | The kubelet kills the container over failing liveness probes (exit 137, reason `Error`). That is a probe restart, and a SIGKILL is not read as a memory kill. |
| `crashloop/application-crash` | The container exits with code 1 by itself and no probe fails. The crash is established and a probe restart is refused. |
| `crashloop/misleading-rollout` | A rollout lands two minutes before latency jumps, but the crashes began before it and query volume is flat. The crash is the finding, and the rollout is refused. |
| `crashloop/ambiguous-exit-and-probe` | An application exit beside a failing liveness probe is ambiguous both ways, so the case ends inconclusive rather than picking one. |

## Development

```bash
make check      # gofmt check, vet, tests — all offline
make build      # bin/vora-probe and bin/vora-probe-worker
make release    # cross-compiled archives + checksums into dist/
make evaluate   # the evaluator comparison
```

## Documentation

- `docs/architecture.md` covers the trust boundary, the step protocol, the evaluator port, limits and how to read a comparison.
- `docs/claims-policy.md` says what Probe may assert, and the evidence each assertion needs.
- `test/fixtures/oom/README.md` describes the fixture format and how to re-freeze a change.

## Licence

MIT. See `LICENSE`.
