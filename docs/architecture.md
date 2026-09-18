# Architecture

Probe investigates a service read-only and explains what it found. This document
covers the trust boundary, the step protocol, the limits, and how to read a
benchmark produced by this repository.

## Trust boundary

```
        ┌──────────────────────────────────────────────┐
        │ controller (trusted, holds credentials)       │
        │  - owns the network, the model, the store      │
        │  - authorises every request                    │
        │  - journals requests before execution          │
        └───────────────┬──────────────────────────────┘
                        │ bounded state envelope + one pending result
                        ▼
        ┌──────────────────────────────────────────────┐
        │ worker (untrusted, no network, no credentials)│
        │  - one deterministic transition per invocation │
        │  - emits one request or the final report       │
        └──────────────────────────────────────────────┘
```

The worker never chooses its own executable, URL or command. It is given a
bounded state envelope and one pending result, and it returns exactly one
schema-validated request or the final report. Everything the worker can ask for
is a member of `gateway.AllowedActions`, with a metric from
`gateway.AllowedMetrics`; anything else fails validation rather than being
interpreted.

Steps 1 and 2 run the whole loop in one process. The split is still real: the
replay driver invokes the worker through the same serialized interface the
controller will use, including the byte limits. That is why the offline suite is
evidence about the protocol and not just about a mock.

## Step protocol

One step consumes at most one pending result and emits at most one request.

```json
{
  "state":   { "incident": {}, "run": {}, "hypotheses": [], "observations": [], "relations": [], "decisions": [], "trace": [], "counters": {} },
  "pending": { "kind": "model" | "infra", "action": {}, "response": {}, "model": {} }
}
```

The worker answers with:

```json
{ "kind": "model_request" | "infra_request" | "final", "model_request": {}, "infra_request": {}, "report": {}, "envelope": {} }
```

Two budgets, two transports. The **state envelope** is capped at 64 KiB and
travels in `state`; a single **tool response** may be up to 2 MiB and travels in
`pending`. A response is normalized into a bounded observation before it is ever
stored, so a large answer can never inflate the state. If even the reduced
observation does not fit, the payload is dropped, the observation is marked
`truncated`, and it becomes a coverage gap — oversize input is reported, never
silently treated as complete.

`counters` carries the ID sequences. A worker is invoked fresh for every
transition, so without them the second observation of a run would be numbered
`OBS-0001` again.

## Determinism

Replay is byte-identical across runs, which is what makes a saved report worth
checking. Three things make that true:

- The clock is injected. Replay uses a monotonic synthetic clock anchored after
  the last recorded retrieval, so decisions never appear to precede their
  evidence, and no real latency leaks into the report.
- Ordered containers only. Relations, observations, claims and timeline entries
  are built by iteration over slices, never over maps.
- `calc/v1` derivations are pure functions of their inputs and are the only
  source of numbers in a report.

Replay latency is not reported, because it is not real. The call trace shows
durations only when a call actually took time, which is the live case.

## Limits

| Limit | Default | Where enforced |
| --- | --- | --- |
| Wall clock per investigation | 600 s | `Engine.exhausted` |
| Infrastructure calls | 50 | `Engine.exhausted` |
| Model calls (including retries) | 20 | `Engine.exhausted` |
| Steps | 40 | `Engine.exhausted` |
| Worker state envelope | 64 KiB | `worker.Step`, `Engine.fit` |
| Tool response | 2 MiB | `worker.Step`, `gateway.Policy.Accept` |
| Evidence window per request | 1 h | `gateway.Action.Validate` |
| Rendered statement | 2 KiB | `investigation.joinBounded` |

All retries consume the same persisted budget. There is no unbounded repair
loop: an invalid planner response is retried once and then rejects the run.

## Policy layers

Three independent checks, so withdrawing a permission never requires trusting a
model or editing a prompt:

1. `gateway.Action.Validate` — structural: the action kind is in the allowlist,
   the metric is in the allowlist, the window is well formed and bounded.
2. `gateway.Policy.Authorize` — situational: an explicit deny list and an entity
   scope applied on top of the allowlist.
3. `investigation.ClaimPolicy` — epistemic: what may be *asserted* about the
   evidence. See `docs/claims-policy.md`.

A refusal at layer 1 or 2 fails the run and is recorded as an escalation. A
refusal at layer 3 produces a narrowed statement instead, and the report shows
both the refusal and the narrowed form.

## Redaction

Tool output is untrusted. Credential-shaped spans are redacted before anything is
persisted, sent to a model, or written to a report. Redaction sets
`Completeness = redacted` and keeps the original digest, because the digest
identifies the evidence as retrieved. That mismatch is the only case
`Response.Validate` tolerates, and clearing the flag makes it fail again.

A log line that reads like an instruction stays data. It is never promoted to an
instruction, and `TestRedactTextKeepsInjectedInstructionsAsData` pins that.

## Planner context

The planner receives observation *summaries*: ID, type, statement, window,
retrieval time, completeness, digest and query metadata. It never receives a
payload. This bounds prompt-injection surface and keeps the envelope small, and
it means every number a model sees was rendered by code.

Ground truth never enters the planner or the evaluator. It lives in
`ground-truth.json` beside each bundle, is loaded only by the harness, and
`TestGroundTruthIsSeparate` proves a case directory verifies without it.

## Persistence

- `journal.jsonl` — append-only, one event per line, sequence numbers assigned by
  the writer and continued on reopen. Requests are journaled *before* execution
  and results before the next step, so an interrupted run reads as an unanswered
  request rather than as a success. A torn final line is tolerated on reopen,
  because that is exactly what an interruption leaves behind.
- `report.json`, `report.md` — the report in machine and human form.
- One investigation at a time, enforced by a `flock` on `<out>/probe.lock`, which
  the kernel releases even if the process dies.
- Artifacts are owner-readable (`0600`), live artifacts are git-ignored, and the
  fixtures under version control remain the source of truth.

## Reading a benchmark

Steps 1 and 2 do not produce a model benchmark. They produce four deterministic
cases evaluated against a hidden key. The numbers that matter here are
qualitative and falsifiable:

- The positive case identifies an evidenced memory-limit kill **and** refuses the
  leak claim, because the series is sawtooth.
- The misleading case has a rollout inside the proximity bound and still ends
  inconclusive, because proximity is not a mechanism.
- The missing-telemetry case ends inconclusive and publishes its two coverage
  gaps.
- The non-OOM case is never reported as an out-of-memory incident.

Step 3 adds the baseline-LLM and Jev evidence-relation arms. When it does, the
comparison is of counts and variances over three runs per variant, not of
statistical significance, and confidence scores are never presented as the
probability that a root cause is correct. Jev is not required to win; a
comparison that shows it does not help is a result.

## Commands

```bash
go test ./...                                   # 112 tests, offline
go test ./test/fixtures -run TestFixtureIntegrity -update   # re-freeze a payload change
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --out .probe
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --json
go run ./cmd/vora-probe verify
```

`cmd/vora-probe-worker` is the fixed worker binary: one serialized
`WorkerInput` on stdin, one `StepResult` on stdout, no arguments.
