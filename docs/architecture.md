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

Replay runs the worker in this process; the live controller (`internal/probe`)
runs the same binary inside a Vora sandbox and drives it one step at a time over
the public exec API. Both are the same port — `probe.StepRunner` — so the loop
cannot tell where a step ran, and the offline suite is evidence about the
protocol rather than about a mock.

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

## Live controller leg

The controller creates one sandbox per attempt — `NETWORK_NONE`, bounded
resources, and a TTL longer than the run's own wall-clock budget so the
controller reaps it rather than a TTL expiring mid-step. Every step is a
fixed-command exec with the bounded envelope on stdin and exactly one result line
on stdout. The sandbox is destroyed on every exit path, including the failure
paths, and its whole life is journaled as `sandbox` events between `run_started`
and `run_finished`.

Exit handling is the subtle part, and it is why the leg exists. protojson omits
fields holding their default value, so a **successful** execution arrives as
`{"exit":{"reason":"EXITED"}}` with no `exitCode` at all. An execution whose
exit chunk never arrives is a different thing — the run was interrupted — and
`probe.ErrInterrupted` makes the two impossible to conflate. Oversized, malformed
or multi-line output is refused rather than trimmed into shape.

The worker measures the wall-clock budget against `Run.Used.StartedAt` using its
own clock, so a live run uses the wall clock while replay keeps its frozen,
synthetic one. A frozen start older than the budget would otherwise read as
exhausted on the first step.

The released worker image is distroless and has no shell on purpose. Vora's gVisor
backend starts every sandbox with `/bin/sh -c 'sleep 86400'`, which such an image
cannot satisfy, so a distroless worker must run on the `bwrap` backend.

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
  because that is exactly what an interruption leaves behind. A live run also
  records `sandbox` created/destroyed events, which correlate the run with the
  sandbox it ran in.
- `report.json`, `report.md` — the report in machine and human form.
- `state.json` — written instead of a report when a run ends `failed` or
  `budget_exhausted`. It is the final state envelope, so the decision that ended
  the run survives the worker; it is not a report and makes no finding.
- One investigation at a time, enforced by a `flock` on `<out>/probe.lock`, which
  the kernel releases even if the process dies.
- Artifacts are owner-readable (`0600`), live artifacts are git-ignored, and the
  fixtures under version control remain the source of truth.

## The evaluator port

Three arms can label evidence: the deterministic rules, a baseline LLM, and Jev.
They implement one interface (`investigation.RelationEvaluator`) answering one
question: *how does this body of evidence bear on this hypothesis?* Everything
else is held constant — the planner and its recorded turns, the evidence (through
the same normalization the loop uses), the label definitions, and the claims
policy that runs afterwards and cannot be overridden by an arm.

What is deliberately *not* constant is how the arms are asked. Both model arms
receive the same label definitions and the same rules text, rendered from
`models.Definitions()` and `models.Rules`, because an arm told that proximity is
not a mechanism and an arm not told would make the comparison a comparison of
prompts.

Two properties are enforced on every arm:

- **Full coverage.** An arm must label every observation it was given, exactly
  once. A partial answer is an invalid response, not a partial result; a model
  that quietly drops the inconvenient evidence is the failure this repository
  exists to prevent.
- **No substitution.** An arm whose endpoint is missing is *blocked*. It is
  reported as blocked and contributes no labels. Falling back to another arm
  would report a result for an experiment that never ran.

Model calls are charged to the model-call budget, and only calls marked remote
are charged — the deterministic arm answers from rules and must not be priced as
if it called a model. Evidence is labelled incrementally and a hypothesis revised
by the planner has its labels dropped, so a model arm's call count is a property
of the arm rather than of how often the loop happens to reassess. The
deterministic arm is the exception: its rules read the whole body of evidence, so
a label can go stale when later evidence arrives (a working set labelled "no
configured limit" once the limit is retained), and since it costs nothing it is
re-asked about every observation on every reassessment.

## Reading a comparison

```bash
go run ./cmd/vora-probe evaluate --out .probe/evaluation        # fixed input
go run ./cmd/vora-probe evaluate --loop --repeats 3             # plus whole-loop
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --evaluator jev
```

Endpoints are run configuration, never build-time constants:

| Variable | Used by |
| --- | --- |
| `VORA_PROBE_MODEL_BASE_URL`, `VORA_PROBE_MODEL_API_KEY`, `VORA_PROBE_MODEL`, `VORA_PROBE_MODEL_MAX_OUTPUT_TOKENS` | baseline arm (`POST {base}/chat/completions`) |
| `VORA_PROBE_JEV_BASE_URL`, `VORA_PROBE_JEV_API_KEY`, `VORA_PROBE_JEV_MODEL` | Jev arm (`POST {base}/v1/systemone`) |

With none set, the run still produces a comparison: the deterministic arm
answers, the model arms are reported as blocked. With one set, the other is still
reported as blocked. This is the intended offline behaviour, not a degraded mode.

The fixed-input suite lives in `test/fixtures/relations/`, split into `dev` and
`held-out`. The splits must be disjoint — `LoadSplits` refuses otherwise — because
a "held-out" case that also appears in development measures memorisation. Each
case carries a `rationale`, which is the claim that its expected label is
correct; if the rules cannot agree with a case's rationale, the case is wrong
rather than the arm, and the acceptance test says so.

A case is a *body* of evidence with one designated `target`, because real
questions need context: asking whether a rollout caused an impact requires both
the rollout and the impact measurement.

### What the numbers mean, and do not

The output is counts, a full confusion matrix, and the spread across repeats.
There is no statistical claim, and the report says so itself. A case answered
differently across repeats is reported separately as *unstable*: an arm that
answers differently each run is unusable even when its average looks fine.

Signals are counted separately because they are different failures:

| Signal | Meaning |
| --- | --- |
| agreement | the arm's label matched the case's expected label |
| unsupported supports | the arm asserted `supports` where the case expects anything else — an unfounded causal claim, worse than declining to decide |
| insufficient-context accuracy | of the cases that should be declined, how many were declined rather than guessed |
| unsafe recommendation | (whole loop) an arm produced a recommendation on a case whose cause the ground truth says is not established |
| traceability failures | (whole loop) a finding was published without citing evidence |
| unstable cases | repeats disagreed with each other |

`confidence` returned by Jev is the concentration of its answer distribution. It
is retained as classification metadata, worded as such in the report, and is
never presented as the probability that a label or a root cause is correct. No
arm's confidence can override the claims policy.

Cost is reported only when a price is known, and only for arms that actually
called a model. A guessed price next to exact counts is worse than no price.

Jev is not required to win. If the deterministic rules beat both model arms — as
they do on the current authored suite, which the rules were written against —
that is the result, and the held-out split is there to say how much of it
survives being written against.

## Limits

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

## Public surface

The layout is a contract, not a convenience:

| Path | Status |
| --- | --- |
| `gateway/`, `investigation/`, `models/`, `evaluation/`, `worker/`, `fixtures/` | importable, supported |
| `internal/store/`, `internal/probe/` | private, may change at any time |
| `cmd/` | command packages, not importable |

`test/layout` enforces both halves: a library package outside `internal/` may not
import `internal/`, and the list of expected public packages is pinned so renaming
one fails the build rather than someone else's. Command packages are exempt —
nobody imports a `main`, and the CLI legitimately drives the internals.

The fixture *loader* is public while the fixture *data* stays under
`test/fixtures/`: consumers pass an explicit path, and `fixtures.Root()` is an
in-repo convenience only.

## Commands

```bash
go test ./...                                   # offline, no credentials
go test ./test/fixtures -run TestFixtureIntegrity -update          # re-freeze a fixture payload
go test ./internal/evaluation -run TestCaseIntegrity -update       # re-freeze a case payload
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --out .probe
go run ./cmd/vora-probe replay test/fixtures/oom/oom-positive --evaluator jev
go run ./cmd/vora-probe evaluate --out .probe/evaluation --loop
go run ./cmd/vora-probe verify
```

The live controller leg is validated separately, against a live vora-api and the
released worker image (see `internal/probe/live_integration_test.go` for the
tunnel and environment it expects):

```bash
go test -tags=integration ./internal/probe/ -run TestLiveInvestigation
```

`cmd/vora-probe-worker` is the fixed worker binary: one serialized
`WorkerInput` on stdin, one `StepResult` on stdout, no arguments.
