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

The engine fits the state 2 KiB under the cap, leaving room for the call record
the controller appends before the next step. When dropping payloads is not
enough, the state budget is exhausted like any other: the run ends as
`budget_exhausted` with a report. A final envelope is never fed back to a
worker, so it is bound by the whole-result limit rather than the state cap.

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

## Alert intake

`internal/intake` turns Alertmanager webhook notifications (payload version 4)
into incidents. It decides what a notification means and never starts model
work, so the receiver answers `202` at once; a receiver that blocked would make
Alertmanager time out and retry, and a retry is a duplicate.

Every notification gets an outcome, including those that start nothing:

| Outcome | When |
| --- | --- |
| `opened` | firing, new: an `alert`-triggered incident, to be investigated |
| `duplicate` | same dedupe key, or its group is already open: appended, nothing started |
| `heartbeat` | only `Watchdog` / `severity=heartbeat` alerts: counted, never investigated |
| `resolved` | the group's open incident is closed |
| `ignored` | resolved, with no open incident for the group |
| `unmapped` | firing, but no configured label names a service: recorded, not guessed |

Resolution is decided **before** dedupe. The dedupe key is
`sha256(groupKey | status | first startsAt, or last endsAt when resolved)`, so a
resolution never matches its firing key; deduping first would open an incident
for an alert that has already stopped.

The incident is built from the group's earliest alert. Its symptom is the
alert's summary, redacted and bounded like any untrusted text, and its window
opens 30 minutes before the alert's start and is capped at `gateway.MaxWindow`.
Namespace and entity (pod or instance) stay on the intake record rather than in
the `probe/v1` incident.

Routes: `POST /webhook/alertmanager`, and read-only `GET /incidents` and
`GET /incidents/{id}`. All need the bearer token, compared in constant time.
`GET /healthz` is open. An empty token refuses to start. A payload that cannot
be acted on gets a `4xx`, which Alertmanager does not retry.

### Server mode

`vora-probe serve --config` puts intake in front of a queue (`internal/serve`).
An opened incident is either queued or recorded as `rate_limited`: each alert
group, and each entity (pod or host), may start only a bounded number of
investigations in a rolling window (defaults: 3 per group and 5 per entity per
hour), so a flapping alert cannot monopolise the worker. Nothing is dropped;
the record says why it was held back.

One worker takes incidents in arrival order, so there is one investigation at
a time, as the CLI's lock guarantees. Each run is bounded by its wall-clock
budget. When the deadline passes, the run is closed with a report and the
worker moves on, so a stalled planner cannot hold the queue. The incident
record tracks `queued`, `rate_limited`, `investigating`, `concluded`,
`not_concluded`, or `error` (no report could be written), with the report
path. The worker runs in-process by default (`probe.Run`), or in a Vora sandbox
when the config names a Vora API. The server refuses to start without a bearer
token, a planner endpoint, a deadline, or positive rate limits. It listens on
`127.0.0.1:9480` unless told otherwise.

Intake's state is an append-only log, `<out>/incidents.jsonl` (0600, one
writer, enforced by a lock). Every change is one typed line, synced before it
is applied or acknowledged: a failed write answers `5xx`, which Alertmanager
retries, so nothing acknowledged is lost. On start the log is replayed through
the same code live changes use, so dedupe keys and open groups survive a
restart. A final line without its newline is a write that never finished and
was never acknowledged, so it is cut off; a corrupt line anywhere else refuses
to load. The server then rebuilds its queue and rate-limit windows from the
records: queued incidents resume in arrival order, and one whose run was cut off
runs again as its next attempt, with a new journal, the old one kept, and the
reason on the record.

### Watch

With a `serve.watch` block, `internal/watch` forecasts memory exhaustion on the
named targets before anything fails (#14). Targets are listed, never
discovered. Every tick it reads each target's working set (trailing window,
default 30m) and limit **through the same gateway port and allowlist an
investigation uses**, so watching adds no egress and no permission. A tick
spends at most `max_queries_per_tick` (two per target, default 20), and targets
beyond that are observed on later ticks, in turn.

Each target has at most one forecast, and its state is in the incident log:

- **opened** when `forecast/v1` puts the limit within the horizon. It becomes an
  incident with trigger `forecast` and a conditional symptom, and goes through
  the same queue, rate limits and delivery as an alert.
- **revised** only when the ETA moves more than 20% from where the open forecast
  projected it. Smaller moves are noise.
- **withdrawn** when the trend stops (not growing, a poor fit, a reset, or growth
  now beyond the horizon), with the reason. A gap in the data is not a trend, so
  it holds the forecast instead.
- **realized** when the working set reaches the limit. That is the forecast
  coming true, not a withdrawal.

A restarted server reads open forecasts back from the log and continues them.

Every tick also labels the forecasts whose outcome has become knowable, by
code, and writes the label to the log once:

- `true_positive`: realized, or an alert for the same target arrived within the
  horizon (P1 intake's alerts are free labels);
- `withdrawn`: taken back with no failure, kept apart from false alarms;
- `missed_after_withdrawal`: withdrawn, then an alert came;
- `false_alarm`: the horizon passed with no crossing and no alert.

With `serve.watch.shadow`, forecasts are recorded and labelled but not
investigated or posted. That is the mode for a real deployment before anyone
should be paged by a forecast, and it builds the labelled history there is
none of. The labels are visible in `GET /incidents`.

In chat, a forecast lives in one thread. The report is labelled `forecast ·`.
Each material revision is a reply with the new conditional statement, posted
once, because the log counts the revisions the thread has heard. A withdrawal
(with its reason) or a realization is the last reply, in its own words, never
"the alert resolved". A revision that arrives after the forecast ended is
dropped, because the end supersedes it. A report posted late carries the latest
forecast and how it ended.

### Delivery

With a `serve.slack` block, every finished incident is posted by
`internal/deliver`, from a queue of its own, so posting never blocks the webhook
or the investigation worker.

- **Routing is code.** The channel and label come from the run's outcome and the
  alert's severity: `finding: <claim>`, `inconclusive`,
  `not concluded (<status>)` or `no report`. Critical alerts go to a critical
  channel when one is configured. A model never decides where, or whether,
  something is posted.
- **The message keeps what makes the report worth reading.** It shows the
  environment on every message, the symptom, the leading claim with its
  evidence IDs, every refused claim with its narrowed form, the missing
  evidence, and the recommendation with its execution status. A run that did
  not conclude says so and recommends nothing. Alert text is escaped, so a rule's
  summary cannot mention `@channel` or disguise a link. Sections and blocks are
  bounded to Slack's limits, and truncation says so.
- **Idempotent.** The first post's `ts` is stored on the incident, in the
  incident log. A retry, a duplicate trigger or a restart that finds it does not
  post again. A resolution after the post is a reply in its thread. A report
  posted after the alert resolved says so, and nothing follows.
- **Never fails an investigation.** The report is on disk before anything is
  posted. A post is attempted a bounded number of times (3, honouring Slack's
  `Retry-After`) and paced at one per second. A post that still fails is
  recorded with its error and retried on the next start.

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

### Forecast derivation (`forecast/v1`)

Foresight (#14) starts from one pure derivation, `ForecastExhaustion`: given
samples and a known limit, when does the series reach the limit if its current
growth persists? It is versioned separately from `calc/v1`, so tuning it
changes no existing report. The outcome is one of three:

- `within_horizon`: a point estimate and a band.
- `beyond_horizon`: real growth, but too slow to raise.
- `refused`: every reason that applies, each with its numbers.

A refusal is a result, not an error. A forecast is refused when:

- the limit is unknown;
- there are too few samples, or the window is too short;
- the series resets inside the window (a restart);
- it is not growing, including growth indistinguishable from none;
- a line fits poorly (a sawtooth, a GC cycle, a step);
- it is already at the limit.

The band is where the fit's confidence band, ŷ(t) ± k·s·√(1/n + (t−t̄)²/Sxx),
meets the limit. The upper edge gives the earliest crossing and the lower edge
the latest. It is a band of plausible crossings, never a probability. The
thresholds in `ForecastPolicy` were set on the development split of the
recorded lab scenarios and frozen before the held-out split was scored. They
met every acceptance criterion on dev unchanged, so they were frozen as they
were. A test pins them, because changing one invalidates the held-out result.

The forecast suite (`evaluate --suite forecast`) replays recorded lab scenarios
(`test/fixtures/forecast/{dev,held-out}`) the way a watch loop will: every
minute, over a trailing 30-minute window, using only what had been sampled by
then. It scores the runs against answer keys that sit beside the cases and are
read only for scoring:

- positives detected before the kill, with their lead times;
- how often the first band held the kill;
- false alarms, meaning a negative with a forecast still open at the end;
- forecasts opened and then withdrawn, reported separately, with how many were
  withdrawn before their predicted crossing;
- lead-time claims on failures that gave no warning, which must be zero.

The results are counts, not rates presented as probabilities.

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
loop: an invalid planner response is retried once and then ends the run as
`failed`.

The live planner asks the provider for a strict JSON Schema reply
(`planner-prompt/v2`). The schema is built from the same closed sets the engine
enforces, so the provider cannot produce a reply that is missing a field or
names something outside the allowlist. A field an action kind does not use is
`null`. On OpenRouter the request also sets `provider.require_parameters`,
because OpenRouter otherwise silently drops a parameter a provider does not
support. The engine still validates every reply: the schema narrows what can
arrive, it does not replace the contract.

A second planner endpoint (`VORA_PROBE_MODEL_FALLBACK_*`, with its own timeout)
is tried when the first fails: a transport error, a timeout, a non-2xx status,
or an unreadable reply. It is never tried once the run's deadline has passed.
Every attempt is charged to the model-call budget, so a fallback is never free
and cannot loop. The trace records, on every planner call, the endpoint and the
model the provider says answered, and why an earlier endpoint was passed over.
The fallback is for the planner alone. An evaluator arm under comparison is
reported as failed, never substituted.

Every run publishes a report, whatever its status. A run that ends `failed` or
`budget_exhausted` gets a report that does not conclude: code builds it from
the state, it records the hypotheses, evidence, gaps, decisions and trace, and
it states no leading claim, evaluates no claims and recommends nothing, because
a verdict on partial evidence reads as a conclusion whatever it is labelled.
Callers also get `probe.ErrNotConcluded` beside the report, so nothing
downstream counts the run as a finding; the CLI exits non-zero.

The same holds when the controller cannot continue: the planner stalls past the
deadline (`budget_exhausted`), or a request is refused, or the worker or its
sandbox fails (`failed`). `Engine.Abandon` closes the run from the last state
the controller holds, records the cause as an escalation, and publishes that
report. The cause is kept in the returned error, so an interrupted worker is
still `ErrInterrupted`. Only a controller that dies outright leaves no report
for that attempt: its journal still shows the unanswered request, and in server
mode the incident runs again as its next attempt when the server restarts.

## Incident classes

An alert maps to a class (`investigation.Classes`); `ContainerRestartLoop` and
`KubePodCrashLooping` are `crashloop`, and `ContainerOOMKilled` is `oom`.
Intake records the class on the incident. The planner is told the class's
competing hypotheses and the evidence to collect first, as guidance: it still
proposes what it judges, and the claims policy is the same for every class. A
class never makes a conclusion admissible.

## Context packages

`context_dir` names a directory of operator-written reference: each
`<name>.md`, whose first line is its description and the rest its body
(topology, what normal looks like, known quirks). The controller reads the
catalog at the start of a run and puts it in the state, because the worker has
no filesystem. The planner sees names and descriptions, and asks for a body with
`read_context`. That is not an infrastructure action and never goes to the
gateway.

**Context is not evidence.** A package is its own record type (`Context`),
never an `Observation`. No fact, relation or claim is built on it, and a claim
that cites it cites nothing the policy recognises, so it is refused like any
unretained evidence. Reports list the packages consulted in their own section,
apart from the evidence.

Loading is bounded. A name must match `^[a-z0-9][a-z0-9-]{0,62}$`, so it has no
separators and no dots. The resolved path must stay inside the directory, so a
symlink that points out is refused. Only regular files are read, a body is at
most 8 KiB and redacted, a run may read at most three packages, and each read
is charged to the infrastructure-call budget.

## Logs

`logs.query` is a closed action. The model names one filter from
`gateway.LogFilters` (`error`, `out_of_memory`, `panic`, `timeout`) and a window
of at most an hour. It never writes a query: the adapter builds it from a fixed
stream selector for the entity plus that filter's fixed line matcher.

Logs carry the most secrets, so they are offered only to incidents of severity
`critical`, `high` or `warning`. An incident of low or unknown severity (a
forecast, a manual run without one) is not offered them. The engine refuses a
planner reply that asks anyway, and the planner's schema for such an incident
cannot even express the action.

A log observation's statement counts lines and gives times. It never quotes
a line, because a log line is exactly where text written to steer a model
lives. The lines stay in the payload, redacted, as evidence. Redaction works on
the decoded payload, so a secret at the end of a line (`password=x"`) is removed
without breaking the JSON around it. A lab without a log source answers
`unavailable`, which becomes a coverage gap rather than a refusal.

With `lab.loki_url` set, the live adapter asks Loki two bounded questions for
the entity's pods in the configured namespace (the Prometheus mapping's
selector), with the filter's fixed matcher:

- the exact count over the window, from `sum(count_over_time(…))` on the
  instant endpoint;
- the first 200 lines, oldest first, from `query_range`, merged across streams
  by time.

When there are more matches than lines kept, the answer is `partial` and
`truncated`, so it becomes a coverage gap and is never read as the whole of the
logs. Policy runs before any request, so a filter outside the closed set never
reaches Loki.

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
- `report.json`, `report.md` — the report in machine and human form, written
  for every run, including one that did not conclude. When the config names
  `lab.prometheus_ui_url`, each metric observation in the report links to the
  Prometheus graph of its exact query, window and resolution. The controller
  builds these links after the report, from what the observation recorded
  (`gateway.PrometheusGraphURL`), never from model text. Kubernetes evidence
  has no graph and gets no link. Replays carry no links and stay byte-identical.
  Slack posts link cited evidence IDs the same way.
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
