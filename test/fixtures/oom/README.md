# OOM fixtures

Four frozen cases for the first end-to-end slice. Each directory holds:

- `bundle.json` holds everything the engine is allowed to see: the incident, the
  recorded planner turns and the recorded infrastructure answers.
- `ground-truth.json` is the hidden answer key. Only the evaluation harness loads
  it; nothing in the bundle references it.

| Case | What it pins down |
| --- | --- |
| `oom-positive` | An evidenced memory-limit kill is identified, and a leak is refused because the sawtooth series does not evidence sustained growth. |
| `misleading-deployment-correlation` | A rollout completes inside the proximity bound of the impact, with flat memory, no restarts and unchanged query volume. Proximity alone must not become causation. |
| `missing-telemetry` | Restarts are evidenced and the terminating cause is not. The report must stay inconclusive and publish its coverage gaps. |
| `non-oom-restart` | A probe-driven restart with memory far below the limit must not be reported as an out-of-memory incident. |

## Editing a bundle

Payloads are frozen by content digest. After changing a payload, re-freeze it:

```bash
go test ./test/fixtures -run TestFixtureIntegrity -update
```

Then re-run the tests. A payload edited without re-freezing fails verification,
which is what keeps a fixture from drifting silently.

## Adding a case

Copy an existing directory, satisfy `fixtures.Verify`, and add a
`ground-truth.json` that `fixtures.VerifyTruth` accepts. The leading claim must
appear in `allowed_claims`, and no claim may be both allowed and forbidden.
