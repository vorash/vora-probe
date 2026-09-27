# Forecast evaluation (`forecast/v1`)

The first recorded evaluation of foresight (#14), reported as counts. It makes
no statistical claims: each split has one seed per scenario.

## How it was run

- **Scenarios.** Twelve lab runs were recorded on `probe-lab` on 2026-09-26/27:
  one seed per scenario (`ramp`, `slow-leak`, `ramp-recover`, `sawtooth`,
  `step`, `noisy-flat`) per family. The dev and held-out families draw from
  non-overlapping parameter ranges.
- **Frozen inputs.** Each case is the recorded working set and limit, and its
  answer key sits beside it (`test/fixtures/forecast`).
- **Replay.** `vora-probe evaluate --suite forecast` replays each case the way
  `watch` runs: every minute, over a trailing 30-minute window, using only what
  had been sampled by then.
- **Protocol.** The thresholds were set on dev and frozen before held-out was
  scored. They met every criterion on dev unchanged, so they were frozen as
  they were (`TestTheForecastThresholdsAreFrozen`).
- **Disclosure.** `ramp-held-out-1` was replayed once with the same thresholds
  while the harness was being built. Separately, the held-out score ran before
  the freeze commit landed, because signing failed on the first attempt. The
  thresholds were identical either way, and none was changed because of any
  held-out result.

## Dev

| Case | Truth | Forecast | Outcome |
| --- | --- | --- | --- |
| `ramp-dev-1` | positive | opened 10:21:14, ETA 1h25m45s (1h21m31s–1h30m24s) | killed 1h28m01s later, **inside** the band, realized |
| `slow-leak-dev-1` | positive | opened 01:34:28, ETA 2h00m00s (1h57m10s–2h02m59s) | killed 1h57m30s later, **inside** the band |
| `step-dev-1` | unforeseeable | none | no lead time claimed |
| `ramp-recover-dev-1` | negative | opened 17:03:41, predicted crossing 18:33:25 | **withdrawn 18:20:41**, before the predicted crossing |
| `sawtooth-dev-1` | negative | none | silent |
| `noisy-flat-dev-1` | negative | none | silent |

Detected 2/2 (lead times 1h28m, 1h57m); band held 2/2; false alarms 0;
opened-then-withdrawn 1 (withdrawn before its predicted crossing); lead-time
claims on unforeseeable 0. **Every criterion is met.**

## Held-out

| Case | Truth | Forecast | Outcome |
| --- | --- | --- | --- |
| `ramp-held-out-1` | positive | opened 12:00:34, ETA 26m28s (22m22s–31m58s) | killed 31m21s later, **inside** the band |
| `slow-leak-held-out-1` | positive | opened 21:04:29, ETA 1h49m58s (1h37m54s–2h05m14s); **opened 3 times, withdrawn twice** | killed 2h14m13s later, **9 min after the band's latest edge** |
| `step-held-out-1` | unforeseeable | none | no lead time claimed |
| `ramp-recover-held-out-1` | negative | opened 19:04:05, predicted crossing 19:35:16 | **withdrawn 19:43:05, 7m49s after** the predicted crossing |
| `sawtooth-held-out-1` | negative | **opened 13:42:28**, ETA 26m43s | withdrawn 4 min later |
| `noisy-flat-held-out-1` | negative | none | silent |

Detected 2/2 (lead times 31m, 2h14m); band held 1/2; false alarms (still open
at the end) 0; opened-then-withdrawn 2 (1 before its predicted crossing);
lead-time claims on unforeseeable 0.

## Against #14's acceptance

| Criterion | Dev | Held-out |
| --- | --- | --- |
| Positives forecast before the kill | met | met |
| Zero forecasts on sawtooth, idle, noisy-flat | met | **not met**: the sawtooth opened one for 4 minutes |
| Every ramp-recover forecast withdrawn before its predicted crossing | met | **not met**: withdrawn 7m49s late |
| Band coverage (published as a count) | 2/2 | 1/2 |
| No lead time claimed on `step` | met | met |
| Byte-identical replay of frozen cases | met | met |

**Held-out does not meet every criterion.** The failures share a shape: at the
held-out parameters (longer sawtooth periods, higher plateaus, faster ramps), a
single tick's window can fit a line well enough to open a forecast, and a
single tick can withdraw one. That produces a 4-minute forecast on a sawtooth,
a slow leak that flaps, and a near miss whose withdrawal waits for the window to
flatten.

## What happens next

Nothing is tuned on these numbers: that would turn held-out into a second dev
set. The fixes this points to have to be derived on dev, then judged on a
**new** held-out set recorded with fresh seeds. Candidates:

- hysteresis: several consecutive qualifying ticks to open, and to withdraw;
- a withdrawal once the predicted crossing has passed without a crossing;
- a longer or adaptive window at slow slopes.

Tracked in #39.
