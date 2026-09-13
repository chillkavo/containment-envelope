# Detection latency

Active attack window: days 1-5 (2026-07-09 to 2026-07-13, [DOC]).
Baseline: public attribution at day 12 (2026-07-09 to 2026-07-21, [DOC]).

## Primary result: daily cadence vs the attribution baseline

| Class | First day detected | Days saved vs 12-day baseline |
|---|---|---|
| V1 | 5 | +7 |
| V10 | 1 | +11 |
| V5 | 1 | +11 |
| V6 | 5 | +7 |

## Cadence sensitivity

| Class | Daily (day) | Weekly (day) | Monthly (day) | Days saved, daily | Days saved, monthly |
|---|---|---|---|---|---|
| V1 | 5 | 7 | 30 | +7 | -18 |
| V10 | 1 | 7 | 30 | +11 | -18 |
| V5 | 1 | 7 | 30 | +11 | -18 |
| V6 | 5 | 7 | 30 | +7 | -18 |

Monthly cadence bundles the entire active window into the first
digest, published on day 30 -- *after* the day-12 attribution baseline. At monthly cadence, attestation is slower than the investigation that actually happened; this is the honest downside of the cadence trade-off, not an edge case.

## Classes that never fire, at any cadence, in this incident

| Class | Why |
|---|---|
| V2 | Coverage gap, not a detection: `l7_terminated_egress` is declared False, so method use is out of scope by the lab's own honest declaration -- flagged every period, never as a finding. |
| V3 | Not observed: this incident used no undeclared credential reference. Detectable class, absent case. |
| V4 | Not observed: the escape used its declared shell tool. Detectable class, absent case. |
| V7 | Not triggered: reconstructed egress (40 MB) stays under the reconstructed ceiling (10 GB). Whether this holds for other plausible ceilings is exactly what sensitivity.py checks -- do not read this row as "V7 is undetectable." |
| V8 | Not detectable by design: the escape used a declared destination within every declared limit. No cadence helps. |
| V9 | Not detectable by design: cross-sandbox coordination is invisible from a single digest regardless of cadence. |
| V11 | Fires as `declared`, not a violation: the envelope honestly grants disabled classifiers for this environment. |

## Daily activity schedule (allocation detail)

| Day | Date | Actions this day | Cumulative |
|---|---|---|---|
| 1 | 2026-07-09 | 3304 | 3304 |
| 2 | 2026-07-10 | 3304 | 6608 |
| 3 | 2026-07-11 | 3304 | 9913 |
| 4 | 2026-07-12 | 3304 | 13217 |
| 5 | 2026-07-13 | 3304 | 16521 |
