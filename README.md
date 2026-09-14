# containment-envelope

**Execution Envelope — Verifiable Containment for AI Agents**
Apart AI Incident Response Sprint · Track 1 · September 2026

## What it is

A declarative permission scheme for agent execution environments, with a verifier that detects divergences between what was declared and what actually occurred using only public artifacts — without access to the lab's network.

A lab publishes two signed artifacts: the **envelope** (what its sandbox was granted, across seven capability families under default-deny) and a **telemetry digest** (aggregate counters of what happened, never raw logs). A third party checks one against the other.

## How to run it

```
cd src
python3 run.py              # detectability matrix
python3 trace_incident.py   # the July 2026 incident, traced
python3 recalibrate.py      # enumeration vs. parameterisation
python3 noise.py         # false-positive decomposition, 1,000 digests
```

Python 3.11+, standard library only. No external dependencies.

## Where each claim comes from

| Claim in the paper | Produced by |
|---|---|
| Table 2 — detectability of the 11 violation classes | `run.py` |
| Table 3 — nine findings across six classes | `trace_incident.py` |
| Table 4 — recalibration v1 → v2 | `recalibrate.py` |
| §4.6 — false-positive decomposition | `noise.py` |

## What we found

Of 11 containment violation classes, 7 are detectable from public artifacts, 2 partially, and 2 are not.

Across 1,000 randomized clean digests, ~0.9% are genuine false positives (all from the step-budget check, whose ceiling sits close to the median run) and ~4.8% are non-actionable true positives: the invariant fired exactly as designed on a rare benign event. The 4 clean controls are boundary-condition checks, not a rate.

Tracing the July 2026 OpenAI → Hugging Face incident: the verifier fires 9 findings across 6 classes (presented as 7 rows in the paper; two rows merge two findings each), but does not catch the escape itself. The zero-day was delivered to a declared egress destination — the class the matrix already reports as undetectable.

Attestation-based containment does not prevent the initial failure. It bounds how long a failure stays invisible from outside. Attribution took 12 days here; with a daily digest cadence the first findings surface on day 1.

Generated output in `results/`.

## Structure

```
schema/     reference envelope and digest, human-readable
src/        verifier, test cases, incident trace, recalibration demo
results/    generated output
```

## Limitations and dual use

The included envelopes and digests are illustrative examples, not actual configurations from any lab. The verifier operates on synthetic data, and the incident envelope is a reconstruction — OpenAI has not published its sandbox configuration.

The detectability matrix is also a map of what evades detection: classes V8 and V9 describe behaviour that produces a clean digest. We publish it because a standard whose gaps are undisclosed produces confidence that is not earned.

## License

MIT
