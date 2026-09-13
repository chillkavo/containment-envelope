# containment-envelope

**Execution Envelope — Verifiable Containment for AI Agents**

Apart AI Incident Response Sprint · Track 1 · September 2026

## What it is

A declarative permission scheme for agent execution environments, with a
verifier that detects divergences between what was declared and what actually
occurred using only public artifacts — without access to the lab's network.

A lab publishes two signed artifacts: the **envelope** (what its sandbox was
granted, across seven capability families under default-deny) and a **telemetry
digest** (aggregate counters of what happened, never raw logs). A third party
checks one against the other.

## How to run it

    cd src
    python3 run.py            # detectability matrix
    python3 trace_incident.py # the July 2026 incident, traced
    python3 recalibrate.py    # enumeration vs. parameterisation

No external dependencies.

## What we found

Of 11 containment violation classes, **7 are detectable** from public artifacts,
2 partially, and 2 are not. Zero false positives across 4 clean controls.

Tracing the July 2026 OpenAI → Hugging Face incident: the verifier fires 9
findings across 6 classes, but **does not catch the escape itself**. The zero-day
was delivered to a *declared* egress destination, which is the class the matrix
already reports as undetectable.

> Attestation-based containment does not prevent the initial failure. It bounds
> how long a failure stays invisible from outside — roughly 12 days, in this case.

Results in `results/`.

## Structure

    schema/     reference envelope and digest, human-readable
    src/        verifier, test cases, incident trace, recalibration demo
    results/    generated output

## Limitations and dual use

The included envelopes and digests are illustrative examples, not actual
configurations from any lab. The verifier operates on synthetic data, and the
incident envelope is a **reconstruction** — OpenAI has not published its sandbox
configuration.

The detectability matrix is also a map of what evades detection: classes V8 and
V9 describe behaviour that produces a clean digest. We publish it because a
standard whose gaps are undisclosed produces confidence that is not earned.

## License

MIT
