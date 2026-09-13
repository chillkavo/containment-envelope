# containment-envelope

# Execution Envelope — Verifiable Containment for AI Agents

Apart AI Incident Response Sprint · Track 1 · September 2026

## What it is

A declarative permission scheme for agent execution environments, with a verifier that detects divergences between what was declared and what actually occurred using only public artifacts — without access to the laboratory network.

## How to run it

```
python src/run.py
```

## What we found

Of 10 containment violation classes, 6 are detectable from public artifacts, 1 is conditional, 2 are partial, and 1 is not.
See `results/matriz.md`.

## Limitations

The included envelopes and digests are illustrative examples, not actual configurations from any laboratory. The verifier operates on synthetic data.

## License

MIT
