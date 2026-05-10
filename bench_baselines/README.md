# Benchmark baselines

This directory holds the per-benchmark baselines that the file-engine v2
benchmark gate (`.github/workflows/native_bench_gate.yml` +
`scripts/bench_gate.py`) checks every PR against. A PR fails the gate if
any tracked metric regresses by more than 5% vs. the baseline.

## How baselines are produced

After Phase A1 Step Zero lands and the first reference CI run completes:

1. CI runs `python -m one_link.perf_lab_native --json --no-legacy --size-mib 64`
2. The `bench_gate.py --baseline` argument points here. With no file present,
   the gate exits NEUTRAL and prints the fresh JSON.
3. The maintainer reviews the fresh JSON, commits it to
   `native_chunk.json` (this directory) as the initial baseline.
4. From the next PR onward, the gate enforces no >5% regression.

## Updating a baseline

Baselines are *only* updated by a maintainer in the same PR that intentionally
changes the kernel (e.g., switching from FastCDC v2020 to a future kernel).
The commit message must include:

- The reason for the regression / change.
- The ADR amendment that covers it.
- The expected throughput delta and rationale.

The gate has no auto-update path on purpose.

## Hardware drift

Baselines are tied to the GitHub-hosted runner class (Ubuntu latest, x86-64).
If the runner class changes substantially (e.g., GitHub upgrades default
runner CPUs), the baselines will need to be re-pinned. This is a manual
maintenance step.

## Files

- `native_chunk.json` — pinned native CDC + BLAKE3 + derivation throughputs
  (created on first reference run).
