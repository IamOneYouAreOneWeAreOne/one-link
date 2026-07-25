# Benchmark baselines

This directory holds benchmark artifacts for the file-engine v2. The
`native_chunk.json` baseline is checked by the pinned GitHub benchmark job
(`.github/workflows/native_bench_gate.yml` + `scripts/bench_gate.py`). A PR
fails that gate if any tracked native throughput regresses by more than 5%.

`coherence_field.json` is different: it is a historical Python-FFI
microbenchmark captured on one local workstation. It is retained for
controlled laboratory comparisons, but it is not a portable release gate.
It predates the schema-v2 provenance fields and therefore cannot establish
its own CPU, Python, native-artifact, or build identity.

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

## Coherence-field baseline qualification

The coherence-field snapshot measures very short Python-to-Rust calls and
list/vector conversions. Its results vary materially with all of the
following:

- CPU model, heterogeneous-core placement, power state, and concurrent load.
- Operating system and architecture.
- Python implementation and minor version.
- Rust toolchain, PyO3 version, release profile, and native build flags.

Only compare `coherence_field.json` with a fresh result when every item above
is pinned to the reference environment and the runner is dedicated. The
explicit lab command remains available:

```text
python scripts/coherence_field_perf_snapshot.py --out perf.json --quiet
python scripts/bench_gate.py --results perf.json \
  --baseline bench_baselines/coherence_field.json \
  --max-regression-percent 10
```

Schema-v2 snapshots record the measurement contract, clock resolution,
sample count, OS/architecture, Python version, native version, and the native
artifact's size and SHA-256. Preserve that snapshot with any lab conclusion;
the metadata makes a comparison auditable but does not make unlike machines
comparable.

Do not rebase this file from a busy workstation or to make a release audit
pass. The portable operator/release check is
`scripts/coherence_field_slo_gate.py`; it enforces absolute end-to-end FFI
latency budgets derived from the five-second production field tick and the
Phase E solve allowance. Native solver regressions remain the responsibility
of the Criterion suite on a pinned benchmark runner.

## Files

- `native_chunk.json` — pinned native CDC + BLAKE3 + derivation throughputs
  (created on first reference run).
- `coherence_field.json` — historical, environment-qualified Python-FFI
  microbenchmark; dedicated-runner tooling only.
