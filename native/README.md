# One Link native — Rust hot-path crates

This is the Cargo workspace for One Link's file engine v2 native runtime.
Per [`../docs/FILE_ENGINE_V2_PLAN.md`](../docs/FILE_ENGINE_V2_PLAN.md),
hot-path code (chunk store, AEAD pipeline, transport, FUSE/FSKit/Dokan) lives
here as Rust crates that the existing Python daemon imports via pyo3.

## Layout

```
native/
├── Cargo.toml                  # workspace root
├── pyproject.toml              # maturin build backend for one_link_native
├── ol_chunk/                   # Phase A1: CDC + BLAKE3 (content-addressed addressing)
├── one_link_native/            # The pyo3 umbrella binding crate; what Python imports
│   ├── Cargo.toml
│   ├── src/lib.rs              # exposes ol_chunk::* (and future crates) as submodules
│   └── python/one_link_native/ # pure-Python part of the package (typestubs, pyi)
└── ...                         # additional crates as phases ship
```

## Architectural decisions

All ADRs live at [`../docs/decisions/`](../docs/decisions/). Phase A1's eight
load-bearing decisions:

1. [ADR-0001 CDC kernel](../docs/decisions/0001-cdc-kernel.md) — FastCDC + Gear-256 + AVX-512/NEON
2. [ADR-0002 AEAD frame](../docs/decisions/0002-aead-frame.md) — AES-256-GCM with 16 KiB internal frames
3. [ADR-0003 on-disk format](../docs/decisions/0003-on-disk-format.md) — chunk_log + manifest_log + LSM
4. [ADR-0004 stripe layout](../docs/decisions/0004-stripe-layout.md) — RS(10,4) over GF(2^8)
5. [ADR-0005 manifest WAL coupling](../docs/decisions/0005-manifest-wal-coupling.md) — two-log atomic commit
6. [ADR-0006 BLAKE3 derive scheme](../docs/decisions/0006-blake3-derive-scheme.md) — domain-separated derivation
7. [ADR-0007 crash-only WAL format](../docs/decisions/0007-crash-only-wal-format.md) — CRC32C + replay invariants
8. [ADR-0008 FFI contract](../docs/decisions/0008-ffi-contract.md) — pyo3 + maturin + abi3

## Build

Prerequisites:

- Rust toolchain (stable). Install via `rustup`: <https://rustup.rs>
- Python 3.11+ with `maturin`: `pip install 'maturin>=1.5,<2.0'`

Dev build (editable install, rebuilds Rust on import):

```bash
cd native
maturin develop --release
```

Production wheel:

```bash
cd native
maturin build --release
```

Cross-platform (CI):

```bash
# Uses cibuildwheel via .github/workflows/native_wheels.yml
# Linux manylinux2014, macOS universal2, Windows x86_64 with AVX-512 dispatched at runtime.
```

## Test

```bash
# Rust unit + integration tests for each crate
cargo test --workspace --release

# Property tests
cargo test --workspace --release -- --include-ignored

# Benchmarks (see ol_chunk/benches/)
cargo bench --workspace

# Python-side regression: Rust output byte-identical to existing Python cdc.py
cd ..
pytest tests/native/ -v
```

## Acceptance gates

Phase A1 acceptance gate (per FILE_ENGINE_V2_PLAN.md):

- ≥ 1 GiB/s end-to-end ingest on single Linux NVMe host
- `kill -9` survival across ≥ 10,000 randomized injection points; zero chunk
  loss; zero manifest divergence after recovery
- AEAD throughput ≥ 4 GiB/s/core (AES-NI) or ≥ 3 GiB/s/core (ChaCha20)
- Manifest WAL convergent recovery
- Round-trip canonical encoding (Coherence ↔ Rust byte-identical) for ≥ 1M
  random structured inputs

Per-crate gates are documented in each crate's README and verified in CI.

## Versioning

Native crate version (currently `0.21.0a0`) is independent of the One Link
parent project version. Native semver:

- Bump minor when a Phase ships its acceptance gate.
- Bump patch for non-breaking improvements within a phase.
- Bump major only on FFI-breaking changes (rare; never within a phase).

## Sovereignty audit

Per FILE_ENGINE_V2_PLAN.md sovereignty / defang concerns: every dep here is
verified open-source, no monthly-bill, no vendor lock-in. Audit at every
release. New deps require sovereignty review.

Current dep audit (Phase A1):

| Dep | License | Vendor risk |
|---|---|---|
| `blake3` | CC0 / Apache-2.0 / MIT | None; reference implementation |
| `fastcdc` | MIT / Apache-2.0 | None |
| `pyo3` | Apache-2.0 | None; broad maintainer base |
| `thiserror`, `anyhow` | MIT / Apache-2.0 | None |
| `proptest` | MIT / Apache-2.0 | None |
| `criterion` | MIT / Apache-2.0 | None |
| `tracing`, `tracing-subscriber` | MIT | None |
| `hex` | MIT / Apache-2.0 | None |
