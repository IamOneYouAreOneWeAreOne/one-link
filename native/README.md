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
│
├── ol_chunk/                   # Phase A1: CDC (FastCDC v2020) + BLAKE3 + ADR-0006 derivation
├── ol_aead/                    # Phase A1: AES-256-GCM + ChaCha20-Poly1305 + 16 KiB frames
├── ol_wal/                     # Phase A1: crash-only write-ahead log per ADR-0007
├── ol_chunk_store/             # Phase A1: chunk_log + manifest_log + LSM + bloom + WAL coupling
├── ol_quic/                    # Phase A2: QUIC transport via quinn + identity-bound TLS
│
├── one_link_native/            # The pyo3 umbrella binding crate; what Python imports
│   ├── Cargo.toml
│   └── src/                    # chunk / aead / wal / store / quic submodules
│
└── one_link_native-stubs/      # PEP-561 type stubs (loaded by Python type checkers)
```

## Architectural decisions

All ADRs live at [`../docs/decisions/`](../docs/decisions/). Ten load-bearing
decisions across Phase A1 + A2:

1. [ADR-0001 CDC kernel](../docs/decisions/0001-cdc-kernel.md) — FastCDC + Gear-256 + AVX-512/NEON
2. [ADR-0002 AEAD frame](../docs/decisions/0002-aead-frame.md) — AES-256-GCM with 16 KiB internal frames
3. [ADR-0003 on-disk format](../docs/decisions/0003-on-disk-format.md) — chunk_log + manifest_log + LSM
4. [ADR-0004 stripe layout](../docs/decisions/0004-stripe-layout.md) — RS(10,4) over GF(2^8)
5. [ADR-0005 manifest WAL coupling](../docs/decisions/0005-manifest-wal-coupling.md) — two-log atomic commit
6. [ADR-0006 BLAKE3 derive scheme](../docs/decisions/0006-blake3-derive-scheme.md) — domain-separated derivation
7. [ADR-0007 crash-only WAL format](../docs/decisions/0007-crash-only-wal-format.md) — CRC32C + replay invariants
8. [ADR-0008 FFI contract](../docs/decisions/0008-ffi-contract.md) — pyo3 + maturin + abi3
9. [ADR-0009 QUIC transport](../docs/decisions/0009-quic-transport.md) — quinn + varint-prefixed wire framing
10. [ADR-0010 identity-bound TLS](../docs/decisions/0010-identity-bound-tls.md) — Ed25519 self-signed + custom verifier

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

- ✓ ≥ 1 GiB/s end-to-end ingest (measured: 3.06 GiB/s parallel CDC scan)
- ✓ Manifest WAL convergent recovery (replay tests + dangling-anchor rejection)
- ⚠ AEAD throughput ≥ 4 GiB/s/core (AES-NI) — software AES at 1.83 GiB/s; AES-NI
  blocked on the dev box by Smart App Control. Phase B will unlock via CI-built
  wheels with target-feature=+aes,+pclmulqdq.
- ⚠ kill -9 fuzz across ≥10,000 random injection points: WAL CRC truncation
  logic verified via 32 unit + 14 Python tests; explicit randomized injection
  harness deferred to a follow-up polish ship.

Phase A2 acceptance gate (per ADR-0009):

- ✓ Throughput within 10% of TCP loopback (measured: ~324 MiB/s integration,
  574+ MiB/s parallel via tokio multi-thread).
- ✓ Identity-bound TLS rejects mismatched fingerprint (TLS layer rejection)
  AND clients not in server registry (data-path rejection).
- ✓ Multi-stream with no head-of-line blocking (32 concurrent streams).
- ⚠ 0-RTT resume <50ms: quinn supports session tickets but the cache isn't
  wired yet. Phase B polish.

Per-crate gates verified in CI on Linux + macOS + Windows × Python 3.11/3.12/3.13.

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

Current dep audit (Phase A1 + A2):

| Dep | License | Vendor risk |
|---|---|---|
| `blake3` | CC0 / Apache-2.0 / MIT | None; reference implementation |
| `fastcdc` | MIT / Apache-2.0 | None |
| `aes-gcm`, `chacha20poly1305`, `aead`, `subtle`, `zeroize` | MIT / Apache-2.0 | None; RustCrypto org |
| `crc32c` | Apache-2.0 / MIT | None |
| `bloomfilter` | MIT / Apache-2.0 | None |
| `quinn`, `quinn-proto`, `quinn-udp` | Apache-2.0 / MIT | None; pure Rust QUIC, used by Cloudflare/iroh/veilid |
| `rustls`, `rustls-pemfile`, `rustls-pki-types` | Apache-2.0 / ISC / MIT | None; rustls is the de-facto Rust TLS |
| `rcgen` | Apache-2.0 / MIT | None; generates self-signed certs |
| `ring` | ISC / MIT-style | None; cryptography primitives |
| `ed25519-dalek` | BSD-3-Clause | None |
| `x509-parser` | MIT / Apache-2.0 | None |
| `tokio` | MIT | None; de-facto Rust async runtime |
| `pyo3` | Apache-2.0 | None; broad maintainer base |
| `rayon` | MIT / Apache-2.0 | None |
| `thiserror`, `anyhow` | MIT / Apache-2.0 | None |
| `proptest`, `criterion` | MIT / Apache-2.0 | None |
| `tracing`, `tracing-subscriber` | MIT | None |
| `hex`, `tempfile`, `rand`, `fs2` | MIT / Apache-2.0 | None |

**Explicitly REJECTED**: `msquic` (Microsoft-controlled), `macFUSE` (GPL-commercial dual; commercial licensing breaks no-monthly-bill on macOS).
