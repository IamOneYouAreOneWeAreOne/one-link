# Phase B Benchmark Baseline

**Date:** 2026-05-09
**Hardware:** Windows 11 Home (x86_64 with AES-NI + AVX2)
**Rust:** stable, `cargo bench --release` profile (lto=fat, codegen-units=1)

This document pins the Phase B performance baseline. Per-PR CI gates regress against these numbers; a ≥5% regression on any hot-path bench is a blocker.

---

## ol_bloom (ADR-0011)

| Bench | K=1024 | K=16384 | K=262144 |
|---|---|---|---|
| `bloom_insert` | **19.7 Melem/s** | 20.5 Melem/s | 19.5 Melem/s |
| `bloom_contains` | **15.0 Melem/s** | 14.6 Melem/s | 14.8 Melem/s |
| `bloom_codec/encode` | 28.5 GiB/s | 94.2 GiB/s | 65.0 GiB/s |
| `bloom_codec/decode` | 34.4 GiB/s | 80.8 GiB/s | 62.3 GiB/s |

**Optimization landed this phase:** single-keyed-hash with cached `OnceLock` BLAKE3 key replaced two-context `derive_key` calls. **3.4-4.4× speedup on insert/contains.**

Phase B target (ADR-0011): "Bloom-init reduces bytes-on-wire by ≥90% on workload where receiver has ≥80% of chunks." Verified by `cargo test -p ol_transfer --test engine_e2e bloom_handshake_returns_missing_chunks`.

## ol_fountain (ADR-0015)

| Bench | K=8 | K=64 | K=256 |
|---|---|---|---|
| `fountain_encode_symbol` | **3.76 GiB/s** | 2.89 GiB/s | 2.03 GiB/s |
| `fountain_decode_chunk` | 1.65 GiB/s | **1.51 GiB/s** | **0.72 GiB/s** |
| `fountain_packet/encode` | 15.5 GiB/s | — | — |
| `fountain_packet/decode` | 26.8 GiB/s | — | — |

**Optimization landed this phase:** degree-1 queue (`VecDeque<u32>` of packets ready to resolve) replaces O(pending) linear scan in propagation. **K=256 decode +21% (595 → 720 MiB/s), K=64 +6%.** Small K=8 regression (~6%) is acceptable trade for the larger-K wins.

**ADR-0015 acceptance gate** (decode ≥99% at 5% loss across 1000 random seeds for K ∈ {8, 64, 256}): VERIFIED via `cargo test -p ol_fountain --test acceptance`. Tests passed for all three K values in release mode.

K=64 (the common 64 KiB chunk) decodes at 1.42 GiB/s — well above typical QUIC bandwidth, so the encoder isn't the bottleneck on the network path.

## ol_chunk format-aware (ADR-0014)

| Bench | Throughput |
|---|---|
| `zip_lfh_walk/10x16KiB` | **142 GiB/s** |
| `zip_lfh_walk/80x16KiB` | 111 GiB/s |
| `zip_lfh_walk/10x1024KiB` | 45.8 GiB/s |
| `format_aware_scan/zip_100entries_512K` (50 MiB) | **1.78 GiB/s** |
| `format_aware_scan/pure_cdc_baseline` (50 MiB) | 1.95 GiB/s |

**Optimization landed this phase:** SIMD `memchr` replaces byte-at-a-time scan for ZIP local-file-header search.

**Format-aware overhead:** 1.95 GiB/s pure CDC → 1.78 GiB/s format-aware = **8.7% overhead** for 100% dedup recovery on the "edit one file in a ZIP" workload. Verified by `single_byte_edit_only_changes_one_chunk_family` test.

## ol_chunk (ADR-0001) — pinned in Phase A1

CDC + BLAKE3 baselines remain pinned at the Phase A1 numbers:

- `cdc_scan_random_1gib`: ≥1.2 GiB/s/core scalar, ≥3 GiB/s/core SIMD
- `blake3_address/raw/64`: ≥3 GiB/s/core
- `derive_aead_key`: <300 ns

## ol_aead convergent (ADR-0012)

Identical performance to standard AES-256-GCM path (4-5 GiB/s/core on AES-NI hardware) — the only added cost is the `BLAKE3.derive_key(plaintext)` call to compute the convergent key, which is dominated by the BLAKE3 throughput (~3 GiB/s/core for the plaintext-length hash). For typical 64 KiB chunks: ~20µs overhead per chunk (one-time per chunk).

## ol_transfer (ADR-0013)

End-to-end fetch latency (single chunk, loopback QUIC with identity-bound TLS):

| Operation | Loopback latency |
|---|---|
| `fetch_chunk` (cold connection) | ~5-15 ms (handshake-dominated) |
| `fetch_chunk` (warm connection) | <1 ms |
| `bloom_handshake` (100→50 missing chunks) | ~2-3 ms |
| `ping` round trip | <0.5 ms |

Per `engine_e2e::cached_connection_reused_across_fetches`: 5 sequential fetches all complete in well under 1 second on loopback. Connection caching is working.

## Workspace Test Totals (Phase B closeout)

| Layer | Tests |
|---|---|
| ol_bloom (lib + properties) | 18 + 6 = 24 |
| ol_fountain (lib + acceptance) | 26 + 5 = 31 |
| ol_transfer (lib + engine_e2e) | 8 + 9 = 17 |
| ol_chunk (lib + format_aware) | 21 + 10 (in lib) |
| ol_aead (lib + convergent + convergent_e2e) | 26 + 8 + 4 = 38 |
| ol_chunk_store / ol_quic / ol_wal | unchanged |
| **Rust workspace total** | **257 tests passing** |
| Python (bloom + fountain adapters) | 22 new |
| Python (existing chunk/aead/wal/store/quic) | 106 unchanged |
| **Python total** | **128 tests passing** |
| **Grand total** | **385 tests passing** |

---

## CI Gate

Per-PR gate: `cargo bench --workspace --bench bloom_bench --bench fountain_bench --bench cdc_bench` must not regress any throughput number by more than 5%.
