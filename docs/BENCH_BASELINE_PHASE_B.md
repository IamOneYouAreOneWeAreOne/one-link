# Phase B Benchmark Baseline

**Date:** 2026-05-10 (revised after Phase B-2 sweep: group commit, fountain wire, scoped bloom, AEAD parallel, CDC parallel BLAKE3)
**Hardware:** Windows 11 Home (x86_64 with AES-NI + AVX2)
**Rust:** stable, `cargo bench --release` profile (lto=fat, codegen-units=1)

This document pins the Phase B performance baseline. Per-PR CI gates regress against these numbers; a ≥5% regression on any hot-path bench is a blocker.

---

## ol_bloom (ADR-0011)

| Bench | N=1024 | N=16384 | N=262144 |
|---|---|---|---|
| `bloom_insert` | **66.5 Melem/s** | 66.4 Melem/s | 65.0 Melem/s |
| `bloom_contains` | **38.5 Melem/s** | 38.4 Melem/s | 35.8 Melem/s |
| `bloom_contains_many` (batch) | ~68 Melem/s | ~69 Melem/s | ~67 Melem/s |
| `bloom_codec/encode` | 28.5 GiB/s | 94.2 GiB/s | 65.0 GiB/s |
| `bloom_codec/decode` | 34.4 GiB/s | 80.8 GiB/s | 62.3 GiB/s |
| `bloom_extend_par` (rayon) | — | 87 Melem/s | 63-96 Melem/s (>1M ids) |

**Optimizations landed this phase (cumulative speedup from original Phase B drop):**
1. Cached-keyed `OnceLock` BLAKE3 → 3.4-4.4× speedup.
2. **BLAKE3 → xxh3-128** swap (Bloom only needs uniform distribution, not collision resistance) → another **2.6-3.4×** on top.

**Net: 8-15× speedup vs original Phase B Bloom (4.7 → 38-66 M elem/s).**

Phase B target (ADR-0011): "Bloom-init reduces bytes-on-wire by ≥90% on workload where receiver has ≥80% of chunks." Verified by `cargo test -p ol_transfer --test engine_e2e bloom_handshake_returns_missing_chunks`.

## ol_fountain (ADR-0015)

| Bench | K=8 | K=64 | K=256 |
|---|---|---|---|
| `fountain_encode_symbol` | **4.27 GiB/s** | 3.01 GiB/s | 2.28 GiB/s |
| `fountain_decode_chunk` | 2.05 GiB/s | **1.69 GiB/s** | **0.83 GiB/s** |
| `fountain_packet/encode` | 15.5 GiB/s | — | — |
| `fountain_packet/decode` | 26.8 GiB/s | — | — |

**Optimizations landed this phase:**
1. **Degree-1 queue** in decoder propagation replaces O(pending) linear scan.
2. **SIMD u64-wide XOR** via `ptr::read_unaligned` (compiler vectorizes to AVX2 `vpxor` / NEON `eor`).
3. **Move-not-clone** of resolved payload Vec into `self.sources` slot.
4. **Skip zero-fill in encoder**: first-neighbor source copies directly into output buffer instead of `vec![0; N]` + XOR-against-zero.

**Net: K=256 decode +40% (595 → 834 MiB/s), K=64 decode +19%, encode +4-13% across K.**

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

### Phase B-2 parallel CDC scan baseline (rayon BLAKE3 hashing)

`scan_to_vec_parallel` keeps boundary discovery sequential but shards BLAKE3 hashing of each discovered chunk across cores. The CDC kernel itself stays sequential because the rolling hash carries state across bytes.

| Buffer | Sequential | Parallel | Speedup |
|---|---|---|---|
| 16 MiB | 2.21 GiB/s | **2.92 GiB/s** | **1.32×** |
| 64 MiB | 2.16 GiB/s | 2.82 GiB/s | 1.31× |
| 256 MiB | 2.08 GiB/s | **3.08 GiB/s** | **1.48×** |

Sequential FastCDC discovery is now the throughput floor (~2 GiB/s). Pushing past it requires shard-with-stitch-zone parallelism (research-grade; Phase C+).

## ol_aead convergent (ADR-0012)

Identical performance to standard AES-256-GCM path (4-5 GiB/s/core on AES-NI hardware) — the only added cost is the `BLAKE3.derive_key(plaintext)` call to compute the convergent key, which is dominated by the BLAKE3 throughput (~3 GiB/s/core for the plaintext-length hash). For typical 64 KiB chunks: ~20µs overhead per chunk (one-time per chunk).

## ol_aead parallel multi-chunk (Phase B-2)

Multi-chunk encrypt/decrypt parallelized across cores via rayon. Each chunk's AEAD is independent (different chunk_id → different nonce + AAD), so the work shards cleanly.

| Bench (64 KiB chunks) | Sequential | Parallel | Speedup |
|---|---|---|---|
| 32 chunks | 943 µs (2.07 GiB/s) | **469 µs (4.17 GiB/s)** | **2.0×** |
| 128 chunks | 3.84 ms (2.03 GiB/s) | **1.10 ms (7.13 GiB/s)** | **3.5×** |

Speedup scales with batch size (rayon dispatch cost amortizes over more chunks). For typical ingest workloads (≥ 100 chunks per file), `encrypt_chunks_par` is the right path.

## ol_transfer (ADR-0013)

End-to-end fetch latency on loopback QUIC with identity-bound TLS (measured via `cargo bench -p ol_transfer --bench transfer_bench`):

| Operation | Loopback latency | Note |
|---|---|---|
| `fetch_chunk_local` | **1.27 µs** | Already in store; Bloom + memtable + read |
| `fetch_chunk_warm_1KiB` | 599 µs | Single fetch (one fsync). Wire round-trip + append + fsync |
| `fetch_many_batched_x32` (NEW) | **2.94 ms / 32 chunks = 92 µs/chunk** | **Group commit: 1 fsync for the whole batch** |
| `sequential_fetch_chunk_x32` | 21.55 ms / 32 chunks = 673 µs/chunk | 32 separate fsyncs (control) |
| `bloom_handshake_warm_1k` | 99 µs | 1000-chunk manifest scope |

**Optimizations landed in Phase B-2:**
1. `Arc<RwLock<ChunkStore>>` replacing `Arc<Mutex<...>>` so concurrent reads parallelize.
2. **Group commit**: `fetch_many` uses `write_local_no_flush` for each task + one `commit()` at the end. **7.3× speedup on multi-chunk fetch** (92 µs/chunk vs 673 µs/chunk).
3. Per-chunk `fsync` cost is now amortized across the whole batch; warm-path fetches are QUIC-RTT-bound (~100 µs) rather than disk-bound.

**New API:**
- `TransferEngine::commit()` — explicit batched-commit barrier.
- `TransferEngine::fetch_chunk_fountain(peer, chunk_id)` — ADR-0015 LT-fountain delivery; uses new `FountainRequest`/`FountainBurst`/`FountainAck` wire kinds.
- `TransferEngine::bloom_handshake_scoped(peer, already_have, want_list)` — client-supplied want_list avoids the server-side full memtable scan (ADR-0011 v2).

## Workspace Test Totals (Phase B-2)

| Layer | Tests |
|---|---|
| ol_bloom (lib + properties) | 18 + 6 = 24 |
| ol_fountain (lib + acceptance + xor) | 26 + 5 + 3 = 34 |
| ol_transfer (lib + engine_e2e: now 11 incl. fountain + scoped-bloom) | 8 + 11 = 19 |
| ol_chunk (lib + format_aware) | 31 in lib |
| ol_aead (lib + convergent + convergent_e2e + parallel_e2e) | 26 + 8 + 4 + 2 = 40 |
| ol_chunk_store / ol_quic / ol_wal | 22 + 34 + 32 |
| **Rust workspace total** | **265 tests passing** |
| Python (bloom + fountain adapters) | 22 |
| Python (existing chunk/aead/wal/store/quic) | 106 |
| **Python total** | **128 tests passing** |
| **Grand total** | **393 tests passing** |

---

## CI Gate

Per-PR gate: `cargo bench --workspace --bench bloom_bench --bench fountain_bench --bench cdc_bench` must not regress any throughput number by more than 5%.
