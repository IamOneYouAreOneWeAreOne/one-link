# ADR-0001: Content-Defined Chunking Kernel — FastCDC with Gear Hash + AVX-512 SIMD

**Status:** ACCEPTED (Phase A1 acceptance number — do not revisit without ADR amendment)
**Phase:** A1 (item #2: native CDC kernel choice)
**Supersedes:** existing `src/one_link/cdc.py` (Python rolling-hash CDC at ~8 MiB/s)

---

## Context

CDC is on the per-byte hot path. Every byte ingested by One Link gets fed through the rolling hash; chunk boundaries determined by the kernel control dedup quality, transfer initiation cost (Bloom filter sizing), and storage amplification. The kernel choice locks in:

1. **Throughput floor.** A 1 GiB/s ingest gate (Phase A1 acceptance) requires the rolling hash to run faster than the rest of the pipeline. FastCDC reference C runs ~1.5 GiB/s/core; SIMD-accelerated FastCDC (AVX-512) runs 5+ GiB/s/core; Gear-only (no boundary normalization) goes higher. Anything slower than 1.5 GiB/s/core ends up the bottleneck once AEAD (~5 GiB/s/core via AES-NI) and BLAKE3 (~3 GiB/s/core) are running.

2. **Chunk size distribution.** Determines bloom filter sizing for transfer initiation (ADR-0008), erasure-stripe sizing (ADR-0004), AEAD frame size (ADR-0002). All three depend on the chunk size statistics the kernel produces. Picking a kernel without committing to a distribution = downstream blast radius.

3. **Cross-platform determinism.** Same input must produce same chunk boundaries on x86-64, ARM64 (Apple Silicon), and (eventually) RISC-V. SIMD acceleration must not produce different boundaries than the reference.

## Decision

**Use FastCDC with Gear hash + AVX-512 / NEON SIMD acceleration. Reference scalar implementation as fallback for non-SIMD platforms.**

Parameters:

| Parameter | Value | Rationale |
|---|---|---|
| Min chunk size | **8 KiB** | Below this, dedup metadata overhead (32-byte BLAKE3 hash + 16-byte ratchet-key-id + bloom-filter slot) dominates. |
| Average chunk size | **64 KiB** | Standard FastCDC parameter; matches Tarsnap, Restic, Borg, OneField production. Hits Bloom-filter sweet spot at ~8 bits/chunk for receivers with ~1 GiB corpus. |
| Max chunk size | **256 KiB** | Above this, FUSE read amplification gets bad (a 64 KiB userspace read decrypts a full chunk). Joint with AEAD frame size (ADR-0002). |
| Boundary mask | **0x0000_0070_0703_0190** (FastCDC small-mask), **0x0000_0058_0303_0590** (FastCDC large-mask) | Standard FastCDC published parameters; produces the documented chunk size distribution centered on 64 KiB. |
| Hash kernel | **Gear-256** (256-entry random table, 64-bit rolling state) | Bytes per cycle ~1.5 scalar; ~4-6 with AVX-512 VPMULLQ + VPSLLQ. NEON: ~3-4. |

**Rejected alternatives:**

- **Rabin fingerprinting** (Borg, original LBFS): 0.5-1 GiB/s/core scalar, hard to SIMD because of polynomial-arithmetic dependencies. Too slow for the engine budget.
- **Buzhash** (rsync, BorgBackup older): similar perf to Rabin, same SIMD problem.
- **AE (asymmetric extremum)**: better dedup ratio than Gear in some workloads but ~30% slower; not enough to justify against Gear+SIMD.
- **CDC-Less / fixed-size chunking**: kills dedup on insertions; only useful for already-aligned content (database pages). Reject as a primary kernel; expose as an optional manifest-format mode for use cases where alignment is guaranteed.

## Consequences

**Positive:**
- Throughput floor of 5+ GiB/s/core on AVX-512 hardware ≈ 8x the engine's 1 GiB/s gate. Plenty of headroom for the rest of the pipeline.
- Cross-platform determinism via same Gear-256 table on every arch. SIMD changes microarchitecture, not the byte-output.
- Chunk size distribution well-characterized; downstream sizing decisions (Bloom filter, AEAD frame, stripe) can be set with confidence.
- OneField Mesh `transport/cdc_dedup.cl` already uses this family (FNV-1a-based, similar shape). Algorithmic understanding shared across projects.

**Negative:**
- AVX-512 isn't universal. Pre-Zen-4 AMD lacks it; Intel post-2018 has it on most server SKUs but Alder Lake P-cores have it disabled in BIOS by default. NEON is universal on ARM64. Mitigation: scalar reference path is never slower than 1.2 GiB/s/core (FastCDC paper benchmark), still meets engine budget on a single core for orchestration, and SIMD is a dispatched runtime selection, not a hard requirement.
- 256-byte hash table consumes 2 KiB of cache per-thread. Acceptable; L1 is 32-48 KiB.

## Verification

Acceptance criteria for the CDC implementation:

1. **Throughput gate**: 1 GiB unique-data ingest in <500ms on a single core (≥2 GiB/s/core measured). Stretch: ≥5 GiB/s/core with AVX-512.
2. **Determinism gate**: byte-for-byte identical chunk boundaries on x86-64, ARM64 (Apple Silicon), and Windows (MSVC + GCC + Clang builds). Test corpus = 100 MiB random-bytes pinned by SEED=42 + 100 MiB real-world file mix.
3. **Distribution gate**: on a 1 GiB Linux kernel source tree, chunk size mean ∈ [60 KiB, 68 KiB], P5 ≥ 12 KiB, P95 ≤ 192 KiB.
4. **Algebraic correctness gate**: scanned boundaries tile the input exactly (no gaps, no overlap, first.start = 0, last.end = buf.len). Each boundary's raw_address equals BLAKE3-256 of `buf[start..end]`. Verified by property tests.
5. **Reference-fixture pin**: a fixed pseudo-random 1 MiB input produces a pinned set of boundary offsets. Any change to that pinned set is a wire-format break and requires an ADR amendment plus a migration plan.

## Wire-compat note (vs existing Python `src/one_link/cdc.py`)

The existing v0.20.x Python kernel is a custom Gear-CDC variant (16 KiB min, 64 KiB avg, 256 KiB max, single boundary mask). FastCDC v2020 is a different algorithm (8 KiB min per this ADR, two-mask normalized chunking) and produces different boundaries on the same input. **This is a deliberate kernel upgrade.**

Migration path:

- Phase A1 ships FastCDC v2020 as the *new* kernel. Chunks ingested under A1 onwards use it.
- Existing chunks from v0.20.x stay readable — they were stored under the old kernel but are content-addressed by their BLAKE3 hashes; the chunk store doesn't care which kernel produced the boundaries.
- Folder sync between a v0.21.0+ peer and a v0.20.x peer for *new* content gets a graceful protocol downgrade if both peers haven't upgraded; engineering: foldersync.py negotiates kernel version during pairing, falls back to legacy Gear-CDC when talking to v0.20.x. Wire-compat preserved across the transition.
- Internal storage: the chunk_log records (per ADR-0003) carry no kernel-identifier flag because chunks are content-addressed; the kernel that produced a chunk is irrelevant once the chunk exists.

## References

- FastCDC paper: Xia et al., USENIX ATC 2016.
- FastCDC C reference: https://github.com/nlfiedler/fastcdc-rs (port basis)
- Gear hash: Xia et al., ATC 2014.
- OneField Mesh design: `OneField Mesh/onefield/transport/cdc_dedup.cl` (~195 lines, 13 tests).
- Existing One Link Python impl: `src/one_link/cdc.py` (regression baseline).
