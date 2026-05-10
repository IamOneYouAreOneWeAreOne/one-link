# ADR-0004: Erasure Coding Stripe Layout

**Status:** ACCEPTED (Phase A1 acceptance number — encoded in chunk_log header even before encoder ships in C)
**Phase:** A1 (item #9: stripe layout decision); used by Phase C item #2 (erasure-coded durability)
**Depends on:** ADR-0001 (chunk size), ADR-0003 (chunk_log header)

---

## Context

Per the FILE_ENGINE_V2_PLAN.md stress-test #1: erasure coding stripes need stripe metadata in the chunk-store layout. If A1 ships without stripe-descriptor support, retrofitting EC in C means a second blob namespace and dual writes — significant complexity. Decision: stripe layout is decided in A1; encoder/decoder ship in C.

Additionally, per stress-test #3: dedup is on data shards only; parity shards are per-storer (because parity over a stripe of chunks mixes ciphertexts; two peers with different stripe boundaries get different parity shards even if data shards are byte-identical).

This ADR locks in:

1. **Stripe descriptor format** in the chunk_log header (ADR-0003 reserved bytes 60-83).
2. **Reed-Solomon parameters** (k data, m parity).
3. **Stripe boundary policy** (how chunks are grouped into stripes).
4. **Parity ownership rules** (who computes, who stores, who reads).

## Decision

**Reed-Solomon (10, 4) over GF(2^8). Stripe boundaries follow CDC chunk boundaries deterministically. Data shards dedup; parity shards are per-storer-cohort.**

### Stripe descriptor (24 bytes in chunk_log header):

```
struct StripeDescriptor {
    stripe_id_lo64:        u64,    // BLAKE3-prefix(64) of canonical-encoded stripe membership list
    stripe_role:           u8,     // 0=Data, 1=Parity, 2=NotStriped (chunk standalone)
    stripe_index:          u8,     // 0..k-1 for Data; 0..m-1 for Parity (within this stripe)
    stripe_k:              u8,     // Number of data shards (10 in initial parameter set)
    stripe_m:              u8,     // Number of parity shards (4)
    cohort_id_lo64:        u64,    // BLAKE3-prefix(64) of the storer cohort identity (for parity ownership)
    reserved:              [u8; 4],// Must be zero
}
```

Rationale per field:

- `stripe_id_lo64`: identifies which stripe this chunk belongs to. The full identity is the canonical-encoded sorted list of (stripe_k member chunk_ids); the 64-bit prefix is enough for stripe lookup with extremely low collision probability (birthday-bounded ~2^32 stripes).
- `stripe_role`: distinguishes data vs parity. NotStriped = chunk is not part of any stripe (standalone or pre-EC chunks from A1 vintage).
- `stripe_k` / `stripe_m`: encoded per-chunk so future parameter changes (e.g., RS(20, 6) for higher durability) don't break existing stripes. Engine reads the per-chunk values; doesn't assume globals.
- `cohort_id_lo64`: identifies which group of storers this parity shard belongs to. **This is the field that breaks parity dedup** intentionally — two cohorts produce different parity for the same data because their cohort_id mixes into the parity derivation.

### Reed-Solomon parameters: RS(10, 4) over GF(2^8)

- **k = 10 data shards.** Each shard is a CDC chunk (8-256 KiB per ADR-0001). Stripe size variance: 80 KiB worst-case minimum stripe (10× 8 KiB) to 2.56 MiB worst-case maximum (10× 256 KiB).
- **m = 4 parity shards.** Survives any 4 simultaneous shard losses. Storage overhead: 40% (4 parity / 10 data). Acceptable for "lose any 2 of 5 devices" policy with ≥1.5× redundancy distributed across user's own devices + trusted peers.
- **Galois field GF(2^8).** Standard RS field; matches OneField Mesh `transport/udp_fec.cl`. SIMD-accelerated on x86 (PCLMUL) and ARM64 (PMULL). Reference throughput: ~3 GiB/s/core encode, ~2 GiB/s/core decode (Backblaze reedsolomon and Klauspost reedsolomon-go benchmarks).

### Stripe boundary policy: deterministic by content-hash

To ensure two peers who receive the same content compute the same stripe boundaries (so data shards dedup), stripe membership is determined by a deterministic content-hash function:

```
fn stripe_assignment(chunk_id: BlakeHash256, k: u8) -> (stripe_seed: u64, position: u8) {
    let h = BLAKE3(b"ol-stripe-v1" || chunk_id || k.to_le_bytes()).first_64_bits();
    let stripe_seed = h & !((1 << 6) - 1);  // Clear low 6 bits; positions occupy them
    let position = (h & 0x3F) % k;          // Position within the stripe
    (stripe_seed, position)
}
```

Two peers each receiving 1000 chunks compute the same `stripe_seed` for chunks with identical chunk_ids. Stripes form when 10 chunks happen to share a `stripe_seed`. Because stripe_seed has 58 bits of entropy (64 - 6 reserved), seed collisions form natural stripe groupings without coordination.

**Why not contiguous-content stripes?** (Stripe_n = chunks 10n..10n+9 in arrival order.) Two peers receiving the same content in different order would compute different stripes, and no data shard would dedup. Hash-based assignment is order-independent.

**Why content-hash + reserve low bits for position?** Forces 1-of-k uniform distribution within a stripe. Without reservation, a hot chunk_id might end up at position 0 in 100 different stripes, defeating the spread.

### Parity ownership rules

- Data shards live in the chunk store of every peer that has the underlying chunk content (normal dedup applies).
- Parity shards are computed and stored by **storers** in a cohort. A "cohort" is a set of peers committed to maintaining redundancy for a folder. Each cohort has a `cohort_id` (32-byte BLAKE3 of canonical-encoded cohort membership).
- A storer in cohort_id=X computes parity for stripes its cohort is responsible for; the parity shard is stored with `cohort_id_lo64 = first_64_bits(X)`. Other cohorts compute different parity (because cohort_id mixes into the parity derivation), so two cohorts holding the same 10 data shards each compute their own 4 parity shards. Parity does not dedup cross-cohort.
- Reconstruction proceeds as standard RS: any 10 of 14 shards reconstructs the data.

### Pre-Phase-C compatibility

In Phase A1, before EC encoder ships, every chunk_log record has `stripe_role = NotStriped (2)`, `stripe_id_lo64 = 0`, `cohort_id_lo64 = 0`. Phase C ships the encoder + decoder; new chunks written under EC-enabled cohorts get filled stripe descriptors. Old A1-vintage chunks remain `NotStriped` and are simply not part of any stripe (durability for them is from device-level replication, not RS).

## Consequences

**Positive:**
- Stripe descriptor reserved in A1 means C plugs in without a chunk_log format break.
- Hash-based stripe assignment means data shards dedup across peers (good for sovereignty: parity is per-cohort, but data is universally dedupable).
- RS(10, 4) at GF(2^8) is well-understood, SIMD-accelerated, and matches OneField's UDP FEC family. Cross-project consistency.
- Engineer can change parameters per-stripe (k, m encoded per-chunk) so future RS(20, 6) deployments don't break existing stripes.
- Parity ownership cleanly decouples cohorts. Two friend groups maintaining redundancy for overlapping content do not interfere.

**Negative:**
- 24 bytes of header overhead per chunk for stripe descriptor, even when not striped (NotStriped uses 0 in those bytes; not free of bytes, but free of computational cost).
- Hash-based stripe boundary means stripe membership is a function of which chunks happen to share a stripe_seed prefix. A folder might end up with most chunks in stripes spread across thousands of partial-stripe groupings. Mitigation: parity is computed only when a stripe is "full enough" (≥ k=10 members in same stripe_seed); incomplete stripes are not parity-protected, fall back to device-level replication. The engine surfaces stripe-completeness as a durability metric.
- Reed-Solomon over GF(2^8) caps stripe size at 256 shards (255 actually, for non-trivial parity). Our k=10 + m=4 is well under this. If we ever want RS(64, 32), still fits.

## Verification

1. **Determinism gate**: two independent peers, given the same set of 1000 chunk_ids, compute identical stripe_seed for every chunk.
2. **Position uniformity**: position distribution across 1M chunks is within 5% of uniform across all k positions.
3. **RS encode/decode gate (Phase C, but layout-tested in A1)**: stripe descriptor field round-trips through chunk_log write/read; pre-EC, value is always (NotStriped, 0, 0, 0, 0). Phase C populates with valid encode parameters.
4. **Cohort isolation**: two cohorts holding identical data compute different parity (cohort_id_lo64 mixes into the RS derivation; verified by property test).
5. **Pre-EC compatibility**: A1-vintage chunks (all NotStriped) read correctly after Phase C lands; C-vintage chunks coexist without index migration.

## References

- Reed-Solomon erasure coding: Plank, "Erasure Codes for Storage Applications," 2005.
- Backblaze open-source reedsolomon: Java reference impl.
- klauspost/reedsolomon: Go reference impl with SIMD.
- OneField Mesh `transport/udp_fec.cl`: K+P Reed-Solomon over GF(2) for the UDP FEC layer (~189 lines, 13 tests).
- BLAKE3 keyed-hash for stripe_seed derivation: BLAKE3 spec, "derive_key" mode.
