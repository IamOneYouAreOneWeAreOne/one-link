# ADR-0016: Reed-Solomon FEC — GF(2^8) Cauchy systematic, custom implementation

**Status:** ACCEPTED (Phase C acceptance number)
**Phase:** C (item #1: Reed-Solomon FEC over chunk stream; item #2: erasure-coded durability)
**Depends on:** ADR-0003 (chunk_log + stripe descriptor reserved bytes), ADR-0004 (stripe layout)

---

## Context

Phase A1 reserved 24-byte stripe descriptors in every `ChunkRecord` for future Reed-Solomon use, and the engine's "files survive disk loss + peer loss" promise (per `FILE_ENGINE_V2_PLAN.md`) needs erasure-coded redundancy across user devices + trusted peers.

The Phase C acceptance gate (line 287 of the plan):

> Reed-Solomon (10,4) survives any 4-shard erasure with 100% recovery across ≥10,000 seeds.

This requires a production Reed-Solomon implementation that:

1. Is **deterministic across platforms** (engine is content-addressed; a chunk's parity bytes are part of its identity).
2. Has **no external runtime dependency** (sovereignty: every layer either has FOSS implementations or degrades; per the plan's "Defang Concerns" table, RS isn't listed as needing an external dep).
3. **Handles arbitrary `(k, m)` configurations** so the engine can pick the right ratio per workload (1.4× for typical durability; 2.0× for archival; 1.1× for ephemeral).
4. Is **fast enough** to not bottleneck encode of a daemon's chunk-write pipeline. At 64 KiB chunks and ~1000 chunks/sec ingest, RS encode budget is ~64 MiB/s. Anything ≥ that is fine; we target ≥500 MiB/s scalar so we have headroom.
5. Survives **structured fuzzing** without panic across random `(k, m, shard subset)` triples.

## Decision

**Ship `ol_fec`: a custom GF(2^8) Reed-Solomon implementation using Cauchy matrices in systematic form. No external RS crate dependency.**

### Why custom (and why GF(2^8) + Cauchy)?

| Approach | Pros | Cons | Decision |
|---|---|---|---|
| `reed-solomon-erasure` crate (Klauspost-style Vandermonde) | Mature, MIT licensed, ~6 GiB/s with AVX2 | External dep; Vandermonde matrices are not always invertible for arbitrary erasure patterns | **Reject** — sovereignty + invertibility concerns |
| `reed-solomon-simd` crate (AVX2/AVX-512 native) | Very fast | External dep; bleeding-edge | **Reject** — sovereignty |
| Custom GF(2^8) Vandermonde | Simple | Same invertibility issue as above | **Reject** |
| **Custom GF(2^8) Cauchy systematic** | Always-invertible submatrices; clean recovery for ANY erasure pattern; no deps | Initial implementation work; lookup-table scalar speed | **Accept** |
| Custom GF(2^16) Cauchy | Wider field; allows larger k | More memory, slower scalar | **Defer** to Phase D if Phase C scale demands it |

**The Cauchy matrix property** is the decisive feature: any submatrix of a Cauchy matrix over GF(2^8) is invertible, so we can always recover from any `k` of `k+m` shards without retries or fallback. Vandermonde matrices have submatrices that fail to invert for certain erasure patterns; we'd have to handle that path. Cauchy is uniformly correct.

### Math

Source data is split into `k` equal-sized **data shards** of length `shard_len` bytes. The encoder produces `m` **parity shards** of the same length. Together: `k + m` shards. The receiver may lose any `m` of them and still recover.

GF(2^8) is the Rijndael field — same as AES. Polynomials are bytes; multiplication uses the irreducible polynomial `x^8 + x^4 + x^3 + x + 1` (0x11B). We precompute:

- `LOG[256]` — discrete log base `g = 0x03` (primitive root of GF(2^8))
- `EXP[510]` — exponentiation table (double-sized to avoid mod after wrap)

Multiplication `a * b` is `EXP[LOG[a] + LOG[b]]` for non-zero `a, b`; 0 otherwise. ~3 cycles scalar.

**Cauchy matrix construction**: pick `k + m` distinct elements `x_0..x_{k+m-1}` from GF(2^8) (we use `0..k+m`). The encoder matrix is the **systematic-form Cauchy matrix**:

```text
G = [ I_k    ]
    [ C_(m,k)]
```

where `C[i][j] = 1 / (x_{k+i} - y_j)` for chosen distinct sets `{y_j}` and `{x_{k+i}}`. The top `k` rows are the identity (so the first `k` output shards are the data unchanged — *systematic* encoding). The bottom `m` rows produce the parity shards.

**Encoding**: for each parity row `i in 0..m`, compute `parity[i] = sum_{j=0..k} C[i][j] * data[j]` where `*` and `+` are GF(2^8) ops.

**Decoding from any `k` shards**: take the rows of `G` corresponding to the received shard indices, form a `k × k` submatrix `G_recv`, invert it (always possible — Cauchy), multiply `G_recv^{-1} * recv_data` to get the original data.

### `ol_fec` API surface

```rust
pub struct Codec {
    k: usize,
    m: usize,
    cauchy_parity_rows: Vec<Vec<u8>>, // m × k matrix of GF(2^8) coefficients
}

impl Codec {
    pub fn new(k: usize, m: usize) -> Result<Self, FecError>;
    pub fn k(&self) -> usize;
    pub fn m(&self) -> usize;
    pub fn total_shards(&self) -> usize; // k + m

    /// Encode k data shards (each of `shard_len` bytes) into m parity shards.
    /// All shards must be equal length.
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, FecError>;

    /// Decode: given received shards (by index 0..k+m) recover the original
    /// k data shards. `present[i]` is `Some(&[u8])` if shard i was received,
    /// `None` otherwise. Must have at least k Some entries.
    pub fn decode(&self, present: &[Option<&[u8]>]) -> Result<Vec<Vec<u8>>, FecError>;
}
```

### Falsifiable acceptance number

Per the Phase C gate:

> **RS(10,4) survives any 4-shard erasure with 100% recovery across ≥10,000 seeds.**

Test: for each of 10,000 random seeds, generate 10 random data shards of 1 KiB each, encode to 14 shards, drop 4 random shards (the most adversarial case = exactly m losses), decode the remaining 10, verify byte-equivalence to the original.

Implementation in `tests/acceptance.rs`. **CI must run this test in release mode and pass 100%.**

## Consequences

**Positive:**
- Cross-platform determinism: GF(2^8) is integer arithmetic; same bytes everywhere.
- Sovereignty: zero new runtime deps for the FEC layer.
- Always-invertible recovery: no edge cases where (k, erasure-pattern) fails.
- Stripe descriptor field in `ChunkRecord` (Phase A1) plugs in directly — `stripe_role = Data | Parity`, `stripe_index in 0..k+m`, `stripe_k`, `stripe_m`.
- Path for Phase D extensions: GF(2^16) and SIMD acceleration are pure-Rust upgrades that don't change the wire format.

**Negative:**
- Scalar lookup-table speed is ~500 MiB/s/core, not the 5+ GiB/s of SIMD-accelerated implementations. Acceptable for Phase C (durability is background work, not line-rate ingest); SIMD is a Phase D upgrade.
- Cauchy matrix construction is O(k * m) at startup; cached in the `Codec` struct, so per-encode cost is just the matrix-vector multiply.

## Verification

1. **Acceptance gate**: RS(10,4) × 10,000 random seeds × 4 random erasures = 100% recovery. Falsifiable; CI gate.
2. **Round-trip property test**: any `(k, m)` with `1 ≤ k ≤ 32`, `1 ≤ m ≤ 16` survives any subset of `k+m` shards where at most `m` are missing.
3. **Determinism**: byte-equivalent parity output on Windows x86_64 + Linux aarch64 (pinned test vector).
4. **Throughput baseline**: encode 1 GiB at RS(10,4) in release mode — measure and pin.
5. **Fuzz**: proptest harness on the GF(2^8) primitives + matrix invert.

## References

- ADR-0003 (chunk_log on-disk format) — defines the stripe descriptor field that this ADR's encoder populates.
- ADR-0004 (stripe layout) — the on-disk shape that maps `ChunkRecord` to stripe slots.
- Cauchy Reed-Solomon: Plank & Xu, "Optimizing Cauchy Reed-Solomon Codes for Fault-Tolerant Network Storage Applications" (NCA 2006).
- GF(2^8) tables: Rijndael / AES specification (FIPS 197).
- `FILE_ENGINE_V2_PLAN.md` line 133-134 (Phase C items 1 + 2).
