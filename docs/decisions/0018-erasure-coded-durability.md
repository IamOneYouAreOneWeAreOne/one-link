# ADR-0018: Erasure-Coded Durability — RS over CDC chunks with StripeDescriptor

**Status:** ACCEPTED (Phase C-2)
**Phase:** C (item #2: erasure-coded durability)
**Depends on:** ADR-0016 (Reed-Solomon FEC), ADR-0003 (chunk_log format), ADR-0004 (stripe layout)

---

## Context

ADR-0016 ships the shard-level RS codec. ADR-0018 lifts it to **whole chunks**: a CDC chunk (8-256 KiB per ADR-0001) becomes a **stripe** of `k` data shards + `m` parity shards. Any `k` of the `k + m` reconstruct the original.

Three durability profiles are pre-registered:

| Profile | k | m | Storage | Survives losing |
|---|---|---|---|---|
| `EPHEMERAL` | 9 | 1 | 1.11× | 1 device |
| `STANDARD` | 10 | 4 | 1.40× | 4 devices |
| `ARCHIVAL` | 6 | 6 | 2.00× | 6 devices |

## Decision

**Ship `ol_erasure`: stripe encode + decode on top of `ol_fec`, with deterministic `StripeId` (BLAKE3 over `(plaintext_len || k || m || plaintext)` with context `ol-erasure-stripe-id-v1`).**

### Cross-sender dedup

Two senders with the same plaintext at the same `(k, m)` produce **byte-identical shards** (both data and parity, because the Cauchy matrix is deterministic and the input is the same). Their `StripeId`s match.

This means the swarm dedups identical content across senders even after erasure coding. Per the plan's stress-test #3: dedup is on data shards; parity is per-storer in expectation, but with deterministic Cauchy matrices, identical plaintext + identical params → identical parity. (Senders can opt into per-cohort parity by mixing a `cohort_id` salt into the encode if desired; v1 doesn't do that.)

### StripeDescriptor wiring

Each shard becomes its own `ChunkRecord` with:

| ChunkRecord field | Value |
|---|---|
| `chunk_id` | `BLAKE3(shard_bytes)` (raw addressing per ADR-0006) |
| `stripe_descriptor.stripe_id_lo64` | low 64 bits of `StripeId` |
| `stripe_descriptor.stripe_role` | `Data` (positions 0..k) or `Parity` (positions 0..m) |
| `stripe_descriptor.stripe_index` | 0-based index within role |
| `stripe_descriptor.stripe_k` | `k` |
| `stripe_descriptor.stripe_m` | `m` |
| `stripe_descriptor.cohort_id_lo64` | 0 (v1; reserved for per-cohort parity in Phase D) |

The 64-bit `stripe_id_lo64` is a collision-domain compromise: full 256-bit IDs are carried on the wire (Phase C-3 will define a `StripeAttestation` frame) but the on-disk shorthand is 64 bits per chunk record header. Birthday-collision floor at 2^32 stripes, well above any plausible single-engine corpus.

## Verification

1. **Round-trip** on arbitrary plaintexts (random sizes, random seeds).
2. **Any 4-of-14 erasure recoverable** (inherited from ADR-0016 + lifted to plaintexts).
3. **Cross-sender deterministic shards** (two encoders, same plaintext + params → byte-equal shards).
4. **Descriptor sanity-check** rejects shard slot/position swaps.

`ol_erasure/src/stripe.rs::tests` exercises all four.

## Consequences

**Positive:**
- Zero new wire format: existing `ChunkRecord` + `StripeDescriptor` carry the data.
- Cross-sender dedup naturally extends to erasure-coded content.
- Storage overhead is a per-share decision; STANDARD / ARCHIVAL / EPHEMERAL profiles cover the common case.

**Negative:**
- `stripe_id_lo64` is 64 bits, not 256. Collision-domain floor ~2^32 stripes. Acceptable.
- Deterministic parity means a malicious storer that holds a parity shard can confirm a guessed plaintext (already true under convergent encryption, ADR-0012). Not a new threat.

## References

- ADR-0016 (Reed-Solomon FEC kernel).
- ADR-0003 (chunk_log format with stripe descriptor field).
- ADR-0004 (stripe layout).
- `FILE_ENGINE_V2_PLAN.md` line 134.
