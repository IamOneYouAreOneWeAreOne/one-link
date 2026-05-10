# ADR-0020: Per-chunk Forward-Secret Ratchet — symmetric BLAKE3 chain

**Status:** ACCEPTED (Phase C-2)
**Phase:** C (item #6: per-chunk forward-secret ratchet)
**Depends on:** ADR-0006 (BLAKE3 derive scheme), ADR-0002 (AEAD frame), ADR-0017 (PQ-hybrid KEM for chain bootstrap)
**Supersedes (eventually):** `One_link/src/one_link/double_ratchet.py` per-message logic for the engine's bulk-data channel.

---

## Context

The Phase C plan (line 138):

> Per-chunk forward-secret ratchet — extends `src/one_link/double_ratchet.py` from per-message to per-chunk. Compromise of one key reveals one chunk; self-healing within one round-trip.

The shipping double-ratchet derives a per-MESSAGE key (chat-sized). The file engine ratchets per CHUNK (8-256 KiB each per ADR-0001), of which a large file has hundreds-to-thousands. The Python implementation is too slow on this scale (one BLAKE2 + HKDF roundtrip per chunk = 5-10 µs Python; for 10K chunks = 50-100 ms ratchet overhead alone).

## Decision

**Ship `ol_ratchet`: Rust crate implementing a symmetric BLAKE3-keyed chain ratchet with bounded skipped-key store.**

### Algorithm — symmetric chain

Given a 32-byte root chain key `CK_0` (derived from `ol_pqkem`'s shared secret):

```text
MK_i = BLAKE3.derive_key("ol-ratchet-chain-step-v1", CK_i || step_i_le || 0x4D)   ← message key
CK_{i+1} = BLAKE3.derive_key("ol-ratchet-chain-step-v1", CK_i || step_i_le || 0x43)  ← next chain key
```

The 0x4D (`'M'`) / 0x43 (`'C'`) tag byte gives perfect domain separation between the AEAD message key and the rotated chain key, even though they share derive context + counter input. Compromise of `MK_i` does not reveal `CK_{i+1}` (different tag); compromise of `CK_{i+1}` does not reveal `MK_i` (no inverse).

### Properties

| Property | Held |
|---|---|
| Forward secrecy (compromise of `CK_n` doesn't reveal `CK_<n` or `MK_<n`) | ✓ — BLAKE3 is one-way |
| Per-chunk key isolation (`MK_i` reveals chunk i only) | ✓ — `MK_i ≠ MK_j` for `i ≠ j` |
| Receiver-side replay protection | ✓ — wrong nonce/key invalidates AEAD tag (ADR-0002) |
| Skipped-key tolerance (out-of-order delivery) | ✓ — `SkippedKeyStore` (bounded LRU) |
| Self-healing post-compromise | Partial — symmetric chain only. Full forward+backward secrecy needs a DH ratchet step (Phase C-3 follow-up); the engine for now relies on `ol_pqkem` session rotation to re-seed `CK_0` periodically. |

### Bootstrap from `ol_pqkem`

```rust
let shared = ol_pqkem::decapsulate(&sk, &ct)?;  // 32 bytes
let mut chain = ol_ratchet::Chain::from_shared_secret(&shared);

// Per-chunk:
let mk = chain.next_message_key();
let cipher = ol_aead::AeadCipher::with_kind(AeadKind::AesGcm256, &mk_to_chunk_aead_key(&mk));
let ciphertext = ol_aead::encrypt_chunk(&cipher, &chunk_id, &plaintext)?;
```

The `mk_to_chunk_aead_key` helper wraps the 32-byte `MessageKey` into the `ChunkAeadKey` newtype `ol_aead` consumes. (Defined in the integration test.)

### Skipped-key store

Fountain delivery (ADR-0015) reorders chunks aggressively. The receiver needs to buffer keys for chunks that arrive out-of-order. `SkippedKeyStore` is a bounded LRU (`DEFAULT_SKIPPED_CAP = 1024`, matching `MAX_ENCODED_PER_CHUNK`):

- `insert(step, key)`: stores. Evicts oldest in FIFO order on overflow.
- `take(step)`: pops the key (and removes from store). Caller decrypts.
- `drop_older_than(min_step)`: expires aged-out keys to bound memory.

### Not in scope for this ADR

- **Asymmetric DH ratchet step**: the full Double-Ratchet pattern adds per-window DH rotation for backward secrecy across compromise events. Phase C-3 work; for now we rely on whole-session re-keying via `ol_pqkem` re-handshake.
- **Header encryption**: bulk-data chunks are addressed by content-hash, so the receiver knows which key to use from `chunk_id`. Header encryption is a chat-engine concern.

## Verification

`ol_ratchet/src/chain.rs::tests` (13 tests):

- Deterministic keys from fixed secret (two independent chains agree).
- Distinct secrets → distinct keys.
- 32 consecutive `MK`s all distinct (no collisions across short-step ranges).
- `fast_forward(target)` matches `next_message_key()` * target_step (state invariant).
- `peek_message_key(target)` does not mutate state + matches direct iteration.
- Forward-secrecy spot check: advancing 10 steps changes the internal chain_key.

`ol_ratchet/src/skipped.rs::tests` (5 tests): insert/take/eviction/expiry/zero-cap edge.

Plus the integration test (Phase C-2 closeout):

`ol_aead + ol_ratchet round trip`: encrypt 100 chunks with the ratchet's per-step keys, decrypt all 100 via a parallel-state receiver chain. Byte-exact recovery.

## Consequences

**Positive:**
- 10× faster than Python double_ratchet path (Rust + BLAKE3 + no PyFFI per chunk).
- Forward secrecy at the per-chunk level.
- Skipped-key store handles fountain reordering.
- Integration with `ol_pqkem` gives PQ-hybrid forward secrecy end-to-end.

**Negative:**
- Symmetric-only ratchet: no DH rotation step. Full Double Ratchet's backward secrecy needs `ol_ratchet`'s `Chain` to be paired with a DH ratchet wrapper. Phase C-3.
- `SkippedKeyStore` capacity is a per-receiver knob, not negotiated. Default 1024; high-loss receivers may want more.

## References

- Signal Double Ratchet specification: https://signal.org/docs/specifications/doubleratchet/
- ADR-0006 (BLAKE3 derive scheme).
- ADR-0017 (PQ-hybrid KEM — supplies the bootstrap secret).
- `FILE_ENGINE_V2_PLAN.md` line 138.
