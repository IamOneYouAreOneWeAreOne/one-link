# ADR-0006: BLAKE3 Domain-Separated Derivation Scheme

**Status:** ACCEPTED (Phase A1 acceptance number)
**Phase:** A1 (used by ADR-0001, 0002, 0003, 0004; touches every cryptographic layer)
**Depends on:** nothing (this is a foundational ADR)

---

## Context

BLAKE3 underpins the engine: chunk addresses (raw + convergent), AEAD per-chunk key derivation, stripe seed assignment, capability hash, manifest content-addressing, ratchet key derivation. Every use of BLAKE3 in the engine MUST be domain-separated: a hash output from one purpose must NOT collide with or be predictable from a hash output for another purpose, even with the same input.

Without domain separation:
- An attacker who learns one chunk's address can predict the convergent address of the same content (acceptable; addresses are not secrets) BUT could also predict the stripe_seed and the chunk's AEAD-key derivation seed if they share a derivation path. That's a problem.
- An adversary who can choose plaintext and observe its chunk address could potentially derive the AEAD-key for that chunk.

This ADR specifies the **single canonical scheme** for every BLAKE3 use in the engine.

## Decision

**Use BLAKE3's keyed-hash and derive_key modes with explicit, versioned domain separators. Every domain has a unique purpose-string, version-pinned, registered in this ADR.**

### Three BLAKE3 modes used:

1. **`hash(input)`** — unkeyed plain hash. Used ONLY for content-addressing (raw chunk addresses, manifest content-hashes) where output is publicly derivable from input.
2. **`keyed_hash(key, input)`** — keyed MAC mode. Used for derivations where the key is a secret (ratchet chain key, session key).
3. **`derive_key(context, key_material)`** — context-string-bound key derivation. Used for purpose-domain-separated subkeys from a master input.

### Registered domain contexts (all start with `ol-` prefix and a version):

```
"ol-chunk-addr-raw-v1"            -> raw-BLAKE3 chunk address (BLAKE3 hash, NOT derive_key)
"ol-chunk-addr-convergent-v1"     -> convergent-encryption chunk address (used as KEY input to AEAD)
"ol-chunk-aead-key-v1"            -> AEAD key per chunk (derive_key context)
"ol-chunk-frame-nonce-v1"         -> per-frame nonce derivation within a chunk (NOT actually used in production: nonce is constructed from chunk_id_lo64 || frame_index per ADR-0002; this context exists as a sanity check that nobody confuses derived-key with constructed-nonce)
"ol-chunk-ratchet-id-v1"          -> 16-byte ratchet_key_id stored in chunk_log header
"ol-stripe-seed-v1"               -> stripe assignment seed (ADR-0004)
"ol-stripe-cohort-mix-v1"         -> cohort_id mixing for parity derivation
"ol-manifest-id-v1"               -> manifest content-address (canonical-encoded manifest body)
"ol-capability-id-v1"             -> capability fingerprint (canonical-encoded cap body)
"ol-revocation-leaf-v1"           -> Merkle revocation log leaf hash
"ol-revocation-internal-v1"       -> Merkle revocation log internal-node hash
"ol-folder-crdt-actor-v1"         -> CRDT actor_id derivation (peer fingerprint -> actor_id)
"ol-share-link-id-v1"             -> share-link fingerprint (canonical-encoded share body)
"ol-bloom-init-key-v1"            -> Bloom filter hash-function seed (Phase B; reserved here)
"ol-fountain-symbol-id-v1"        -> RaptorQ encoded-symbol identifier (Phase B; reserved)
"ol-network-coding-id-v1"         -> XOR network-coding combined-symbol identifier (Phase B; reserved)
"ol-pq-hybrid-derive-v1"          -> ML-KEM + X25519 hybrid combiner KDF (Phase C; reserved)
```

Reserved contexts for future phases are listed here so phases B/C/D do not accidentally collide with each other; ADR amendment required to add new contexts.

### Use-site rules:

**Rule 1: Raw chunk address (ADR-0003 chunk_id_full when flags.address_kind = raw):**
```
chunk_id_full = BLAKE3.hash(plaintext_chunk_bytes)
```
No domain separator; this is the canonical content-address. Compatibility with external content-addressed-storage tooling depends on plain BLAKE3.

**Rule 2: Convergent chunk address (chunk_id_full when flags.address_kind = convergent):**
```
chunk_id_full = BLAKE3.derive_key(
    context = "ol-chunk-addr-convergent-v1",
    key_material = plaintext_chunk_bytes,
    output_length = 32,
)
```
Domain-separated from raw address so a single chunk has different addresses under each scheme; engine never confuses them.

**Rule 3: AEAD per-chunk key:**
```
aead_key = BLAKE3.derive_key(
    context = "ol-chunk-aead-key-v1",
    key_material = ratchet_chain_key || chunk_id_full,
    output_length = 32,  // AES-256
)
```
For convergent encryption, `ratchet_chain_key` is replaced by the chunk's content (derived deterministically) — guaranteeing identical plaintext → identical AEAD key → identical ciphertext from any sender.

**Rule 4: Ratchet key id (16 bytes stored in chunk_log header):**
```
ratchet_key_id = BLAKE3.derive_key(
    context = "ol-chunk-ratchet-id-v1",
    key_material = ratchet_chain_key || chunk_id_full,
    output_length = 16,
)
```
Used at recovery to look up which ratchet generation a chunk's AEAD key came from.

**Rule 5: Stripe seed (ADR-0004):**
```
let h = BLAKE3.derive_key(
    context = "ol-stripe-seed-v1",
    key_material = chunk_id_full || stripe_k.to_le_bytes(),
    output_length = 8,
);
let stripe_seed = u64::from_le_bytes(h) & !((1 << 6) - 1);  // Reserve low 6 bits for position
let position = (u64::from_le_bytes(h) & 0x3F) % stripe_k;
```

**Rule 6: Cohort-mixed parity derivation:**
Reed-Solomon parity computation incorporates `cohort_id` such that:
```
parity_seed = BLAKE3.derive_key(
    context = "ol-stripe-cohort-mix-v1",
    key_material = stripe_id || cohort_id,
    output_length = 32,
)
// parity_seed XOR-mixed into RS encode coefficients
```
Result: two cohorts holding the same stripe data compute different parity. (Implementation detail in C-phase RS encoder; spec'd here.)

**Rule 7: Capability fingerprint:**
```
cap_id = BLAKE3.derive_key(
    context = "ol-capability-id-v1",
    key_material = canonical_encode(cap_body),
    output_length = 32,
)
```
Domain separates from manifest IDs; engine never confuses the two.

**Rule 8: Manifest content-address:**
```
manifest_id = BLAKE3.derive_key(
    context = "ol-manifest-id-v1",
    key_material = canonical_encode(manifest_body),
    output_length = 32,
)
```

**Rule 9: Merkle revocation log:**
```
leaf_hash = BLAKE3.derive_key(
    context = "ol-revocation-leaf-v1",
    key_material = canonical_encode(revocation_event),
    output_length = 32,
)
internal_hash = BLAKE3.derive_key(
    context = "ol-revocation-internal-v1",
    key_material = left_child_hash || right_child_hash,
    output_length = 32,
)
```
Domain-separated leaf vs internal so an attacker cannot present an internal-node hash as a leaf or vice versa (the second-preimage attack on naive Merkle trees).

### Forbidden uses:

- **No string-concatenation pseudo-domain-separators.** `BLAKE3.hash("aead-key-" || chunk_id)` is forbidden. Use `derive_key`.
- **No reuse of derived keys across purposes.** A key derived with `"ol-chunk-aead-key-v1"` MUST NOT be used as a ratchet input. Each derived key has exactly one purpose.
- **No domain-separator-version reuse.** When the protocol semantics of a domain change, the version increments (`v1` → `v2`). Both versions remain valid (engine handles legacy chunks); an ADR amendment registers the new context.

### Property tests:

- For every two distinct contexts c1 != c2 and every input x, `derive_key(c1, x) != derive_key(c2, x)` (probabilistically; collision is ~2^-256).
- For every context c and inputs x1 != x2, `derive_key(c, x1) != derive_key(c, x2)`.
- For raw vs convergent addressing: same plaintext produces different chunk_ids under the two modes.

## Consequences

**Positive:**
- All cryptographic boundaries domain-separated. An adversary who learns one derived key learns nothing about other derived keys, even with the same input.
- Single canonical registry of contexts in this ADR; no ambiguity about what a given hash output means.
- Versioned: protocol evolution doesn't break old chunks (engine recognizes both versions; can migrate gradually).
- Aligns with NIST SP 800-185 KMAC pattern and BLAKE3 spec recommendations for derive_key.

**Negative:**
- 16-byte context strings cost memory + a small fixed CPU overhead per BLAKE3 call. Negligible.
- Adding a new domain requires ADR amendment, not just a code change. This is a feature: prevents accidental domain duplication across phases.

## Verification

1. **Domain-separation property test**: for each pair (c1, c2) in the registered context list, and 1M random inputs, verify `derive_key(c1, x) != derive_key(c2, x)`.
2. **Cross-version isolation**: when v2 of any domain ships, engine handles v1-vintage chunks via fallback path; v1 and v2 hashes never collide.
3. **No raw-keyed-hash ambiguity test**: assert that nothing in the codebase calls `BLAKE3.hash` with a runtime-string concatenation as input. Static lint check: any BLAKE3 use must be either (a) plain hash with literal input, (b) keyed_hash with explicit key parameter, (c) derive_key with one of the registered contexts.

## References

- BLAKE3 spec: https://github.com/BLAKE3-team/BLAKE3-specs
- BLAKE3 derive_key: spec §6.4
- NIST SP 800-185 KMAC: parallel domain separation pattern
- "Cryptographic Right Answers" Aumasson et al.: domain separation discussion
- HKDF (RFC 5869): historical analog; we use BLAKE3.derive_key for stronger composability
