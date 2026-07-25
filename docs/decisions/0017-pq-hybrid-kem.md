# ADR-0017: PQ-hybrid KEM — ML-KEM-768 + X25519 with BLAKE3 combiner

**Status:** ACCEPTED; live daemon-channel activation added 2026-07-23
**Phase:** C (item #7: PQ-hybrid by default)
**Depends on:** ADR-0006 (BLAKE3 derive scheme), ADR-0010 (identity-bound TLS)

---

## Context

The Phase C gate (line 290 of `FILE_ENGINE_V2_PLAN.md`):

> ML-KEM-768 + X25519 hybrid completes handshake at PQ-conservative parameters.

Historical context: the original daemon exposed `pq_hybrid.NullKEM`, which
performs no PQ operation. The native ML-KEM-768 implementation replaced that
placeholder for production selection, and the live v3 channel handshake now
uses the native ABI directly. `NullKEM` remains only for explicitly authorized
legacy/test construction and is never advertised as post-quantum.

Hybrid KEMs are the conservative path: combine a classical KEM (X25519) with a post-quantum KEM (ML-KEM-768) such that an adversary needs to break **both** to recover the shared secret. If ML-KEM is broken (cryptanalysis advances), X25519 still protects. If X25519 is broken (large-scale quantum), ML-KEM still protects.

## Decision

**Ship `ol_pqkem`: a hybrid KEM crate combining ML-KEM-768 + X25519 via a BLAKE3-derived combiner.**

The live channel composes this KEM with a separate ephemeral X25519 exchange,
an Ed25519-authenticated complete version/suite/key transcript, HKDF-SHA256
extraction, and bidirectional key confirmation. It never silently retries a
failed v3 handshake as classical. This activation protects daemon session-key
establishment against harvest-now-decrypt-later; it does not by itself make the
Ed25519 identity signature post-quantum.

### Algorithm choices

| Component | Choice | Rationale |
|---|---|---|
| Classical KEM | **X25519** (RFC 7748) | Industry standard, hardware accelerated on ARM via PMULL+EOR3, ~10K ops/sec/core in software |
| Post-quantum KEM | **ML-KEM-768** (FIPS 203) | NIST-standardized in 2024; "768" is the recommended PQ-conservative parameter set (Category 3 security; ~192-bit equivalent) |
| Hash combiner | **BLAKE3.derive_key** | Already in our toolbox (ADR-0006); fast; XOF for arbitrary output lengths |
| Shared-secret length | **32 bytes** | Matches AEAD key length (ADR-0002); single output usable directly |

**Rejected alternatives:**

- **Kyber-768 (pre-NIST-final naming)** — Same algorithm as ML-KEM-768 but pre-standard naming; we use the FIPS 203 name.
- **ML-KEM-512** (PQ-cautious Category 1) — Weaker; only ~128-bit equivalent; saves bandwidth but our handshake budget tolerates ML-KEM-768's 1184-byte public keys.
- **ML-KEM-1024** (Category 5) — Excessive (256-bit equivalent); our threat model doesn't need it.
- **HQC**, **Classic McEliece** — Other PQ KEMs; not selected for hybrid mode in TLS / industry consensus.
- **No combiner**, just concat the secrets — Misses the "indifferentiability from random oracle" property; a malformed PQ output could leak bits of the classical secret via implementation bugs in the AEAD using the concatenation directly.

### KEM combiner — domain-separated BLAKE3 KDF

```text
ss_hybrid = BLAKE3.derive_key(
    context = "ol-pqkem-hybrid-v1",
    key_material =
        ml_kem_ciphertext  ||
        ml_kem_shared_secret ||
        x25519_public_key  ||
        x25519_shared_secret,
    output_length = 32,
)
```

**Why include the ciphertexts/pubkeys in the KDF input**:

The "X-Wing" hybrid KEM construction (Bernstein et al., 2024) proves IND-CCA security of the hybrid if and only if the KDF binds **both KEMs' public outputs** alongside their shared secrets. Without it, an adversary who controls one KEM's ciphertext can mauleate the hybrid secret. With it, both KEMs' public state is committed in the hash.

Our specific construction:
- `ml_kem_ciphertext` (1088 bytes for ML-KEM-768) — the encapsulation output
- `ml_kem_shared_secret` (32 bytes) — derived inside the ML-KEM
- `x25519_public_key` (32 bytes) — the responder's ephemeral pubkey
- `x25519_shared_secret` (32 bytes) — derived via X25519 DH

The BLAKE3 derive_key context `"ol-pqkem-hybrid-v1"` is registered in ADR-0006 (we'll add it to the registry table when this ADR is implemented).

### `ol_pqkem` API surface

```rust
/// Hybrid public key: ML-KEM-768 EK + X25519 pubkey.
pub struct HybridPublicKey {
    ml_kem_ek: [u8; 1184],
    x25519_pk: [u8; 32],
}

/// Hybrid secret key: ML-KEM-768 DK + X25519 sk.
pub struct HybridSecretKey {
    ml_kem_dk: [u8; 2400],
    x25519_sk: [u8; 32],
}

/// Hybrid ciphertext: ML-KEM-768 CT + X25519 ephemeral pubkey.
pub struct HybridCiphertext {
    ml_kem_ct: [u8; 1088],
    x25519_eph_pk: [u8; 32],
}

/// Generate a fresh keypair (responder side).
pub fn keypair(rng: &mut impl rand_core::CryptoRng) -> (HybridPublicKey, HybridSecretKey);

/// Encapsulate to `pk`; returns the ciphertext + 32-byte shared secret
/// (initiator side).
pub fn encapsulate(
    pk: &HybridPublicKey,
    rng: &mut impl rand_core::CryptoRng,
) -> (HybridCiphertext, [u8; 32]);

/// Decapsulate `ct` with `sk`; returns the 32-byte shared secret
/// (responder side).
pub fn decapsulate(sk: &HybridSecretKey, ct: &HybridCiphertext) -> [u8; 32];
```

### Dependencies (production-grade, well-audited)

- `ml-kem` (RustCrypto) — pure-Rust ML-KEM-768 implementation, NIST FIPS 203 compliant.
- `x25519-dalek` — pure-Rust X25519, already used elsewhere in the engine.
- `blake3` — already a workspace dep.

All three are FOSS, audited, and align with the plan's sovereignty constraints.

### Migration from `pq_hybrid.NullKEM`

The shipping daemon's `One_link/src/one_link/pq_hybrid.py` has a `NullKEM` placeholder. Phase C:

1. Add Python adapter `one_link.pqkem_native` wrapping the new `ol_pqkem` crate (similar pattern to `bloom_native.py` / `fountain_native.py`).
2. Replace `NullKEM.encapsulate/.decapsulate` call sites with the native adapter.
3. Mark `NullKEM` deprecated; keep the import path for one release cycle.
4. Ratchet upgrade path (Phase C item #6 per-chunk ratchet) consumes the hybrid output as its chain-key seed.

### Falsifiable acceptance number

Per the plan:

> **ML-KEM-768 + X25519 hybrid completes handshake at PQ-conservative parameters.**

Test: `encapsulate(pk)` and `decapsulate(sk, ct)` produce identical 32-byte shared secrets across ≥10,000 random `(pk, sk)` pairs. Additionally:

- **Cross-determinism**: a fixed `(pk, ciphertext)` decapsulates to the same secret on x86_64 + arm64.
- **NIST test vector**: at least one known-answer-test vector for ML-KEM-768 (from the NIST KAT files) passes.

## Consequences

**Positive:**
- Eliminates the `NullKEM` placeholder; ships real PQ-conservative security by default.
- Works alongside existing X25519 / Ed25519 infrastructure; no breaking changes elsewhere.
- BLAKE3 combiner reuses the engine's existing hash primitive; one less moving part.
- Crate is small (<200 LoC of glue around `ml-kem` and `x25519-dalek`).

**Negative:**
- Adds `ml-kem` to the workspace dep list. It's RustCrypto, well-maintained, but still new code in the supply chain. We pin a version and mirror it through `Cargo.lock`.
- Handshake bandwidth increases: ML-KEM-768 public key is 1184 bytes vs X25519's 32 bytes. Acceptable: handshakes are once per session, not per chunk.
- ML-KEM-768 keygen is slower than X25519 (~50 µs vs ~5 µs). Still negligible compared to QUIC handshake RTT.

## Verification

1. **Acceptance gate**: 10K random keypair × encap/decap round trips, byte-equivalent shared secret.
2. **Cross-platform determinism**: pinned test vector for fixed `(seed, pk, sk, ct, ss)`.
3. **NIST KAT**: at least one ML-KEM-768 KAT passes.
4. **Property test**: any keypair survives encap/decap. Any malformed ciphertext fails to decap (the IND-CCA property — ML-KEM has implicit rejection; our hybrid must too).
5. **Constant-time check** (links to ADR Phase C item #9): timing variance of decapsulate across valid vs malformed inputs < 1% of mean.

## References

- FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (NIST, August 2024).
- Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, Schwabe et al., "X-Wing: The Hybrid KEM You've Been Looking For" (eprint 2024/039).
- ADR-0006 (BLAKE3 derive scheme).
- ADR-0010 (identity-bound TLS).
- `FILE_ENGINE_V2_PLAN.md` line 139 (Phase C item #7).
