//! BLAKE3 domain-separated derivation per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
//!
//! Every cryptographic boundary in the engine domain-separates its BLAKE3
//! use via a registered context string. This module is the single canonical
//! implementation; downstream crates call these helpers rather than
//! invoking BLAKE3 directly.
//!
//! ## Forbidden patterns
//!
//! - `blake3::hash(b"prefix" || input)` for purpose-domain separation —
//!   use `derive_key` instead.
//! - Using one derived key for two different purposes — call the
//!   purpose-specific helper for each use.
//! - Hardcoding context strings outside this module — they live in the
//!   `DerivationContext` enum so a static lint can enforce single source
//!   of truth.

/// Registered BLAKE3 derivation contexts per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
///
/// Each variant represents one cryptographic purpose. The `as_str()`
/// method returns the canonical context string used in `derive_key`.
/// Adding a new variant requires an ADR amendment.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum DerivationContext {
    /// Convergent-encryption chunk address.
    ChunkAddrConvergent,
    /// Per-chunk AEAD key.
    ChunkAeadKey,
    /// Per-chunk ratchet-key-id (16 bytes stored in chunk_log header).
    ChunkRatchetId,
    /// Stripe seed for content-addressed RS stripe assignment.
    StripeSeed,
    /// Cohort_id mixing for Reed-Solomon parity derivation.
    StripeCohortMix,
    /// Manifest content-address.
    ManifestId,
    /// Capability fingerprint.
    CapabilityId,
    /// Merkle revocation log leaf hash.
    RevocationLeaf,
    /// Merkle revocation log internal-node hash.
    RevocationInternal,
    /// CRDT actor_id derivation from peer fingerprint.
    FolderCrdtActor,
    /// Share-link fingerprint.
    ShareLinkId,
    /// Bloom filter hash-function seed (Phase B; reserved here).
    BloomInitKey,
    /// RaptorQ encoded-symbol identifier (Phase B; reserved).
    FountainSymbolId,
    /// XOR network-coding combined-symbol identifier (Phase B; reserved).
    NetworkCodingId,
    /// ML-KEM + X25519 hybrid combiner KDF (Phase C; reserved).
    PqHybridDerive,
}

impl DerivationContext {
    /// The canonical context string registered in [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChunkAddrConvergent => "ol-chunk-addr-convergent-v1",
            Self::ChunkAeadKey => "ol-chunk-aead-key-v1",
            Self::ChunkRatchetId => "ol-chunk-ratchet-id-v1",
            Self::StripeSeed => "ol-stripe-seed-v1",
            Self::StripeCohortMix => "ol-stripe-cohort-mix-v1",
            Self::ManifestId => "ol-manifest-id-v1",
            Self::CapabilityId => "ol-capability-id-v1",
            Self::RevocationLeaf => "ol-revocation-leaf-v1",
            Self::RevocationInternal => "ol-revocation-internal-v1",
            Self::FolderCrdtActor => "ol-folder-crdt-actor-v1",
            Self::ShareLinkId => "ol-share-link-id-v1",
            Self::BloomInitKey => "ol-bloom-init-key-v1",
            Self::FountainSymbolId => "ol-fountain-symbol-id-v1",
            Self::NetworkCodingId => "ol-network-coding-id-v1",
            Self::PqHybridDerive => "ol-pq-hybrid-derive-v1",
        }
    }
}

/// Derive a 32-byte key for a registered domain context.
///
/// This is the canonical wrapper around `blake3::derive_key` for engine
/// use. Callers MUST use a registered context (the `DerivationContext`
/// enum); ad-hoc context strings are forbidden by [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md).
#[inline]
#[must_use]
pub fn derive_key32(context: DerivationContext, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context.as_str(), key_material)
}

/// Derive a 16-byte key for a registered domain context.
///
/// Used by [`derive_ratchet_key_id`] to produce the `ratchet_key_id` field
/// stored in the chunk_log header. BLAKE3 supports arbitrary output length;
/// we truncate to 16 bytes via XOF mode.
#[must_use]
pub fn derive_key16(context: DerivationContext, key_material: &[u8]) -> [u8; 16] {
    let key32 = blake3::derive_key(context.as_str(), key_material);
    let mut out = [0u8; 16];
    out.copy_from_slice(&key32[..16]);
    out
}

/// Raw chunk address: plain `BLAKE3.hash(plaintext)` per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 1.
///
/// This is the canonical content-addressed identifier for chunks under
/// non-convergent encryption. Compatible with external content-addressed
/// storage tooling that uses plain BLAKE3.
#[inline]
#[must_use]
pub fn chunk_address_raw(plaintext: &[u8]) -> [u8; 32] {
    *blake3::hash(plaintext).as_bytes()
}

/// Convergent chunk address: `derive_key("ol-chunk-addr-convergent-v1", plaintext)`
/// per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 2.
///
/// Same plaintext from any sender produces the same address, enabling
/// cross-sender deduplication for content under convergent encryption.
/// Domain-separated from the raw address so the engine never confuses the
/// two addressing schemes.
#[inline]
#[must_use]
pub fn chunk_address_convergent(plaintext: &[u8]) -> [u8; 32] {
    derive_key32(DerivationContext::ChunkAddrConvergent, plaintext)
}

/// Derive a per-chunk AEAD key per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 3.
///
/// `ratchet_chain_key` is the current double-ratchet chain key for the
/// session this chunk is being encrypted under. `chunk_id_full` is the
/// 32-byte BLAKE3 chunk address (raw or convergent).
///
/// For convergent encryption, callers should supply the chunk content
/// itself (or a content-derived value) as `ratchet_chain_key` so that
/// identical plaintext from any sender produces an identical AEAD key.
#[must_use]
pub fn derive_aead_key(ratchet_chain_key: &[u8; 32], chunk_id_full: &[u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(ratchet_chain_key);
    material[32..].copy_from_slice(chunk_id_full);
    derive_key32(DerivationContext::ChunkAeadKey, &material)
}

/// Derive the 16-byte `ratchet_key_id` stored in the chunk_log header
/// per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 4 and [ADR-0003](../../../docs/decisions/0003-on-disk-format.md).
///
/// This identifier lets recovery look up which ratchet generation a
/// chunk's AEAD key came from without storing the ratchet chain key
/// itself in the on-disk record.
#[must_use]
pub fn derive_ratchet_key_id(ratchet_chain_key: &[u8; 32], chunk_id_full: &[u8; 32]) -> [u8; 16] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(ratchet_chain_key);
    material[32..].copy_from_slice(chunk_id_full);
    derive_key16(DerivationContext::ChunkRatchetId, &material)
}

/// Derive the stripe seed and within-stripe position for a chunk per
/// [ADR-0004](../../../docs/decisions/0004-stripe-layout.md) and
/// [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 5.
///
/// `chunk_id_full` is the 32-byte BLAKE3 chunk address. `stripe_k` is the
/// number of data shards per stripe (default 10 per [ADR-0004]).
///
/// Returns `(stripe_seed, position)` where `stripe_seed` has the low 6
/// bits cleared (reserved for position assignment) and `position` is in
/// `[0, stripe_k)`.
#[must_use]
pub fn derive_stripe_seed(chunk_id_full: &[u8; 32], stripe_k: u8) -> (u64, u8) {
    let mut material = [0u8; 33];
    material[..32].copy_from_slice(chunk_id_full);
    material[32] = stripe_k;
    let derived = derive_key32(DerivationContext::StripeSeed, &material);
    let h = u64::from_le_bytes(derived[..8].try_into().expect("8 bytes"));
    let stripe_seed = h & !((1u64 << 6) - 1);
    let position = ((h & 0x3F) % u64::from(stripe_k.max(1))) as u8;
    (stripe_seed, position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_address_matches_blake3_hash() {
        let plain = b"Hello, world!";
        let addr = chunk_address_raw(plain);
        let expected = blake3::hash(plain);
        assert_eq!(addr, *expected.as_bytes());
    }

    #[test]
    fn convergent_address_differs_from_raw_address() {
        let plain = b"Hello, world!";
        let raw = chunk_address_raw(plain);
        let conv = chunk_address_convergent(plain);
        assert_ne!(raw, conv, "raw and convergent addresses must differ");
    }

    #[test]
    fn convergent_address_is_deterministic_across_callers() {
        let plain = b"shared content sent by two peers";
        let a = chunk_address_convergent(plain);
        let b = chunk_address_convergent(plain);
        assert_eq!(a, b, "convergent address must be deterministic");
    }

    #[test]
    fn aead_key_changes_with_chunk_id() {
        let chain = [0x42u8; 32];
        let chunk_a = [0x01u8; 32];
        let chunk_b = [0x02u8; 32];
        let key_a = derive_aead_key(&chain, &chunk_a);
        let key_b = derive_aead_key(&chain, &chunk_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn aead_key_changes_with_chain_key() {
        let chain_a = [0x42u8; 32];
        let chain_b = [0x43u8; 32];
        let chunk = [0x01u8; 32];
        let key_a = derive_aead_key(&chain_a, &chunk);
        let key_b = derive_aead_key(&chain_b, &chunk);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn ratchet_key_id_is_16_bytes_and_independent_of_aead_key() {
        let chain = [0x55u8; 32];
        let chunk = [0x01u8; 32];
        let aead = derive_aead_key(&chain, &chunk);
        let ratchet_id = derive_ratchet_key_id(&chain, &chunk);
        assert_eq!(ratchet_id.len(), 16);
        // The two share derivation inputs but use different domain
        // contexts, so output prefixes must differ.
        assert_ne!(&aead[..16], &ratchet_id[..]);
    }

    #[test]
    fn stripe_seed_clears_low_6_bits() {
        let chunk = [0x77u8; 32];
        let (seed, _pos) = derive_stripe_seed(&chunk, 10);
        assert_eq!(seed & 0x3F, 0, "low 6 bits must be cleared");
    }

    #[test]
    fn stripe_position_within_k_range() {
        let mut chunk = [0u8; 32];
        for i in 0..200 {
            chunk[0] = i as u8;
            chunk[1] = (i >> 8) as u8;
            let (_seed, pos) = derive_stripe_seed(&chunk, 10);
            assert!(pos < 10, "position {pos} must be < k=10");
        }
    }

    #[test]
    fn stripe_seed_deterministic_per_chunk_id() {
        let chunk = [0x99u8; 32];
        let (s1, p1) = derive_stripe_seed(&chunk, 10);
        let (s2, p2) = derive_stripe_seed(&chunk, 10);
        assert_eq!((s1, p1), (s2, p2));
    }

    #[test]
    fn all_contexts_unique() {
        // Every registered context must produce a distinct output for the
        // same input. Domain-separation invariant.
        let input = b"identical-input-across-contexts";
        let contexts = [
            DerivationContext::ChunkAddrConvergent,
            DerivationContext::ChunkAeadKey,
            DerivationContext::ChunkRatchetId,
            DerivationContext::StripeSeed,
            DerivationContext::StripeCohortMix,
            DerivationContext::ManifestId,
            DerivationContext::CapabilityId,
            DerivationContext::RevocationLeaf,
            DerivationContext::RevocationInternal,
            DerivationContext::FolderCrdtActor,
            DerivationContext::ShareLinkId,
            DerivationContext::BloomInitKey,
            DerivationContext::FountainSymbolId,
            DerivationContext::NetworkCodingId,
            DerivationContext::PqHybridDerive,
        ];
        let derived: Vec<[u8; 32]> = contexts.iter().map(|c| derive_key32(*c, input)).collect();
        for i in 0..derived.len() {
            for j in (i + 1)..derived.len() {
                assert_ne!(
                    derived[i], derived[j],
                    "contexts {:?} and {:?} produced equal output",
                    contexts[i], contexts[j],
                );
            }
        }
    }

    #[test]
    fn context_strings_are_canonical() {
        // Spot-check a few critical context strings against the ADR-0006
        // registered values.
        assert_eq!(
            DerivationContext::ChunkAddrConvergent.as_str(),
            "ol-chunk-addr-convergent-v1",
        );
        assert_eq!(
            DerivationContext::ChunkAeadKey.as_str(),
            "ol-chunk-aead-key-v1",
        );
        assert_eq!(DerivationContext::StripeSeed.as_str(), "ol-stripe-seed-v1",);
    }
}
