//! Stripe encode + decode operating on whole chunks.

use ol_fec::Codec;

use crate::error::ErasureError;

/// Per-shard role within a stripe. Mirrors `ol_chunk_store::StripeRole`
/// but is local to this crate (we don't want a runtime dep on
/// chunk_store; the daemon glues the two when it stores shards on
/// disk).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ShardRole {
    /// One of `k` data shards.
    Data,
    /// One of `m` parity shards.
    Parity,
}

/// Stripe identity: 32-byte BLAKE3 of the **canonical stripe context**
/// (plaintext length || k || m || plaintext-content-id). Two senders
/// of the same plaintext at the same (k, m) produce the same StripeId
/// — that's the cross-sender dedup property for data shards.
pub type StripeId = [u8; 32];

/// Stripe configuration. `k` data shards + `m` parity shards, all
/// equal length. The total `k + m` must be ≤ 255 (ADR-0016).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StripeParams {
    /// Number of data shards.
    pub k: usize,
    /// Number of parity shards.
    pub m: usize,
}

impl StripeParams {
    /// Standard durability config: 10 data + 4 parity = 14 shards,
    /// any 10 recover. ~1.4× storage overhead.
    pub const STANDARD: Self = Self { k: 10, m: 4 };

    /// Archival config: 6 data + 6 parity = 12 shards, any 6 recover.
    /// ~2.0× storage; tolerates losing half the cohort.
    pub const ARCHIVAL: Self = Self { k: 6, m: 6 };

    /// Ephemeral config: 9 data + 1 parity = 10 shards, any 9 recover.
    /// ~1.11× storage; tolerates one device loss only.
    pub const EPHEMERAL: Self = Self { k: 9, m: 1 };
}

/// One shard of a stripe — bytes + role + position. The daemon wraps
/// this in a `ChunkRecord` with the matching `StripeDescriptor` when
/// it persists to disk.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Shard {
    /// Raw shard bytes. Same length across all shards in a stripe.
    pub bytes: Vec<u8>,
    /// Data or Parity.
    pub role: ShardRole,
    /// Position within its role (`0..k` for Data, `0..m` for Parity).
    pub index: u8,
    /// Length of the ORIGINAL plaintext, before padding to a multiple
    /// of `k`. Carried in every shard so the decoder knows how much
    /// to trim from the reassembled buffer.
    pub plaintext_len: u64,
    /// Identity of the stripe this shard belongs to.
    pub stripe_id: StripeId,
}

/// BLAKE3 derive_key context for stripe IDs. Domain-separated against
/// other BLAKE3 derivations on the same plaintext (ADR-0006 registry).
const STRIPE_ID_CONTEXT: &str = "ol-erasure-stripe-id-v1";

/// Compute the canonical [`StripeId`] for a (plaintext, k, m) tuple.
///
/// Same plaintext + same params → same StripeId. Different params →
/// different StripeId (so RS(10,4) and RS(6,6) stripes of the same
/// plaintext do NOT collide).
#[must_use]
pub fn stripe_id_of(plaintext: &[u8], params: StripeParams) -> StripeId {
    // BLAKE3 derive_key over a length-prefixed canonical concatenation:
    //   [u64 plaintext_len][u8 k][u8 m][plaintext bytes]
    let mut input = Vec::with_capacity(plaintext.len() + 10);
    input.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
    input.push(params.k as u8);
    input.push(params.m as u8);
    input.extend_from_slice(plaintext);
    blake3::derive_key(STRIPE_ID_CONTEXT, &input)
}

/// Encode `plaintext` into a stripe of `k + m` shards.
///
/// Padding: if `plaintext.len()` is not a multiple of `k`, the last
/// data shard is zero-padded. The decoder trims back to the original
/// length using the `plaintext_len` field carried in every shard.
///
/// # Errors
///
/// - [`ErasureError::InvalidParameters`] if the underlying `ol_fec`
///   codec rejects `(k, m)`.
/// - [`ErasureError::EmptyPlaintext`] if `plaintext.is_empty()`.
pub fn encode_stripe(
    plaintext: &[u8],
    params: StripeParams,
) -> Result<Vec<Shard>, ErasureError> {
    if plaintext.is_empty() {
        return Err(ErasureError::EmptyPlaintext);
    }
    let codec = Codec::new(params.k, params.m)?;
    let stripe_id = stripe_id_of(plaintext, params);
    let plaintext_len = plaintext.len() as u64;

    // Pad to a multiple of k, then split into k equal-sized shards.
    let shard_len = plaintext.len().div_ceil(params.k);
    let mut padded = vec![0u8; shard_len * params.k];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let mut data_shards: Vec<Vec<u8>> = (0..params.k)
        .map(|i| padded[i * shard_len..(i + 1) * shard_len].to_vec())
        .collect();

    // Encode parity.
    let data_refs: Vec<&[u8]> = data_shards.iter().map(|d| d.as_slice()).collect();
    let parity_shards = codec.encode(&data_refs)?;

    // Build typed Shard values.
    let mut out = Vec::with_capacity(params.k + params.m);
    for (i, bytes) in data_shards.drain(..).enumerate() {
        out.push(Shard {
            bytes,
            role: ShardRole::Data,
            index: i as u8,
            plaintext_len,
            stripe_id,
        });
    }
    for (i, bytes) in parity_shards.into_iter().enumerate() {
        out.push(Shard {
            bytes,
            role: ShardRole::Parity,
            index: i as u8,
            plaintext_len,
            stripe_id,
        });
    }
    Ok(out)
}

/// Decode a stripe back to its original plaintext given any `k` of
/// the `k + m` shards.
///
/// `present` is indexed as: positions `0..k` for data shards
/// 0..k, positions `k..k+m` for parity shards 0..m. Caller MUST
/// supply the shards in the canonical position layout; the function
/// verifies role + index match each slot.
///
/// # Errors
///
/// - [`ErasureError::PresentSlotCount`] on length mismatch.
/// - [`ErasureError::ShardDescriptorMismatch`] if a shard at slot
///   `i` reports the wrong role/index.
/// - [`ErasureError::InvalidParameters`] if the codec fails.
pub fn decode_stripe(
    params: StripeParams,
    present: &[Option<&Shard>],
) -> Result<Vec<u8>, ErasureError> {
    let total = params.k + params.m;
    if present.len() != total {
        return Err(ErasureError::PresentSlotCount {
            expected: total,
            got: present.len(),
        });
    }
    // Sanity-check role + index per slot.
    for (pos, slot) in present.iter().enumerate() {
        let Some(shard) = slot else {
            continue;
        };
        let (expected_role, expected_index) = if pos < params.k {
            (ShardRole::Data, pos as u8)
        } else {
            (ShardRole::Parity, (pos - params.k) as u8)
        };
        if shard.role != expected_role || shard.index != expected_index {
            return Err(ErasureError::ShardDescriptorMismatch {
                pos,
                role: shard.role,
                index: shard.index,
                expected_role,
                expected_index,
            });
        }
    }

    let codec = Codec::new(params.k, params.m)?;
    let raw_present: Vec<Option<&[u8]>> = present
        .iter()
        .map(|s| s.as_ref().map(|shard| shard.bytes.as_slice()))
        .collect();
    let data_shards = codec.decode(&raw_present)?;

    // Determine plaintext_len from any present shard.
    let plaintext_len = present
        .iter()
        .find_map(|s| s.as_ref().map(|shard| shard.plaintext_len as usize))
        .expect("at least one present shard ensures we have plaintext_len");

    let mut plaintext = Vec::with_capacity(plaintext_len);
    for shard in &data_shards {
        plaintext.extend_from_slice(shard);
    }
    plaintext.truncate(plaintext_len);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    #[test]
    fn encode_decode_basic() {
        let plaintext: Vec<u8> = (0..1000u32).map(|i| (i & 0xFF) as u8).collect();
        let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
        assert_eq!(shards.len(), 14);
        for shard in &shards {
            assert_eq!(shard.plaintext_len, plaintext.len() as u64);
        }

        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn encode_decode_padded_plaintext() {
        // plaintext.len() = 13 = K + 3; needs padding to 20 bytes
        // (2 bytes per shard × 10 shards). Decoder must trim back.
        let plaintext: Vec<u8> = (0..13u8).collect();
        let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn recover_from_arbitrary_4_erasures() {
        let plaintext: Vec<u8> = (0..5000u32).map(|i| (i & 0xFF) as u8).collect();
        let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
        // Drop shards 0, 5, 11, 13.
        let mut present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        for &drop in &[0, 5, 11, 13] {
            present[drop] = None;
        }
        let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn cross_sender_data_shards_are_byte_equivalent() {
        let plaintext = b"raw camera footage that twelve senders share";
        let alice_shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        let bob_shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();

        // Same StripeId.
        assert_eq!(alice_shards[0].stripe_id, bob_shards[0].stripe_id);
        // Data shards (positions 0..k) are byte-equivalent across senders.
        for i in 0..StripeParams::STANDARD.k {
            assert_eq!(alice_shards[i].bytes, bob_shards[i].bytes);
        }
        // Parity shards are also byte-equivalent under this scheme
        // because the Cauchy matrix is deterministic; same data → same parity.
        for i in StripeParams::STANDARD.k..(StripeParams::STANDARD.k + StripeParams::STANDARD.m) {
            assert_eq!(alice_shards[i].bytes, bob_shards[i].bytes);
        }
    }

    #[test]
    fn rejects_empty_plaintext() {
        let r = encode_stripe(&[], StripeParams::STANDARD);
        assert!(matches!(r, Err(ErasureError::EmptyPlaintext)));
    }

    #[test]
    fn rejects_wrong_present_count() {
        let plaintext = b"test";
        let _shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        let result = decode_stripe(StripeParams::STANDARD, &[]);
        assert!(matches!(result, Err(ErasureError::PresentSlotCount { .. })));
    }

    #[test]
    fn rejects_shard_descriptor_mismatch() {
        let plaintext = b"test";
        let shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        // Swap shards 0 and 1's positions.
        let mut present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        present.swap(0, 1);
        let result = decode_stripe(StripeParams::STANDARD, &present);
        assert!(matches!(result, Err(ErasureError::ShardDescriptorMismatch { .. })));
    }

    #[test]
    fn random_chunks_round_trip_many_seeds() {
        // 100 random chunks at various sizes; each encodes + decodes.
        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        for trial in 0..100 {
            let len = 1 + rng.r#gen_range(0..16_384);
            let plaintext: Vec<u8> = (0..len).map(|_| rng.r#gen::<u8>()).collect();
            let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
            let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
            let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
            assert_eq!(decoded, plaintext, "trial {trial} (len={len}) failed");
        }
    }
}
