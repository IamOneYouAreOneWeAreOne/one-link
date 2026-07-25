//! Stripe encode + decode operating on whole chunks.

use ol_fec::{Codec, FecError};

use crate::error::ErasureError;

/// Per-shard role within a stripe. Mirrors `ol_chunk_store::StripeRole`
/// but is local to this crate (we don't want a runtime dep on
/// `chunk_store`; the daemon glues the two when it stores shards on
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
/// of the same plaintext at the same (k, m) produce the same `StripeId`
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

    /// Validate the field-size and non-zero invariants without
    /// allocating a stripe.
    pub fn validate(self) -> Result<(), ErasureError> {
        Codec::new(self.k, self.m).map(|_| ()).map_err(Into::into)
    }
}

/// Maximum plaintext bytes in one erasure stripe. One Link stripes
/// whole CDC chunks (normally <=256 KiB); the 1 MiB ceiling matches the
/// bulk-frame/WAL envelope while preventing multiplicative allocation
/// from unbounded FFI callers.
pub const MAX_STRIPE_PLAINTEXT_BYTES: usize = 1024 * 1024;

/// Maximum bytes in one externally reconstructed shard.
pub const MAX_SHARD_BYTES: usize = MAX_STRIPE_PLAINTEXT_BYTES;

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

/// BLAKE3 `derive_key` context for stripe IDs. Domain-separated against
/// other BLAKE3 derivations on the same plaintext (ADR-0006 registry).
const STRIPE_ID_CONTEXT: &str = "ol-erasure-stripe-id-v1";

/// Compute the canonical [`StripeId`] for a (plaintext, k, m) tuple.
///
/// Same plaintext + same params → same `StripeId`. Different params →
/// different `StripeId` (so RS(10,4) and RS(6,6) stripes of the same
/// plaintext do NOT collide).
#[must_use]
pub fn stripe_id_of(plaintext: &[u8], params: StripeParams) -> StripeId {
    // BLAKE3 derive_key over a length-prefixed canonical concatenation:
    //   [u64 plaintext_len][u8 k][u8 m][plaintext bytes]
    // Stream the canonical concatenation directly into BLAKE3. This
    // is byte-identical to `derive_key(context, concatenation)` and
    // avoids a second plaintext-sized allocation and memcpy.
    let mut hasher = blake3::Hasher::new_derive_key(STRIPE_ID_CONTEXT);
    hasher.update(&(plaintext.len() as u64).to_le_bytes());
    match (u8::try_from(params.k), u8::try_from(params.m)) {
        (Ok(k), Ok(m))
            if k > 0
                && m > 0
                && params
                    .k
                    .checked_add(params.m)
                    .is_some_and(|total| total <= 255) =>
        {
            hasher.update(&[k, m]);
        }
        _ => {
            // Valid stripes retain the frozen `[u8 k][u8 m]` encoding.
            // Invalid public inputs get a collision-resistant diagnostic ID
            // instead of silently truncating large parameters into that space.
            hasher.update(&[0, 0]);
            hasher.update(&params.k.to_le_bytes());
            hasher.update(&params.m.to_le_bytes());
        }
    }
    hasher.update(plaintext);
    *hasher.finalize().as_bytes()
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
pub fn encode_stripe(plaintext: &[u8], params: StripeParams) -> Result<Vec<Shard>, ErasureError> {
    if plaintext.is_empty() {
        return Err(ErasureError::EmptyPlaintext);
    }
    if plaintext.len() > MAX_STRIPE_PLAINTEXT_BYTES {
        return Err(ErasureError::PlaintextTooLarge {
            got: plaintext.len(),
            max: MAX_STRIPE_PLAINTEXT_BYTES,
        });
    }
    let codec = Codec::new(params.k, params.m)?;
    let stripe_id = stripe_id_of(plaintext, params);
    let plaintext_len = u64::try_from(plaintext.len()).expect("supported usize fits in u64");

    // Pad to a multiple of k, then split into k equal-sized shards.
    let shard_len = plaintext.len().div_ceil(params.k);
    let mut padded = vec![0u8; shard_len * params.k];
    padded[..plaintext.len()].copy_from_slice(plaintext);
    let mut data_shards: Vec<Vec<u8>> = (0..params.k)
        .map(|i| padded[i * shard_len..(i + 1) * shard_len].to_vec())
        .collect();

    // Encode parity.
    let data_refs: Vec<&[u8]> = data_shards.iter().map(std::vec::Vec::as_slice).collect();
    let parity_shards = codec.encode(&data_refs)?;

    // Build typed Shard values.
    let mut out = Vec::with_capacity(params.k + params.m);
    for (i, bytes) in data_shards.drain(..).enumerate() {
        out.push(Shard {
            bytes,
            role: ShardRole::Data,
            index: validated_shard_index(i, params)?,
            plaintext_len,
            stripe_id,
        });
    }
    for (i, bytes) in parity_shards.into_iter().enumerate() {
        out.push(Shard {
            bytes,
            role: ShardRole::Parity,
            index: validated_shard_index(i, params)?,
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
    let codec = Codec::new(params.k, params.m)?;
    let total = codec.total_shards();
    if present.len() != total {
        return Err(ErasureError::PresentSlotCount {
            expected: total,
            got: present.len(),
        });
    }
    // Sanity-check role + index per slot.
    let mut expected_metadata: Option<(StripeId, u64, usize)> = None;
    for (pos, slot) in present.iter().enumerate() {
        let Some(shard) = slot else {
            continue;
        };
        let (expected_role, expected_index) = if pos < params.k {
            (ShardRole::Data, validated_shard_index(pos, params)?)
        } else {
            (
                ShardRole::Parity,
                validated_shard_index(pos - params.k, params)?,
            )
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
        if let Some((stripe_id, plaintext_len, shard_len)) = expected_metadata {
            if shard.stripe_id != stripe_id {
                return Err(ErasureError::ShardMetadataMismatch {
                    pos,
                    field: "stripe_id",
                });
            }
            if shard.plaintext_len != plaintext_len {
                return Err(ErasureError::ShardMetadataMismatch {
                    pos,
                    field: "plaintext_len",
                });
            }
            if shard.bytes.len() != shard_len {
                return Err(ErasureError::ShardMetadataMismatch {
                    pos,
                    field: "shard length",
                });
            }
        } else {
            expected_metadata = Some((shard.stripe_id, shard.plaintext_len, shard.bytes.len()));
        }
    }

    let raw_present: Vec<Option<&[u8]>> = present
        .iter()
        .map(|s| s.as_ref().map(|shard| shard.bytes.as_slice()))
        .collect();
    let data_shards = codec.decode(&raw_present)?;

    // Successful FEC decode proves at least K shards were present, so
    // metadata must exist. Keep the failure path explicit rather than
    // relying on an invariant `expect` in production code.
    let (expected_stripe_id, plaintext_len_u64, shard_len) =
        expected_metadata.ok_or(ErasureError::InvalidPlaintextLength { got: 0, max: 0 })?;
    let max_plaintext_len =
        shard_len
            .checked_mul(params.k)
            .ok_or(ErasureError::InvalidPlaintextLength {
                got: plaintext_len_u64,
                max: usize::MAX,
            })?;
    let plaintext_len =
        usize::try_from(plaintext_len_u64).map_err(|_| ErasureError::InvalidPlaintextLength {
            got: plaintext_len_u64,
            max: max_plaintext_len,
        })?;
    if plaintext_len == 0
        || plaintext_len > max_plaintext_len
        || plaintext_len > MAX_STRIPE_PLAINTEXT_BYTES
    {
        return Err(ErasureError::InvalidPlaintextLength {
            got: plaintext_len_u64,
            max: max_plaintext_len.min(MAX_STRIPE_PLAINTEXT_BYTES),
        });
    }

    let mut plaintext = Vec::with_capacity(max_plaintext_len);
    for shard in &data_shards {
        plaintext.extend_from_slice(shard);
    }
    plaintext.truncate(plaintext_len);
    if stripe_id_of(&plaintext, params) != expected_stripe_id {
        return Err(ErasureError::StripeIdMismatch);
    }
    Ok(plaintext)
}

fn validated_shard_index(index: usize, params: StripeParams) -> Result<u8, ErasureError> {
    u8::try_from(index).map_err(|_| {
        ErasureError::InvalidParameters(FecError::InvalidParameters {
            k: params.k,
            m: params.m,
        })
    })
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
    fn streamed_stripe_id_preserves_frozen_canonical_bytes() {
        let plaintext = b"canonical stripe id regression";
        let params = StripeParams::STANDARD;
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
        canonical.push(u8::try_from(params.k).expect("validated k fits u8"));
        canonical.push(u8::try_from(params.m).expect("validated m fits u8"));
        canonical.extend_from_slice(plaintext);
        assert_eq!(
            stripe_id_of(plaintext, params),
            blake3::derive_key(STRIPE_ID_CONTEXT, &canonical)
        );
    }

    #[test]
    fn rejects_inconsistent_or_forged_shard_metadata() {
        let plaintext = b"metadata integrity must be enforced";
        let mut shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        shards[1].plaintext_len += 1;
        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        assert!(matches!(
            decode_stripe(StripeParams::STANDARD, &present),
            Err(ErasureError::ShardMetadataMismatch {
                field: "plaintext_len",
                ..
            })
        ));

        let mut shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        for shard in &mut shards {
            shard.plaintext_len = u64::MAX;
        }
        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        assert!(matches!(
            decode_stripe(StripeParams::STANDARD, &present),
            Err(ErasureError::InvalidPlaintextLength { .. })
        ));

        let mut shards = encode_stripe(plaintext, StripeParams::STANDARD).unwrap();
        for shard in &mut shards {
            shard.stripe_id = [0xFF; 32];
        }
        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        assert!(matches!(
            decode_stripe(StripeParams::STANDARD, &present),
            Err(ErasureError::StripeIdMismatch)
        ));
    }

    #[test]
    fn rejects_empty_plaintext() {
        let r = encode_stripe(&[], StripeParams::STANDARD);
        assert!(matches!(r, Err(ErasureError::EmptyPlaintext)));
    }

    #[test]
    fn rejects_oversized_plaintext() {
        let plaintext = vec![0u8; MAX_STRIPE_PLAINTEXT_BYTES + 1];
        assert!(matches!(
            encode_stripe(&plaintext, StripeParams::STANDARD),
            Err(ErasureError::PlaintextTooLarge { .. })
        ));
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
        assert!(matches!(
            result,
            Err(ErasureError::ShardDescriptorMismatch { .. })
        ));
    }

    #[test]
    fn random_chunks_round_trip_many_seeds() {
        // 100 random chunks at various sizes; each encodes + decodes.
        let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
        for trial in 0..100 {
            let len = 1 + rng.random_range(0..16_384);
            let plaintext: Vec<u8> = (0..len).map(|_| rng.random::<u8>()).collect();
            let shards = encode_stripe(&plaintext, StripeParams::STANDARD).unwrap();
            let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
            let decoded = decode_stripe(StripeParams::STANDARD, &present).unwrap();
            assert_eq!(decoded, plaintext, "trial {trial} (len={len}) failed");
        }
    }
}
