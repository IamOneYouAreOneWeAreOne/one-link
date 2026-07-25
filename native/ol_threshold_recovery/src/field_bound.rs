//! Coherence-field-bound threshold recovery (alien-tech layer).
//!
//! Adds a keyed mask layer on top of plain Shamir. Each share-stream is
//! masked with a domain-separated BLAKE3 keyed-XOF stream derived from:
//!
//! 1. A secret 32-byte CSPRNG-grade binding key. A public field-solver
//!    output is context, not sufficient key material by itself.
//! 2. The share-holder's per-peer field score at mint time (in [0, 1]).
//!
//! Recovery requires the same binding key and context. Keep that key in a
//! separate trust domain from the masked shares.
//!
//! ## What this defeats
//!
//! - **Separated-backup capture**: stealing all masked share files is not
//!   enough when the binding key is stored independently.
//! - **Context binding**: holder scores, epoch, and share index are committed
//!   into distinct mask streams.
//! - **Primary threshold remains explicit**: possession of the witness never
//!   substitutes for K valid Shamir shares.
//!
//! ## What this gracefully degrades to
//!
//! Callers who don't have a field deployment can use plain Shamir via
//! [`crate::shamir::share_bytes`]. The `field_bound_*` functions in
//! this module are a defense-in-depth layer ON TOP of that, not a
//! replacement. With a `FieldWitness::placeholder()`, the layer is a
//! no-op and behaviour is identical to plain Shamir.
//!
//! ## Implementation
//!
//! BLAKE3 keyed-XOF supplies the mask stream with an explicit v2 domain tag.

use thiserror::Error;

use crate::prng::PrngState;
use crate::shamir::{
    reconstruct_bytes as plain_reconstruct_bytes, share_bytes as plain_share_bytes,
    share_bytes_secure as plain_share_bytes_secure, ShareError, MAX_SECRET_BYTES,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FIELD_OTP_DOMAIN: &[u8] = b"one-link/field-bound-share-mask/v2";

/// Errors from field-bound operations.
#[derive(Debug, Error, PartialEq)]
pub enum FieldBindingError {
    /// Wrap a [`ShareError`] from the inner plain-Shamir layer.
    #[error("plain-Shamir layer rejected: {0}")]
    Inner(#[from] ShareError),
    /// Number of holder field scores doesn't match the expected number of
    /// shares.
    #[error("expected {expected} field scores, got {got}")]
    ScoreCountMismatch {
        /// What was expected.
        expected: usize,
        /// What was supplied.
        got: usize,
    },
    /// A field score is outside [0, 1] — caller error.
    #[error("field score must be in [0, 1]; got {got}")]
    FieldScoreOutOfRange {
        /// Bad value.
        got: f64,
    },

    /// A supplied share index does not identify a witness holder.
    #[error("share index {index} is outside witness holder range 0..{holder_count}")]
    ShareIndexOutOfRange {
        /// Invalid index.
        index: usize,
        /// Number of holders committed by the witness.
        holder_count: usize,
    },

    /// The same original share index was supplied more than once.
    #[error("duplicate original share index {index}")]
    DuplicateShareIndex {
        /// Duplicated index.
        index: usize,
    },
}

/// Secret field-binding context required at recovery time.
///
/// This value is not safe to store beside the masked shares: it contains the
/// keyed-XOF key and therefore can remove the field mask. The Shamir threshold
/// remains the primary security boundary; field binding is defense in depth.
#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct FieldWitness {
    /// Secret 32-byte binding key. It must contain CSPRNG-grade entropy.
    /// Public or low-entropy field output alone is not a cryptographic key.
    pub field_seed: [u8; 32],
    /// Per-share field scores in [0, 1]. Same length as `n`. The score
    /// is the `OneField` `τ_c` normalised value for each share-holder.
    pub holder_scores: Vec<f64>,
    /// Mint-time epoch (caller-supplied; nanoseconds since arbitrary
    /// epoch). Mixed into the KDF so refresh ticks produce different
    /// masks even when field state hasn't changed.
    pub epoch_ns: u64,
}

impl std::fmt::Debug for FieldWitness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FieldWitness")
            .field("field_seed", &"[REDACTED]")
            .field("holder_count", &self.holder_scores.len())
            .field("epoch_ns", &self.epoch_ns)
            .finish()
    }
}

impl FieldWitness {
    /// Construct a no-op witness — field-binding becomes a passthrough
    /// (all-zero OTP). Use when no field deployment is available so
    /// the same code path supports both alien-tech AND plain Shamir.
    #[must_use]
    pub fn placeholder(n: usize) -> Self {
        Self {
            field_seed: [0u8; 32],
            holder_scores: vec![0.0; n],
            epoch_ns: 0,
        }
    }

    /// Is this a placeholder witness (no actual binding applied)?
    #[must_use]
    pub fn is_placeholder(&self) -> bool {
        self.field_seed == [0u8; 32]
            && self.epoch_ns == 0
            && self.holder_scores.iter().all(|s| *s == 0.0)
    }

    /// Derive the OTP for share index `i` over `n_bytes` of secret.
    /// Pure function of the witness + share index, so a recovering
    /// caller with the same witness produces the same OTP.
    fn derive_otp(&self, share_index: usize, n_bytes: usize) -> Vec<u8> {
        if self.is_placeholder() {
            return vec![0u8; n_bytes];
        }
        let score = self.holder_scores.get(share_index).copied().unwrap_or(0.0);
        let score_bits = if score == 0.0 { 0.0f64 } else { score }.to_bits();
        let mut hasher = blake3::Hasher::new_keyed(&self.field_seed);
        hasher.update(FIELD_OTP_DOMAIN);
        hasher.update(&(share_index as u64).to_be_bytes());
        hasher.update(&score_bits.to_be_bytes());
        hasher.update(&self.epoch_ns.to_be_bytes());
        let mut reader = hasher.finalize_xof();
        let mut otp = vec![0u8; n_bytes];
        reader.fill(&mut otp);
        otp
    }
}

fn validate_witness(witness: &FieldWitness) -> Result<(), FieldBindingError> {
    if witness.holder_scores.len() > crate::shamir::max_participants() as usize {
        return Err(FieldBindingError::ScoreCountMismatch {
            expected: crate::shamir::max_participants() as usize,
            got: witness.holder_scores.len(),
        });
    }
    for &score in &witness.holder_scores {
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return Err(FieldBindingError::FieldScoreOutOfRange { got: score });
        }
    }
    Ok(())
}

/// Split a multi-byte secret with field-bound shares.
///
/// Each share-stream produced by plain Shamir is XOR-masked with a
/// witness-derived mask. Keep the witness key separate from the shares.
///
/// # Errors
/// - [`FieldBindingError::Inner`] for plain-Shamir layer errors.
/// - [`FieldBindingError::ScoreCountMismatch`] when `holder_scores.len()
///   != n`.
/// - [`FieldBindingError::FieldScoreOutOfRange`] when any score is
///   outside [0, 1].
pub fn field_bound_split(
    secret: &[u8],
    k: u32,
    n: u32,
    state: &mut PrngState,
    witness: &FieldWitness,
) -> Result<Vec<Vec<u8>>, FieldBindingError> {
    validate_witness(witness)?;
    if witness.holder_scores.len() != n as usize {
        return Err(FieldBindingError::ScoreCountMismatch {
            expected: n as usize,
            got: witness.holder_scores.len(),
        });
    }
    let plain_streams = plain_share_bytes(secret, k, n, state)?;
    Ok(mask_share_streams(plain_streams, witness))
}

/// Production field-bound split using operating-system CSPRNG coefficients.
pub fn field_bound_split_secure(
    secret: &[u8],
    k: u32,
    n: u32,
    witness: &FieldWitness,
) -> Result<Vec<Vec<u8>>, FieldBindingError> {
    validate_witness(witness)?;
    if witness.holder_scores.len() != n as usize {
        return Err(FieldBindingError::ScoreCountMismatch {
            expected: n as usize,
            got: witness.holder_scores.len(),
        });
    }
    let plain_streams = plain_share_bytes_secure(secret, k, n)?;
    Ok(mask_share_streams(plain_streams, witness))
}

fn mask_share_streams(mut plain_streams: Vec<Vec<u8>>, witness: &FieldWitness) -> Vec<Vec<u8>> {
    for (i, stream) in plain_streams.iter_mut().enumerate() {
        let otp = Zeroizing::new(witness.derive_otp(i, stream.len()));
        for (b, m) in stream.iter_mut().zip(otp.iter()) {
            *b ^= *m;
        }
    }
    plain_streams
}

/// Reconstruct a multi-byte secret from at least K field-bound shares.
///
/// Caller supplies the x-values of the chosen shares, the corresponding
/// masked share-streams, AND the original witness (must equal the one
/// from mint time). Each stream is un-masked with its witness-derived
/// OTP, then standard Lagrange interpolation recovers the secret.
///
/// `share_indices` carries the 0-based original index of each supplied
/// share so the right OTP is derived. (When you minted with N = 5 and
/// supply shares 0, 2, 4 to recover, pass `share_indices = [0, 2, 4]`.)
///
/// # Errors
/// - [`FieldBindingError::Inner`] for plain-Shamir layer errors.
/// - [`FieldBindingError::ScoreCountMismatch`] when witness scores
///   length is wrong.
pub fn field_bound_reconstruct(
    xs: &[u8],
    streams: &[&[u8]],
    share_indices: &[usize],
    k: u32,
    witness: &FieldWitness,
) -> Result<Vec<u8>, FieldBindingError> {
    validate_witness(witness)?;
    if xs.len() != streams.len() || xs.len() != share_indices.len() {
        return Err(FieldBindingError::Inner(ShareError::NotEnoughShares {
            have: xs.len().min(streams.len()).min(share_indices.len()),
            need: k,
        }));
    }
    let mut seen = [false; 255];
    for &index in share_indices {
        if index >= witness.holder_scores.len() || index >= seen.len() {
            return Err(FieldBindingError::ShareIndexOutOfRange {
                index,
                holder_count: witness.holder_scores.len(),
            });
        }
        if seen[index] {
            return Err(FieldBindingError::DuplicateShareIndex { index });
        }
        seen[index] = true;
    }
    for stream in streams {
        if stream.len() > MAX_SECRET_BYTES {
            return Err(FieldBindingError::Inner(ShareError::SecretTooLarge {
                actual: stream.len(),
                max: MAX_SECRET_BYTES,
            }));
        }
    }
    // Unmask each provided stream with its OTP.
    let mut unmasked: Vec<Vec<u8>> = Vec::with_capacity(streams.len());
    for (idx_in_supply, &original_index) in share_indices.iter().enumerate() {
        let stream = streams[idx_in_supply];
        let otp = Zeroizing::new(witness.derive_otp(original_index, stream.len()));
        let mut row = Vec::with_capacity(stream.len());
        for (b, m) in stream.iter().zip(otp.iter()) {
            row.push(*b ^ *m);
        }
        unmasked.push(row);
    }
    let ref_slices: Vec<&[u8]> = unmasked.iter().map(Vec::as_slice).collect();
    let recovered = plain_reconstruct_bytes(xs, &ref_slices, k)?;
    Ok(recovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_witness(n: usize, seed_byte: u8) -> FieldWitness {
        let mut field_seed = [0u8; 32];
        field_seed.fill(seed_byte);
        let holder_scores = (0..n)
            .map(|i| {
                let index = u32::try_from(i).expect("test holder count fits in u32");
                0.1 + 0.1 * f64::from(index)
            })
            .collect();
        FieldWitness {
            field_seed,
            holder_scores,
            epoch_ns: 1_234_567_890,
        }
    }

    #[test]
    fn round_trip_with_real_witness() {
        let secret = b"this is the master identity seed";
        let witness = make_witness(5, 0x42);
        let mut st = PrngState::new(0xCAFE_F00D_DEAD_BEEF);
        let masked = field_bound_split(secret, 3, 5, &mut st, &witness).unwrap();
        // Reconstruct from shares 0, 2, 4 (x = 1, 3, 5).
        let xs = vec![1u8, 3, 5];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[2].as_slice(),
            masked[4].as_slice(),
        ];
        let indices = vec![0usize, 2, 4];
        let recovered = field_bound_reconstruct(&xs, &supplied, &indices, 3, &witness).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn placeholder_witness_is_passthrough() {
        // With a placeholder witness, the OTP is determined entirely by
        // witness fields (which are zeroed) -> the OTP IS predictable
        // but identical on both sides, so round-trip works.
        let secret = b"plain shamir fallback";
        let witness = FieldWitness::placeholder(5);
        assert!(witness.is_placeholder());
        let mut st = PrngState::new(0xBEEF_0000_0000_0001);
        let masked = field_bound_split(secret, 3, 5, &mut st, &witness).unwrap();
        let mut plain_state = PrngState::new(0xBEEF_0000_0000_0001);
        let plain = plain_share_bytes(secret, 3, 5, &mut plain_state).unwrap();
        assert_eq!(masked, plain, "placeholder must be a literal no-op");
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered = field_bound_reconstruct(&xs, &supplied, &indices, 3, &witness).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn impossible_and_duplicate_share_indices_are_rejected() {
        let witness = make_witness(5, 0x55);
        assert!(matches!(
            field_bound_reconstruct(&[1], &[b"x"], &[usize::MAX], 1, &witness),
            Err(FieldBindingError::ShareIndexOutOfRange { .. })
        ));
        assert!(matches!(
            field_bound_reconstruct(&[1, 2], &[b"x", b"y"], &[0, 0], 2, &witness),
            Err(FieldBindingError::DuplicateShareIndex { index: 0 })
        ));
    }

    #[test]
    fn secure_field_bound_split_is_fresh_and_roundtrips() {
        let witness = make_witness(5, 0x77);
        let secret = b"field-bound production key";
        let first = field_bound_split_secure(secret, 3, 5, &witness).unwrap();
        let second = field_bound_split_secure(secret, 3, 5, &witness).unwrap();
        assert_ne!(first, second);
        let supplied = [
            first[0].as_slice(),
            first[2].as_slice(),
            first[4].as_slice(),
        ];
        assert_eq!(
            field_bound_reconstruct(&[1, 3, 5], &supplied, &[0, 2, 4], 3, &witness).unwrap(),
            secret
        );
    }

    #[test]
    fn wrong_witness_breaks_recovery() {
        // Regression for key/context mismatch: these fixture inputs do
        // not reconstruct the original bytes under a different witness.
        // This is not a brute-force or entropy proof.
        let secret = b"sensitive identity material";
        let real_witness = make_witness(5, 0x42);
        let mut st = PrngState::new(0xCAFE_F00D_DEAD_BEEF);
        let masked = field_bound_split(secret, 3, 5, &mut st, &real_witness).unwrap();
        // Build a different witness — same shape, different field seed.
        let fake_witness = make_witness(5, 0x99);
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered =
            field_bound_reconstruct(&xs, &supplied, &indices, 3, &fake_witness).unwrap();
        // The derived mask differs for this fixture, so the recovered
        // bytes differ from the original secret.
        assert_ne!(recovered, secret);
    }

    #[test]
    fn wrong_holder_scores_break_recovery() {
        // A changed holder score selects a different mask stream for
        // this fixture. Scores are context, not assumed secret entropy.
        let secret = b"defense in depth, identity-bound";
        let real_witness = make_witness(5, 0x42);
        let mut st = PrngState::new(0x1111_2222_3333_4444);
        let masked = field_bound_split(secret, 3, 5, &mut st, &real_witness).unwrap();
        let mut fake_witness = real_witness.clone();
        // Perturb one holder's score by 0.01 — enough to change the
        // f64 bit pattern and re-key the entire OTP stream.
        fake_witness.holder_scores[0] += 0.01;
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered =
            field_bound_reconstruct(&xs, &supplied, &indices, 3, &fake_witness).unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn score_count_mismatch_is_caught() {
        let secret = b"x";
        let witness = make_witness(3, 0x42); // 3 scores
        let mut st = PrngState::new(0);
        let err = field_bound_split(secret, 2, 5, &mut st, &witness).unwrap_err();
        match err {
            FieldBindingError::ScoreCountMismatch { expected, got } => {
                assert_eq!(expected, 5);
                assert_eq!(got, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn out_of_range_score_is_caught() {
        let secret = b"x";
        let mut witness = make_witness(5, 0x42);
        witness.holder_scores[2] = 1.5; // > 1.0
        let mut st = PrngState::new(0);
        let err = field_bound_split(secret, 3, 5, &mut st, &witness).unwrap_err();
        assert!(matches!(
            err,
            FieldBindingError::FieldScoreOutOfRange { .. }
        ));
    }
}
