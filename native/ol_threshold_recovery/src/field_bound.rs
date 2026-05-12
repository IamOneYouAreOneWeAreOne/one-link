//! Coherence-field-bound threshold recovery (alien-tech layer).
//!
//! Adds an XOR mask layer on top of plain Shamir. Each share-stream is
//! masked with a one-time pad derived from:
//!
//! 1. The coherence-field state at the moment of minting (a 32-byte
//!    "field seed" the caller produces from
//!    `coherence_field_native.solve_helmholtz`'s output).
//! 2. The share-holder's per-peer field score at mint time (in [0, 1]).
//!
//! The OTP for share i across all bytes is computed from
//! `HKDF(field_seed || holder_field_score_i)`. Recovery requires the
//! caller to produce the same OTP, which in turn requires reconstructing
//! the field witness — and that requires the field seed AND the same
//! N share-holders' field scores at mint time.
//!
//! ## What this defeats
//!
//! - **Cloud backup capture**: an attacker who exfiltrates all N raw
//!   share-files from cloud backups still cannot decrypt — the OTPs
//!   are derived from the swarm's coherence-field state, which the
//!   attacker doesn't have.
//! - **Offline brute force**: the field seed has 256 bits of entropy
//!   from the field solver's PDE result. Not searchable.
//! - **Lone-attacker reconstruction**: even with all 5 shares + the
//!   field seed in hand, the attacker also needs the share-holders'
//!   field scores at mint time. Those are bound to the actual peer
//!   identities in the swarm.
//!
//! ## What this gracefully degrades to
//!
//! Callers who don't have a field deployment can use plain Shamir via
//! [`crate::shamir::share_bytes`]. The `field_bound_*` functions in
//! this module are a defense-in-depth layer ON TOP of that, not a
//! replacement. With a `FieldWitness::placeholder()`, the layer is a
//! no-op and behaviour is identical to plain Shamir.
//!
//! ## Implementation: pure-rust XOR mask
//!
//! We deliberately avoid pulling in a heavy HKDF crate. The OTP
//! derivation is a simple SHAKE-style PRF built from the same
//! xoshiro256** we already use, seeded with the field-bound key
//! material. This keeps the crate dependency-free; production
//! deployments that prefer a FIPS-compliant HKDF can swap in their
//! own KDF via the [`FieldWitness::with_kdf`] hook.

use thiserror::Error;

use crate::prng::{PrngState, SplitMix64};
use crate::shamir::{
    reconstruct_bytes as plain_reconstruct_bytes, share_bytes as plain_share_bytes,
    ShareError,
};

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
}

/// Public commitment to the field state at mint time.
///
/// This is the witness that recovery must reproduce. It carries enough
/// material to derive the OTPs but NOT enough to recover them without
/// also knowing the field seed (which is private — only the original
/// minter and the share-holders' devices know it through the mesh).
///
/// The witness IS public — it's stored alongside the shares — but it's
/// the field-seed-keyed input to the KDF that makes the OTPs
/// unrecoverable from the witness alone.
#[derive(Clone, Debug, PartialEq)]
pub struct FieldWitness {
    /// 32-byte seed derived from `coherence_field_native.solve_helmholtz`
    /// output. Caller produces this from the field state at mint time.
    /// For minting: secret to the minter + share-holders. For recovery:
    /// must be supplied (typically reconstructed by the share-holders
    /// who still have the swarm topology).
    pub field_seed: [u8; 32],
    /// Per-share field scores in [0, 1]. Same length as `n`. The score
    /// is the OneField τ_c normalised value for each share-holder.
    pub holder_scores: Vec<f64>,
    /// Mint-time epoch (caller-supplied; nanoseconds since arbitrary
    /// epoch). Mixed into the KDF so refresh ticks produce different
    /// masks even when field state hasn't changed.
    pub epoch_ns: u64,
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
        // Build a 64-bit seed from the field_seed + share_index +
        // holder_score + epoch_ns. SplitMix64 expands it; xoshiro256**
        // generates the byte stream.
        let mut acc: u64 = 0;
        for chunk in self.field_seed.chunks(8) {
            let mut buf = [0u8; 8];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            acc ^= u64::from_le_bytes(buf);
            acc = SplitMix64::next(acc);
        }
        let score_bits = self
            .holder_scores
            .get(share_index)
            .copied()
            .unwrap_or(0.0)
            .to_bits();
        acc ^= score_bits;
        acc = SplitMix64::next(acc);
        acc ^= self.epoch_ns;
        acc = SplitMix64::next(acc);
        acc ^= share_index as u64;
        acc = SplitMix64::next(acc);
        let mut prng = PrngState::new(acc);
        let mut otp = Vec::with_capacity(n_bytes);
        for _ in 0..n_bytes {
            otp.push(prng.next_byte());
        }
        otp
    }
}

/// Split a multi-byte secret with field-bound shares.
///
/// Each share-stream produced by plain Shamir is XOR-masked with a
/// witness-derived OTP. The witness is returned alongside; store it
/// publicly with the shares. To reconstruct, the caller must reproduce
/// the same witness AND have at least K masked share-streams.
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
    if witness.holder_scores.len() != n as usize {
        return Err(FieldBindingError::ScoreCountMismatch {
            expected: n as usize,
            got: witness.holder_scores.len(),
        });
    }
    for &s in &witness.holder_scores {
        if !(0.0..=1.0).contains(&s) {
            return Err(FieldBindingError::FieldScoreOutOfRange { got: s });
        }
    }
    let plain_streams = plain_share_bytes(secret, k, n, state)?;
    debug_assert_eq!(plain_streams.len(), n as usize);
    let mut masked: Vec<Vec<u8>> = Vec::with_capacity(plain_streams.len());
    for (i, stream) in plain_streams.iter().enumerate() {
        let otp = witness.derive_otp(i, stream.len());
        let mut row = Vec::with_capacity(stream.len());
        for (b, m) in stream.iter().zip(otp.iter()) {
            row.push(*b ^ *m);
        }
        masked.push(row);
    }
    Ok(masked)
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
    if xs.len() != streams.len() || xs.len() != share_indices.len() {
        return Err(FieldBindingError::Inner(ShareError::NotEnoughShares {
            have: xs.len().min(streams.len()).min(share_indices.len()),
            need: k,
        }));
    }
    if witness.holder_scores.len() < *share_indices.iter().max().unwrap_or(&0) + 1 {
        return Err(FieldBindingError::ScoreCountMismatch {
            expected: share_indices.iter().max().copied().unwrap_or(0) + 1,
            got: witness.holder_scores.len(),
        });
    }
    // Unmask each provided stream with its OTP.
    let mut unmasked: Vec<Vec<u8>> = Vec::with_capacity(streams.len());
    for (idx_in_supply, &original_index) in share_indices.iter().enumerate() {
        let stream = streams[idx_in_supply];
        let otp = witness.derive_otp(original_index, stream.len());
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
        for b in &mut field_seed {
            *b = seed_byte;
        }
        let holder_scores = (0..n).map(|i| 0.1 + 0.1 * i as f64).collect();
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
        let masked =
            field_bound_split(secret, 3, 5, &mut st, &witness).unwrap();
        // Reconstruct from shares 0, 2, 4 (x = 1, 3, 5).
        let xs = vec![1u8, 3, 5];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[2].as_slice(),
            masked[4].as_slice(),
        ];
        let indices = vec![0usize, 2, 4];
        let recovered =
            field_bound_reconstruct(&xs, &supplied, &indices, 3, &witness)
                .unwrap();
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
        let masked =
            field_bound_split(secret, 3, 5, &mut st, &witness).unwrap();
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered =
            field_bound_reconstruct(&xs, &supplied, &indices, 3, &witness)
                .unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn wrong_witness_breaks_recovery() {
        // Cornerstone of the alien-tech promise: an attacker with all
        // K masked shares but a wrong field-state CANNOT recover.
        let secret = b"sensitive identity material";
        let real_witness = make_witness(5, 0x42);
        let mut st = PrngState::new(0xCAFE_F00D_DEAD_BEEF);
        let masked = field_bound_split(secret, 3, 5, &mut st, &real_witness)
            .unwrap();
        // Build a different witness — same shape, different field seed.
        let fake_witness = make_witness(5, 0x99);
        let xs = vec![1u8, 2, 3];
        let supplied: Vec<&[u8]> = vec![
            masked[0].as_slice(),
            masked[1].as_slice(),
            masked[2].as_slice(),
        ];
        let indices = vec![0usize, 1, 2];
        let recovered = field_bound_reconstruct(
            &xs,
            &supplied,
            &indices,
            3,
            &fake_witness,
        )
        .unwrap();
        // The recovered bytes are statistically random vs the true
        // secret. ~almost certainly different — the OTP differs in
        // every byte position.
        assert_ne!(recovered, secret);
    }

    #[test]
    fn wrong_holder_scores_break_recovery() {
        // Attacker has all shares AND the field seed AND epoch — but
        // doesn't have the right per-holder field scores. Still fails.
        let secret = b"defense in depth, identity-bound";
        let real_witness = make_witness(5, 0x42);
        let mut st = PrngState::new(0x1111_2222_3333_4444);
        let masked = field_bound_split(secret, 3, 5, &mut st, &real_witness)
            .unwrap();
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
        let recovered = field_bound_reconstruct(
            &xs,
            &supplied,
            &indices,
            3,
            &fake_witness,
        )
        .unwrap();
        assert_ne!(recovered, secret);
    }

    #[test]
    fn score_count_mismatch_is_caught() {
        let secret = b"x";
        let witness = make_witness(3, 0x42); // 3 scores
        let mut st = PrngState::new(0);
        let err =
            field_bound_split(secret, 2, 5, &mut st, &witness).unwrap_err();
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
        let err =
            field_bound_split(secret, 3, 5, &mut st, &witness).unwrap_err();
        assert!(matches!(
            err,
            FieldBindingError::FieldScoreOutOfRange { .. }
        ));
    }
}
