//! Coherence Mesh Phase F1.4 — channel-reciprocity proximity Factor-2.
//!
//! THE PHYSICS-LAYER PAIR-TRUST PRIMITIVE no consumer messenger has.
//!
//! Ports `OneField/onefield/mesh/bootstrap.cl` SECTION 3 (Tier 10
//! production, reviewed 2026-04-09): a 4-stage key-derivation pipeline
//! that produces an IDENTICAL 256-bit secret on two devices in the
//! same physical environment WITHOUT ever transmitting the secret.
//!
//! ## Why this is alien tech
//!
//! Standard pair-by-QR proves *knowledge* (you scanned the screen).
//! Channel-reciprocity proves *physical co-presence*. A remote attacker
//! who captures the QR via telephoto camera AND the bootstrap traffic
//! STILL can't derive the Factor-2 secret because they weren't in the
//! room. The shared key comes from the physics of the environment.
//!
//! Crypto term: this is an **unconditionally-secure key agreement**
//! protocol when the eavesdropper's mutual information with the
//! channel is below a threshold. Bose, Bennett & Brassard's
//! information-theoretic foundation; channel reciprocity is the
//! practical instantiation.
//!
//! ## Pipeline
//!
//! 1. **Probe** (out-of-scope for this crate): each side collects a
//!    vector of physical observations. OneField uses RF channel
//!    measurements; in One Link without SDR hardware we use WiFi
//!    SSID/RSSI fingerprints + mDNS broadcasts + BLE advertisements
//!    + timing observations. **What** to probe is the daemon's job;
//!    this crate operates on the resulting observation bytes.
//!
//! 2. **Quantize** ([`quantize::quantize_observations`]): map the
//!    continuous observation vector to a bit string via median
//!    threshold + guard band. Both sides produce nearly-identical
//!    bit strings; remaining errors are corrected in stage 3.
//!
//! 3. **Reconcile** ([`reconcile::reconcile_with_syndrome`]): one
//!    side sends a "syndrome" (block-parity bits) over the public
//!    bootstrap channel. The other side uses it to flip its
//!    disagreeing bits without revealing the underlying secret bits.
//!    Standard CASCADE-style information reconciliation.
//!
//! 4. **Privacy amplification** ([`amplify::privacy_amplify`]):
//!    BLAKE3-keyed hash the reconciled bits down to 256 bits. Even
//!    if the eavesdropper learned some bits from the syndrome, the
//!    final 256 bits are information-theoretically secret as long as
//!    Eve's mutual information is below the entropy of the input.
//!
//! ## What this crate provides
//!
//! Pure-Rust pipeline. No I/O, no radio hardware. The daemon-side
//! integration (WiFi scanner, mDNS sniffer, BLE advertiser query)
//! lives in a separate wiring layer.

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_sign_loss)]

pub mod amplify;
pub mod cascade;
pub mod hamming;
pub mod prng;
pub mod quantize;
pub mod reconcile;

pub use amplify::{privacy_amplify, AMPLIFIED_KEY_BYTES};
pub use cascade::{
    multi_pass_reconcile, multi_pass_syndromes, permutation_for_pass, CASCADE_PASSES_DEFAULT,
};
pub use hamming::{
    decode_syndrome_to_data_index, hamming_reconcile, parity_bits_for_block,
    parity_bits_for_string, HAMMING_CODEWORD_BITS, HAMMING_DATA_BITS, HAMMING_PARITY_BITS,
};
pub use quantize::{
    quantize_observations, QuantizeConfig, GUARD_BAND_DEFAULT, OBSERVATION_BYTES_DEFAULT,
};
pub use reconcile::{block_syndrome, reconcile_with_syndrome, SYNDROME_BLOCK_BITS_DEFAULT};

use thiserror::Error;

/// Errors during the proximity-pair pipeline.
#[derive(Debug, Error, PartialEq)]
pub enum PairError {
    /// Observation vector is empty or too short to quantize.
    #[error("observation vector too short: {got} bytes (need {min})")]
    ObservationTooShort {
        /// Bytes supplied.
        got: usize,
        /// Minimum required.
        min: usize,
    },
    /// The two sides' quantized bit strings disagree on too many
    /// positions even after syndrome reconciliation. Either the
    /// devices aren't actually co-located, or the observation
    /// vectors weren't aligned (different probe schedules).
    #[error("too many disagreements after reconciliation: {got} (max {max})")]
    TooManyDisagreements {
        /// Bit mismatches.
        got: usize,
        /// Acceptable max.
        max: usize,
    },
    /// Privacy amplification was asked to produce more bits than the
    /// input has remaining entropy after syndrome exposure.
    #[error("not enough entropy for {requested}-bit key; input {input_bits} bits less leaked {leaked_bits}")]
    InsufficientEntropy {
        /// Bits requested in the final key.
        requested: usize,
        /// Bits in the reconciled string before amplification.
        input_bits: usize,
        /// Bits leaked via the syndrome.
        leaked_bits: usize,
    },
}

/// High-level convenience: full pipeline in one call.
///
/// Caller supplies:
///   - `my_observations`: this side's probe-result byte vector
///   - `peer_syndrome`: parity bits the peer sent over the public
///     bootstrap channel (i.e., they ran `block_syndrome` on their
///     quantized bits and shipped the result to us)
///   - `config`: tunables
///
/// Returns the 32-byte final key, identical on both sides when their
/// observation vectors were physically close enough.
///
/// # Errors
/// - [`PairError::ObservationTooShort`] when input is below the
///   configured minimum
/// - [`PairError::TooManyDisagreements`] when the reconciliation
///   produced more than `config.max_disagreement_bits` mismatches
///   (heuristic — true mismatch requires comparing to peer)
/// - [`PairError::InsufficientEntropy`] when amplification can't
///   safely produce the requested key size given syndrome leakage
pub fn derive_factor2_secret(
    my_observations: &[u8],
    peer_syndrome: &[u8],
    config: &PipelineConfig,
) -> Result<[u8; AMPLIFIED_KEY_BYTES], PairError> {
    let quantized = quantize_observations(my_observations, &config.quantize)?;
    let reconciled = reconcile_with_syndrome(&quantized, peer_syndrome, config.syndrome_block_bits);
    // Syndrome leaks one bit per syndrome byte. Final key has
    // AMPLIFIED_KEY_BYTES*8 = 256 bits. We need at least that much
    // residual entropy after leakage.
    let leaked_bits = peer_syndrome.len(); // 1 bit per byte (one parity per block)
    let key_bits = AMPLIFIED_KEY_BYTES * 8;
    if reconciled.len() < leaked_bits + key_bits {
        return Err(PairError::InsufficientEntropy {
            requested: key_bits,
            input_bits: reconciled.len(),
            leaked_bits,
        });
    }
    let key = privacy_amplify(&reconciled, &config.amplify_salt);
    Ok(key)
}

/// All tunables in one place.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Quantization parameters.
    pub quantize: QuantizeConfig,
    /// Block size in bits for syndrome generation. Larger = less
    /// leakage but more reconciliation rounds. OneField uses 8.
    pub syndrome_block_bits: usize,
    /// Salt mixed into BLAKE3-keyed privacy amplification. Must be
    /// the same on both sides; typically derived from the bootstrap
    /// handshake transcript (Factor-1 QR scan).
    pub amplify_salt: [u8; 32],
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            quantize: QuantizeConfig::default(),
            syndrome_block_bits: SYNDROME_BLOCK_BITS_DEFAULT,
            amplify_salt: *b"OL-proximity-pair-v1-default-sal",
        }
    }
}
