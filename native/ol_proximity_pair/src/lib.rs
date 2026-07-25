//! Research primitives for a future channel-reciprocity pairing factor.
//!
//! This crate is **not a shipped proximity-authentication protocol**. It has
//! no radio/probe acquisition, authenticated interactive reconciliation,
//! min-entropy estimator, leakage accounting, or hardware validation. Its
//! current single-flip and permutation drivers do not guarantee that two
//! noisy observations converge to identical bits. Outputs are therefore
//! unconfirmed candidates and must never be used directly as authentication
//! decisions or traffic keys.
//!
//! ## Pipeline
//!
//! 1. **Probe** (out-of-scope for this crate): each side collects a
//!    vector of physical observations. `OneField` uses RF channel
//!    measurements; in One Link without SDR hardware we use `WiFi`
//!    SSID/RSSI fingerprints + mDNS broadcasts + BLE advertisements,
//!    plus timing observations. **What** to probe is the daemon's job;
//!    this crate operates on the resulting observation bytes.
//!
//! 2. **Quantize** ([`quantize::quantize_observations`]): map the
//!    continuous observation vector to a bit string via median
//!    threshold + guard band. Both sides produce nearly-identical
//!    bit strings; remaining errors are corrected in stage 3.
//!
//! 3. **Experimental reconcile** ([`reconcile::reconcile_with_syndrome`]):
//!    one side sends block parities. The current implementation aligns those
//!    parities by flipping a fixed position; it cannot locate arbitrary errors
//!    and is not the interactive CASCADE protocol.
//!
//! 4. **Candidate extraction** ([`amplify::privacy_amplify`]): BLAKE3
//!    compresses the candidate bits to 256 bits. This is a computational hash,
//!    not a proof of input entropy or information-theoretic secrecy.
//!
//! ## What this crate provides
//!
//! Pure-Rust pipeline. No I/O, no radio hardware. The daemon-side
//! integration (`WiFi` scanner, mDNS sniffer, BLE advertiser query)
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
    /// The candidate bit string is too short for the configured conservative
    /// size policy after accounting for disclosed parity bits. Passing this
    /// check does not establish min-entropy.
    #[error("not enough candidate input for {requested} output bits: input {input_bits} bits less {disclosed_bits} disclosed parity bits")]
    InsufficientInputBits {
        /// Output width requested by the extractor.
        requested: usize,
        /// Candidate bits supplied to the extractor.
        input_bits: usize,
        /// Public parity bits disclosed by this one-pass helper.
        disclosed_bits: usize,
    },
}

/// Run the current non-interactive research pipeline and return an
/// **unconfirmed candidate**.
///
/// Caller supplies:
///   - `my_observations`: this side's probe-result byte vector
///   - `peer_syndrome`: parity bits the peer sent over the public
///     bootstrap channel (i.e., they ran `block_syndrome` on their
///     quantized bits and shipped the result to us)
///   - `config`: tunables
///
/// The returned bytes are not a Factor-2 secret and are not safe as a traffic
/// key or authentication decision. They may diverge even for similar inputs.
/// A complete protocol must add aligned probing, real interactive
/// reconciliation, conservative entropy estimation/leakage accounting, and
/// explicit peer key confirmation. The `ol_pair_qr` state machine provides
/// equality confirmation for externally supplied candidates, but does not
/// establish their physical provenance or entropy.
///
/// # Errors
/// - [`PairError::ObservationTooShort`] when input is below the
///   configured minimum
/// - [`PairError::InsufficientInputBits`] when the candidate is below the
///   conservative size floor after public parity disclosure
pub fn derive_unconfirmed_candidate(
    my_observations: &[u8],
    peer_syndrome: &[u8],
    config: &PipelineConfig,
) -> Result<[u8; AMPLIFIED_KEY_BYTES], PairError> {
    let quantized = quantize_observations(my_observations, &config.quantize)?;
    let reconciled = reconcile_with_syndrome(&quantized, peer_syndrome, config.syndrome_block_bits);
    // Syndrome leaks one bit per syndrome byte. Final key has
    // AMPLIFIED_KEY_BYTES*8 = 256 bits. We need at least that much
    // residual entropy after leakage.
    let disclosed_bits = peer_syndrome.len(); // one parity bit per byte
    let key_bits = AMPLIFIED_KEY_BYTES * 8;
    if reconciled.len() < disclosed_bits + key_bits {
        return Err(PairError::InsufficientInputBits {
            requested: key_bits,
            input_bits: reconciled.len(),
            disclosed_bits,
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
    /// leakage but more reconciliation rounds. `OneField` uses 8.
    pub syndrome_block_bits: usize,
    /// Salt mixed into BLAKE3 candidate extraction. Must be
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
