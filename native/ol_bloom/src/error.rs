//! Errors for `ol_bloom`.

use thiserror::Error;

/// Errors produced by Bloom filter operations.
#[derive(Debug, Error)]
pub enum BloomError {
    /// Filter parameters are invalid (`m_bits == 0`, `k == 0`, etc).
    #[error("invalid bloom parameters: {0}")]
    InvalidParameters(&'static str),

    /// Encoded filter is shorter than the 12-byte header.
    #[error("encoded bloom too short: got {got} bytes, need at least {needed}")]
    EncodedTooShort {
        /// Length received.
        got: usize,
        /// Minimum length required.
        needed: usize,
    },

    /// Encoded filter's bit-array length doesn't match the declared `m_bits`.
    #[error(
        "bloom encoded length mismatch: header says m_bits={m_bits} (= {expected_bytes} bytes), got {got} bytes"
    )]
    LengthMismatch {
        /// `m_bits` from header.
        m_bits: u32,
        /// Bytes expected from header.
        expected_bytes: usize,
        /// Bytes actually received.
        got: usize,
    },

    /// Header reserved bytes were not zero.
    #[error("bloom header reserved bytes non-zero")]
    ReservedNonZero,

    /// Filter exceeds [`crate::filter::MAX_FILTER_BYTES`] (1 MiB on-wire cap).
    #[error("bloom filter too large: {got} bytes > max {max} bytes")]
    FilterTooLarge {
        /// Length received.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
}
