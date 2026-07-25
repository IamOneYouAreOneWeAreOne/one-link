//! Errors for `ol_erasure`.

use thiserror::Error;

/// Errors produced by the chunk-level erasure codec.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum ErasureError {
    /// `k` / `m` parameters violate ADR-0016 limits.
    #[error("invalid (k, m): {0}")]
    InvalidParameters(#[from] ol_fec::FecError),

    /// `plaintext.is_empty()` — nothing to encode.
    #[error("empty plaintext cannot be striped")]
    EmptyPlaintext,

    /// Plaintext exceeds the bounded whole-chunk resource envelope.
    #[error("plaintext too large for one stripe: {got} > max {max}")]
    PlaintextTooLarge {
        /// Bytes supplied.
        got: usize,
        /// Maximum accepted bytes.
        max: usize,
    },

    /// `decode_stripe` was given a `present` vector with the wrong
    /// shape (must be exactly `k + m` slots).
    #[error("expected {expected} shard slots, got {got}")]
    PresentSlotCount {
        /// `k + m`.
        expected: usize,
        /// Number provided.
        got: usize,
    },

    /// A shard slot's role / index disagrees with the position it
    /// occupies in the `present` array. (We sanity-check this up front
    /// rather than silently miscomputing.)
    #[error("shard at position {pos}: descriptor reports role={role:?}/index={index}, expected role={expected_role:?}/index={expected_index}")]
    ShardDescriptorMismatch {
        /// 0-based position in the `present` array.
        pos: usize,
        /// Reported role.
        role: super::stripe::ShardRole,
        /// Reported index.
        index: u8,
        /// Expected role.
        expected_role: super::stripe::ShardRole,
        /// Expected index.
        expected_index: u8,
    },

    /// Present shards disagree on immutable stripe metadata.
    #[error("shard at position {pos} has inconsistent {field}")]
    ShardMetadataMismatch {
        /// Canonical slot containing the conflicting shard.
        pos: usize,
        /// Metadata field that disagreed.
        field: &'static str,
    },

    /// Declared plaintext length cannot fit in the decoded data shards.
    #[error("invalid declared plaintext length: {got} > decoded capacity {max}")]
    InvalidPlaintextLength {
        /// Declared plaintext bytes.
        got: u64,
        /// Maximum bytes represented by the data shards.
        max: usize,
    },

    /// Reconstructed plaintext does not match the authenticated stripe id.
    #[error("reconstructed plaintext does not match stripe_id")]
    StripeIdMismatch,
}
