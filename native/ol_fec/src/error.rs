//! Errors for `ol_fec`.

use thiserror::Error;

/// Errors produced by the Reed-Solomon codec.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum FecError {
    /// `k` or `m` is zero, or `k + m > 255` (GF(2^8) has 256 elements;
    /// distinct shard tags can't exceed that).
    #[error("invalid (k, m) parameters: k={k}, m={m} — require k>=1, m>=1, k+m<=255")]
    InvalidParameters {
        /// Number of data shards requested.
        k: usize,
        /// Number of parity shards requested.
        m: usize,
    },

    /// The caller supplied a wrong number of data shards to `encode`.
    #[error("expected {expected} data shards, got {got}")]
    DataShardCount {
        /// `k` from the codec.
        expected: usize,
        /// Number provided by the caller.
        got: usize,
    },

    /// Data shards are not all the same length.
    #[error(
        "data shards must be equal-length; got at least one length={len} differing from {expected}"
    )]
    InconsistentShardLen {
        /// First shard's length (the reference).
        expected: usize,
        /// First differing shard's length.
        len: usize,
    },

    /// A single shard exceeds the codec's per-shard resource envelope.
    #[error("shard too large: {got} bytes > max {max} bytes")]
    ShardTooLarge {
        /// Requested or received shard length.
        got: usize,
        /// Maximum shard length.
        max: usize,
    },

    /// The complete `(k + m) * shard_len` stripe exceeds the bounded
    /// working-set envelope.
    #[error("FEC stripe working set too large: {got} bytes > max {max} bytes")]
    WorkingSetTooLarge {
        /// Computed aggregate bytes, or `usize::MAX` on overflow.
        got: usize,
        /// Maximum aggregate bytes.
        max: usize,
    },

    /// `decode` was given the wrong total number of `present` slots.
    #[error("expected {expected} present slots, got {got}")]
    PresentSlotCount {
        /// `k + m`.
        expected: usize,
        /// Number provided.
        got: usize,
    },

    /// `decode` was given fewer than `k` present shards.
    #[error("not enough shards to decode: need {needed}, got {got}")]
    InsufficientShards {
        /// `k` from the codec.
        needed: usize,
        /// Number of `Some(...)` entries in `present`.
        got: usize,
    },

    /// An allegedly Cauchy-derived recovery matrix was singular.
    #[error("recovery matrix is singular or internally inconsistent")]
    SingularMatrix,
}
