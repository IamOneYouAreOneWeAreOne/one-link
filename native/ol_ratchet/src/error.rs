//! Errors for `ol_ratchet`.

use thiserror::Error;

/// Errors from ratchet operations.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum RatchetError {
    /// Asked the chain to fast-forward backward in time (step `i` <
    /// current `step`).
    #[error("cannot rewind chain: requested step {requested} but current step is {current}")]
    Rewind {
        /// Step requested.
        requested: u64,
        /// Current chain step.
        current: u64,
    },

    /// Skipped-key store overflowed its capacity. A peer is sending
    /// extremely out-of-order chunks (or trying to exhaust memory).
    #[error("skipped-key store is full at capacity {cap}; refusing to add more")]
    SkippedStoreFull {
        /// Configured cap.
        cap: usize,
    },

    /// A skipped key was requested but not found (either expired,
    /// never seen, or never derived).
    #[error("no skipped key for step {step}")]
    SkippedKeyNotFound {
        /// Step the caller asked for.
        step: u64,
    },

    /// Fast-forward / peek requested a step too far ahead of the
    /// current chain position. Closes the audit L11 (May 2026)
    /// DoS where a malicious peer could ship `seq = u64::MAX` and
    /// force the receiver into an indefinite BLAKE3 derive loop.
    #[error(
        "skip too large: from step {from} requested {target} (delta {delta}, max {max})"
    )]
    SkipTooLarge {
        /// Current chain step.
        from: u64,
        /// Requested target step.
        target: u64,
        /// Number of steps the caller asked us to advance/peek across.
        delta: u64,
        /// Maximum skip we allow in one operation.
        max: u64,
    },
}
