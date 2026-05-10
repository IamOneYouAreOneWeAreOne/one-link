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
}
