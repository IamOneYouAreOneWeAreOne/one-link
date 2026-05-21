//! Error types for `ol_radio_batcher`.

use thiserror::Error;

/// Errors that may arise from batcher operations.
///
/// Operations are designed to be infallible-by-design where possible.
/// These errors signal misuse (queue full) or invalid construction
/// (zero window).
#[derive(Debug, Error, Clone, PartialEq)]
pub enum BatcherError {
    /// Queue is at its `max_queue_size` limit. The caller must drain
    /// before enqueuing more.
    ///
    /// The selector's `safe_default` action when this happens is
    /// emit-now (treat as urgent_bypass): if we can't queue, we must
    /// transmit. The daemon translates this into a direct send.
    #[error("queue full: size={size}, max={max}")]
    QueueFull {
        /// Current queue size.
        size: usize,
        /// Configured maximum.
        max: usize,
    },

    /// DRX window was 0 — the batcher would never delay anything,
    /// which makes the scheduler trivially useless. Reject in the
    /// constructor.
    #[error("drx_window_ms must be > 0 (got {got})")]
    InvalidDrxWindow {
        /// The offending value.
        got: u32,
    },

    /// max_queue_size was 0 — would refuse every enqueue. Reject in
    /// the constructor.
    #[error("max_queue_size must be > 0 (got {got})")]
    InvalidMaxQueueSize {
        /// The offending value.
        got: usize,
    },
}
