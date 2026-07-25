//! Error types for `ol_align`.

use thiserror::Error;

/// Errors that may arise computing the alignment trust score.
///
/// Most callers do not need to catch these — the function rejects
/// nonsense inputs (negative distance, non-finite staleness, zero L)
/// rather than producing silently-wrong trust values.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AlignError {
    /// `hop_distance` was negative. Hop distance is a non-negative count.
    #[error("hop_distance must be >= 0 (got {got})")]
    NegativeHopDistance {
        /// The offending value.
        got: f32,
    },

    /// `staleness_seconds` was negative. Time-since-last-contact is >= 0.
    #[error("staleness_seconds must be >= 0 (got {got})")]
    NegativeStaleness {
        /// The offending value.
        got: f32,
    },

    /// One of the inputs was NaN or infinite. The Gaussian is defined for
    /// finite reals only.
    #[error("inputs must be finite (got hop={hop}, staleness={staleness}, L={l})")]
    NonFinite {
        /// The hop-distance input at the point of failure.
        hop: f32,
        /// The staleness input at the point of failure.
        staleness: f32,
        /// The `L_session` input at the point of failure.
        l: f32,
    },

    /// `L_session` was zero or negative — divide-by-zero in the kernel.
    #[error("L_session must be > 0 (got {got})")]
    InvalidLSession {
        /// The offending value.
        got: f32,
    },
}
