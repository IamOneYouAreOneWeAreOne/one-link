//! Errors that arise constructing a [`Context`](crate::Context).

use thiserror::Error;

/// Errors building a [`Context`](crate::Context) from raw inputs.
///
/// Decision logic itself does NOT return errors — every `Decide` impl
/// must produce an action for every context. These errors arise only
/// at the Context-construction boundary (e.g. a daemon adapter feeds
/// in an unknown string label).
#[derive(Debug, Error, Clone, PartialEq)]
pub enum DecideError {
    /// `observed_loss` was outside [0, 1] or non-finite.
    #[error("observed_loss must be in [0, 1] (got {got})")]
    InvalidLoss {
        /// The offending value.
        got: f32,
    },

    /// `pattern_strength` was outside [0, 1] or non-finite.
    #[error("pattern_strength must be in [0, 1] (got {got})")]
    InvalidPatternStrength {
        /// The offending value.
        got: f32,
    },

    /// An enum label didn't match any known variant.
    #[error("unknown {field} label: {got:?} (expected {expected})")]
    UnknownLabel {
        /// Which field was being parsed.
        field: &'static str,
        /// The string that didn't parse.
        got: String,
        /// Human-readable list of accepted labels.
        expected: &'static str,
    },
}
