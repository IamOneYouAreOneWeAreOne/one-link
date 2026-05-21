//! Error types for `ol_selector`.

use thiserror::Error;

/// Errors that may arise inside the selector. Decision logic itself
/// must always produce a [`Decision`](crate::Decision); these errors
/// only surface from construction / configuration boundaries.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum SelectorError {
    /// Caller requested a non-standard onion-hop count that's not one
    /// of the supported tiers (1, 3, or 5).
    #[error("onion_hops must be 1, 3, or 5 (got {got})")]
    UnsupportedOnionHops {
        /// The requested hop count.
        got: u8,
    },
}
