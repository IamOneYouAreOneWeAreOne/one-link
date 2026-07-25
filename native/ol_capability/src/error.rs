//! Errors for `ol_capability`.

use thiserror::Error;

/// Errors produced by capability operations.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum CapError {
    /// HMAC signature does not match the recomputed chain. Caller
    /// must reject the cap.
    #[error("signature mismatch (cap was forged or root key wrong)")]
    SignatureMismatch,

    /// A caveat rejected the context.
    #[error("caveat {idx} ({reason}) rejected the context")]
    CaveatRejected {
        /// Index of the rejecting caveat in the chain.
        idx: usize,
        /// Static reason description.
        reason: &'static str,
    },

    /// Decoded wire bytes had an unrecognized caveat tag byte.
    #[error("unknown caveat tag: {tag}")]
    UnknownCaveat {
        /// Tag byte received.
        tag: u8,
    },

    /// Wire format is structurally invalid.
    #[error("malformed capability wire: {reason}")]
    Malformed {
        /// What was wrong.
        reason: &'static str,
    },

    /// A locally constructed capability or caveat exceeds a protocol
    /// resource bound.  This is distinct from malformed peer input so API
    /// callers can correct their request without treating it as an attack.
    #[error("capability resource limit exceeded: {reason}")]
    ResourceLimit {
        /// The bound that was exceeded.
        reason: &'static str,
    },
}
