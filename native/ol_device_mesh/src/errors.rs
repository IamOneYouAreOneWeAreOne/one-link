//! Error types for the device-mesh layer.

use thiserror::Error;

/// Result alias used across the crate.
pub type DeviceMeshResult<T> = Result<T, DeviceMeshError>;

/// Typed error surface for device-mesh operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceMeshError {
    /// Wrong byte length supplied to a parse/from_bytes function.
    #[error("wrong length: expected {expected}, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Day index advanced past the configured chain horizon.
    #[error("ratchet day index {got} exceeds chain horizon {max}")]
    RatchetExhausted {
        /// Day requested.
        got: u64,
        /// Maximum allowed day index for this chain.
        max: u64,
    },
    /// Subkey attestation signature verification failed.
    #[error("subkey attestation failed cryptographic verification")]
    AttestationVerifyFail,
    /// Liveness proof signature verification failed.
    #[error("liveness proof failed cryptographic verification")]
    LivenessVerifyFail,
    /// Liveness proof outside the allowed clock-skew window.
    #[error("liveness proof timestamp outside skew window (got {got_unix}, now {now_unix}, max skew {max_skew_secs})")]
    LivenessOutOfWindow {
        /// Proof's claimed unix-seconds timestamp.
        got_unix: u64,
        /// Verifier's current unix-seconds clock.
        now_unix: u64,
        /// Maximum allowed clock skew in seconds.
        max_skew_secs: u64,
    },
    /// Hardware wrapper rejected the supplied ciphertext (unwrap failed).
    #[error("hardware wrapper unwrap failed (likely wrong slot or tampered ciphertext)")]
    HardwareUnwrapFail,
    /// Underlying PQ-hybrid signature error bubbled up from `ol_pqsig`.
    #[error("pqsig error: {0}")]
    PqSig(String),
}

impl From<ol_pqsig::PqSigError> for DeviceMeshError {
    fn from(e: ol_pqsig::PqSigError) -> Self {
        Self::PqSig(format!("{e}"))
    }
}
