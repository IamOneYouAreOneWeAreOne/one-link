use thiserror::Error;

pub type Result<T> = std::result::Result<T, HwKeyError>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HwKeyError {
    #[error("key not found: {0}")]
    NotFound(String),

    #[error("TOFU violation: stored public key does not match presented key")]
    TofuMismatch,

    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    #[error("attestation failed: {0}")]
    AttestationFailed(String),

    #[error("io error: {0}")]
    Io(String),

    #[error("invalid public key encoding")]
    InvalidKeyEncoding,

    #[error("invalid key label: {0}")]
    InvalidLabel(&'static str),

    #[error("key-store state is unavailable because its lock was poisoned")]
    StateUnavailable,

    #[error("key-store capacity exhausted")]
    CapacityExceeded,
}
