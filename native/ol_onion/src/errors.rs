//! Typed errors for the onion-circuit layer.

use thiserror::Error;

/// Top-level error type for every public operation in `ol_onion`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OnionError {
    /// The encoded byte slice is too short for the expected struct.
    #[error("truncated frame: needed {needed} bytes, got {got}")]
    Truncated {
        /// Bytes the decoder still needed.
        needed: usize,
        /// Bytes actually available.
        got: usize,
    },

    /// The wire frame had unexpected length.
    #[error("frame size wrong: got {got}, expected {expected}")]
    BadFrameSize {
        /// Bytes received.
        got: usize,
        /// Bytes required.
        expected: usize,
    },

    /// The version byte didn't match.
    #[error("unsupported protocol version: got {got}, supported {supported}")]
    UnsupportedVersion {
        /// Version byte read off the wire.
        got: u8,
        /// Version this build accepts.
        supported: u8,
    },

    /// The AEAD verification step failed. Either the packet was
    /// tampered in flight, or this relay is not the intended next
    /// hop. Hard error — drop the packet.
    #[error("AEAD verification failed at peel")]
    AeadFail,

    /// The ephemeral X25519 public key in the packet decoded to a
    /// small-order point. Rejected to prevent confined-subgroup
    /// attacks.
    #[error("ephemeral X25519 public key is small-order")]
    SmallOrderPubkey,

    /// The circuit has too many hops for [`MAX_HOPS`].
    #[error("circuit has too many hops: got {got}, max {max}")]
    TooManyHops {
        /// Number of hops in the circuit.
        got: usize,
        /// Maximum supported.
        max: usize,
    },

    /// The payload would not fit in the packet's fixed payload area
    /// after AEAD overhead is accounted for.
    #[error("payload oversize: got {got}, max {max} after AEAD overhead")]
    PayloadOversize {
        /// Plaintext payload byte length.
        got: usize,
        /// Maximum permitted plaintext.
        max: usize,
    },

    /// Empty circuit passed to `build_onion`.
    #[error("circuit is empty (need at least one hop)")]
    EmptyCircuit,

    /// Internal invariant violation. Indicates a bug, not an attack.
    #[error("internal invariant violated: {0}")]
    Internal(&'static str),

    /// A Schnorr (or aggregate) signature did not verify mathematically.
    /// Distinct from `AeadFail` so callers can tell which primitive
    /// rejected the input.
    #[error("schnorr signature did not verify")]
    SignatureInvalid,
}

/// Result alias for crate operations.
pub type OnionResult<T> = Result<T, OnionError>;

#[allow(unused_imports)]
use crate::packet::MAX_HOPS;
