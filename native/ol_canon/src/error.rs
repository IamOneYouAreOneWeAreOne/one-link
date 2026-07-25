//! Typed encode + decode failure modes for the canonical codec.

use thiserror::Error;

/// Errors the encoder can surface. The encoder is infallible for the
/// in-memory `Vec<u8>` path; the only knob that produces errors is the
/// optional [`crate::CanonEncoder::with_limit`] cap, which lets
/// callers refuse to allocate more than a budget allows.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncodeError {
    /// `with_limit(N)` was set and this write would push the buffer
    /// past N bytes.
    #[error("encoder buffer would exceed configured limit")]
    BufferOverflow,

    /// A requested write overflowed the platform's addressable length.
    #[error("encoder length arithmetic overflow")]
    SizeOverflow,

    /// The allocator refused the requested capacity reservation.
    #[error("encoder could not reserve requested capacity")]
    AllocationFailed,
}

/// Errors the decoder can return. All variants leave the decoder's
/// read position unchanged so the caller can inspect the error +
/// re-frame if needed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended mid-value. Includes the byte offset where the
    /// truncation was detected so log lines pinpoint the breakage.
    #[error("unexpected end of input at byte {0}")]
    UnexpectedEof(usize),

    /// Wire byte didn't map to any known [`crate::TypeTag`]. Carries
    /// the raw byte for debug output. Decoders must reject this —
    /// silently skipping an unknown tag would let an attacker hide
    /// extra bytes in the frame.
    #[error("unknown type tag: 0x{0:02X}")]
    UnknownTag(u8),

    /// LEB128 varint exceeded 10 bytes (max for a u64). Indicates
    /// either a corrupt input or a malicious oversize-varint attempt.
    #[error("varint too long (>10 bytes); corrupt input")]
    VarintTooLong,

    /// Caller expected one tag but the next byte was a different
    /// (valid) tag. Carries both for clear diagnostics.
    #[error("expected tag {expected:?}, found {found:?}")]
    TagMismatch {
        /// The tag the caller expected to see.
        expected: crate::TypeTag,
        /// The tag actually present on the wire.
        found: crate::TypeTag,
    },

    /// UTF-8 string field contained invalid UTF-8 bytes.
    #[error("invalid UTF-8 in string field")]
    InvalidUtf8,

    /// Length-prefixed field claimed a length larger than the
    /// remaining buffer. Indicates a corrupt or malicious input.
    #[error("length prefix {claimed} exceeds remaining {remaining}")]
    LengthOverflow {
        /// Length the wire frame claimed.
        claimed: u64,
        /// Bytes actually still available.
        remaining: usize,
    },

    /// A decoded integer cannot be represented by the target platform/type.
    #[error("wire integer {value} does not fit {target}")]
    NumericOverflow {
        /// Value found on the wire.
        value: u64,
        /// Destination integer type.
        target: &'static str,
    },

    /// A collection header claims more values than can possibly fit in the
    /// remaining encoded bytes (every canonical value has at least a tag).
    #[error("collection count {claimed} exceeds structural maximum {maximum}")]
    CollectionTooLarge {
        /// Element or field count found on the wire.
        claimed: u64,
        /// Maximum possible count given the remaining frame bytes.
        maximum: usize,
    },
}
