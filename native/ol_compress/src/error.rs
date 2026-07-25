//! Error types for `ol_compress`.

use thiserror::Error;

/// Errors that may arise from compression / decompression.
#[derive(Debug, Error)]
pub enum CompressError {
    /// zstd encode/decode failure.
    #[error("zstd error: {0}")]
    Zstd(#[from] std::io::Error),

    /// lz4 decode failure (the `lz4_flex` error variant).
    #[error("lz4 decompress error: {0}")]
    Lz4Decompress(#[from] lz4_flex::block::DecompressError),

    /// An uncompressed input exceeded the process-wide safety ceiling.
    #[error("compression input exceeds max ({actual} bytes > max {max} bytes)")]
    InputTooLarge {
        /// Actual input length.
        actual: usize,
        /// Process-wide maximum input length.
        max: usize,
    },

    /// A tagged compressed payload exceeded the process-wide wire ceiling.
    #[error("compressed payload exceeds max ({actual} bytes > max {max} bytes)")]
    PayloadTooLarge {
        /// Actual payload length.
        actual: usize,
        /// Process-wide maximum payload length.
        max: usize,
    },

    /// The decompression output exceeded the caller's `max_size` cap.
    #[error("decompressed output exceeds max ({decompressed} bytes > max {max} bytes)")]
    OutputTooLarge {
        /// Bytes observed or declared by the decoder.  For streaming codecs,
        /// this is the first byte beyond the limit rather than the full bomb
        /// size, because decoding stops immediately at the boundary.
        decompressed: usize,
        /// Caller's max-size cap.
        max: usize,
    },

    /// Unknown algorithm tag on the wire.
    #[error("unknown algorithm tag: {tag}")]
    UnknownTag {
        /// The offending tag byte.
        tag: u8,
    },

    /// Payload too short to carry the codec tag header.
    #[error("payload too short for codec tag: {len} bytes")]
    PayloadTooShort {
        /// Actual length received.
        len: usize,
    },
}
