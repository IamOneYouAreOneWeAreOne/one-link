//! Error types for `ol_compress`.

use thiserror::Error;

/// Errors that may arise from compression / decompression.
#[derive(Debug, Error)]
pub enum CompressError {
    /// zstd encode/decode failure.
    #[error("zstd error: {0}")]
    Zstd(#[from] std::io::Error),

    /// lz4 decode failure (the lz4_flex error variant).
    #[error("lz4 decompress error: {0}")]
    Lz4Decompress(#[from] lz4_flex::block::DecompressError),

    /// The decompression output exceeded the caller's max_size cap.
    #[error("decompressed output exceeds max ({decompressed} bytes > max {max} bytes)")]
    OutputTooLarge {
        /// Bytes the decoder would have produced.
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
