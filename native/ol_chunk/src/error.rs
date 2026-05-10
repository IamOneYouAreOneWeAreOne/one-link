//! Error types for `ol_chunk`.
//!
//! Pyo3 bindings in `one_link_native` map these to Python exceptions per
//! [ADR-0008](../../../docs/decisions/0008-ffi-contract.md).

use thiserror::Error;

/// Errors produced by chunk-layer operations.
#[derive(Debug, Error)]
pub enum ChunkError {
    /// CDC scan was given a buffer that is too small to chunk safely.
    /// This is not necessarily an error in itself (a 0-byte buffer is
    /// trivially a single empty chunk) but it can indicate a caller bug.
    #[error("buffer too small for CDC scan: got {got} bytes, minimum {min}")]
    BufferTooSmall {
        /// Buffer length received.
        got: usize,
        /// Minimum length required (typically the CDC min chunk size).
        min: usize,
    },

    /// CDC parameters violate FastCDC invariants (min < avg < max,
    /// all powers-of-two-aligned).
    #[error("invalid CDC parameters: {0}")]
    InvalidParameters(&'static str),

    /// AEAD frame size requested is incompatible with the chunk size
    /// distribution. Frame size must divide the maximum chunk size cleanly.
    #[error("AEAD frame size {frame} incompatible with chunk size {chunk}")]
    FrameSizeMismatch {
        /// Frame size in bytes.
        frame: usize,
        /// Chunk size in bytes.
        chunk: usize,
    },
}
