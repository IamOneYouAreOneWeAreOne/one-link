//! Error types for `ol_aead`.

use thiserror::Error;

/// Errors produced by AEAD operations.
///
/// All variants are non-information-leaking: a remote attacker observing
/// only the variant kind cannot distinguish "your padding was wrong" from
/// "your tag was wrong" because both surface as the generic
/// [`AeadError::Authentication`]. This matches `RustCrypto`'s
/// `aead::Error` opacity policy and avoids padding-oracle analogues.
#[derive(Debug, Error)]
pub enum AeadError {
    /// AEAD authentication failed: the tag did not verify against the
    /// ciphertext + AAD + key + nonce. This includes any tampering of
    /// the ciphertext, AAD, or key, or a nonce mismatch.
    ///
    /// Returned to the caller without detail to avoid leaking the
    /// failure mode to a remote attacker.
    #[error("AEAD authentication failed")]
    Authentication,

    /// The provided ciphertext buffer doesn't match the expected layout
    /// for the given plaintext length: it must be
    /// `plaintext_len + frame_count * AEAD_TAG_LEN`.
    #[error("invalid ciphertext length: expected {expected}, got {got}")]
    InvalidCiphertextLength {
        /// Expected length in bytes.
        expected: usize,
        /// Length received.
        got: usize,
    },

    /// The plaintext buffer is too large for the engine's maximum chunk
    /// size (256 KiB per ADR-0001). Larger inputs must be re-chunked.
    #[error("plaintext too large for a single chunk: got {got}, max {max}")]
    PlaintextTooLarge {
        /// Length received.
        got: usize,
        /// Maximum chunk size.
        max: usize,
    },

    /// A single random-access frame exceeds the 16 KiB frame envelope.
    #[error("frame too large: got {got}, max {max}")]
    FrameTooLarge {
        /// Frame bytes received.
        got: usize,
        /// Maximum frame bytes.
        max: usize,
    },

    /// A parallel batch contains too many chunks.
    #[error("AEAD batch too large: got {got} chunks, max {max}")]
    BatchTooLarge {
        /// Number of chunks requested.
        got: usize,
        /// Maximum chunks in one call.
        max: usize,
    },

    /// A parallel batch exceeds the aggregate input-byte budget.
    #[error("AEAD batch input too large: got {got} bytes, max {max}")]
    BatchBytesTooLarge {
        /// Aggregate bytes, or `usize::MAX` on arithmetic overflow.
        got: usize,
        /// Maximum aggregate bytes.
        max: usize,
    },

    /// AAD (the `chunk_id`) was not exactly 32 bytes.
    #[error("AAD must be exactly 32 bytes (BLAKE3 chunk_id), got {got}")]
    InvalidAad {
        /// Length received.
        got: usize,
    },

    /// Frame index overflowed u32 (more than 4 billion frames in one
    /// chunk — unreachable for chunk sizes ≤ 256 KiB but checked anyway).
    #[error("frame index {got} exceeds u32::MAX")]
    FrameIndexOverflow {
        /// Index that overflowed.
        got: u64,
    },

    /// Frame index is out of range for the given chunk plaintext length.
    #[error("frame index {got} out of range for {frame_count} frames")]
    FrameIndexOutOfRange {
        /// Index requested.
        got: usize,
        /// Total frames in the chunk.
        frame_count: usize,
    },
}
