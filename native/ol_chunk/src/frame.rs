//! AEAD frame layout constants per [ADR-0002](../../../docs/decisions/0002-aead-frame.md).
//!
//! A "chunk" (the CDC output, 8-256 KiB per [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md))
//! is the deduplication unit. A "frame" (16 KiB plaintext + 16 byte AEAD
//! tag) is the encryption unit. One chunk holds one or more sequential
//! frames so FUSE random-access reads decrypt only the frame containing
//! the requested offset, capping read amplification at 16-32 KiB.
//!
//! This module defines only the layout constants and pure functions
//! computing frame counts. AEAD encrypt/decrypt itself lives in
//! `ol_aead`. Keeping the constants in `ol_chunk` lets the chunk store
//! validate frame counts without depending on the AEAD crate.

/// AEAD frame plaintext payload size in bytes (16 KiB).
///
/// Joint with the chunk-size distribution from [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md):
/// a 64 KiB mean chunk holds 4 frames; max 256 KiB chunk holds 16 frames.
pub const AEAD_FRAME_PLAINTEXT_LEN: usize = 16 * 1024;

/// AEAD authentication tag length in bytes.
///
/// 128 bits for both AES-256-GCM and ChaCha20-Poly1305 per [ADR-0002](../../../docs/decisions/0002-aead-frame.md).
/// Truncation savings are not worth the security loss.
pub const AEAD_TAG_LEN: usize = 16;

/// Compute the number of AEAD frames needed to cover a plaintext chunk
/// of `chunk_plaintext_len` bytes.
///
/// Rounds up: a chunk of 16,385 bytes needs 2 frames (16,384 + 1 byte).
/// The trailing frame may be shorter than `AEAD_FRAME_PLAINTEXT_LEN`.
#[inline]
#[must_use]
pub const fn frame_count_for_plaintext(chunk_plaintext_len: usize) -> usize {
    if chunk_plaintext_len == 0 {
        return 0;
    }
    chunk_plaintext_len.div_ceil(AEAD_FRAME_PLAINTEXT_LEN)
}

/// Compute the on-wire ciphertext length for a chunk: plaintext + per-frame
/// AEAD tags.
#[inline]
#[must_use]
pub const fn ciphertext_len_for_plaintext(chunk_plaintext_len: usize) -> usize {
    chunk_plaintext_len + frame_count_for_plaintext(chunk_plaintext_len) * AEAD_TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_count_zero_for_empty_chunk() {
        assert_eq!(frame_count_for_plaintext(0), 0);
    }

    #[test]
    fn frame_count_one_for_subframe_chunk() {
        assert_eq!(frame_count_for_plaintext(1), 1);
        assert_eq!(frame_count_for_plaintext(AEAD_FRAME_PLAINTEXT_LEN), 1);
    }

    #[test]
    fn frame_count_rounds_up() {
        assert_eq!(frame_count_for_plaintext(AEAD_FRAME_PLAINTEXT_LEN + 1), 2);
        // 64 KiB mean chunk = 4 frames per ADR-0002.
        assert_eq!(frame_count_for_plaintext(64 * 1024), 4);
        // 256 KiB max chunk = 16 frames per ADR-0002.
        assert_eq!(frame_count_for_plaintext(256 * 1024), 16);
    }

    #[test]
    fn ciphertext_overhead_is_per_frame_tags() {
        // 64 KiB plaintext → 4 tags × 16 = 64 bytes overhead, 0.097%.
        let plain = 64 * 1024;
        let cipher = ciphertext_len_for_plaintext(plain);
        assert_eq!(cipher, plain + 4 * AEAD_TAG_LEN);
    }
}
