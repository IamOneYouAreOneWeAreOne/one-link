//! AEAD nonce construction per [ADR-0002](../../../docs/decisions/0002-aead-frame.md).
//!
//! Nonce = 96 bits = `chunk_id_lo64 || frame_index_u32`, all little-endian.
//!
//! - `chunk_id_lo64`: lower 64 bits of the BLAKE3 chunk address (raw or
//!   convergent per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md)).
//!   A 64-bit prefix can collide; content addressing alone does not
//!   guarantee uniqueness.
//! - `frame_index_u32`: zero-based index of the frame within the chunk.
//!
//! The calling engine's contract is to detect and reject a reused 64-bit
//! prefix under the same AEAD key (or use an independently derived key).
//! The birthday probability is material at large populations, and this crate
//! does not own a registry that can enforce the contract. Within one accepted
//! chunk, distinct in-range frame indices produce distinct nonce bytes.

use crate::error::AeadError;

/// Nonce length in bytes (96 bits) for both AES-256-GCM and
/// ChaCha20-Poly1305 in this engine.
pub const FRAME_NONCE_LEN: usize = 12;

/// Construct a 12-byte nonce from a `chunk_id` and frame index.
///
/// `chunk_id` is the full 32-byte BLAKE3 chunk address; the lower 64 bits
/// are interpreted little-endian as `chunk_id_lo64`.
///
/// `frame_index` is the zero-based index of the frame within the chunk.
/// Must fit in `u32`.
///
/// # Errors
///
/// Returns [`AeadError::FrameIndexOverflow`] if `frame_index` exceeds `u32::MAX`.
pub fn frame_nonce(
    chunk_id: &[u8; 32],
    frame_index: u64,
) -> Result<[u8; FRAME_NONCE_LEN], AeadError> {
    let idx32 = u32::try_from(frame_index)
        .map_err(|_| AeadError::FrameIndexOverflow { got: frame_index })?;
    let mut nonce = [0u8; FRAME_NONCE_LEN];
    // First 8 bytes: chunk_id lower 64 bits, little-endian.
    nonce[..8].copy_from_slice(&chunk_id[..8]);
    // Last 4 bytes: frame_index as u32 little-endian.
    nonce[8..].copy_from_slice(&idx32.to_le_bytes());
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_lo64_then_index() {
        let mut chunk_id = [0u8; 32];
        // First 8 bytes = 0x01..0x08 (little-endian = 0x0807060504030201)
        for (value, slot) in (1u8..=8).zip(chunk_id.iter_mut()) {
            *slot = value;
        }
        // Remaining bytes irrelevant.
        let nonce = frame_nonce(&chunk_id, 7).unwrap();
        assert_eq!(&nonce[..8], &chunk_id[..8]);
        assert_eq!(&nonce[8..], &[7u8, 0, 0, 0]);
    }

    #[test]
    fn distinct_frames_distinct_nonces() {
        let chunk_id = [0xAAu8; 32];
        let n0 = frame_nonce(&chunk_id, 0).unwrap();
        let n1 = frame_nonce(&chunk_id, 1).unwrap();
        let n_big = frame_nonce(&chunk_id, u64::from(u32::MAX)).unwrap();
        assert_ne!(n0, n1);
        assert_ne!(n0, n_big);
        assert_ne!(n1, n_big);
    }

    #[test]
    fn distinct_chunks_distinct_nonces() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        a[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        b[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 9]);
        let na = frame_nonce(&a, 0).unwrap();
        let nb = frame_nonce(&b, 0).unwrap();
        assert_ne!(na, nb);
    }

    #[test]
    fn overflow_rejected() {
        let chunk_id = [0u8; 32];
        let result = frame_nonce(&chunk_id, u64::from(u32::MAX) + 1);
        assert!(matches!(result, Err(AeadError::FrameIndexOverflow { .. })));
    }
}
