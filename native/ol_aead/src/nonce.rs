//! AEAD nonce construction per [ADR-0002](../../../docs/decisions/0002-aead-frame.md).
//!
//! Nonce = 96 bits = `chunk_id_lo64 || frame_index_u32`, all little-endian.
//!
//! - `chunk_id_lo64`: lower 64 bits of the BLAKE3 chunk address (raw or
//!   convergent per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md)).
//!   Guaranteed unique per chunk under content-addressing.
//! - `frame_index_u32`: zero-based index of the frame within the chunk.
//!
//! This construction is reuse-impossible by design: same chunk_id_lo64
//! across two chunks would already be a content-address collision (~2^-32
//! probability for 4 billion chunks; the engine refuses to write a chunk
//! whose 64-bit prefix matches an existing one). Within a chunk, frame
//! indices are distinct by definition.

use crate::error::AeadError;

/// Nonce length in bytes (96 bits) for both AES-256-GCM and
/// ChaCha20-Poly1305 in this engine.
pub const FRAME_NONCE_LEN: usize = 12;

/// Construct a 12-byte nonce from a chunk_id and frame index.
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
pub fn frame_nonce(chunk_id: &[u8; 32], frame_index: u64) -> Result<[u8; FRAME_NONCE_LEN], AeadError> {
    if frame_index > u64::from(u32::MAX) {
        return Err(AeadError::FrameIndexOverflow { got: frame_index });
    }
    let mut nonce = [0u8; FRAME_NONCE_LEN];
    // First 8 bytes: chunk_id lower 64 bits, little-endian.
    nonce[..8].copy_from_slice(&chunk_id[..8]);
    // Last 4 bytes: frame_index as u32 little-endian.
    let idx32 = frame_index as u32;
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
        for i in 0..8 {
            chunk_id[i] = (i + 1) as u8;
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
        let n_big = frame_nonce(&chunk_id, u32::MAX as u64).unwrap();
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
