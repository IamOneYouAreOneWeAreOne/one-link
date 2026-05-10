//! Per-frame and per-chunk encrypt / decrypt entry points.
//!
//! The chunk-level [`encrypt_chunk`] / [`decrypt_chunk`] functions
//! divide a chunk plaintext into 16 KiB AEAD frames per
//! [ADR-0002](../../../docs/decisions/0002-aead-frame.md), encrypting
//! each with its own nonce and 16-byte tag, and emit the on-wire layout
//! `[ct_frame_0 || tag_0 || ct_frame_1 || tag_1 || ... ]`.
//!
//! For random-access reads (FUSE/FSKit/Dokan), the per-frame functions
//! [`encrypt_frame`] / [`decrypt_frame`] operate on a single frame
//! identified by `(chunk_id, frame_index)`. Reading a 64 KiB random
//! offset from a 256 KiB chunk decrypts at most 2 frames (32 KiB) — the
//! amplification cap from ADR-0002.

use ol_chunk::{frame_count_for_plaintext, AEAD_FRAME_PLAINTEXT_LEN, AEAD_TAG_LEN};

use crate::cipher::AeadCipher;
use crate::error::AeadError;
use crate::nonce::frame_nonce;

/// Internal mirror of `AEAD_TAG_LEN` for use in stack-array sizes
/// (`const` evaluation in `[u8; N]`). Identical to `AEAD_TAG_LEN`.
pub(crate) const AEAD_TAG_LEN_USIZE: usize = AEAD_TAG_LEN;

/// Maximum supported chunk size for a single AEAD pipeline call.
///
/// Per [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md), CDC
/// produces chunks ≤ 256 KiB. The AEAD pipeline rejects larger inputs
/// to keep the on-stack frame index calculation bounded.
pub const MAX_CHUNK_PLAINTEXT_LEN: usize = 256 * 1024;

/// View of a single AEAD frame within a chunk's on-wire ciphertext layout.
///
/// `ciphertext_offset` is the byte offset in the chunk's ciphertext
/// where the frame's ciphertext starts. `ciphertext_len` is the length
/// of the frame's ciphertext (≤ 16 KiB; only the LAST frame may be
/// shorter). The 16-byte tag follows immediately at
/// `ciphertext_offset + ciphertext_len`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FrameRef {
    /// Frame index within the chunk.
    pub index: usize,
    /// Plaintext offset within the chunk.
    pub plaintext_offset: usize,
    /// Plaintext length of this frame (max 16 KiB).
    pub plaintext_len: usize,
    /// Ciphertext offset within the on-wire layout.
    pub ciphertext_offset: usize,
}

impl FrameRef {
    /// Length of this frame's tag in bytes (always 16).
    #[inline]
    #[must_use]
    pub const fn tag_len(self) -> usize {
        AEAD_TAG_LEN_USIZE
    }

    /// Total on-wire length: plaintext + tag.
    #[inline]
    #[must_use]
    pub const fn ciphertext_len_with_tag(self) -> usize {
        self.plaintext_len + AEAD_TAG_LEN_USIZE
    }
}

/// Compute the ciphertext layout for a chunk plaintext of length `L`.
///
/// Returns a Vec of [`FrameRef`] that describes each frame's plaintext
/// and ciphertext positions. The last frame may be shorter than 16 KiB.
#[must_use]
pub fn frame_layout(plaintext_len: usize) -> Vec<FrameRef> {
    let mut frames = Vec::with_capacity(frame_count_for_plaintext(plaintext_len));
    let mut plaintext_offset = 0usize;
    let mut ciphertext_offset = 0usize;
    let mut index = 0usize;
    while plaintext_offset < plaintext_len {
        let remaining = plaintext_len - plaintext_offset;
        let plaintext_len_this = remaining.min(AEAD_FRAME_PLAINTEXT_LEN);
        frames.push(FrameRef {
            index,
            plaintext_offset,
            plaintext_len: plaintext_len_this,
            ciphertext_offset,
        });
        plaintext_offset += plaintext_len_this;
        ciphertext_offset += plaintext_len_this + AEAD_TAG_LEN_USIZE;
        index += 1;
    }
    frames
}

/// Encrypt a complete chunk plaintext into a single ciphertext buffer.
///
/// Layout (per [ADR-0002](../../../docs/decisions/0002-aead-frame.md)):
/// `[ct_frame_0 || tag_0 || ct_frame_1 || tag_1 || ...]`.
///
/// Output buffer length = `plaintext.len() + frame_count * AEAD_TAG_LEN`.
///
/// # Errors
///
/// - [`AeadError::PlaintextTooLarge`] if `plaintext.len() > MAX_CHUNK_PLAINTEXT_LEN`.
/// - [`AeadError::InvalidAad`] if `chunk_id` is not exactly 32 bytes.
/// - [`AeadError::Authentication`] on encrypt failure (programming error).
pub fn encrypt_chunk(
    cipher: &AeadCipher,
    chunk_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if plaintext.len() > MAX_CHUNK_PLAINTEXT_LEN {
        return Err(AeadError::PlaintextTooLarge {
            got: plaintext.len(),
            max: MAX_CHUNK_PLAINTEXT_LEN,
        });
    }
    let frames = frame_layout(plaintext.len());
    let total_ciphertext_len = plaintext.len() + frames.len() * AEAD_TAG_LEN_USIZE;
    let mut output = Vec::with_capacity(total_ciphertext_len);
    for f in &frames {
        let nonce = frame_nonce(chunk_id, f.index as u64)?;
        let plaintext_slice = &plaintext[f.plaintext_offset..f.plaintext_offset + f.plaintext_len];
        // Append plaintext bytes; the cipher mutates them in-place into ciphertext.
        let frame_start_in_output = output.len();
        output.extend_from_slice(plaintext_slice);
        let frame_buf = &mut output[frame_start_in_output..];
        let tag = cipher.encrypt_in_place(&nonce, chunk_id.as_slice(), frame_buf)?;
        output.extend_from_slice(&tag);
    }
    debug_assert_eq!(output.len(), total_ciphertext_len);
    Ok(output)
}

/// Decrypt a complete chunk ciphertext into the corresponding plaintext.
///
/// Inverse of [`encrypt_chunk`]. Validates the on-wire layout and every
/// frame's tag in constant time.
///
/// # Errors
///
/// - [`AeadError::InvalidCiphertextLength`] if `ciphertext` doesn't match
///   the expected `plaintext_len + frame_count * AEAD_TAG_LEN` shape.
/// - [`AeadError::Authentication`] on any tag verification failure.
pub fn decrypt_chunk(
    cipher: &AeadCipher,
    chunk_id: &[u8; 32],
    plaintext_len: usize,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if plaintext_len > MAX_CHUNK_PLAINTEXT_LEN {
        return Err(AeadError::PlaintextTooLarge {
            got: plaintext_len,
            max: MAX_CHUNK_PLAINTEXT_LEN,
        });
    }
    let frames = frame_layout(plaintext_len);
    let expected_ct_len = plaintext_len + frames.len() * AEAD_TAG_LEN_USIZE;
    if ciphertext.len() != expected_ct_len {
        return Err(AeadError::InvalidCiphertextLength {
            expected: expected_ct_len,
            got: ciphertext.len(),
        });
    }
    let mut output = vec![0u8; plaintext_len];
    let mut ct_cursor = 0usize;
    for f in &frames {
        let nonce = frame_nonce(chunk_id, f.index as u64)?;
        // Slice out frame ciphertext + trailing tag.
        let frame_ct = &ciphertext[ct_cursor..ct_cursor + f.plaintext_len];
        let tag_slice = &ciphertext[ct_cursor + f.plaintext_len
            ..ct_cursor + f.plaintext_len + AEAD_TAG_LEN_USIZE];
        let mut tag_arr = [0u8; AEAD_TAG_LEN_USIZE];
        tag_arr.copy_from_slice(tag_slice);
        // Copy ciphertext into the output buffer in the right plaintext position.
        let pt_slice = &mut output[f.plaintext_offset..f.plaintext_offset + f.plaintext_len];
        pt_slice.copy_from_slice(frame_ct);
        cipher.decrypt_in_place(&nonce, chunk_id.as_slice(), pt_slice, &tag_arr)?;
        ct_cursor += f.plaintext_len + AEAD_TAG_LEN_USIZE;
    }
    Ok(output)
}

/// Encrypt a single frame.
///
/// Used by streaming senders that emit frames one-at-a-time.
/// `frame_plaintext.len()` must be ≤ `AEAD_FRAME_PLAINTEXT_LEN`.
///
/// # Errors
///
/// As [`encrypt_chunk`].
pub fn encrypt_frame(
    cipher: &AeadCipher,
    chunk_id: &[u8; 32],
    frame_index: u64,
    frame_plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; AEAD_TAG_LEN_USIZE]), AeadError> {
    if frame_plaintext.len() > AEAD_FRAME_PLAINTEXT_LEN {
        return Err(AeadError::PlaintextTooLarge {
            got: frame_plaintext.len(),
            max: AEAD_FRAME_PLAINTEXT_LEN,
        });
    }
    let nonce = frame_nonce(chunk_id, frame_index)?;
    let mut buf = frame_plaintext.to_vec();
    let tag = cipher.encrypt_in_place(&nonce, chunk_id.as_slice(), &mut buf)?;
    Ok((buf, tag))
}

/// Decrypt a single frame.
///
/// Used by random-access readers (FUSE/FSKit/Dokan) that decrypt only
/// the frame containing the requested offset.
///
/// # Errors
///
/// - [`AeadError::Authentication`] on tag verification failure.
pub fn decrypt_frame(
    cipher: &AeadCipher,
    chunk_id: &[u8; 32],
    frame_index: u64,
    frame_ciphertext: &[u8],
    tag: &[u8; AEAD_TAG_LEN_USIZE],
) -> Result<Vec<u8>, AeadError> {
    let nonce = frame_nonce(chunk_id, frame_index)?;
    let mut buf = frame_ciphertext.to_vec();
    cipher.decrypt_in_place(&nonce, chunk_id.as_slice(), &mut buf, tag)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{AeadCipher, AeadKind};
    use crate::key::ChunkAeadKey;

    fn fixed_cipher(kind: AeadKind) -> AeadCipher {
        let key = ChunkAeadKey::from_bytes([0x77u8; 32]);
        AeadCipher::with_kind(kind, &key)
    }

    #[test]
    fn chunk_round_trip_aes() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x11u8; 32];
        let plaintext = (0..50_000u32).map(|i| (i & 0xFF) as u8).collect::<Vec<_>>();
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).unwrap();
        // Sanity: 50,000 bytes produces ceil(50000/16384) = 4 frames.
        let frames = frame_layout(plaintext.len());
        assert_eq!(frames.len(), 4);
        assert_eq!(ciphertext.len(), plaintext.len() + 4 * AEAD_TAG_LEN_USIZE);
        let recovered = decrypt_chunk(&cipher, &chunk_id, plaintext.len(), &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chunk_round_trip_chacha() {
        let cipher = fixed_cipher(AeadKind::ChaCha20Poly1305);
        let chunk_id = [0x22u8; 32];
        let plaintext = (0..150_000u32).map(|i| (i & 0xFF) as u8).collect::<Vec<_>>();
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).unwrap();
        let recovered = decrypt_chunk(&cipher, &chunk_id, plaintext.len(), &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn empty_chunk_yields_empty_ciphertext() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x33u8; 32];
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, b"").unwrap();
        assert_eq!(ciphertext.len(), 0);
        let recovered = decrypt_chunk(&cipher, &chunk_id, 0, &ciphertext).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn max_size_chunk_round_trip() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x44u8; 32];
        let plaintext = vec![0xABu8; MAX_CHUNK_PLAINTEXT_LEN];
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).unwrap();
        // 256 KiB / 16 KiB = 16 frames per ADR-0002.
        assert_eq!(frame_layout(plaintext.len()).len(), 16);
        let recovered = decrypt_chunk(&cipher, &chunk_id, plaintext.len(), &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn oversized_chunk_rejected() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x55u8; 32];
        let plaintext = vec![0u8; MAX_CHUNK_PLAINTEXT_LEN + 1];
        let result = encrypt_chunk(&cipher, &chunk_id, &plaintext);
        assert!(matches!(result, Err(AeadError::PlaintextTooLarge { .. })));
    }

    #[test]
    fn wrong_ciphertext_length_rejected_on_decrypt() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x66u8; 32];
        let plaintext = vec![0u8; 50_000];
        let mut ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).unwrap();
        ciphertext.pop(); // truncate by 1 byte
        let result = decrypt_chunk(&cipher, &chunk_id, plaintext.len(), &ciphertext);
        assert!(matches!(result, Err(AeadError::InvalidCiphertextLength { .. })));
    }

    #[test]
    fn bit_flip_in_any_frame_rejected() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0x77u8; 32];
        let plaintext = vec![0xFFu8; 50_000]; // 4 frames
        let original_ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).unwrap();
        // Flip a bit in each frame in turn; recovery must fail every time.
        for frame_byte in [0usize, 16384, 32768, 49000] {
            let mut tampered = original_ciphertext.clone();
            tampered[frame_byte] ^= 0x01;
            let result = decrypt_chunk(&cipher, &chunk_id, plaintext.len(), &tampered);
            assert!(matches!(result, Err(AeadError::Authentication)));
        }
    }

    #[test]
    fn cross_chunk_id_rejected() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let id_a = [0x88u8; 32];
        let id_b = [0x89u8; 32];
        let plaintext = b"top secret".to_vec();
        let ciphertext = encrypt_chunk(&cipher, &id_a, &plaintext).unwrap();
        // Decrypt with the WRONG chunk_id (which is the AAD).
        let result = decrypt_chunk(&cipher, &id_b, plaintext.len(), &ciphertext);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn cross_cipher_rejected() {
        // Encrypt with AES, decrypt with ChaCha (or vice versa) MUST fail.
        let aes = fixed_cipher(AeadKind::AesGcm256);
        let chacha = fixed_cipher(AeadKind::ChaCha20Poly1305);
        let chunk_id = [0x99u8; 32];
        let plaintext = b"asymmetric ciphers".to_vec();
        let ciphertext = encrypt_chunk(&aes, &chunk_id, &plaintext).unwrap();
        let result = decrypt_chunk(&chacha, &chunk_id, plaintext.len(), &ciphertext);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn single_frame_round_trip() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0xAAu8; 32];
        let frame_index = 3u64;
        let frame_plaintext = vec![0x42u8; 8000];
        let (frame_ct, tag) =
            encrypt_frame(&cipher, &chunk_id, frame_index, &frame_plaintext).unwrap();
        let recovered = decrypt_frame(&cipher, &chunk_id, frame_index, &frame_ct, &tag).unwrap();
        assert_eq!(recovered, frame_plaintext);
    }

    #[test]
    fn frame_index_swap_rejected() {
        let cipher = fixed_cipher(AeadKind::AesGcm256);
        let chunk_id = [0xBBu8; 32];
        let plaintext = vec![0x11u8; AEAD_FRAME_PLAINTEXT_LEN];
        let (frame_ct, tag) = encrypt_frame(&cipher, &chunk_id, 0, &plaintext).unwrap();
        // Decrypt as if it were frame 1.
        let result = decrypt_frame(&cipher, &chunk_id, 1, &frame_ct, &tag);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn frame_layout_matches_adr_0002() {
        // 64 KiB plaintext = 4 frames per ADR-0002.
        let frames = frame_layout(64 * 1024);
        assert_eq!(frames.len(), 4);
        for (i, f) in frames.iter().enumerate() {
            assert_eq!(f.index, i);
            assert_eq!(f.plaintext_len, AEAD_FRAME_PLAINTEXT_LEN);
            assert_eq!(f.plaintext_offset, i * AEAD_FRAME_PLAINTEXT_LEN);
            assert_eq!(f.ciphertext_offset, i * (AEAD_FRAME_PLAINTEXT_LEN + AEAD_TAG_LEN_USIZE));
        }
    }
}
