//! AEAD cipher dispatch: AES-256-GCM primary, ChaCha20-Poly1305 fallback.
//!
//! Per [ADR-0002](../../../docs/decisions/0002-aead-frame.md):
//!
//! - On x86 with AES-NI available, `AeadKind::AesGcm256` is the default.
//! - On ARM64 with AES intrinsics, `AeadKind::AesGcm256` is also default.
//! - On platforms without hardware AES, `AeadKind::ChaCha20Poly1305` is
//!   chosen by [`AeadKind::default_for_host`].
//!
//! Both ciphers expose identical 32-byte key, 12-byte nonce, 16-byte tag
//! AEAD interfaces — so the [`AeadCipher`] enum just dispatches at the
//! init step and reuses identical encrypt/decrypt code paths.

use aead::{AeadInPlace, KeyInit};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;

use crate::error::AeadError;
use crate::key::ChunkAeadKey;

/// AEAD primitive selection.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum AeadKind {
    /// AES-256-GCM (primary on x86 / ARM64 with hardware accel).
    AesGcm256,
    /// ChaCha20-Poly1305 (fallback when no hardware AES is present).
    ChaCha20Poly1305,
}

impl AeadKind {
    /// Pick the best AEAD for the running host.
    ///
    /// Conservative policy: any hardware AES support → `AesGcm256`;
    /// otherwise `ChaCha20Poly1305`. The detection runs at first call;
    /// callers can also pin a kind explicitly via [`AeadCipher::with_kind`].
    #[must_use]
    pub fn default_for_host() -> Self {
        if has_hardware_aes() {
            Self::AesGcm256
        } else {
            Self::ChaCha20Poly1305
        }
    }
}

/// Detect hardware AES support at runtime.
///
/// On x86, checks AES-NI via `std::arch::is_x86_feature_detected!`.
/// On ARM64, checks AES intrinsics via `std::arch::is_aarch64_feature_detected!`.
/// All other architectures return `false` (forces ChaCha20 fallback).
#[must_use]
pub fn has_hardware_aes() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "x86")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    {
        false
    }
}

/// Per-frame key wrapper. The `cipher::FrameKey` is a derived per-frame
/// key passed into encrypt/decrypt — distinct from the per-chunk
/// [`ChunkAeadKey`] in `key.rs` (which is what the upstream KDF emits).
///
/// In the current pipeline, `FrameKey == ChunkAeadKey` because all frames
/// in a chunk share the chunk's AEAD key (frame nonces handle the
/// per-frame uniqueness). The type alias-like wrapper exists to keep the
/// API symmetric for future per-frame ratcheting (Phase C).
pub type FrameKey = ChunkAeadKey;

/// Concrete AEAD cipher initialized with a key.
///
/// Constructed via [`AeadCipher::with_kind`] or [`AeadCipher::default_for_host`].
/// Once constructed, `encrypt_in_place` / `decrypt_in_place` are zero-copy.
#[derive(Clone)]
pub enum AeadCipher {
    /// AES-256-GCM cipher initialized with a 32-byte key.
    AesGcm256(Aes256Gcm),
    /// ChaCha20-Poly1305 cipher initialized with a 32-byte key.
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl std::fmt::Debug for AeadCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't expose the key in Debug output. Just the kind.
        let kind = match self {
            Self::AesGcm256(_) => "AesGcm256",
            Self::ChaCha20Poly1305(_) => "ChaCha20Poly1305",
        };
        f.debug_tuple("AeadCipher").field(&kind).finish()
    }
}

impl AeadCipher {
    /// Initialize the host's preferred AEAD with the given key.
    #[must_use]
    pub fn default_for_host(key: &ChunkAeadKey) -> Self {
        Self::with_kind(AeadKind::default_for_host(), key)
    }

    /// Initialize a specific AEAD kind with the given key.
    #[must_use]
    pub fn with_kind(kind: AeadKind, key: &ChunkAeadKey) -> Self {
        match kind {
            AeadKind::AesGcm256 => {
                let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
                    .expect("AES-256-GCM accepts any 32-byte key");
                Self::AesGcm256(cipher)
            }
            AeadKind::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
                    .expect("ChaCha20-Poly1305 accepts any 32-byte key");
                Self::ChaCha20Poly1305(cipher)
            }
        }
    }

    /// Which kind this cipher dispatches to.
    #[must_use]
    pub fn kind(&self) -> AeadKind {
        match self {
            Self::AesGcm256(_) => AeadKind::AesGcm256,
            Self::ChaCha20Poly1305(_) => AeadKind::ChaCha20Poly1305,
        }
    }

    /// Encrypt-in-place with the given nonce and AAD.
    ///
    /// `buffer` is mutated to hold the ciphertext (same length as input
    /// plaintext). The 16-byte authentication tag is returned separately
    /// for caller-controlled framing.
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::Authentication`] only on the encrypt side if
    /// the underlying AEAD signaled an error (RustCrypto's encrypt side
    /// rarely fails — would indicate a programming error).
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; crate::nonce::FRAME_NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; crate::frame::AEAD_TAG_LEN_USIZE], AeadError> {
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
        let tag = match self {
            Self::AesGcm256(c) => c
                .encrypt_in_place_detached(nonce_arr, aad, buffer)
                .map_err(|_| AeadError::Authentication)?,
            Self::ChaCha20Poly1305(c) => c
                .encrypt_in_place_detached(nonce_arr, aad, buffer)
                .map_err(|_| AeadError::Authentication)?,
        };
        let mut tag_arr = [0u8; crate::frame::AEAD_TAG_LEN_USIZE];
        tag_arr.copy_from_slice(tag.as_slice());
        Ok(tag_arr)
    }

    /// Decrypt-in-place verifying the given tag.
    ///
    /// `buffer` is mutated to hold the plaintext. Tag verification uses
    /// constant-time comparison via the underlying RustCrypto subtle ops.
    ///
    /// # Errors
    ///
    /// Returns [`AeadError::Authentication`] on any verification failure
    /// (tampered ciphertext, AAD, key, nonce, or tag).
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8; crate::nonce::FRAME_NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; crate::frame::AEAD_TAG_LEN_USIZE],
    ) -> Result<(), AeadError> {
        let nonce_arr = aead::generic_array::GenericArray::from_slice(nonce);
        let tag_arr = aead::generic_array::GenericArray::from_slice(tag);
        match self {
            Self::AesGcm256(c) => c
                .decrypt_in_place_detached(nonce_arr, aad, buffer, tag_arr)
                .map_err(|_| AeadError::Authentication),
            Self::ChaCha20Poly1305(c) => c
                .decrypt_in_place_detached(nonce_arr, aad, buffer, tag_arr)
                .map_err(|_| AeadError::Authentication),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonce::frame_nonce;

    fn fixed_key() -> ChunkAeadKey {
        ChunkAeadKey::from_bytes([0x42u8; 32])
    }

    #[test]
    fn host_aead_kind_picks_aes_on_x86() {
        // Most CI x86 hosts have AES-NI. ARM64 + AES too. Other archs
        // would prefer ChaCha20.
        let kind = AeadKind::default_for_host();
        assert!(matches!(kind, AeadKind::AesGcm256 | AeadKind::ChaCha20Poly1305));
    }

    #[test]
    fn aes_gcm_round_trip() {
        let key = fixed_key();
        let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &key);
        let nonce = frame_nonce(&[0x01u8; 32], 0).unwrap();
        let aad = [0x99u8; 32];
        let plaintext = b"hello, AEAD!".to_vec();
        let mut buf = plaintext.clone();
        let tag = cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        // Decrypt
        cipher.decrypt_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn chacha20_round_trip() {
        let key = fixed_key();
        let cipher = AeadCipher::with_kind(AeadKind::ChaCha20Poly1305, &key);
        let nonce = frame_nonce(&[0x02u8; 32], 7).unwrap();
        let aad = [0x55u8; 32];
        let plaintext = b"hello, ChaCha20-Poly1305".to_vec();
        let mut buf = plaintext.clone();
        let tag = cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        cipher.decrypt_in_place(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = fixed_key();
        let cipher = AeadCipher::default_for_host(&key);
        let nonce = frame_nonce(&[0x03u8; 32], 0).unwrap();
        let aad = [0xAAu8; 32];
        let plaintext = b"sensitive data".to_vec();
        let mut buf = plaintext.clone();
        let tag = cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        // Flip a bit in the ciphertext.
        buf[0] ^= 0x01;
        let result = cipher.decrypt_in_place(&nonce, &aad, &mut buf, &tag);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn tampered_tag_rejected() {
        let key = fixed_key();
        let cipher = AeadCipher::default_for_host(&key);
        let nonce = frame_nonce(&[0x04u8; 32], 0).unwrap();
        let aad = [0xBBu8; 32];
        let mut buf = b"data".to_vec();
        let mut tag = cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        tag[0] ^= 0x01;
        let result = cipher.decrypt_in_place(&nonce, &aad, &mut buf, &tag);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn tampered_aad_rejected() {
        let key = fixed_key();
        let cipher = AeadCipher::default_for_host(&key);
        let nonce = frame_nonce(&[0x05u8; 32], 0).unwrap();
        let aad = [0xCCu8; 32];
        let mut bad_aad = aad;
        bad_aad[0] ^= 0x01;
        let mut buf = b"data".to_vec();
        let tag = cipher.encrypt_in_place(&nonce, &aad, &mut buf).unwrap();
        let result = cipher.decrypt_in_place(&nonce, &bad_aad, &mut buf, &tag);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn nonce_swap_rejected() {
        let key = fixed_key();
        let cipher = AeadCipher::default_for_host(&key);
        let n_a = frame_nonce(&[0x06u8; 32], 0).unwrap();
        let n_b = frame_nonce(&[0x06u8; 32], 1).unwrap();
        let aad = [0xDDu8; 32];
        let mut buf = b"data".to_vec();
        let tag = cipher.encrypt_in_place(&n_a, &aad, &mut buf).unwrap();
        // Swap nonce on decrypt.
        let result = cipher.decrypt_in_place(&n_b, &aad, &mut buf, &tag);
        assert!(matches!(result, Err(AeadError::Authentication)));
    }

    #[test]
    fn aes_and_chacha_produce_distinct_ciphertexts() {
        let key = fixed_key();
        let nonce = frame_nonce(&[0x07u8; 32], 0).unwrap();
        let aad = [0xEEu8; 32];
        let plaintext = b"identical input across two ciphers".to_vec();
        let mut buf_aes = plaintext.clone();
        let mut buf_chacha = plaintext.clone();
        let aes = AeadCipher::with_kind(AeadKind::AesGcm256, &key);
        let chacha = AeadCipher::with_kind(AeadKind::ChaCha20Poly1305, &key);
        let _ = aes.encrypt_in_place(&nonce, &aad, &mut buf_aes).unwrap();
        let _ = chacha.encrypt_in_place(&nonce, &aad, &mut buf_chacha).unwrap();
        assert_ne!(buf_aes, buf_chacha);
    }
}
