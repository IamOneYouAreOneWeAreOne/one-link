//! AEAD key material and zeroization.

use zeroize::{Zeroize, Zeroizing};

/// Length of an AEAD frame key in bytes.
///
/// 32 bytes (256 bits) — both AES-256-GCM and ChaCha20-Poly1305 use
/// 256-bit keys per [ADR-0002](../../../docs/decisions/0002-aead-frame.md).
pub const FRAME_KEY_LEN: usize = 32;

/// A 32-byte AEAD key. Wraps the bytes in `Zeroizing` so the memory is
/// cleared on drop, eliminating one common side-channel (post-use key
/// material lingering in the heap).
///
/// Construct via [`ChunkAeadKey::from_bytes`]; the inner array is private
/// so callers don't accidentally clone the key elsewhere without zeroize
/// coverage.
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct ChunkAeadKey {
    inner: [u8; FRAME_KEY_LEN],
}

impl ChunkAeadKey {
    /// Construct a key from a 32-byte array.
    ///
    /// The caller is responsible for the upstream KDF: typically
    /// `ol_chunk::blake3_wrap::derive_aead_key(ratchet_chain_key, chunk_id)`
    /// per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md)
    /// Rule 3.
    #[inline]
    #[must_use]
    pub fn from_bytes(bytes: [u8; FRAME_KEY_LEN]) -> Self {
        Self { inner: bytes }
    }

    /// Borrow the underlying bytes. Use sparingly; prefer the
    /// `ChunkAeadKey` wrapper for everything because the wrapper handles
    /// zeroize on drop.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; FRAME_KEY_LEN] {
        &self.inner
    }
}

/// Zeroizing wrapper for any 32-byte key material — used internally for
/// derived per-frame keys (Phase C ratchet).
#[allow(dead_code)]
pub(crate) type SecretBytes = Zeroizing<[u8; FRAME_KEY_LEN]>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_round_trip() {
        let bytes = [0x42u8; FRAME_KEY_LEN];
        let key = ChunkAeadKey::from_bytes(bytes);
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn key_is_clonable() {
        let bytes = [0x42u8; FRAME_KEY_LEN];
        let key1 = ChunkAeadKey::from_bytes(bytes);
        let key2 = key1.clone();
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }
}
