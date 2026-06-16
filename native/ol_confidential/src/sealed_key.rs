//! Opaque sealed key blob handed back by a [`crate::ConfidentialProvider`].

use zeroize::Zeroize;

use crate::ProviderTag;

/// Provider-opaque sealed key bytes. Callers MUST NOT introspect
/// `bytes`; the layout is intentionally provider-private so we can
/// swap representations (software AEAD blob, SGX sealed data, TPM
/// wrapped blob) without breaking callers.
///
/// Drop zeroizes `bytes` defensively even though the sealed form
/// is itself ciphertext — a defense-in-depth practice that catches
/// the case where a future provider stores plaintext padding
/// alongside the ciphertext.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedKey {
    /// Which provider produced this blob; checked at unseal time.
    pub provider_tag: ProviderTag,
    /// Provider-opaque bytes. For [`crate::SoftwareProvider`] this is
    /// `nonce(12) || ciphertext(N) || tag(16)` under a per-process
    /// ephemeral ChaCha20-Poly1305 key.
    pub bytes: Vec<u8>,
}

impl std::fmt::Debug for SealedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedKey")
            .field("provider_tag", &self.provider_tag)
            .field("bytes.len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl Drop for SealedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl SealedKey {
    /// Construct from raw parts. Crate-internal: callers obtain
    /// [`SealedKey`] only via [`crate::ConfidentialProvider::seal_master`]
    /// or [`crate::ConfidentialProvider::derive_child`].
    pub(crate) fn new(provider_tag: ProviderTag, bytes: Vec<u8>) -> Self {
        Self {
            provider_tag,
            bytes,
        }
    }
}
