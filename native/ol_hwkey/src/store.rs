//! KeyStore trait: the platform-agnostic surface that callers code against.

use crate::error::Result;
use crate::KeyGuarantee;

/// Opaque handle to a key inside a backend. The backend chooses how to
/// represent the handle (a path, a CryptoKit ref, a TPM blob, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyHandle(pub String);

/// A 32-byte BLAKE3 fingerprint of the public key. Same shape across
/// backends so callers can pin without knowing which backend was used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn fingerprint(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }
}

/// Vendor attestation evidence. When present and verified the caller can
/// upgrade their `KeyGuarantee` reading from `HardwareBound` to
/// `HardwareAttested`.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Vendor-specific attestation blob (Apple App Attest CBOR, Android
    /// key attestation cert chain, Windows TPM quote, etc.).
    pub blob: Vec<u8>,
    /// String tag identifying the vendor format. Caller dispatches on
    /// this to pick a verifier.
    pub format: String,
}

pub trait KeyStore: Send + Sync {
    fn guarantee(&self) -> KeyGuarantee;

    /// Get-or-create a key for `label`. On first call creates and stores;
    /// on subsequent calls returns the same handle. Backends that
    /// support hardware-bound storage will generate the key inside the
    /// secure element.
    fn get_or_create(&self, label: &str) -> Result<KeyHandle>;

    /// Return the public key for a previously created handle. Returns
    /// `NotFound` if the handle is unknown.
    fn public_key(&self, handle: &KeyHandle) -> Result<PublicKey>;

    /// Optional vendor attestation. Software-only backends return
    /// `BackendUnavailable`.
    fn attest(&self, _handle: &KeyHandle, _challenge: &[u8]) -> Result<Attestation> {
        Err(crate::error::HwKeyError::BackendUnavailable(
            "this backend does not support attestation".into(),
        ))
    }

    /// Detect a TOFU violation: presented key bytes do not match the
    /// stored public key for that label. Software backends use the
    /// stored fingerprint; hardware backends rely on the secure
    /// element's tamper detection.
    fn check_tofu(&self, label: &str, presented: &PublicKey) -> Result<()>;
}
