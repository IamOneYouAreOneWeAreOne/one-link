//! The platform-agnostic sealed-op surface.

use ol_pqsig::HybridVerifyingKey;

use crate::attestation::{AttestationDoc, AttestationNonce};
use crate::errors::ConfidentialResult;
use crate::sealed_key::SealedKey;
use crate::tier::ConfidentialTier;

/// Provider tag — identifies the back-end that produced a sealed
/// blob or an attestation doc. Carried in the wire format so a doc
/// produced by one provider can't be opened by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ProviderTag {
    /// Software-only baseline (this crate's reference impl).
    Software = 1,
    /// macOS Secure Enclave (future Phase 2).
    AppleSecureEnclave = 2,
    /// Android `StrongBox` (future Phase 2).
    AndroidStrongBox = 3,
    /// Windows TPM via `NCrypt` / tss-esapi (future Phase 2).
    WindowsTpm = 4,
    /// Intel SGX (future Phase 2).
    IntelSgx = 5,
    /// AMD SEV-SNP (future Phase 2).
    AmdSevSnp = 6,
    /// ARM `TrustZone` / OP-TEE (future Phase 2).
    ArmTrustZone = 7,
}

impl ProviderTag {
    /// Domain byte written to attestation canonical bytes so the
    /// verifier knows which tag the issuer claimed.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a single tag byte. Returns `None` for unknown tags so
    /// forward-compat callers can ignore newer-format docs gracefully.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Software),
            2 => Some(Self::AppleSecureEnclave),
            3 => Some(Self::AndroidStrongBox),
            4 => Some(Self::WindowsTpm),
            5 => Some(Self::IntelSgx),
            6 => Some(Self::AmdSevSnp),
            7 => Some(Self::ArmTrustZone),
            _ => None,
        }
    }
}

/// The single trait every confidential-compute back-end implements.
///
/// Sealed operations return ONLY public outputs (sigs, verifying
/// keys, ciphertexts). Secret material lives behind [`SealedKey`]
/// and never crosses this boundary in plaintext.
pub trait ConfidentialProvider: Send + Sync {
    /// Tier this provider operates at.
    fn tier(&self) -> ConfidentialTier;

    /// Provider tag — must match the tag carried in any
    /// [`SealedKey`] this provider produces.
    fn tag(&self) -> ProviderTag;

    /// Seal a raw 32-byte master seed under this provider. Caller
    /// SHOULD zeroize the input seed after the call.
    ///
    /// # Errors
    /// Returns `Internal` if the provider's sealing primitive fails
    /// (should not happen for software providers).
    fn seal_master(&self, seed: &[u8; 32]) -> ConfidentialResult<SealedKey>;

    /// Derive a child key from a sealed master + a context tag. The
    /// child is itself a [`SealedKey`]; the master is never exposed.
    /// Used for per-day ratchet, per-channel keys, etc.
    ///
    /// # Errors
    /// Returns `SealedKeyAuthFail` / `SealedKeyWrongProvider` if the
    /// supplied master blob can't be opened by this provider.
    fn derive_child(
        &self,
        sealed_master: &SealedKey,
        context_tag: &[u8],
    ) -> ConfidentialResult<SealedKey>;

    /// Sign `transcript` under a sealed signing key. The provider
    /// unseals internally, signs via the hybrid `Ed25519 + ML-DSA-65`
    /// primitive, and zeroizes the unsealed buffer before return.
    /// The caller sees only the public signature bytes.
    ///
    /// # Errors
    /// Returns `SealedKeyAuthFail` if the blob can't be unsealed; or
    /// `PqSig` if the underlying signing primitive fails.
    fn sealed_sign(
        &self,
        sealed: &SealedKey,
        transcript: &[u8],
    ) -> ConfidentialResult<Vec<u8>>;

    /// Return the verifying-key bytes for the keypair represented by
    /// `sealed`. Safe to expose because this is the public half.
    ///
    /// # Errors
    /// Returns `SealedKeyAuthFail` if the blob can't be unsealed.
    fn verifying_key(&self, sealed: &SealedKey) -> ConfidentialResult<HybridVerifyingKey>;

    /// Issue a signed attestation doc binding this provider, the
    /// sealed master, a peer-supplied nonce, and an issuance window.
    ///
    /// The doc is signed under the master's hybrid signing key (the
    /// peer pins `master_vk` out-of-band). Real-hardware providers
    /// additionally embed a platform quote in
    /// [`AttestationDoc::platform_quote`]; the software provider
    /// leaves that field empty.
    ///
    /// # Errors
    /// Returns `SealedKeyAuthFail` if the master blob can't be
    /// opened, or `Internal` if the platform quote primitive errs.
    fn attest(
        &self,
        sealed_master: &SealedKey,
        peer_nonce: AttestationNonce,
        issued_unix: u64,
        deadline_unix: u64,
        field_witness: Option<&[u8; 32]>,
    ) -> ConfidentialResult<AttestationDoc>;
}
