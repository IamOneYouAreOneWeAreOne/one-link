//! Typed errors for the confidential-compute surface.

use thiserror::Error;

/// Result alias used throughout this crate.
pub type ConfidentialResult<T> = std::result::Result<T, ConfidentialError>;

/// Failure modes for sealed-op + attestation calls.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConfidentialError {
    /// The sealed blob is the wrong length for the supplied provider.
    #[error("sealed key wrong length: expected {expected}, got {got}")]
    SealedKeyBadLength {
        /// Expected length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// The sealed blob does not authenticate (AEAD tag failed) — wrong
    /// process / wrong provider / wrong day.
    #[error("sealed key authentication failed")]
    SealedKeyAuthFail,
    /// The sealed blob's provider tag does not match the provider
    /// trying to open it.
    #[error("sealed key wrong provider: expected {expected:?}, got {got:?}")]
    SealedKeyWrongProvider {
        /// Provider we expected (this provider's tag).
        expected: crate::ProviderTag,
        /// Provider tag carried in the sealed blob.
        got: crate::ProviderTag,
    },
    /// Attestation doc's master signature did not verify.
    #[error("attestation master signature did not verify")]
    AttestationMasterSigFail,
    /// Attestation doc is past its `deadline_unix`.
    #[error("attestation expired: deadline_unix={deadline_unix} now_unix={now_unix}")]
    AttestationExpired {
        /// Deadline carried in the doc.
        deadline_unix: u64,
        /// Verifier's wall clock.
        now_unix: u64,
    },
    /// Attestation doc's deadline is not strictly after `issued_unix`.
    #[error("attestation deadline_unix={deadline_unix} not after issued_unix={issued_unix}")]
    AttestationBadFreshnessWindow {
        /// issued.
        issued_unix: u64,
        /// deadline.
        deadline_unix: u64,
    },
    /// Attestation freshness window is wider than the policy maximum.
    /// Tightens replay risk against long-lived attestation docs.
    #[error("attestation freshness window {got} secs exceeds max {max}")]
    AttestationFreshnessWindowTooWide {
        /// Got width.
        got: u64,
        /// Policy maximum.
        max: u64,
    },
    /// Peer's nonce in the doc does not match the nonce the peer sent.
    #[error("attestation peer-nonce mismatch")]
    AttestationPeerNonceMismatch,
    /// Field witness in the doc does not match the verifier's local
    /// witness — the doc is bound to a different physical environment.
    #[error("attestation field-witness mismatch")]
    AttestationFieldWitnessMismatch,
    /// Provider tag declared in the doc disagrees with what the master
    /// claims to run.
    #[error("attestation provider tag mismatch")]
    AttestationProviderTagMismatch,
    /// Provider tier carried in the doc is below the verifier's
    /// required floor. Closes the silent-TPM-downgrade vector: a
    /// peer that previously pinned a HardwareBound master_vk
    /// refuses a later Software-tier doc.
    #[error("attestation provider tier {got:?} below required min {min:?}")]
    AttestationProviderTierTooLow {
        /// Doc-asserted tier (mapped from `doc.provider_tag`).
        got: crate::tier::ConfidentialTier,
        /// Minimum tier the verifier requires.
        min: crate::tier::ConfidentialTier,
    },
    /// Issuer's SDP-layer Ed25519 pubkey embedded in the attestation
    /// doc does not match the SDP identity the verifier is actually
    /// talking to over the wire. Closes the identity-confusion attack
    /// where a peer attests with someone else's master_vk under
    /// their own SDP identity (audit C1 May 2026).
    #[error("attestation issuer SDP pubkey does not match channel identity")]
    AttestationIssuerSdpPubkeyMismatch,
    /// Hybrid-sig under the hood reported a problem.
    #[error("pqsig: {0}")]
    PqSig(String),
    /// Internal invariant violated. Should never happen at runtime;
    /// indicates a logic bug.
    #[error("internal: {0}")]
    Internal(&'static str),
}

impl From<ol_pqsig::PqSigError> for ConfidentialError {
    fn from(value: ol_pqsig::PqSigError) -> Self {
        ConfidentialError::PqSig(format!("{value}"))
    }
}
