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
    /// Audit I3 May 2026 — issuer's claimed `issued_unix` is farther
    /// in the future than `ATTESTATION_MAX_CLOCK_SKEW_SECS` allows.
    /// Detects a forward-skewed issuer who could otherwise mint a
    /// doc whose deadline lies past the verifier's clock for far
    /// longer than the freshness window would allow.
    #[error("attestation issuer clock skew: issued_unix={issued_unix} now_unix={now_unix} max_skew={max_skew_secs}")]
    AttestationIssuerClockSkew {
        /// `doc.issued_unix`.
        issued_unix: u64,
        /// Verifier's wall clock.
        now_unix: u64,
        /// Policy maximum.
        max_skew_secs: u64,
    },
    /// Audit I3 May 2026 — doc is ancient relative to verifier wall
    /// clock (issued > `ATTESTATION_MAX_AGE_SECS` ago). Independent
    /// from `AttestationExpired` because a clock-skew adversary
    /// could otherwise craft a deadline that hasn't passed despite
    /// the doc being weeks old.
    #[error(
        "attestation too old: issued_unix={issued_unix} now_unix={now_unix} max_age={max_age_secs}"
    )]
    AttestationTooOld {
        /// `doc.issued_unix`.
        issued_unix: u64,
        /// Verifier's wall clock.
        now_unix: u64,
        /// Policy maximum.
        max_age_secs: u64,
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
    /// Field-context commitment in the doc does not match the verifier's
    /// expected bytes. No physical-environment inference is implied.
    #[error("attestation field-witness mismatch")]
    AttestationFieldWitnessMismatch,
    /// Provider tag declared in the doc disagrees with what the master
    /// claims to run.
    #[error("attestation provider tag mismatch")]
    AttestationProviderTagMismatch,
    /// Provider tier carried in the doc is below the verifier's
    /// required floor. Closes the silent-TPM-downgrade vector: a
    /// peer that previously pinned a `HardwareBound` `master_vk`
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
    /// where a peer attests with someone else's `master_vk` under
    /// their own SDP identity (audit C1 May 2026).
    #[error("attestation issuer SDP pubkey does not match channel identity")]
    AttestationIssuerSdpPubkeyMismatch,
    /// Hybrid-sig under the hood reported a problem.
    #[error("pqsig: {0}")]
    PqSig(String),
    /// Internal invariant violated. Should never happen at runtime;
    /// indicates a logic bug. Carries a static string for the
    /// hot-path checks where allocating an error message would be
    /// inappropriate.
    #[error("internal: {0}")]
    Internal(&'static str),
    /// Internal invariant violated with run-time context. Used by
    /// the platform-specific hardware backends (e.g. `windows_tpm`)
    /// whose underlying FFI returns dynamic error strings that we
    /// can't statify. Audit L6 May 2026: replaces a `Box::leak`
    /// shim that leaked one boxed-str per TPM error.
    #[error("internal: {0}")]
    InternalOwned(String),
}

impl From<ol_pqsig::PqSigError> for ConfidentialError {
    fn from(value: ol_pqsig::PqSigError) -> Self {
        ConfidentialError::PqSig(format!("{value}"))
    }
}
