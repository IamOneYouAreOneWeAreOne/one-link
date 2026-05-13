//! Error types for the device-mesh layer.

use thiserror::Error;

/// Result alias used across the crate.
pub type DeviceMeshResult<T> = Result<T, DeviceMeshError>;

/// Typed error surface for device-mesh operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceMeshError {
    /// Wrong byte length supplied to a parse/from_bytes function.
    #[error("wrong length: expected {expected}, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// Day index advanced past the configured chain horizon.
    #[error("ratchet day index {got} exceeds chain horizon {max}")]
    RatchetExhausted {
        /// Day requested.
        got: u64,
        /// Maximum allowed day index for this chain.
        max: u64,
    },
    /// Subkey attestation signature verification failed.
    #[error("subkey attestation failed cryptographic verification")]
    AttestationVerifyFail,
    /// Liveness proof signature verification failed.
    #[error("liveness proof failed cryptographic verification")]
    LivenessVerifyFail,
    /// Liveness proof outside the allowed clock-skew window.
    #[error("liveness proof timestamp outside skew window (got {got_unix}, now {now_unix}, max skew {max_skew_secs})")]
    LivenessOutOfWindow {
        /// Proof's claimed unix-seconds timestamp.
        got_unix: u64,
        /// Verifier's current unix-seconds clock.
        now_unix: u64,
        /// Maximum allowed clock skew in seconds.
        max_skew_secs: u64,
    },
    /// Hardware wrapper rejected the supplied ciphertext (unwrap failed).
    #[error("hardware wrapper unwrap failed (likely wrong slot or tampered ciphertext)")]
    HardwareUnwrapFail,
    /// Underlying PQ-hybrid signature error bubbled up from `ol_pqsig`.
    #[error("pqsig error: {0}")]
    PqSig(String),
    /// Quorum policy: master signature failed verification.
    #[error("quorum policy failed cryptographic verification")]
    PolicyVerifyFail,
    /// Quorum policy: empty roster supplied at mint time.
    #[error("quorum policy roster is empty")]
    PolicyEmptyRoster,
    /// Quorum policy: roster exceeds the max-eligible bound.
    #[error("quorum policy roster too large: {got} (max {max})")]
    PolicyRosterTooLarge {
        /// Actual roster size.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Quorum policy: roster contains duplicate device ids.
    #[error("quorum policy roster contains duplicate device ids")]
    PolicyDuplicateRoster,
    /// Quorum policy: invalid threshold (k=0 or k > N).
    #[error("quorum policy bad threshold k={k} for roster size n={n}")]
    PolicyBadThreshold {
        /// Threshold value.
        k: u8,
        /// Roster size.
        n: usize,
    },
    /// Quorum policy: label exceeds the maximum.
    #[error("quorum policy label too long: {got} bytes (max {max})")]
    PolicyLabelTooLong {
        /// Actual length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Quorum proposal: issuer signature failed verification.
    #[error("quorum proposal failed cryptographic verification by issuer")]
    ProposalIssuerVerifyFail,
    /// Quorum proposal: deadline is not strictly after issued_unix.
    #[error("quorum proposal deadline_unix={deadline_unix} must be after issued_unix={issued_unix}")]
    ProposalDeadlineNotAfterIssue {
        /// Issue wall-clock.
        issued_unix: u64,
        /// Deadline wall-clock.
        deadline_unix: u64,
    },
    /// Issuer device is not in the policy's eligible list.
    #[error("issuer device id is not in the policy roster")]
    IssuerNotEligible {
        /// Offending device id.
        device_id: [u8; 16],
    },
    /// Approver device is not in the policy's eligible list.
    #[error("approver device id is not in the policy roster")]
    ApproverNotEligible {
        /// Offending device id.
        device_id: [u8; 16],
    },
    /// Quorum approval: signature failed verification.
    #[error("quorum approval failed cryptographic verification")]
    ApprovalVerifyFail,
    /// Quorum approval was signed for a different proposal id.
    #[error("quorum approval's proposal_id does not match the certificate's proposal")]
    ApprovalForOtherProposal,
    /// Quorum approval signed past its proposal's deadline.
    #[error("quorum approval at approved_unix={approved_unix} is past deadline_unix={deadline_unix}")]
    ApprovalPastDeadline {
        /// Approval wall-clock.
        approved_unix: u64,
        /// Proposal deadline.
        deadline_unix: u64,
    },
    /// Two approvals from the same device in one certificate.
    #[error("certificate contains two approvals from the same device id")]
    DuplicateApprover {
        /// Offending device id.
        device_id: [u8; 16],
    },
    /// Certificate carries more approvals than allowed.
    #[error("certificate has too many approvals: {got} (max {max})")]
    CertTooManyApprovals {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Certificate's proposal references a different policy than the
    /// policy field.
    #[error("certificate's proposal.policy_id mismatches the certificate's policy.policy_id")]
    CertProposalPolicyMismatch,
    /// Certificate's proposal deadline is past the verifier's wall clock.
    #[error("certificate's proposal expired at deadline_unix={deadline_unix} (now_unix={now_unix})")]
    CertProposalExpired {
        /// Deadline wall-clock.
        deadline_unix: u64,
        /// Verifier wall-clock.
        now_unix: u64,
    },
    /// Certificate doesn't carry enough distinct approvers.
    #[error("certificate has {got} distinct approvers, threshold needs {needed}")]
    CertBelowThreshold {
        /// Distinct approver count.
        got: usize,
        /// Required threshold.
        needed: u8,
    },
    /// A signer's subkey attestation is missing from the certificate cache.
    #[error("certificate is missing an attestation for device {device_id:x?} day {day_index}")]
    AttestationMissing {
        /// Device id that's missing an attestation.
        device_id: [u8; 16],
        /// Day index that needed coverage.
        day_index: u64,
    },
}

impl From<ol_pqsig::PqSigError> for DeviceMeshError {
    fn from(e: ol_pqsig::PqSigError) -> Self {
        Self::PqSig(format!("{e}"))
    }
}
