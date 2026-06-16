//! Error types for the device-mesh layer.

use thiserror::Error;

/// Result alias used across the crate.
pub type DeviceMeshResult<T> = Result<T, DeviceMeshError>;

/// Typed error surface for device-mesh operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeviceMeshError {
    /// Wrong byte length supplied to a `parse/from_bytes` function.
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
    /// Quorum proposal: deadline is not strictly after `issued_unix`.
    #[error(
        "quorum proposal deadline_unix={deadline_unix} must be after issued_unix={issued_unix}"
    )]
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
    #[error(
        "quorum approval at approved_unix={approved_unix} is past deadline_unix={deadline_unix}"
    )]
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
    #[error(
        "certificate's proposal expired at deadline_unix={deadline_unix} (now_unix={now_unix})"
    )]
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
    /// Mesh-state authenticated op failed cryptographic verification.
    #[error("mesh-state authenticated op failed cryptographic verification")]
    AuthOpVerifyFail,
    /// Op delta kind doesn't match the target subtree's CRDT kind.
    #[error("op delta kind doesn't match the subtree's CRDT kind")]
    DeltaKindMismatch,
    /// Op delta payload exceeds the per-value byte budget.
    #[error("op delta value too long: {got} bytes (max {max})")]
    DeltaValueTooLong {
        /// Actual payload length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Subtree label exceeds the maximum allowed length.
    #[error("subtree label too long: {got} bytes (max {max})")]
    SubtreeLabelTooLong {
        /// Actual length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Tried to register the same subtree label with a different CRDT kind.
    #[error("subtree label is already registered under a different CRDT kind")]
    SubtreeKindCollision,
    /// Op targets a subtree label that doesn't exist in the state.
    #[error("op targets a subtree label that is not registered in the mesh state")]
    SubtreeMissing,
    /// Op sequence number regressed for an emitter device.
    #[error("op seq regression for device {device_id:x?}: got {got}, last seen {last_seen}")]
    OpSeqNotMonotonic {
        /// Offending emitter device id.
        device_id: [u8; 16],
        /// Sequence number on the rejected op.
        got: u64,
        /// Highest seq we'd already accepted.
        last_seen: u64,
    },
    /// Erasure policy supplied k=0.
    #[error("erasure policy: data shard count k must be ≥ 1")]
    ErasurePolicyZeroData,
    /// Erasure policy: k+m exceeds the workspace bound.
    #[error("erasure policy: k+m = {k}+{m} exceeds the maximum {max}")]
    ErasurePolicyOversize {
        /// Data shard count.
        k: u8,
        /// Parity shard count.
        m: u8,
        /// Maximum allowed sum.
        max: u8,
    },
    /// Erasure policy supplied `min_devices_per_shard = 0`.
    #[error("erasure policy: min_devices_per_shard must be ≥ 1")]
    ErasurePolicyZeroMinDevices,
    /// File manifest has no chunks.
    #[error("file manifest is empty (no chunks)")]
    FileManifestEmpty,
    /// File manifest carries more chunks than allowed.
    #[error("file manifest has too many chunks: {got} (max {max})")]
    FileManifestTooManyChunks {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// File manifest mime type exceeds the byte budget.
    #[error("file manifest mime too long: {got} bytes (max {max})")]
    FileManifestMimeTooLong {
        /// Actual length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// File manifest declares zero-size chunks.
    #[error("file manifest chunk_size must be ≥ 1")]
    FileManifestZeroChunkSize,
    /// File manifest's chunk count is not a multiple of the stripe
    /// width `(k + m)`.
    #[error("file manifest chunk count {got} is not a multiple of stripe width {stripe}")]
    FileManifestChunkCountNotStripe {
        /// Actual chunk count.
        got: usize,
        /// Stripe width = k + m.
        stripe: usize,
    },
    /// Storage attestation carries more chunk hashes than allowed.
    #[error("storage attestation has too many chunks: {got} (max {max})")]
    AttestationTooManyChunks {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Storage attestation chunk hashes are not strictly sorted.
    #[error("storage attestation chunk hashes are not strictly sorted + deduplicated")]
    AttestationChunksNotSorted,
    /// Storage attestation signature failed verification.
    #[error("storage attestation failed cryptographic verification")]
    StorageAttestVerifyFail,
    /// Fetch request signature failed verification.
    #[error("fetch request failed cryptographic verification")]
    FetchRequestVerifyFail,
    /// Fetch request has no chunks.
    #[error("fetch request must name at least one chunk")]
    FetchRequestEmpty,
    /// Fetch request carries more chunks than allowed.
    #[error("fetch request has too many chunks: {got} (max {max})")]
    FetchRequestTooManyChunks {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Fetch request chunk hashes are not strictly sorted.
    #[error("fetch request chunk hashes are not strictly sorted + deduplicated")]
    FetchRequestChunksNotSorted,
    /// Fetch request deadline is not strictly after issue time.
    #[error("fetch request deadline_unix={deadline_unix} must be after issued_unix={issued_unix}")]
    FetchRequestDeadlineNotAfterIssue {
        /// Issue wall-clock.
        issued_unix: u64,
        /// Deadline wall-clock.
        deadline_unix: u64,
    },
    /// Chunk ack signature failed verification.
    #[error("chunk ack failed cryptographic verification")]
    ChunkAckVerifyFail,
    /// Fan-out planner received an empty source list.
    #[error("fan-out planner needs at least one source")]
    FanOutNoSources,
    /// Fan-out planner `overrequest_factor` below 1.0 or non-finite.
    /// `got_bits` is `f64::to_bits` of the offending value so the
    /// error stays `Eq`-friendly.
    #[error("fan-out overrequest_factor must be >= 1.0 and finite (got bits 0x{got_bits:x})")]
    FanOutBadOverrequestFactor {
        /// Bit representation of the bad value supplied.
        got_bits: u64,
    },
    /// Replan invoked with no chunks remaining to fetch.
    #[error("fan-out replan called with no still-needed chunks")]
    FanOutNothingToReplan,
    /// Route announcement signature failed verification.
    #[error("route announcement failed cryptographic verification")]
    RouteAnnouncementVerifyFail,
    /// Route announcement carries more links than allowed.
    #[error("route announcement has too many links: {got} (max {max})")]
    RouteAnnouncementTooManyLinks {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Route announcement links are not strictly sorted by peer id.
    #[error(
        "route announcement links must be sorted ascending by peer_device_id with no duplicates"
    )]
    RouteAnnouncementLinksNotSorted,
    /// Route announcement carries a self-loop (announcer listed
    /// itself as one of its peers).
    #[error("route announcement contains a self-loop (announcer is in its own links)")]
    RouteAnnouncementSelfLoop,
    /// Onion attestation signature failed verification.
    #[error("onion attestation failed cryptographic verification")]
    OnionAttestationVerifyFail,
    /// Onion attestation validity window has expiry before mint.
    #[error("onion attestation has expiry day {expiry} before mint day {mint}")]
    OnionAttestationBadValidityWindow {
        /// Mint day index.
        mint: u64,
        /// Expiry day index.
        expiry: u64,
    },
    /// Registry lookup couldn't find an attestation for the device.
    #[error("onion registry has no attestation for device {device_id:x?}")]
    OnionRegistryDeviceMissing {
        /// Device id queried.
        device_id: [u8; 16],
    },
    /// Registry entry exists but the queried day is outside its
    /// validity window.
    #[error("onion attestation for device {device_id:x?} doesn't cover day {day} (mint {mint}, expiry {expiry})")]
    OnionRegistryDayOutOfWindow {
        /// Device id queried.
        device_id: [u8; 16],
        /// Day requested.
        day: u64,
        /// Mint day.
        mint: u64,
        /// Expiry day.
        expiry: u64,
    },
    /// Self-onion route needs at least 2 hops (source + destination).
    #[error("self-onion route has too few hops: {got}")]
    SelfOnionRouteTooShort {
        /// Actual hop count.
        got: usize,
    },
    /// Self-onion hop pubkey is invalid Ristretto255.
    #[error("self-onion hop pubkey is not a valid Ristretto255 point for device {device_id:x?}")]
    SelfOnionBadHopPubkey {
        /// Device whose pubkey was malformed.
        device_id: [u8; 16],
    },
    /// Self-onion payload exceeds the Sphinx-permitted max.
    #[error("self-onion payload too large: {got} bytes (max {max})")]
    SelfOnionPayloadOversize {
        /// Actual payload length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Underlying Sphinx build failed.
    #[error("self-onion Sphinx build failed: {0}")]
    SelfOnionSphinxBuildFailed(String),
    /// Underlying Sphinx peel failed.
    #[error("self-onion Sphinx peel failed: {0}")]
    SelfOnionSphinxPeelFailed(String),
    /// Duress code was empty.
    #[error("duress code must be at least one byte")]
    DuressCodeEmpty,
    /// Underlying Argon2 derivation failed.
    #[error("duress code Argon2 derivation failed: {0}")]
    DuressArgon2Failed(String),
    /// Duress envelope plaintext was empty (real or decoy).
    #[error("duress envelope plaintext (real or decoy) cannot be empty")]
    DuressEnvelopePlaintextEmpty,
    /// Duress envelope plaintext exceeded the byte budget.
    #[error("duress envelope plaintext too long (max {max} bytes)")]
    DuressEnvelopePlaintextTooLong {
        /// Maximum allowed.
        max: usize,
    },
    /// Real and decoy codes were the same — refuse to mint a
    /// deniable envelope under a single password.
    #[error("real and decoy codes must differ")]
    DuressCodesIdentical,
    /// AEAD encrypt / decrypt failed.
    #[error("duress envelope AEAD failed: {0}")]
    DuressAeadFailed(String),
    /// Duress alert signature failed verification.
    #[error("duress alert failed cryptographic verification")]
    DuressAlertVerifyFail,
    /// Pairing commitment didn't match the supplied secret on one
    /// channel.
    #[error("pairing commitment on channel {channel:?} doesn't match the supplied secret")]
    PairChannelCommitmentMismatch {
        /// The mismatched channel.
        channel: crate::duress::pair::PairingChannel,
    },
    /// One of the required pairing channels (QR / Audio / Motion)
    /// was missing from the supplied commitment set.
    #[error(
        "pairing commitment set missing required channel(s): qr={qr} audio={audio} motion={motion}"
    )]
    PairChannelMissing {
        /// Whether QR was seen.
        qr: bool,
        /// Whether Audio was seen.
        audio: bool,
        /// Whether Motion was seen.
        motion: bool,
    },
    /// Pairing commitments spread past the allowed time window.
    #[error("pairing commitment span {span_ms}ms exceeds window {window_ms}ms")]
    PairChannelOutOfWindow {
        /// Span between earliest and latest commitment timestamps.
        span_ms: u64,
        /// Allowed window.
        window_ms: u64,
    },
    /// Capability attestation has too many capabilities.
    #[error("capability attestation has too many capabilities: {got} (max {max})")]
    CapabilityAttestationTooMany {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Capability list is not strictly sorted (no duplicates allowed).
    #[error("capability attestation list must be sorted ascending with no duplicates")]
    CapabilityAttestationNotSorted,
    /// Validity window has expiry strictly before mint.
    #[error("capability attestation expiry day {expiry} is before mint day {mint}")]
    CapabilityAttestationBadValidityWindow {
        /// Mint day.
        mint: u64,
        /// Expiry day.
        expiry: u64,
    },
    /// Capability attestation signature failed verification.
    #[error("capability attestation failed cryptographic verification")]
    CapabilityAttestationVerifyFail,
    /// Task class empty.
    #[error("task class must be at least one byte")]
    TaskClassEmpty,
    /// Task class string too long.
    #[error("task class too long: {got} bytes (max {max})")]
    TaskClassTooLong {
        /// Actual length.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Task request listed too many required capabilities.
    #[error("task request requires too many capabilities: {got} (max {max})")]
    TaskTooManyCapabilities {
        /// Actual count.
        got: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Task request required-capabilities list not strictly sorted.
    #[error("task request required_capabilities must be sorted ascending with no duplicates")]
    TaskCapabilitiesNotSorted,
    /// Task request deadline is not strictly after issue.
    #[error("task request deadline_unix={deadline_unix} must be after issued_unix={issued_unix}")]
    TaskDeadlineNotAfterIssue {
        /// Issue time.
        issued_unix: u64,
        /// Deadline.
        deadline_unix: u64,
    },
    /// Task request signature failed verification.
    #[error("task request failed cryptographic verification")]
    TaskRequestVerifyFail,
    /// Task result signature failed verification.
    #[error("task result failed cryptographic verification")]
    TaskResultVerifyFail,
}

impl From<ol_pqsig::PqSigError> for DeviceMeshError {
    fn from(e: ol_pqsig::PqSigError) -> Self {
        Self::PqSig(format!("{e}"))
    }
}
