//! Quorum proposals.
//!
//! A proposal is "I, device X, propose that operation O be approved
//! under policy P by the deadline D." The issuer's subkey signs the
//! canonical bytes; the BLAKE3 digest of the canonical bytes is the
//! [`ProposalId`] that approvals bind to.

use blake3::Hasher;
use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::policy::{QuorumPolicy, QuorumPolicyId, POLICY_ID_LEN};

/// Length of the per-proposal nonce.
pub const PROPOSAL_NONCE_LEN: usize = 16;

/// Per-proposal nonce; uniformly random per proposal.
pub type ProposalNonce = [u8; PROPOSAL_NONCE_LEN];

/// Length of the BLAKE3 digest committing to the operation payload.
pub const OPERATION_DIGEST_LEN: usize = 32;

/// Domain-separation tag for proposal-signing.
pub const PROPOSAL_DOMAIN: &[u8] = b"OL-device-mesh-proposal-v1";

/// BLAKE3 digest of the canonical proposal transcript; what
/// approvals bind to.
pub type ProposalId = [u8; 32];

/// One issued proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumProposal {
    /// Which policy governs this proposal.
    pub policy_id: QuorumPolicyId,
    /// 32-byte digest of the actual operation payload. Layer 2
    /// doesn't interpret these bytes; higher layers commit to the
    /// operation via BLAKE3.
    pub operation_digest: [u8; OPERATION_DIGEST_LEN],
    /// Per-proposal nonce.
    pub nonce: ProposalNonce,
    /// Wall-clock seconds at issue time.
    pub issued_unix: u64,
    /// Wall-clock seconds the proposal expires.
    pub deadline_unix: u64,
    /// Issuer's device id.
    pub issuer_device_id: [u8; DEVICE_ID_LEN],
    /// Issuer's subkey day-index at issue time. Verifier cross-
    /// checks against the subkey-attestation cache.
    pub issuer_day_index: u64,
    /// Issuer's subkey signature over the canonical bytes.
    pub issuer_sig: Vec<u8>,
}

impl QuorumProposal {
    /// Canonical bytes the issuer signs over.
    #[must_use] 
    pub fn canonical_transcript(
        policy_id: &QuorumPolicyId,
        operation_digest: &[u8; OPERATION_DIGEST_LEN],
        nonce: &ProposalNonce,
        issued_unix: u64,
        deadline_unix: u64,
        issuer_device_id: &[u8; DEVICE_ID_LEN],
        issuer_day_index: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PROPOSAL_DOMAIN.len()
                + POLICY_ID_LEN
                + OPERATION_DIGEST_LEN
                + PROPOSAL_NONCE_LEN
                + 8
                + 8
                + DEVICE_ID_LEN
                + 8,
        );
        out.extend_from_slice(PROPOSAL_DOMAIN);
        out.extend_from_slice(policy_id);
        out.extend_from_slice(operation_digest);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&issued_unix.to_be_bytes());
        out.extend_from_slice(&deadline_unix.to_be_bytes());
        out.extend_from_slice(issuer_device_id);
        out.extend_from_slice(&issuer_day_index.to_be_bytes());
        out
    }

    /// Compute the [`ProposalId`] (BLAKE3 over the canonical transcript).
    #[must_use] 
    pub fn proposal_id(&self) -> ProposalId {
        let transcript = Self::canonical_transcript(
            &self.policy_id,
            &self.operation_digest,
            &self.nonce,
            self.issued_unix,
            self.deadline_unix,
            &self.issuer_device_id,
            self.issuer_day_index,
        );
        let mut h = Hasher::new();
        h.update(b"OL-device-mesh-proposal-id-v1");
        h.update(&transcript);
        *h.finalize().as_bytes()
    }

    /// Verify the issuer's signature against the supplied subkey VK.
    /// Caller is responsible for proving that VK is the issuer's
    /// (typically via a [`crate::SubkeyAttestation`] under the master).
    pub fn verify_issuer(&self, issuer_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.issuer_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.issuer_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.policy_id,
            &self.operation_digest,
            &self.nonce,
            self.issued_unix,
            self.deadline_unix,
            &self.issuer_device_id,
            self.issuer_day_index,
        );
        issuer_vk
            .verify(&transcript, &self.issuer_sig)
            .map_err(|_| DeviceMeshError::ProposalIssuerVerifyFail)
    }
}

/// Propose an operation. The issuer's subkey signs the canonical
/// transcript; the resulting [`QuorumProposal`] is broadcast to the
/// sibling devices that will sign approvals.
pub fn propose_operation(
    issuer: &DeviceSubkey,
    policy: &QuorumPolicy,
    operation_digest: [u8; OPERATION_DIGEST_LEN],
    nonce: ProposalNonce,
    issued_unix: u64,
    deadline_unix: u64,
) -> DeviceMeshResult<QuorumProposal> {
    if !policy.is_eligible(issuer.device_id()) {
        return Err(DeviceMeshError::IssuerNotEligible {
            device_id: *issuer.device_id(),
        });
    }
    if deadline_unix <= issued_unix {
        return Err(DeviceMeshError::ProposalDeadlineNotAfterIssue {
            issued_unix,
            deadline_unix,
        });
    }
    let transcript = QuorumProposal::canonical_transcript(
        &policy.policy_id,
        &operation_digest,
        &nonce,
        issued_unix,
        deadline_unix,
        issuer.device_id(),
        issuer.day_index(),
    );
    let sig = issuer.sign(&transcript)?;
    Ok(QuorumProposal {
        policy_id: policy.policy_id,
        operation_digest,
        nonce,
        issued_unix,
        deadline_unix,
        issuer_device_id: *issuer.device_id(),
        issuer_day_index: issuer.day_index(),
        issuer_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn setup() -> (MasterIdentity, DeviceSubkey, QuorumPolicy) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let policy = super::super::policy::mint_policy(
            &master,
            [0x42; 16],
            b"test-policy",
            2,
            vec![id, [0x77; 16], [0x88; 16]],
        )
        .unwrap();
        (master, sk, policy)
    }

    #[test]
    fn propose_and_verify_round_trip() {
        let (_master, sk, policy) = setup();
        let now: u64 = 1_700_000_000;
        let p = propose_operation(
            &sk,
            &policy,
            [0xEE; OPERATION_DIGEST_LEN],
            [0xDA; PROPOSAL_NONCE_LEN],
            now,
            now + 3600,
        )
        .unwrap();
        p.verify_issuer(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn proposal_id_is_deterministic() {
        let (_m, sk, policy) = setup();
        let now: u64 = 1_700_000_000;
        let p = propose_operation(
            &sk, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        assert_eq!(p.proposal_id(), p.proposal_id());
    }

    #[test]
    fn ineligible_issuer_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        // Policy that excludes `id`.
        let policy = super::super::policy::mint_policy(
            &master,
            [0x42; 16],
            b"test-policy",
            1,
            vec![[0x77; 16], [0x88; 16]],
        )
        .unwrap();
        let now: u64 = 1_700_000_000;
        let err = propose_operation(
            &sk, &policy, [0xEE; 32], [0xDA; 16], now, now + 100,
        )
        .unwrap_err();
        assert!(matches!(err, DeviceMeshError::IssuerNotEligible { .. }));
    }

    #[test]
    fn deadline_before_issue_rejected() {
        let (_m, sk, policy) = setup();
        let err = propose_operation(
            &sk, &policy, [0xEE; 32], [0xDA; 16], 1000, 1000,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::ProposalDeadlineNotAfterIssue { .. }
        ));
    }

    #[test]
    fn tampered_operation_digest_breaks_verify() {
        let (_m, sk, policy) = setup();
        let now: u64 = 1_700_000_000;
        let mut p = propose_operation(
            &sk, &policy, [0xEE; 32], [0xDA; 16], now, now + 100,
        )
        .unwrap();
        p.operation_digest[0] ^= 0xFF;
        let err = p.verify_issuer(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ProposalIssuerVerifyFail));
    }
}
