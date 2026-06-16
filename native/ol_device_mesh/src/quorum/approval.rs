//! Per-device approval records.
//!
//! An [`QuorumApproval`] is "I, device X, approve proposal P at
//! wall-clock T." The approver's subkey signs the canonical bytes;
//! the `proposal_id` binds the approval to one specific proposal so
//! it can't be replayed against a different operation.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

use super::proposal::{ProposalId, QuorumProposal};

/// Domain-separation tag for approval-signing.
pub const APPROVAL_DOMAIN: &[u8] = b"OL-device-mesh-approval-v1";

/// One sibling-device approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumApproval {
    /// Which proposal is being approved (BLAKE3 over canonical bytes).
    pub proposal_id: ProposalId,
    /// Approving device's id.
    pub approver_device_id: [u8; DEVICE_ID_LEN],
    /// Approver's subkey day-index at approval time.
    pub approver_day_index: u64,
    /// Wall-clock seconds at approval time.
    pub approved_unix: u64,
    /// Approver's subkey signature over the canonical bytes.
    pub approver_sig: Vec<u8>,
}

impl QuorumApproval {
    /// Canonical bytes the approver signs over.
    #[must_use]
    pub fn canonical_transcript(
        proposal_id: &ProposalId,
        approver_device_id: &[u8; DEVICE_ID_LEN],
        approver_day_index: u64,
        approved_unix: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(APPROVAL_DOMAIN.len() + 32 + DEVICE_ID_LEN + 8 + 8);
        out.extend_from_slice(APPROVAL_DOMAIN);
        out.extend_from_slice(proposal_id);
        out.extend_from_slice(approver_device_id);
        out.extend_from_slice(&approver_day_index.to_be_bytes());
        out.extend_from_slice(&approved_unix.to_be_bytes());
        out
    }

    /// Verify the approver's signature against the supplied subkey
    /// VK. Caller proves the VK is the approver's via the master-
    /// signed [`crate::SubkeyAttestation`] cache.
    pub fn verify(&self, approver_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.approver_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.approver_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.proposal_id,
            &self.approver_device_id,
            self.approver_day_index,
            self.approved_unix,
        );
        approver_vk
            .verify(&transcript, &self.approver_sig)
            .map_err(|_| DeviceMeshError::ApprovalVerifyFail)
    }
}

/// Sign an approval on `proposal` using `approver`'s subkey.
pub fn sign_approval(
    approver: &DeviceSubkey,
    proposal: &QuorumProposal,
    approved_unix: u64,
) -> DeviceMeshResult<QuorumApproval> {
    if approved_unix > proposal.deadline_unix {
        return Err(DeviceMeshError::ApprovalPastDeadline {
            approved_unix,
            deadline_unix: proposal.deadline_unix,
        });
    }
    let proposal_id = proposal.proposal_id();
    let transcript = QuorumApproval::canonical_transcript(
        &proposal_id,
        approver.device_id(),
        approver.day_index(),
        approved_unix,
    );
    let sig = approver.sign(&transcript)?;
    Ok(QuorumApproval {
        proposal_id,
        approver_device_id: *approver.device_id(),
        approver_day_index: approver.day_index(),
        approved_unix,
        approver_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::policy::mint_policy;
    use super::super::proposal::{propose_operation, OPERATION_DIGEST_LEN};
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn three_devices() -> (
        MasterIdentity,
        DeviceSubkey,
        DeviceSubkey,
        DeviceSubkey,
        crate::quorum::policy::QuorumPolicy,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id1 = fresh_device_id(&mut OsRng);
        let id2 = fresh_device_id(&mut OsRng);
        let id3 = fresh_device_id(&mut OsRng);
        let (sk1, _) = mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
        let (sk2, _) = mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
        let (sk3, _) = mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
        let policy = mint_policy(&master, [0x42; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
        (master, sk1, sk2, sk3, policy)
    }

    #[test]
    fn approval_round_trips_through_verify() {
        let (_m, sk1, sk2, _sk3, policy) = three_devices();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1,
            &policy,
            [0xEE; OPERATION_DIGEST_LEN],
            [0xDA; 16],
            now,
            now + 3600,
        )
        .unwrap();
        let approval = sign_approval(&sk2, &proposal, now + 60).unwrap();
        approval.verify(&sk2.verifying_key()).unwrap();
    }

    #[test]
    fn past_deadline_rejected_at_sign() {
        let (_m, sk1, sk2, _sk3, policy) = three_devices();
        let now: u64 = 1_700_000_000;
        let proposal =
            propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100).unwrap();
        let err = sign_approval(&sk2, &proposal, now + 200).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ApprovalPastDeadline { .. }));
    }

    #[test]
    fn approval_cant_be_verified_under_different_subkey() {
        let (_m, sk1, sk2, sk3, policy) = three_devices();
        let now: u64 = 1_700_000_000;
        let proposal =
            propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100).unwrap();
        let approval = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let err = approval.verify(&sk3.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ApprovalVerifyFail));
    }

    #[test]
    fn approval_for_different_proposal_id_breaks_verify() {
        let (_m, sk1, sk2, _sk3, policy) = three_devices();
        let now: u64 = 1_700_000_000;
        let proposal =
            propose_operation(&sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100).unwrap();
        let mut approval = sign_approval(&sk2, &proposal, now + 1).unwrap();
        approval.proposal_id[0] ^= 0xFF;
        let err = approval.verify(&sk2.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ApprovalVerifyFail));
    }
}
