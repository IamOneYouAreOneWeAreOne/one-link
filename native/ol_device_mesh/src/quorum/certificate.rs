//! Quorum certificate: end-to-end verifiable record of K-of-N approval.
//!
//! The certificate carries everything a verifier needs to confirm
//! "the master, whose VK is X, has authorized this operation through
//! a K-of-N quorum of its device mesh."

use std::collections::HashSet;

use ol_pqsig::{HybridVerifyingKey, HYBRID_VK_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{SubkeyAttestation, DEVICE_ID_LEN};

use super::approval::QuorumApproval;
use super::policy::QuorumPolicy;
use super::proposal::QuorumProposal;

/// Maximum allowed approvals in one certificate. Bounded to keep
/// verification cost predictable and reject amplification.
pub const MAX_APPROVALS: usize = 64;

/// Maximum size of a policy's eligible-devices roster.
pub const MAX_ELIGIBLE_DEVICES: usize = 64;

/// A fully-formed quorum certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumCertificate {
    /// The proposal being authorised.
    pub proposal: QuorumProposal,
    /// At least `proposal.policy.k` approvals from distinct
    /// eligible devices.
    pub approvals: Vec<QuorumApproval>,
    /// The policy that governs this proposal (master-signed).
    pub policy: QuorumPolicy,
    /// `SubkeyAttestation` cache for every signer (issuer + approvers).
    /// Verifier looks up each signer's VK here instead of going off-
    /// network. Order is irrelevant; lookup is by device id.
    pub subkey_attestations: Vec<SubkeyAttestation>,
}

impl QuorumCertificate {
    /// End-to-end verify this certificate under `master_vk`.
    ///
    /// `now_unix` is the verifier's current wall-clock. The proposal
    /// must not yet be past its `deadline_unix`.
    pub fn verify(
        &self,
        master_vk: &HybridVerifyingKey,
        now_unix: u64,
    ) -> DeviceMeshResult<()> {
        // (0) Shape: bounded approvals + bounded roster.
        if self.approvals.len() > MAX_APPROVALS {
            return Err(DeviceMeshError::CertTooManyApprovals {
                got: self.approvals.len(),
                max: MAX_APPROVALS,
            });
        }
        if self.policy.eligible_devices.len() > MAX_ELIGIBLE_DEVICES {
            return Err(DeviceMeshError::PolicyRosterTooLarge {
                got: self.policy.eligible_devices.len(),
                max: MAX_ELIGIBLE_DEVICES,
            });
        }

        // (1) Policy signed by master.
        self.policy.verify(master_vk)?;

        // (2) Every subkey attestation signed by master.
        for att in &self.subkey_attestations {
            att.verify(master_vk)?;
        }

        // (3) Proposal binds to this policy.
        if self.proposal.policy_id != self.policy.policy_id {
            return Err(DeviceMeshError::CertProposalPolicyMismatch);
        }

        // (4) Proposal hasn't expired vs verifier wall clock.
        if now_unix > self.proposal.deadline_unix {
            return Err(DeviceMeshError::CertProposalExpired {
                deadline_unix: self.proposal.deadline_unix,
                now_unix,
            });
        }

        // (5) Issuer is eligible.
        if !self.policy.is_eligible(&self.proposal.issuer_device_id) {
            return Err(DeviceMeshError::IssuerNotEligible {
                device_id: self.proposal.issuer_device_id,
            });
        }

        // (6) Issuer signature verifies under its attested subkey VK.
        let issuer_vk = self.subkey_vk_for(
            &self.proposal.issuer_device_id,
            self.proposal.issuer_day_index,
        )?;
        self.proposal.verify_issuer(&issuer_vk)?;

        // (7) Each approval is signed by its approver's attested VK,
        // commits to THIS proposal's id, is from an eligible device,
        // is within the deadline, and the approver-set is distinct.
        let proposal_id = self.proposal.proposal_id();
        let mut seen: HashSet<[u8; DEVICE_ID_LEN]> = HashSet::new();
        for a in &self.approvals {
            if a.proposal_id != proposal_id {
                return Err(DeviceMeshError::ApprovalForOtherProposal);
            }
            if a.approved_unix > self.proposal.deadline_unix {
                return Err(DeviceMeshError::ApprovalPastDeadline {
                    approved_unix: a.approved_unix,
                    deadline_unix: self.proposal.deadline_unix,
                });
            }
            if !self.policy.is_eligible(&a.approver_device_id) {
                return Err(DeviceMeshError::ApproverNotEligible {
                    device_id: a.approver_device_id,
                });
            }
            if !seen.insert(a.approver_device_id) {
                return Err(DeviceMeshError::DuplicateApprover {
                    device_id: a.approver_device_id,
                });
            }
            let approver_vk =
                self.subkey_vk_for(&a.approver_device_id, a.approver_day_index)?;
            a.verify(&approver_vk)?;
        }

        // (8) Distinct-approver count meets the threshold.
        if seen.len() < (self.policy.k as usize) {
            return Err(DeviceMeshError::CertBelowThreshold {
                got: seen.len(),
                needed: self.policy.k,
            });
        }

        Ok(())
    }

    /// Look up a signer's hybrid verifying key from the attestation
    /// cache. The attestation must already verify under the master
    /// (caller is responsible — `verify` checks this in step (2)
    /// before any lookup in step (6)+).
    fn subkey_vk_for(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        day_index: u64,
    ) -> DeviceMeshResult<HybridVerifyingKey> {
        for att in &self.subkey_attestations {
            if &att.device_id == device_id && att.covers_day(day_index) {
                if att.subkey_vk_bytes.len() != HYBRID_VK_LEN {
                    return Err(DeviceMeshError::BadLength {
                        expected: HYBRID_VK_LEN,
                        got: att.subkey_vk_bytes.len(),
                    });
                }
                return HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes)
                    .map_err(DeviceMeshError::from);
            }
        }
        Err(DeviceMeshError::AttestationMissing {
            device_id: *device_id,
            day_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::quorum::approval::sign_approval;
    use crate::quorum::policy::mint_policy;
    use crate::quorum::proposal::{propose_operation, OPERATION_DIGEST_LEN};
    use crate::subkey::{fresh_device_id, mint_subkey, DeviceSubkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn happy_path() -> (
        MasterIdentity,
        QuorumPolicy,
        DeviceSubkey, DeviceSubkey, DeviceSubkey,
        SubkeyAttestation, SubkeyAttestation, SubkeyAttestation,
    ) {
        let master = MasterIdentity::generate(&mut OsRng);
        let id1 = fresh_device_id(&mut OsRng);
        let id2 = fresh_device_id(&mut OsRng);
        let id3 = fresh_device_id(&mut OsRng);
        let (sk1, a1) =
            mint_subkey(&master, DeviceClass::Phone, id1, 0, 365).unwrap();
        let (sk2, a2) =
            mint_subkey(&master, DeviceClass::Laptop, id2, 0, 365).unwrap();
        let (sk3, a3) =
            mint_subkey(&master, DeviceClass::Desktop, id3, 0, 365).unwrap();
        let policy =
            mint_policy(&master, [0x42; 16], b"p", 2, vec![id1, id2, id3]).unwrap();
        (master, policy, sk1, sk2, sk3, a1, a2, a3)
    }

    #[test]
    fn end_to_end_verify() {
        let (master, policy, sk1, sk2, sk3, a1, a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; OPERATION_DIGEST_LEN], [0xDA; 16],
            now, now + 3600,
        )
        .unwrap();
        let appr2 = sign_approval(&sk2, &proposal, now + 60).unwrap();
        let appr3 = sign_approval(&sk3, &proposal, now + 120).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![appr2, appr3],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        cert.verify(&master.verifying_key(), now + 200).unwrap();
    }

    #[test]
    fn below_threshold_rejected() {
        let (master, policy, sk1, sk2, _sk3, a1, a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        let only_one = sign_approval(&sk2, &proposal, now + 60).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![only_one], // need 2; have 1
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        let err = cert.verify(&master.verifying_key(), now + 200).unwrap_err();
        assert!(matches!(err, DeviceMeshError::CertBelowThreshold { .. }));
    }

    #[test]
    fn expired_proposal_rejected() {
        let (master, policy, sk1, sk2, sk3, a1, a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 100,
        )
        .unwrap();
        let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2, ap3],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        // Verifier is 1000s past the deadline.
        let err = cert
            .verify(&master.verifying_key(), now + 2000)
            .unwrap_err();
        assert!(matches!(err, DeviceMeshError::CertProposalExpired { .. }));
    }

    #[test]
    fn duplicate_approver_rejected() {
        let (master, policy, sk1, sk2, _sk3, a1, a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        let ap_a = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let ap_b = sign_approval(&sk2, &proposal, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap_a, ap_b], // both from sk2
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
        assert!(matches!(err, DeviceMeshError::DuplicateApprover { .. }));
    }

    #[test]
    fn approval_for_other_proposal_rejected() {
        let (master, policy, sk1, sk2, sk3, a1, a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let real = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        let other = propose_operation(
            &sk1, &policy, [0xFF; 32], [0xDB; 16], now, now + 3600,
        )
        .unwrap();
        // Sign approval against "other" but stuff into "real" cert.
        let bad = sign_approval(&sk2, &other, now + 1).unwrap();
        let good = sign_approval(&sk3, &real, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal: real,
            approvals: vec![bad, good],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
        assert!(matches!(err, DeviceMeshError::ApprovalForOtherProposal));
    }

    #[test]
    fn missing_attestation_rejected() {
        let (master, policy, sk1, sk2, sk3, a1, _a2, a3) = happy_path();
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2, ap3],
            policy,
            // a2 deliberately missing
            subkey_attestations: vec![a1, a3],
        };
        let err = cert.verify(&master.verifying_key(), now + 100).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AttestationMissing { .. }));
    }

    #[test]
    fn cross_master_certificate_rejected() {
        let (master_a, policy, sk1, sk2, sk3, a1, a2, a3) = happy_path();
        let master_b = MasterIdentity::generate(&mut OsRng);
        let now: u64 = 1_700_000_000;
        let proposal = propose_operation(
            &sk1, &policy, [0xEE; 32], [0xDA; 16], now, now + 3600,
        )
        .unwrap();
        let ap2 = sign_approval(&sk2, &proposal, now + 1).unwrap();
        let ap3 = sign_approval(&sk3, &proposal, now + 2).unwrap();
        let cert = QuorumCertificate {
            proposal,
            approvals: vec![ap2, ap3],
            policy,
            subkey_attestations: vec![a1, a2, a3],
        };
        let err = cert
            .verify(&master_b.verifying_key(), now + 100)
            .unwrap_err();
        // Policy verify is the first thing to fail.
        assert!(matches!(err, DeviceMeshError::PolicyVerifyFail));
        let _ = master_a;
    }
}
