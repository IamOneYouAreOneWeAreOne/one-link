//! Master-signed quorum policy.
//!
//! A policy describes WHICH devices count for a class of operations
//! and HOW MANY of them must approve. Master signs it; every device
//! pins the policy bytes.

use blake3::Hasher;
use ol_pqsig::{HybridSigningKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::master::MasterIdentity;
use crate::subkey::DEVICE_ID_LEN;

/// Length of the canonical policy identifier (random 16 bytes —
/// chosen by master at mint, treated as opaque by everyone else).
pub const POLICY_ID_LEN: usize = 16;

/// Length of a [`QuorumPolicyId`].
pub type QuorumPolicyId = [u8; POLICY_ID_LEN];

/// Maximum allowed length of a policy's human-readable label.
pub const POLICY_LABEL_MAX: usize = 64;

/// Domain-separation tag for the policy-signing transcript.
pub const POLICY_DOMAIN: &[u8] = b"OL-device-mesh-policy-v1";

/// A master-signed quorum policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumPolicy {
    /// Stable identifier for this policy. Chosen by the master at
    /// mint; higher layers reference it by id.
    pub policy_id: QuorumPolicyId,
    /// Human-readable label (e.g. `b"high-stakes-cap-grant"`).
    /// Length-bounded; signed into the transcript.
    pub label: Vec<u8>,
    /// Threshold: how many approvals are required. MUST be ≥ 1 and
    /// ≤ `eligible_devices.len()`.
    pub k: u8,
    /// Devices that count for approving this policy's operations.
    /// Stable per master signature; revoking a device requires
    /// re-signing a new policy.
    pub eligible_devices: Vec<[u8; DEVICE_ID_LEN]>,
    /// Master's hybrid signature over the canonical transcript.
    pub master_sig: Vec<u8>,
}

impl QuorumPolicy {
    /// Canonical bytes the master signs over.
    #[must_use]
    pub fn canonical_transcript(
        policy_id: &QuorumPolicyId,
        label: &[u8],
        k: u8,
        eligible_devices: &[[u8; DEVICE_ID_LEN]],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            POLICY_DOMAIN.len()
                + POLICY_ID_LEN
                + 2
                + label.len()
                + 1
                + 2
                + eligible_devices.len() * DEVICE_ID_LEN,
        );
        out.extend_from_slice(POLICY_DOMAIN);
        out.extend_from_slice(policy_id);
        let label_len = u16::try_from(label.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&label_len.to_be_bytes());
        out.extend_from_slice(label);
        out.push(k);
        let n = u16::try_from(eligible_devices.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for id in eligible_devices {
            out.extend_from_slice(id);
        }
        out
    }

    /// Verify the master signature on this policy.
    pub fn verify(&self, master_vk: &ol_pqsig::HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = Self::canonical_transcript(
            &self.policy_id,
            &self.label,
            self.k,
            &self.eligible_devices,
        );
        master_vk
            .verify(&transcript, &self.master_sig)
            .map_err(|_| DeviceMeshError::PolicyVerifyFail)
    }

    /// Return whether `device_id` is in the eligible list.
    #[must_use]
    pub fn is_eligible(&self, device_id: &[u8; DEVICE_ID_LEN]) -> bool {
        self.eligible_devices.iter().any(|d| d == device_id)
    }

    /// BLAKE3 commitment of the canonical transcript. Higher layers
    /// use this as the policy's content-addressed handle.
    #[must_use]
    pub fn handle(&self) -> [u8; 32] {
        let transcript = Self::canonical_transcript(
            &self.policy_id,
            &self.label,
            self.k,
            &self.eligible_devices,
        );
        let mut h = Hasher::new();
        h.update(b"OL-device-mesh-policy-handle-v1");
        h.update(&transcript);
        *h.finalize().as_bytes()
    }

    fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.label.len() > POLICY_LABEL_MAX {
            return Err(DeviceMeshError::PolicyLabelTooLong {
                got: self.label.len(),
                max: POLICY_LABEL_MAX,
            });
        }
        if self.eligible_devices.is_empty() {
            return Err(DeviceMeshError::PolicyEmptyRoster);
        }
        if self.eligible_devices.len() > super::certificate::MAX_ELIGIBLE_DEVICES {
            return Err(DeviceMeshError::PolicyRosterTooLarge {
                got: self.eligible_devices.len(),
                max: super::certificate::MAX_ELIGIBLE_DEVICES,
            });
        }
        if self.k == 0 || (self.k as usize) > self.eligible_devices.len() {
            return Err(DeviceMeshError::PolicyBadThreshold {
                k: self.k,
                n: self.eligible_devices.len(),
            });
        }
        // Reject duplicate device IDs in the roster — otherwise a
        // duplicate could be used to inflate the apparent K.
        let mut sorted = self.eligible_devices.clone();
        sorted.sort_unstable();
        let dedup_len = {
            let mut s = sorted.clone();
            s.dedup();
            s.len()
        };
        if dedup_len != sorted.len() {
            return Err(DeviceMeshError::PolicyDuplicateRoster);
        }
        if self.master_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.master_sig.len(),
            });
        }
        Ok(())
    }
}

/// Mint a fresh quorum policy: master signs the canonical transcript
/// and returns the populated struct.
pub fn mint_policy(
    master: &MasterIdentity,
    policy_id: QuorumPolicyId,
    label: &[u8],
    k: u8,
    eligible_devices: Vec<[u8; DEVICE_ID_LEN]>,
) -> DeviceMeshResult<QuorumPolicy> {
    let policy_unsigned = QuorumPolicy {
        policy_id,
        label: label.to_vec(),
        k,
        eligible_devices,
        master_sig: vec![0u8; HYBRID_SIG_LEN], // placeholder for shape_check
    };
    policy_unsigned.shape_check()?;
    let transcript = QuorumPolicy::canonical_transcript(
        &policy_unsigned.policy_id,
        &policy_unsigned.label,
        policy_unsigned.k,
        &policy_unsigned.eligible_devices,
    );
    let master_signing: HybridSigningKey = master.signing_key();
    let sig = master_signing.sign(&transcript)?;
    Ok(QuorumPolicy {
        policy_id: policy_unsigned.policy_id,
        label: policy_unsigned.label,
        k: policy_unsigned.k,
        eligible_devices: policy_unsigned.eligible_devices,
        master_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_master() -> MasterIdentity {
        MasterIdentity::generate(&mut OsRng)
    }

    fn ids(n: usize) -> Vec<[u8; DEVICE_ID_LEN]> {
        (0..n)
            .map(|i| {
                let mut x = [0u8; DEVICE_ID_LEN];
                x[0] = i as u8;
                x
            })
            .collect()
    }

    #[test]
    fn mint_and_verify_round_trip() {
        let master = make_master();
        let policy = mint_policy(&master, [0x01; 16], b"label", 2, ids(3)).unwrap();
        policy.verify(&master.verifying_key()).unwrap();
    }

    #[test]
    fn mint_wrong_master_rejects_verify() {
        let master_a = make_master();
        let master_b = make_master();
        let policy = mint_policy(&master_a, [0x01; 16], b"label", 2, ids(3)).unwrap();
        let err = policy.verify(&master_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyVerifyFail));
    }

    #[test]
    fn empty_roster_rejected_at_mint() {
        let master = make_master();
        let err = mint_policy(&master, [0x01; 16], b"label", 1, vec![]).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyEmptyRoster));
    }

    #[test]
    fn duplicate_roster_rejected_at_mint() {
        let master = make_master();
        let mut v = ids(2);
        v.push(v[0]);
        let err = mint_policy(&master, [0x01; 16], b"label", 2, v).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyDuplicateRoster));
    }

    #[test]
    fn threshold_too_large_rejected_at_mint() {
        let master = make_master();
        let err = mint_policy(&master, [0x01; 16], b"label", 4, ids(3)).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyBadThreshold { .. }));
    }

    #[test]
    fn zero_threshold_rejected_at_mint() {
        let master = make_master();
        let err = mint_policy(&master, [0x01; 16], b"label", 0, ids(3)).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyBadThreshold { .. }));
    }

    #[test]
    fn label_too_long_rejected_at_mint() {
        let master = make_master();
        let long = vec![b'a'; POLICY_LABEL_MAX + 1];
        let err = mint_policy(&master, [0x01; 16], &long, 2, ids(3)).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyLabelTooLong { .. }));
    }

    #[test]
    fn handle_is_deterministic() {
        let master = make_master();
        let p = mint_policy(&master, [0x01; 16], b"x", 2, ids(3)).unwrap();
        assert_eq!(p.handle(), p.handle());
    }

    #[test]
    fn tampered_label_breaks_verify() {
        let master = make_master();
        let mut p = mint_policy(&master, [0x01; 16], b"label", 2, ids(3)).unwrap();
        p.label = b"forged".to_vec();
        let err = p.verify(&master.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyVerifyFail));
    }

    #[test]
    fn tampered_k_breaks_verify() {
        let master = make_master();
        let mut p = mint_policy(&master, [0x01; 16], b"label", 2, ids(3)).unwrap();
        p.k = 1;
        let err = p.verify(&master.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::PolicyVerifyFail));
    }
}
