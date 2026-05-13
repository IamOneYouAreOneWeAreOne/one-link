//! Master-signed device-capability attestation.

use ol_pqsig::{HybridSigningKey, HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::master::MasterIdentity;
use crate::subkey::DEVICE_ID_LEN;

use super::capability::{DeviceCapability, MAX_CAPABILITIES_PER_DEVICE};

/// Domain-separation tag for capability-attestation signing.
pub const CAPABILITY_ATTESTATION_DOMAIN: &[u8] =
    b"OL-mesh-capability-attestation-v1";

/// One master-signed capability binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityAttestation {
    /// The device the attestation binds.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Sorted, de-duplicated capability list.
    pub capabilities: Vec<DeviceCapability>,
    /// First day index the binding is valid for.
    pub mint_day_index: u64,
    /// Last day index the binding is valid for.
    pub expiry_day_index: u64,
    /// Master hybrid signature over the canonical transcript.
    pub master_sig: Vec<u8>,
}

impl CapabilityAttestation {
    /// Canonical bytes the master signs.
    pub fn canonical_transcript(
        device_id: &[u8; DEVICE_ID_LEN],
        capabilities: &[DeviceCapability],
        mint_day_index: u64,
        expiry_day_index: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            CAPABILITY_ATTESTATION_DOMAIN.len()
                + DEVICE_ID_LEN
                + 2
                + capabilities.len() * 8
                + 8
                + 8,
        );
        out.extend_from_slice(CAPABILITY_ATTESTATION_DOMAIN);
        out.extend_from_slice(device_id);
        let count = u16::try_from(capabilities.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for c in capabilities {
            out.extend_from_slice(&c.tag());
        }
        out.extend_from_slice(&mint_day_index.to_be_bytes());
        out.extend_from_slice(&expiry_day_index.to_be_bytes());
        out
    }

    /// Validate shape (sorted + de-duplicated + bounded).
    pub fn shape_check(&self) -> DeviceMeshResult<()> {
        if self.capabilities.len() > MAX_CAPABILITIES_PER_DEVICE {
            return Err(DeviceMeshError::CapabilityAttestationTooMany {
                got: self.capabilities.len(),
                max: MAX_CAPABILITIES_PER_DEVICE,
            });
        }
        let mut prev: Option<DeviceCapability> = None;
        for c in &self.capabilities {
            if let Some(p) = prev {
                if *c <= p {
                    return Err(DeviceMeshError::CapabilityAttestationNotSorted);
                }
            }
            prev = Some(*c);
        }
        if self.expiry_day_index < self.mint_day_index {
            return Err(DeviceMeshError::CapabilityAttestationBadValidityWindow {
                mint: self.mint_day_index,
                expiry: self.expiry_day_index,
            });
        }
        if self.master_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.master_sig.len(),
            });
        }
        Ok(())
    }

    /// Verify the master signature.
    pub fn verify(&self, master_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        self.shape_check()?;
        let transcript = Self::canonical_transcript(
            &self.device_id,
            &self.capabilities,
            self.mint_day_index,
            self.expiry_day_index,
        );
        master_vk
            .verify(&transcript, &self.master_sig)
            .map_err(|_| DeviceMeshError::CapabilityAttestationVerifyFail)
    }

    /// Does this attestation cover `day`?
    #[must_use]
    pub fn covers_day(&self, day: u64) -> bool {
        day >= self.mint_day_index && day <= self.expiry_day_index
    }

    /// Does this attestation include `cap`?
    #[must_use]
    pub fn has(&self, cap: DeviceCapability) -> bool {
        self.capabilities.binary_search(&cap).is_ok()
    }
}

/// Master signs a capability attestation. Sorts + de-duplicates the
/// capability list at sign time so two devices with the same
/// capabilities produce byte-identical transcripts.
pub fn sign_capability_attestation(
    master: &MasterIdentity,
    device_id: [u8; DEVICE_ID_LEN],
    mut capabilities: Vec<DeviceCapability>,
    mint_day_index: u64,
    expiry_day_index: u64,
) -> DeviceMeshResult<CapabilityAttestation> {
    if expiry_day_index < mint_day_index {
        return Err(DeviceMeshError::CapabilityAttestationBadValidityWindow {
            mint: mint_day_index,
            expiry: expiry_day_index,
        });
    }
    capabilities.sort();
    capabilities.dedup();
    if capabilities.len() > MAX_CAPABILITIES_PER_DEVICE {
        return Err(DeviceMeshError::CapabilityAttestationTooMany {
            got: capabilities.len(),
            max: MAX_CAPABILITIES_PER_DEVICE,
        });
    }
    let transcript = CapabilityAttestation::canonical_transcript(
        &device_id,
        &capabilities,
        mint_day_index,
        expiry_day_index,
    );
    let signing: HybridSigningKey = master.signing_key();
    let sig = signing.sign(&transcript)?;
    Ok(CapabilityAttestation {
        device_id,
        capabilities,
        mint_day_index,
        expiry_day_index,
        master_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let master = MasterIdentity::generate(&mut OsRng);
        let att = sign_capability_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            vec![DeviceCapability::Gpu, DeviceCapability::CpuHeavy],
            0,
            365,
        )
        .unwrap();
        att.verify(&master.verifying_key()).unwrap();
        assert!(att.has(DeviceCapability::Gpu));
        assert!(att.has(DeviceCapability::CpuHeavy));
        assert!(!att.has(DeviceCapability::Camera));
        assert!(att.covers_day(0));
        assert!(att.covers_day(365));
        assert!(!att.covers_day(366));
    }

    #[test]
    fn duplicates_collapse_at_sign() {
        let master = MasterIdentity::generate(&mut OsRng);
        let att = sign_capability_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            vec![
                DeviceCapability::Gpu,
                DeviceCapability::Gpu,
                DeviceCapability::CpuHeavy,
            ],
            0,
            365,
        )
        .unwrap();
        assert_eq!(att.capabilities.len(), 2);
    }

    #[test]
    fn bad_validity_window_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let err = sign_capability_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            vec![DeviceCapability::Gpu],
            100,
            50,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::CapabilityAttestationBadValidityWindow { .. }
        ));
    }

    #[test]
    fn unsorted_post_sign_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut att = sign_capability_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            vec![
                DeviceCapability::Gpu,
                DeviceCapability::CpuHeavy,
                DeviceCapability::Camera,
            ],
            0,
            365,
        )
        .unwrap();
        att.capabilities.swap(0, 2);
        let err = att.verify(&master.verifying_key()).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::CapabilityAttestationNotSorted
        ));
    }

    #[test]
    fn wrong_master_rejected() {
        let master_a = MasterIdentity::generate(&mut OsRng);
        let master_b = MasterIdentity::generate(&mut OsRng);
        let att = sign_capability_attestation(
            &master_a,
            [0xAA; DEVICE_ID_LEN],
            vec![DeviceCapability::Gpu],
            0,
            365,
        )
        .unwrap();
        let err = att.verify(&master_b.verifying_key()).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::CapabilityAttestationVerifyFail
        ));
    }
}
