//! Aggregated capability registry.

use std::collections::BTreeMap;

use ol_pqsig::HybridVerifyingKey;

use crate::errors::DeviceMeshResult;
use crate::subkey::DEVICE_ID_LEN;

use super::attestation::CapabilityAttestation;
use super::capability::DeviceCapability;

/// Registry of master-attested device capabilities.
#[derive(Debug, Clone, Default)]
pub struct CapabilityRegistry {
    entries: BTreeMap<[u8; DEVICE_ID_LEN], CapabilityAttestation>,
}

impl CapabilityRegistry {
    /// Empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Ingest an attestation. Verifies under `master_vk` and
    /// replaces any prior entry for the same device id.
    pub fn ingest(
        &mut self,
        att: CapabilityAttestation,
        master_vk: &HybridVerifyingKey,
    ) -> DeviceMeshResult<()> {
        att.verify(master_vk)?;
        self.entries.insert(att.device_id, att);
        Ok(())
    }

    /// Devices that ALL hold the requested capability set at `day`.
    /// Returns ids in deterministic order.
    #[must_use]
    pub fn devices_with(
        &self,
        capabilities: &[DeviceCapability],
        day: u64,
    ) -> Vec<[u8; DEVICE_ID_LEN]> {
        let mut out = Vec::new();
        for (id, att) in &self.entries {
            if !att.covers_day(day) {
                continue;
            }
            let all = capabilities.iter().all(|c| att.has(*c));
            if all {
                out.push(*id);
            }
        }
        out
    }

    /// Lookup an attestation by device id.
    #[must_use]
    pub fn attestation_for(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
    ) -> Option<&CapabilityAttestation> {
        self.entries.get(device_id)
    }

    /// Number of attested devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::attestation::sign_capability_attestation;
    use super::*;
    use crate::master::MasterIdentity;
    use rand::rngs::OsRng;

    #[test]
    fn devices_with_filters_correctly() {
        let master = MasterIdentity::generate(&mut OsRng);
        let phone = [0x11; DEVICE_ID_LEN];
        let desktop = [0x22; DEVICE_ID_LEN];
        let mut reg = CapabilityRegistry::empty();
        reg.ingest(
            sign_capability_attestation(
                &master,
                phone,
                vec![DeviceCapability::Microphone, DeviceCapability::Camera],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        reg.ingest(
            sign_capability_attestation(
                &master,
                desktop,
                vec![DeviceCapability::Gpu, DeviceCapability::CpuHeavy, DeviceCapability::AlwaysOn],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        let gpu_devices =
            reg.devices_with(&[DeviceCapability::Gpu], 100);
        assert_eq!(gpu_devices, vec![desktop]);
        let mic_devices =
            reg.devices_with(&[DeviceCapability::Microphone], 100);
        assert_eq!(mic_devices, vec![phone]);
    }

    #[test]
    fn devices_with_outside_window_excluded() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0x33; DEVICE_ID_LEN];
        let mut reg = CapabilityRegistry::empty();
        reg.ingest(
            sign_capability_attestation(
                &master,
                id,
                vec![DeviceCapability::Gpu],
                10,
                100,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        assert!(reg.devices_with(&[DeviceCapability::Gpu], 5).is_empty());
        assert_eq!(
            reg.devices_with(&[DeviceCapability::Gpu], 50),
            vec![id]
        );
        assert!(reg.devices_with(&[DeviceCapability::Gpu], 200).is_empty());
    }

    #[test]
    fn empty_capability_query_returns_all_in_window() {
        let master = MasterIdentity::generate(&mut OsRng);
        let mut reg = CapabilityRegistry::empty();
        reg.ingest(
            sign_capability_attestation(
                &master,
                [0x11; DEVICE_ID_LEN],
                vec![DeviceCapability::Gpu],
                0,
                365,
            )
            .unwrap(),
            &master.verifying_key(),
        )
        .unwrap();
        let all = reg.devices_with(&[], 100);
        assert_eq!(all.len(), 1);
    }
}
