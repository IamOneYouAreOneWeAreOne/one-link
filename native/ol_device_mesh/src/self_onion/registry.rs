//! Aggregated onion-key registry.
//!
//! Pins one [`OnionAttestation`] per device. Replicas verify each
//! attestation under the pinned master VK on ingest; lookups
//! materialise the bound pubkey for sender-side circuit construction.

use std::collections::BTreeMap;

use ol_pqsig::HybridVerifyingKey;

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::DEVICE_ID_LEN;

use super::attestation::OnionAttestation;
use super::identity::ONION_PUBKEY_LEN;

/// Registry of master-attested onion-pubkey mappings.
#[derive(Debug, Clone, Default)]
pub struct OnionKeyRegistry {
    entries: BTreeMap<[u8; DEVICE_ID_LEN], OnionAttestation>,
}

impl OnionKeyRegistry {
    /// Empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Ingest an attestation. Verifies it under `master_vk` and
    /// replaces any prior entry for the same device id.
    pub fn ingest(
        &mut self,
        att: OnionAttestation,
        master_vk: &HybridVerifyingKey,
    ) -> DeviceMeshResult<()> {
        att.verify(master_vk)?;
        self.entries.insert(att.device_id, att);
        Ok(())
    }

    /// Look up the onion pubkey bound to `device_id` at `day`.
    pub fn pubkey_for(
        &self,
        device_id: &[u8; DEVICE_ID_LEN],
        day: u64,
    ) -> DeviceMeshResult<[u8; ONION_PUBKEY_LEN]> {
        let att =
            self.entries
                .get(device_id)
                .ok_or(DeviceMeshError::OnionRegistryDeviceMissing {
                    device_id: *device_id,
                })?;
        if !att.covers_day(day) {
            return Err(DeviceMeshError::OnionRegistryDayOutOfWindow {
                device_id: *device_id,
                day,
                mint: att.mint_day_index,
                expiry: att.expiry_day_index,
            });
        }
        Ok(att.onion_pubkey)
    }

    /// Iterator over `(device_id, attestation)` pairs in deterministic order.
    pub fn entries(&self) -> impl Iterator<Item = (&[u8; DEVICE_ID_LEN], &OnionAttestation)> {
        self.entries.iter()
    }

    /// Number of attestations held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True iff no attestations.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::super::attestation::sign_onion_attestation;
    use super::super::identity::derive_onion_identity;
    use super::*;
    use crate::master::MasterIdentity;
    use rand::rngs::OsRng;

    #[test]
    fn ingest_and_lookup() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master, &id);
        let att = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
        let mut reg = OnionKeyRegistry::empty();
        reg.ingest(att, &master.verifying_key()).unwrap();
        let pk = reg.pubkey_for(&id, 100).unwrap();
        assert_eq!(pk, identity.public_bytes());
    }

    #[test]
    fn lookup_missing_device_errors() {
        let reg = OnionKeyRegistry::empty();
        let err = reg.pubkey_for(&[0xBB; DEVICE_ID_LEN], 1).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::OnionRegistryDeviceMissing { .. }
        ));
    }

    #[test]
    fn lookup_out_of_window_errors() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master, &id);
        let att = sign_onion_attestation(&master, id, identity.public_bytes(), 10, 100).unwrap();
        let mut reg = OnionKeyRegistry::empty();
        reg.ingest(att, &master.verifying_key()).unwrap();
        let err = reg.pubkey_for(&id, 5).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::OnionRegistryDayOutOfWindow { .. }
        ));
    }

    #[test]
    fn ingest_under_wrong_master_rejected() {
        let master_a = MasterIdentity::generate(&mut OsRng);
        let master_b = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master_a, &id);
        let att = sign_onion_attestation(&master_a, id, identity.public_bytes(), 0, 365).unwrap();
        let mut reg = OnionKeyRegistry::empty();
        let err = reg.ingest(att, &master_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::OnionAttestationVerifyFail));
    }
}
