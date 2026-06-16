//! Master-signed onion-pubkey attestation.
//!
//! Binds a `device_id → ristretto_pubkey` mapping under the master's
//! hybrid signing key. Replicas pin the master VK once + use the
//! attestation to validate every onion hop they hear about.

use ol_pqsig::{HybridSigningKey, HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::master::MasterIdentity;
use crate::subkey::DEVICE_ID_LEN;

use super::identity::ONION_PUBKEY_LEN;

/// Domain-separation tag for the onion-attestation signing transcript.
pub const ONION_ATTESTATION_DOMAIN: &[u8] = b"OL-mesh-onion-attestation-v1";

/// Master-signed onion attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionAttestation {
    /// Device the attestation binds.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Compressed Ristretto255 onion public key.
    pub onion_pubkey: [u8; ONION_PUBKEY_LEN],
    /// First day the binding is valid for (matching the Layer-1
    /// `SubkeyAttestation` shape so revocations work uniformly).
    pub mint_day_index: u64,
    /// Last day the binding is valid for.
    pub expiry_day_index: u64,
    /// Master hybrid signature over the canonical transcript.
    pub master_sig: Vec<u8>,
}

impl OnionAttestation {
    /// Canonical bytes the master signs.
    #[must_use]
    pub fn canonical_transcript(
        device_id: &[u8; DEVICE_ID_LEN],
        onion_pubkey: &[u8; ONION_PUBKEY_LEN],
        mint_day_index: u64,
        expiry_day_index: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            ONION_ATTESTATION_DOMAIN.len() + DEVICE_ID_LEN + ONION_PUBKEY_LEN + 8 + 8,
        );
        out.extend_from_slice(ONION_ATTESTATION_DOMAIN);
        out.extend_from_slice(device_id);
        out.extend_from_slice(onion_pubkey);
        out.extend_from_slice(&mint_day_index.to_be_bytes());
        out.extend_from_slice(&expiry_day_index.to_be_bytes());
        out
    }

    /// Verify the master signature.
    pub fn verify(&self, master_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.master_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.master_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.device_id,
            &self.onion_pubkey,
            self.mint_day_index,
            self.expiry_day_index,
        );
        master_vk
            .verify(&transcript, &self.master_sig)
            .map_err(|_| DeviceMeshError::OnionAttestationVerifyFail)
    }

    /// Is `day` within the validity window?
    #[must_use]
    pub const fn covers_day(&self, day: u64) -> bool {
        day >= self.mint_day_index && day <= self.expiry_day_index
    }
}

/// Mint an onion attestation under the master.
pub fn sign_onion_attestation(
    master: &MasterIdentity,
    device_id: [u8; DEVICE_ID_LEN],
    onion_pubkey: [u8; ONION_PUBKEY_LEN],
    mint_day_index: u64,
    expiry_day_index: u64,
) -> DeviceMeshResult<OnionAttestation> {
    if expiry_day_index < mint_day_index {
        return Err(DeviceMeshError::OnionAttestationBadValidityWindow {
            mint: mint_day_index,
            expiry: expiry_day_index,
        });
    }
    let transcript = OnionAttestation::canonical_transcript(
        &device_id,
        &onion_pubkey,
        mint_day_index,
        expiry_day_index,
    );
    let signing: HybridSigningKey = master.signing_key();
    let sig = signing.sign(&transcript)?;
    Ok(OnionAttestation {
        device_id,
        onion_pubkey,
        mint_day_index,
        expiry_day_index,
        master_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::identity::derive_onion_identity;
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn sign_verify_round_trip() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master, &id);
        let att = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
        att.verify(&master.verifying_key()).unwrap();
        assert!(att.covers_day(0));
        assert!(att.covers_day(365));
        assert!(!att.covers_day(366));
    }

    #[test]
    fn wrong_master_rejected() {
        let master_a = MasterIdentity::generate(&mut OsRng);
        let master_b = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master_a, &id);
        let att = sign_onion_attestation(&master_a, id, identity.public_bytes(), 0, 365).unwrap();
        let err = att.verify(&master_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::OnionAttestationVerifyFail));
    }

    #[test]
    fn tampered_pubkey_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0xAA; DEVICE_ID_LEN];
        let identity = derive_onion_identity(&master, &id);
        let mut att = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
        att.onion_pubkey[0] ^= 0xFF;
        let err = att.verify(&master.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::OnionAttestationVerifyFail));
    }

    #[test]
    fn bad_validity_window_rejected_at_sign() {
        let master = MasterIdentity::generate(&mut OsRng);
        let err = sign_onion_attestation(
            &master,
            [0xAA; DEVICE_ID_LEN],
            [0; ONION_PUBKEY_LEN],
            100,
            50,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::OnionAttestationBadValidityWindow { .. }
        ));
    }
}
