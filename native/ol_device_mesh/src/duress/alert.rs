//! Signed "I'm under duress" broadcast.
//!
//! When a [`super::DuressEnvelope::unlock`] returns
//! [`super::UnlockOutcome::Decoy`], the daemon SILENTLY signs a
//! [`DuressAlert`] using the seized device's subkey and emits it to
//! every sibling. Siblings validate the signature under the
//! master-attested subkey VK and escalate to a Layer-2 quorum
//! revocation. The seized device continues running in decoy mode so
//! the captor doesn't notice.

use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

/// Domain-separation tag for duress-alert signing.
pub const DUR_ALERT_DOMAIN: &[u8] = b"OL-mesh-duress-alert-v1";

/// One signed duress alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuressAlert {
    /// The seized device.
    pub triggered_device_id: [u8; DEVICE_ID_LEN],
    /// Subkey day-index at sign time.
    pub triggered_day_index: u64,
    /// Wall-clock seconds the alert was issued.
    pub triggered_unix: u64,
    /// 16-byte random nonce so replays are detectable per
    /// proposal_id-style dedup at receivers.
    pub nonce: [u8; 16],
    /// Subkey signature over the canonical transcript.
    pub subkey_sig: Vec<u8>,
}

impl DuressAlert {
    /// Canonical bytes the subkey signs over.
    #[must_use] 
    pub fn canonical_transcript(
        triggered_device_id: &[u8; DEVICE_ID_LEN],
        triggered_day_index: u64,
        triggered_unix: u64,
        nonce: &[u8; 16],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            DUR_ALERT_DOMAIN.len() + DEVICE_ID_LEN + 8 + 8 + 16,
        );
        out.extend_from_slice(DUR_ALERT_DOMAIN);
        out.extend_from_slice(triggered_device_id);
        out.extend_from_slice(&triggered_day_index.to_be_bytes());
        out.extend_from_slice(&triggered_unix.to_be_bytes());
        out.extend_from_slice(nonce);
        out
    }

    /// Verify under the seized device's subkey VK (which receivers
    /// have via the Layer-1 `SubkeyAttestation` cache).
    pub fn verify(&self, subkey_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.subkey_sig.len() != HYBRID_SIG_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_SIG_LEN,
                got: self.subkey_sig.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            &self.triggered_device_id,
            self.triggered_day_index,
            self.triggered_unix,
            &self.nonce,
        );
        subkey_vk
            .verify(&transcript, &self.subkey_sig)
            .map_err(|_| DeviceMeshError::DuressAlertVerifyFail)
    }
}

/// Sign a duress alert using the seized device's subkey.
pub fn sign_duress_alert(
    subkey: &DeviceSubkey,
    triggered_unix: u64,
    nonce: [u8; 16],
) -> DeviceMeshResult<DuressAlert> {
    let transcript = DuressAlert::canonical_transcript(
        subkey.device_id(),
        subkey.day_index(),
        triggered_unix,
        &nonce,
    );
    let sig = subkey.sign(&transcript)?;
    Ok(DuressAlert {
        triggered_device_id: *subkey.device_id(),
        triggered_day_index: subkey.day_index(),
        triggered_unix,
        nonce,
        subkey_sig: sig.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use crate::DeviceClass;
    use rand::rngs::OsRng;

    fn make_sk() -> DeviceSubkey {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = make_sk();
        let alert = sign_duress_alert(&sk, 1_700_000_000, [0xAA; 16]).unwrap();
        alert.verify(&sk.verifying_key()).unwrap();
    }

    #[test]
    fn tampered_nonce_breaks_verify() {
        let sk = make_sk();
        let mut alert =
            sign_duress_alert(&sk, 1_700_000_000, [0xAA; 16]).unwrap();
        alert.nonce[0] ^= 0xFF;
        let err = alert.verify(&sk.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::DuressAlertVerifyFail));
    }

    #[test]
    fn cross_subkey_rejected() {
        let sk_a = make_sk();
        let sk_b = make_sk();
        let alert =
            sign_duress_alert(&sk_a, 1_700_000_000, [0xAA; 16]).unwrap();
        let err = alert.verify(&sk_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::DuressAlertVerifyFail));
    }
}
