//! Per-device subkey and master-signed attestation.
//!
//! A [`DeviceSubkey`] is the working signing key on one physical
//! device. It's a [`ol_pqsig::HybridSigningKey`] derived
//! deterministically from the master seed plus a transcript of
//! `(device_class, device_id, day_index)` — see
//! [`crate::derivation`].
//!
//! Devices NEVER advertise their subkey verifying key directly.
//! Instead the master mints a [`SubkeyAttestation`] that binds:
//! - the subkey's verifying-key bytes,
//! - the device class + ID,
//! - the day index at mint,
//! - an expiry day index (the chain horizon),
//! and signs the whole transcript under the master's hybrid signing
//! key. Friends pin the master pubkey and verify each subkey via the
//! master's signature on the attestation. From a friend's POV there
//! is still ONE identity.

use blake3::Hasher;
use ol_pqsig::{HybridSigningKey, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::derivation::{
    derive_field_bound_subkey_seed, derive_subkey_seed, SUBKEY_SEED_LEN,
};
use crate::device_class::{DeviceClass, DEVICE_CLASS_TAG_LEN};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::master::MasterIdentity;

/// Length of the per-device identifier.
pub const DEVICE_ID_LEN: usize = 16;

/// Domain-separation tag for the subkey-attestation signing transcript.
pub const SUBKEY_ATTESTATION_DOMAIN: &[u8] = b"OL-device-mesh-attestation-v1";

/// One device's working signing key. Sized exactly like the master
/// but lives in a single device's RAM and ratchets daily.
#[derive(ZeroizeOnDrop)]
pub struct DeviceSubkey {
    seed: [u8; SUBKEY_SEED_LEN],
    class: DeviceClass,
    device_id: [u8; DEVICE_ID_LEN],
    /// Current day index — incremented monotonically by the ratchet.
    day_index: u64,
}

impl DeviceSubkey {
    /// Construct directly from a derived seed. Caller is responsible
    /// for using one of the [`mint_subkey`] / [`mint_subkey_field_bound`]
    /// entry points; this is mostly useful in tests + recovery flows.
    pub fn from_seed(
        seed: [u8; SUBKEY_SEED_LEN],
        class: DeviceClass,
        device_id: [u8; DEVICE_ID_LEN],
        day_index: u64,
    ) -> Self {
        Self {
            seed,
            class,
            device_id,
            day_index,
        }
    }

    /// Borrow the device class.
    #[must_use]
    pub fn class(&self) -> DeviceClass {
        self.class
    }

    /// Borrow the device ID.
    #[must_use]
    pub fn device_id(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.device_id
    }

    /// Current day index.
    #[must_use]
    pub fn day_index(&self) -> u64 {
        self.day_index
    }

    /// Materialize the underlying signing key (and zeroize the
    /// scratch buffer on drop).
    pub fn signing_key(&self) -> HybridSigningKey {
        HybridSigningKey::from_bytes(&self.seed)
            .expect("subkey seed length is invariant-checked")
    }

    /// Subkey's verifying key — what the attestation binds.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Sign a message under this subkey.
    pub fn sign(&self, message: &[u8]) -> DeviceMeshResult<[u8; HYBRID_SIG_LEN]> {
        Ok(self.signing_key().sign(message)?)
    }

    /// Advance the ratchet one day. Zeroizes the prior seed.
    pub fn step_one_day(&mut self) {
        let new_seed = crate::ratchet::ratchet_one_day(&mut self.seed);
        self.seed = new_seed;
        self.day_index = self.day_index.saturating_add(1);
    }

    /// Borrow the raw seed (DANGEROUS — only for serialization to
    /// the hardware wrapper).
    pub fn raw_seed(&self) -> &[u8; SUBKEY_SEED_LEN] {
        &self.seed
    }
}

impl std::fmt::Debug for DeviceSubkey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceSubkey")
            .field("class", &self.class)
            .field("day_index", &self.day_index)
            .finish_non_exhaustive()
    }
}

/// Master-signed attestation that binds a device subkey's verifying
/// key to the master pubkey. Friends verify each attestation under
/// the master's `HybridVerifyingKey`; the subkey verifying key never
/// needs to be pinned separately.
///
/// Layout (canonical-bytes form, signed):
///
/// ```text
/// SUBKEY_ATTESTATION_DOMAIN (29 bytes ASCII)
/// device_class.tag()         (8 bytes)
/// device_id                  (16 bytes)
/// mint_day_index             (8 bytes, big-endian u64)
/// expiry_day_index           (8 bytes, big-endian u64)
/// subkey_vk_bytes            (HYBRID_VK_LEN bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubkeyAttestation {
    /// Class of the attested device.
    pub class: DeviceClass,
    /// Device ID.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// First day the subkey is valid for.
    pub mint_day_index: u64,
    /// Last day the subkey is valid for (chain horizon).
    pub expiry_day_index: u64,
    /// Subkey's hybrid verifying key bytes.
    pub subkey_vk_bytes: Vec<u8>,
    /// Master's hybrid signature over the canonical transcript.
    pub master_sig: Vec<u8>,
}

impl SubkeyAttestation {
    /// Canonical bytes the master signs over.
    #[must_use]
    pub fn canonical_transcript(
        class: DeviceClass,
        device_id: &[u8; DEVICE_ID_LEN],
        mint_day_index: u64,
        expiry_day_index: u64,
        subkey_vk_bytes: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SUBKEY_ATTESTATION_DOMAIN.len()
                + DEVICE_CLASS_TAG_LEN
                + DEVICE_ID_LEN
                + 8
                + 8
                + subkey_vk_bytes.len(),
        );
        out.extend_from_slice(SUBKEY_ATTESTATION_DOMAIN);
        out.extend_from_slice(&class.tag());
        out.extend_from_slice(device_id);
        out.extend_from_slice(&mint_day_index.to_be_bytes());
        out.extend_from_slice(&expiry_day_index.to_be_bytes());
        out.extend_from_slice(subkey_vk_bytes);
        out
    }

    /// Verify the attestation under the master's verifying key.
    pub fn verify(&self, master_vk: &HybridVerifyingKey) -> DeviceMeshResult<()> {
        if self.subkey_vk_bytes.len() != HYBRID_VK_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: HYBRID_VK_LEN,
                got: self.subkey_vk_bytes.len(),
            });
        }
        let transcript = Self::canonical_transcript(
            self.class,
            &self.device_id,
            self.mint_day_index,
            self.expiry_day_index,
            &self.subkey_vk_bytes,
        );
        master_vk
            .verify(&transcript, &self.master_sig)
            .map_err(|_| DeviceMeshError::AttestationVerifyFail)
    }

    /// Returns true if `day` falls within the attestation's validity
    /// window.
    #[must_use]
    pub fn covers_day(&self, day: u64) -> bool {
        day >= self.mint_day_index && day <= self.expiry_day_index
    }
}

/// Mint a fresh subkey for `(class, device_id)` at `mint_day_index`
/// and produce the master-signed attestation. The attestation is
/// valid through `expiry_day_index` inclusive.
pub fn mint_subkey(
    master: &MasterIdentity,
    class: DeviceClass,
    device_id: [u8; DEVICE_ID_LEN],
    mint_day_index: u64,
    expiry_day_index: u64,
) -> DeviceMeshResult<(DeviceSubkey, SubkeyAttestation)> {
    let seed = derive_subkey_seed(master.seed(), class, &device_id, mint_day_index);
    let subkey = DeviceSubkey::from_seed(seed, class, device_id, mint_day_index);
    let attestation = build_attestation(master, &subkey, mint_day_index, expiry_day_index)?;
    Ok((subkey, attestation))
}

/// Mint a field-bound subkey. The subkey's underlying seed is XOR-
/// masked by a BLAKE3 keystream keyed on `field_seed`, so a captured
/// raw subkey is useless without reproducing the field witness.
pub fn mint_subkey_field_bound(
    master: &MasterIdentity,
    class: DeviceClass,
    device_id: [u8; DEVICE_ID_LEN],
    mint_day_index: u64,
    expiry_day_index: u64,
    field_seed: &[u8; 32],
) -> DeviceMeshResult<(DeviceSubkey, SubkeyAttestation)> {
    let seed = derive_field_bound_subkey_seed(
        master.seed(),
        class,
        &device_id,
        mint_day_index,
        field_seed,
    );
    let subkey = DeviceSubkey::from_seed(seed, class, device_id, mint_day_index);
    let attestation = build_attestation(master, &subkey, mint_day_index, expiry_day_index)?;
    Ok((subkey, attestation))
}

fn build_attestation(
    master: &MasterIdentity,
    subkey: &DeviceSubkey,
    mint_day_index: u64,
    expiry_day_index: u64,
) -> DeviceMeshResult<SubkeyAttestation> {
    let subkey_vk_bytes = subkey.verifying_key().to_bytes().to_vec();
    let transcript = SubkeyAttestation::canonical_transcript(
        subkey.class,
        subkey.device_id(),
        mint_day_index,
        expiry_day_index,
        &subkey_vk_bytes,
    );
    let master_signing = master.signing_key();
    let master_sig = master_signing.sign(&transcript)?.to_vec();
    Ok(SubkeyAttestation {
        class: subkey.class,
        device_id: *subkey.device_id(),
        mint_day_index,
        expiry_day_index,
        subkey_vk_bytes,
        master_sig,
    })
}

/// Re-derive a subkey for an arbitrary day directly from the master.
/// Used in two flows:
///   1. New device pairing: master fast-forwards to the current day.
///   2. Forensic recovery: replay a specific day's traffic in support.
///
/// This is the master-only path; ordinary device operation uses
/// `step_one_day` to advance forward.
pub fn redrive_subkey_at_day(
    master: &MasterIdentity,
    class: DeviceClass,
    device_id: [u8; DEVICE_ID_LEN],
    day_index: u64,
) -> DeviceSubkey {
    let seed = derive_subkey_seed(master.seed(), class, &device_id, day_index);
    DeviceSubkey::from_seed(seed, class, device_id, day_index)
}

/// RNG-helper: fresh 16-byte device ID.
pub fn fresh_device_id<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; DEVICE_ID_LEN] {
    let mut id = [0u8; DEVICE_ID_LEN];
    rng.fill_bytes(&mut id);
    id
}

/// Convenience: BLAKE3 of the master verifying key (used as the
/// friend-side identity-pin handle).
#[must_use]
pub fn master_pin_handle(master_vk: &HybridVerifyingKey) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"OL-device-mesh-master-pin-v1");
    h.update(&master_vk.to_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn mint_round_trip_verifies() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk, att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        att.verify(&master.verifying_key()).unwrap();
        assert!(att.covers_day(0));
        assert!(att.covers_day(365));
        assert!(!att.covers_day(366));
        // Subkey's vk in the attestation matches what the subkey produces.
        assert_eq!(
            &att.subkey_vk_bytes[..],
            &sk.verifying_key().to_bytes()[..]
        );
    }

    #[test]
    fn attestation_tampered_field_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (_sk, mut att) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        // Flip a byte in the subkey VK — signature must reject.
        att.subkey_vk_bytes[7] ^= 0x01;
        let err = att.verify(&master.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
    }

    #[test]
    fn attestation_under_different_master_rejected() {
        let master_a = MasterIdentity::generate(&mut OsRng);
        let master_b = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (_sk, att) =
            mint_subkey(&master_a, DeviceClass::Phone, id, 0, 365).unwrap();
        // master_b can't validate master_a's attestation.
        let err = att.verify(&master_b.verifying_key()).unwrap_err();
        assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
    }

    #[test]
    fn ratchet_step_advances_day_and_changes_signing() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (mut sk, _att) =
            mint_subkey(&master, DeviceClass::Laptop, id, 0, 365).unwrap();
        let day0_vk = sk.verifying_key().to_bytes();
        sk.step_one_day();
        assert_eq!(sk.day_index(), 1);
        let day1_vk = sk.verifying_key().to_bytes();
        assert_ne!(&day0_vk[..], &day1_vk[..]);
    }

    #[test]
    fn redrive_recovers_original_day_seed() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (sk_mint, _att) =
            mint_subkey(&master, DeviceClass::Desktop, id, 7, 365).unwrap();
        let sk_redrive =
            redrive_subkey_at_day(&master, DeviceClass::Desktop, id, 7);
        assert_eq!(sk_mint.raw_seed(), sk_redrive.raw_seed());
    }

    #[test]
    fn field_bound_subkey_differs_from_plain() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = fresh_device_id(&mut OsRng);
        let (plain, _) =
            mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
        let (bound, _) = mint_subkey_field_bound(
            &master,
            DeviceClass::Phone,
            id,
            0,
            365,
            &[0xCC; 32],
        )
        .unwrap();
        assert_ne!(plain.raw_seed(), bound.raw_seed());
    }

    #[test]
    fn master_pin_handle_deterministic() {
        let m = MasterIdentity::generate(&mut OsRng);
        let h1 = master_pin_handle(&m.verifying_key());
        let h2 = master_pin_handle(&m.verifying_key());
        assert_eq!(h1, h2);
    }

    #[test]
    fn master_pin_handle_distinguishes_masters() {
        let a = MasterIdentity::generate(&mut OsRng);
        let b = MasterIdentity::generate(&mut OsRng);
        assert_ne!(
            master_pin_handle(&a.verifying_key()),
            master_pin_handle(&b.verifying_key())
        );
    }
}
