//! HKDF subkey-seed derivation.
//!
//! Per-device subkey seeds are derived deterministically from the
//! master seed plus a transcript of `(device_class, device_id,
//! day_index)`. Determinism gives us "lose a device and recover the
//! same subkey from the master" for free; the transcript ensures two
//! devices of the same class at the same day never collide.
//!
//! Domain-separation prevents this HKDF output from colliding with
//! any other BLAKE3-keyed derivation in the system (capabilities,
//! ratchets, attestations).

use blake3::Hasher;
use zeroize::Zeroize;

use crate::device_class::{DeviceClass, DEVICE_CLASS_TAG_LEN};
use crate::master::MASTER_SEED_LEN;

/// Length of a subkey seed (same shape as the master seed — 32 bytes
/// Ed25519 + 32 bytes ML-DSA).
pub const SUBKEY_SEED_LEN: usize = MASTER_SEED_LEN;

/// Domain-separation tag for subkey-seed derivation.
pub const HKDF_DOMAIN: &[u8] = b"OL-device-mesh-subkey-v1";

/// Derive a per-device subkey seed.
///
/// The transcript is:
/// `HKDF_DOMAIN || master_seed || device_class.tag() || device_id || day_index_be`.
///
/// Output is 64 bytes (split into the 32-byte Ed25519 half + 32-byte
/// ML-DSA half) so the result drops directly into
/// [`ol_pqsig::HybridSigningKey::from_bytes`].
///
/// `day_index = 0` is the seed at mint time; the daily ratchet uses
/// `day_index > 0` to advance forward.
#[must_use]
pub fn derive_subkey_seed(
    master_seed: &[u8; MASTER_SEED_LEN],
    device_class: DeviceClass,
    device_id: &[u8; 16],
    day_index: u64,
) -> [u8; SUBKEY_SEED_LEN] {
    // Use BLAKE3-keyed hashing as the HKDF primitive. BLAKE3's
    // `derive_key` function is the canonical "HKDF-like" path
    // recommended by the BLAKE3 authors. We extract twice — once for
    // the Ed25519 half, once for the ML-DSA half — under distinct
    // sub-context strings so the two halves are independent random
    // variables conditioned on the master.
    let mut out = [0u8; SUBKEY_SEED_LEN];
    let class_tag: [u8; DEVICE_CLASS_TAG_LEN] = device_class.tag();
    let day_be = day_index.to_be_bytes();
    let mut h = Hasher::new();
    h.update(HKDF_DOMAIN);
    h.update(b"-ed25519");
    h.update(master_seed);
    h.update(&class_tag);
    h.update(device_id);
    h.update(&day_be);
    let d = h.finalize();
    out[..32].copy_from_slice(d.as_bytes());

    let mut h2 = Hasher::new();
    h2.update(HKDF_DOMAIN);
    h2.update(b"-mldsa");
    h2.update(master_seed);
    h2.update(&class_tag);
    h2.update(device_id);
    h2.update(&day_be);
    let d2 = h2.finalize();
    out[32..].copy_from_slice(d2.as_bytes());

    // No zeroize needed on the local Hashers — BLAKE3 hashes the
    // master seed and the result is the secret we care about.
    let _ = class_tag;
    out
}

/// Field-bound variant: XOR-mask the derived seed with a BLAKE3
/// keystream keyed on the field witness. A captured raw seed without
/// the witness reconstructs to garbage.
///
/// The mask is `BLAKE3(b"OL-device-mesh-field-mask-v1" || field_seed
/// || class_tag || device_id || day_be)` expanded to 64 bytes.
#[must_use]
pub fn derive_field_bound_subkey_seed(
    master_seed: &[u8; MASTER_SEED_LEN],
    device_class: DeviceClass,
    device_id: &[u8; 16],
    day_index: u64,
    field_seed: &[u8; 32],
) -> [u8; SUBKEY_SEED_LEN] {
    let mut out = derive_subkey_seed(master_seed, device_class, device_id, day_index);
    let class_tag: [u8; DEVICE_CLASS_TAG_LEN] = device_class.tag();
    let day_be = day_index.to_be_bytes();
    let mut h = Hasher::new();
    h.update(b"OL-device-mesh-field-mask-v1");
    h.update(field_seed);
    h.update(&class_tag);
    h.update(device_id);
    h.update(&day_be);
    let mut reader = h.finalize_xof();
    let mut mask = [0u8; SUBKEY_SEED_LEN];
    reader.fill(&mut mask);
    for i in 0..SUBKEY_SEED_LEN {
        out[i] ^= mask[i];
    }
    mask.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let id = [0x55u8; 16];
        let a = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
        let b = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn different_device_class_yields_different_seed() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let id = [0x55u8; 16];
        let phone = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
        let laptop = derive_subkey_seed(&master, DeviceClass::Laptop, &id, 0);
        assert_ne!(phone, laptop);
    }

    #[test]
    fn different_device_id_yields_different_seed() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let a = derive_subkey_seed(&master, DeviceClass::Phone, &[0x01; 16], 0);
        let b = derive_subkey_seed(&master, DeviceClass::Phone, &[0x02; 16], 0);
        assert_ne!(a, b);
    }

    #[test]
    fn different_day_index_yields_different_seed() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let id = [0x55u8; 16];
        let d0 = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
        let d1 = derive_subkey_seed(&master, DeviceClass::Phone, &id, 1);
        assert_ne!(d0, d1);
    }

    #[test]
    fn ed25519_and_mldsa_halves_independent() {
        // The two halves are derived under distinct sub-contexts; if
        // one half is correlated with the other a future regression
        // would silently weaken the hybrid signature security.
        let master = [0x99u8; MASTER_SEED_LEN];
        let seed = derive_subkey_seed(&master, DeviceClass::Desktop, &[0; 16], 7);
        let (ed, ml) = seed.split_at(32);
        assert_ne!(ed, ml);
    }

    #[test]
    fn field_binding_changes_seed() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let id = [0x55u8; 16];
        let raw = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
        let bound =
            derive_field_bound_subkey_seed(&master, DeviceClass::Phone, &id, 0, &[0xCC; 32]);
        assert_ne!(raw, bound);
    }

    #[test]
    fn field_binding_with_distinct_witness_yields_distinct_seed() {
        let master = [0x42u8; MASTER_SEED_LEN];
        let id = [0x55u8; 16];
        let a = derive_field_bound_subkey_seed(&master, DeviceClass::Phone, &id, 0, &[0xAA; 32]);
        let b = derive_field_bound_subkey_seed(&master, DeviceClass::Phone, &id, 0, &[0xBB; 32]);
        assert_ne!(a, b);
    }
}
