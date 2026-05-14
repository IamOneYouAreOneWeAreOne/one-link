//! Per-device Ristretto255 onion identity.
//!
//! Each device gets a Ristretto255 keypair derived deterministically
//! from the master seed plus the device id and a domain string.
//! The secret half lives in the device's memory (and the platform
//! hardware wrapper at rest, via Layer-1 [`crate::HardwareWrapper`]);
//! the public half is master-attested and broadcast to siblings via
//! [`super::OnionAttestation`].
//!
//! Deterministic derivation means the master can re-mint the onion
//! identity on a new pairing (analogous to the Layer-1
//! [`crate::redrive_subkey_at_day`] path).

use blake3::Hasher;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::master::MasterIdentity;
use crate::subkey::DEVICE_ID_LEN;

/// Length of the secret scalar's wire form (`Scalar::to_bytes` is
/// canonically 32 bytes; we keep the bytes for at-rest storage).
pub const ONION_SECRET_LEN: usize = 32;

/// Length of the Ristretto255 public point's compressed form.
pub const ONION_PUBKEY_LEN: usize = 32;

/// Domain-separation tag for onion-identity derivation.
pub const ONION_DERIVATION_DOMAIN: &[u8] = b"OL-mesh-onion-identity-v1";

/// One device's Ristretto255 onion identity.
#[derive(ZeroizeOnDrop)]
pub struct OnionIdentity {
    secret_bytes: [u8; ONION_SECRET_LEN],
}

impl OnionIdentity {
    /// Construct from raw scalar bytes (e.g., after at-rest load).
    #[must_use] 
    pub const fn from_secret_bytes(secret_bytes: [u8; ONION_SECRET_LEN]) -> Self {
        Self { secret_bytes }
    }

    /// Borrow the raw secret bytes. DANGEROUS — only for at-rest
    /// serialization via the hardware wrapper.
    #[must_use] 
    pub const fn secret_bytes(&self) -> &[u8; ONION_SECRET_LEN] {
        &self.secret_bytes
    }

    /// Materialize the scalar.
    fn scalar(&self) -> Scalar {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&self.secret_bytes);
        Scalar::from_bytes_mod_order_wide(&wide)
    }

    /// Compute the public point.
    #[must_use] 
    pub fn public_point(&self) -> RistrettoPoint {
        let s = self.scalar();
        &s * RISTRETTO_BASEPOINT_TABLE
    }

    /// Compressed public-point bytes (32-byte Ristretto255 encoding).
    #[must_use] 
    pub fn public_bytes(&self) -> [u8; ONION_PUBKEY_LEN] {
        self.public_point().compress().to_bytes()
    }

    /// Borrow the secret scalar for the Sphinx peel path. The
    /// caller must NOT log or persist the result.
    #[must_use] 
    pub fn peel_scalar(&self) -> Scalar {
        self.scalar()
    }
}

impl std::fmt::Debug for OnionIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnionIdentity").finish_non_exhaustive()
    }
}

/// Derive the device's onion identity deterministically from the
/// master seed + device id.
///
/// HKDF chain: `BLAKE3-XOF(ONION_DERIVATION_DOMAIN || master_seed ||
/// device_id)` expanded to 64 bytes, then folded into a Scalar via
/// `from_bytes_mod_order_wide` for unbiased sampling.
#[must_use]
pub fn derive_onion_identity(
    master: &MasterIdentity,
    device_id: &[u8; DEVICE_ID_LEN],
) -> OnionIdentity {
    let mut h = Hasher::new();
    h.update(ONION_DERIVATION_DOMAIN);
    h.update(master.seed());
    h.update(device_id);
    let mut reader = h.finalize_xof();
    let mut wide = [0u8; 64];
    reader.fill(&mut wide);
    let scalar = Scalar::from_bytes_mod_order_wide(&wide);
    // Encode the scalar back to canonical 32-byte form. This is
    // bit-exact under from_bytes_mod_order_wide for any later
    // reload (`from_secret_bytes` → `from_bytes_mod_order_wide`
    // with zero-padded high half).
    let mut secret_bytes = [0u8; ONION_SECRET_LEN];
    secret_bytes.copy_from_slice(&scalar.to_bytes());
    wide.zeroize();
    OnionIdentity { secret_bytes }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn derivation_deterministic_per_master_and_device() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0x42; DEVICE_ID_LEN];
        let a = derive_onion_identity(&master, &id);
        let b = derive_onion_identity(&master, &id);
        assert_eq!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn different_device_ids_yield_different_keys() {
        let master = MasterIdentity::generate(&mut OsRng);
        let a = derive_onion_identity(&master, &[0x01; DEVICE_ID_LEN]);
        let b = derive_onion_identity(&master, &[0x02; DEVICE_ID_LEN]);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn different_masters_yield_different_keys() {
        let master_a = MasterIdentity::generate(&mut OsRng);
        let master_b = MasterIdentity::generate(&mut OsRng);
        let id = [0x42; DEVICE_ID_LEN];
        let a = derive_onion_identity(&master_a, &id);
        let b = derive_onion_identity(&master_b, &id);
        assert_ne!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn round_trip_via_secret_bytes() {
        let master = MasterIdentity::generate(&mut OsRng);
        let id = [0x42; DEVICE_ID_LEN];
        let a = derive_onion_identity(&master, &id);
        let b = OnionIdentity::from_secret_bytes(*a.secret_bytes());
        assert_eq!(a.public_bytes(), b.public_bytes());
    }

    #[test]
    fn public_point_is_non_identity() {
        // Sanity: the BLAKE3-XOF derivation should hit the identity
        // with vanishingly small probability. Check 32 different
        // devices.
        let master = MasterIdentity::generate(&mut OsRng);
        for i in 0..32u8 {
            let id = [i; DEVICE_ID_LEN];
            let identity = derive_onion_identity(&master, &id);
            let pt = identity.public_point();
            assert_ne!(pt, RistrettoPoint::default());
        }
    }
}
