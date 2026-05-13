//! Master identity — the 32-byte seed everything else derives from.
//!
//! `MasterIdentity` wraps a `HybridSigningKey` plus the raw seed used
//! to deterministically derive per-device subkeys. The seed never
//! leaves the device that holds the master role; everywhere else
//! works with the `HybridVerifyingKey` (the friends-side pin).
//!
//! Threat model for the seed:
//!
//! - At rest: stored under hardware wrapping (Layer-1 [`crate::HardwareWrapper`])
//!   or under threshold-recovery sharding (`ol_threshold_recovery`).
//! - In memory: zeroized on `Drop`.
//! - Recovery: lost master seed reconstitutes from any K of N
//!   threshold-recovery shares.

use ol_pqsig::{HybridSigningKey, HybridVerifyingKey, HYBRID_SK_LEN};
use rand_core::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Length of the canonical master seed in bytes.
pub const MASTER_SEED_LEN: usize = HYBRID_SK_LEN;

/// The master identity that owns the device mesh. Friends pin this
/// identity's `HybridVerifyingKey`; per-device subkeys are derived
/// from `seed` via `derivation::derive_subkey_seed`.
#[derive(ZeroizeOnDrop)]
pub struct MasterIdentity {
    /// Canonical seed: 32-byte Ed25519 seed || 32-byte ML-DSA seed.
    seed: [u8; MASTER_SEED_LEN],
}

impl MasterIdentity {
    /// Generate a fresh master identity from a cryptographically
    /// secure RNG. Use exactly once per human.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; MASTER_SEED_LEN];
        rng.fill_bytes(&mut seed);
        Self { seed }
    }

    /// Construct from an existing seed. Use this on a paired device
    /// recovering from threshold-recovery shares.
    pub fn from_seed(seed: [u8; MASTER_SEED_LEN]) -> Self {
        Self { seed }
    }

    /// Parse from wire bytes (length-checked).
    pub fn from_bytes(bytes: &[u8]) -> DeviceMeshResult<Self> {
        if bytes.len() != MASTER_SEED_LEN {
            return Err(DeviceMeshError::BadLength {
                expected: MASTER_SEED_LEN,
                got: bytes.len(),
            });
        }
        let mut seed = [0u8; MASTER_SEED_LEN];
        seed.copy_from_slice(bytes);
        Ok(Self { seed })
    }

    /// Borrow the raw seed. Callers who hold this for any non-trivial
    /// duration MUST zeroize it themselves.
    pub fn seed(&self) -> &[u8; MASTER_SEED_LEN] {
        &self.seed
    }

    /// Materialize the underlying [`HybridSigningKey`]. Called rarely
    /// (only when the master itself signs an attestation); per-device
    /// signing always goes through `DeviceSubkey`.
    pub fn signing_key(&self) -> HybridSigningKey {
        HybridSigningKey::from_bytes(&self.seed)
            .expect("master seed length is invariant-checked")
    }

    /// Borrow the public verifying key — the byte string friends pin.
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        self.signing_key().verifying_key()
    }
}

impl std::fmt::Debug for MasterIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasterIdentity").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn generate_yields_distinct_seeds() {
        let a = MasterIdentity::generate(&mut OsRng);
        let b = MasterIdentity::generate(&mut OsRng);
        assert_ne!(a.seed(), b.seed());
    }

    #[test]
    fn from_seed_round_trip() {
        let raw = [0x42u8; MASTER_SEED_LEN];
        let m = MasterIdentity::from_seed(raw);
        assert_eq!(m.seed(), &raw);
    }

    #[test]
    fn from_bytes_length_check() {
        let too_short = vec![0u8; MASTER_SEED_LEN - 1];
        let err = MasterIdentity::from_bytes(&too_short).unwrap_err();
        assert!(matches!(err, DeviceMeshError::BadLength { .. }));
    }

    #[test]
    fn signing_key_yields_consistent_vk() {
        let m = MasterIdentity::generate(&mut OsRng);
        let vk1 = m.verifying_key().to_bytes();
        let vk2 = m.signing_key().verifying_key().to_bytes();
        assert_eq!(vk1, vk2);
    }
}
