//! Hardware-bound subkey wrapping.
//!
//! At rest, the per-device subkey seed should be wrapped under the
//! platform's hardware key store: Apple Secure Enclave on iOS/macOS,
//! Android StrongBox on modern Android, Windows TPM2 on PC, ARM
//! TrustZone on embedded. Loss of the device's RAM (cold-boot,
//! sleep with display lock, etc.) means the wrapped seed sits in
//! cold storage; unwrapping requires the hardware key.
//!
//! This module defines the *trait* the daemon programs against, plus
//! a [`SoftwareWrapper`] reference implementation that uses
//! BLAKE3-keyed AEAD-style XOR + MAC (NOT for production — it's a
//! testing fixture). Per-platform backends (Secure Enclave / TPM /
//! StrongBox / TrustZone) implement the same trait against their
//! respective KEKs.
//!
//! ## Sovereignty contract
//!
//! Hardware-bound is TOFU-degrading: if no hardware backend is
//! available the daemon falls back to a software-encrypted seed file
//! on disk. Vendor attestation chains (Apple, Google, Microsoft) are
//! OPTIONAL — they harden the binding but the system functions
//! without them.

use blake3::Hasher;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::errors::{DeviceMeshError, DeviceMeshResult};

/// Number of bytes of overhead the [`SoftwareWrapper`] adds to each
/// wrapped seed (nonce + MAC).
pub const WRAPPED_KEY_OVERHEAD: usize = 12 + 32;

/// Wrap / unwrap the raw subkey seed using a hardware-bound key.
///
/// The trait is intentionally minimal: callers hand in plaintext
/// bytes, get out ciphertext bytes, and vice versa. The KEK never
/// leaves the platform's secure store.
pub trait HardwareWrapper: std::fmt::Debug + Send + Sync {
    /// Wrap a raw seed for at-rest storage. The returned ciphertext
    /// is what the daemon writes to disk.
    fn wrap(&self, plaintext: &[u8]) -> DeviceMeshResult<Vec<u8>>;

    /// Unwrap ciphertext back to the raw seed. Returns
    /// [`DeviceMeshError::HardwareUnwrapFail`] on integrity failure.
    fn unwrap(&self, ciphertext: &[u8]) -> DeviceMeshResult<Vec<u8>>;
}

/// Reference / test implementation: a single in-memory 32-byte KEK
/// XOR'd with a BLAKE3-derived keystream + 32-byte BLAKE3-keyed MAC.
///
/// ## NOT FOR PRODUCTION
///
/// The KEK lives in process memory, so it offers NO hardware
/// protection. Suitable for tests + the daemon's "no hardware
/// available" fallback when paired with an OS-keyring-stored KEK
/// outside this crate. Production binds to platform hardware via a
/// per-platform impl.
#[derive(ZeroizeOnDrop)]
pub struct SoftwareWrapper {
    kek: [u8; 32],
}

impl std::fmt::Debug for SoftwareWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareWrapper").finish_non_exhaustive()
    }
}

impl SoftwareWrapper {
    /// Construct from a raw 32-byte KEK.
    pub fn new(kek: [u8; 32]) -> Self {
        Self { kek }
    }

    fn keystream(&self, nonce: &[u8; 12], len: usize) -> Vec<u8> {
        let mut h = Hasher::new_keyed(&self.kek);
        h.update(b"OL-device-mesh-hw-stream-v1");
        h.update(nonce);
        let mut reader = h.finalize_xof();
        let mut out = vec![0u8; len];
        reader.fill(&mut out);
        out
    }

    fn mac(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new_keyed(&self.kek);
        h.update(b"OL-device-mesh-hw-mac-v1");
        h.update(nonce);
        h.update(ciphertext);
        *h.finalize().as_bytes()
    }
}

impl HardwareWrapper for SoftwareWrapper {
    fn wrap(&self, plaintext: &[u8]) -> DeviceMeshResult<Vec<u8>> {
        // Deterministic nonce from BLAKE3(kek || plaintext). This is
        // safe under the assumption that each plaintext seed is
        // unique (which is true — they're 64-byte hybrid seeds). For
        // a generic AEAD that's not safe; this is a CONFINED test
        // fixture and we accept the constraint.
        let mut nh = Hasher::new_keyed(&self.kek);
        nh.update(b"OL-device-mesh-hw-nonce-v1");
        nh.update(plaintext);
        let nd = nh.finalize();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nd.as_bytes()[..12]);

        let ks = self.keystream(&nonce, plaintext.len());
        let mut ct = vec![0u8; plaintext.len()];
        for i in 0..plaintext.len() {
            ct[i] = plaintext[i] ^ ks[i];
        }
        let mac = self.mac(&nonce, &ct);
        let mut out = Vec::with_capacity(12 + ct.len() + 32);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    fn unwrap(&self, ciphertext: &[u8]) -> DeviceMeshResult<Vec<u8>> {
        if ciphertext.len() < WRAPPED_KEY_OVERHEAD {
            return Err(DeviceMeshError::BadLength {
                expected: WRAPPED_KEY_OVERHEAD,
                got: ciphertext.len(),
            });
        }
        let pt_len = ciphertext.len() - WRAPPED_KEY_OVERHEAD;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&ciphertext[..12]);
        let ct = &ciphertext[12..12 + pt_len];
        let supplied_mac = &ciphertext[12 + pt_len..];

        let expected_mac = self.mac(&nonce, ct);
        if !bool::from(expected_mac.ct_eq(supplied_mac)) {
            return Err(DeviceMeshError::HardwareUnwrapFail);
        }
        let ks = self.keystream(&nonce, pt_len);
        let mut pt = vec![0u8; pt_len];
        for i in 0..pt_len {
            pt[i] = ct[i] ^ ks[i];
        }
        Ok(pt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let w = SoftwareWrapper::new([0xAB; 32]);
        let pt = b"64-byte plaintext-----------------------------------------------";
        assert_eq!(pt.len(), 64);
        let ct = w.wrap(pt).unwrap();
        assert_eq!(ct.len(), pt.len() + WRAPPED_KEY_OVERHEAD);
        let rec = w.unwrap(&ct).unwrap();
        assert_eq!(&rec[..], &pt[..]);
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let w = SoftwareWrapper::new([0xAB; 32]);
        let mut ct = w.wrap(&[0x42; 64]).unwrap();
        ct[20] ^= 0x01;
        let err = w.unwrap(&ct).unwrap_err();
        assert!(matches!(err, DeviceMeshError::HardwareUnwrapFail));
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        let w = SoftwareWrapper::new([0xAB; 32]);
        let err = w.unwrap(&[0u8; 10]).unwrap_err();
        assert!(matches!(err, DeviceMeshError::BadLength { .. }));
    }

    #[test]
    fn distinct_keks_reject_each_others_ciphertext() {
        let a = SoftwareWrapper::new([0x11; 32]);
        let b = SoftwareWrapper::new([0x22; 32]);
        let ct = a.wrap(&[0xCD; 64]).unwrap();
        let err = b.unwrap(&ct).unwrap_err();
        assert!(matches!(err, DeviceMeshError::HardwareUnwrapFail));
    }
}
