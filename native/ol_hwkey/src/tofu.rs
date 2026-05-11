//! In-memory TOFU store — the always-available fallback.
//!
//! Real platform backends (Secure Enclave, StrongBox, TPM) are added behind
//! Cargo features as separate modules. The default build uses this software
//! TOFU store, which still gives the plan's "first-use record + rotation
//! detection" guarantee without a hardware root.

use std::collections::HashMap;
use std::sync::Mutex;

use subtle::ConstantTimeEq;

use crate::error::{HwKeyError, Result};
use crate::store::{KeyHandle, KeyStore, PublicKey};
use crate::KeyGuarantee;

/// Generates a "public key" from a label by hashing the label with a per-store
/// random root. This is NOT cryptographically a real keypair — the TofuStore
/// is for testing the trait surface, the rotation-detection invariant, and as
/// a fallback when no hardware backend is reachable. Real keypairs come from
/// platform backends (Secure Enclave / StrongBox / TPM) that implement
/// `KeyStore` separately.
#[derive(Debug)]
pub struct TofuStore {
    root: [u8; 32],
    inner: Mutex<HashMap<String, PublicKey>>,
}

impl TofuStore {
    pub fn new(root: [u8; 32]) -> Self {
        Self {
            root,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn derive_pk(&self, label: &str) -> PublicKey {
        let mut hasher = blake3::Hasher::new_keyed(&self.root);
        hasher.update(b"ol-hwkey-tofu-pk-v1");
        hasher.update(label.as_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(hasher.finalize().as_bytes());
        PublicKey(bytes)
    }
}

impl KeyStore for TofuStore {
    fn guarantee(&self) -> KeyGuarantee {
        KeyGuarantee::TofuOnly
    }

    fn get_or_create(&self, label: &str) -> Result<KeyHandle> {
        let mut inner = self.inner.lock().expect("poisoned");
        if !inner.contains_key(label) {
            let pk = self.derive_pk(label);
            inner.insert(label.to_string(), pk);
        }
        Ok(KeyHandle(label.to_string()))
    }

    fn public_key(&self, handle: &KeyHandle) -> Result<PublicKey> {
        let inner = self.inner.lock().expect("poisoned");
        inner
            .get(&handle.0)
            .cloned()
            .ok_or_else(|| HwKeyError::NotFound(handle.0.clone()))
    }

    fn check_tofu(&self, label: &str, presented: &PublicKey) -> Result<()> {
        let inner = self.inner.lock().expect("poisoned");
        let stored = inner
            .get(label)
            .ok_or_else(|| HwKeyError::NotFound(label.into()))?;
        // Constant-time compare so a timing-side-channel doesn't leak which
        // byte of the fingerprint diverges.
        if stored.0.ct_eq(&presented.0).into() {
            Ok(())
        } else {
            Err(HwKeyError::TofuMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TofuStore {
        TofuStore::new([0x42; 32])
    }

    #[test]
    fn get_or_create_is_idempotent() {
        let s = store();
        let h1 = s.get_or_create("alice").unwrap();
        let h2 = s.get_or_create("alice").unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn public_key_stable_across_calls() {
        let s = store();
        let h = s.get_or_create("alice").unwrap();
        let pk1 = s.public_key(&h).unwrap();
        let pk2 = s.public_key(&h).unwrap();
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn distinct_labels_distinct_keys() {
        let s = store();
        let _ = s.get_or_create("alice").unwrap();
        let _ = s.get_or_create("bob").unwrap();
        let pk_alice = s.public_key(&KeyHandle("alice".into())).unwrap();
        let pk_bob = s.public_key(&KeyHandle("bob".into())).unwrap();
        assert_ne!(pk_alice, pk_bob);
    }

    #[test]
    fn tofu_accepts_matching_key() {
        let s = store();
        let h = s.get_or_create("alice").unwrap();
        let pk = s.public_key(&h).unwrap();
        s.check_tofu("alice", &pk).unwrap();
    }

    #[test]
    fn tofu_rejects_rotated_key() {
        let s = store();
        let _ = s.get_or_create("alice").unwrap();
        let attacker_pk = PublicKey([0xAA; 32]);
        assert_eq!(
            s.check_tofu("alice", &attacker_pk).unwrap_err(),
            HwKeyError::TofuMismatch
        );
    }

    #[test]
    fn unknown_handle_not_found() {
        let s = store();
        let err = s.public_key(&KeyHandle("ghost".into())).unwrap_err();
        assert!(matches!(err, HwKeyError::NotFound(_)));
    }

    #[test]
    fn attest_not_supported_on_tofu() {
        let s = store();
        let h = s.get_or_create("alice").unwrap();
        let err = s.attest(&h, b"challenge").unwrap_err();
        assert!(matches!(err, HwKeyError::BackendUnavailable(_)));
    }

    #[test]
    fn guarantee_is_tofu_only() {
        let s = store();
        assert_eq!(s.guarantee(), KeyGuarantee::TofuOnly);
    }
}
