//! Cross-witness attestation between sibling devices.
//!
//! Each device periodically emits a [`LivenessProof`]: a signature
//! over `(my_device_id, my_class, my_day_index, wall_clock, state_root)`
//! using its CURRENT subkey. Sibling devices receive the proof,
//! verify the signature under the master's known subkey-attestation
//! chain, and check that the wall-clock falls within the allowed
//! skew window.
//!
//! A device that fails to emit a fresh, valid proof within the
//! configured window gets flagged for Layer-2 quorum-revocation.
//!
//! The witness signature does NOT cover the master directly — it
//! covers the subkey transcript. Layer-2 cross-checks the witness
//! against the master-signed `SubkeyAttestation` for that device, so
//! a forged witness signed under a stale or revoked subkey fails the
//! Layer-2 check.

use blake3::Hasher;
use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN};

use crate::device_class::{DeviceClass, DEVICE_CLASS_TAG_LEN};
use crate::errors::{DeviceMeshError, DeviceMeshResult};
use crate::subkey::{DeviceSubkey, DEVICE_ID_LEN};

/// Domain-separation tag for liveness proofs.
pub const LIVENESS_DOMAIN: &[u8] = b"OL-device-mesh-liveness-v1";

/// Default skew window for liveness proof acceptance (5 minutes).
pub const DEFAULT_LIVENESS_SKEW_SECS: u64 = 300;

/// One sibling's liveness proof.
///
/// Layout (canonical-bytes form, signed):
///
/// ```text
/// LIVENESS_DOMAIN     (28 bytes ASCII)
/// device_id           (16 bytes)
/// class.tag()         (8 bytes)
/// day_index_be        (8 bytes)
/// wall_unix_be        (8 bytes)
/// state_root          (32 bytes)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessProof {
    /// Reporter's device ID.
    pub device_id: [u8; DEVICE_ID_LEN],
    /// Reporter's class.
    pub class: DeviceClass,
    /// Day index of the subkey used to sign.
    pub day_index: u64,
    /// Wall-clock unix-seconds at issue time.
    pub wall_unix: u64,
    /// 32-byte digest committing to the reporter's local state root
    /// at issue time. Layer 3 (CRDT mirror) defines the contents.
    pub state_root: [u8; 32],
    /// Subkey signature over the canonical transcript.
    pub subkey_sig: Vec<u8>,
}

impl LivenessProof {
    /// Canonical bytes that the subkey signs over.
    #[must_use]
    pub fn canonical_transcript(
        device_id: &[u8; DEVICE_ID_LEN],
        class: DeviceClass,
        day_index: u64,
        wall_unix: u64,
        state_root: &[u8; 32],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            LIVENESS_DOMAIN.len()
                + DEVICE_ID_LEN
                + DEVICE_CLASS_TAG_LEN
                + 8
                + 8
                + 32,
        );
        out.extend_from_slice(LIVENESS_DOMAIN);
        out.extend_from_slice(device_id);
        out.extend_from_slice(&class.tag());
        out.extend_from_slice(&day_index.to_be_bytes());
        out.extend_from_slice(&wall_unix.to_be_bytes());
        out.extend_from_slice(state_root);
        out
    }

    /// Issue a fresh proof using the given subkey + wall clock + state.
    pub fn issue(
        subkey: &DeviceSubkey,
        wall_unix: u64,
        state_root: [u8; 32],
    ) -> DeviceMeshResult<Self> {
        let transcript = Self::canonical_transcript(
            subkey.device_id(),
            subkey.class(),
            subkey.day_index(),
            wall_unix,
            &state_root,
        );
        let sig = subkey.sign(&transcript)?;
        Ok(Self {
            device_id: *subkey.device_id(),
            class: subkey.class(),
            day_index: subkey.day_index(),
            wall_unix,
            state_root,
            subkey_sig: sig.to_vec(),
        })
    }
}

/// A sibling-device witness record: the subkey's verifying key
/// (obtained out-of-band, typically via the master's
/// `SubkeyAttestation`) plus the wall-clock window the verifier
/// accepts.
#[derive(Debug, Clone)]
pub struct SiblingWitness {
    /// The reporter's subkey verifying key.
    pub subkey_vk: HybridVerifyingKey,
    /// Maximum allowed clock skew between reporter and verifier
    /// (in seconds).
    pub max_skew_secs: u64,
}

/// Build a sibling-witness record from a verified subkey VK.
#[must_use] 
pub const fn sibling_witness(subkey_vk: HybridVerifyingKey, max_skew_secs: u64) -> SiblingWitness {
    SiblingWitness {
        subkey_vk,
        max_skew_secs,
    }
}

/// Verify a liveness proof under the given witness + verifier's
/// current wall clock.
///
/// Returns `Ok(())` if both the signature AND the timestamp window
/// check pass; otherwise returns the relevant typed error.
pub fn verify_liveness(
    proof: &LivenessProof,
    witness: &SiblingWitness,
    now_unix: u64,
) -> DeviceMeshResult<()> {
    if proof.subkey_sig.len() != HYBRID_SIG_LEN {
        return Err(DeviceMeshError::BadLength {
            expected: HYBRID_SIG_LEN,
            got: proof.subkey_sig.len(),
        });
    }
    let transcript = LivenessProof::canonical_transcript(
        &proof.device_id,
        proof.class,
        proof.day_index,
        proof.wall_unix,
        &proof.state_root,
    );
    witness
        .subkey_vk
        .verify(&transcript, &proof.subkey_sig)
        .map_err(|_| DeviceMeshError::LivenessVerifyFail)?;
    // Clock-skew check after the signature check so a forged proof
    // never reaches the timing branch — keeps the verify path
    // constant-time-uniform across "good timestamp / bad signature"
    // vs "bad timestamp / bad signature" cases.
    let diff = proof.wall_unix.abs_diff(now_unix);
    if diff > witness.max_skew_secs {
        return Err(DeviceMeshError::LivenessOutOfWindow {
            got_unix: proof.wall_unix,
            now_unix,
            max_skew_secs: witness.max_skew_secs,
        });
    }
    Ok(())
}

/// Convenience: 32-byte BLAKE3 commitment for a serialized state
/// blob. Layer 3 uses this directly when computing the CRDT root.
#[must_use]
pub fn state_root(state: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"OL-device-mesh-state-root-v1");
    h.update(state);
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master::MasterIdentity;
    use crate::subkey::{fresh_device_id, mint_subkey};
    use rand::rngs::OsRng;

    fn mint(master: &MasterIdentity, class: DeviceClass) -> DeviceSubkey {
        let id = fresh_device_id(&mut OsRng);
        let (sk, _att) = mint_subkey(master, class, id, 0, 365).unwrap();
        sk
    }

    #[test]
    fn issue_and_verify_round_trip() {
        let master = MasterIdentity::generate(&mut OsRng);
        let sk = mint(&master, DeviceClass::Phone);
        let now: u64 = 1_700_000_000;
        let proof = LivenessProof::issue(&sk, now, state_root(b"state")).unwrap();
        let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
        verify_liveness(&proof, &witness, now).unwrap();
    }

    #[test]
    fn tampered_state_root_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let sk = mint(&master, DeviceClass::Phone);
        let now: u64 = 1_700_000_000;
        let mut proof =
            LivenessProof::issue(&sk, now, state_root(b"state")).unwrap();
        proof.state_root[0] ^= 0x01;
        let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
        let err = verify_liveness(&proof, &witness, now).unwrap_err();
        assert!(matches!(err, DeviceMeshError::LivenessVerifyFail));
    }

    #[test]
    fn stale_timestamp_rejected() {
        let master = MasterIdentity::generate(&mut OsRng);
        let sk = mint(&master, DeviceClass::Phone);
        let issued_at: u64 = 1_700_000_000;
        let proof =
            LivenessProof::issue(&sk, issued_at, state_root(b"state")).unwrap();
        let witness = sibling_witness(sk.verifying_key(), 60);
        let later = issued_at + 120; // 60 seconds past skew
        let err = verify_liveness(&proof, &witness, later).unwrap_err();
        assert!(matches!(
            err,
            DeviceMeshError::LivenessOutOfWindow { .. }
        ));
    }

    #[test]
    fn cross_device_witness_fails() {
        let master = MasterIdentity::generate(&mut OsRng);
        let sk_a = mint(&master, DeviceClass::Phone);
        let sk_b = mint(&master, DeviceClass::Laptop);
        let now: u64 = 1_700_000_000;
        let proof_a =
            LivenessProof::issue(&sk_a, now, state_root(b"state")).unwrap();
        // Verify under B's subkey VK — must fail.
        let witness_b = sibling_witness(sk_b.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
        let err = verify_liveness(&proof_a, &witness_b, now).unwrap_err();
        assert!(matches!(err, DeviceMeshError::LivenessVerifyFail));
    }

    #[test]
    fn state_root_deterministic() {
        let a = state_root(b"hello");
        let b = state_root(b"hello");
        assert_eq!(a, b);
        let c = state_root(b"hellp");
        assert_ne!(a, c);
    }
}
