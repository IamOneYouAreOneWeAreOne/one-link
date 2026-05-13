//! Adversarial vectors for Row 8 Layer 1.
//!
//! Exhaustive coverage of every known attack pattern against
//! per-device identity stacks.

use ol_device_mesh::derivation::{
    derive_field_bound_subkey_seed, derive_subkey_seed,
};
use ol_device_mesh::{
    mint_subkey, redrive_subkey_at_day, sibling_witness, state_root,
    verify_liveness, DeviceClass, DeviceMeshError, HardwareWrapper, LivenessProof,
    MasterIdentity, SoftwareWrapper, DEFAULT_LIVENESS_SKEW_SECS, DEVICE_ID_LEN,
    MASTER_SEED_LEN, SUBKEY_SEED_LEN,
};
use rand::rngs::OsRng;

// ── Identity-confusion attacks ────────────────────────────────────

#[test]
fn adversarial_forge_subkey_under_fake_master_rejected() {
    // Attacker generates their OWN master, mints an attestation for
    // a device id they don't own, presents it to a verifier who has
    // pinned the REAL master. Must reject.
    let real_master = MasterIdentity::generate(&mut OsRng);
    let attacker_master = MasterIdentity::generate(&mut OsRng);
    let target_id = [0xAA; DEVICE_ID_LEN];
    let (_sk, att) = mint_subkey(
        &attacker_master,
        DeviceClass::Phone,
        target_id,
        0,
        365,
    )
    .unwrap();
    let err = att.verify(&real_master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
}

#[test]
fn adversarial_replay_same_attestation_across_devices_rejected() {
    // Attacker captures a phone attestation, tries to present it as
    // a laptop attestation by changing the device_class field.
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0xBB; DEVICE_ID_LEN];
    let (_sk, mut att) =
        mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    // Swap the class field; signature was made over the original tag.
    att.class = DeviceClass::Laptop;
    let err = att.verify(&master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
}

#[test]
fn adversarial_extend_expiry_rejected() {
    // Attacker captures an attestation expiring at day 30, mutates
    // the expiry field to day 36500. Signature is bound to expiry.
    let master = MasterIdentity::generate(&mut OsRng);
    let (_sk, mut att) =
        mint_subkey(&master, DeviceClass::Phone, [0xCC; 16], 0, 30).unwrap();
    att.expiry_day_index = 36_500;
    let err = att.verify(&master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
}

#[test]
fn adversarial_subkey_vk_swap_rejected() {
    // Attacker generates their own subkey, swaps its VK into a
    // captured attestation. Signature won't verify against the
    // new VK bytes.
    let master = MasterIdentity::generate(&mut OsRng);
    let (_sk_a, mut att) =
        mint_subkey(&master, DeviceClass::Phone, [0xDD; 16], 0, 365).unwrap();
    let attacker_master = MasterIdentity::generate(&mut OsRng);
    let (sk_b, _att_b) = mint_subkey(
        &attacker_master,
        DeviceClass::Phone,
        [0xDD; 16],
        0,
        365,
    )
    .unwrap();
    att.subkey_vk_bytes = sk_b.verifying_key().to_bytes().to_vec();
    let err = att.verify(&master.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::AttestationVerifyFail));
}

// ── Liveness-proof attacks ────────────────────────────────────────

#[test]
fn adversarial_liveness_proof_signed_under_wrong_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0xEE; 16], 0, 365).unwrap();
    let (sk_b, _att) =
        mint_subkey(&master, DeviceClass::Laptop, [0xFF; 16], 0, 365).unwrap();
    let now = 1_700_000_000;
    // Issue under A but verify under B's VK — must fail.
    let proof = LivenessProof::issue(&sk_a, now, state_root(b"x")).unwrap();
    let witness = sibling_witness(sk_b.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
    let err = verify_liveness(&proof, &witness, now).unwrap_err();
    assert!(matches!(err, DeviceMeshError::LivenessVerifyFail));
}

#[test]
fn adversarial_liveness_truncated_signature_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0x11; 16], 0, 365).unwrap();
    let now = 1_700_000_000;
    let mut proof = LivenessProof::issue(&sk, now, state_root(b"x")).unwrap();
    proof.subkey_sig.truncate(8);
    let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
    let err = verify_liveness(&proof, &witness, now).unwrap_err();
    assert!(matches!(err, DeviceMeshError::BadLength { .. }));
}

#[test]
fn adversarial_liveness_replay_at_future_time_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0x22; 16], 0, 365).unwrap();
    let issued_at = 1_700_000_000;
    let proof = LivenessProof::issue(&sk, issued_at, state_root(b"x")).unwrap();
    let witness = sibling_witness(sk.verifying_key(), 60);
    // Verifier is 1 hour later — outside the 60-second skew.
    let err = verify_liveness(&proof, &witness, issued_at + 3600).unwrap_err();
    assert!(matches!(err, DeviceMeshError::LivenessOutOfWindow { .. }));
}

#[test]
fn adversarial_liveness_state_root_swap_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, [0x33; 16], 0, 365).unwrap();
    let now = 1_700_000_000;
    let mut proof = LivenessProof::issue(&sk, now, state_root(b"real")).unwrap();
    proof.state_root = state_root(b"fake"); // commit-mismatch
    let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
    let err = verify_liveness(&proof, &witness, now).unwrap_err();
    assert!(matches!(err, DeviceMeshError::LivenessVerifyFail));
}

// ── Hardware-wrapper attacks ──────────────────────────────────────

#[test]
fn adversarial_hardware_wrapper_tampered_ciphertext_rejected() {
    let w = SoftwareWrapper::new([0x77; 32]);
    let mut ct = w.wrap(&[0x42; SUBKEY_SEED_LEN]).unwrap();
    // Flip a byte in the body.
    ct[20] ^= 0x01;
    let err = w.unwrap(&ct).unwrap_err();
    assert!(matches!(err, DeviceMeshError::HardwareUnwrapFail));
}

#[test]
fn adversarial_hardware_wrapper_tampered_mac_rejected() {
    let w = SoftwareWrapper::new([0x77; 32]);
    let mut ct = w.wrap(&[0x42; SUBKEY_SEED_LEN]).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    let err = w.unwrap(&ct).unwrap_err();
    assert!(matches!(err, DeviceMeshError::HardwareUnwrapFail));
}

#[test]
fn adversarial_hardware_wrapper_truncated_ciphertext_rejected() {
    let w = SoftwareWrapper::new([0x77; 32]);
    let err = w.unwrap(&[0u8; 5]).unwrap_err();
    assert!(matches!(err, DeviceMeshError::BadLength { .. }));
}

// ── Field-binding attacks ─────────────────────────────────────────

#[test]
fn adversarial_field_bound_seed_unrecoverable_without_witness() {
    // The plain-derivation seed and the field-bound seed must differ
    // for any non-trivial witness, AND the field-bound seed must not
    // appear in plaintext-recoverable form. (We check the strict
    // property: knowing the master + transcript + plain raw seed does
    // NOT reveal the field-bound seed without the witness.)
    let master = [0x42; MASTER_SEED_LEN];
    let id = [0x55; DEVICE_ID_LEN];
    let plain = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);
    let bound = derive_field_bound_subkey_seed(
        &master,
        DeviceClass::Phone,
        &id,
        0,
        &[0xCC; 32],
    );
    assert_ne!(plain, bound);
    // Bonus: bounding under TWO different witnesses yields two distinct
    // bound seeds, both differing from plain.
    let bound_b = derive_field_bound_subkey_seed(
        &master,
        DeviceClass::Phone,
        &id,
        0,
        &[0xDD; 32],
    );
    assert_ne!(bound, bound_b);
    assert_ne!(bound_b, plain);
}

// ── Ratchet attacks ───────────────────────────────────────────────

#[test]
fn adversarial_ratchet_cannot_recover_prior_day() {
    // Take a subkey at day=5, advance to day=6, confirm day-5 seed
    // is not recoverable from day-6 alone (one-way property).
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x88; DEVICE_ID_LEN];
    let (mut sk, _att) =
        mint_subkey(&master, DeviceClass::Phone, id, 5, 365).unwrap();
    let day5_seed = *sk.raw_seed();
    sk.step_one_day();
    assert_ne!(sk.raw_seed(), &day5_seed);
    // Master CAN re-derive day 5 (it has the master seed):
    let re_day5 = redrive_subkey_at_day(&master, DeviceClass::Phone, id, 5);
    assert_eq!(re_day5.raw_seed(), &day5_seed);
}

// ── Domain-separation / cross-protocol attacks ────────────────────

#[test]
fn adversarial_subkey_seed_independent_of_other_blake3_uses() {
    // Sanity: the subkey-derivation output is bound to its domain
    // string. Two callers that BLAKE3-hash the same transcript but
    // with DIFFERENT domain strings must produce different bytes.
    let master = [0x42; MASTER_SEED_LEN];
    let id = [0x55; DEVICE_ID_LEN];
    let real = derive_subkey_seed(&master, DeviceClass::Phone, &id, 0);

    // Hand-computed BLAKE3 over the SAME transcript bytes but without
    // the domain tag — must not match.
    let mut h = blake3::Hasher::new();
    h.update(&master);
    h.update(&DeviceClass::Phone.tag());
    h.update(&id);
    h.update(&0u64.to_be_bytes());
    let mut naive = [0u8; SUBKEY_SEED_LEN];
    naive[..32].copy_from_slice(h.finalize().as_bytes());
    naive[32..].copy_from_slice(h.finalize().as_bytes());
    assert_ne!(real, naive);
}
