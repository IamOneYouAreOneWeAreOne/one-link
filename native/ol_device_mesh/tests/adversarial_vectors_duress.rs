//! Adversarial vectors for Row 8 Layer 10 duress.

use ol_device_mesh::duress::{
    create_duress_envelope, sign_duress_alert, unlock_duress_envelope,
    verify_pairing_cross_channel, PairingChannel, PairingCommitment, UnlockOutcome,
};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN};
use rand::rngs::OsRng;

// ── DuressEnvelope adversarial ─────────────────────────────────────

#[test]
fn adversarial_captor_with_disk_image_only_unlocks_decoy() {
    // The captor has the envelope bytes + types the user's REAL
    // code (because they coerced it out of the user). WITHOUT the
    // field witness, they still only recover the decoy at best —
    // and probably nothing.
    let witness = [0x42; 32];
    let env = create_duress_envelope(
        b"REAL secrets the captor must not see",
        b"decoy fake plausible state",
        b"real-pass",
        b"duress-code",
        &witness,
        &mut OsRng,
    )
    .unwrap();
    // Captor types the real code WITHOUT the witness.
    let outcome = unlock_duress_envelope(&env, b"real-pass", None).unwrap();
    assert!(matches!(outcome, UnlockOutcome::WrongCode));
}

#[test]
fn adversarial_captor_with_real_code_and_wrong_witness_fails() {
    // Captor extracted the user's real code somehow but supplied
    // the wrong field witness (no way to know the right one).
    let witness_correct = [0x42; 32];
    let witness_attacker = [0x99; 32];
    let env = create_duress_envelope(
        b"real",
        b"decoy",
        b"real-pass",
        b"duress-code",
        &witness_correct,
        &mut OsRng,
    )
    .unwrap();
    let outcome = unlock_duress_envelope(&env, b"real-pass", Some(&witness_attacker)).unwrap();
    assert!(matches!(outcome, UnlockOutcome::WrongCode));
}

#[test]
fn adversarial_tampered_real_ciphertext_yields_wrong_code() {
    let witness = [0x42; 32];
    let mut env = create_duress_envelope(
        b"real",
        b"decoy",
        b"real-pass",
        b"duress-code",
        &witness,
        &mut OsRng,
    )
    .unwrap();
    env.real_ct[0] ^= 0xFF;
    // Real path fails (AEAD MAC mismatch); decoy path fails too
    // since "real-pass" isn't the decoy code.
    let outcome = unlock_duress_envelope(&env, b"real-pass", Some(&witness)).unwrap();
    assert!(matches!(outcome, UnlockOutcome::WrongCode));
}

#[test]
fn adversarial_tampered_decoy_ciphertext_yields_wrong_code() {
    let witness = [0x42; 32];
    let mut env = create_duress_envelope(
        b"real",
        b"decoy",
        b"real-pass",
        b"duress-code",
        &witness,
        &mut OsRng,
    )
    .unwrap();
    env.decoy_ct[0] ^= 0xFF;
    // Decoy path fails on AEAD MAC.
    let outcome = unlock_duress_envelope(&env, b"duress-code", None).unwrap();
    assert!(matches!(outcome, UnlockOutcome::WrongCode));
}

#[test]
fn adversarial_identical_codes_rejected() {
    let witness = [0x42; 32];
    let err = create_duress_envelope(b"real", b"decoy", b"same", b"same", &witness, &mut OsRng)
        .unwrap_err();
    assert!(matches!(err, DeviceMeshError::DuressCodesIdentical));
}

#[test]
fn adversarial_oversize_plaintext_rejected() {
    // 16 MiB + 1 byte.
    let big = vec![0u8; 16 * 1024 * 1024 + 1];
    let witness = [0x42; 32];
    let err = create_duress_envelope(&big, b"decoy", b"real", b"duress", &witness, &mut OsRng)
        .unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::DuressEnvelopePlaintextTooLong { .. }
    ));
}

#[test]
fn adversarial_structural_indistinguishability() {
    // The two ciphertexts should be the same length when plaintexts
    // are the same length. Captor inspecting the disk image can't
    // tell which is "the real one" by size.
    let witness = [0x42; 32];
    let env = create_duress_envelope(
        b"identical length plaintext A",
        b"identical length plaintext B",
        b"real-code",
        b"duress-code",
        &witness,
        &mut OsRng,
    )
    .unwrap();
    assert_eq!(env.real_ct.len(), env.decoy_ct.len());
    assert_eq!(env.real_salt.len(), env.decoy_salt.len());
    assert_eq!(env.real_nonce.len(), env.decoy_nonce.len());
}

// ── DuressAlert adversarial ────────────────────────────────────────

#[test]
fn adversarial_alert_cross_subkey_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk_a, _) =
        mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let (sk_b, _) =
        mint_subkey(&master, DeviceClass::Laptop, [0xBB; DEVICE_ID_LEN], 0, 365).unwrap();
    let alert = sign_duress_alert(&sk_a, 1, [0xCC; 16]).unwrap();
    let err = alert.verify(&sk_b.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::DuressAlertVerifyFail));
}

#[test]
fn adversarial_alert_truncated_signature_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0xAA; DEVICE_ID_LEN], 0, 365).unwrap();
    let mut alert = sign_duress_alert(&sk, 1, [0xCC; 16]).unwrap();
    alert.subkey_sig.truncate(8);
    let err = alert.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::BadLength { .. }));
}

// ── Pairing cross-channel adversarial ─────────────────────────────

#[test]
fn adversarial_qr_only_pair_rejected() {
    // Attacker photographs the QR but can't reproduce audio/motion.
    let secret = b"real-pair-secret";
    let commits = vec![PairingCommitment::build(
        PairingChannel::Qr,
        secret,
        [0; 16],
        100,
    )];
    let err = verify_pairing_cross_channel(&commits, secret, 1_000).unwrap_err();
    assert!(matches!(err, DeviceMeshError::PairChannelMissing { .. }));
}

#[test]
fn adversarial_one_channel_lying_rejected() {
    // Attacker substitutes a fake commitment on the audio channel.
    let real = b"real-secret";
    let fake = b"fake-secret";
    let commits = vec![
        PairingCommitment::build(PairingChannel::Qr, real, [0; 16], 100),
        PairingCommitment::build(PairingChannel::Audio, fake, [1; 16], 110),
        PairingCommitment::build(PairingChannel::Motion, real, [2; 16], 120),
    ];
    let err = verify_pairing_cross_channel(&commits, real, 1_000).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::PairChannelCommitmentMismatch { .. }
    ));
}

#[test]
fn adversarial_stale_commitment_rejected() {
    // Attacker replays an OLD QR commitment + fresh audio + motion.
    let secret = b"secret";
    let commits = vec![
        PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 0),
        PairingCommitment::build(PairingChannel::Audio, secret, [1; 16], 50_000),
        PairingCommitment::build(PairingChannel::Motion, secret, [2; 16], 50_100),
    ];
    let err = verify_pairing_cross_channel(&commits, secret, 1_000).unwrap_err();
    assert!(matches!(
        err,
        DeviceMeshError::PairChannelOutOfWindow { .. }
    ));
}

#[test]
fn adversarial_duplicate_channel_doesnt_satisfy_required_three() {
    // Three commits, all on the QR channel. Should fail with
    // missing audio + motion.
    let secret = b"secret";
    let commits = vec![
        PairingCommitment::build(PairingChannel::Qr, secret, [0; 16], 100),
        PairingCommitment::build(PairingChannel::Qr, secret, [1; 16], 110),
        PairingCommitment::build(PairingChannel::Qr, secret, [2; 16], 120),
    ];
    let err = verify_pairing_cross_channel(&commits, secret, 1_000).unwrap_err();
    assert!(matches!(err, DeviceMeshError::PairChannelMissing { .. }));
}
