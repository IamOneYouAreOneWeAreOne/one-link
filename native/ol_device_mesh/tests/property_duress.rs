//! Property tests for Row 8 Layer 10 duress + deniable + steg-pair.
//!
//! Argon2 derivations are slow (~50 ms); we keep iteration counts
//! deliberately low for the keygen-bound path. The cheap-derivation
//! path (pair commitments) runs at 1M.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_device_mesh::duress::{
    create_duress_envelope, sign_duress_alert, unlock_duress_envelope, PairingChannel,
    PairingCommitment, UnlockOutcome,
};
use ol_device_mesh::{mint_subkey, DeviceClass, DeviceMeshError, MasterIdentity, DEVICE_ID_LEN};

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn keygen_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        1_000
    } else {
        100
    }
}

// ── 1M-iter properties on pair commitments ─────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// PairingCommitment.matches is true iff the secret matches.
    #[test]
    fn pair_commitment_matches_iff_secret_matches(
        secret in prop::collection::vec(any::<u8>(), 1..32),
        wrong in prop::collection::vec(any::<u8>(), 1..32),
        nonce in any::<[u8; 16]>(),
        ts in any::<u64>(),
    ) {
        prop_assume!(secret != wrong);
        let c = PairingCommitment::build(PairingChannel::Qr, &secret, nonce, ts);
        prop_assert!(c.matches(&secret));
        prop_assert!(!c.matches(&wrong));
    }

    /// PairingCommitment is deterministic on its inputs.
    #[test]
    fn pair_commitment_deterministic(
        secret in prop::collection::vec(any::<u8>(), 1..32),
        nonce in any::<[u8; 16]>(),
        ts in any::<u64>(),
    ) {
        let a = PairingCommitment::build(PairingChannel::Qr, &secret, nonce, ts);
        let b = PairingCommitment::build(PairingChannel::Qr, &secret, nonce, ts);
        prop_assert_eq!(a.commitment, b.commitment);
    }

    /// Distinct channel tags yield distinct commitments for the
    /// same (secret, nonce, ts).
    #[test]
    fn pair_commitment_channel_separated(
        secret in prop::collection::vec(any::<u8>(), 1..32),
        nonce in any::<[u8; 16]>(),
        ts in any::<u64>(),
    ) {
        let qr = PairingCommitment::build(PairingChannel::Qr, &secret, nonce, ts);
        let au = PairingCommitment::build(PairingChannel::Audio, &secret, nonce, ts);
        let mo = PairingCommitment::build(PairingChannel::Motion, &secret, nonce, ts);
        prop_assert_ne!(qr.commitment, au.commitment);
        prop_assert_ne!(qr.commitment, mo.commitment);
        prop_assert_ne!(au.commitment, mo.commitment);
    }
}

// ── 100-iter properties on Argon2-bound paths ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: keygen_cases(),
        max_global_rejects: keygen_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Real-code + correct witness ALWAYS unlocks to real plaintext.
    #[test]
    fn real_code_with_witness_round_trips(
        real in prop::collection::vec(any::<u8>(), 1..64),
        decoy in prop::collection::vec(any::<u8>(), 1..64),
        witness in any::<[u8; 32]>(),
    ) {
        let real_code = b"real-code-v1";
        let decoy_code = b"decoy-code-v1";
        let env = create_duress_envelope(
            &real, &decoy, real_code, decoy_code, &witness, &mut OsRng,
        ).unwrap();
        let outcome = unlock_duress_envelope(&env, real_code, Some(&witness)).unwrap();
        let ok = matches!(outcome, UnlockOutcome::Real(_));
        prop_assert!(ok);
    }

    /// Decoy code (no witness needed) ALWAYS unlocks to decoy.
    #[test]
    fn decoy_code_unlocks_decoy(
        real in prop::collection::vec(any::<u8>(), 1..64),
        decoy in prop::collection::vec(any::<u8>(), 1..64),
        witness in any::<[u8; 32]>(),
    ) {
        let real_code = b"real-pwd-xyz";
        let decoy_code = b"decoy-pwd-abc";
        let env = create_duress_envelope(
            &real, &decoy, real_code, decoy_code, &witness, &mut OsRng,
        ).unwrap();
        let outcome = unlock_duress_envelope(&env, decoy_code, None).unwrap();
        let ok = matches!(outcome, UnlockOutcome::Decoy(_));
        prop_assert!(ok);
    }
}

// ── DuressAlert sign+verify ───────────────────────────────────────

#[test]
fn duress_alert_sign_verify_round_trip() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let alert = sign_duress_alert(&sk, 1_700_000_000, [0xAA; 16]).unwrap();
    alert.verify(&sk.verifying_key()).unwrap();
}

#[test]
fn duress_alert_tampered_timestamp_rejected() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55; DEVICE_ID_LEN];
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let mut alert = sign_duress_alert(&sk, 1_700_000_000, [0xAA; 16]).unwrap();
    alert.triggered_unix = 9_999;
    let err = alert.verify(&sk.verifying_key()).unwrap_err();
    assert!(matches!(err, DeviceMeshError::DuressAlertVerifyFail));
}
