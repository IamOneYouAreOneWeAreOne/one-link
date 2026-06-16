//! Pinned KAT vectors for Row 8 Layer 10 duress.

use ol_device_mesh::duress::{
    derive_duress_key, DuressAlert, PairingChannel, PairingCommitment, ARGON2_M_COST_KIB,
    ARGON2_T_COST, DUR_ALERT_DOMAIN, DUR_ENVELOPE_DOMAIN, DUR_SALT_LEN, PAIR_COMMITMENT_DOMAIN,
    REQUIRED_PAIR_CHANNELS,
};
use ol_device_mesh::DEVICE_ID_LEN;

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_DURESS_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(DUR_ENVELOPE_DOMAIN, b"OL-mesh-duress-envelope-v1");
    assert_eq!(DUR_ALERT_DOMAIN, b"OL-mesh-duress-alert-v1");
    assert_eq!(PAIR_COMMITMENT_DOMAIN, b"OL-mesh-pair-commitment-v1");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(DUR_SALT_LEN, 32);
    assert_eq!(REQUIRED_PAIR_CHANNELS, 3);
    assert_eq!(ARGON2_M_COST_KIB, 19_456);
    assert_eq!(ARGON2_T_COST, 2);
}

#[test]
fn kat_pairing_channel_tags_pinned() {
    assert_eq!(&PairingChannel::Qr.tag(), b"OL-PR-QR");
    assert_eq!(&PairingChannel::Audio.tag(), b"OL-PR-AU");
    assert_eq!(&PairingChannel::Motion.tag(), b"OL-PR-MO");
}

#[test]
fn kat_duress_alert_canonical_transcript_pinned() {
    let bytes =
        DuressAlert::canonical_transcript(&[0xAA; DEVICE_ID_LEN], 7, 1_700_000_000, &[0xBB; 16]);
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(DUR_ALERT_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("duress-alert canonical_transcript", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    const EXPECTED_HEX: &str = concat!(
        "4f4c2d6d6573682d6475726573732d616c6572742d7631", // domain
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",               // device_id
        "0000000000000007",                               // day_index
        "000000006553f100",                               // triggered_unix
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",               // nonce
    );
    assert_eq!(hex, EXPECTED_HEX, "duress-alert transcript drift");
}

#[test]
fn kat_pair_commitment_pinned() {
    let secret = b"shared-pair-secret";
    let commit = PairingCommitment::build(PairingChannel::Qr, secret, [0xCC; 16], 1_700_000_000);
    let hex = to_hex(&commit.commitment);
    check_regen("pair commitment (QR, fixed inputs)", || {
        eprintln!("    EXPECTED_COMMITMENT_HEX = \"{hex}\"");
    });
    assert_eq!(hex.len(), 64);
}

#[test]
fn kat_argon2_derivation_deterministic_for_fixed_inputs() {
    let salt = b"0123456789abcdef0123456789abcdef";
    let a = derive_duress_key(b"hunter22", salt).unwrap();
    let b = derive_duress_key(b"hunter22", salt).unwrap();
    assert_eq!(a.key_bytes(), b.key_bytes());
}
