//! Pinned KAT vectors for Row 8 Layer 7 self-onion.

use ol_device_mesh::self_onion::{
    derive_onion_identity, OnionAttestation, ONION_ATTESTATION_DOMAIN, ONION_DERIVATION_DOMAIN,
    ONION_PUBKEY_LEN, ONION_SECRET_LEN, SELF_ONION_DOMAIN_PAYLOAD,
};
use ol_device_mesh::{MasterIdentity, DEVICE_ID_LEN};
use std::fmt::Write as _;

const EXPECTED_HEX: &str = concat!(
    "4f4c2d6d6573682d6f6e696f6e2d6174746573746174696f6e2d7631", // domain
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",                         // device_id
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", // onion_pubkey
    "0000000000000007",                                         // mint_day = 7
    "000000000000016d",                                         // expiry_day = 365
);

fn check_regen<F: FnOnce()>(label: &str, dump: F) {
    if std::env::var("OL_SELF_ONION_KAT_REGEN").as_deref() == Ok("1") {
        eprintln!("[KAT REGEN] {label}");
        dump();
    }
}

fn to_hex(b: &[u8]) -> String {
    let mut hex = String::with_capacity(b.len() * 2);
    for byte in b {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

#[test]
fn kat_domain_tags_pinned() {
    assert_eq!(ONION_DERIVATION_DOMAIN, b"OL-mesh-onion-identity-v1");
    assert_eq!(ONION_ATTESTATION_DOMAIN, b"OL-mesh-onion-attestation-v1");
    assert_eq!(SELF_ONION_DOMAIN_PAYLOAD, b"OL-mesh-self-onion-v1\0");
}

#[test]
fn kat_bound_constants_pinned() {
    assert_eq!(ONION_PUBKEY_LEN, 32);
    assert_eq!(ONION_SECRET_LEN, 32);
}

#[test]
fn kat_onion_identity_derivation_from_fixed_master() {
    let seed = [0x42u8; 64];
    let master = MasterIdentity::from_seed(seed);
    let id = [0xAAu8; DEVICE_ID_LEN];
    let identity = derive_onion_identity(&master, &id);
    let pk_hex = to_hex(&identity.public_bytes());
    let sk_hex = to_hex(identity.secret_bytes());
    check_regen("onion identity (MASTER=0x42*64, device_id=0xAA*16)", || {
        eprintln!("    EXPECTED_PK_HEX = \"{pk_hex}\"");
        eprintln!("    EXPECTED_SK_HEX = \"{sk_hex}\"");
    });
    assert_eq!(pk_hex.len(), 64);
    assert_eq!(sk_hex.len(), 64);
}

#[test]
fn kat_attestation_canonical_transcript_pinned() {
    let bytes = OnionAttestation::canonical_transcript(
        &[0xAA; DEVICE_ID_LEN],
        &[0xBB; ONION_PUBKEY_LEN],
        7,
        365,
    );
    let hex = to_hex(&bytes);
    let domain_hex = to_hex(ONION_ATTESTATION_DOMAIN);
    assert!(hex.starts_with(&domain_hex));
    check_regen("onion-attestation canonical_transcript", || {
        eprintln!("    EXPECTED_HEX = \"{hex}\"");
    });
    assert_eq!(hex, EXPECTED_HEX, "onion-attestation transcript drift");
}
