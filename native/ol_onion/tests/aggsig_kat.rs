//! Known-answer test vectors for Sphinx Coherence T1.5 (Schnorr aggregation).
//!
//! Pins:
//! - Verifying key bytes for seeded signing keys (0x00, 0x01, 0xFF).
//! - Signature bytes for fixed (seed, msg) pairs.
//! - Cross-verification: each pinned signature verifies under the
//!   pinned verifying key for the pinned message.
//!
//! Regenerate with `OL_AGGSIG_KAT_REGEN=1` when the primitive's
//! transcript wire format or domain-separation constants change.

use ol_onion::sphinx::aggsig::{verify, SchnorrSignature, SchnorrSigningKey, SchnorrVerifyingKey};

// ── Pinned expected outputs ──────────────────────────────────────

const EXPECTED_VK_SEED_00_HEX: &str =
    "98501549bb130856a27ca267a819d72d2da5f5d1f7c130a0be8b438eda9fe45c";
const EXPECTED_VK_SEED_01_HEX: &str =
    "982be0c26963f0aaa676b9cf75751547525520312192ab790b323c8e75f86107";
const EXPECTED_VK_SEED_FF_HEX: &str =
    "265440dc656a614dfa4702b8b1950864043ec4048cf6cef6a5dec35221d83b18";

const EXPECTED_SIG_SEED_00_MSG_EMPTY_HEX: &str =
    "98a977c006e09de8844edd9702b2de7d8c3945a5531af4718830fa3773f57b12848e43ce3d2760e786cc423c30eae0a627c18b8603e464f1bde214020f782201";
const EXPECTED_SIG_SEED_01_MSG_HELLO_HEX: &str =
    "aa8ac0c6f2058d6b9da15ae6bbe9453651d8197cdf053e6cea4be6c6ecb4eb049111fadf7004db3ac9ee43f05ab0ff02eb17a014ae34826a54823d778f34ea06";
const EXPECTED_SIG_SEED_FF_MSG_LONG_HEX: &str =
    "b4da6653859da0b2f05cf8ef37176eaf04bb3fcca905bd1102b9d218acb8ee57d816a4aba22149571e88682ed034bd62b46b7522dd80825de13732087258280d";

// ── Helpers ──────────────────────────────────────────────────────

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn maybe_regen() -> bool {
    std::env::var("OL_AGGSIG_KAT_REGEN").as_deref() == Ok("1")
}

fn assert_or_regen(name: &str, expected: &str, actual: &str) {
    if expected.is_empty() || maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name}_HEX = \"{actual}\";");
        if expected.is_empty() && !maybe_regen() {
            panic!("EXPECTED_{name}_HEX is empty; run with OL_AGGSIG_KAT_REGEN=1");
        }
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\nexpected: {expected}\nactual:   {actual}"
    );
}

// ── Pinned KATs ──────────────────────────────────────────────────

#[test]
fn vk_for_seed_00() {
    let sk = SchnorrSigningKey::from_seed(&[0x00; 32]);
    let vk = sk.verifying_key();
    assert_or_regen("VK_SEED_00", EXPECTED_VK_SEED_00_HEX, &hex(&vk.0));
}

#[test]
fn vk_for_seed_01() {
    let sk = SchnorrSigningKey::from_seed(&[0x01; 32]);
    let vk = sk.verifying_key();
    assert_or_regen("VK_SEED_01", EXPECTED_VK_SEED_01_HEX, &hex(&vk.0));
}

#[test]
fn vk_for_seed_ff() {
    let sk = SchnorrSigningKey::from_seed(&[0xFF; 32]);
    let vk = sk.verifying_key();
    assert_or_regen("VK_SEED_FF", EXPECTED_VK_SEED_FF_HEX, &hex(&vk.0));
}

#[test]
fn sig_for_seed_00_msg_empty() {
    let sk = SchnorrSigningKey::from_seed(&[0x00; 32]);
    let sig = sk.sign(b"");
    assert_or_regen(
        "SIG_SEED_00_MSG_EMPTY",
        EXPECTED_SIG_SEED_00_MSG_EMPTY_HEX,
        &hex(&sig.0),
    );
}

#[test]
fn sig_for_seed_01_msg_hello() {
    let sk = SchnorrSigningKey::from_seed(&[0x01; 32]);
    let sig = sk.sign(b"hello");
    assert_or_regen(
        "SIG_SEED_01_MSG_HELLO",
        EXPECTED_SIG_SEED_01_MSG_HELLO_HEX,
        &hex(&sig.0),
    );
}

#[test]
fn sig_for_seed_ff_msg_long() {
    let sk = SchnorrSigningKey::from_seed(&[0xFF; 32]);
    let msg = vec![0xA5u8; 1024];
    let sig = sk.sign(&msg);
    assert_or_regen(
        "SIG_SEED_FF_MSG_LONG",
        EXPECTED_SIG_SEED_FF_MSG_LONG_HEX,
        &hex(&sig.0),
    );
}

#[test]
fn pinned_signatures_self_verify() {
    // Each pinned signature must verify under its pinned VK and msg.
    // Skip if KATs haven't been pinned yet (regen mode).
    if maybe_regen() {
        return;
    }
    let cases: &[(&str, &str, &[u8])] = &[
        (
            EXPECTED_VK_SEED_00_HEX,
            EXPECTED_SIG_SEED_00_MSG_EMPTY_HEX,
            b"",
        ),
        (
            EXPECTED_VK_SEED_01_HEX,
            EXPECTED_SIG_SEED_01_MSG_HELLO_HEX,
            b"hello",
        ),
    ];
    let long_msg = vec![0xA5u8; 1024];
    let mut all_cases: Vec<(&str, &str, &[u8])> = cases.to_vec();
    all_cases.push((
        EXPECTED_VK_SEED_FF_HEX,
        EXPECTED_SIG_SEED_FF_MSG_LONG_HEX,
        long_msg.as_slice(),
    ));
    for (vk_hex, sig_hex, msg) in all_cases {
        let vk_bytes = hex_to_array_32(vk_hex);
        let sig_bytes = hex_to_array_64(sig_hex);
        let vk = SchnorrVerifyingKey(vk_bytes);
        let sig = SchnorrSignature(sig_bytes);
        verify(&vk, msg, &sig).expect("pinned KAT must self-verify");
    }
}

fn hex_to_array_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex_to_array_64(s: &str) -> [u8; 64] {
    assert_eq!(s.len(), 128);
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
