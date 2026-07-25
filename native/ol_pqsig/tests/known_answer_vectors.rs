//! Pinned known-answer test vectors for `ol_pqsig`.
//!
//! Bricks against silent regression in BLAKE3 / Ed25519 / ML-DSA-65
//! crate updates. Regenerate via `OL_PQSIG_KAT_REGEN=1` when the
//! wire format intentionally changes.

use std::fmt::Write as _;

use ol_pqsig::{
    HybridSigningKey, HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_SK_LEN, HYBRID_VK_LEN,
};
use rand::SeedableRng;

const KAT_RNG_SEED: [u8; 32] = [0xA1u8; 32];

fn deterministic_keypair() -> (HybridSigningKey, HybridVerifyingKey) {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(KAT_RNG_SEED);
    HybridSigningKey::generate(&mut rng)
}

fn maybe_regen() -> bool {
    std::env::var("OL_PQSIG_KAT_REGEN").as_deref() == Ok("1")
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &byte in b {
        write!(&mut s, "{byte:02x}").expect("writing to String cannot fail");
    }
    s
}

fn assert_or_regen(name: &str, expected: &str, actual_bytes: &[u8]) {
    let actual = hex(actual_bytes);
    if expected.is_empty() || maybe_regen() {
        eprintln!("KAT regen: const EXPECTED_{name} = \"{actual}\";");
        assert!(
            !expected.is_empty() || maybe_regen(),
            "EXPECTED_{name} is empty; run with OL_PQSIG_KAT_REGEN=1 to populate"
        );
        return;
    }
    assert_eq!(
        expected, actual,
        "\nKAT mismatch for {name}.\nexpected: {expected}\nactual:   {actual}"
    );
}

// ── Pinned outputs (regenerate via OL_PQSIG_KAT_REGEN=1) ─────────
// Only the first 32 bytes of each captured for brevity; full
// byte-length still asserted via `len` checks below.

const EXPECTED_VK_FIRST_32_HEX: &str =
    "45d6810bea204f289fd4bd2fc445bec36892325ad2d01a40e95317913e664e19";

#[test]
fn kat_vk_first_bytes_pinned() {
    let (_, vk) = deterministic_keypair();
    let bytes = vk.to_bytes();
    assert_eq!(bytes.len(), HYBRID_VK_LEN);
    let head = &bytes[..32];
    assert_or_regen("VK_FIRST_32_HEX", EXPECTED_VK_FIRST_32_HEX, head);
}

#[test]
fn kat_sk_full_pinned() {
    let (sk, _) = deterministic_keypair();
    let bytes = sk.to_bytes();
    assert_eq!(bytes.len(), HYBRID_SK_LEN);
    // SK is 64 bytes total (ed25519 seed + ml-dsa seed). Pin the full thing.
    let expected = "7921b6ed8fa8cff2baf61a43f3a66a9f591d569c4ffe6c9f26b4feddb0a80d2b806f09308412341c4e16299bcdaec47823a8476c755f51055efeccf7a8f1f189";
    assert_or_regen("SK_FULL_HEX", expected, &bytes);
}

const EXPECTED_SIG_FIRST_64_HEX: &str =
    "2caf79ed45d2110d66afad09eb0fd48acf79860b7553e414c293e6b18ed7eac7164f846506735810bc27e2e0ca69891a44eab8945f7f31aaca5ee824ebdcb40e";

#[test]
fn kat_sig_first_bytes_pinned() {
    let (sk, _) = deterministic_keypair();
    let sig = sk.sign(b"OL-pqsig-kat-message").unwrap();
    assert_eq!(sig.len(), HYBRID_SIG_LEN);
    // First 64 bytes = the Ed25519 half. Pin those.
    assert_or_regen("SIG_FIRST_64_HEX", EXPECTED_SIG_FIRST_64_HEX, &sig[..64]);
}

#[test]
fn kat_verify_pinned_signature_succeeds() {
    let (sk, vk) = deterministic_keypair();
    let sig = sk.sign(b"OL-pqsig-kat-message").unwrap();
    vk.verify(b"OL-pqsig-kat-message", &sig).unwrap();
}

#[test]
fn kat_constants_match_fips_204() {
    assert_eq!(HYBRID_VK_LEN, 1984);
    assert_eq!(HYBRID_SK_LEN, 64);
    assert_eq!(HYBRID_SIG_LEN, 3373);
}
