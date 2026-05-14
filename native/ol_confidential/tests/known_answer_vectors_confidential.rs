//! Pinned known-answer vectors for the Row 10 confidential-compute
//! surface. Any change in canonical bytes, provider-tag wire-byte,
//! or signing key derivation will fail these vectors — forcing the
//! author to consider whether the change is a deliberate version bump.

use ol_confidential::{
    attestation::canonical_attestation_transcript, ConfidentialProvider, ProviderTag,
    SoftwareProvider,
};
use ol_pqsig::HybridSigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

#[test]
fn kat_provider_tag_byte_codes_pinned() {
    // The numeric tag values are wire-format. Changing any of these
    // is a breaking change.
    assert_eq!(ProviderTag::Software.as_u8(), 1);
    assert_eq!(ProviderTag::AppleSecureEnclave.as_u8(), 2);
    assert_eq!(ProviderTag::AndroidStrongBox.as_u8(), 3);
    assert_eq!(ProviderTag::WindowsTpm.as_u8(), 4);
    assert_eq!(ProviderTag::IntelSgx.as_u8(), 5);
    assert_eq!(ProviderTag::AmdSevSnp.as_u8(), 6);
    assert_eq!(ProviderTag::ArmTrustZone.as_u8(), 7);
}

#[test]
fn kat_provider_tag_round_trip() {
    for raw in 1u8..=7 {
        let tag = ProviderTag::from_u8(raw).expect("known tag");
        assert_eq!(tag.as_u8(), raw);
    }
    // Unknown tag returns None (forward-compat).
    assert!(ProviderTag::from_u8(0).is_none());
    assert!(ProviderTag::from_u8(8).is_none());
    assert!(ProviderTag::from_u8(255).is_none());
}

#[test]
fn kat_attestation_transcript_pinned_no_witness() {
    // Deterministic master.
    let (_sk, vk) = HybridSigningKey::generate(&mut ChaCha20Rng::from_seed([0xAB; 32]));
    let nonce = [0x42u8; 32];
    let bytes = canonical_attestation_transcript(
        ProviderTag::Software,
        &vk,
        &nonce,
        100,
        120,
        None,
        &[],
    );
    // 32-byte BLAKE3 digest of (domain || tag || vk || nonce || times
    // || witness-presence-flag || qlen || quote). Pin the hex to lock
    // the wire format. Regenerating this vector means a deliberate
    // wire bump.
    let hex_now = hex::encode(&bytes);
    insta_eq(&hex_now, &EXPECTED_KAT_TRANSCRIPT_NO_WITNESS);
}

#[test]
fn kat_attestation_transcript_pinned_with_witness() {
    let (_sk, vk) = HybridSigningKey::generate(&mut ChaCha20Rng::from_seed([0xCD; 32]));
    let nonce = [0x77u8; 32];
    let witness = [0xEEu8; 32];
    let bytes = canonical_attestation_transcript(
        ProviderTag::Software,
        &vk,
        &nonce,
        1_000_000,
        1_000_030,
        Some(&witness),
        b"sgx-mock-quote",
    );
    let hex_now = hex::encode(&bytes);
    insta_eq(&hex_now, &EXPECTED_KAT_TRANSCRIPT_WITH_WITNESS);
}

#[test]
fn kat_software_provider_deterministic_from_seed() {
    // Same provider seed + master seed must produce signatures that
    // verify under the same vk. (This is the "deterministic
    // for incident-response replay" guarantee.)
    let prov_a = SoftwareProvider::from_seed(&[0x10; 32]);
    let prov_b = SoftwareProvider::from_seed(&[0x10; 32]);
    let master = [0x20; 32];
    let sealed_a = prov_a.seal_master(&master).unwrap();
    let vk = prov_a.verifying_key(&sealed_a).unwrap();
    // Provider B can sign blobs created by Provider A.
    let sig = prov_b.sealed_sign(&sealed_a, b"hello").unwrap();
    vk.verify(b"hello", &sig).unwrap();
}

fn insta_eq(actual: &str, expected: &str) {
    if expected.is_empty() {
        // Bootstrap: print the value the test should pin to.
        // CI sets ONE_LINK_KAT_BOOTSTRAP=1 once, the author copies
        // the printed hex into EXPECTED_*. Empty in CI = test fails.
        if std::env::var("ONE_LINK_KAT_BOOTSTRAP").as_deref() == Ok("1") {
            eprintln!("KAT bootstrap value: {actual}");
            return;
        }
        panic!("KAT expected value not pinned; set ONE_LINK_KAT_BOOTSTRAP=1 then paste {actual}");
    }
    assert_eq!(actual, expected, "KAT regression — wire format changed");
}

// Pinned hex from bootstrap run. Regenerate with
// `ONE_LINK_KAT_BOOTSTRAP=1 cargo test -p ol_confidential --test known_answer_vectors_confidential`.
const EXPECTED_KAT_TRANSCRIPT_NO_WITNESS: &str =
    "d6c12dffc0fd68622bf54a11aa7092b5f4f1ded4786378caaa1029ecb301c2e9";
const EXPECTED_KAT_TRANSCRIPT_WITH_WITNESS: &str =
    "b28304aa1443d0792123cf86213b004842a07a71991abf1a1e5265a9c93700b9";
