//! End-to-end TPM-hardware round trip: produce a `platform_quote`
//! on the real TPM in this machine, then verify it with the
//! cross-platform p256 verifier.
//!
//! Requires Windows + a TPM 2.0 + the `windows-tpm` feature. Tests
//! are #[ignore]'d so default `cargo test` skips them on hosts that
//! don't have hardware access. Run with `--features windows-tpm
//! --ignored` to exercise.

#![cfg(all(target_os = "windows", feature = "windows-tpm"))]

use ol_confidential::platform_quote::{
    canonical_platform_quote_subtranscript, parse_platform_quote, verify_platform_quote,
};
use ol_confidential::windows_tpm::{produce_platform_quote, TpmAttestationKey};
use ol_confidential::ProviderTag;

const VK_PLACEHOLDER: [u8; 1984] = [0x42u8; 1984];

fn fresh_key(name_suffix: &str) -> TpmAttestationKey {
    let name = format!("OL-confidential-tpm-round-trip-{name_suffix}-v1");
    TpmAttestationKey::acquire_or_create(&name).expect("TPM key acquire")
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_verifies_cross_platform() {
    let key = fresh_key("verifies");
    let peer_nonce = [0xAA; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    let quote = produce_platform_quote(&key, &digest).expect("produce");
    let pub_blob = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    )
    .expect("verify");
    assert!(!pub_blob.is_empty());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_wrong_master_vk() {
    let key = fresh_key("wrong-vk");
    let peer_nonce = [0x11; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    let quote = produce_platform_quote(&key, &digest).expect("produce");

    // Verifier supplies a DIFFERENT master_vk → sub-transcript
    // differs → sig fails.
    let wrong_vk = [0x99u8; 1984];
    let r = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &wrong_vk,
        &peer_nonce,
        100,
        120,
        None,
    );
    assert!(r.is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_wrong_peer_nonce() {
    let key = fresh_key("wrong-nonce");
    let peer_nonce_a = [0x22; 32];
    let peer_nonce_b = [0x33; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce_a,
        100,
        120,
        None,
    );
    let quote = produce_platform_quote(&key, &digest).expect("produce");
    let r = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce_b,
        100,
        120,
        None,
    );
    assert!(r.is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_tampered_signature() {
    let key = fresh_key("tampered");
    let peer_nonce = [0x44; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    let mut quote = produce_platform_quote(&key, &digest).expect("produce");
    // Flip a byte deep inside the sig area.
    let len = quote.len();
    quote[len - 5] ^= 0x01;
    let r = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    assert!(r.is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_persists_across_acquire_calls() {
    // Two separate acquire_or_create calls with the same name MUST
    // return the same key (verified via the public blob matching).
    let key1 = fresh_key("persist");
    let key2 = fresh_key("persist");
    let pub1 = key1.public_blob().expect("export 1");
    let pub2 = key2.public_blob().expect("export 2");
    assert_eq!(pub1, pub2, "persisted key must round-trip across handles");
}

#[test]
#[ignore = "requires hardware TPM access"]
fn full_attestation_doc_with_tpm_round_trip() {
    use ol_confidential::windows_tpm::{attest_with_tpm, verify_attestation_with_tpm};
    use ol_confidential::{ConfidentialProvider, SoftwareProvider};
    use rand::rngs::OsRng;

    let tpm = fresh_key("full-rt");
    let sw = SoftwareProvider::generate(&mut OsRng);
    let master_seed = [0x55u8; 32];
    let sealed = sw.seal_master(&master_seed).unwrap();
    let peer_nonce = [0xCC; 32];

    let doc = attest_with_tpm(&sw, &sealed, &tpm, peer_nonce, 1_000, 1_020, None).unwrap();
    let tpm_pub = verify_attestation_with_tpm(&doc, &peer_nonce, None, 1_010).unwrap();
    assert!(!tpm_pub.is_empty());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn full_attestation_doc_rejected_when_software_provider_tries_to_verify() {
    use ol_confidential::windows_tpm::attest_with_tpm;
    use ol_confidential::{verify_attestation, SoftwareProvider};
    use ol_confidential::{ConfidentialProvider};
    use rand::rngs::OsRng;

    let tpm = fresh_key("sw-tries");
    let sw = SoftwareProvider::generate(&mut OsRng);
    let master_seed = [0x55u8; 32];
    let sealed = sw.seal_master(&master_seed).unwrap();
    let peer_nonce = [0xEE; 32];

    let doc = attest_with_tpm(&sw, &sealed, &tpm, peer_nonce, 1_000, 1_020, None).unwrap();
    // The doc has provider_tag = WindowsTpm. Software-only verify
    // (which does NOT validate platform_quote) should still accept
    // the MASTER sig — the master sig commits to the platform_quote
    // bytes, so any tamper breaks it. This call SHOULD pass.
    verify_attestation(&doc, &peer_nonce, None, 1_010).unwrap();
}

#[test]
#[ignore = "requires hardware TPM access"]
fn full_attestation_doc_rejects_swapped_platform_quote() {
    use ol_confidential::windows_tpm::{attest_with_tpm, verify_attestation_with_tpm};
    use ol_confidential::{ConfidentialProvider, SoftwareProvider};
    use rand::rngs::OsRng;

    let tpm = fresh_key("swap-pq");
    let sw = SoftwareProvider::generate(&mut OsRng);
    let master_seed = [0x55u8; 32];
    let sealed = sw.seal_master(&master_seed).unwrap();
    let peer_nonce_a = [0xA0; 32];
    let peer_nonce_b = [0xB0; 32];

    let doc_a = attest_with_tpm(&sw, &sealed, &tpm, peer_nonce_a, 1_000, 1_020, None).unwrap();
    let doc_b = attest_with_tpm(&sw, &sealed, &tpm, peer_nonce_b, 2_000, 2_020, None).unwrap();
    // Swap doc_a's platform_quote for doc_b's. master sig over
    // doc_a's transcript (with doc_a's original platform_quote) now
    // sees the wrong platform_quote → master sig FAILS verify.
    let mut tampered = doc_a.clone();
    tampered.platform_quote = doc_b.platform_quote.clone();
    let r = verify_attestation_with_tpm(&tampered, &peer_nonce_a, None, 1_010);
    assert!(r.is_err(), "platform_quote swap must break master sig");
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_wrong_issued_or_deadline() {
    let key = fresh_key("wrong-time");
    let peer_nonce = [0x66; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    let quote = produce_platform_quote(&key, &digest).expect("produce");
    // Wrong issued_unix.
    assert!(verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        101,
        120,
        None,
    )
    .is_err());
    // Wrong deadline_unix.
    assert!(verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        121,
        None,
    )
    .is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_witness_mismatch() {
    let key = fresh_key("wrong-witness");
    let peer_nonce = [0x77; 32];
    let witness_commitment_a = [0xAA; 32];
    let witness_commitment_b = [0xBB; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        Some(&witness_commitment_a),
    );
    let quote = produce_platform_quote(&key, &digest).expect("produce");
    // Same quote but verifier supplies a different witness commitment.
    let r = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        Some(&witness_commitment_b),
    );
    assert!(r.is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_quote_rejects_truncated_pub_blob() {
    let key = fresh_key("trunc-pub");
    let peer_nonce = [0x99; 32];
    let digest = canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    let mut quote = produce_platform_quote(&key, &digest).expect("produce");
    // Truncate one byte off the end — sig integrity fails.
    quote.pop();
    let r = verify_platform_quote(
        &quote,
        ProviderTag::WindowsTpm,
        &VK_PLACEHOLDER,
        &peer_nonce,
        100,
        120,
        None,
    );
    assert!(r.is_err());
}

#[test]
#[ignore = "requires hardware TPM access"]
fn tpm_two_distinct_key_names_produce_distinct_keys() {
    let a = fresh_key("distinct-a");
    let b = fresh_key("distinct-b");
    let pa = a.public_blob().expect("export a");
    let pb = b.public_blob().expect("export b");
    assert_ne!(pa, pb, "different key names must give different keys");
}
