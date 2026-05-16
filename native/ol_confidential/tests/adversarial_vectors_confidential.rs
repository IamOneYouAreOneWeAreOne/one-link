//! Adversarial vectors for the Row 10 confidential-compute surface.
//!
//! Every test names the threat and asserts the surface rejects it.

use ol_confidential::{
    fresh_attestation_nonce, sign_attestation, verify_attestation, ConfidentialError,
    ConfidentialProvider, ConfidentialTier, ProviderTag, SoftwareProvider,
    ATTESTATION_FRESHNESS_WINDOW_SECS, ISSUER_SDP_PUBKEY_LEN,
};
use ol_pqsig::HybridSigningKey;
use rand::rngs::OsRng;

fn fresh_sk() -> HybridSigningKey {
    let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
    sk
}

const TEST_SDP_PUBKEY: [u8; ISSUER_SDP_PUBKEY_LEN] = [0xC1; ISSUER_SDP_PUBKEY_LEN];

fn sign_sw(
    sk: &HybridSigningKey,
    nonce: [u8; 32],
    issued: u64,
    deadline: u64,
    witness: Option<&[u8; 32]>,
    quote: Vec<u8>,
) -> ol_confidential::ConfidentialResult<ol_confidential::AttestationDoc> {
    sign_attestation(
        sk,
        ProviderTag::Software,
        nonce,
        issued,
        deadline,
        witness,
        quote,
        TEST_SDP_PUBKEY,
    )
}

fn verify_sw(
    doc: &ol_confidential::AttestationDoc,
    nonce: &[u8; 32],
    witness: Option<&[u8; 32]>,
    now: u64,
) -> ol_confidential::ConfidentialResult<()> {
    verify_attestation(
        doc,
        nonce,
        witness,
        now,
        ConfidentialTier::Software,
        &TEST_SDP_PUBKEY,
    )
}

#[test]
fn adversarial_sealed_blob_from_one_process_cant_open_in_another() {
    // T-LOCAL-MAL-USER: malware grabs a sealed key blob off disk
    // and tries to load it in another process. With a per-process
    // ephemeral sealing key, the AEAD tag fails in the new process.
    let p1 = SoftwareProvider::generate(&mut OsRng);
    let p2 = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x42u8; 32];
    let sealed = p1.seal_master(&seed).unwrap();
    let r = p2.sealed_sign(&sealed, b"x");
    assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
}

#[test]
fn adversarial_attestation_doc_from_one_master_cant_be_signed_by_another() {
    // T-REMOTE-IMPERSONATE: attacker constructs a doc claiming
    // master_vk=victim_vk but signs with their own key. Verify
    // must fail because the sig is under attacker_vk, not master_vk.
    let victim = fresh_sk();
    let attacker = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    // Attacker signs an attestation but claims victim's key.
    let mut doc = sign_sw(&attacker, nonce, 100, 120, None, vec![]).unwrap();
    // Swap the published master_vk to victim's.
    doc.master_vk = victim.verifying_key();
    let r = verify_sw(&doc, &nonce, None, 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_cross_provider_doc_via_tag_swap_breaks_master_sig() {
    // Attacker mints a Software doc, then swaps the provider_tag to
    // IntelSgx hoping the verifier upgrades trust. Since provider_tag
    // is in the signed transcript, the swap breaks the master sig.
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let mut doc = sign_sw(&sk, nonce, 100, 120, None, vec![]).unwrap();
    doc.provider_tag = ProviderTag::IntelSgx;
    let r = verify_sw(&doc, &nonce, None, 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_witness_swap_breaks_master_sig() {
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let witness_a = [0xAA; 32];
    let witness_b = [0xBB; 32];
    let mut doc = sign_sw(&sk, nonce, 100, 120, Some(&witness_a), vec![])
    .unwrap();
    // Swap the commitment leaf (attacker re-derives for a different
    // witness B). Sig over the original transcript should now fail.
    let new_cmt = {
        let mut h = blake3::Hasher::new();
        h.update(b"OL-confidential-field-witness-commitment-v1");
        h.update(&witness_b);
        *h.finalize().as_bytes()
    };
    doc.field_witness_commitment = Some(new_cmt);
    let r = verify_sw(&doc, &nonce, Some(&witness_b), 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_deadline_extension_breaks_master_sig() {
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let mut doc = sign_sw(&sk, nonce, 100, 120, None, vec![]).unwrap();
    // Attacker tries to extend the deadline to defeat the freshness
    // check. Sig over the original (deadline=120) bytes won't verify.
    doc.deadline_unix = 100 + ATTESTATION_FRESHNESS_WINDOW_SECS;
    let r = verify_sw(&doc, &nonce, None, 100 + ATTESTATION_FRESHNESS_WINDOW_SECS - 1);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_platform_quote_tamper_breaks_master_sig() {
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    // Issue with empty platform_quote (software baseline).
    let mut doc = sign_sw(&sk, nonce, 100, 120, None, vec![]).unwrap();
    // Attacker injects fake SGX quote bytes; sig should now fail.
    doc.platform_quote = b"fake SGX quote bytes".to_vec();
    let r = verify_sw(&doc, &nonce, None, 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_replay_after_deadline_rejected() {
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let doc = sign_sw(&sk, nonce, 100, 120, None, vec![]).unwrap();
    // The peer captured the doc and tries to replay it 100s later.
    let r = verify_sw(&doc, &nonce, None, 220);
    assert!(matches!(r, Err(ConfidentialError::AttestationExpired { .. })));
}

#[test]
fn adversarial_doc_minted_for_peer_a_rejected_by_peer_b() {
    let sk = fresh_sk();
    let nonce_a = fresh_attestation_nonce(&mut OsRng);
    let nonce_b = fresh_attestation_nonce(&mut OsRng);
    let doc = sign_sw(&sk, nonce_a, 100, 120, None, vec![]).unwrap();
    // Peer B's verifier sees a doc bound to peer A's nonce; rejects.
    let r = verify_sw(&doc, &nonce_b, None, 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationPeerNonceMismatch)));
}

#[test]
fn adversarial_truncated_sig_rejected() {
    let sk = fresh_sk();
    let nonce = fresh_attestation_nonce(&mut OsRng);
    let mut doc = sign_sw(&sk, nonce, 100, 120, None, vec![]).unwrap();
    doc.master_sig.truncate(doc.master_sig.len() - 1);
    let r = verify_sw(&doc, &nonce, None, 110);
    assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
}

#[test]
fn adversarial_sealed_blob_bit_flip_rejected() {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x55; 32];
    let mut sealed = provider.seal_master(&seed).unwrap();
    // Flip last byte (tag area).
    let last = sealed.bytes.len() - 1;
    sealed.bytes[last] ^= 0x01;
    let r = provider.sealed_sign(&sealed, b"x");
    assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
}

#[test]
fn adversarial_sealed_blob_truncated_rejected() {
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x55; 32];
    let mut sealed = provider.seal_master(&seed).unwrap();
    sealed.bytes.truncate(sealed.bytes.len() - 1);
    let r = provider.sealed_sign(&sealed, b"x");
    assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
}

#[test]
fn adversarial_child_key_does_not_leak_master_seed() {
    // Two children derived under different context tags must NOT
    // collide on verifying keys (no master-seed leak via constant
    // child seed).
    let provider = SoftwareProvider::generate(&mut OsRng);
    let seed = [0x77; 32];
    let sealed_master = provider.seal_master(&seed).unwrap();
    let c1 = provider.derive_child(&sealed_master, b"alpha").unwrap();
    let c2 = provider.derive_child(&sealed_master, b"beta").unwrap();
    let vk1 = provider.verifying_key(&c1).unwrap();
    let vk2 = provider.verifying_key(&c2).unwrap();
    assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    // Neither child VK should equal the master VK either.
    let vk_master = provider.verifying_key(&sealed_master).unwrap();
    assert_ne!(vk1.to_bytes(), vk_master.to_bytes());
    assert_ne!(vk2.to_bytes(), vk_master.to_bytes());
}
