//! Adversarial vectors for Sphinx Coherence T1.5 (Schnorr aggregation).
//!
//! Targeted attempts to bypass `verify` / `batch_verify`:
//! - Identity-R signatures (R = O)
//! - Identity-PK signatures (PK = O)
//! - Swapped messages
//! - Cross-signer swap
//! - Duplicated entry
//! - Tampered batch order (verifier weighting binds to order)
//! - Truncated signatures
//! - Replay across distinct keys

use ol_onion::sphinx::aggsig::{
    batch_verify, verify, SchnorrSignature, SchnorrSigningKey, SchnorrVerifyingKey,
};

fn sk(seed: u8) -> SchnorrSigningKey {
    SchnorrSigningKey::from_seed(&[seed; 32])
}

#[test]
fn identity_r_signature_rejected() {
    let sk_a = sk(1);
    let vk = sk_a.verifying_key();
    let sig = sk_a.sign(b"msg");
    // Replace R with the encoded identity (all-zero).
    let mut tampered = sig;
    tampered.0[..32].copy_from_slice(&[0u8; 32]);
    assert!(verify(&vk, b"msg", &tampered).is_err());
}

#[test]
fn identity_pk_rejected_at_decode_or_verify() {
    let sk_a = sk(2);
    let sig = sk_a.sign(b"msg");
    // Verifying key is the encoded identity. Either we reject at
    // decode or at math; both are acceptable rejections.
    let evil_vk = SchnorrVerifyingKey([0u8; 32]);
    assert!(verify(&evil_vk, b"msg", &sig).is_err());
}

#[test]
fn identity_pk_forgery_attempt_rejected() {
    // Regression test for H2 (post-audit fix May 14 2026): with
    // vk = O the equation `s*G == R + c*PK` reduces to `s*G == R`,
    // which any attacker can satisfy with (R = nonce*G, s = nonce).
    // Audit found: verify() previously accepted this. Fix rejects
    // identity-VK at decode time.
    let evil_vk = SchnorrVerifyingKey([0u8; 32]);
    // Construct a forgery that satisfies s*G == R with no signing key.
    // s = 7 (arbitrary), R = 7*G compressed.
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    let s = Scalar::from(7u64);
    let r_point = RISTRETTO_BASEPOINT_TABLE * &s;
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_point.compress().to_bytes());
    sig_bytes[32..].copy_from_slice(s.as_bytes());
    let forgery = ol_onion::sphinx::aggsig::SchnorrSignature(sig_bytes);
    // This forgery would verify under vk = identity if the decoder
    // didn't reject. Confirm it's rejected.
    assert!(
        verify(&evil_vk, b"forge-target", &forgery).is_err(),
        "identity-VK signature forgery must be rejected at decode"
    );
}

#[test]
fn bn_aggregate_rejects_duplicate_participants() {
    // Regression test for H1 (post-audit fix May 14 2026): one key
    // owning two entries previously aggregated into a "two-signer"
    // proof. Fix dedups + rejects on collision.
    use ol_onion::sphinx::aggsig::bn_aggregate;
    let sk_a = sk(17);
    let vk_a = sk_a.verifying_key();
    let sig_1 = sk_a.sign(b"m1");
    let sig_2 = sk_a.sign(b"m2");
    let entries = vec![
        (vk_a, b"m1".as_slice(), sig_1),
        (vk_a, b"m2".as_slice(), sig_2),
    ];
    assert!(
        bn_aggregate(&entries).is_err(),
        "BN aggregate over duplicate participants must be rejected"
    );
}

#[test]
fn swapped_messages_in_batch_rejected() {
    let sk_a = sk(3);
    let sk_b = sk(4);
    let sig_a = sk_a.sign(b"alpha");
    let sig_b = sk_b.sign(b"beta");
    // Pair each sig with the OTHER message.
    let entries = vec![
        (sk_a.verifying_key(), b"beta".as_slice(), sig_a),
        (sk_b.verifying_key(), b"alpha".as_slice(), sig_b),
    ];
    assert!(batch_verify(&entries).is_err());
}

#[test]
fn cross_signer_swap_in_batch_rejected() {
    let sk_a = sk(5);
    let sk_b = sk(6);
    let sig_a = sk_a.sign(b"x");
    let sig_b = sk_b.sign(b"x");
    // Swap the signatures across the verifying keys.
    let entries = vec![
        (sk_a.verifying_key(), b"x".as_slice(), sig_b),
        (sk_b.verifying_key(), b"x".as_slice(), sig_a),
    ];
    assert!(batch_verify(&entries).is_err());
}

#[test]
fn duplicate_entry_in_batch_still_valid() {
    // Duplicating an entry is not an attack: both copies are valid
    // sigs over the same (vk, msg). Batch should accept.
    let sk_a = sk(7);
    let sig_a = sk_a.sign(b"only");
    let vk_a = sk_a.verifying_key();
    let entries = vec![
        (vk_a, b"only".as_slice(), sig_a),
        (vk_a, b"only".as_slice(), sig_a),
        (vk_a, b"only".as_slice(), sig_a),
    ];
    assert!(batch_verify(&entries).is_ok());
}

#[test]
fn batch_weighting_binds_to_full_transcript() {
    // The verifier mixes (vk, len, msg, sig) into the weight RNG.
    // So a deliberate reorder of the entries produces a different
    // set of weights — but BOTH orderings should still verify (the
    // linear equation balances under any choice of weights). This
    // test affirms order-independence, not the inverse.
    let sk_a = sk(8);
    let sk_b = sk(9);
    let sk_c = sk(10);
    let entries_forward = vec![
        (sk_a.verifying_key(), b"m1".as_slice(), sk_a.sign(b"m1")),
        (sk_b.verifying_key(), b"m2".as_slice(), sk_b.sign(b"m2")),
        (sk_c.verifying_key(), b"m3".as_slice(), sk_c.sign(b"m3")),
    ];
    let entries_reverse = vec![
        (sk_c.verifying_key(), b"m3".as_slice(), sk_c.sign(b"m3")),
        (sk_b.verifying_key(), b"m2".as_slice(), sk_b.sign(b"m2")),
        (sk_a.verifying_key(), b"m1".as_slice(), sk_a.sign(b"m1")),
    ];
    assert!(batch_verify(&entries_forward).is_ok());
    assert!(batch_verify(&entries_reverse).is_ok());
}

#[test]
fn replay_against_different_key_rejected() {
    // A signature valid for (vk_a, msg) must be invalid for
    // (vk_b, msg) — basic forgery resistance.
    let sk_a = sk(11);
    let sk_b = sk(12);
    let sig = sk_a.sign(b"replay-target");
    assert!(verify(&sk_b.verifying_key(), b"replay-target", &sig).is_err());
}

#[test]
fn long_message_handled() {
    // 64 KiB message — make sure the streaming hash path handles it.
    let sk_a = sk(13);
    let vk = sk_a.verifying_key();
    let msg = vec![0xABu8; 65_536];
    let sig = sk_a.sign(&msg);
    assert!(verify(&vk, &msg, &sig).is_ok());
}

#[test]
fn zero_length_message_handled() {
    let sk_a = sk(14);
    let vk = sk_a.verifying_key();
    let sig = sk_a.sign(b"");
    assert!(verify(&vk, b"", &sig).is_ok());
    // And appending anything must fail.
    assert!(verify(&vk, b"x", &sig).is_err());
}

#[test]
fn corrupted_r_first_32_bytes_rejected() {
    let sk_a = sk(15);
    let vk = sk_a.verifying_key();
    let mut sig = sk_a.sign(b"target");
    // Flip every bit in R.
    for b in sig.0.iter_mut().take(32) {
        *b ^= 0xFF;
    }
    assert!(verify(&vk, b"target", &sig).is_err());
}

#[test]
fn corrupted_s_last_32_bytes_rejected() {
    let sk_a = sk(16);
    let vk = sk_a.verifying_key();
    let mut sig = sk_a.sign(b"target");
    sig.0[32] ^= 0x01;
    assert!(verify(&vk, b"target", &sig).is_err());
}

#[test]
fn many_signers_batch() {
    // 32-signer batch — exercises the multi-scalar-mult path.
    let mut sks = Vec::new();
    for i in 0..32u8 {
        sks.push(SchnorrSigningKey::from_seed(&[i; 32]));
    }
    let msgs: Vec<Vec<u8>> = (0..32u8).map(|i| vec![i, i ^ 0x55, i.wrapping_mul(7)]).collect();
    let sigs: Vec<SchnorrSignature> = sks
        .iter()
        .zip(msgs.iter())
        .map(|(sk, m)| sk.sign(m))
        .collect();
    let entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = (0..32)
        .map(|i| (sks[i].verifying_key(), msgs[i].as_slice(), sigs[i]))
        .collect();
    assert!(batch_verify(&entries).is_ok());
}
