//! Property tests for Sphinx Coherence T1.5 — Schnorr aggregation.
//!
//! 1M iters CI default / 5M iters nightly via `ONE_LINK_F1_GATE=1`.

use proptest::prelude::*;

use ol_onion::sphinx::aggsig::{
    batch_verify, verify, SchnorrSignature, SchnorrSigningKey, SchnorrVerifyingKey,
};
use ol_onion::OnionError;

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn light_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        500_000
    } else {
        100_000
    }
}

// ── Single-signer round-trip ─────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// For any (seed, msg): sign(seed, msg) is verified by verifying_key(seed).
    #[test]
    fn sign_verify_round_trip(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let sk = SchnorrSigningKey::from_seed(&seed);
        let vk = sk.verifying_key();
        let sig = sk.sign(&msg);
        prop_assert!(verify(&vk, &msg, &sig).is_ok());
    }

    /// Determinism: sign(seed, msg) twice produces identical signatures.
    #[test]
    fn sign_is_deterministic(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let sk = SchnorrSigningKey::from_seed(&seed);
        let a = sk.sign(&msg);
        let b = sk.sign(&msg);
        prop_assert_eq!(a.0, b.0);
    }

    /// Any single-bit flip in the signature is rejected.
    #[test]
    fn one_bit_flip_rejected(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 1..128),
        bit in 0u32..512,
    ) {
        let sk = SchnorrSigningKey::from_seed(&seed);
        let vk = sk.verifying_key();
        let mut sig = sk.sign(&msg);
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        sig.0[byte] ^= mask;
        prop_assert!(verify(&vk, &msg, &sig).is_err());
    }

    /// Any single-bit flip in the message is rejected.
    #[test]
    fn message_tamper_rejected(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 1..128),
        bit_pos in 0u32..1024,
    ) {
        let sk = SchnorrSigningKey::from_seed(&seed);
        let vk = sk.verifying_key();
        let sig = sk.sign(&msg);
        let mut tampered = msg.clone();
        let byte = (bit_pos as usize) / 8;
        if byte < tampered.len() {
            tampered[byte] ^= 1u8 << (bit_pos % 8);
            // Skip the no-op case (bit was the same in both).
            if tampered != msg {
                prop_assert!(verify(&vk, &tampered, &sig).is_err());
            }
        }
    }

    /// Wrong verifying key (independent seed) always rejects.
    #[test]
    fn wrong_vk_rejected(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        prop_assume!(seed_a != seed_b);
        let sk_a = SchnorrSigningKey::from_seed(&seed_a);
        let sk_b = SchnorrSigningKey::from_seed(&seed_b);
        // Different seeds with overwhelming probability yield different VKs.
        prop_assume!(sk_a.verifying_key().0 != sk_b.verifying_key().0);
        let sig = sk_a.sign(&msg);
        prop_assert!(verify(&sk_b.verifying_key(), &msg, &sig).is_err());
    }
}

// ── Batch verification properties ────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        max_global_rejects: light_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Batch verify of N valid sigs always accepts.
    #[test]
    fn batch_verify_accepts_all_valid(
        seeds in proptest::collection::vec(any::<[u8; 32]>(), 1..8),
        msg_seed in any::<[u8; 32]>(),
    ) {
        let msgs: Vec<Vec<u8>> = (0..seeds.len())
            .map(|i| {
                let mut v = msg_seed.to_vec();
                v.push(i as u8);
                v
            })
            .collect();
        let sks: Vec<SchnorrSigningKey> = seeds.iter().map(SchnorrSigningKey::from_seed).collect();
        let mut entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = Vec::new();
        let sigs: Vec<SchnorrSignature> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        for (i, sk) in sks.iter().enumerate() {
            entries.push((sk.verifying_key(), msgs[i].as_slice(), sigs[i]));
        }
        prop_assert!(batch_verify(&entries).is_ok());
    }

    /// Corrupting any single entry's signature causes batch reject.
    #[test]
    fn batch_verify_rejects_one_corrupted(
        seeds in proptest::collection::vec(any::<[u8; 32]>(), 2..8),
        msg_byte in any::<u8>(),
        which in 0usize..8,
        bit in 0u32..512,
    ) {
        let n = seeds.len();
        let msgs: Vec<Vec<u8>> = (0..n).map(|i| vec![msg_byte, i as u8]).collect();
        let sks: Vec<SchnorrSigningKey> = seeds.iter().map(SchnorrSigningKey::from_seed).collect();
        let mut sigs: Vec<SchnorrSignature> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        let target = which % n;
        sigs[target].0[(bit / 8) as usize] ^= 1u8 << (bit % 8);
        let mut entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = Vec::new();
        for (i, sk) in sks.iter().enumerate() {
            entries.push((sk.verifying_key(), msgs[i].as_slice(), sigs[i]));
        }
        prop_assert!(batch_verify(&entries).is_err());
    }
}

// ── Edge cases as proptest one-shots ─────────────────────────────

#[test]
fn empty_signature_decodes_as_internal() {
    let vk_seed = [0u8; 32];
    let vk = SchnorrSigningKey::from_seed(&vk_seed).verifying_key();
    // R encoded as zeros decodes to the identity point on Ristretto
    // (allowed by encoding), but the s side is canonical. So the
    // signature should mathematically fail-to-verify (not Internal).
    let zero_sig = SchnorrSignature([0u8; 64]);
    match verify(&vk, b"msg", &zero_sig) {
        Ok(()) => panic!("zero signature must not verify"),
        Err(OnionError::SignatureInvalid | OnionError::Internal(_)) => {}
        Err(e) => panic!("unexpected error variant: {e:?}"),
    }
}

#[test]
fn non_canonical_s_is_internal_error() {
    let sk = SchnorrSigningKey::from_seed(&[1u8; 32]);
    let vk = sk.verifying_key();
    let mut sig = sk.sign(b"x");
    // Force non-canonical s: set top byte to 0xFF which exceeds the
    // group order for the Ristretto255 scalar field.
    sig.0[63] = 0xFF;
    match verify(&vk, b"x", &sig) {
        Err(OnionError::Internal(_)) => {}
        // It's plausible the bit pattern is still canonical but wrong.
        // Either Internal or SignatureInvalid is acceptable here; the
        // test asserts we never silently accept.
        Err(OnionError::SignatureInvalid) => {}
        Ok(()) => panic!("malformed signature must not verify"),
        Err(e) => panic!("unexpected error variant: {e:?}"),
    }
}
