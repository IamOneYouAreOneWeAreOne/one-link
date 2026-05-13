//! Property tests for ol_pqsig at the F1.x bar.
//!
//! CI default: 1M iters. Nightly (ONE_LINK_F1_GATE=1): 5M iters.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_pqsig::{
    HybridSigningKey, HybridVerifyingKey, PqSigError, HYBRID_SIG_LEN, HYBRID_SK_LEN, HYBRID_VK_LEN,
};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn light_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        50_000
    } else {
        10_000
    }
}

// ── Length-validation properties (1M cheap iters; no keygen) ────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Wrong-length VK bytes always rejected (no keygen — pure decode).
    #[test]
    fn vk_arbitrary_bytes_typed_err(
        bytes in prop::collection::vec(any::<u8>(), 0usize..=2100)
    ) {
        if bytes.len() == HYBRID_VK_LEN {
            return Ok(()); // skip the valid-length case
        }
        let r = HybridVerifyingKey::from_bytes(&bytes);
        let is_expected = matches!(
            r,
            Err(PqSigError::BadLength { .. }) | Err(PqSigError::InvalidPubkey)
        );
        prop_assert!(is_expected);
    }

    /// Wrong-length SK bytes always rejected (no keygen — pure decode).
    #[test]
    fn sk_arbitrary_bytes_typed_err(
        bytes in prop::collection::vec(any::<u8>(), 0usize..=200)
    ) {
        if bytes.len() == HYBRID_SK_LEN {
            return Ok(());
        }
        let r = HybridSigningKey::from_bytes(&bytes);
        let is_bad_len = matches!(r, Err(PqSigError::BadLength { .. }));
        prop_assert!(is_bad_len);
    }
}

// ── Keygen-bound properties (lighter — each keygen is ~0.7ms) ───

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        max_global_rejects: light_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// VerifyingKey round-trips through to_bytes/from_bytes.
    #[test]
    fn vk_round_trip(seed in any::<[u8; 32]>()) {
        // Use the seed deterministically by feeding StaticSecret semantics
        // through HybridSigningKey::generate via a chacha rng.
        let mut rng = rand_chacha::ChaCha20Rng::from_seed_with_rand_core(seed);
        let (_sk, vk) = HybridSigningKey::generate(&mut rng);
        let bytes = vk.to_bytes();
        let vk2 = HybridVerifyingKey::from_bytes(&bytes).unwrap();
        prop_assert_eq!(vk, vk2);
    }

    /// SigningKey round-trips through to_bytes/from_bytes.
    #[test]
    fn sk_round_trip(seed in any::<[u8; 32]>()) {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed_with_rand_core(seed);
        let (sk, vk) = HybridSigningKey::generate(&mut rng);
        let bytes = sk.to_bytes();
        let sk2 = HybridSigningKey::from_bytes(&bytes).unwrap();
        // Verify by signing + checking the original vk accepts it.
        let sig = sk2.sign(b"prop-test").unwrap();
        vk.verify(b"prop-test", &sig).unwrap();
    }

    /// Verify with wrong-length sig always rejected.
    #[test]
    fn sig_wrong_length_rejected(
        sig in prop::collection::vec(any::<u8>(), 0usize..=4000),
    ) {
        if sig.len() == HYBRID_SIG_LEN {
            return Ok(());
        }
        let mut rng = rand::thread_rng();
        let (_, vk) = HybridSigningKey::generate(&mut rng);
        let r = vk.verify(b"x", &sig);
        let is_expected = matches!(
            r,
            Err(PqSigError::BadLength { .. })
                | Err(PqSigError::Ed25519VerifyFail)
                | Err(PqSigError::MlDsaVerifyFail)
        );
        prop_assert!(is_expected);
    }
}

// ── End-to-end sign/verify (lighter — each ml-dsa keygen is ~ms) ─

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        max_global_rejects: light_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Sign + verify round-trips for any payload up to 1KB.
    #[test]
    fn sign_verify_roundtrip(
        msg in prop::collection::vec(any::<u8>(), 0usize..=1024),
    ) {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk.sign(&msg).unwrap();
        vk.verify(&msg, &sig).unwrap();
    }

    /// Any one-bit flip in the message → verify fails.
    #[test]
    fn message_tamper_rejected(
        msg in prop::collection::vec(any::<u8>(), 1usize..=256),
        flip_byte in 0usize..256,
        flip_bit in 0u8..8,
    ) {
        let flip_byte = flip_byte % msg.len();
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk.sign(&msg).unwrap();
        let mut tampered = msg.clone();
        tampered[flip_byte] ^= 1u8 << flip_bit;
        prop_assert_ne!(&tampered, &msg);
        let r = vk.verify(&tampered, &sig);
        prop_assert!(r.is_err());
    }

    /// Any one-bit flip in the signature → verify fails.
    #[test]
    fn signature_tamper_rejected(
        msg in prop::collection::vec(any::<u8>(), 0usize..=256),
        flip_byte in 0usize..HYBRID_SIG_LEN,
        flip_bit in 0u8..8,
    ) {
        let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk.sign(&msg).unwrap();
        let mut tampered = sig;
        tampered[flip_byte] ^= 1u8 << flip_bit;
        let r = vk.verify(&msg, &tampered);
        prop_assert!(r.is_err());
    }

    /// Cross-key: signature from sk_a never verifies under vk_b.
    #[test]
    fn cross_key_replay_rejected(
        msg in prop::collection::vec(any::<u8>(), 0usize..=128),
    ) {
        let (sk_a, _) = HybridSigningKey::generate(&mut OsRng);
        let (_, vk_b) = HybridSigningKey::generate(&mut OsRng);
        let sig = sk_a.sign(&msg).unwrap();
        let r = vk_b.verify(&msg, &sig);
        prop_assert!(r.is_err());
    }

    /// Deterministic sign: same (sk, msg) → same sig.
    #[test]
    fn deterministic_sign(
        msg in prop::collection::vec(any::<u8>(), 0usize..=128),
    ) {
        let (sk, _) = HybridSigningKey::generate(&mut OsRng);
        let s1 = sk.sign(&msg).unwrap();
        let s2 = sk.sign(&msg).unwrap();
        prop_assert_eq!(s1, s2);
    }
}

// Helper: a tiny extension that makes rand_chacha seedable from a
// rand_core::SeedableRng via a 32-byte array. (rand_chacha's
// SeedableRng impl is on the older trait; alias for clarity.)
trait FromCoreSeed {
    fn from_seed_with_rand_core(seed: [u8; 32]) -> Self;
}
impl FromCoreSeed for rand_chacha::ChaCha20Rng {
    fn from_seed_with_rand_core(seed: [u8; 32]) -> Self {
        use rand::SeedableRng as _;
        rand_chacha::ChaCha20Rng::from_seed(seed)
    }
}
