//! Property tests for the Row 10 confidential-compute surface.

use proptest::prelude::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::OnceLock;

use ol_confidential::{
    sign_attestation, verify_attestation, ConfidentialProvider, ConfidentialTier, ProviderTag,
    SoftwareProvider, ATTESTATION_FRESHNESS_WINDOW_SECS, ISSUER_SDP_PUBKEY_LEN,
};
use ol_pqsig::{HybridSigningKey, HybridVerifyingKey};

fn cheap_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

// Heavy proptest cases (sealed_sign etc. are ~250µs apiece) — keep
// these bounded so default test runs finish in seconds.
fn heavy_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        50_000
    } else {
        5_000
    }
}

const TEST_SDP_PUBKEY: [u8; ISSUER_SDP_PUBKEY_LEN] = [0xD4; ISSUER_SDP_PUBKEY_LEN];

/// The cheap properties vary transcript inputs, not the issuer key. Expanding
/// an ML-DSA key for every one of their millions of cases dominates the entire
/// workspace gate without increasing the state space under test. Generate the
/// three deterministic public keys exactly once per test process while
/// preserving the distinct AB/CD/EF fixtures each property used previously.
fn transcript_verifying_keys() -> &'static [HybridVerifyingKey] {
    static VERIFYING_KEYS: OnceLock<Box<[HybridVerifyingKey]>> = OnceLock::new();
    VERIFYING_KEYS.get_or_init(|| {
        vec![
            HybridSigningKey::generate(&mut ChaCha20Rng::from_seed([0xAB; 32])).1,
            HybridSigningKey::generate(&mut ChaCha20Rng::from_seed([0xCD; 32])).1,
            HybridSigningKey::generate(&mut ChaCha20Rng::from_seed([0xEF; 32])).1,
        ]
        .into_boxed_slice()
    })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cheap_cases(),
        max_global_rejects: cheap_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Canonical attestation transcript is a pure function: identical
    /// inputs produce identical bytes.
    #[test]
    fn transcript_deterministic(
        nonce in any::<[u8; 32]>(),
        issued in 0u64..u64::MAX/2,
        offset in 1u64..=ATTESTATION_FRESHNESS_WINDOW_SECS,
        witness_opt in proptest::option::of(any::<[u8; 32]>()),
    ) {
        let vk = &transcript_verifying_keys()[0];
        let deadline = issued.saturating_add(offset);
        let q = vec![0u8; 4];
        let t1 = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software,
            vk,
            &nonce,
            issued,
            deadline,
            witness_opt.as_ref(),
            &q,
            &TEST_SDP_PUBKEY,
        );
        let t2 = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software,
            vk,
            &nonce,
            issued,
            deadline,
            witness_opt.as_ref(),
            &q,
            &TEST_SDP_PUBKEY,
        );
        prop_assert_eq!(t1, t2);
    }

    /// Distinct peer nonces produce distinct transcript bytes (and
    /// therefore distinct signatures).
    #[test]
    fn distinct_nonces_diverge(
        nonce_a in any::<[u8; 32]>(),
        nonce_b in any::<[u8; 32]>(),
    ) {
        prop_assume!(nonce_a != nonce_b);
        let vk = &transcript_verifying_keys()[1];
        let t1 = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software, vk, &nonce_a, 100, 120, None, &[], &TEST_SDP_PUBKEY,
        );
        let t2 = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software, vk, &nonce_b, 100, 120, None, &[], &TEST_SDP_PUBKEY,
        );
        prop_assert_ne!(t1, t2);
    }

    /// Witness-Some and Witness-None paths produce distinct transcripts
    /// for the same other inputs.
    #[test]
    fn witness_presence_changes_transcript(
        nonce in any::<[u8; 32]>(),
        witness in any::<[u8; 32]>(),
    ) {
        let vk = &transcript_verifying_keys()[2];
        let t_none = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software, vk, &nonce, 100, 120, None, &[], &TEST_SDP_PUBKEY,
        );
        let t_some = ol_confidential::attestation::canonical_attestation_transcript(
            ProviderTag::Software, vk, &nonce, 100, 120, Some(&witness), &[], &TEST_SDP_PUBKEY,
        );
        prop_assert_ne!(t_none, t_some);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: heavy_cases(),
        max_global_rejects: heavy_cases() * 4,
        .. ProptestConfig::default()
    })]

    /// sign + verify round-trip under freshly chosen master.
    #[test]
    fn sign_verify_round_trip(
        nonce in any::<[u8; 32]>(),
        offset in 1u64..=ATTESTATION_FRESHNESS_WINDOW_SECS,
    ) {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, 1_000_000, 1_000_000 + offset, None, Vec::new(),
            TEST_SDP_PUBKEY,
        ).unwrap();
        verify_attestation(
            &doc,
            &nonce,
            None,
            1_000_000,
            ConfidentialTier::Software,
            &TEST_SDP_PUBKEY,
        ).unwrap();
    }

    /// `now_unix > deadline` always rejects.
    #[test]
    fn now_past_deadline_always_rejects(
        nonce in any::<[u8; 32]>(),
        offset in 1u64..=ATTESTATION_FRESHNESS_WINDOW_SECS,
        slack in 1u64..1_000_000,
    ) {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        let issued = 1_000_000u64;
        let deadline = issued + offset;
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, issued, deadline, None, Vec::new(),
            TEST_SDP_PUBKEY,
        ).unwrap();
        let now = deadline + slack;
        prop_assert!(verify_attestation(
            &doc,
            &nonce,
            None,
            now,
            ConfidentialTier::Software,
            &TEST_SDP_PUBKEY,
        ).is_err());
    }

    /// Sealed seed round-trips through software provider's seal/sign
    /// path: signature verifies under the publicly exposed VK.
    #[test]
    fn sealed_sign_verifies_under_published_vk(
        seed in any::<[u8; 32]>(),
        msg in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let sealed = provider.seal_master(&seed).unwrap();
        let vk = provider.verifying_key(&sealed).unwrap();
        let sig = provider.sealed_sign(&sealed, &msg).unwrap();
        vk.verify(&msg, &sig).unwrap();
    }
}
