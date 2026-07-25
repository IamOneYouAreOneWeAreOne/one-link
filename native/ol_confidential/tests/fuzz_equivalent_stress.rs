//! Proptest-driven mirror of `fuzz/fuzz_targets/fuzz_confidential.rs`.
//! Windows Smart App Control blocks cargo-fuzz on consumer Win11
//! installs; this runs the same surface under `cargo test`.

use proptest::prelude::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::sync::OnceLock;

use ol_confidential::{
    sign_attestation, verify_attestation, AttestationDoc, ConfidentialProvider, ConfidentialTier,
    ProviderTag, SoftwareProvider, ATTESTATION_NONCE_LEN, ISSUER_SDP_PUBKEY_LEN,
};
use ol_pqsig::{HybridSigningKey, HybridVerifyingKey};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        50_000
    } else {
        10_000
    }
}

const TEST_SDP_PUBKEY: [u8; ISSUER_SDP_PUBKEY_LEN] = [0xE5; ISSUER_SDP_PUBKEY_LEN];

struct DeterministicFixtures {
    provider: SoftwareProvider,
    signing_key: HybridSigningKey,
    bogus_verifying_key: HybridVerifyingKey,
}

/// None of the fuzz input reaches fixture construction. Rebuilding these same
/// deterministic ML-DSA keys for every case only repeats identical key
/// expansion; retain the exact RNG sequence while constructing them once.
fn deterministic_fixtures() -> &'static DeterministicFixtures {
    static FIXTURES: OnceLock<DeterministicFixtures> = OnceLock::new();
    FIXTURES.get_or_init(|| {
        let mut rng = ChaCha20Rng::from_seed([0xC0; 32]);
        let provider = SoftwareProvider::generate(&mut rng);
        let (signing_key, _verifying_key) = HybridSigningKey::generate(&mut rng);
        let bogus_verifying_key = HybridSigningKey::generate(&mut rng).1;
        DeterministicFixtures {
            provider,
            signing_key,
            bogus_verifying_key,
        }
    })
}

fn fuzz_body(data: &[u8]) {
    let fixtures = deterministic_fixtures();
    let provider = &fixtures.provider;

    let mut seed = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        seed[i] = *b;
    }
    if let Ok(sealed) = provider.seal_master(&seed) {
        let _ = provider.sealed_sign(&sealed, data);
        let _ = provider.verifying_key(&sealed);
        let _ = provider.derive_child(&sealed, data);
    }

    let real = provider.seal_master(&[0xAB; 32]).unwrap();
    let mut tampered = real.clone();
    for (i, b) in data.iter().take(tampered.bytes.len()).enumerate() {
        tampered.bytes[i] ^= *b;
    }
    let _ = provider.sealed_sign(&tampered, b"probe");

    let mut nonce = [0u8; ATTESTATION_NONCE_LEN];
    for (i, b) in data.iter().take(ATTESTATION_NONCE_LEN).enumerate() {
        nonce[i] = *b;
    }
    let provider_tag = match data.first().copied().unwrap_or(1) % 7 {
        0 | 1 => ProviderTag::Software,
        2 => ProviderTag::AppleSecureEnclave,
        3 => ProviderTag::AndroidStrongBox,
        4 => ProviderTag::WindowsTpm,
        5 => ProviderTag::IntelSgx,
        _ => ProviderTag::AmdSevSnp,
    };
    let issued = u64::from(data.get(1).copied().unwrap_or(0)) * 1_000;
    let offset = (u64::from(data.get(2).copied().unwrap_or(1)) % 35) + 1;
    let deadline = issued.saturating_add(offset);
    let quote: Vec<u8> = data.iter().skip(3).take(64).copied().collect();
    if let Ok(doc) = sign_attestation(
        &fixtures.signing_key,
        provider_tag,
        nonce,
        issued,
        deadline,
        None,
        quote,
        TEST_SDP_PUBKEY,
    ) {
        let now = issued.saturating_add(offset / 2);
        let _ = verify_attestation(
            &doc,
            &nonce,
            None,
            now,
            ConfidentialTier::Software,
            &TEST_SDP_PUBKEY,
        );
    }

    let bogus = AttestationDoc {
        provider_tag,
        master_vk: fixtures.bogus_verifying_key.clone(),
        peer_nonce: nonce,
        issued_unix: issued,
        deadline_unix: deadline,
        field_witness_commitment: None,
        platform_quote: data.iter().take(32).copied().collect(),
        issuer_sdp_pubkey: TEST_SDP_PUBKEY,
        master_sig: data.iter().take(3357).copied().collect(),
    };
    let _ = verify_attestation(
        &bogus,
        &nonce,
        None,
        issued.saturating_add(1),
        ConfidentialTier::Software,
        &TEST_SDP_PUBKEY,
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    #[test]
    fn stress_confidential_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        fuzz_body(&data);
    }
}
