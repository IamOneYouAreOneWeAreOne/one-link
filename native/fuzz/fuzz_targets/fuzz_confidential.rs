#![no_main]
//! Fuzz the Row 10 confidential-compute surface.
//!
//! Must never panic on any input shape; all errors are typed.

use libfuzzer_sys::fuzz_target;
use ol_confidential::{
    sign_attestation, verify_attestation, AttestationDoc,
    ConfidentialProvider, ProviderTag, SoftwareProvider, ATTESTATION_NONCE_LEN,
};
use ol_pqsig::HybridSigningKey;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fuzz_target!(|data: &[u8]| {
    let mut rng = ChaCha20Rng::from_seed([0xC0; 32]);

    // 1. SoftwareProvider seal + unseal + sealed_sign on arbitrary bytes.
    let provider = SoftwareProvider::generate(&mut rng);
    let mut seed = [0u8; 32];
    for (i, b) in data.iter().take(32).enumerate() {
        seed[i] = *b;
    }
    if let Ok(sealed) = provider.seal_master(&seed) {
        let _ = provider.sealed_sign(&sealed, data);
        let _ = provider.verifying_key(&sealed);
        let _ = provider.derive_child(&sealed, data);
    }

    // 2. Tamper with a real sealed blob.
    let real = provider.seal_master(&[0xAB; 32]).unwrap();
    let mut tampered = real.clone();
    for (i, b) in data.iter().take(tampered.bytes.len()).enumerate() {
        tampered.bytes[i] ^= *b;
    }
    let _ = provider.sealed_sign(&tampered, b"probe");

    // 3. Attestation sign + verify with fuzz-bytes-as-nonce.
    let (sk, _vk) = HybridSigningKey::generate(&mut rng);
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
        &sk, provider_tag, nonce, issued, deadline, None, quote,
    ) {
        let now = issued.saturating_add(offset / 2);
        let _ = verify_attestation(&doc, &nonce, None, now);
        let mut other_nonce = nonce;
        other_nonce[0] ^= 0xFF;
        let _ = verify_attestation(&doc, &other_nonce, None, now);
    }

    // 4. Construct a bogus AttestationDoc from fuzz bytes directly.
    let bogus = AttestationDoc {
        provider_tag,
        master_vk: HybridSigningKey::generate(&mut rng).1,
        peer_nonce: nonce,
        issued_unix: issued,
        deadline_unix: deadline,
        field_witness_commitment: None,
        platform_quote: data.iter().take(32).copied().collect(),
        master_sig: data.iter().take(3357).copied().collect(),
    };
    let _ = verify_attestation(&bogus, &nonce, None, issued.saturating_add(1));
});
