//! End-to-end test: convergent encryption produces byte-identical
//! ciphertext from independent senders, then decrypts back to the same
//! plaintext.
//!
//! This is the property ADR-0012 leans on for cross-user dedup. If it
//! fails, the convergent mode is broken at the wire level.

use ol_aead::{
    decrypt_chunk, derive_convergent_aead_key, encrypt_chunk, resolve_mode, AeadCipher, AeadKind,
    ContentType, ConvergentPolicy, EncryptionMode,
};
use ol_chunk::chunk_address_convergent;

fn cipher_for_key(key: &ol_aead::ChunkAeadKey) -> AeadCipher {
    AeadCipher::with_kind(AeadKind::AesGcm256, key)
}

#[test]
fn cross_sender_determinism_aes_gcm() {
    // Two senders each independently encrypt the same plaintext under
    // convergent mode. Their ciphertexts must be byte-identical.
    let plaintext =
        b"the raw camera footage that twelve people want to share with the colorist".to_vec();

    let alice_key = derive_convergent_aead_key(&plaintext);
    let bob_key = derive_convergent_aead_key(&plaintext);
    assert_eq!(alice_key.as_bytes(), bob_key.as_bytes(), "keys diverged");

    let alice_addr = chunk_address_convergent(&plaintext);
    let bob_addr = chunk_address_convergent(&plaintext);
    assert_eq!(alice_addr, bob_addr, "chunk addresses diverged");

    let alice_cipher = cipher_for_key(&alice_key);
    let bob_cipher = cipher_for_key(&bob_key);

    let alice_ct = encrypt_chunk(&alice_cipher, &alice_addr, &plaintext).unwrap();
    let bob_ct = encrypt_chunk(&bob_cipher, &bob_addr, &plaintext).unwrap();

    assert_eq!(
        alice_ct, bob_ct,
        "convergent encryption must produce identical ciphertext for identical plaintext"
    );

    // And both decrypt to the original plaintext.
    let alice_pt = decrypt_chunk(&alice_cipher, &alice_addr, plaintext.len(), &alice_ct).unwrap();
    let bob_pt = decrypt_chunk(&bob_cipher, &bob_addr, plaintext.len(), &bob_ct).unwrap();
    assert_eq!(alice_pt, plaintext);
    assert_eq!(bob_pt, plaintext);
}

#[test]
fn distinct_plaintexts_diverge() {
    // Negative: different plaintexts must produce different ciphertext.
    let pt1 = b"file A bytes".to_vec();
    let pt2 = b"file B bytes".to_vec();
    let k1 = derive_convergent_aead_key(&pt1);
    let k2 = derive_convergent_aead_key(&pt2);
    let addr1 = chunk_address_convergent(&pt1);
    let addr2 = chunk_address_convergent(&pt2);
    let c1 = cipher_for_key(&k1);
    let c2 = cipher_for_key(&k2);
    let ct1 = encrypt_chunk(&c1, &addr1, &pt1).unwrap();
    let ct2 = encrypt_chunk(&c2, &addr2, &pt2).unwrap();
    assert_ne!(ct1, ct2);
    assert_ne!(addr1, addr2);
}

#[test]
fn convergent_dedup_64k_chunk() {
    // A full-size 64 KiB chunk: two senders, byte-identical ciphertext.
    let plaintext: Vec<u8> = (0..(64 * 1024))
        .map(|i| ((i as u32).wrapping_mul(0x9E3779B9) ^ ((i as u32) >> 5)) as u8)
        .collect();
    let key = derive_convergent_aead_key(&plaintext);
    let addr = chunk_address_convergent(&plaintext);
    let cipher_a = cipher_for_key(&key);
    let cipher_b = cipher_for_key(&key);
    let ct_a = encrypt_chunk(&cipher_a, &addr, &plaintext).unwrap();
    let ct_b = encrypt_chunk(&cipher_b, &addr, &plaintext).unwrap();
    assert_eq!(ct_a, ct_b);
    assert_eq!(
        ct_a.len(),
        plaintext.len() + 4 * 16, // 4 frames × 16-byte tag
        "expected 4 frames * 16-byte tag for a 64 KiB chunk"
    );
}

#[test]
fn policy_gate_examples() {
    assert_eq!(
        resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::MassMedia),
        EncryptionMode::Convergent
    );
    assert_eq!(
        resolve_mode(&ConvergentPolicy::AllowedTypes, ContentType::OfficeDocument),
        EncryptionMode::Standard
    );
    assert_eq!(
        resolve_mode(&ConvergentPolicy::Never, ContentType::MassMedia),
        EncryptionMode::Standard
    );
}
