//! AEAD tag-tampering constant-time test.
//!
//! Per the file-engine-v2 plan's Phase C item #9 sweep: AEAD tag
//! verification must be constant-time (i.e. always run to completion
//! across all 16 tag bytes, regardless of where a mismatch occurs).
//! RustCrypto's `aead` trait uses `subtle::ConstantTimeEq` internally;
//! these tests confirm the property holds end-to-end through
//! `ol_aead::decrypt_chunk` for both AES-GCM and ChaCha20-Poly1305.

use ol_aead::{decrypt_chunk, encrypt_chunk, AeadCipher, AeadKind, ChunkAeadKey};

fn fixed_cipher(kind: AeadKind) -> AeadCipher {
    let key = ChunkAeadKey::from_bytes([0x77u8; 32]);
    AeadCipher::with_kind(kind, &key)
}

/// Encrypts a chunk, flips a single byte ANYWHERE in the ciphertext-
/// or-tag region (it's interleaved per ADR-0002), and verifies that
/// every such tampering fails authentication.
fn run_tamper_sweep(kind: AeadKind, plaintext_len: usize) {
    let cipher = fixed_cipher(kind);
    let chunk_id = [0x42u8; 32];
    let plaintext: Vec<u8> = (0..plaintext_len).map(|i| (i & 0xFF) as u8).collect();
    let ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).expect("encrypt");

    // Decrypt the original — must succeed.
    let recovered = decrypt_chunk(&cipher, &chunk_id, plaintext_len, &ciphertext).unwrap();
    assert_eq!(recovered, plaintext);

    // Tamper every byte; each tampered ciphertext must fail to decrypt.
    let mut failures_observed = 0usize;
    for byte_idx in 0..ciphertext.len() {
        let mut tampered = ciphertext.clone();
        tampered[byte_idx] ^= 0xFF;
        match decrypt_chunk(&cipher, &chunk_id, plaintext_len, &tampered) {
            Ok(_) => panic!("decrypt succeeded on tampered byte {byte_idx} — auth broken"),
            Err(_) => failures_observed += 1,
        }
    }
    assert_eq!(failures_observed, ciphertext.len());
}

#[test]
fn aes_gcm_tag_tampering_every_byte_fails() {
    run_tamper_sweep(AeadKind::AesGcm256, 1024);
}

#[test]
fn chacha20_poly1305_tag_tampering_every_byte_fails() {
    run_tamper_sweep(AeadKind::ChaCha20Poly1305, 1024);
}

/// Multi-frame chunk (≥ 2 AEAD frames per ADR-0002): tampering in any
/// frame's tag region must fail.
#[test]
fn multi_frame_aes_gcm_tampering() {
    // 40 KiB plaintext → 3 frames (16 KiB + 16 KiB + 8 KiB).
    run_tamper_sweep(AeadKind::AesGcm256, 40 * 1024);
}
