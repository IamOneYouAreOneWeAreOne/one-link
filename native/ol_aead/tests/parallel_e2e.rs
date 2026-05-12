//! End-to-end test for the parallel multi-chunk encrypt/decrypt path.

use ol_aead::{decrypt_chunks_par, encrypt_chunks_par, AeadCipher, AeadKind, ChunkAeadKey};

#[test]
fn round_trip_64_chunks_parallel() {
    let cipher =
        AeadCipher::with_kind(AeadKind::AesGcm256, &ChunkAeadKey::from_bytes([0x42u8; 32]));
    let mut plaintexts: Vec<Vec<u8>> = Vec::new();
    let mut chunk_ids: Vec<[u8; 32]> = Vec::new();
    for i in 0..64u32 {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_le_bytes());
        chunk_ids.push(id);
        // 64 KiB chunk
        plaintexts.push(
            (0..(64 * 1024u32))
                .map(|j| (j.wrapping_mul(i.wrapping_add(1))) as u8)
                .collect(),
        );
    }
    let inputs: Vec<(&[u8; 32], &[u8])> = chunk_ids
        .iter()
        .zip(plaintexts.iter())
        .map(|(id, pt)| (id, pt.as_slice()))
        .collect();
    let ciphertexts = encrypt_chunks_par(&cipher, &inputs).unwrap();
    assert_eq!(ciphertexts.len(), 64);

    let dec_inputs: Vec<(&[u8; 32], usize, &[u8])> = chunk_ids
        .iter()
        .zip(plaintexts.iter().zip(ciphertexts.iter()))
        .map(|(id, (pt, ct))| (id, pt.len(), ct.as_slice()))
        .collect();
    let recovered = decrypt_chunks_par(&cipher, &dec_inputs).unwrap();
    assert_eq!(recovered.len(), 64);
    for (a, b) in plaintexts.iter().zip(recovered.iter()) {
        assert_eq!(a, b);
    }
}

#[test]
fn empty_input_returns_empty() {
    let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &ChunkAeadKey::from_bytes([0u8; 32]));
    let ciphertexts = encrypt_chunks_par(&cipher, &[]).unwrap();
    assert!(ciphertexts.is_empty());
    let recovered = decrypt_chunks_par(&cipher, &[]).unwrap();
    assert!(recovered.is_empty());
}
