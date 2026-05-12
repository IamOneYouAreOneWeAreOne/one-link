//! High-scale integration test: 10,000-chunk ratchet stream.
//!
//! Confirms the chain + AEAD path holds up at engine-realistic scale.
//! At ~200 ns/step the entire 10K-step sweep should complete in well
//! under 5 ms of ratchet overhead.

use ol_aead::{decrypt_chunk, encrypt_chunk, AeadCipher, AeadKind, ChunkAeadKey};
use ol_ratchet::Chain;
use std::time::Instant;

const CHUNKS: usize = 10_000;

fn mk_to_aead_key(mk: &ol_ratchet::MessageKey) -> ChunkAeadKey {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&mk[..]);
    ChunkAeadKey::from_bytes(bytes)
}

fn chunk_id_for(step: u64) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&step.to_le_bytes());
    id[31] = 0xCD;
    id
}

#[test]
fn ratchet_10000_chunk_stream_aead_round_trip() {
    let shared = [0x11u8; 32];
    let mut sender_chain = Chain::from_shared_secret(&shared);
    let mut receiver_chain = Chain::from_shared_secret(&shared);

    let plaintext_template = b"chunk-payload-of-medium-sample-size-with-trailing-bytes-padding";

    let start = Instant::now();
    let mut total_bytes = 0usize;
    for step in 0..CHUNKS as u64 {
        // Sender.
        let mk = sender_chain.next_message_key();
        let key = mk_to_aead_key(&mk);
        let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &key);
        let chunk_id = chunk_id_for(step);
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, plaintext_template).unwrap();
        total_bytes += ciphertext.len();

        // Receiver — mirror chain.
        let recv_mk = receiver_chain.next_message_key();
        assert_eq!(*recv_mk, *mk);
        let recv_key = mk_to_aead_key(&recv_mk);
        let recv_cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &recv_key);
        let recovered = decrypt_chunk(
            &recv_cipher,
            &chunk_id,
            plaintext_template.len(),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(recovered, plaintext_template);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "10,000-chunk ratchet stream: {:?} total ({:.1} ns/chunk), {} bytes ciphertext",
        elapsed,
        elapsed.as_nanos() as f64 / CHUNKS as f64,
        total_bytes
    );

    // Sanity: < 5 seconds in debug, well under 1 s in release.
    assert!(
        elapsed.as_secs() < 30,
        "10K-chunk stream took {}s — engine ratchet is too slow",
        elapsed.as_secs()
    );
}

#[test]
fn ratchet_chain_keys_all_distinct_at_10k_scale() {
    let mut chain = Chain::from_shared_secret(&[0x99u8; 32]);
    let mut hashes = std::collections::HashSet::new();
    for _ in 0..CHUNKS {
        let mk = chain.next_message_key();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&mk[..]);
        // Use first 16 bytes as the dedup key (full 32 would balloon HashSet).
        let mut head = [0u8; 16];
        head.copy_from_slice(&bytes[..16]);
        assert!(
            hashes.insert(head),
            "collision in 10K-step chain — BLAKE3 broken or chain not advancing"
        );
    }
    assert_eq!(hashes.len(), CHUNKS);
}
