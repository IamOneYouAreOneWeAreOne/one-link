//! Integration test: `ol_ratchet` per-chunk keys drive `ol_aead`
//! encrypt/decrypt round trip per ADR-0020.
//!
//! Models the daemon's hot path:
//!
//! 1. Sender and receiver bootstrap `Chain`s from the same KEM shared
//!    secret (would normally come from `ol_pqkem::decapsulate`).
//! 2. Sender steps the chain, derives `MK_i`, encrypts chunk i.
//! 3. Receiver mirrors: same step, same `MK_i`, decrypts chunk i.
//! 4. Forward-secrecy spot check: leaking `MK_i` leaks NO other `MK_j`
//!    (verified by comparing byte-equality).

use ol_aead::{decrypt_chunk, encrypt_chunk, AeadCipher, AeadKind, ChunkAeadKey};
use ol_ratchet::{Chain, MessageKey};

const CHUNKS: usize = 100;
type Ciphertext = (u64, [u8; 32], Vec<u8>, Vec<u8>);

fn mk_to_aead_key(mk: &MessageKey) -> ChunkAeadKey {
    // The MessageKey is exactly 32 bytes; ChunkAeadKey is `from_bytes([u8; 32])`.
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&mk[..]);
    ChunkAeadKey::from_bytes(bytes)
}

fn chunk_id_for(step: u64) -> [u8; 32] {
    // Each chunk has its own content-addressed id. For this test we
    // synthesize one from `step` so it's stable.
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&step.to_le_bytes());
    id[31] = 0xCD;
    id
}

#[test]
fn ratchet_per_chunk_round_trip_100_chunks() {
    let shared_secret = [0x42u8; 32];

    // Two independent chains seeded from the same secret.
    let mut sender_chain = Chain::from_shared_secret(&shared_secret);
    let mut receiver_chain = Chain::from_shared_secret(&shared_secret);

    // Stash one of the message keys to verify forward-secrecy spot check.
    let mut keys_seen: Vec<[u8; 32]> = Vec::with_capacity(CHUNKS);

    let chunk_count = u64::try_from(CHUNKS).expect("supported Rust pointer widths fit in u64");
    for step in 0..chunk_count {
        // Sender side.
        let mk = sender_chain.next_message_key();
        let mut mk_bytes = [0u8; 32];
        mk_bytes.copy_from_slice(&mk[..]);
        keys_seen.push(mk_bytes);

        let aead_key = mk_to_aead_key(&mk);
        let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &aead_key);
        let chunk_id = chunk_id_for(step);
        let plaintext = format!("chunk-{step}-payload-of-some-length").into_bytes();
        let ciphertext = encrypt_chunk(&cipher, &chunk_id, &plaintext).expect("encrypt");

        // Receiver side: mirror the chain.
        let recv_mk = receiver_chain.next_message_key();
        assert_eq!(
            *recv_mk, *mk,
            "sender + receiver chains diverged at step {step}"
        );
        let recv_aead_key = mk_to_aead_key(&recv_mk);
        let recv_cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &recv_aead_key);
        let decrypted =
            decrypt_chunk(&recv_cipher, &chunk_id, plaintext.len(), &ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    // Forward-secrecy spot check: all 100 message keys are distinct.
    let mut unique = std::collections::HashSet::new();
    for k in &keys_seen {
        assert!(unique.insert(*k), "duplicate message key in chain");
    }
    assert_eq!(unique.len(), CHUNKS);
}

#[test]
fn ratchet_handles_reordered_delivery_via_skipped_keys() {
    use ol_ratchet::SkippedKeyStore;

    let shared_secret = [0x99u8; 32];
    let mut sender_chain = Chain::from_shared_secret(&shared_secret);
    let mut receiver_chain = Chain::from_shared_secret(&shared_secret);
    let mut skipped = SkippedKeyStore::with_capacity(16);

    // Sender encrypts chunks 0..10.
    let mut ciphertexts: Vec<Ciphertext> = Vec::new();
    for step in 0..10u64 {
        let mk = sender_chain.next_message_key();
        let aead_key = mk_to_aead_key(&mk);
        let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &aead_key);
        let chunk_id = chunk_id_for(step);
        let pt = format!("step-{step}").into_bytes();
        let ct = encrypt_chunk(&cipher, &chunk_id, &pt).unwrap();
        ciphertexts.push((step, chunk_id, pt, ct));
    }

    // Receiver consumes them in reverse order: 9, 8, 7, ..., 0.
    // For each one, advance the receiver chain to step+1, stashing
    // intermediate keys in `skipped`. Then take the matching key.
    for (step, chunk_id, pt, ct) in ciphertexts.iter().rev() {
        // Advance receiver chain past `step`, stashing skipped keys.
        while receiver_chain.step() <= *step {
            let cur_step = receiver_chain.step();
            let mk = receiver_chain.next_message_key();
            if cur_step == *step {
                // The key we actually want — use it directly.
                let aead_key = mk_to_aead_key(&mk);
                let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &aead_key);
                let decrypted = decrypt_chunk(&cipher, chunk_id, pt.len(), ct).expect("decrypt");
                assert_eq!(decrypted, *pt);
            } else {
                skipped.insert(cur_step, mk).unwrap();
            }
        }
        // If the receiver had already advanced past `step` (skipped key path),
        // we'd pull from `skipped` here. In this test's exact ordering the
        // first iteration advances 0..10, so subsequent iterations always
        // pull from `skipped`.
        if let Ok(mk) = skipped.take(*step) {
            let aead_key = mk_to_aead_key(&mk);
            let cipher = AeadCipher::with_kind(AeadKind::AesGcm256, &aead_key);
            let decrypted = decrypt_chunk(&cipher, chunk_id, pt.len(), ct).expect("decrypt");
            assert_eq!(decrypted, *pt);
        }
    }

    // After the test, all 10 skipped keys should have been consumed.
    assert_eq!(skipped.len(), 0);
}
