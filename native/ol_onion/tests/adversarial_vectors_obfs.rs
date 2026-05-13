//! Adversarial test vectors for the Row 7 transport_obfs layer.
//!
//! Each test exercises a known attack pattern against bridge-style
//! obfuscated transports and confirms the layer rejects / no-ops as
//! designed.

use ol_onion::transport_obfs::handshake::{
    BridgeKeypair, ClientHandshake, HandshakeError, ServerHandshake,
    BRIDGE_ID_LEN, BRIDGE_PUBKEY_LEN, HANDSHAKE_EPOCH_SECS, HANDSHAKE_LEN,
};
use ol_onion::transport_obfs::primitive::{
    deobfuscate, derive_nonce, obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN,
};
use ol_onion::transport_obfs::session::{Session, SESSION_KEY_LEN};
use rand::rngs::OsRng;

// ── Probe-attacker: random bytes / well-known protocol probes ──────

#[test]
fn adversarial_probe_with_random_bytes_silently_dropped() {
    // An active probe attacker without bridge_id can't forge a valid
    // HMAC. Server's accept must return BadMac (not "leaked which
    // bytes were correct").
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let now = 1_700_000_000u64;
    for seed in 0u8..16 {
        let probe = [seed.wrapping_mul(3); HANDSHAKE_LEN];
        let err = ServerHandshake::accept(&mut OsRng, &bridge, &probe, now)
            .unwrap_err();
        // Either BadMac (most likely) or SmallOrderPubkey (low-order point).
        assert!(
            matches!(err, HandshakeError::BadMac | HandshakeError::SmallOrderPubkey),
            "probe with seed {seed} returned unexpected error: {err:?}"
        );
    }
}

#[test]
fn adversarial_probe_with_all_zeros_rejected() {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let probe = [0u8; HANDSHAKE_LEN];
    let err =
        ServerHandshake::accept(&mut OsRng, &bridge, &probe, 1_700_000_000)
            .unwrap_err();
    // All-zeros pubkey is a small-order X25519 point; either error path is OK.
    assert!(matches!(
        err,
        HandshakeError::BadMac | HandshakeError::SmallOrderPubkey
    ));
}

#[test]
fn adversarial_probe_with_correct_pubkey_wrong_mac_rejected() {
    // Sophisticated attacker captures a real client_ephem_pk and
    // tries to forge the MAC. Must fail.
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000u64;
    let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
    let mut tampered = *client.first_message();
    // Replace MAC field with all zeros (a "guess").
    for b in &mut tampered[32..] {
        *b = 0;
    }
    let err =
        ServerHandshake::accept(&mut OsRng, &bridge, &tampered, now).unwrap_err();
    assert_eq!(err, HandshakeError::BadMac);
}

// ── Replay: outside the epoch window ───────────────────────────────

#[test]
fn adversarial_replay_two_epochs_later_rejected() {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000u64;
    let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
    let captured = *client.first_message();
    let future_now = now + 2 * HANDSHAKE_EPOCH_SECS;
    let err = ServerHandshake::accept(&mut OsRng, &bridge, &captured, future_now)
        .unwrap_err();
    assert_eq!(err, HandshakeError::BadMac);
}

// ── Truncation / oversize ──────────────────────────────────────────

#[test]
fn adversarial_truncated_handshake_rejected() {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    for len in [0usize, 1, 16, 31, HANDSHAKE_LEN - 1] {
        let bytes = vec![0u8; len];
        let err =
            ServerHandshake::accept(&mut OsRng, &bridge, &bytes, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::BadLength { .. }));
    }
}

// ── Cross-bridge handshake confusion ───────────────────────────────

#[test]
fn adversarial_handshake_for_other_bridge_rejected() {
    // Client targets bridge A; that handshake forwarded to bridge B
    // (different id) must fail. Even if attacker passes B the bytes
    // that succeed at A, B's HMAC key incorporates B's id.
    let bridge_a = BridgeKeypair::generate(&mut OsRng);
    let bridge_b = BridgeKeypair::generate(&mut OsRng);
    let bridge_a_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge_a.public.as_bytes();
    let now = 1_700_000_000u64;
    let client = ClientHandshake::start(&mut OsRng, &bridge_a_pk, &bridge_a.id, now);
    // Forward client_first → bridge_b.
    let err =
        ServerHandshake::accept(&mut OsRng, &bridge_b, client.first_message(), now)
            .unwrap_err();
    assert_eq!(err, HandshakeError::BadMac);
}

// ── Session: key-confusion + replay tolerance ──────────────────────

#[test]
fn adversarial_session_wrong_key_cant_decrypt() {
    // Attacker holds wrong keys; can't recover plaintext.
    let k1 = [0xAA; SESSION_KEY_LEN];
    let k2 = [0xBB; SESSION_KEY_LEN];
    let real_client = Session::new(k1, k2);

    let wrong_k1 = [0xCC; SESSION_KEY_LEN];
    let wrong_k2 = [0xDD; SESSION_KEY_LEN];
    let attacker = Session::for_server(wrong_k1, wrong_k2);

    let plaintext = b"secret traffic";
    let on_wire = real_client.seal_outbound(plaintext, 1);
    // Attacker tries to decrypt with their key — output is garbage.
    let recovered = attacker.open_inbound(&on_wire, 1).unwrap();
    assert_ne!(recovered, plaintext);
}

#[test]
fn adversarial_session_nonce_reuse_leaks_xor() {
    // Sanity check on the well-known XOR-cipher property:
    // SAME (key, counter) on two plaintexts → cipher_a ⊕ cipher_b
    // = plaintext_a ⊕ plaintext_b. This test exists to lock in that
    // the daemon MUST advance counter per packet; if it doesn't,
    // this property leaks XOR. Recorded here as a known hazard.
    let k1 = [0x11u8; SESSION_KEY_LEN];
    let k2 = [0x22u8; SESSION_KEY_LEN];
    let client = Session::new(k1, k2);
    let p1 = b"plaintext-AAAAAA";
    let p2 = b"plaintext-BBBBBB";
    let c1 = client.seal_outbound(p1, 1);
    let c2 = client.seal_outbound(p2, 1); // SAME counter -- BAD!
    let xor_c: Vec<u8> = c1.iter().zip(c2.iter()).map(|(a, b)| a ^ b).collect();
    let xor_p: Vec<u8> = p1.iter().zip(p2.iter()).map(|(a, b)| a ^ b).collect();
    assert_eq!(xor_c, xor_p, "nonce reuse leaks plaintext XOR");
}

// ── derive_nonce: edge cases ───────────────────────────────────────

#[test]
fn adversarial_derive_nonce_collision_search_bounded() {
    // Confirm conn_id-counter pairs are 12 bytes total — 96-bit
    // nonce space. Attacker trying random nonces has 2^-96 collision
    // probability per attempt. This is the SECURITY assumption, not a
    // bypass — but pin the byte layout that grounds it.
    let n1 = derive_nonce(0, 0);
    let n2 = derive_nonce(u32::MAX, u64::MAX);
    assert_ne!(n1, n2);
    assert_eq!(n1.len(), OBFS_NONCE_LEN);
}

// ── Primitive: malleability + length checks ─────────────────────────

#[test]
fn adversarial_primitive_zero_length_input_passes() {
    let key = [0xABu8; OBFS_KEY_LEN];
    let nonce = [0xCDu8; OBFS_NONCE_LEN];
    let cipher = obfuscate(&key, &nonce, &[]);
    assert_eq!(cipher.len(), 0);
    let plain = deobfuscate(&key, &nonce, &cipher);
    assert_eq!(plain, Vec::<u8>::new());
}

#[test]
fn adversarial_primitive_one_byte_input_round_trips() {
    let key = [0x01u8; OBFS_KEY_LEN];
    let nonce = [0x02u8; OBFS_NONCE_LEN];
    let cipher = obfuscate(&key, &nonce, &[0xFF]);
    let plain = deobfuscate(&key, &nonce, &cipher);
    assert_eq!(plain, vec![0xFF]);
}
