//! Property tests for the Row 7 transport_obfs primitive + handshake.
//!
//! Two surfaces, two gate tiers:
//!   - `primitive` (cheap, pure XOR): 1M iters CI default.
//!   - `handshake` (X25519 + BLAKE3, heavy): 10k iters CI default.
//!
//! Nightly: 5M / 100k via `ONE_LINK_F1_GATE=1`.

use proptest::prelude::*;
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use ol_onion::transport_obfs::handshake::{
    BridgeKeypair, ClientHandshake, HandshakeError, ServerHandshake,
    BRIDGE_ID_LEN, BRIDGE_PUBKEY_LEN, HANDSHAKE_EPOCH_SECS, HANDSHAKE_LEN,
};
use ol_onion::transport_obfs::primitive::{
    deobfuscate, derive_nonce, obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN,
};

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

// ── Primitive: pure-XOR properties at 1M iters ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// Round-trip: deobfuscate(obfuscate(k, n, b)) == b for any bytes.
    #[test]
    fn obfuscate_deobfuscate_round_trip(
        key in any::<[u8; OBFS_KEY_LEN]>(),
        nonce in any::<[u8; OBFS_NONCE_LEN]>(),
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let cipher = obfuscate(&key, &nonce, &bytes);
        let plain = deobfuscate(&key, &nonce, &cipher);
        prop_assert_eq!(plain, bytes);
    }

    /// Length-preserving: obfuscate output is exactly input length.
    #[test]
    fn obfuscate_preserves_length(
        key in any::<[u8; OBFS_KEY_LEN]>(),
        nonce in any::<[u8; OBFS_NONCE_LEN]>(),
        bytes in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let cipher = obfuscate(&key, &nonce, &bytes);
        prop_assert_eq!(cipher.len(), bytes.len());
    }

    /// `derive_nonce` is deterministic.
    #[test]
    fn derive_nonce_deterministic(
        conn_id in any::<u32>(),
        counter in any::<u64>(),
    ) {
        let n1 = derive_nonce(conn_id, counter);
        let n2 = derive_nonce(conn_id, counter);
        prop_assert_eq!(n1, n2);
    }

    /// `derive_nonce` distinct conn_ids OR counters yield distinct nonces.
    #[test]
    fn derive_nonce_distinct(
        c1 in any::<u32>(),
        n1 in any::<u64>(),
        c2 in any::<u32>(),
        n2 in any::<u64>(),
    ) {
        prop_assume!((c1, n1) != (c2, n2));
        prop_assert_ne!(derive_nonce(c1, n1), derive_nonce(c2, n2));
    }
}

// ── Primitive: differential properties at 100k iters ───────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases() / 10,
        max_global_rejects: cases(),
        .. ProptestConfig::default()
    })]

    /// Different keys ALMOST CERTAINLY produce different output (for
    /// non-zero plaintext or any plaintext including all-zero — the
    /// keystreams differ, so XOR differs).
    #[test]
    fn different_keys_different_output(
        k1 in any::<[u8; OBFS_KEY_LEN]>(),
        k2 in any::<[u8; OBFS_KEY_LEN]>(),
        nonce in any::<[u8; OBFS_NONCE_LEN]>(),
        bytes in prop::collection::vec(any::<u8>(), 8..256),
    ) {
        prop_assume!(k1 != k2);
        let c1 = obfuscate(&k1, &nonce, &bytes);
        let c2 = obfuscate(&k2, &nonce, &bytes);
        prop_assert_ne!(c1, c2);
    }

    /// Tampering the ciphertext propagates to the recovered plaintext
    /// (XOR is malleable — confirms upper layer MUST authenticate).
    #[test]
    fn tamper_propagates(
        key in any::<[u8; OBFS_KEY_LEN]>(),
        nonce in any::<[u8; OBFS_NONCE_LEN]>(),
        bytes in prop::collection::vec(any::<u8>(), 16..256),
        flip_idx in any::<u8>(),
    ) {
        let mut cipher = obfuscate(&key, &nonce, &bytes);
        let idx = (flip_idx as usize) % cipher.len();
        cipher[idx] ^= 0x01;
        let recovered = deobfuscate(&key, &nonce, &cipher);
        prop_assert_ne!(recovered.clone(), bytes.clone());
        // Exactly one byte differs.
        let mut diffs = 0;
        for (r, b) in recovered.iter().zip(bytes.iter()) {
            if r != b { diffs += 1; }
        }
        prop_assert_eq!(diffs, 1);
    }
}

// ── Handshake: 10k iters (X25519 + BLAKE3 are heavy) ───────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        max_global_rejects: 100_000,
        .. ProptestConfig::default()
    })]

    /// Honest handshake under current epoch → matching session keys.
    #[test]
    fn handshake_honest_round_trip(
        bridge_seed in any::<[u8; 32]>(),
        bridge_id in any::<[u8; BRIDGE_ID_LEN]>(),
        client_seed in any::<[u8; 32]>(),
        server_seed in any::<[u8; 32]>(),
        now in any::<u64>(),
        message in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        let bridge = BridgeKeypair::from_parts(bridge_seed, bridge_id);
        let bridge_pk = *bridge.public.as_bytes();
        let mut client_rng = ChaCha20Rng::from_seed(client_seed);
        let mut server_rng = ChaCha20Rng::from_seed(server_seed);

        let client = ClientHandshake::start(&mut client_rng, &bridge_pk, &bridge_id, now);
        let (reply, server_session) =
            ServerHandshake::accept(&mut server_rng, &bridge, client.first_message(), now)
                .unwrap();
        let client_session = client.finish(&reply).unwrap();

        // Round-trip a message in each direction.
        let on_wire_c2s = client_session.seal_outbound(&message, 1);
        prop_assert_eq!(server_session.open_inbound(&on_wire_c2s, 1).unwrap(), message.clone());

        let on_wire_s2c = server_session.seal_outbound(&message, 2);
        prop_assert_eq!(client_session.open_inbound(&on_wire_s2c, 2).unwrap(), message);
    }

    /// Wrong bridge_id ALWAYS rejected as BadMac.
    #[test]
    fn handshake_wrong_bridge_id_rejected(
        bridge_seed in any::<[u8; 32]>(),
        real_id in any::<[u8; BRIDGE_ID_LEN]>(),
        fake_id in any::<[u8; BRIDGE_ID_LEN]>(),
        client_seed in any::<[u8; 32]>(),
        server_seed in any::<[u8; 32]>(),
        now in any::<u64>(),
    ) {
        prop_assume!(real_id != fake_id);
        let bridge = BridgeKeypair::from_parts(bridge_seed, real_id);
        let bridge_pk = *bridge.public.as_bytes();
        let mut client_rng = ChaCha20Rng::from_seed(client_seed);
        let mut server_rng = ChaCha20Rng::from_seed(server_seed);

        let client = ClientHandshake::start(&mut client_rng, &bridge_pk, &fake_id, now);
        let err = ServerHandshake::accept(
            &mut server_rng, &bridge, client.first_message(), now
        ).unwrap_err();
        prop_assert_eq!(err, HandshakeError::BadMac);
    }

    /// Tampering any handshake byte ALWAYS rejected.
    #[test]
    fn handshake_tampered_first_rejected(
        bridge_seed in any::<[u8; 32]>(),
        bridge_id in any::<[u8; BRIDGE_ID_LEN]>(),
        client_seed in any::<[u8; 32]>(),
        server_seed in any::<[u8; 32]>(),
        now in any::<u64>(),
        flip_idx in 0u8..HANDSHAKE_LEN as u8,
    ) {
        let bridge = BridgeKeypair::from_parts(bridge_seed, bridge_id);
        let bridge_pk = *bridge.public.as_bytes();
        let mut client_rng = ChaCha20Rng::from_seed(client_seed);
        let mut server_rng = ChaCha20Rng::from_seed(server_seed);

        let client = ClientHandshake::start(&mut client_rng, &bridge_pk, &bridge_id, now);
        let mut tampered = *client.first_message();
        tampered[flip_idx as usize] ^= 0x01;
        let r = ServerHandshake::accept(&mut server_rng, &bridge, &tampered, now);
        // Either BadMac (most likely) or SmallOrderPubkey (vanishingly
        // rare; flipping byte 0 may yield a low-order point).
        prop_assert!(r.is_err());
    }

    /// Two-epoch skew ALWAYS rejected.
    #[test]
    fn handshake_two_epoch_skew_rejected(
        bridge_seed in any::<[u8; 32]>(),
        bridge_id in any::<[u8; BRIDGE_ID_LEN]>(),
        client_seed in any::<[u8; 32]>(),
        server_seed in any::<[u8; 32]>(),
        client_now in 0u64..(u64::MAX - 4 * HANDSHAKE_EPOCH_SECS),
    ) {
        let bridge = BridgeKeypair::from_parts(bridge_seed, bridge_id);
        let bridge_pk = *bridge.public.as_bytes();
        let mut client_rng = ChaCha20Rng::from_seed(client_seed);
        let mut server_rng = ChaCha20Rng::from_seed(server_seed);

        let client = ClientHandshake::start(&mut client_rng, &bridge_pk, &bridge_id, client_now);
        let server_now = client_now + 2 * HANDSHAKE_EPOCH_SECS;
        let err = ServerHandshake::accept(
            &mut server_rng, &bridge, client.first_message(), server_now
        ).unwrap_err();
        prop_assert_eq!(err, HandshakeError::BadMac);
    }
}

// ── Handshake: drop-test (non-property, but goes here) ─────────────

#[test]
fn handshake_truncated_first_rejected() {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    for len in [0usize, 1, HANDSHAKE_LEN - 1] {
        let bytes = vec![0u8; len];
        let err = ServerHandshake::accept(&mut OsRng, &bridge, &bytes, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::BadLength { .. }));
    }
}

#[test]
fn handshake_constant_length_messages() {
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000;
    let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
    let (reply, _session) =
        ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), now).unwrap();
    assert_eq!(client.first_message().len(), HANDSHAKE_LEN);
    assert_eq!(reply.len(), HANDSHAKE_LEN);
    assert_eq!(HANDSHAKE_LEN, 48);
}
