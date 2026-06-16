//! Adversarial test vectors for ol_onion.
//!
//! Catches known-attack patterns + edge cases that random property
//! tests might miss.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_onion::{
    build_onion, peel_one_layer, Circuit, HopDescriptor, HopId, OnionError, OnionPacket,
    PeelOutcome, HOP_ID_LEN,
};

fn make_hop_pair(i: u8) -> (StaticSecret, HopDescriptor) {
    let sk = StaticSecret::from([i; 32]);
    let pk = PublicKey::from(&sk);
    (
        sk,
        HopDescriptor {
            id: HopId::from_bytes([i; HOP_ID_LEN]),
            pubkey: pk,
        },
    )
}

// ── Hop blindness ────────────────────────────────────────────────

#[test]
fn adversarial_relay_cannot_decrypt_inner_layer() {
    // Build a 3-hop onion. r1 peels its layer, then tries to peel
    // the inner packet with its OWN key (instead of forwarding) —
    // must fail with AeadFail.
    let (r1_sk, r1) = make_hop_pair(1);
    let (_, r2) = make_hop_pair(2);
    let (_, dest) = make_hop_pair(3);
    let circuit = Circuit::new(vec![r1, r2.clone(), dest]).unwrap();
    let packet = build_onion(&circuit, b"secret", &mut OsRng).unwrap();
    let outcome = peel_one_layer(&r1_sk, &packet).unwrap();
    let inner_bytes = match outcome {
        PeelOutcome::Forward {
            inner_packet_bytes, ..
        } => inner_packet_bytes,
        _ => panic!(),
    };
    let inner = OnionPacket::decode(&inner_bytes).unwrap();
    // r1 attempts to peel the inner packet (which belongs to r2).
    let err = peel_one_layer(&r1_sk, &inner).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_relay_cannot_decrypt_destination_layer() {
    // Build a 2-hop onion. r1 peels its layer, then tries to peel
    // the destination's layer with its own key — must fail.
    let (r1_sk, r1) = make_hop_pair(10);
    let (_, dest) = make_hop_pair(20);
    let circuit = Circuit::new(vec![r1, dest]).unwrap();
    let packet = build_onion(&circuit, b"plaintext", &mut OsRng).unwrap();
    let outcome = peel_one_layer(&r1_sk, &packet).unwrap();
    let inner_bytes = match outcome {
        PeelOutcome::Forward {
            inner_packet_bytes, ..
        } => inner_packet_bytes,
        _ => panic!(),
    };
    let inner = OnionPacket::decode(&inner_bytes).unwrap();
    let err = peel_one_layer(&r1_sk, &inner).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

// ── Replay defense ───────────────────────────────────────────────

#[test]
fn adversarial_replay_of_same_packet_yields_same_plaintext() {
    // The crate itself has no replay defense — that's an application-
    // layer concern. Document by testing that replay IS possible
    // here; callers must check nonces / sequence numbers above us.
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"replay-me", &mut OsRng).unwrap();
    let o1 = peel_one_layer(&dest_sk, &packet).unwrap();
    let o2 = peel_one_layer(&dest_sk, &packet).unwrap();
    assert_eq!(o1, o2);
}

// ── Tamper detection ─────────────────────────────────────────────

#[test]
fn adversarial_flip_any_byte_in_ciphertext_rejected() {
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"some payload", &mut OsRng).unwrap();
    for i in 0..packet.ciphertext.len() {
        let mut p = packet.clone();
        p.ciphertext[i] ^= 0x01;
        let err = peel_one_layer(&dest_sk, &p).unwrap_err();
        assert_eq!(err, OnionError::AeadFail, "byte index {i}");
    }
}

#[test]
fn adversarial_flip_nonce_byte_rejected() {
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let mut packet = build_onion(&circuit, b"x", &mut OsRng).unwrap();
    packet.aead_nonce[0] ^= 0x80;
    let err = peel_one_layer(&dest_sk, &packet).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_flip_hops_remaining_rejected() {
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let mut packet = build_onion(&circuit, b"x", &mut OsRng).unwrap();
    packet.hops_remaining ^= 0x80;
    let err = peel_one_layer(&dest_sk, &packet).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

// ── Edge cases ───────────────────────────────────────────────────

#[test]
fn adversarial_empty_payload_works() {
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"", &mut OsRng).unwrap();
    let outcome = peel_one_layer(&dest_sk, &packet).unwrap();
    match outcome {
        PeelOutcome::Deliver { payload } => assert!(payload.is_empty()),
        _ => panic!(),
    }
}

#[test]
fn adversarial_max_circuit_round_trip() {
    // MAX_HOPS = 5. Build the max-length circuit.
    let pairs: Vec<(StaticSecret, HopDescriptor)> = (1..=5).map(make_hop_pair).collect();
    let descs: Vec<HopDescriptor> = pairs.iter().map(|(_, h)| h.clone()).collect();
    let circuit = Circuit::new(descs).unwrap();
    let mut packet = build_onion(&circuit, b"max-hops", &mut OsRng).unwrap();
    for (i, (sk, _)) in pairs.iter().enumerate() {
        let outcome = peel_one_layer(sk, &packet).unwrap();
        match outcome {
            PeelOutcome::Forward {
                inner_packet_bytes, ..
            } => {
                packet = OnionPacket::decode(&inner_packet_bytes).unwrap();
                assert!(i + 1 < pairs.len());
            }
            PeelOutcome::Deliver { payload } => {
                assert_eq!(payload, b"max-hops");
                assert_eq!(i, pairs.len() - 1);
                return;
            }
        }
    }
}

#[test]
fn adversarial_one_hop_circuit_works() {
    // Edge: circuit with just the destination (no real relay).
    let (dest_sk, dest) = make_hop_pair(99);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"direct", &mut OsRng).unwrap();
    assert_eq!(packet.hops_remaining, 0);
    let outcome = peel_one_layer(&dest_sk, &packet).unwrap();
    match outcome {
        PeelOutcome::Deliver { payload } => assert_eq!(payload, b"direct"),
        _ => panic!(),
    }
}

// ── Two independent circuits don't cross-contaminate ─────────────

#[test]
fn adversarial_truncated_at_every_byte_position_rejected() {
    // Build a real packet, then try decoding every prefix shorter
    // than the full packet — must reject every one of them with a
    // typed error (Truncated, BadFrameSize, etc.).
    let (_, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"abc", &mut OsRng).unwrap();
    let enc = packet.encode();
    for prefix_len in 0..enc.len() {
        let result = OnionPacket::decode(&enc[..prefix_len]);
        assert!(
            result.is_err(),
            "truncated decode at len {} unexpectedly succeeded",
            prefix_len
        );
    }
    // Full-length decode succeeds.
    let _ = OnionPacket::decode(&enc).unwrap();
}

#[test]
fn adversarial_replay_across_circuits_blocked() {
    // Build two circuits with the SAME destination but different
    // (ciphertext, nonce, ephem_pubkey) seeds. Cross-feeding fails.
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit_a = Circuit::new(vec![dest.clone()]).unwrap();
    let circuit_b = Circuit::new(vec![dest]).unwrap();
    let packet_a = build_onion(&circuit_a, b"a", &mut OsRng).unwrap();
    let packet_b = build_onion(&circuit_b, b"b", &mut OsRng).unwrap();
    // Each packet decrypts correctly.
    let oa = peel_one_layer(&dest_sk, &packet_a).unwrap();
    let ob = peel_one_layer(&dest_sk, &packet_b).unwrap();
    assert!(matches!(oa, PeelOutcome::Deliver { ref payload } if payload == b"a"));
    assert!(matches!(ob, PeelOutcome::Deliver { ref payload } if payload == b"b"));
    // Splicing the ciphertext of one into the other's header fails AEAD.
    let mut spliced = packet_a.clone();
    spliced.ciphertext = packet_b.ciphertext.clone();
    let err = peel_one_layer(&dest_sk, &spliced).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_swapped_ephem_pubkey_rejected() {
    // Replace the ephem pubkey with one from a different circuit —
    // AEAD must fail because the derived layer key won't match.
    let (dest_sk, dest) = make_hop_pair(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"x", &mut OsRng).unwrap();
    let other_packet = build_onion(&circuit.clone(), b"y", &mut OsRng).unwrap();
    let mut tampered = packet.clone();
    tampered.ephem_pubkey = other_packet.ephem_pubkey;
    let err = peel_one_layer(&dest_sk, &tampered).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_random_garbage_packet_decode_returns_typed_err() {
    // Random bytes have astronomical odds of decoding as a valid
    // OnionPacket. Refusal must be a typed error, not a panic.
    for seed in 0u32..1000 {
        let mut bytes = Vec::with_capacity(64);
        let mut s = seed as u64;
        for _ in 0..64 {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            bytes.push((s >> 33) as u8);
        }
        let _ = OnionPacket::decode(&bytes); // must NEVER panic
    }
}

#[test]
fn adversarial_two_circuits_with_shared_keys_dont_collide() {
    let (sk1, r1) = make_hop_pair(1);
    let (sk2, r2) = make_hop_pair(2);

    let circuit_a = Circuit::new(vec![r1.clone(), r2.clone()]).unwrap();
    let circuit_b = Circuit::new(vec![r2.clone(), r1.clone()]).unwrap();

    let packet_a = build_onion(&circuit_a, b"path-a", &mut OsRng).unwrap();
    let packet_b = build_onion(&circuit_b, b"path-b", &mut OsRng).unwrap();

    // Each peel uses the right key.
    let oa = peel_one_layer(&sk1, &packet_a).unwrap();
    let ob = peel_one_layer(&sk2, &packet_b).unwrap();
    assert!(matches!(oa, PeelOutcome::Forward { .. }));
    assert!(matches!(ob, PeelOutcome::Forward { .. }));

    // Cross-feeding fails.
    let err = peel_one_layer(&sk2, &packet_a).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
    let err = peel_one_layer(&sk1, &packet_b).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}
