//! Adversarial test vectors for Sphinx Coherence.
//!
//! Every-byte-flip, cross-circuit, every known onion-routing attack
//! class. These are the regression bricks against future "optimizations"
//! that accidentally weaken the security guarantees.

use rand::rngs::OsRng;
use rand::Rng;

use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPacket,
    SphinxPeelOutcome, SPHINX_PACKET_LEN,
};
use ol_onion::sphinx::pq::{
    build_pq_sphinx_onion, generate_pq_keypair, peel_pq_sphinx_entry, PqSphinxHop, PqSphinxPacket,
    PqSphinxPeelOutcome,
};
use ol_onion::{HopId, OnionError};

fn make_relay() -> (curve25519_dalek::scalar::Scalar, SphinxHop) {
    let (sk, pk) = generate_static_keypair(&mut OsRng);
    let mut id = [0u8; 32];
    OsRng.fill(&mut id);
    (
        sk,
        SphinxHop {
            id: HopId::from_bytes(id),
            static_pk: pk,
        },
    )
}

// ── Tamper detection: every byte rejected ────────────────────────

/// Sphinx authenticates ONLY the header. The payload region is
/// ChaCha20-encrypted but NOT authenticated by Sphinx itself — the
/// application layer is expected to AEAD-encrypt its inner content.
/// This test verifies the property at each region:
///
/// - Header-region flips (bytes 1..289): rejected with AeadFail.
/// - Payload-region flips (bytes 289..): may decrypt to different
///   bytes, but the user-level AEAD would catch that.
#[test]
fn adversarial_header_region_byte_flips_rejected() {
    use ol_onion::sphinx::primitives::HEADER_LEN;
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"adv-test", &mut OsRng).unwrap();
    let bytes = packet.as_bytes();

    // Header region is: 1 (version) + 32 (alpha) + 16 (mac) + HEADER_LEN.
    // Skip byte 0 (version validates separately).
    let header_region_end = 1 + 32 + 16 + HEADER_LEN;
    for i in 1..header_region_end {
        let mut tampered = *bytes;
        tampered[i] ^= 0x01;
        let pkt = match SphinxPacket::from_bytes(&tampered) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match peel_sphinx_layer(&dest_sk, &pkt) {
            Err(OnionError::AeadFail) | Err(OnionError::SmallOrderPubkey) => {} // tamper detected
            Err(other) => panic!("byte {i} flip: unexpected error {other:?}"),
            Ok(out) => panic!("byte {i} flip: unexpectedly succeeded with {out:?}"),
        }
    }
}

/// Payload-region byte flips do NOT trigger Sphinx-layer errors
/// (payload is ChaCha20-stream-encrypted; no auth at Sphinx layer).
/// But the decrypted user payload at those positions DOES change,
/// which a caller-side AEAD would catch.
#[test]
fn adversarial_payload_region_flips_change_user_payload() {
    use ol_onion::sphinx::primitives::HEADER_LEN;
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    // Use a longer payload so most flips land inside user data.
    let user_payload = vec![0xCDu8; 256];
    let packet = build_sphinx_onion(&eph_sk, &[dest], &user_payload, &mut OsRng).unwrap();
    let bytes = packet.as_bytes();
    let payload_region_start = 1 + 32 + 16 + HEADER_LEN;
    // Flip a byte in the middle of the user payload area (~100 bytes
    // into the user data, well clear of the length prefix).
    let i = payload_region_start + 2 + 100;
    let mut tampered = *bytes;
    tampered[i] ^= 0x01;
    let pkt = SphinxPacket::from_bytes(&tampered).unwrap();
    let outcome = peel_sphinx_layer(&dest_sk, &pkt).unwrap();
    match outcome {
        SphinxPeelOutcome::Deliver { payload } => {
            // The payload was modified by the flip — Sphinx itself
            // does NOT detect this; the caller's AEAD would.
            assert_ne!(payload, user_payload, "payload byte flip didn't propagate to decrypt");
        }
        _ => panic!(),
    }
}

#[test]
fn adversarial_truncated_packet_rejected() {
    let (_, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
    let bytes = packet.as_bytes();
    for len in 0..SPHINX_PACKET_LEN {
        let err = SphinxPacket::from_bytes(&bytes[..len]).unwrap_err();
        assert!(matches!(err, OnionError::BadFrameSize { .. } | OnionError::Truncated { .. }));
    }
}

#[test]
fn adversarial_wrong_version_byte_rejected() {
    let (_, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
    for bad_version in [0u8, 1, 2, 4, 5, 99, 0xFF] {
        let mut bytes = *packet.as_bytes();
        bytes[0] = bad_version;
        let err = SphinxPacket::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            err,
            OnionError::UnsupportedVersion { .. }
        ));
    }
}

#[test]
fn adversarial_random_garbage_decode_typed_err_no_panic() {
    // 10k random byte sequences — must never panic; the decoder must
    // always return a typed error or a structurally-valid packet that
    // fails at peel time.
    for seed in 0u32..10_000 {
        let mut bytes = [0u8; SPHINX_PACKET_LEN];
        let mut s = seed as u64;
        for b in &mut bytes {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
            *b = (s >> 33) as u8;
        }
        let _ = SphinxPacket::from_bytes(&bytes);
        // No panic = pass.
    }
}

#[test]
fn adversarial_small_order_alpha_rejected() {
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
    // Replace alpha with all-zero (small-order point).
    let mut bytes = *packet.as_bytes();
    for i in 1..33 {
        bytes[i] = 0;
    }
    let tampered = SphinxPacket::from_bytes(&bytes).unwrap();
    let err = peel_sphinx_layer(&dest_sk, &tampered).unwrap_err();
    assert_eq!(err, OnionError::SmallOrderPubkey);
}

// ── Cross-circuit isolation ──────────────────────────────────────

#[test]
fn adversarial_cross_circuit_alpha_swap_rejected() {
    // Build two packets to the SAME destination via independent
    // sender ephemeral keys. Swap their alphas. Both must reject.
    let (dest_sk, dest) = make_relay();
    let (eph_a, _) = generate_static_keypair(&mut OsRng);
    let (eph_b, _) = generate_static_keypair(&mut OsRng);
    let packet_a =
        build_sphinx_onion(&eph_a, &[dest.clone()], b"a", &mut OsRng).unwrap();
    let packet_b =
        build_sphinx_onion(&eph_b, &[dest.clone()], b"b", &mut OsRng).unwrap();

    let mut spliced = *packet_a.as_bytes();
    spliced[1..33].copy_from_slice(&packet_b.as_bytes()[1..33]);
    let pkt = SphinxPacket::from_bytes(&spliced).unwrap();
    let err = peel_sphinx_layer(&dest_sk, &pkt).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_relay_attempts_inner_peel_rejected() {
    // 3-hop circuit: r1, r2, dest. r1 peels its layer. r1 then tries
    // to peel the FORWARDED inner packet with its own key (i.e., r1
    // tries to read r2's content). Must fail AEAD/MAC.
    let (r1_sk, r1) = make_relay();
    let (_r2_sk, r2) = make_relay();
    let (_dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[r1.clone(), r2, dest], b"x", &mut OsRng).unwrap();

    let outcome = peel_sphinx_layer(&r1_sk, &packet).unwrap();
    let inner = match outcome {
        SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
        _ => panic!(),
    };
    // r1 tries to peel inner with its own key.
    let err = peel_sphinx_layer(&r1_sk, &inner).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

// ── Wrong-key rejection ──────────────────────────────────────────

#[test]
fn adversarial_wrong_relay_key_rejected_across_random_seeds() {
    // 1000 random wrong-keys — never accidentally accepted.
    let (_dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"x", &mut OsRng).unwrap();
    for _ in 0..1000 {
        let (wrong_sk, _) = generate_static_keypair(&mut OsRng);
        let err = peel_sphinx_layer(&wrong_sk, &packet).unwrap_err();
        assert_eq!(err, OnionError::AeadFail);
    }
}

// ── PQ-hybrid adversarials ───────────────────────────────────────

fn make_pq_entry() -> (
    curve25519_dalek::scalar::Scalar,
    <ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey,
    PqSphinxHop,
) {
    let (x_sk, x_pk) = generate_static_keypair(&mut OsRng);
    let (pq_dk, pq_ek) = generate_pq_keypair(&mut OsRng);
    let mut id = [0u8; 32];
    OsRng.fill(&mut id);
    (
        x_sk,
        pq_dk,
        PqSphinxHop {
            id: HopId::from_bytes(id),
            static_x_pk: x_pk,
            static_pq_pk: Some(pq_ek),
        },
    )
}

#[test]
fn adversarial_pq_wrong_pq_dk_at_entry_rejected() {
    let (entry_x_sk, _entry_pq_dk, entry) = make_pq_entry();
    let (wrong_pq_dk, _) = generate_pq_keypair(&mut OsRng);
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet =
        build_pq_sphinx_onion(&eph_sk, &[entry.clone()], b"x", &mut OsRng).unwrap();
    let err = peel_pq_sphinx_entry(&entry_x_sk, &wrong_pq_dk, &packet).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_pq_intermediate_attempts_entry_peel_rejected() {
    // If a downstream relay tries to peel a packet AS IF it were the
    // entry hop (i.e., uses its own PQ key for decap), it must fail.
    // This catches a daemon bug where intermediate hops accidentally
    // use the entry-mode peel function.
    let (entry_x_sk, entry_pq_dk, entry) = make_pq_entry();
    let (mid_x_sk, mid_x_pk) = generate_static_keypair(&mut OsRng);
    let (_mid_pq_dk, _) = generate_pq_keypair(&mut OsRng);
    let mut mid_id = [0u8; 32];
    OsRng.fill(&mut mid_id);
    let mid = PqSphinxHop {
        id: HopId::from_bytes(mid_id),
        static_x_pk: mid_x_pk,
        static_pq_pk: None, // intermediate hops don't have PQ pubkeys in this design
    };
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet =
        build_pq_sphinx_onion(&eph_sk, &[entry, mid], b"x", &mut OsRng).unwrap();

    // Entry peels with hybrid.
    let outcome = peel_pq_sphinx_entry(&entry_x_sk, &entry_pq_dk, &packet).unwrap();
    let next = match outcome {
        PqSphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
        _ => panic!(),
    };

    // Now an attacker (or buggy daemon) tries to peel the forwarded
    // packet at the mid hop using ENTRY-mode (with some PQ key).
    let (some_pq_dk, _) = generate_pq_keypair(&mut OsRng);
    let err = peel_pq_sphinx_entry(&mid_x_sk, &some_pq_dk, &next).unwrap_err();
    assert_eq!(err, OnionError::AeadFail);
}

#[test]
fn adversarial_pq_header_region_byte_flips_rejected() {
    use ol_onion::sphinx::primitives::HEADER_LEN;
    use ol_onion::sphinx::pq::ML_KEM_CT_LEN;
    let (entry_x_sk, entry_pq_dk, entry) = make_pq_entry();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_pq_sphinx_onion(&eph_sk, &[entry], b"adv", &mut OsRng).unwrap();
    let bytes = packet.as_bytes().to_vec();
    // Header region: 1 + 32 (alpha) + 1088 (pq_ct) + 16 (mac) + HEADER_LEN.
    let header_region_end = 1 + 32 + ML_KEM_CT_LEN + 16 + HEADER_LEN;
    // Step by 47 (a prime; reasonable sample density) for speed.
    for byte_idx in (1..header_region_end).step_by(47) {
        let mut tampered = bytes.clone();
        tampered[byte_idx] ^= 0x01;
        let pkt = match PqSphinxPacket::from_bytes(&tampered) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let result = peel_pq_sphinx_entry(&entry_x_sk, &entry_pq_dk, &pkt);
        match result {
            Err(OnionError::AeadFail) | Err(OnionError::SmallOrderPubkey) => {}
            Err(other) => panic!("byte {byte_idx} flip: unexpected error {other:?}"),
            Ok(out) => panic!("byte {byte_idx} flip: unexpectedly succeeded with {out:?}"),
        }
    }
}

// ── Edge cases ───────────────────────────────────────────────────

#[test]
fn adversarial_empty_payload_works() {
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"", &mut OsRng).unwrap();
    let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
    match outcome {
        SphinxPeelOutcome::Deliver { payload } => assert!(payload.is_empty()),
        _ => panic!(),
    }
}

#[test]
fn adversarial_max_payload_works() {
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    use ol_onion::sphinx::core::SPHINX_MAX_USER_PAYLOAD;
    let payload = vec![0xAA; SPHINX_MAX_USER_PAYLOAD];
    let packet = build_sphinx_onion(&eph_sk, &[dest], &payload, &mut OsRng).unwrap();
    let outcome = peel_sphinx_layer(&dest_sk, &packet).unwrap();
    match outcome {
        SphinxPeelOutcome::Deliver { payload: out } => assert_eq!(out, payload),
        _ => panic!(),
    }
}

#[test]
fn adversarial_max_hops_round_trip() {
    use ol_onion::sphinx::primitives::MAX_HOPS;
    let pairs: Vec<_> = (0..MAX_HOPS).map(|_| make_relay()).collect();
    let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let mut packet =
        build_sphinx_onion(&eph_sk, &circuit, b"max-hop adv", &mut OsRng).unwrap();
    for (i, (sk, _)) in pairs.iter().enumerate() {
        match peel_sphinx_layer(sk, &packet).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => {
                packet = next_packet;
                assert!(i + 1 < pairs.len());
            }
            SphinxPeelOutcome::Deliver { payload } => {
                assert_eq!(payload, b"max-hop adv");
                assert_eq!(i, pairs.len() - 1);
                return;
            }
        }
    }
}

#[test]
fn adversarial_too_many_hops_rejected() {
    use ol_onion::sphinx::primitives::MAX_HOPS;
    let pairs: Vec<_> = (0..MAX_HOPS + 1).map(|_| make_relay()).collect();
    let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let err = build_sphinx_onion(&eph_sk, &circuit, b"x", &mut OsRng).unwrap_err();
    assert!(matches!(err, OnionError::TooManyHops { .. }));
}

#[test]
fn adversarial_empty_circuit_rejected() {
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let err = build_sphinx_onion(&eph_sk, &[], b"x", &mut OsRng).unwrap_err();
    assert_eq!(err, OnionError::EmptyCircuit);
}

#[test]
fn adversarial_payload_oversize_rejected() {
    use ol_onion::sphinx::core::SPHINX_MAX_USER_PAYLOAD;
    let (_, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let huge = vec![0u8; SPHINX_MAX_USER_PAYLOAD + 1];
    let err = build_sphinx_onion(&eph_sk, &[dest], &huge, &mut OsRng).unwrap_err();
    assert!(matches!(err, OnionError::PayloadOversize { .. }));
}

// ── Replay (intentionally permitted at this layer) ───────────────

#[test]
fn adversarial_replay_yields_same_plaintext() {
    // The Sphinx layer has no replay defense — that's an application-
    // layer concern. Document this by testing that REPLAY IS POSSIBLE
    // (caller MUST check nonces / sequence numbers above us).
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"replay", &mut OsRng).unwrap();
    let o1 = peel_sphinx_layer(&dest_sk, &packet).unwrap();
    let o2 = peel_sphinx_layer(&dest_sk, &packet).unwrap();
    assert_eq!(o1, o2);
}
