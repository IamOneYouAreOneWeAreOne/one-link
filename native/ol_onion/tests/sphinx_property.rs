//! Sphinx Coherence property tests at the F1.x bar.
//!
//! 1M iters CI default / 5M iters nightly via ONE_LINK_F1_GATE=1.

use proptest::prelude::*;
use rand::rngs::OsRng;

use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPeelOutcome,
    SPHINX_PACKET_LEN,
};
use ol_onion::sphinx::field::{derive_hop_keys_with_witness, FIELD_WITNESS_LEN};
use ol_onion::sphinx::primitives::{
    build_filler, chacha20_keystream, derive_hop_keys, header_mac, verify_header_mac, HEADER_LEN,
    MAX_HOPS, SLOT_LEN,
};
use ol_onion::HopId;

fn cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        5_000_000
    } else {
        1_000_000
    }
}

fn light_cases() -> u32 {
    if std::env::var("ONE_LINK_F1_GATE").as_deref() == Ok("1") {
        500_000
    } else {
        100_000
    }
}

// ── Primitives properties ────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        max_global_rejects: cases() * 4,
        .. ProptestConfig::default()
    })]

    /// derive_hop_keys is deterministic + collision-free between
    /// the four sub-keys.
    #[test]
    fn derive_hop_keys_deterministic_and_collision_free(
        shared in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(),
    ) {
        let k1 = derive_hop_keys(&shared, &alpha);
        let k2 = derive_hop_keys(&shared, &alpha);
        prop_assert_eq!(k1.header_stream, k2.header_stream);
        prop_assert_eq!(k1.mac_key, k2.mac_key);
        // Sub-keys distinct (domain-separated).
        prop_assert_ne!(k1.header_stream, k1.mac_key);
        prop_assert_ne!(k1.header_stream, k1.payload_stream);
        prop_assert_ne!(k1.mac_key, k1.blinding_seed);
    }

    /// One-bit flip in `shared` produces fully-different keys
    /// (BLAKE3 avalanche property).
    #[test]
    fn derive_hop_keys_avalanche(
        shared in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(),
        flip_byte in 0u8..32,
    ) {
        let mut shared2 = shared;
        shared2[flip_byte as usize] ^= 0x01;
        let k1 = derive_hop_keys(&shared, &alpha);
        let k2 = derive_hop_keys(&shared2, &alpha);
        prop_assert_ne!(k1.header_stream, k2.header_stream);
        prop_assert_ne!(k1.mac_key, k2.mac_key);
        prop_assert_ne!(k1.payload_stream, k2.payload_stream);
        prop_assert_ne!(k1.blinding_seed, k2.blinding_seed);
    }

    /// header_mac is deterministic + one-byte tamper detection.
    #[test]
    fn header_mac_tamper_detection(
        key in any::<[u8; 32]>(),
        data in prop::collection::vec(any::<u8>(), HEADER_LEN..=HEADER_LEN),
        flip_byte in 0usize..HEADER_LEN,
    ) {
        let m1 = header_mac(&key, &data);
        let mut data2 = data.clone();
        data2[flip_byte] ^= 0x01;
        let m2 = header_mac(&key, &data2);
        prop_assert_ne!(m1, m2);
        // Verify is constant-time + accepts only the real MAC.
        prop_assert!(verify_header_mac(&key, &data, &m1));
        prop_assert!(!verify_header_mac(&key, &data2, &m1));
    }

    /// ChaCha20 keystream determinism.
    #[test]
    fn chacha20_deterministic_per_key(
        key in any::<[u8; 32]>(),
        len in 32usize..=512,
    ) {
        let a = chacha20_keystream(&key, len);
        let b = chacha20_keystream(&key, len);
        prop_assert_eq!(a, b);
    }
}

// ── Filler properties ────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        .. ProptestConfig::default()
    })]

    /// Filler length is exactly n * SLOT_LEN.
    #[test]
    fn filler_length_invariant(
        n_relays in 0usize..=MAX_HOPS,
    ) {
        let keys: Vec<[u8; 32]> = (0..n_relays)
            .map(|i| [i as u8 + 1; 32])
            .collect();
        let filler = build_filler(&keys);
        prop_assert_eq!(filler.len(), n_relays * SLOT_LEN);
    }

    /// Filler is deterministic for the same input keys.
    #[test]
    fn filler_deterministic(
        keys in prop::collection::vec(any::<[u8; 32]>(), 1..=MAX_HOPS),
    ) {
        let f1 = build_filler(&keys);
        let f2 = build_filler(&keys);
        prop_assert_eq!(f1, f2);
    }
}

// ── Sphinx end-to-end correctness ────────────────────────────────

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

use rand::Rng;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases() / 10,  // expensive — many curve ops per iter
        max_global_rejects: light_cases(),
        .. ProptestConfig::default()
    })]

    /// For any 1..=MAX_HOPS circuit and any payload up to MAX_USER_PAYLOAD,
    /// build + peel-through-all-hops recovers the original payload.
    #[test]
    fn sphinx_end_to_end_round_trip(
        n_hops in 1usize..=MAX_HOPS,
        payload_len in 0usize..=200,
    ) {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i as u8).wrapping_mul(31)).collect();
        let pairs: Vec<_> = (0..n_hops).map(|_| make_relay()).collect();
        let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut packet = build_sphinx_onion(&eph_sk, &circuit, &payload, &mut OsRng).unwrap();

        for (i, (sk, _)) in pairs.iter().enumerate() {
            match peel_sphinx_layer(sk, &packet).unwrap() {
                SphinxPeelOutcome::Forward { next_packet, .. } => {
                    prop_assert!(i + 1 < pairs.len());
                    packet = next_packet;
                }
                SphinxPeelOutcome::Deliver { payload: out } => {
                    prop_assert_eq!(i, pairs.len() - 1);
                    prop_assert_eq!(out, payload);
                    return Ok(());
                }
            }
        }
        // Should have returned above.
        prop_assert!(false, "fell through without delivery");
    }

    /// Packet size is invariant at every layer.
    #[test]
    fn sphinx_packet_size_constant(
        n_hops in 1usize..=MAX_HOPS,
    ) {
        let pairs: Vec<_> = (0..n_hops).map(|_| make_relay()).collect();
        let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let mut packet = build_sphinx_onion(&eph_sk, &circuit, b"x", &mut OsRng).unwrap();
        prop_assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);
        for (i, (sk, _)) in pairs.iter().enumerate() {
            match peel_sphinx_layer(sk, &packet).unwrap() {
                SphinxPeelOutcome::Forward { next_packet, .. } => {
                    prop_assert_eq!(next_packet.as_bytes().len(), SPHINX_PACKET_LEN);
                    packet = next_packet;
                }
                SphinxPeelOutcome::Deliver { .. } => {
                    prop_assert_eq!(i, pairs.len() - 1);
                    return Ok(());
                }
            }
        }
    }
}

// ── Field-bound properties ───────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        .. ProptestConfig::default()
    })]

    /// Same witness → same keys; different witnesses → different keys.
    #[test]
    fn field_bound_witness_determinism(
        shared in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(),
        witness in any::<[u8; FIELD_WITNESS_LEN]>(),
    ) {
        let k1 = derive_hop_keys_with_witness(&shared, &alpha, &witness);
        let k2 = derive_hop_keys_with_witness(&shared, &alpha, &witness);
        prop_assert_eq!(k1.header_stream, k2.header_stream);
        prop_assert_eq!(k1.mac_key, k2.mac_key);
    }

    /// One-bit flip in witness causes avalanche across all sub-keys.
    #[test]
    fn field_bound_one_bit_avalanche(
        shared in any::<[u8; 32]>(),
        alpha in any::<[u8; 32]>(),
        witness in any::<[u8; FIELD_WITNESS_LEN]>(),
        flip_byte in 0u8..32,
    ) {
        let mut w2 = witness;
        w2[flip_byte as usize] ^= 0x01;
        let k1 = derive_hop_keys_with_witness(&shared, &alpha, &witness);
        let k2 = derive_hop_keys_with_witness(&shared, &alpha, &w2);
        prop_assert_ne!(k1.header_stream, k2.header_stream);
        prop_assert_ne!(k1.mac_key, k2.mac_key);
        prop_assert_ne!(k1.payload_stream, k2.payload_stream);
        prop_assert_ne!(k1.blinding_seed, k2.blinding_seed);
    }
}

// ── PQ-hybrid properties ─────────────────────────────────────────

use ol_onion::sphinx::pq::{combine_hybrid_shared, PqSphinxHop};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: light_cases(),
        .. ProptestConfig::default()
    })]

    /// combine_hybrid_shared is deterministic per (classical, pq, alpha).
    #[test]
    fn pq_combine_deterministic(
        cs in any::<[u8; 32]>(),
        ps in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(),
    ) {
        let h1 = combine_hybrid_shared(&cs, &ps, &a);
        let h2 = combine_hybrid_shared(&cs, &ps, &a);
        prop_assert_eq!(h1, h2);
    }

    /// Any one-byte flip in any of the three inputs avalanches.
    #[test]
    fn pq_combine_one_byte_avalanche(
        cs in any::<[u8; 32]>(),
        ps in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(),
        which in 0u8..3,
        flip_byte in 0u8..32,
    ) {
        let h_real = combine_hybrid_shared(&cs, &ps, &a);
        let mut cs2 = cs;
        let mut ps2 = ps;
        let mut a2 = a;
        match which {
            0 => cs2[flip_byte as usize] ^= 0x01,
            1 => ps2[flip_byte as usize] ^= 0x01,
            _ => a2[flip_byte as usize] ^= 0x01,
        }
        let h_flipped = combine_hybrid_shared(&cs2, &ps2, &a2);
        prop_assert_ne!(h_real, h_flipped);
    }
}

// ── PQ-hybrid end-to-end (expensive — ML-KEM is ~100µs) ─────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 200,  // ML-KEM encap+decap is slow; keep light
        .. ProptestConfig::default()
    })]

    /// PQ-hybrid 1-hop round trip succeeds for any seeded payload.
    #[test]
    fn pq_sphinx_one_hop_round_trip(
        payload_len in 0usize..=200,
    ) {
        use ol_onion::sphinx::pq::{
            build_pq_sphinx_onion, generate_pq_keypair, peel_pq_sphinx_entry,
            PqSphinxPeelOutcome,
        };
        let payload: Vec<u8> = (0..payload_len).map(|i| i as u8).collect();
        let (entry_x_sk, entry_x_pk) = generate_static_keypair(&mut OsRng);
        let (entry_pq_dk, entry_pq_ek) = generate_pq_keypair(&mut OsRng);
        let mut id = [0u8; 32];
        OsRng.fill(&mut id);
        let entry = PqSphinxHop {
            id: HopId::from_bytes(id),
            static_x_pk: entry_x_pk,
            static_pq_pk: Some(entry_pq_ek),
        };
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet =
            build_pq_sphinx_onion(&eph_sk, &[entry], &payload, &mut OsRng).unwrap();
        match peel_pq_sphinx_entry(&entry_x_sk, &entry_pq_dk, &packet).unwrap() {
            PqSphinxPeelOutcome::Deliver { payload: out } => {
                prop_assert_eq!(out, payload);
            }
            _ => prop_assert!(false, "expected Deliver"),
        }
    }
}
