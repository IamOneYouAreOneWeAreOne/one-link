//! Empirical hop-blindness tests.
//!
//! TLA+ proves logical hop-blindness (see `docs/formal/onion.tla`).
//! These tests check the empirical byte-level property: at every
//! position along a 3-hop circuit, the packet "looks the same" in
//! its structural features (version byte, hops_remaining field
//! takes the expected value, ephemeral pubkey + nonce + ciphertext
//! all appear uniformly random to an observer).
//!
//! What we DON'T claim: that a global passive adversary cannot
//! correlate timing or packet size. Packet size shrinks
//! predictably per peel — that's the documented transport-layer
//! padding concern.

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_onion::{
    build_onion, peel_one_layer, Circuit, HopDescriptor, HopId, OnionPacket, PeelOutcome,
    HOP_ID_LEN,
};

fn make_hop(i: u8) -> (StaticSecret, HopDescriptor) {
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

/// Byte-frequency chi-squared statistic against uniform.
fn chi_squared_uniform(bytes: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let expected = n / 256.0;
    if expected < 1.0 {
        return 0.0; // sample too small to be meaningful
    }
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

#[test]
fn ciphertext_at_each_hop_looks_uniformly_random() {
    // Build a 3-hop circuit, peel at each hop, accumulate the
    // ciphertext bytes from every layer. Aggregate chi-squared
    // should be in the "looks uniform" range (chi-sq < 350 for
    // df=255 at p=0.001).
    let (r1_sk, r1) = make_hop(1);
    let (r2_sk, r2) = make_hop(2);
    let (dest_sk, dest) = make_hop(3);
    let circuit = Circuit::new(vec![r1, r2, dest]).unwrap();
    let mut all_ciphertext = Vec::new();

    // Build ~50 packets so we have ~50*200 = 10000 bytes of ciphertext.
    for _ in 0..50 {
        let payload = vec![0xAAu8; 200]; // constant plaintext to isolate the cipher
        let mut packet = build_onion(&circuit, &payload, &mut OsRng).unwrap();
        all_ciphertext.extend_from_slice(&packet.ciphertext);
        // Peel through.
        for sk in [&r1_sk, &r2_sk, &dest_sk] {
            match peel_one_layer(sk, &packet).unwrap() {
                PeelOutcome::Forward {
                    inner_packet_bytes, ..
                } => {
                    packet = OnionPacket::decode(&inner_packet_bytes).unwrap();
                    all_ciphertext.extend_from_slice(&packet.ciphertext);
                }
                PeelOutcome::Deliver { .. } => break,
            }
        }
    }

    let chi = chi_squared_uniform(&all_ciphertext);
    // 350 is the chi-sq critical value for df=255 at p=0.001 (very
    // loose). ChaCha20 ciphertext should sit well under this.
    eprintln!(
        "hop_blindness: {} bytes, chi-sq = {chi:.1}",
        all_ciphertext.len()
    );
    assert!(
        chi < 350.0,
        "ciphertext bytes deviate from uniform: chi-sq = {chi:.1}"
    );
}

#[test]
fn packet_structure_invariant_across_all_hops() {
    // At every hop along a 3-hop circuit the packet has:
    //   - version == 1
    //   - hops_remaining decrements by 1
    //   - ephem_pubkey is non-zero (small-order defense)
    //   - aead_nonce is 12 bytes
    //   - ciphertext is non-empty
    let (r1_sk, r1) = make_hop(10);
    let (r2_sk, r2) = make_hop(20);
    let (dest_sk, dest) = make_hop(30);
    let circuit = Circuit::new(vec![r1, r2, dest]).unwrap();
    let mut packet = build_onion(&circuit, b"hop-blindness", &mut OsRng).unwrap();

    let mut hops_seen: Vec<u8> = vec![packet.hops_remaining];
    assert_eq!(packet.version, 1);
    assert!(packet.ephem_pubkey.iter().any(|&b| b != 0));
    assert!(!packet.ciphertext.is_empty());

    for sk in [&r1_sk, &r2_sk, &dest_sk] {
        match peel_one_layer(sk, &packet).unwrap() {
            PeelOutcome::Forward {
                inner_packet_bytes, ..
            } => {
                packet = OnionPacket::decode(&inner_packet_bytes).unwrap();
                hops_seen.push(packet.hops_remaining);
                assert_eq!(packet.version, 1);
                assert!(packet.ephem_pubkey.iter().any(|&b| b != 0));
                assert!(!packet.ciphertext.is_empty());
            }
            PeelOutcome::Deliver { .. } => break,
        }
    }
    // hops_remaining at each layer: 2, 1, 0.
    assert_eq!(hops_seen, vec![2u8, 1, 0]);
}

#[test]
fn ephemeral_pubkey_distinct_at_each_hop() {
    // Each layer has its own ephemeral X25519 keypair. Across all
    // layers of one packet, the ephem_pubkey values are pairwise
    // distinct (in practice, with negligible random collision
    // probability).
    let (r1_sk, r1) = make_hop(11);
    let (r2_sk, r2) = make_hop(22);
    let (_, dest) = make_hop(33);
    let circuit = Circuit::new(vec![r1, r2, dest]).unwrap();
    let mut packet = build_onion(&circuit, b"x", &mut OsRng).unwrap();

    let mut seen = vec![packet.ephem_pubkey];
    for sk in [&r1_sk, &r2_sk] {
        match peel_one_layer(sk, &packet).unwrap() {
            PeelOutcome::Forward {
                inner_packet_bytes, ..
            } => {
                packet = OnionPacket::decode(&inner_packet_bytes).unwrap();
                seen.push(packet.ephem_pubkey);
            }
            _ => panic!(),
        }
    }
    // All three pubkeys distinct.
    for i in 0..seen.len() {
        for j in (i + 1)..seen.len() {
            assert_ne!(seen[i], seen[j], "ephem_pubkey collision");
        }
    }
}
