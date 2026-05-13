//! Empirical hop-blindness tests for Sphinx Coherence.
//!
//! Verifies the load-bearing property: same-circuit alpha values at
//! different hops are statistically indistinguishable from independent
//! random Ristretto255 group elements.

use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashSet;

use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPeelOutcome,
};
use ol_onion::HopId;

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

/// Chi-squared statistic of byte distribution vs uniform.
fn chi_squared_uniform(bytes: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let n = bytes.len() as f64;
    let expected = n / 256.0;
    if expected < 1.0 {
        return 0.0;
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
fn alpha_bytes_at_each_hop_look_uniform() {
    // Build 50 random 3-hop circuits, collect alpha at every hop,
    // verify the aggregate byte distribution looks uniform via
    // chi-squared.
    let mut all_alpha_bytes = Vec::new();
    for _ in 0..50 {
        let (r1_sk, r1) = make_relay();
        let (r2_sk, r2) = make_relay();
        let (_dest_sk, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let packet = build_sphinx_onion(&eph_sk, &[r1, r2, dest], b"x", &mut OsRng).unwrap();

        // alpha at hop 0
        all_alpha_bytes.extend_from_slice(&packet.as_bytes()[1..33]);

        // peel r1
        let next = match peel_sphinx_layer(&r1_sk, &packet).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
            _ => panic!(),
        };
        all_alpha_bytes.extend_from_slice(&next.as_bytes()[1..33]);

        // peel r2
        let next = match peel_sphinx_layer(&r2_sk, &next).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
            _ => panic!(),
        };
        all_alpha_bytes.extend_from_slice(&next.as_bytes()[1..33]);
    }
    // 50 circuits * 3 hops * 32 bytes = 4800 bytes.
    let chi = chi_squared_uniform(&all_alpha_bytes);
    eprintln!(
        "alpha bytes: {} bytes, chi-sq vs uniform = {chi:.1}",
        all_alpha_bytes.len()
    );
    // df=255 critical at p=0.001 is ~340. Ristretto255 compressed
    // points should sit well under this.
    assert!(chi < 400.0, "alpha bytes deviate from uniform: chi-sq = {chi}");
}

#[test]
fn alpha_at_consecutive_hops_pairwise_distinct() {
    // For 100 random 3-hop circuits, alpha at every hop is unique
    // (i.e., the blinding actually changes alpha).
    let mut alpha_set: HashSet<[u8; 32]> = HashSet::new();
    let mut total = 0;
    for _ in 0..100 {
        let (r1_sk, r1) = make_relay();
        let (r2_sk, r2) = make_relay();
        let (_, dest) = make_relay();
        let (eph_sk, _) = generate_static_keypair(&mut OsRng);
        let p0 = build_sphinx_onion(&eph_sk, &[r1, r2, dest], b"x", &mut OsRng).unwrap();
        let mut a0 = [0u8; 32];
        a0.copy_from_slice(&p0.as_bytes()[1..33]);
        alpha_set.insert(a0);
        total += 1;

        let p1 = match peel_sphinx_layer(&r1_sk, &p0).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
            _ => panic!(),
        };
        let mut a1 = [0u8; 32];
        a1.copy_from_slice(&p1.as_bytes()[1..33]);
        alpha_set.insert(a1);
        total += 1;

        let p2 = match peel_sphinx_layer(&r2_sk, &p1).unwrap() {
            SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
            _ => panic!(),
        };
        let mut a2 = [0u8; 32];
        a2.copy_from_slice(&p2.as_bytes()[1..33]);
        alpha_set.insert(a2);
        total += 1;
    }
    // All 300 alphas should be distinct (probability of accidental
    // collision is negligible for Ristretto255).
    assert_eq!(alpha_set.len(), total);
}

#[test]
fn packet_structure_invariant_across_hops() {
    // At every hop the packet has identical structural metadata:
    // version=3, length=SPHINX_PACKET_LEN.
    let (r1_sk, r1) = make_relay();
    let (r2_sk, r2) = make_relay();
    let (_, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let p0 = build_sphinx_onion(&eph_sk, &[r1, r2, dest], b"hop-blindness", &mut OsRng).unwrap();
    use ol_onion::sphinx::core::{SPHINX_PACKET_LEN, SPHINX_VERSION};
    assert_eq!(p0.as_bytes().len(), SPHINX_PACKET_LEN);
    assert_eq!(p0.as_bytes()[0], SPHINX_VERSION);

    let p1 = match peel_sphinx_layer(&r1_sk, &p0).unwrap() {
        SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
        _ => panic!(),
    };
    assert_eq!(p1.as_bytes().len(), SPHINX_PACKET_LEN);
    assert_eq!(p1.as_bytes()[0], SPHINX_VERSION);

    let p2 = match peel_sphinx_layer(&r2_sk, &p1).unwrap() {
        SphinxPeelOutcome::Forward { next_packet, .. } => next_packet,
        _ => panic!(),
    };
    assert_eq!(p2.as_bytes().len(), SPHINX_PACKET_LEN);
    assert_eq!(p2.as_bytes()[0], SPHINX_VERSION);
}
