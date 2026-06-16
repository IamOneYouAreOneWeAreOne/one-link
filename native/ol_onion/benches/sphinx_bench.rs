//! Microbenchmarks for Sphinx Coherence hot paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use rand::Rng;

use ol_onion::sphinx::core::{
    build_sphinx_onion, generate_static_keypair, peel_sphinx_layer, SphinxHop, SphinxPeelOutcome,
};
use ol_onion::sphinx::primitives::{
    build_filler, chacha20_keystream, derive_hop_keys, header_mac, HEADER_LEN, MAX_HOPS,
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

fn bench_derive_hop_keys(c: &mut Criterion) {
    let shared = [0x11u8; 32];
    let alpha = [0x22u8; 32];
    c.bench_function("sphinx::derive_hop_keys", |b| {
        b.iter(|| {
            let k = derive_hop_keys(black_box(&shared), black_box(&alpha));
            black_box(k);
        });
    });
}

fn bench_chacha20_header_keystream(c: &mut Criterion) {
    let key = [0x77u8; 32];
    c.bench_function("sphinx::chacha20_keystream_HEADER_LEN", |b| {
        b.iter(|| {
            let ks = chacha20_keystream(black_box(&key), HEADER_LEN);
            black_box(ks);
        });
    });
}

fn bench_chacha20_payload_keystream(c: &mut Criterion) {
    let key = [0x77u8; 32];
    c.bench_function("sphinx::chacha20_keystream_PAYLOAD_LEN", |b| {
        b.iter(|| {
            let ks = chacha20_keystream(black_box(&key), 1024);
            black_box(ks);
        });
    });
}

fn bench_header_mac(c: &mut Criterion) {
    let key = [0x55u8; 32];
    let data = vec![0xCDu8; HEADER_LEN];
    c.bench_function("sphinx::header_mac", |b| {
        b.iter(|| {
            let m = header_mac(black_box(&key), black_box(&data));
            black_box(m);
        });
    });
}

fn bench_filler_max_hops(c: &mut Criterion) {
    let keys: Vec<[u8; 32]> = (0..MAX_HOPS - 1).map(|i| [i as u8 + 1; 32]).collect();
    c.bench_function("sphinx::build_filler_4_relays", |b| {
        b.iter(|| {
            let f = build_filler(black_box(&keys));
            black_box(f);
        });
    });
}

fn bench_build_1_hop(c: &mut Criterion) {
    let (_, dest) = make_relay();
    let circuit = vec![dest];
    c.bench_function("sphinx::build_onion_1_hop", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let p = build_sphinx_onion(
                black_box(&eph_sk),
                black_box(&circuit),
                b"payload",
                &mut OsRng,
            )
            .unwrap();
            black_box(p);
        });
    });
}

fn bench_build_3_hop(c: &mut Criterion) {
    let (_, r1) = make_relay();
    let (_, r2) = make_relay();
    let (_, dest) = make_relay();
    let circuit = vec![r1, r2, dest];
    c.bench_function("sphinx::build_onion_3_hop", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let p = build_sphinx_onion(
                black_box(&eph_sk),
                black_box(&circuit),
                b"payload",
                &mut OsRng,
            )
            .unwrap();
            black_box(p);
        });
    });
}

fn bench_build_5_hop(c: &mut Criterion) {
    let pairs: Vec<_> = (0..5).map(|_| make_relay()).collect();
    let circuit: Vec<SphinxHop> = pairs.iter().map(|(_, h)| h.clone()).collect();
    c.bench_function("sphinx::build_onion_5_hop", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let p = build_sphinx_onion(
                black_box(&eph_sk),
                black_box(&circuit),
                b"payload",
                &mut OsRng,
            )
            .unwrap();
            black_box(p);
        });
    });
}

fn bench_peel_one_layer(c: &mut Criterion) {
    let (dest_sk, dest) = make_relay();
    let (eph_sk, _) = generate_static_keypair(&mut OsRng);
    let packet = build_sphinx_onion(&eph_sk, &[dest], b"payload", &mut OsRng).unwrap();
    c.bench_function("sphinx::peel_one_layer", |b| {
        b.iter(|| {
            let o = peel_sphinx_layer(black_box(&dest_sk), black_box(&packet)).unwrap();
            black_box(o);
        });
    });
}

fn bench_full_3_hop_round_trip(c: &mut Criterion) {
    let (r1_sk, r1) = make_relay();
    let (r2_sk, r2) = make_relay();
    let (dest_sk, dest) = make_relay();
    let circuit = vec![r1, r2, dest];
    c.bench_function("sphinx::full_3_hop_round_trip", |b| {
        b.iter(|| {
            let (eph_sk, _) = generate_static_keypair(&mut OsRng);
            let mut packet = build_sphinx_onion(&eph_sk, &circuit, b"payload", &mut OsRng).unwrap();
            for sk in [&r1_sk, &r2_sk, &dest_sk] {
                match peel_sphinx_layer(sk, &packet).unwrap() {
                    SphinxPeelOutcome::Forward { next_packet, .. } => packet = next_packet,
                    SphinxPeelOutcome::Deliver { payload } => {
                        black_box(payload);
                        break;
                    }
                }
            }
        });
    });
}

criterion_group!(
    benches,
    bench_derive_hop_keys,
    bench_chacha20_header_keystream,
    bench_chacha20_payload_keystream,
    bench_header_mac,
    bench_filler_max_hops,
    bench_build_1_hop,
    bench_build_3_hop,
    bench_build_5_hop,
    bench_peel_one_layer,
    bench_full_3_hop_round_trip,
);
criterion_main!(benches);
