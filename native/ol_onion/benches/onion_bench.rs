//! Microbenchmarks for ol_onion hot paths.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use ol_onion::{
    build_onion, peel_one_layer, Circuit, HopDescriptor, HopId, HOP_ID_LEN,
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

fn bench_build_1_hop(c: &mut Criterion) {
    let (_, dest) = make_hop(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    c.bench_function("build_onion_1_hop", |b| {
        b.iter(|| {
            let p = build_onion(&circuit, black_box(b"payload"), &mut OsRng).unwrap();
            black_box(p);
        });
    });
}

fn bench_build_3_hop(c: &mut Criterion) {
    let (_, r1) = make_hop(1);
    let (_, r2) = make_hop(2);
    let (_, r3) = make_hop(3);
    let (_, dest) = make_hop(4);
    let circuit = Circuit::new(vec![r1, r2, r3, dest]).unwrap();
    c.bench_function("build_onion_3_hop", |b| {
        b.iter(|| {
            let p = build_onion(&circuit, black_box(b"payload"), &mut OsRng).unwrap();
            black_box(p);
        });
    });
}

fn bench_peel_1_hop(c: &mut Criterion) {
    let (dest_sk, dest) = make_hop(1);
    let circuit = Circuit::new(vec![dest]).unwrap();
    let packet = build_onion(&circuit, b"payload", &mut OsRng).unwrap();
    c.bench_function("peel_one_layer", |b| {
        b.iter(|| {
            let o = peel_one_layer(black_box(&dest_sk), black_box(&packet)).unwrap();
            black_box(o);
        });
    });
}

criterion_group!(benches, bench_build_1_hop, bench_build_3_hop, bench_peel_1_hop);
criterion_main!(benches);
