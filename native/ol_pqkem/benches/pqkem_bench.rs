//! Throughput benchmarks for `ol_pqkem`.
//!
//! Measures the three KEM operations + the BLAKE3 combiner. Pinned in
//! `BENCH_BASELINE_PHASE_C.md` for the Phase C optimization gate.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_pqkem::{decapsulate, encapsulate, keypair, HybridPublicKey, HybridSecretKey};
use rand::rngs::StdRng;
use rand::SeedableRng;

fn bench_keypair(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x9E37_79B9);
    c.bench_function("pqkem_keypair", |b| {
        b.iter(|| {
            let kp = keypair(black_box(&mut rng));
            black_box(kp);
        });
    });
}

fn bench_encapsulate(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xCAFE_BABE);
    let (pk, _sk): (HybridPublicKey, HybridSecretKey) = keypair(&mut rng);
    c.bench_function("pqkem_encapsulate", |b| {
        b.iter(|| {
            let (ct, ss) = encapsulate(black_box(&pk), &mut rng).unwrap();
            black_box((ct, ss));
        });
    });
}

fn bench_decapsulate(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF);
    let (pk, sk) = keypair(&mut rng);
    let (ct, _) = encapsulate(&pk, &mut rng).unwrap();
    c.bench_function("pqkem_decapsulate", |b| {
        b.iter(|| {
            let ss = decapsulate(black_box(&sk), black_box(&ct)).unwrap();
            black_box(ss);
        });
    });
}

fn bench_full_round_trip(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0xBABE_F00D);
    c.bench_function("pqkem_full_round_trip", |b| {
        b.iter(|| {
            let (pk, sk) = keypair(&mut rng);
            let (ct, ss1) = encapsulate(&pk, &mut rng).unwrap();
            let ss2 = decapsulate(&sk, &ct).unwrap();
            black_box((ss1, ss2));
        });
    });
}

criterion_group!(
    benches,
    bench_keypair,
    bench_encapsulate,
    bench_decapsulate,
    bench_full_round_trip,
);
criterion_main!(benches);
