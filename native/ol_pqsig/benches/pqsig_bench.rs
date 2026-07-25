//! Criterion benchmarks for hybrid post-quantum signatures.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::rngs::OsRng;

use ol_pqsig::HybridSigningKey;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("pqsig::generate_keypair", |b| {
        b.iter(|| {
            let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
            black_box((sk, vk));
        });
    });
}

fn bench_sign(c: &mut Criterion) {
    let (sk, _) = HybridSigningKey::generate(&mut OsRng);
    c.bench_function("pqsig::sign", |b| {
        b.iter(|| {
            let sig = sk.sign(black_box(b"benchmark message")).unwrap();
            black_box(sig);
        });
    });
}

fn bench_verify(c: &mut Criterion) {
    let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
    let msg = b"benchmark message";
    let sig = sk.sign(msg).unwrap();
    c.bench_function("pqsig::verify", |b| {
        b.iter(|| {
            vk.verify(black_box(msg), black_box(&sig[..])).unwrap();
        });
    });
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{bench_keygen, bench_sign, bench_verify, criterion_group};

    criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
}
criterion_main!(criterion_benchmark_harness::benches);
