//! Microbenchmarks for Sphinx Coherence T1.5 (Schnorr aggregation).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::OsRng;

use ol_onion::sphinx::aggsig::{
    batch_verify, verify, SchnorrSignature, SchnorrSigningKey, SchnorrVerifyingKey,
};

fn bench_sign(c: &mut Criterion) {
    let sk = SchnorrSigningKey::generate(&mut OsRng);
    let msg = vec![0u8; 256];
    c.bench_function("aggsig::sign_256B", |b| {
        b.iter(|| black_box(sk.sign(black_box(&msg))));
    });
}

fn bench_verify(c: &mut Criterion) {
    let sk = SchnorrSigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let msg = vec![0u8; 256];
    let sig = sk.sign(&msg);
    c.bench_function("aggsig::verify_256B", |b| {
        b.iter(|| {
            verify(black_box(&vk), black_box(&msg), black_box(&sig)).unwrap();
        });
    });
}

fn bench_verifying_key(c: &mut Criterion) {
    let sk = SchnorrSigningKey::generate(&mut OsRng);
    c.bench_function("aggsig::verifying_key", |b| {
        b.iter(|| black_box(sk.verifying_key()));
    });
}

fn bench_batch_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggsig::batch_verify");
    for &n in &[1usize, 4, 8, 16, 32, 64] {
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            sks.push(SchnorrSigningKey::generate(&mut OsRng));
        }
        let msgs: Vec<Vec<u8>> = (0..n).map(|i| vec![(i & 0xFF) as u8; 64]).collect();
        let sigs: Vec<SchnorrSignature> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        let entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = (0..n)
            .map(|i| (sks[i].verifying_key(), msgs[i].as_slice(), sigs[i]))
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(n), &entries, |b, entries| {
            b.iter(|| {
                batch_verify(black_box(entries)).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_sequential_verify_for_compare(c: &mut Criterion) {
    // Baseline for batch_verify speed-up: verify N sigs one at a time.
    let mut group = c.benchmark_group("aggsig::sequential_verify");
    for &n in &[1usize, 4, 8, 16, 32, 64] {
        let mut sks = Vec::with_capacity(n);
        for _ in 0..n {
            sks.push(SchnorrSigningKey::generate(&mut OsRng));
        }
        let msgs: Vec<Vec<u8>> = (0..n).map(|i| vec![(i & 0xFF) as u8; 64]).collect();
        let sigs: Vec<SchnorrSignature> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| sk.sign(m))
            .collect();
        let vks: Vec<SchnorrVerifyingKey> = sks.iter().map(|s| s.verifying_key()).collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(n),
            &(vks, msgs, sigs),
            |b, (vks, msgs, sigs)| {
                b.iter(|| {
                    for i in 0..n {
                        verify(&vks[i], &msgs[i], &sigs[i]).unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_sign,
    bench_verify,
    bench_verifying_key,
    bench_batch_verify,
    bench_sequential_verify_for_compare
);
criterion_main!(benches);
