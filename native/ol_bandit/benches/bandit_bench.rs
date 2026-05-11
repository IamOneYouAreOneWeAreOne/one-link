//! Throughput benchmarks for `ol_bandit`.
//!
//! The bandit is called on EVERY transfer decision (chunk size choice,
//! parallelism, FEC ratio, etc.) so per-op cost matters. Target: < 1 µs
//! per `select` and per `update` for arms ≤ 10. Anything substantially
//! slower than this is on the daemon's hot path.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_bandit::{Bandit, BanditRng, BanditSeed};

fn bench_select(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandit_select");
    for &n_arms in &[2usize, 5, 10, 32] {
        let mut bandit = Bandit::new(n_arms).unwrap();
        // Warm up the bandit with 50 random updates so arms aren't all uniform.
        let mut rng = BanditSeed::new(0x9E37_79B9);
        for _ in 0..50 {
            let idx = bandit.select(&mut rng);
            bandit.update(idx, 0.7).unwrap();
        }
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(n_arms), &n_arms, |b, _| {
            b.iter(|| {
                let idx = bandit.select(black_box(&mut rng));
                black_box(idx);
            });
        });
    }
    group.finish();
}

fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandit_update");
    for &n_arms in &[2usize, 5, 10, 32] {
        let mut bandit = Bandit::new(n_arms).unwrap();
        let mut rng = BanditSeed::new(0xCAFE);
        let mut i = 0usize;
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(n_arms), &n_arms, |b, _| {
            b.iter(|| {
                let arm = i % n_arms;
                let reward = rng.next_f64();
                bandit.update(arm, reward).unwrap();
                i = i.wrapping_add(1);
            });
        });
    }
    group.finish();
}

/// End-to-end: 200-interaction sim (the Phase C gate horizon).
fn bench_full_horizon(c: &mut Criterion) {
    let mut group = c.benchmark_group("bandit_full_horizon");
    group.throughput(Throughput::Elements(200));
    group.bench_function("5-arm-200-iter", |b| {
        b.iter(|| {
            let mut bandit = Bandit::new(5).unwrap();
            let mut rng = BanditSeed::new(0xBABE);
            let probs = [0.20_f64, 0.40, 0.55, 0.70, 0.85];
            for _ in 0..200 {
                let arm = bandit.select(&mut rng);
                let u = rng.next_f64();
                let reward = if u < probs[arm] { 1.0 } else { 0.0 };
                bandit.update(arm, reward).unwrap();
            }
            black_box(bandit.best_arm());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_select, bench_update, bench_full_horizon);
criterion_main!(benches);
