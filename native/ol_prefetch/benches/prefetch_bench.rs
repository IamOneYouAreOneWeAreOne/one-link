//! Criterion benchmarks for the prefetch predictor.

use criterion::{black_box, criterion_main, Criterion};
use ol_prefetch::PrefetchPredictor;

fn bench_observe(c: &mut Criterion) {
    c.bench_function("observe_then_predict", |b| {
        let mut p = PrefetchPredictor::default();
        let peer = [0x01u8; 32];
        let mut t = 0u64;
        b.iter(|| {
            for i in 0..10u8 {
                p.observe(black_box(&peer), [i; 32], t);
                t += 10;
            }
            let preds = p.predict_top_n(black_box(&peer), 3);
            black_box(preds);
        });
    });
}

fn benchmarks() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_observe(&mut criterion);
}

criterion_main!(benchmarks);
