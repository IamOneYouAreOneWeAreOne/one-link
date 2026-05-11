use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

criterion_group!(benches, bench_observe);
criterion_main!(benches);
