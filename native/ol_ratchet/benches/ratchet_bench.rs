//! Throughput benchmarks for `ol_ratchet`.
//!
//! Each chunk fetched / sent under per-chunk forward secrecy advances
//! the chain once. At 10K chunks per file × ~200 ns/step we're under
//! 2 ms ratchet overhead — perfectly acceptable. Target: ~200 ns per
//! `next_message_key`.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use ol_ratchet::{Chain, SkippedKeyStore};

fn bench_next_message_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_next_message_key");
    group.throughput(Throughput::Elements(1));
    group.bench_function("single_step", |b| {
        let mut chain = Chain::from_shared_secret(&[0x42u8; 32]);
        b.iter(|| {
            let mk = chain.next_message_key();
            black_box(mk);
        });
    });
    group.finish();
}

fn bench_fast_forward(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_fast_forward");
    group.bench_function("100-steps", |b| {
        b.iter(|| {
            let mut chain = Chain::from_shared_secret(&[0x77u8; 32]);
            chain.fast_forward(100).unwrap();
            black_box(chain.step());
        });
    });
    group.finish();
}

fn bench_peek_message_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_peek");
    group.bench_function("peek_step_100", |b| {
        let chain = Chain::from_shared_secret(&[0x33u8; 32]);
        b.iter(|| {
            let mk = chain.peek_message_key(100).unwrap();
            black_box(mk);
        });
    });
    group.finish();
}

fn bench_skipped_store_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_skipped_store");
    group.bench_function("insert+take", |b| {
        let mut store = SkippedKeyStore::with_capacity(1024);
        let chain = Chain::from_shared_secret(&[0xCDu8; 32]);
        let mk = chain.peek_message_key(0).unwrap();
        let mut step = 0u64;
        b.iter(|| {
            store.insert(step, mk.clone()).unwrap();
            let pulled = store.take(step).unwrap();
            black_box(pulled);
            step = step.wrapping_add(1);
        });
    });
    group.finish();
}

/// End-to-end: 1000-chunk chain advance (simulates a moderate-size file).
fn bench_thousand_chunk_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("ratchet_thousand_chunks");
    group.throughput(Throughput::Elements(1000));
    group.bench_function("1000_advances", |b| {
        b.iter(|| {
            let mut chain = Chain::from_shared_secret(&[0xAAu8; 32]);
            for _ in 0..1000 {
                let mk = chain.next_message_key();
                black_box(mk);
            }
        });
    });
    group.finish();
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{
        bench_fast_forward, bench_next_message_key, bench_peek_message_key,
        bench_skipped_store_round_trip, bench_thousand_chunk_chain, criterion_group,
    };

    criterion_group!(
        benches,
        bench_next_message_key,
        bench_fast_forward,
        bench_peek_message_key,
        bench_skipped_store_round_trip,
        bench_thousand_chunk_chain,
    );
}
criterion_main!(criterion_benchmark_harness::benches);
