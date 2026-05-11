//! Throughput benchmarks for `ol_erasure`.
//!
//! Lifts `ol_fec` shard throughput to whole-chunk stripe throughput at
//! realistic chunk sizes (64 KiB CDC chunks per ADR-0001).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_erasure::{decode_stripe, encode_stripe, Shard, StripeParams};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn make_plaintext(seed: u64, len: usize) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..len).map(|_| rng.r#gen::<u8>()).collect()
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("erasure_encode");
    let configs: &[(StripeParams, usize, &str)] = &[
        (StripeParams::EPHEMERAL, 64 * 1024, "EPHEMERAL-64KiB"),
        (StripeParams::STANDARD, 64 * 1024, "STANDARD-64KiB"),
        (StripeParams::STANDARD, 256 * 1024, "STANDARD-256KiB"),
        (StripeParams::ARCHIVAL, 64 * 1024, "ARCHIVAL-64KiB"),
    ];
    for &(params, len, label) in configs {
        let plaintext = make_plaintext(0x9E37_79B9, len);
        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(label), &plaintext, |b, pt| {
            b.iter(|| {
                let shards = encode_stripe(black_box(pt), params).unwrap();
                black_box(shards);
            });
        });
    }
    group.finish();
}

fn bench_decode_no_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("erasure_decode_full");
    let params = StripeParams::STANDARD;
    let plaintext = make_plaintext(0xCAFE_BABE, 64 * 1024);
    let shards = encode_stripe(&plaintext, params).unwrap();
    group.throughput(Throughput::Bytes(plaintext.len() as u64));
    group.bench_function("STANDARD-64KiB-no-loss", |b| {
        let present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
        b.iter(|| {
            let decoded = decode_stripe(params, black_box(&present)).unwrap();
            black_box(decoded);
        });
    });
    group.finish();
}

fn bench_decode_with_erasures(c: &mut Criterion) {
    let mut group = c.benchmark_group("erasure_decode_with_loss");
    let params = StripeParams::STANDARD;
    let plaintext = make_plaintext(0xF00D_BABE, 64 * 1024);
    let shards = encode_stripe(&plaintext, params).unwrap();
    group.throughput(Throughput::Bytes(plaintext.len() as u64));

    // Drop shards 0, 2, 5, 11 — covers data + parity recovery work.
    let mut present: Vec<Option<&Shard>> = shards.iter().map(Some).collect();
    for &drop in &[0usize, 2, 5, 11] {
        present[drop] = None;
    }
    group.bench_function("STANDARD-64KiB-drop-4", |b| {
        b.iter(|| {
            let decoded = decode_stripe(params, black_box(&present)).unwrap();
            black_box(decoded);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_encode,
    bench_decode_no_loss,
    bench_decode_with_erasures,
);
criterion_main!(benches);
