//! Throughput benchmarks for `ol_bloom`.

use criterion::{black_box, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_bloom::Bloom;

fn make_id(i: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..4].copy_from_slice(&i.to_le_bytes());
    a[31] = 0xCD;
    a
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_insert");
    for &n in &[1024_usize, 16_384, 262_144] {
        group.throughput(Throughput::Elements(
            u64::try_from(n).expect("benchmark size fits in u64"),
        ));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let count = u32::try_from(n).expect("benchmark size fits in u32");
            let ids: Vec<_> = (0_u32..count).map(make_id).collect();
            b.iter_with_setup(
                || Bloom::new(n),
                |mut f| {
                    for cid in &ids {
                        f.insert(black_box(cid));
                    }
                    black_box(&f);
                },
            );
        });
    }
    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_contains");
    for &n in &[1024_usize, 16_384, 262_144] {
        group.throughput(Throughput::Elements(
            u64::try_from(n).expect("benchmark size fits in u64"),
        ));
        let mut f = Bloom::new(n);
        let count = u32::try_from(n).expect("benchmark size fits in u32");
        let ids: Vec<_> = (0_u32..count).map(make_id).collect();
        for cid in &ids {
            f.insert(cid);
        }
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    let cid = make_id(u32::try_from(i).expect("benchmark index fits in u32"));
                    let r = f.contains(black_box(&cid));
                    black_box(r);
                }
            });
        });
    }
    group.finish();
}

fn bench_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_codec");
    for &n in &[1024_usize, 16_384, 262_144] {
        let mut f = Bloom::new(n);
        let count = u32::try_from(n).expect("benchmark size fits in u32");
        for i in 0_u32..count {
            f.insert(&make_id(i));
        }
        let encoded = f.encode().unwrap();
        group.throughput(Throughput::Bytes(
            u64::try_from(encoded.len()).expect("encoded benchmark size fits in u64"),
        ));
        group.bench_with_input(BenchmarkId::new("encode", n), &n, |b, _| {
            b.iter(|| {
                let bytes = f.encode().unwrap();
                black_box(bytes);
            });
        });
        group.bench_with_input(BenchmarkId::new("decode", n), &n, |b, _| {
            b.iter(|| {
                let decoded = Bloom::decode(black_box(&encoded)).unwrap();
                black_box(decoded);
            });
        });
    }
    group.finish();
}

/// Parallel build path: build a fresh Bloom from N ids using rayon.
fn bench_extend_par(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_extend_par");
    for &n in &[16_384_usize, 262_144, 1_000_000] {
        let count = u32::try_from(n).expect("benchmark size fits in u32");
        let ids: Vec<_> = (0_u32..count).map(make_id).collect();
        group.throughput(Throughput::Elements(
            u64::try_from(n).expect("benchmark size fits in u64"),
        ));
        group.bench_with_input(BenchmarkId::from_parameter(n), &ids, |b, ids| {
            b.iter_with_setup(
                || Bloom::new(n),
                |mut f| {
                    f.extend_par(black_box(ids));
                    black_box(&f);
                },
            );
        });
    }
    group.finish();
}

/// Batch presence check: walk N ids through `contains_many`.
fn bench_contains_many(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_contains_many");
    for &n in &[1024_usize, 16_384, 262_144] {
        let mut f = Bloom::new(n);
        let count = u32::try_from(n).expect("benchmark size fits in u32");
        let ids: Vec<_> = (0_u32..count).map(make_id).collect();
        for cid in &ids {
            f.insert(cid);
        }
        group.throughput(Throughput::Elements(
            u64::try_from(n).expect("benchmark size fits in u64"),
        ));
        group.bench_with_input(BenchmarkId::from_parameter(n), &ids, |b, ids| {
            b.iter(|| {
                let v = f.contains_many(black_box(ids));
                black_box(v);
            });
        });
    }
    group.finish();
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{
        bench_contains, bench_contains_many, bench_encode_decode, bench_extend_par, bench_insert,
    };
    use criterion::criterion_group;

    criterion_group!(
        benches,
        bench_insert,
        bench_contains,
        bench_encode_decode,
        bench_extend_par,
        bench_contains_many,
    );
}
criterion_main!(criterion_benchmark_harness::benches);
