//! Throughput benchmarks for `ol_bloom`.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_bloom::Bloom;

fn make_id(i: u32) -> [u8; 32] {
    let mut a = [0u8; 32];
    a[..4].copy_from_slice(&i.to_le_bytes());
    a[31] = 0xCD;
    a
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("bloom_insert");
    for &n in &[1024usize, 16384, 262144] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            let ids: Vec<_> = (0u32..n as u32).map(make_id).collect();
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
    for &n in &[1024usize, 16384, 262144] {
        group.throughput(Throughput::Elements(n as u64));
        let mut f = Bloom::new(n);
        let ids: Vec<_> = (0u32..n as u32).map(make_id).collect();
        for cid in &ids {
            f.insert(cid);
        }
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                for i in 0..n {
                    let cid = make_id(i as u32);
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
    for &n in &[1024usize, 16384, 262144] {
        let mut f = Bloom::new(n);
        for i in 0u32..n as u32 {
            f.insert(&make_id(i));
        }
        let encoded = f.encode().unwrap();
        group.throughput(Throughput::Bytes(encoded.len() as u64));
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

criterion_group!(benches, bench_insert, bench_contains, bench_encode_decode);
criterion_main!(benches);
