//! Throughput benchmarks for `ol_fec`.
//!
//! Per ADR-0016: targets ≥500 MiB/s/core scalar on RS(10,4) at 64 KiB
//! shards. Phase D upgrades (SIMD) will push past 5 GiB/s/core.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_fec::Codec;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn make_data(k: usize, shard_len: usize, seed: u64) -> Vec<Vec<u8>> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..k)
        .map(|_| (0..shard_len).map(|_| rng.r#gen::<u8>()).collect())
        .collect()
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_encode");
    let configs: &[(usize, usize, usize)] = &[
        (4, 2, 16 * 1024),  // small RS(4,2), 16 KiB shards
        (10, 4, 64 * 1024), // standard RS(10,4), 64 KiB shards
        (16, 8, 64 * 1024), // wide RS(16,8), 64 KiB shards
    ];
    for &(k, m, shard_len) in configs {
        let codec = Codec::new(k, m).unwrap();
        let data = make_data(k, shard_len, 0x9E37_79B9);
        let refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let total_data_bytes = (k * shard_len) as u64;
        group.throughput(Throughput::Bytes(total_data_bytes));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("RS({k},{m}) {}KiB", shard_len / 1024)),
            &(codec, refs),
            |b, (codec, refs)| {
                b.iter(|| {
                    let parity = codec.encode(black_box(refs)).unwrap();
                    black_box(parity);
                });
            },
        );
    }
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_decode");
    let configs: &[(usize, usize, usize)] =
        &[(4, 2, 16 * 1024), (10, 4, 64 * 1024), (16, 8, 64 * 1024)];
    for &(k, m, shard_len) in configs {
        let codec = Codec::new(k, m).unwrap();
        let data = make_data(k, shard_len, 0xCAFE_BABE);
        let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_slice()).collect();
        let parity = codec.encode(&data_refs).unwrap();
        // Drop the first `m` data shards to force full recovery work.
        let mut present: Vec<Option<&[u8]>> = Vec::with_capacity(k + m);
        for (i, d) in data.iter().enumerate() {
            if i < m {
                present.push(None);
            } else {
                present.push(Some(d.as_slice()));
            }
        }
        for p in &parity {
            present.push(Some(p.as_slice()));
        }
        let total_data_bytes = (k * shard_len) as u64;
        group.throughput(Throughput::Bytes(total_data_bytes));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("RS({k},{m}) {}KiB", shard_len / 1024)),
            &(codec, present),
            |b, (codec, present)| {
                b.iter(|| {
                    let decoded = codec.decode(black_box(present)).unwrap();
                    black_box(decoded);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
