//! Criterion benches tracking encoder throughput on representative
//! payloads. The plan's Phase A1 acceptance gate calls out 1M
//! structured inputs in the byte-equivalence test; this bench
//! ensures the per-op cost stays in the sub-microsecond regime we
//! need for the chunk-envelope hot path.

// criterion_group! expands to a public function without docs.
#![allow(missing_docs)]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ol_canon::CanonEncoder;

fn bench_primitive_encode(c: &mut Criterion) {
    c.bench_function("encode_u64", |b| {
        b.iter(|| {
            let mut e = CanonEncoder::new();
            e.encode_u64(black_box(0xDEAD_BEEF_CAFE_BABE)).unwrap();
            black_box(e.finish());
        });
    });
    c.bench_function("encode_string_short", |b| {
        b.iter(|| {
            let mut e = CanonEncoder::new();
            e.encode_string(black_box("hello, canonical world"))
                .unwrap();
            black_box(e.finish());
        });
    });
    c.bench_function("encode_bytes_256B", |b| {
        let payload = vec![0xABu8; 256];
        b.iter(|| {
            let mut e = CanonEncoder::new();
            e.encode_bytes(black_box(&payload)).unwrap();
            black_box(e.finish());
        });
    });
}

fn bench_aggregate_encode(c: &mut Criterion) {
    // Models a small CRDT operation: vector clock + payload bytes.
    c.bench_function("encode_vector_clock_4_entries", |b| {
        let entries: Vec<(Vec<u8>, u64)> = (0..4)
            .map(|i| (vec![i as u8; 16], 1234u64 + i as u64))
            .collect();
        b.iter(|| {
            let mut e = CanonEncoder::new();
            e.encode_vector_clock(black_box(&entries)).unwrap();
            black_box(e.finish());
        });
    });
    c.bench_function("encode_struct_4_fields", |b| {
        b.iter(|| {
            let mut e = CanonEncoder::new();
            e.encode_struct_header(0xCAFE_BABE, 4).unwrap();
            e.encode_u64(42).unwrap();
            e.encode_string("hello").unwrap();
            e.encode_bool(true).unwrap();
            e.encode_bytes(&[0u8; 32]).unwrap();
            black_box(e.finish());
        });
    });
}

criterion_group!(benches, bench_primitive_encode, bench_aggregate_encode);
criterion_main!(benches);
