//! Throughput benchmarks for `ol_fountain`.
//!
//! Targets the ADR-0015 hot paths:
//!
//! - LT encode: one symbol at a time, K source symbols of 1 KiB.
//! - LT decode: ingest stream until reconstructed.
//! - Packet encode/decode: wire-format header serialization.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_fountain::{FountainPacket, LtDecoder, LtEncoder};

fn make_source(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.wrapping_add(0xC0FFEE);
    while out.len() < len {
        // SplitMix-style PRNG for fast deterministic fill.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let z = z ^ (z >> 31);
        out.extend_from_slice(&z.to_le_bytes());
    }
    out.truncate(len);
    out
}

const SYMBOL_LEN: usize = 1024;

fn bench_encode_one_symbol(c: &mut Criterion) {
    let mut group = c.benchmark_group("fountain_encode_symbol");
    for &k in &[8u32, 64, 256] {
        let source = make_source(0xDEAD_BEEF, (k as usize) * SYMBOL_LEN);
        let enc = LtEncoder::new(&source, SYMBOL_LEN).unwrap();
        group.throughput(Throughput::Bytes(SYMBOL_LEN as u64));
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            let mut sid = 0u32;
            b.iter(|| {
                let payload = enc.encode_symbol(black_box(sid));
                sid = sid.wrapping_add(1);
                black_box(payload);
            });
        });
    }
    group.finish();
}

fn bench_decode_full_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("fountain_decode_chunk");
    for &k in &[8u32, 64, 256] {
        let source = make_source(0xCAFE_BABE, (k as usize) * SYMBOL_LEN);
        let enc = LtEncoder::new(&source, SYMBOL_LEN).unwrap();
        // Pre-compute enough symbols to guarantee decode succeeds.
        let max_symbols = (k * 3).max(64);
        let symbols: Vec<_> = (0u32..max_symbols).map(|sid| (sid, enc.encode_symbol(sid))).collect();
        group.throughput(Throughput::Bytes((k as u64) * (SYMBOL_LEN as u64)));
        group.bench_with_input(BenchmarkId::from_parameter(k), &k, |b, _| {
            b.iter(|| {
                let mut dec = LtDecoder::new(k, SYMBOL_LEN, source.len()).unwrap();
                for (sid, payload) in &symbols {
                    if dec.ingest(*sid, payload).unwrap() {
                        break;
                    }
                }
                let result = dec.finish().unwrap();
                black_box(result);
            });
        });
    }
    group.finish();
}

fn bench_packet_round_trip(c: &mut Criterion) {
    let mut group = c.benchmark_group("fountain_packet");
    let payload = vec![0xCDu8; SYMBOL_LEN];
    let chunk_id = [0xABu8; 32];

    group.throughput(Throughput::Bytes((SYMBOL_LEN + 44) as u64));
    group.bench_function("encode", |b| {
        b.iter(|| {
            let p = FountainPacket::new(
                black_box(chunk_id),
                black_box(64),
                black_box(7),
                black_box(64 * 1024),
                black_box(payload.clone()),
            );
            black_box(p.encode())
        });
    });
    let encoded = FountainPacket::new(chunk_id, 64, 7, 64 * 1024, payload.clone()).encode();
    group.bench_function("decode", |b| {
        b.iter(|| {
            let p = FountainPacket::decode(black_box(&encoded)).unwrap();
            black_box(p);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_encode_one_symbol,
    bench_decode_full_chunk,
    bench_packet_round_trip
);
criterion_main!(benches);
