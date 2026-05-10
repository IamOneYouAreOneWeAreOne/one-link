//! Throughput benchmarks for `ol_chunk`.
//!
//! Phase A1 acceptance gate per [ADR-0001](../../../docs/decisions/0001-cdc-kernel.md):
//! ≥ 2 GiB/s/core scalar; ≥ 5 GiB/s/core with AVX-512 / NEON dispatch.
//!
//! Run:
//!   cargo bench --bench cdc_bench
//!
//! These benches are part of the per-PR benchmark gate. PRs that regress
//! `cdc_scan_random_1gib` throughput by > 5 % must be rejected.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ol_chunk::{blake3_wrap, ChunkScanner};

/// Deterministic xorshift RNG so the benchmark workload is identical across
/// machines and across CI runs. SEED matches our perf_lab convention.
fn fill_pseudo_random(buf: &mut [u8], mut state: u64) {
    for byte in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = (state & 0xFF) as u8;
    }
}

fn bench_cdc_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("cdc_scan");
    for &size_mib in &[1usize, 16, 256, 1024] {
        let n = size_mib * 1024 * 1024;
        let mut buf = vec![0u8; n];
        fill_pseudo_random(
            &mut buf,
            0x1234_5678_DEAD_BEEF_u64.wrapping_add(size_mib as u64),
        );
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size_mib), &buf, |b, buf| {
            b.iter(|| {
                let scanner = ChunkScanner::new(black_box(buf));
                let mut count = 0usize;
                for boundary in scanner {
                    black_box(boundary);
                    count += 1;
                }
                black_box(count);
            });
        });
    }
    group.finish();
}

fn bench_blake3_chunk_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_address");
    for &size_kib in &[8usize, 64, 256] {
        let n = size_kib * 1024;
        let mut buf = vec![0u8; n];
        fill_pseudo_random(
            &mut buf,
            0xCAFE_BABE_F00D_BAAD_u64.wrapping_add(size_kib as u64),
        );
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::new("raw", size_kib), &buf, |b, buf| {
            b.iter(|| {
                let addr = blake3_wrap::chunk_address_raw(black_box(buf));
                black_box(addr);
            });
        });
        group.bench_with_input(BenchmarkId::new("convergent", size_kib), &buf, |b, buf| {
            b.iter(|| {
                let addr = blake3_wrap::chunk_address_convergent(black_box(buf));
                black_box(addr);
            });
        });
    }
    group.finish();
}

fn bench_aead_key_derivation(c: &mut Criterion) {
    let chain = [0x42u8; 32];
    let chunk = [0x01u8; 32];
    c.bench_function("derive_aead_key", |b| {
        b.iter(|| {
            let key = blake3_wrap::derive_aead_key(black_box(&chain), black_box(&chunk));
            black_box(key);
        });
    });
    c.bench_function("derive_ratchet_key_id", |b| {
        b.iter(|| {
            let id = blake3_wrap::derive_ratchet_key_id(black_box(&chain), black_box(&chunk));
            black_box(id);
        });
    });
    c.bench_function("derive_stripe_seed", |b| {
        b.iter(|| {
            let (s, p) = blake3_wrap::derive_stripe_seed(black_box(&chunk), 10);
            black_box((s, p));
        });
    });
}

criterion_group!(
    benches,
    bench_cdc_scan,
    bench_blake3_chunk_address,
    bench_aead_key_derivation,
);
criterion_main!(benches);
