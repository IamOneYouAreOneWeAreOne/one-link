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
use ol_chunk::{
    blake3_wrap, scan_format_aware, scan_to_vec, scan_to_vec_parallel, zip_lfh_offsets, CdcParams,
    ChunkScanner, ContainerFormat, ZIP_LFH_FIXED_LEN, ZIP_LFH_MAGIC,
};

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

fn make_dummy_zip(entries: usize, entry_size: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(entries * (ZIP_LFH_FIXED_LEN + 7 + entry_size));
    for i in 0..entries {
        buf.extend_from_slice(&ZIP_LFH_MAGIC);
        buf.extend_from_slice(&20u16.to_le_bytes()); // version_needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&8u16.to_le_bytes()); // compression_method = deflate
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod_time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod_date
        buf.extend_from_slice(&0u32.to_le_bytes()); // crc-32
        buf.extend_from_slice(&(entry_size as u32).to_le_bytes()); // compressed
        buf.extend_from_slice(&(entry_size as u32).to_le_bytes()); // uncompressed
        buf.extend_from_slice(&7u16.to_le_bytes()); // name_length
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra_length
        let name = format!("file{i:02}\0");
        buf.extend_from_slice(&name.as_bytes()[..7]);
        buf.extend(std::iter::repeat((i as u8) ^ 0xAB).take(entry_size));
    }
    buf
}

fn bench_zip_lfh_walk(c: &mut Criterion) {
    let mut group = c.benchmark_group("zip_lfh_walk");
    // Realistic mix: 16 KiB-1 MiB entries, 10-80 entries per archive.
    for &(entries, entry_size) in &[
        (10usize, 16 * 1024usize),
        (80, 16 * 1024),
        (10, 1024 * 1024),
    ] {
        let buf = make_dummy_zip(entries, entry_size);
        group.throughput(Throughput::Bytes(buf.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(
                "entries-x-size",
                format!("{entries}x{}KiB", entry_size / 1024),
            ),
            &buf,
            |b, buf| {
                b.iter(|| {
                    let offs = zip_lfh_offsets(black_box(buf));
                    black_box(offs);
                });
            },
        );
    }
    group.finish();
}

/// Parallel scan path: CDC boundary discovery is inherently sequential
/// (rolling-hash state), but BLAKE3 hashing of each discovered chunk is
/// embarrassingly parallel. `scan_to_vec_parallel` shards the BLAKE3
/// pass across rayon. Win lands above ~1 MiB buffers.
fn bench_par_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("cdc_scan_par");
    for &size_mib in &[16usize, 64, 256] {
        let n = size_mib * 1024 * 1024;
        let mut buf = vec![0u8; n];
        fill_pseudo_random(&mut buf, 0xBEEF_F00D_u64.wrapping_add(size_mib as u64));
        group.throughput(Throughput::Bytes(n as u64));
        group.bench_with_input(BenchmarkId::new("seq", size_mib), &buf, |b, buf| {
            b.iter(|| {
                let v = scan_to_vec(black_box(buf));
                black_box(v);
            });
        });
        group.bench_with_input(BenchmarkId::new("par", size_mib), &buf, |b, buf| {
            b.iter(|| {
                let v = scan_to_vec_parallel(black_box(buf));
                black_box(v);
            });
        });
    }
    group.finish();
}

fn bench_format_aware_scan(c: &mut Criterion) {
    let mut group = c.benchmark_group("format_aware_scan");
    // 50-MiB-class dummy ZIP: 100 entries × 512 KiB each.
    let buf = make_dummy_zip(100, 512 * 1024);
    let n = buf.len() as u64;
    group.throughput(Throughput::Bytes(n));
    group.bench_function("zip_100entries_512K", |b| {
        b.iter(|| {
            let r = scan_format_aware(
                black_box(&buf),
                Some(ContainerFormat::Zip),
                CdcParams::default(),
            )
            .unwrap();
            black_box(r);
        });
    });
    // Pure-CDC baseline on the same buffer (no forced cuts; same size).
    group.bench_function("pure_cdc_baseline", |b| {
        b.iter(|| {
            let bounds: Vec<_> = ChunkScanner::new(black_box(&buf)).collect();
            black_box(bounds);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_cdc_scan,
    bench_blake3_chunk_address,
    bench_aead_key_derivation,
    bench_zip_lfh_walk,
    bench_format_aware_scan,
    bench_par_scan,
);
criterion_main!(benches);
