//! Criterion benchmark for `ol_threshold_recovery`.
//!
//! Establishes throughput baselines + per-operation cycle estimates.
//! Re-run after any change to verify no regression.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use ol_threshold_recovery::field_bound::{
    field_bound_reconstruct, field_bound_split, FieldWitness,
};
use ol_threshold_recovery::gf256::{gf_mul, gf_mul_fast};
use ol_threshold_recovery::prng::PrngState;
use ol_threshold_recovery::shamir::{reconstruct_bytes, share_bytes};

fn bench_gf_mul(c: &mut Criterion) {
    let mut g = c.benchmark_group("gf256");
    // Constant-time path — what secret code uses.
    g.bench_function("gf_mul_constant_time", |bch| {
        bch.iter(|| {
            let mut acc: u32 = 0;
            for a in 0u32..16 {
                for b in 0u32..16 {
                    acc = acc.wrapping_add(gf_mul(black_box(a), black_box(b)));
                }
            }
            black_box(acc);
        });
    });
    // Fast LUT path — what public-value code uses.
    g.bench_function("gf_mul_fast_lut", |bch| {
        bch.iter(|| {
            let mut acc: u32 = 0;
            for a in 0u8..16 {
                for b in 0u8..16 {
                    acc = acc.wrapping_add(u32::from(gf_mul_fast(black_box(a), black_box(b))));
                }
            }
            black_box(acc);
        });
    });
    g.finish();
}

fn bench_shamir_split(c: &mut Criterion) {
    let mut g = c.benchmark_group("shamir_split");
    for &n_bytes in &[32usize, 256, 1024, 4096] {
        let secret = vec![0x42u8; n_bytes];
        g.throughput(Throughput::Bytes(n_bytes as u64));
        g.bench_with_input(BenchmarkId::new("3_of_5", n_bytes), &secret, |bch, s| {
            bch.iter(|| {
                let mut st = PrngState::new(0xDEAD_BEEF);
                let out = share_bytes(black_box(s), 3, 5, &mut st);
                black_box(out)
            });
        });
    }
    g.finish();
}

fn bench_shamir_reconstruct(c: &mut Criterion) {
    let mut g = c.benchmark_group("shamir_reconstruct");
    for &n_bytes in &[32usize, 256, 1024, 4096] {
        let secret = vec![0x42u8; n_bytes];
        let mut st = PrngState::new(0xDEAD_BEEF);
        let streams = share_bytes(&secret, 3, 5, &mut st).unwrap();
        let xs = vec![1u8, 2, 3];
        g.throughput(Throughput::Bytes(n_bytes as u64));
        g.bench_with_input(
            BenchmarkId::new("3_of_5", n_bytes),
            &streams,
            |bch, streams| {
                bch.iter(|| {
                    let refs: Vec<&[u8]> = streams[..3].iter().map(Vec::as_slice).collect();
                    let out = reconstruct_bytes(black_box(&xs), black_box(&refs), 3);
                    black_box(out)
                });
            },
        );
    }
    g.finish();
}

fn bench_field_bound_split(c: &mut Criterion) {
    let mut g = c.benchmark_group("field_bound_split");
    for &n_bytes in &[32usize, 256, 1024] {
        let secret = vec![0x42u8; n_bytes];
        let witness = FieldWitness {
            field_seed: [0x99u8; 32],
            holder_scores: vec![0.1, 0.3, 0.5, 0.7, 0.9],
            epoch_ns: 1_700_000_000_000_000_000,
        };
        g.throughput(Throughput::Bytes(n_bytes as u64));
        g.bench_with_input(BenchmarkId::new("3_of_5", n_bytes), &secret, |bch, s| {
            bch.iter(|| {
                let mut st = PrngState::new(0xDEAD_BEEF);
                let out = field_bound_split(black_box(s), 3, 5, &mut st, &witness);
                black_box(out)
            });
        });
    }
    g.finish();
}

fn bench_field_bound_reconstruct(c: &mut Criterion) {
    let mut g = c.benchmark_group("field_bound_reconstruct");
    for &n_bytes in &[32usize, 256, 1024] {
        let secret = vec![0x42u8; n_bytes];
        let witness = FieldWitness {
            field_seed: [0x99u8; 32],
            holder_scores: vec![0.1, 0.3, 0.5, 0.7, 0.9],
            epoch_ns: 1_700_000_000_000_000_000,
        };
        let mut st = PrngState::new(0xDEAD_BEEF);
        let masked = field_bound_split(&secret, 3, 5, &mut st, &witness).unwrap();
        let xs = vec![1u8, 2, 3];
        let indices = vec![0usize, 1, 2];
        g.throughput(Throughput::Bytes(n_bytes as u64));
        g.bench_with_input(
            BenchmarkId::new("3_of_5", n_bytes),
            &masked,
            |bch, masked| {
                bch.iter(|| {
                    let supplied: Vec<&[u8]> = masked[..3].iter().map(Vec::as_slice).collect();
                    let out = field_bound_reconstruct(
                        black_box(&xs),
                        black_box(&supplied),
                        black_box(&indices),
                        3,
                        &witness,
                    );
                    black_box(out)
                });
            },
        );
    }
    g.finish();
}

// Criterion's macro generates the public group function, so the lint exception
// is confined to that generated item instead of the benchmark crate.
#[allow(missing_docs)]
mod criterion_benchmark_harness {
    use super::{
        bench_field_bound_reconstruct, bench_field_bound_split, bench_gf_mul,
        bench_shamir_reconstruct, bench_shamir_split, criterion_group,
    };

    criterion_group!(
        benches,
        bench_gf_mul,
        bench_shamir_split,
        bench_shamir_reconstruct,
        bench_field_bound_split,
        bench_field_bound_reconstruct,
    );
}
criterion_main!(criterion_benchmark_harness::benches);
