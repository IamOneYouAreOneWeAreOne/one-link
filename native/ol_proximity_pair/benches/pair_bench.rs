//! Criterion baselines for ol_proximity_pair.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use ol_proximity_pair::{
    block_syndrome, privacy_amplify, quantize_observations, reconcile_with_syndrome, QuantizeConfig,
};

fn bench_quantize(c: &mut Criterion) {
    let obs: Vec<u8> = (0..512u32).map(|i| (i.wrapping_mul(31)) as u8).collect();
    let cfg = QuantizeConfig {
        min_bytes: 128,
        guard_band: 0.10,
    };
    c.bench_function("quantize/512_bytes", |bch| {
        bch.iter(|| black_box(quantize_observations(black_box(&obs), &cfg).unwrap()));
    });
}

fn bench_syndrome(c: &mut Criterion) {
    let bits: Vec<u8> = (0..512).map(|i| (i as u8) & 1).collect();
    c.bench_function("syndrome/512_bits_block8", |bch| {
        bch.iter(|| black_box(block_syndrome(black_box(&bits), 8)));
    });
}

fn bench_reconcile(c: &mut Criterion) {
    let bits: Vec<u8> = (0..512).map(|i| (i as u8) & 1).collect();
    let syndrome = block_syndrome(&bits, 8);
    c.bench_function("reconcile/512_bits_block8", |bch| {
        bch.iter(|| {
            black_box(reconcile_with_syndrome(
                black_box(&bits),
                black_box(&syndrome),
                8,
            ))
        });
    });
}

fn bench_amplify(c: &mut Criterion) {
    let bits: Vec<u8> = (0..256).map(|i| (i as u8) & 1).collect();
    let salt = [0x42u8; 32];
    c.bench_function("amplify/256_bits_blake3", |bch| {
        bch.iter(|| black_box(privacy_amplify(black_box(&bits), black_box(&salt))));
    });
}

criterion_group!(
    benches,
    bench_quantize,
    bench_syndrome,
    bench_reconcile,
    bench_amplify,
);
criterion_main!(benches);
