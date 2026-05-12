//! Constant-time validation for `gf_mul`.
//!
//! The promise: `gf_mul(a, b)` runs in the same number of cycles
//! regardless of `a` and `b` (no data-dependent branches; masked XOR
//! instead of `if y_lsb { ... }`). This test measures wall-clock
//! variance across operand distributions and gates at < 5% relative
//! standard deviation.
//!
//! Wall-clock measurement is noisy — CPU cache, scheduling, frequency
//! scaling all add variance — so the gate is loose (5% relative
//! stddev). The TIGHT gate would be `dudect` or `cpucycles`-based
//! cycle-accurate measurement; that's a follow-up for the
//! constant-time audit sweep tracked in Phase C.
//!
//! What this catches RIGHT NOW: any future "optimization" that adds
//! a data-dependent branch to gf_mul (e.g., "skip when y == 0")
//! creates a measurable timing spike that bumps stddev > 5%.

use std::time::Instant;

use ol_threshold_recovery::gf256::gf_mul;

const SAMPLES_PER_BUCKET: usize = 50_000;
const BUCKETS: usize = 16;

fn measure_ns(a: u32, b: u32, n: usize) -> u128 {
    let start = Instant::now();
    let mut acc: u32 = 0;
    for _ in 0..n {
        // Use the accumulator so the optimiser can't dead-code-eliminate.
        acc = gf_mul(a.wrapping_add(acc & 0xFF), b);
    }
    let elapsed = start.elapsed().as_nanos();
    // Black-box the accumulator.
    std::hint::black_box(acc);
    elapsed
}

#[test]
fn gf_mul_constant_time_across_operand_buckets() {
    // 16 buckets of distinct (a, b) operand pairs spanning the full
    // GF(2^8) range. Measure SAMPLES_PER_BUCKET multiplications per
    // bucket; compute relative stddev across the 16 wall-clock totals.
    let pairs: [(u32, u32); BUCKETS] = [
        (0x00, 0x00),
        (0x00, 0xFF),
        (0xFF, 0x00),
        (0xFF, 0xFF),
        (0x01, 0x80),
        (0x80, 0x01),
        (0x55, 0xAA),
        (0xAA, 0x55),
        (0x57, 0x83),
        (0x53, 0xCA),
        (0x10, 0x20),
        (0x42, 0x42),
        (0x7F, 0x80),
        (0xFE, 0x01),
        (0x33, 0xCC),
        (0x99, 0x66),
    ];

    // Warm-up pass to stabilise CPU frequency scaling + caches.
    for &(a, b) in &pairs {
        let _ = measure_ns(a, b, 10_000);
    }

    let mut totals: Vec<f64> = Vec::with_capacity(BUCKETS);
    for &(a, b) in &pairs {
        let ns = measure_ns(a, b, SAMPLES_PER_BUCKET) as f64;
        totals.push(ns);
    }

    let mean: f64 = totals.iter().sum::<f64>() / totals.len() as f64;
    let variance: f64 = totals
        .iter()
        .map(|t| (t - mean).powi(2))
        .sum::<f64>()
        / totals.len() as f64;
    let stddev = variance.sqrt();
    let rel_stddev = stddev / mean;

    println!(
        "gf_mul timing: mean={:.0}ns stddev={:.0}ns rel={:.2}%",
        mean,
        stddev,
        rel_stddev * 100.0
    );
    // Gate: < 5% relative stddev. Loose because wall-clock noise on
    // a dev workstation is real; tightening requires cycle-accurate
    // measurement (dudect / cpucycles), tracked separately.
    assert!(
        rel_stddev < 0.05,
        "gf_mul timing varies > 5% across operand buckets: rel_stddev={:.2}%",
        rel_stddev * 100.0
    );
}
