//! Constant-time validation for `ol_onion` comparison surfaces.
//!
//! Same pattern as F1.1 / F2: measure wall-clock variance across
//! buckets; gate at 5% relative stddev.

use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_onion::keyderiv::LayerKey;
use ol_onion::{HopId, HOP_ID_LEN};

const SAMPLES_PER_BUCKET: usize = 50_000;

fn relative_stddev(samples: &[f64]) -> f64 {
    let sample_count = f64::from(u32::try_from(samples.len()).unwrap());
    let mean: f64 = samples.iter().sum::<f64>() / sample_count;
    let variance: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / sample_count;
    variance.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iterations: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        work();
    }
    start.elapsed()
}

#[test]
fn hop_id_eq_constant_time() {
    let base = HopId::from_bytes([0x42u8; HOP_ID_LEN]);
    let candidates: Vec<HopId> = vec![
        HopId::from_bytes([0x42u8; HOP_ID_LEN]),
        {
            let mut b = [0x42u8; HOP_ID_LEN];
            b[0] ^= 0x01;
            HopId::from_bytes(b)
        },
        {
            let mut b = [0x42u8; HOP_ID_LEN];
            b[15] ^= 0x01;
            HopId::from_bytes(b)
        },
        {
            let mut b = [0x42u8; HOP_ID_LEN];
            b[31] ^= 0x01;
            HopId::from_bytes(b)
        },
        HopId::from_bytes([0xCDu8; HOP_ID_LEN]),
    ];
    for c in &candidates {
        let _ = measure(
            || {
                let _ = base == *c;
            },
            10_000,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(candidates.len());
    for c in &candidates {
        let ns = measure(
            || {
                std::hint::black_box(base == *std::hint::black_box(c));
            },
            SAMPLES_PER_BUCKET,
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("hop_id eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    timing_gate!(
        rel < 0.05,
        "hop_id eq relative stddev {rel:.4} exceeds 5% gate"
    );
}

#[test]
fn layer_key_eq_constant_time() {
    let base = LayerKey::from_bytes([0x42u8; 32]);
    let candidates: Vec<LayerKey> = vec![
        LayerKey::from_bytes([0x42u8; 32]),
        {
            let mut b = [0x42u8; 32];
            b[0] ^= 0x01;
            LayerKey::from_bytes(b)
        },
        {
            let mut b = [0x42u8; 32];
            b[15] ^= 0x01;
            LayerKey::from_bytes(b)
        },
        {
            let mut b = [0x42u8; 32];
            b[31] ^= 0x01;
            LayerKey::from_bytes(b)
        },
        LayerKey::from_bytes([0xCDu8; 32]),
    ];
    // Warm up.
    for c in &candidates {
        let _ = measure(
            || {
                let _ = base == *c;
            },
            10_000,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(candidates.len());
    for c in &candidates {
        let ns = measure(
            || {
                std::hint::black_box(base == *std::hint::black_box(c));
            },
            SAMPLES_PER_BUCKET,
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("layer_key eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    timing_gate!(
        rel < 0.05,
        "layer_key eq relative stddev {rel:.4} exceeds 5% gate"
    );
}
