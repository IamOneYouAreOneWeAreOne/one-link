//! Constant-time validation for ol_onion comparison surfaces.
//!
//! Same pattern as F1.1 / F2: measure wall-clock variance across
//! buckets; gate at 5% relative stddev.

use std::time::Instant;

use ol_onion::keyderiv::LayerKey;

const SAMPLES_PER_BUCKET: usize = 50_000;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance: f64 =
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    variance.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iterations: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iterations {
        work();
    }
    start.elapsed().as_nanos()
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
        let _ = measure(|| {
            let _ = base == *c;
        }, 10_000);
    }
    let mut totals: Vec<f64> = Vec::with_capacity(candidates.len());
    for c in &candidates {
        let ns = measure(
            || {
                std::hint::black_box(base == *std::hint::black_box(c));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("layer_key eq totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(rel < 0.05, "layer_key eq relative stddev {rel:.4} exceeds 5% gate");
}
