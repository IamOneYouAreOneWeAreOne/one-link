//! Constant-time gate tests for Sphinx Coherence comparison surfaces.
//!
//! Wall-clock variance < 5% across mismatched-byte positions. Catches
//! regressions that re-introduce data-dependent branches.

use std::time::Instant;

use ol_onion::sphinx::primitives::{header_mac, verify_header_mac, HEADER_LEN};

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
fn header_mac_verify_constant_time() {
    let key = [0x42u8; 32];
    let data = vec![0xCDu8; HEADER_LEN];
    let real_mac = header_mac(&key, &data);

    // Buckets: real_mac, byte-0 diff, byte-8 diff, byte-15 diff (last byte).
    let buckets: Vec<[u8; 16]> = vec![
        real_mac,
        {
            let mut m = real_mac;
            m[0] ^= 0x01;
            m
        },
        {
            let mut m = real_mac;
            m[8] ^= 0x01;
            m
        },
        {
            let mut m = real_mac;
            m[15] ^= 0x01;
            m
        },
    ];

    for b in &buckets {
        let _ = measure(
            || {
                let _ = verify_header_mac(&key, &data, b);
            },
            10_000,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(buckets.len());
    for b in &buckets {
        let ns = measure(
            || {
                std::hint::black_box(verify_header_mac(
                    &key,
                    &data,
                    std::hint::black_box(b),
                ));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("header_mac verify totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(
        rel < 0.05,
        "header_mac verify relative stddev {rel:.4} exceeds 5% gate"
    );
}
