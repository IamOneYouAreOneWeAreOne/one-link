//! Constant-time gate for the Layer 10 duress-alert verify path.

use std::time::Instant;

use ol_device_mesh::duress::{sign_duress_alert, DuressAlert};
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 200;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let var: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    var.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iters: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iters {
        work();
    }
    start.elapsed().as_nanos()
}

#[test]
fn duress_alert_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let real = sign_duress_alert(&sk, 1_700_000_000, [0xCC; 16]).unwrap();
    let vk = sk.verifying_key();
    let sig_len = real.subkey_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<DuressAlert> = positions
        .iter()
        .map(|&pos| {
            let mut a = real.clone();
            a.subkey_sig[pos] ^= 0x01;
            a
        })
        .collect();
    for alert in &variants {
        let _ = measure(
            || {
                let _ = alert.verify(&vk);
            },
            5,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for alert in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(alert.verify(std::hint::black_box(&vk)));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("duress-alert verify timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    assert!(
        rel < 0.30,
        "duress-alert verify relative stddev {rel:.4} exceeds 30% gate"
    );
}
