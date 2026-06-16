//! Constant-time gate for the Layer 7 onion-attestation verify path.

use std::time::Instant;

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_device_mesh::self_onion::{derive_onion_identity, sign_onion_attestation, OnionAttestation};
use ol_device_mesh::{MasterIdentity, DEVICE_ID_LEN};
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
fn onion_attestation_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55; DEVICE_ID_LEN];
    let identity = derive_onion_identity(&master, &id);
    let real = sign_onion_attestation(&master, id, identity.public_bytes(), 0, 365).unwrap();
    let vk = master.verifying_key();
    let sig_len = real.master_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<OnionAttestation> = positions
        .iter()
        .map(|&pos| {
            let mut a = real.clone();
            a.master_sig[pos] ^= 0x01;
            a
        })
        .collect();
    for att in &variants {
        let _ = measure(
            || {
                let _ = att.verify(&vk);
            },
            5,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for att in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(att.verify(std::hint::black_box(&vk)));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("onion-attestation verify timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    timing_gate!(
        rel < 0.30,
        "onion-attestation verify relative stddev {rel:.4} exceeds 30% gate"
    );
}
