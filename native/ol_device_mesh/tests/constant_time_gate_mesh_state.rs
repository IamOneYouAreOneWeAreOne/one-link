//! Constant-time gate for the Layer 3 auth-op verify path.
//!
//! Same pattern as the Layer 1 / Layer 2 gates: measure variance
//! across signature-byte tamper positions and assert 30 % relative
//! stddev. Catches accidental short-circuits in the verify path.

use std::time::Instant;

use ol_device_mesh::mesh_state::{AuthenticatedOp, Delta};
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::HybridVerifyingKey;
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 200;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let var: f64 =
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
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
fn auth_op_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55u8; DEVICE_ID_LEN];
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    let real = AuthenticatedOp::sign(
        &sk,
        b"contacts".to_vec(),
        Delta::OrAdd { element: b"alice".to_vec(), tag: [0x77; 16] },
        1,
        1_700_000_000,
    )
    .unwrap();
    let sig_len = real.subkey_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<AuthenticatedOp> = positions
        .iter()
        .map(|&pos| {
            let mut c = real.clone();
            c.subkey_sig[pos] ^= 0x01;
            c
        })
        .collect();

    // Warm-up.
    for op in &variants {
        let _ = measure(
            || {
                let _ = op.verify(&vk);
            },
            5,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for op in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(op.verify(std::hint::black_box(&vk)));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!(
        "auth-op verify timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}"
    );
    assert!(
        rel < 0.30,
        "auth-op verify relative stddev {rel:.4} exceeds 30% gate"
    );
}
