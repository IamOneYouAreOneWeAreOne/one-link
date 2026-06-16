//! Constant-time validation for the liveness-proof verify path.
//!
//! `verify_liveness` does:
//!   1. signature verify under the witness subkey VK (ol_pqsig, uniform
//!      across tamper position — see row 1's own ct gate)
//!   2. clock-skew check (after the signature so the timing branch
//!      never reaches a forged proof)
//!
//! This gate measures total wall-clock variance across 5 tamper
//! positions in the subkey signature. Gate at 30% relative stddev —
//! the residual baseline comes from ML-DSA-internal data-dependent
//! verify variance (a property of the upstream `ml-dsa` crate, not
//! our layer). If upstream tightens to strict CT verify later, this
//! gate tightens too.

use std::time::Instant;

use ol_device_mesh::{
    mint_subkey, sibling_witness, state_root, verify_liveness, DeviceClass, LivenessProof,
    MasterIdentity, DEFAULT_LIVENESS_SKEW_SECS,
};
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 200;

fn relative_stddev(samples: &[f64]) -> f64 {
    let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance: f64 =
        samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / samples.len() as f64;
    variance.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iters: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..iters {
        work();
    }
    start.elapsed().as_nanos()
}

#[test]
fn liveness_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let id = [0x55u8; 16];
    let (sk, _att) = mint_subkey(&master, DeviceClass::Phone, id, 0, 365).unwrap();
    let witness = sibling_witness(sk.verifying_key(), DEFAULT_LIVENESS_SKEW_SECS);
    let now = 1_700_000_000u64;
    let real = LivenessProof::issue(&sk, now, state_root(b"state")).unwrap();
    let sig_len = real.subkey_sig.len();

    // Tamper positions across the signature: early Ed25519, mid
    // Ed25519, last Ed25519, early ML-DSA, last ML-DSA.
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut tampered: Vec<LivenessProof> = positions
        .iter()
        .map(|&pos| {
            let mut p = real.clone();
            p.subkey_sig[pos] ^= 0x01;
            p
        })
        .collect();

    // Warm-up.
    for proof in &tampered {
        let _ = measure(
            || {
                let _ = verify_liveness(proof, &witness, now);
            },
            5,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(tampered.len());
    for proof in &mut tampered {
        let ns = measure(
            || {
                let _ = std::hint::black_box(verify_liveness(
                    std::hint::black_box(proof),
                    std::hint::black_box(&witness),
                    now,
                ));
            },
            SAMPLES_PER_BUCKET,
        ) as f64;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("liveness-verify timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    // 30% gate matches row 1's pqsig::verify ct-gate (this verify
    // delegates to it).
    assert!(
        rel < 0.30,
        "liveness verify relative stddev {rel:.4} exceeds 30% gate — \
         likely a short-circuit regression in verify_liveness"
    );
}
