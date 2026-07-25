//! Constant-time gate for the Layer 4 storage-attestation verify
//! path. 30 % rel-stddev gate matches the other ct gates in the
//! crate (all delegate to `ol_pqsig` verify).

use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_device_mesh::distributed_fs::{sign_storage_attestation, StorageAttestation};
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};
use ol_pqsig::HybridVerifyingKey;
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 200;

fn relative_stddev(samples: &[f64]) -> f64 {
    let sample_count =
        f64::from(u32::try_from(samples.len()).expect("the timing gate has five buckets"));
    let mean: f64 = samples.iter().sum::<f64>() / sample_count;
    let var: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / sample_count;
    var.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iters: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        work();
    }
    start.elapsed()
}

#[test]
fn storage_attest_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, att_layer1) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att_layer1.subkey_vk_bytes).unwrap();
    let real =
        sign_storage_attestation(&sk, 1_700_000_000, vec![[0x01; 32], [0x02; 32], [0x03; 32]])
            .unwrap();
    let sig_len = real.subkey_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<StorageAttestation> = positions
        .iter()
        .map(|&pos| {
            let mut a = real.clone();
            a.subkey_sig[pos] ^= 0x01;
            a
        })
        .collect();

    // Warm-up.
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
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel_stddev = relative_stddev(&totals);
    eprintln!(
        "storage-attest verify timing totals (ns) = {totals:?}, rel_stddev = {rel_stddev:.4}"
    );
    timing_gate!(
        rel_stddev < 0.30,
        "storage-attest verify relative stddev {rel_stddev:.4} exceeds 30% gate"
    );
}
