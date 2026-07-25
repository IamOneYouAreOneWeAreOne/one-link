//! Constant-time gate for the Layer 8 task-request verify path.

use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_device_mesh::compute::{sign_task_request, TaskClass, TaskRequest};
use ol_device_mesh::distributed_fs::FILE_ID_LEN;
use ol_device_mesh::{mint_subkey, DeviceClass, MasterIdentity, DEVICE_ID_LEN};
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
fn task_request_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, _) = mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let real = sign_task_request(
        &sk,
        TaskClass::new(b"transcribe-audio").unwrap(),
        [0xCC; FILE_ID_LEN],
        vec![ol_device_mesh::compute::DeviceCapability::Microphone],
        300,
        10_000,
        1,
        10_000,
        [0xDA; 16],
    )
    .unwrap();
    let vk = sk.verifying_key();
    let sig_len = real.requester_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<TaskRequest> = positions
        .iter()
        .map(|&pos| {
            let mut r = real.clone();
            r.requester_sig[pos] ^= 0x01;
            r
        })
        .collect();
    for req in &variants {
        let _ = measure(
            || {
                let _ = req.verify(&vk);
            },
            5,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for req in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(req.verify(std::hint::black_box(&vk)));
            },
            SAMPLES_PER_BUCKET,
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel_stddev = relative_stddev(&totals);
    eprintln!("task-req verify timing totals (ns) = {totals:?}, rel_stddev = {rel_stddev:.4}");
    timing_gate!(
        rel_stddev < 0.30,
        "task-req verify relative stddev {rel_stddev:.4} exceeds 30% gate"
    );
}
