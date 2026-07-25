//! Constant-time gate for the Layer 6 announcement verify path.

use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_device_mesh::self_routing::{sign_route_announcement, PeerLink, RouteAnnouncement};
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
fn route_announcement_verify_constant_time_across_tamper_positions() {
    let master = MasterIdentity::generate(&mut OsRng);
    let (sk, att) =
        mint_subkey(&master, DeviceClass::Phone, [0x55; DEVICE_ID_LEN], 0, 365).unwrap();
    let vk = HybridVerifyingKey::from_bytes(&att.subkey_vk_bytes).unwrap();
    let real = sign_route_announcement(
        &sk,
        1_700_000_000,
        vec![
            PeerLink {
                peer_device_id: [0x11; DEVICE_ID_LEN],
                tau_score: 100,
                last_seen_unix: 1,
                direct: true,
            },
            PeerLink {
                peer_device_id: [0x22; DEVICE_ID_LEN],
                tau_score: 50,
                last_seen_unix: 1,
                direct: true,
            },
            PeerLink {
                peer_device_id: [0x33; DEVICE_ID_LEN],
                tau_score: 25,
                last_seen_unix: 1,
                direct: true,
            },
        ],
    )
    .unwrap();
    let sig_len = real.announcer_sig.len();
    let positions = [0usize, 32, 63, 64, sig_len - 1];

    let mut variants: Vec<RouteAnnouncement> = positions
        .iter()
        .map(|&pos| {
            let mut a = real.clone();
            a.announcer_sig[pos] ^= 0x01;
            a
        })
        .collect();

    // Warm-up.
    for ann in &variants {
        let _ = measure(
            || {
                let _ = ann.verify(&vk);
            },
            5,
        );
    }
    let mut totals: Vec<f64> = Vec::with_capacity(variants.len());
    for ann in &mut variants {
        let ns = measure(
            || {
                let _ = std::hint::black_box(ann.verify(std::hint::black_box(&vk)));
            },
            SAMPLES_PER_BUCKET,
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel_stddev = relative_stddev(&totals);
    eprintln!("route-ann verify timing totals (ns) = {totals:?}, rel_stddev = {rel_stddev:.4}");
    timing_gate!(
        rel_stddev < 0.30,
        "route-ann verify relative stddev {rel_stddev:.4} exceeds 30% gate"
    );
}
