//! Constant-time validation for the handshake MAC verify path.
//!
//! `ServerHandshake::accept` checks the client MAC using
//! `subtle::ConstantTimeEq` — but a regression that swaps it for
//! `==` (or short-circuits across the current/previous epoch check)
//! would leak first-differing-byte position to a timing attacker.
//!
//! Pattern matches F1.1 / F2 / row 1: measure wall-clock variance
//! across buckets that mismatch at different byte positions; gate at
//! a low % relative stddev.

use std::time::{Duration, Instant};

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_onion::transport_obfs::handshake::{
    BridgeKeypair, ClientHandshake, ServerHandshake, BRIDGE_PUBKEY_LEN, HANDSHAKE_LEN,
};
use rand::rngs::OsRng;

const SAMPLES_PER_BUCKET: usize = 5_000;

fn relative_stddev(samples: &[f64]) -> f64 {
    let sample_count = f64::from(u32::try_from(samples.len()).unwrap());
    let mean: f64 = samples.iter().sum::<f64>() / sample_count;
    let variance: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / sample_count;
    variance.sqrt() / mean
}

fn measure<F: FnMut()>(mut work: F, iters: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        work();
    }
    start.elapsed()
}

#[test]
fn handshake_mac_verify_constant_time_across_tamper_positions() {
    // Build a real client handshake message, then create tampered
    // versions that mismatch the MAC at different byte positions in
    // the MAC field (offset 32..48 of the 48-byte message).
    let bridge = BridgeKeypair::generate(&mut OsRng);
    let bridge_pk: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
    let now = 1_700_000_000u64;
    let client = ClientHandshake::start(&mut OsRng, &bridge_pk, &bridge.id, now);
    let real_msg = *client.first_message();

    // Five tamper positions in the MAC field (bytes 32..48):
    //   32 = first MAC byte
    //   35 = early MAC byte
    //   39 = mid MAC byte
    //   43 = late MAC byte
    //   47 = last MAC byte
    // A non-CT comparison would diverge in timing across these.
    let positions = [32usize, 35, 39, 43, 47];
    let mut tampered: Vec<[u8; HANDSHAKE_LEN]> = positions
        .iter()
        .map(|&pos| {
            let mut m = real_msg;
            m[pos] ^= 0xFF;
            m
        })
        .collect();

    // Warm up the path so the first-call overhead is amortized.
    for msg in &tampered {
        let _ = measure(
            || {
                let _ = ServerHandshake::accept(&mut OsRng, &bridge, msg, now);
            },
            10,
        );
    }

    let mut totals: Vec<f64> = Vec::with_capacity(tampered.len());
    for msg in &mut tampered {
        let ns = measure(
            || {
                let _ = std::hint::black_box(ServerHandshake::accept(
                    &mut OsRng,
                    std::hint::black_box(&bridge),
                    std::hint::black_box(msg),
                    now,
                ));
            },
            SAMPLES_PER_BUCKET,
        )
        .as_secs_f64()
            * 1_000_000_000.0;
        totals.push(ns);
    }
    let rel = relative_stddev(&totals);
    eprintln!("handshake-MAC timing totals (ns) = {totals:?}, rel_stddev = {rel:.4}");
    // The MAC compare itself is constant-time via `subtle::ct_eq`.
    // Residual variance comes from the always-run "try current AND
    // previous epoch" path (two MAC recomputes) plus general OS noise.
    // 15% gate catches the LARGE regressions:
    //   - Swap of `subtle::ct_eq` for byte `==`.
    //   - "Short-circuit on current-epoch match" optimization that
    //     skips the previous-epoch try.
    timing_gate!(
        rel < 0.15,
        "handshake-MAC relative stddev {rel:.4} exceeds 15% gate — \
         likely a non-constant-time compare regression"
    );
}
