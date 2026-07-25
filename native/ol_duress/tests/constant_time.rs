//! Phase D timing-side-channel verification for `ol_duress`.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase C item #9 + Phase D #6:
//!
//! > Design target: a complete storage integration should avoid an
//! > observable real/decoy disk-pattern distinction.
//!
//! And the broader Phase C constant-time sweep gate.
//!
//! This microbenchmark compares `DuressGate::open()` wall-clock samples for:
//!
//! - Real-key path (returns `DuressOutcome::Real`).
//! - Duress-key path (returns `DuressOutcome::Duress { ... }`).
//! - Wrong-passphrase path (returns `Err(GateError::Rejected)`).
//!
//! `DuressGate::open` uses `subtle::ConstantTimeEq` for both check-
//! hash comparisons, and runs both derivations before selecting a branch.
//! This noisy timing gate can catch large regressions on the measured host;
//! it does not prove identical machine code, constant-time execution, disk-
//! pattern deniability, or resistance to a capable local observer.

use std::hint::black_box;
use std::time::Instant;

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_duress::DuressGate;

fn u128_as_f64(value: u128) -> f64 {
    let words = [
        u32::try_from(value >> 96).expect("the top u128 limb fits in u32"),
        u32::try_from((value >> 64) & u128::from(u32::MAX))
            .expect("the second u128 limb fits in u32"),
        u32::try_from((value >> 32) & u128::from(u32::MAX))
            .expect("the third u128 limb fits in u32"),
        u32::try_from(value & u128::from(u32::MAX)).expect("the low u128 limb fits in u32"),
    ];
    words.into_iter().fold(0.0_f64, |acc, word| {
        acc.mul_add(4_294_967_296.0, f64::from(word))
    })
}

fn measure(fn_to_call: impl Fn() + Send, iters: usize, bursts: usize) -> f64 {
    // Warm-up.
    for _ in 0..iters {
        fn_to_call();
    }
    let mut total_ns = 0u128;
    for _ in 0..bursts {
        let s = Instant::now();
        for _ in 0..iters {
            fn_to_call();
        }
        total_ns += s.elapsed().as_nanos();
    }
    let samples = iters
        .checked_mul(bursts)
        .expect("the timing sample count must fit in usize");
    let samples = u64::try_from(samples).expect("supported Rust pointer widths fit in u64");
    u128_as_f64(total_ns) / u128_as_f64(u128::from(samples))
}

#[test]
fn duress_open_timing_variance_under_120_percent_real_vs_duress() {
    let gate = DuressGate::new([0x42u8; 32], [0xAAu8; 32], [0x77u8; 32]);
    let real_pw = b"real-secret-passphrase";
    let duress_pw = b"duress-coercion-passphrase";

    // Precompute expected check hashes (this is what the daemon's
    // account-setup code persists once + reuses).
    let real_check = blake3::derive_key(
        "ol-duress-real-check-v1",
        &[&[0x42u8; 32][..], real_pw].concat(),
    );
    let duress_check = blake3::derive_key(
        "ol-duress-decoy-check-v1",
        &[&[0xAAu8; 32][..], duress_pw].concat(),
    );

    let iters = 5_000;
    let bursts = 10;

    let t_real = measure(
        || {
            let r = gate.open(
                black_box(real_pw),
                black_box(&real_check),
                black_box(&duress_check),
            );
            let _ = black_box(r);
        },
        iters,
        bursts,
    );
    let t_duress = measure(
        || {
            let r = gate.open(
                black_box(duress_pw),
                black_box(&real_check),
                black_box(&duress_check),
            );
            let _ = black_box(r);
        },
        iters,
        bursts,
    );
    let t_wrong = measure(
        || {
            let r = gate.open(
                black_box(b"completely-different-password"),
                black_box(&real_check),
                black_box(&duress_check),
            );
            let _ = black_box(r);
        },
        iters,
        bursts,
    );

    eprintln!("DuressGate::open timing:");
    eprintln!("  real_pw   = {t_real:.1} ns/call");
    eprintln!("  duress_pw = {t_duress:.1} ns/call");
    eprintln!("  wrong_pw  = {t_wrong:.1} ns/call");

    let max_t = t_real.max(t_duress).max(t_wrong);
    let min_t = t_real.min(t_duress).min(t_wrong);
    let ratio = max_t / min_t;
    eprintln!("  max/min ratio = {ratio:.4}");

    timing_gate!(
        ratio < 1.20,
        "DuressGate::open timing diverges {ratio:.3}× across (real, duress, wrong) — \
         possible side-channel leak"
    );
}
