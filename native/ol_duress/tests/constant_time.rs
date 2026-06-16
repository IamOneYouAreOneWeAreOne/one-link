//! Phase D timing-side-channel verification for `ol_duress`.
//!
//! Per `FILE_ENGINE_V2_PLAN.md` Phase C item #9 + Phase D #6:
//!
//! > Plausibly deniable storage: duress key unlocks decoy with no
//! > observable disk-pattern difference from real-key unlock.
//!
//! And the broader Phase C constant-time sweep gate.
//!
//! The threat model: an attacker watching the operator type a
//! passphrase + measuring `DuressGate::open()` wall-clock time
//! must NOT be able to distinguish:
//!
//! - Real-key path (returns `DuressOutcome::Real`).
//! - Duress-key path (returns `DuressOutcome::Duress { ... }`).
//! - Wrong-passphrase path (returns `Err(GateError::Rejected)`).
//!
//! `DuressGate::open` uses `subtle::ConstantTimeEq` for both check-
//! hash comparisons, and runs BOTH derivations regardless of which
//! branch the result follows. The work each path does is identical
//! at the CPU instruction level; this test confirms wall-clock
//! variance stays below the plan's 1.20× ceiling (looser than the
//! <1% mean variance the underlying primitive guarantees — the
//! looser bound covers OS-scheduling noise).

use std::hint::black_box;
use std::time::Instant;

#[path = "../../test_support/timing_gate.rs"]
mod timing_gate;

use ol_duress::DuressGate;

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
    total_ns as f64 / (iters * bursts) as f64
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
    eprintln!("  real_pw   = {:.1} ns/call", t_real);
    eprintln!("  duress_pw = {:.1} ns/call", t_duress);
    eprintln!("  wrong_pw  = {:.1} ns/call", t_wrong);

    let max_t = t_real.max(t_duress).max(t_wrong);
    let min_t = t_real.min(t_duress).min(t_wrong);
    let ratio = max_t / min_t;
    eprintln!("  max/min ratio = {:.4}", ratio);

    timing_gate!(
        ratio < 1.20,
        "DuressGate::open timing diverges {ratio:.3}× across (real, duress, wrong) — \
         possible side-channel leak"
    );
}
