//! Shared, CI-safe gate for the native crates' wall-clock timing tests.
//!
//! The constant-time tests (DuressGate::open, `*::ct_eq`, Sphinx peel,
//! quorum / fan-out / liveness verify, ...) check side-channel
//! resistance by MEASURING wall-clock time and asserting the variance
//! across code paths stays under a ceiling. The actual *correctness*
//! guarantee comes from the code itself (`subtle::ConstantTimeEq` +
//! running both branches' work unconditionally); the wall-clock check
//! is a belt-and-suspenders sanity gate on top of that.
//!
//! Wall-clock variance is unreliable on shared / turbo-boosting CI
//! runners: scheduler preemption + CPU frequency scaling produce false
//! FAILURES (observed across the ubuntu/macos matrix), and the same
//! noise can also mask a genuine leak — so it is not a sound *hard* CI
//! gate.
//!
//! `timing_gate!` mirrors `assert!` (same `(cond, fmt, args...)`
//! syntax) but, when the condition fails, only PANICS under
//! `OL_TIMING_GATES=1` (a dedicated quiet / pinned timing job, or a
//! developer running locally). By default — including the per-PR CI
//! matrix — it prints a WARNING and continues. The measurement +
//! diagnostics still run every time, so nothing is skipped and
//! coverage is intact.
//!
//! Included into each test crate via
//! `#[path = "../../test_support/timing_gate.rs"] mod timing_gate;`
//! (every gate test lives at `native/<crate>/tests/<file>.rs`, so the
//! relative path is uniform).

/// `assert!`-shaped wall-clock timing gate. Hard-fails only under
/// `OL_TIMING_GATES=1`; otherwise warns and continues. See the module
/// docs for why wall-clock asserts are not a sound hard CI gate.
#[macro_export]
macro_rules! timing_gate {
    ($cond:expr, $($arg:tt)+) => {{
        // Bind to a bool first: a direct `!($cond)` would trip
        // clippy::neg_cmp_op_on_partial_ord when `$cond` is a float
        // comparison (e.g. `rel < 0.30`).
        let passed: bool = $cond;
        if !passed {
            let detail = format!($($arg)+);
            if ::std::env::var_os("OL_TIMING_GATES").is_some() {
                panic!("{}", detail);
            }
            eprintln!(
                "WARNING (timing gate, non-strict): {}\n  \
                 (set OL_TIMING_GATES=1 to enforce this as a hard failure)",
                detail
            );
        }
    }};
}
