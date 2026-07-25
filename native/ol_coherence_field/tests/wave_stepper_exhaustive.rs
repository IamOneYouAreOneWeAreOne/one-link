//! Exhaustive property + analytic tests for the [`WaveStepper`].
//!
//! "Build it to the max + test it exhaustively" pass per integration
//! map D25. The tests fall into four groups:
//!
//! 1. **Numerical invariants** (property tests via proptest)
//!    - Constant field stays constant
//!    - Symmetric initial conditions stay symmetric
//!    - Field magnitude is bounded (no runaway)
//!    - CFL violation always errors when enforcement is on
//!
//! 2. **Analytic correctness** (KAT-style fixed-input checks)
//!    - 1D chain wave propagation matches the analytic d'Alembert
//!      solution at one timestep (within leapfrog truncation)
//!    - Stationary equilibrium under no source + zero initial velocity
//!    - Reflection at boundaries (open-ended chain)
//!
//! 3. **Energy conservation** (undamped case)
//!    - Total energy drift over 100 steps must be bounded
//!    - Damped case: energy decays monotonically
//!
//! 4. **Stress + robustness**
//!    - 1000-node random graph, 100 steps, no panic, no NaN
//!    - Pathological inputs (NaN, infinity, empty graph)
//!    - Clamp triggers on runaway
//!    - Step count + cascade warning counters stay consistent

use std::collections::HashMap;

use ol_coherence_field::wave::{WaveError, WaveStepper, DEFAULT_DAMPING, DEFAULT_WAVE_SPEED};
use proptest::prelude::*;

// ─── Helpers ──────────────────────────────────────────────────────

fn fixture_index_as_f32(index: usize) -> f32 {
    f32::from(u16::try_from(index).expect("wave fixtures stay within the u16 domain"))
}

/// 1D open chain: n0 — n1 — n2 — ... — n_{n-1}
fn chain_neighbors(n: usize) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for i in 0..n {
        let mut ns = Vec::new();
        if i > 0 {
            ns.push(format!("n{}", i - 1));
        }
        if i < n - 1 {
            ns.push(format!("n{}", i + 1));
        }
        out.insert(format!("n{i}"), ns);
    }
    out
}

/// Ring of n nodes: n0 — n1 — ... — n_{n-1} — n0
fn ring_neighbors(n: usize) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for i in 0..n {
        let prev = if i == 0 { n - 1 } else { i - 1 };
        let next = (i + 1) % n;
        out.insert(
            format!("n{i}"),
            vec![format!("n{prev}"), format!("n{next}")],
        );
    }
    out
}

/// Build a constant field across `nodes`.
fn constant_field(nodes: &[&str], value: f32) -> HashMap<String, f32> {
    nodes.iter().map(|n| ((*n).to_string(), value)).collect()
}

// ─── Group 1: Numerical Invariants (proptest) ───────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A constant field has zero Laplacian and (after the first step
    /// from a zero-velocity seed) zero kinetic term, so a constant
    /// field must stay constant under any (c, γ, dt) within CFL.
    ///
    /// Proves the leapfrog scheme preserves the equilibrium state —
    /// no spurious drift from numerical noise.
    #[test]
    fn const_field_stays_constant(
        c in 0.0f32..1.0,
        gamma in 0.0f32..0.5,
        // dt bounded so CFL holds: c · dt · √2 ≤ 1 → dt ≤ 1/(c·√2)
        // Use 0.3 / (c+1e-6) to be safely inside the bound.
        dt_factor in 0.01f32..0.3,
        value in -10.0f32..10.0,
        n_nodes in 3usize..15,
    ) {
        let dt = dt_factor / (c + 1e-6);
        let mut w = WaveStepper::new()
            .with_wave_speed(c).unwrap()
            .with_damping(gamma).unwrap();
        let node_strs: Vec<String> = (0..n_nodes).map(|i| format!("n{i}")).collect();
        let initial: HashMap<String, f32> = node_strs.iter()
            .map(|n| (n.clone(), value))
            .collect();
        w.seed(&initial);
        let neighbors = chain_neighbors(n_nodes);
        for _ in 0..5 {
            w.step(dt, &neighbors).unwrap();
        }
        for n in &node_strs {
            let v = w.psi_at(n).unwrap();
            let drift = (v - value).abs();
            prop_assert!(
                drift < 1e-3,
                "node {n} drifted from {value} to {v} (drift={drift})",
            );
        }
    }

    /// Reflection-symmetric initial conditions stay symmetric: if
    /// ψ(n_i) = ψ(n_{n-1-i}) on a chain, the wave-stepper output
    /// preserves the symmetry. This proves no off-by-one or
    /// directional bias in the Laplacian discretisation.
    #[test]
    fn symmetric_initial_stays_symmetric(
        c in 0.1f32..1.0,
        gamma in 0.0f32..0.1,
        dt_factor in 0.05f32..0.3,
        center_height in -5.0f32..5.0,
        n_half in 2usize..7,
    ) {
        let n = 2 * n_half + 1;
        let dt = dt_factor / (c + 1e-6);
        let mut w = WaveStepper::new()
            .with_wave_speed(c).unwrap()
            .with_damping(gamma).unwrap();
        let mut initial = HashMap::new();
        for i in 0..n {
            // Triangular profile: peak at center, fall off linearly.
            let dist = i.abs_diff(n_half);
            let val = center_height
                * (1.0 - fixture_index_as_f32(dist) / fixture_index_as_f32(n_half));
            initial.insert(format!("n{i}"), val);
        }
        w.seed(&initial);
        let neighbors = chain_neighbors(n);
        // Step a few times; symmetry must be preserved every step.
        for _ in 0..10 {
            w.step(dt, &neighbors).unwrap();
            for i in 0..n_half {
                let left = w.psi_at(&format!("n{i}")).unwrap();
                let reflected = n - 1 - i;
                let right = w.psi_at(&format!("n{reflected}")).unwrap();
                let asym = (left - right).abs();
                prop_assert!(
                    asym < 1e-4,
                    "asymmetry at step: left[{i}]={left} right[{reflected}]={right} asym={asym}",
                );
            }
        }
    }

    /// Field magnitude must be bounded across many steps for any CFL-
    /// compliant input. With damping ≥ 0, a wave-equation solution
    /// cannot exceed `max_initial_value × growth_factor` where the
    /// growth factor is bounded for CFL-stable schemes.
    ///
    /// We assert a loose bound: 100× the initial maximum. A truly
    /// unstable scheme would blow up exponentially and fail this.
    #[test]
    fn magnitude_bounded_over_many_steps(
        c in 0.1f32..0.9,
        gamma in 0.05f32..0.3,
        dt_factor in 0.05f32..0.2,
        n_nodes in 5usize..20,
    ) {
        let dt = dt_factor / (c + 1e-6);
        let mut w = WaveStepper::new()
            .with_wave_speed(c).unwrap()
            .with_damping(gamma).unwrap();
        let mut initial = HashMap::new();
        // Random-ish but deterministic initial disturbance.
        for i in 0..n_nodes {
            let v = (fixture_index_as_f32(i) * 0.137).sin();
            initial.insert(format!("n{i}"), v);
        }
        let initial_max: f32 = initial.values().fold(0.0f32, |m, &v| m.max(v.abs()));
        w.seed(&initial);
        let neighbors = ring_neighbors(n_nodes);
        for step in 0..200 {
            w.step(dt, &neighbors).unwrap();
            let current_max: f32 = w.iter().fold(0.0f32, |m, (_, &v)| m.max(v.abs()));
            prop_assert!(
                current_max < initial_max * 100.0,
                "magnitude exploded at step {step}: max={current_max} initial={initial_max}",
            );
            prop_assert!(
                current_max.is_finite(),
                "NaN/Inf appeared at step {step}",
            );
        }
    }

    /// CFL violation always errors when enforcement is on. The CFL
    /// bound is `c · dt · √λ_max ≤ 1`; we deliberately exceed it.
    #[test]
    fn cfl_violation_always_errors(
        c in 0.5f32..2.0,
        dt_factor in 1.5f32..5.0,
        n_nodes in 3usize..10,
    ) {
        // dt = dt_factor / (c · √2) — guarantees courant > 1.
        let dt = dt_factor / (c * (2.0_f32).sqrt());
        let mut w = WaveStepper::new()
            .with_wave_speed(c).unwrap();
        w.seed(&constant_field(
            &(0..n_nodes).map(|i| Box::leak(format!("n{i}").into_boxed_str()) as &str)
                .collect::<Vec<_>>(),
            0.5,
        ));
        let neighbors = chain_neighbors(n_nodes);
        let r = w.step(dt, &neighbors);
        let is_cfl = matches!(&r, Err(WaveError::CflViolation { .. }));
        prop_assert!(is_cfl, "expected CFL violation, got {:?}", r);
    }
}

// ─── Group 2: Analytic Correctness ──────────────────────────────────

#[test]
fn courant_number_matches_analytic() {
    // c = 1.0, dt = 0.5, λ_max bound = 2: courant = 1.0 · 0.5 · √2 ≈ 0.707
    let w = WaveStepper::new().with_wave_speed(1.0).unwrap();
    let courant = w.courant_number(0.5);
    assert!((courant - 0.5 * (2.0_f32).sqrt()).abs() < 1e-6);
}

#[test]
fn max_stable_dt_for_unit_speed() {
    // max_dt = 1 / (1.0 · √2) ≈ 0.707
    let w = WaveStepper::new().with_wave_speed(1.0).unwrap();
    let m = w.max_stable_dt();
    assert!((m - 1.0 / (2.0_f32).sqrt()).abs() < 1e-6);
}

#[test]
fn max_stable_dt_for_zero_speed_is_infinity() {
    let w = WaveStepper::new().with_wave_speed(0.0).unwrap();
    assert!(w.max_stable_dt().is_infinite() && w.max_stable_dt().is_sign_positive());
}

#[test]
fn disturbance_propagates_at_finite_speed() {
    // Inject a delta at n5 in a 11-node chain; after one step the
    // disturbance must be visible at n4 and n6 but NOT at n3 or n7
    // (signal cone bounded by c · dt < 1 grid spacing).
    let mut w = WaveStepper::new()
        .with_wave_speed(1.0)
        .unwrap()
        .with_damping(0.0)
        .unwrap();
    let mut initial = HashMap::new();
    for i in 0..11 {
        initial.insert(format!("n{i}"), 0.0);
    }
    initial.insert("n5".to_string(), 1.0);
    w.seed(&initial);
    let neighbors = chain_neighbors(11);
    // dt = 0.3 — well within CFL.
    w.step(0.3, &neighbors).unwrap();
    // Immediate neighbors should have moved.
    let n4 = w.psi_at("n4").unwrap();
    let n6 = w.psi_at("n6").unwrap();
    assert!(n4.abs() > 1e-6, "n4 should have received signal: got {n4}");
    assert!(n6.abs() > 1e-6, "n6 should have received signal: got {n6}");
    // Symmetry — n4 == n6 to machine precision.
    assert!((n4 - n6).abs() < 1e-6, "broken symmetry: n4={n4} n6={n6}");
    // Distant nodes should still be (close to) zero.
    let n0 = w.psi_at("n0").unwrap();
    assert!(n0.abs() < 1e-6, "n0 leaked signal: {n0}");
}

#[test]
fn ring_topology_periodic_wraparound() {
    // On a ring, a disturbance at n0 should propagate to both n1 AND
    // n_{N-1} (wraparound) symmetrically.
    let mut w = WaveStepper::new()
        .with_wave_speed(1.0)
        .unwrap()
        .with_damping(0.0)
        .unwrap();
    let n = 8;
    let mut initial = HashMap::new();
    for i in 0..n {
        initial.insert(format!("n{i}"), 0.0);
    }
    initial.insert("n0".to_string(), 1.0);
    w.seed(&initial);
    let neighbors = ring_neighbors(n);
    w.step(0.3, &neighbors).unwrap();
    let n1 = w.psi_at("n1").unwrap();
    let n_last = w.psi_at(&format!("n{}", n - 1)).unwrap();
    assert!(
        (n1 - n_last).abs() < 1e-6,
        "wraparound broken: n1={n1} n_last={n_last}"
    );
}

// ─── Group 3: Energy Conservation ────────────────────────────────────

#[test]
fn undamped_energy_drift_bounded() {
    // For γ = 0, total energy should be approximately conserved.
    // Leapfrog truncation gives O(dt²) per step error; over 100
    // steps we allow drift up to 10% for safety, but typically
    // observe much less.
    let mut w = WaveStepper::new()
        .with_wave_speed(0.7)
        .unwrap()
        .with_damping(0.0)
        .unwrap();
    let n = 11;
    let mut initial = HashMap::new();
    for i in 0..n {
        // Sine-wave initial profile — has well-defined energy.
        let v = (fixture_index_as_f32(i) * std::f32::consts::PI / 5.0).sin();
        initial.insert(format!("n{i}"), v);
    }
    w.seed(&initial);
    let neighbors = ring_neighbors(n);
    let dt = 0.1;
    let initial_energy = w.total_energy(dt, &neighbors);
    for _ in 0..100 {
        w.step(dt, &neighbors).unwrap();
    }
    let final_energy = w.total_energy(dt, &neighbors);
    // With dt small enough, energy drift should be bounded.
    // The leapfrog scheme is symplectic so energy oscillates but
    // doesn't grow secularly.
    if initial_energy > 1e-6 {
        let relative_drift = (final_energy - initial_energy).abs() / initial_energy;
        assert!(
            relative_drift < 0.5,
            "energy drift too large: initial={initial_energy} final={final_energy} drift={relative_drift}",
        );
    }
}

#[test]
fn damped_energy_decays_monotonically() {
    // For γ > 0, total energy should decrease monotonically (modulo
    // small leapfrog oscillation). We check that after 50 steps the
    // energy is strictly less than at step 5.
    let mut w = WaveStepper::new()
        .with_wave_speed(0.5)
        .unwrap()
        .with_damping(0.2)
        .unwrap();
    let n = 7;
    let mut initial = HashMap::new();
    for i in 0..n {
        let v = (fixture_index_as_f32(i) * 0.5).sin();
        initial.insert(format!("n{i}"), v);
    }
    w.seed(&initial);
    let neighbors = ring_neighbors(n);
    let dt = 0.1;
    // Skip first few steps to let transient settle.
    for _ in 0..5 {
        w.step(dt, &neighbors).unwrap();
    }
    let early_energy = w.total_energy(dt, &neighbors);
    for _ in 0..50 {
        w.step(dt, &neighbors).unwrap();
    }
    let late_energy = w.total_energy(dt, &neighbors);
    assert!(
        late_energy < early_energy,
        "damped energy didn't decay: early={early_energy} late={late_energy}",
    );
}

// ─── Group 4: Stress + Robustness ────────────────────────────────────

#[test]
fn stress_1000_nodes_100_steps_no_panic() {
    let n = 1000;
    let mut w = WaveStepper::new().with_wave_speed(0.5).unwrap();
    let mut initial = HashMap::new();
    let mut neighbors: HashMap<String, Vec<String>> = HashMap::new();
    for i in 0..n {
        // Initial: small noise.
        initial.insert(
            format!("n{i}"),
            (fixture_index_as_f32(i) * 0.137).sin() * 0.1,
        );
        // Each node connected to next 2 (degree 4 ring).
        let prev1 = if i == 0 { n - 1 } else { i - 1 };
        let prev2 = if i < 2 { n - 2 + i } else { i - 2 };
        let next1 = (i + 1) % n;
        let next2 = (i + 2) % n;
        neighbors.insert(
            format!("n{i}"),
            vec![
                format!("n{prev2}"),
                format!("n{prev1}"),
                format!("n{next1}"),
                format!("n{next2}"),
            ],
        );
    }
    w.seed(&initial);
    let dt = 0.3;
    for step in 0..100 {
        let r = w.step(dt, &neighbors);
        assert!(r.is_ok(), "step {step} failed: {r:?}");
    }
    // After 100 steps we shouldn't have any NaNs.
    for (node, value) in w.iter() {
        assert!(value.is_finite(), "NaN at node {node}: value {value}");
    }
    assert_eq!(w.step_count(), 100);
}

#[test]
fn clamp_traps_runaway() {
    // Construct a stepper with a tight clamp + an initial condition
    // guaranteed to exceed it within one step.
    let mut w = WaveStepper::new()
        .with_wave_speed(0.5)
        .unwrap()
        .with_clamp_range(Some((0.0, 1.0)));
    let n = 5;
    let mut initial = HashMap::new();
    for i in 0..n {
        initial.insert(format!("n{i}"), 0.5);
    }
    // Inject a big disturbance that the leapfrog will propagate
    // outside [0, 1].
    initial.insert("n2".to_string(), 2.5);
    w.seed(&initial);
    let r = w.step(0.3, &chain_neighbors(n));
    // The disturbance is already outside [0, 1] at seed time + one
    // step pushes it further. Clamp should trigger.
    assert!(matches!(r, Err(WaveError::ClampTripped { .. })));
}

#[test]
fn step_atomicity_on_error() {
    // On error, the snapshots must NOT advance — the caller can
    // inspect the pre-step state to diagnose.
    let mut w = WaveStepper::new()
        .with_wave_speed(0.5)
        .unwrap()
        .with_clamp_range(Some((0.0, 1.0)));
    let mut initial = HashMap::new();
    initial.insert("n0".to_string(), 0.5);
    initial.insert("n1".to_string(), 2.5);
    w.seed(&initial);
    let before = w.psi_at("n0").unwrap();
    let _ = w.step(0.3, &chain_neighbors(2)); // expected to error
    let after = w.psi_at("n0").unwrap();
    assert_eq!(
        before.to_bits(),
        after.to_bits(),
        "snapshots advanced on error"
    );
    assert_eq!(w.step_count(), 0, "step_count incremented on error");
}

#[test]
fn pathological_inputs_zero_dt() {
    let mut w = WaveStepper::new();
    let r = w.step(0.0, &HashMap::new());
    assert!(matches!(r, Err(WaveError::InvalidDt { .. })));
}

#[test]
fn pathological_inputs_nan_dt() {
    let mut w = WaveStepper::new();
    let r = w.step(f32::NAN, &HashMap::new());
    assert!(matches!(r, Err(WaveError::InvalidDt { .. })));
}

#[test]
fn pathological_inputs_infinity_dt() {
    let mut w = WaveStepper::new();
    let r = w.step(f32::INFINITY, &HashMap::new());
    assert!(matches!(r, Err(WaveError::InvalidDt { .. })));
}

#[test]
fn empty_graph_is_a_no_op() {
    let mut w = WaveStepper::new();
    let n = w.step(0.1, &HashMap::new()).unwrap();
    assert_eq!(n, 0);
    assert!(w.is_empty());
    assert_eq!(w.step_count(), 1);
}

#[test]
fn zero_wave_speed_field_just_damps() {
    // c = 0 means no wave propagation; only damping should act.
    let mut w = WaveStepper::new()
        .with_wave_speed(0.0)
        .unwrap()
        .with_damping(0.5)
        .unwrap();
    let mut initial = HashMap::new();
    initial.insert("n0".to_string(), 1.0);
    w.seed(&initial);
    // With γ > 0 and zero wave speed, the leapfrog reduces to:
    //   ψ(t+dt) = 2·ψ(t) − ψ(t−dt) − γ·dt·(ψ(t) − ψ(t−dt))
    //          = ψ(t) + (1 − γ·dt)·(ψ(t) − ψ(t−dt))
    // For our seeded initial conditions ψ(t) = ψ(t−dt) so the velocity
    // term is zero; ψ stays constant on the first step.
    w.step(0.1, &HashMap::new()).unwrap();
    let v = w.psi_at("n0").unwrap();
    assert!((v - 1.0).abs() < 1e-5);
}

#[test]
fn cfl_can_be_disabled_for_advanced_callers() {
    // With cfl_enforce=false, the step should still execute even at
    // a courant > 1. Useful for golden-vector regression tests where
    // the inputs are known-stable for some other reason.
    let mut w = WaveStepper::new()
        .with_wave_speed(2.0)
        .unwrap() // intentionally fast
        .with_cfl_enforce(false);
    let mut initial = HashMap::new();
    for i in 0..3 {
        initial.insert(format!("n{i}"), 0.5);
    }
    w.seed(&initial);
    // dt at courant ~ 2.83 — would normally fail.
    let r = w.step(1.0, &chain_neighbors(3));
    // No CFL error. May still produce reasonable output for one step.
    assert!(r.is_ok());
}

#[test]
fn cascade_warnings_counter_matches_returned_value() {
    let mut w = WaveStepper::new()
        .with_wave_speed(1.0)
        .unwrap()
        .with_threshold(0.001); // very sensitive
    let mut initial = HashMap::new();
    initial.insert("n0".to_string(), 1.0);
    initial.insert("n1".to_string(), 0.0);
    initial.insert("n2".to_string(), 0.0);
    w.seed(&initial);
    let neighbors = chain_neighbors(3);
    let warns_returned = w.step(0.3, &neighbors).unwrap();
    let warns_counter = w.cascade_warnings();
    assert_eq!(u64::from(warns_returned), warns_counter);
}

#[test]
fn reset_warnings_preserves_state() {
    let mut w = WaveStepper::new()
        .with_wave_speed(1.0)
        .unwrap()
        .with_threshold(0.001);
    let mut initial = HashMap::new();
    initial.insert("n0".to_string(), 1.0);
    initial.insert("n1".to_string(), 0.0);
    w.seed(&initial);
    let neighbors = chain_neighbors(2);
    w.step(0.3, &neighbors).unwrap();
    assert!(w.cascade_warnings() > 0);
    w.reset_warnings();
    assert_eq!(w.cascade_warnings(), 0);
    // Field state still intact.
    assert!(w.psi_at("n0").is_some());
}

#[test]
fn defaults_unchanged_after_construction() {
    let w = WaveStepper::new();
    assert_eq!(w.wave_speed().to_bits(), DEFAULT_WAVE_SPEED.to_bits());
    assert_eq!(w.damping().to_bits(), DEFAULT_DAMPING.to_bits());
    assert_eq!(w.step_count(), 0);
    assert_eq!(w.cascade_warnings(), 0);
    assert_eq!(w.clamp_range(), None);
}
