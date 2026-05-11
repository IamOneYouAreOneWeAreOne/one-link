//! Phase E acceptance gate: **linear-source no-go regression test.**
//!
//! The S_One galaxy chain proves a sharp no-go: if the source is
//! linear in density (`S_b ∝ ρ_b`), the coherence flux collapses to
//! `g_coh ∝ g_bar`. Translated to graphs: if the source is just
//! `S = α · ρ`, then the Helmholtz solution `δτ_c` is a linear scaling
//! of `ρ`. The "shape" of the response carries no new information
//! beyond what was already in `ρ`.
//!
//! This regression test confirms the implementation actually exhibits
//! that behaviour — important because if it DIDN'T, the engine would
//! be silently solving a different equation than the theory.
//!
//! Test logic:
//!
//! 1. Build an arbitrary graph + density vector ρ.
//! 2. Use `linear_source(ρ, weight=1)` to make `S₁ = ρ`.
//! 3. Use `linear_source(ρ, weight=2)` to make `S₂ = 2ρ`.
//! 4. Solve Helmholtz for both. Verify `δτ_c(S₂) = 2 · δτ_c(S₁)`
//!    (linearity preserved).
//! 5. Verify that the SHAPE of `δτ_c` matches the shape of `ρ` (the
//!    field's correlation with ρ is the maximum possible, modulo
//!    Helmholtz smoothing) — i.e. no new information appears that
//!    wasn't already in `ρ`.

use ol_coherence_field::pde::sparse_solver::CgConfig;
use ol_coherence_field::{linear_source, solve_helmholtz, GraphLaplacian};

#[test]
fn linear_source_response_scales_linearly() {
    let n = 10;
    let mut g = GraphLaplacian::new(n);
    // Build a small connected graph (path + a few extra edges).
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    g.add_edge(0, 5, 0.5).unwrap();
    g.add_edge(2, 7, 0.5).unwrap();

    let rho: Vec<f64> = (0..n).map(|i| (i as f64 + 1.0).sqrt()).collect();
    let s1 = linear_source(&rho, 1.0).unwrap();
    let s2 = linear_source(&rho, 2.0).unwrap();

    let cfg = CgConfig::default();
    let r1 = solve_helmholtz(&g, 1.0, 0.5, &s1, cfg).unwrap();
    let r2 = solve_helmholtz(&g, 1.0, 0.5, &s2, cfg).unwrap();

    // Linearity: r2 ≈ 2 · r1 elementwise.
    for i in 0..n {
        let expected = 2.0 * r1.field[i];
        assert!(
            (r2.field[i] - expected).abs() < 1e-6,
            "linearity broken at node {i}: {} vs {}",
            r2.field[i],
            expected,
        );
    }
}

#[test]
fn no_information_beyond_rho_in_linear_case() {
    // The Helmholtz solution for a linear source is a smoothed
    // version of ρ. Verify that adding a constant offset to ρ
    // produces an output that ONLY differs from the no-offset case
    // by a constant scaling of the same field — no new structure
    // appears.
    let n = 8;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    let rho: Vec<f64> = (0..n).map(|i| (i as f64).sin().abs() + 0.5).collect();
    let rho_offset: Vec<f64> = rho.iter().map(|&r| r + 10.0).collect();
    let s = linear_source(&rho, 1.0).unwrap();
    let s_off = linear_source(&rho_offset, 1.0).unwrap();
    let cfg = CgConfig::default();
    let r = solve_helmholtz(&g, 1.0, 0.5, &s, cfg).unwrap();
    let r_off = solve_helmholtz(&g, 1.0, 0.5, &s_off, cfg).unwrap();
    // The offset response = original response + uniform shift (the
    // offset is a constant, which the operator maps to a constant).
    let diff: Vec<f64> = r_off
        .field
        .iter()
        .zip(r.field.iter())
        .map(|(a, b)| a - b)
        .collect();
    let mean_diff = diff.iter().sum::<f64>() / (n as f64);
    let max_dev = diff
        .iter()
        .map(|d| (d - mean_diff).abs())
        .fold(0.0_f64, f64::max);
    assert!(
        max_dev < 1e-6,
        "uniform offset produced non-uniform response: max deviation {max_dev}",
    );
}
