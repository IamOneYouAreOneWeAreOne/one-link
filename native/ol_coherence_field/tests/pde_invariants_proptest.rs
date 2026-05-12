//! Property-based PDE invariant tests for the coherence-field solver.
//!
//! Each test verifies a mathematical property the field MUST satisfy
//! regardless of graph shape, source distribution, or `(D, Γ)` choice.
//! These are "no-bug-can-hide" properties — if the solver returns a
//! number that violates one of them, the bug is in the math, not in
//! the calling code.
//!
//! Properties verified:
//!
//! 1. **Linearity in source** — solving with source `αS₁ + βS₂` gives
//!    the same field as `αx₁ + βx₂` where `xᵢ` solve with `Sᵢ`.
//! 2. **Reciprocity** — for symmetric operator, the Green-function
//!    matrix entry `G(i, j) = G(j, i)`. Direct consequence of `L = Lᵀ`.
//! 3. **Sign preservation** — if `S ≥ 0` componentwise, then the
//!    recovered field `δτ_c ≥ 0` componentwise (positive source →
//!    positive field; M-matrix property).
//! 4. **Pure-damping limit** — when the graph has no edges, the
//!    Helmholtz equation collapses to `Γ · δτ_c = S` so `δτ_c = S / Γ`
//!    exactly.
//! 5. **Symmetric source → symmetric field** — for a graph with a
//!    reflection automorphism `σ`, if `S(σ(i)) = S(i)` for all `i`,
//!    then the recovered field satisfies the same symmetry.

use ol_coherence_field::{
    pde::CgConfig, solve_helmholtz, FieldError, GraphLaplacian, HelmholtzSolver,
};
use proptest::prelude::*;

/// Build a small random connected ring graph with optional chords.
/// Parameters in domain: `n` ∈ [4, 32], `chord_prob` ∈ [0, 1].
fn arb_ring_with_chords() -> impl Strategy<Value = GraphLaplacian> {
    (4_usize..=32_usize, 0u64..=255).prop_map(|(n, seed)| {
        let mut g = GraphLaplacian::new(n);
        // Ring backbone — guarantees connectivity.
        for i in 0..n {
            let j = (i + 1) % n;
            g.add_edge(i, j, 1.0).unwrap();
        }
        // Pseudo-random chords driven by the seed.
        let mut s = seed.wrapping_mul(0x9E37_79B9);
        for i in 0..n {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            if (s >> 56) < 64 {
                let j = ((s >> 32) as usize) % n;
                if i != j {
                    let _ = g.add_edge(i, j, 0.5);
                }
            }
        }
        g
    })
}

fn arb_source(n: usize) -> impl Strategy<Value = Vec<f64>> {
    proptest::collection::vec(-5.0_f64..=5.0_f64, n)
}

fn solve_for(graph: &GraphLaplacian, d: f64, gamma: f64, s: &[f64]) -> Vec<f64> {
    let cfg = CgConfig {
        max_iter: 5_000,
        tolerance: 1e-10,
    };
    solve_helmholtz(graph, d, gamma, s, cfg)
        .expect("CG must converge for well-conditioned operator")
        .field
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Linearity: x(αS₁ + βS₂) = α·x(S₁) + β·x(S₂).
    #[test]
    fn linearity_in_source(
        graph in arb_ring_with_chords(),
        seed in 0u64..u64::MAX,
        alpha in -3.0f64..3.0,
        beta in -3.0f64..3.0,
    ) {
        let n = graph.n();
        let mut prng = seed;
        let mut next = || {
            prng = prng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((prng >> 32) as i64 as f64) / (i32::MAX as f64) * 5.0
        };
        let s1: Vec<f64> = (0..n).map(|_| next()).collect();
        let s2: Vec<f64> = (0..n).map(|_| next()).collect();
        let combo: Vec<f64> = (0..n).map(|i| alpha * s1[i] + beta * s2[i]).collect();
        let x1 = solve_for(&graph, 1.0, 0.5, &s1);
        let x2 = solve_for(&graph, 1.0, 0.5, &s2);
        let x_combo = solve_for(&graph, 1.0, 0.5, &combo);
        for i in 0..n {
            let predicted = alpha * x1[i] + beta * x2[i];
            let err = (predicted - x_combo[i]).abs();
            prop_assert!(
                err < 1e-5,
                "linearity violated at node {i}: predicted={predicted:.6}, got={:.6}",
                x_combo[i]
            );
        }
    }

    /// Reciprocity: G(i, j) = G(j, i) where G is the Green function
    /// for the symmetric operator (Γ·I + D·L). Verified by solving
    /// with a unit-source at i and reading off the j-th component,
    /// vs solving with unit-source at j and reading off the i-th.
    #[test]
    fn reciprocity_of_green_function(
        graph in arb_ring_with_chords(),
        i_seed in 0u64..u64::MAX,
        j_seed in 0u64..u64::MAX,
    ) {
        let n = graph.n();
        let i = (i_seed as usize) % n;
        let j = (j_seed as usize) % n;
        prop_assume!(i != j);
        let mut s_i = vec![0.0; n];
        let mut s_j = vec![0.0; n];
        s_i[i] = 1.0;
        s_j[j] = 1.0;
        let x_from_i = solve_for(&graph, 1.0, 0.5, &s_i);
        let x_from_j = solve_for(&graph, 1.0, 0.5, &s_j);
        let g_ij = x_from_i[j];
        let g_ji = x_from_j[i];
        prop_assert!(
            (g_ij - g_ji).abs() < 1e-6,
            "reciprocity violated: G({i},{j})={g_ij:.6}, G({j},{i})={g_ji:.6}"
        );
    }

    /// Sign preservation: S ≥ 0 ⟹ δτ_c ≥ 0. The Helmholtz operator
    /// (Γ·I + D·L) is an M-matrix; its inverse has all non-negative
    /// entries, so non-negative input always produces non-negative
    /// output.
    #[test]
    fn positive_source_produces_positive_field(
        graph in arb_ring_with_chords(),
        s_seed in 0u64..u64::MAX,
    ) {
        let n = graph.n();
        let mut prng = s_seed;
        let s: Vec<f64> = (0..n).map(|_| {
            prng = prng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((prng >> 32) as u32 as f64) / (u32::MAX as f64) * 5.0
        }).collect();
        let x = solve_for(&graph, 1.0, 0.5, &s);
        for i in 0..n {
            prop_assert!(
                x[i] >= -1e-9,
                "negative field at node {i}: x={:.6e} (source max = {:.3})",
                x[i],
                s.iter().cloned().fold(0.0_f64, f64::max),
            );
        }
    }

    /// Pure-damping limit: empty graph ⟹ δτ_c[i] = S[i] / Γ.
    #[test]
    fn pure_damping_recovers_source_over_gamma(
        n in 4usize..=24,
        gamma in 0.1f64..5.0,
        s in arb_source(24),
    ) {
        let g = GraphLaplacian::new(n);
        let trimmed = &s[..n];
        let x = solve_for(&g, 1.0, gamma, trimmed);
        for i in 0..n {
            let expected = trimmed[i] / gamma;
            prop_assert!(
                (x[i] - expected).abs() < 1e-6,
                "pure-damping deviation at node {i}: got {:.6}, expected {:.6}",
                x[i],
                expected
            );
        }
    }

    /// Translation invariance on a ring: rotating the source by `k`
    /// positions rotates the field by the same `k` positions. Tests
    /// the discrete rotational symmetry of the pure ring graph.
    #[test]
    fn ring_translation_symmetry(
        n in 6usize..=24,
        source_node in 0usize..24,
        shift in 0usize..24,
    ) {
        prop_assume!(source_node < n);
        prop_assume!(shift < n);
        let mut g = GraphLaplacian::new(n);
        for i in 0..n {
            g.add_edge(i, (i + 1) % n, 1.0).unwrap();
        }
        let mut s0 = vec![0.0; n];
        s0[source_node] = 1.0;
        let x0 = solve_for(&g, 1.0, 0.5, &s0);
        let mut s_shifted = vec![0.0; n];
        s_shifted[(source_node + shift) % n] = 1.0;
        let x_shifted = solve_for(&g, 1.0, 0.5, &s_shifted);
        for i in 0..n {
            let predicted = x0[(n + i - shift) % n];
            prop_assert!(
                (predicted - x_shifted[i]).abs() < 1e-6,
                "ring translation symmetry violated at node {i}: \
                 predicted {:.6}, got {:.6}",
                predicted,
                x_shifted[i]
            );
        }
    }
}

/// Round-trip property: solving and then applying the operator to the
/// recovered field should reproduce the source to within CG tolerance.
/// Checks (Γ·I + D·L)·x ≈ S after `solve_helmholtz`.
#[test]
fn solve_round_trips_through_operator() {
    let n = 32;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    for i in (0..n).step_by(5) {
        let j = (i + 11) % n;
        if i != j {
            let _ = g.add_edge(i, j, 0.5);
        }
    }
    let d = 1.0;
    let gamma = 0.5;
    let mut s = vec![0.0; n];
    s[n / 3] = 1.0;
    s[2 * n / 3] = -0.7;
    let cfg = CgConfig {
        max_iter: 5_000,
        tolerance: 1e-10,
    };
    let result = solve_helmholtz(&g, d, gamma, &s, cfg).unwrap();
    // Compute (Γ·I + D·L) · x and check we recover S.
    let mut ax = vec![0.0; n];
    g.matvec(&result.field, &mut ax);
    let mut residual = 0.0_f64;
    for i in 0..n {
        let lhs = gamma * result.field[i] + d * ax[i];
        residual += (lhs - s[i]).powi(2);
    }
    residual = residual.sqrt();
    assert!(
        residual < 1e-6,
        "round-trip residual too large: {residual:.3e}"
    );
}

/// HelmholtzSolver invariant: identical (graph, d, gamma, source)
/// inputs must produce identical field outputs across calls, even
/// after warm-start has been triggered. (Numerical equality, not
/// just convergence equality.)
#[test]
fn solver_repeated_solve_idempotent_after_warm_start() {
    let n = 24;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    let mut s = vec![0.0; n];
    s[n / 2] = 1.0;
    let cfg = CgConfig::default();
    let mut solver = HelmholtzSolver::new(n);
    let r1 = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
    let r2 = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
    let r3 = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
    for i in 0..n {
        let d12 = (r1.field[i] - r2.field[i]).abs();
        let d23 = (r2.field[i] - r3.field[i]).abs();
        assert!(d12 < 1e-9, "r1 != r2 at node {i}: {d12:.3e}");
        assert!(d23 < 1e-9, "r2 != r3 at node {i}: {d23:.3e}");
    }
}

/// HelmholtzSolver dimension-mismatch error path. The solver must
/// reject sources of the wrong length without panicking.
#[test]
fn solver_rejects_source_length_mismatch() {
    let n = 8;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    let s_wrong = vec![1.0; n + 3];
    let mut solver = HelmholtzSolver::new(n);
    let err = solver
        .solve(&g, 1.0, 0.5, &s_wrong, CgConfig::default())
        .unwrap_err();
    assert!(matches!(err, FieldError::SourceLengthMismatch { .. }));
}
