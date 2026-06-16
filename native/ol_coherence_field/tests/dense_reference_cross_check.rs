// Indexed loops mirror the textbook dense linear-algebra notation
// (matrix rows/cols addressed across several arrays); idiomatic
// iterators would obscure the math this cross-check is verifying.
#![allow(clippy::needless_range_loop)]
//! Dense-linalg cross-check: solve `(Γ·I + D·L)·x = b` with a naive
//! Gaussian elimination on a fully-materialized dense matrix, and
//! verify the sparse CG path produces the same answer.
//!
//! This is the "two implementations agree" gate. If CG ever produces
//! a result that diverges from textbook dense Gaussian elimination by
//! more than ~1e-6 in any component, something is wrong with either
//! the CSR matvec, the preconditioner, or the CG iteration math.
//!
//! Kept small (n ≤ 64) because dense GE is O(n³) — pure correctness
//! check, not a performance test.

use ol_coherence_field::{pde::CgConfig, solve_helmholtz, GraphLaplacian};

/// Materialize the dense matrix `M = Γ·I + D·L` for the given graph.
fn dense_helmholtz_matrix(g: &GraphLaplacian, d: f64, gamma: f64) -> Vec<Vec<f64>> {
    let n = g.n();
    let mut m = vec![vec![0.0_f64; n]; n];
    for i in 0..n {
        m[i][i] = gamma + d * g.degree(i);
        for &(j, w) in g.neighbors(i) {
            m[i][j] -= d * w;
        }
    }
    m
}

/// Dense Gaussian elimination with partial pivoting. Returns the
/// solution `x` to `M·x = b`. Allocates fresh — not optimised because
/// this is reference-only.
fn dense_gaussian_solve(mut m: Vec<Vec<f64>>, mut b: Vec<f64>) -> Vec<f64> {
    let n = b.len();
    assert_eq!(m.len(), n);
    for col in 0..n {
        // Partial pivot: find max |M[r][col]| over rows r ≥ col.
        let mut pivot = col;
        let mut pivot_val = m[col][col].abs();
        for r in (col + 1)..n {
            let v = m[r][col].abs();
            if v > pivot_val {
                pivot = r;
                pivot_val = v;
            }
        }
        assert!(
            pivot_val > 1e-14,
            "matrix singular at column {col}; pivot magnitude {pivot_val:.3e}"
        );
        if pivot != col {
            m.swap(col, pivot);
            b.swap(col, pivot);
        }
        // Eliminate below.
        let m_col = m[col][col];
        for r in (col + 1)..n {
            let factor = m[r][col] / m_col;
            if factor == 0.0 {
                continue;
            }
            for c in col..n {
                let v = m[col][c];
                m[r][c] -= factor * v;
            }
            b[r] -= factor * b[col];
        }
    }
    // Back-substitution.
    let mut x = vec![0.0_f64; n];
    for r in (0..n).rev() {
        let mut acc = b[r];
        for c in (r + 1)..n {
            acc -= m[r][c] * x[c];
        }
        x[r] = acc / m[r][r];
    }
    x
}

fn cg_vs_dense(graph: &GraphLaplacian, d: f64, gamma: f64, b: &[f64]) {
    let cfg = CgConfig {
        max_iter: 5_000,
        tolerance: 1e-12,
    };
    let cg = solve_helmholtz(graph, d, gamma, b, cfg).expect("CG converges");
    let dense_m = dense_helmholtz_matrix(graph, d, gamma);
    let dense = dense_gaussian_solve(dense_m, b.to_vec());
    let n = graph.n();
    for i in 0..n {
        let diff = (cg.field[i] - dense[i]).abs();
        let rel = diff / dense[i].abs().max(1e-12);
        assert!(
            diff < 1e-6 && rel < 1e-3,
            "node {i}: CG={:.9}, dense={:.9}, abs={diff:.3e}, rel={rel:.3e}",
            cg.field[i],
            dense[i],
        );
    }
}

#[test]
fn small_path_graph_matches_dense() {
    let n = 8;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    let mut b = vec![0.0; n];
    b[3] = 1.0;
    cg_vs_dense(&g, 1.0, 0.5, &b);
}

#[test]
fn small_ring_with_chords_matches_dense() {
    let n = 12;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n {
        g.add_edge(i, (i + 1) % n, 1.0).unwrap();
    }
    // A few chord edges.
    g.add_edge(0, 5, 0.7).unwrap();
    g.add_edge(2, 8, 0.3).unwrap();
    g.add_edge(4, 11, 0.4).unwrap();
    let b: Vec<f64> = (0..n).map(|i| (i as f64).sin()).collect();
    cg_vs_dense(&g, 1.0, 0.5, &b);
}

#[test]
fn dense_star_graph_with_strong_damping() {
    // Star: node 0 connected to all others. Verify dense + CG agree
    // even with a high-degree hub vertex (the operator condition
    // number scales with max degree).
    let n = 16;
    let mut g = GraphLaplacian::new(n);
    for i in 1..n {
        g.add_edge(0, i, 1.0).unwrap();
    }
    let mut b = vec![0.0; n];
    b[0] = 1.0;
    cg_vs_dense(&g, 1.0, 2.0, &b);
}

#[test]
fn high_loss_low_diffusion_extreme_regime() {
    // Yukawa regime: gamma >> D. Operator is heavily diagonally
    // dominant; both solvers should agree closely.
    let n = 20;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n - 1 {
        g.add_edge(i, i + 1, 1.0).unwrap();
    }
    for i in (0..n).step_by(3) {
        let j = (i + 7) % n;
        if i != j {
            let _ = g.add_edge(i, j, 0.3);
        }
    }
    let b: Vec<f64> = (0..n)
        .map(|i| if i % 2 == 0 { 1.0 } else { -0.5 })
        .collect();
    cg_vs_dense(&g, 0.01, 5.0, &b);
}

#[test]
fn low_damping_long_range_regime() {
    // Poisson-like: gamma << D. Condition number worse; verify CG
    // still hits the dense answer to tight tolerance.
    let n = 24;
    let mut g = GraphLaplacian::new(n);
    for i in 0..n {
        g.add_edge(i, (i + 1) % n, 1.0).unwrap();
    }
    let mut b = vec![0.0; n];
    b[n / 4] = 1.0;
    b[3 * n / 4] = -0.7;
    cg_vs_dense(&g, 10.0, 0.05, &b);
}
