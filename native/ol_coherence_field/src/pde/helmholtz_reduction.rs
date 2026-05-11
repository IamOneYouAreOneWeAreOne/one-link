//! Quasi-static Helmholtz reduction of the reaction-diffusion PDE.
//!
//! Starting from
//!
//! ```text
//! ∂_t δτ_c = D · ∇²(δτ_c) − Γ · δτ_c + S
//! ```
//!
//! and setting `∂_t δτ_c = 0` (the production-rate case where the
//! field equilibrates faster than topology changes — exactly the
//! plan's "PDE solver runs once per topology change, not per chunk"
//! posture), we get the Helmholtz form:
//!
//! ```text
//! 0 = D · ∇²(δτ_c) − Γ · δτ_c + S
//! ⟺ (Γ · I − D · ∇²) δτ_c = S
//! ```
//!
//! On a graph, `∇² = −L` where `L` is the graph Laplacian (positive
//! semi-definite). So the discrete equation is
//!
//! ```text
//! (Γ · I + D · L) · δτ_c = S
//! ```
//!
//! and the operator on the left is symmetric positive definite for
//! any `Γ > 0` or any graph with at least one non-trivial connected
//! component (when `Γ = 0` the constant mode is in the kernel, so we
//! require `Γ > 0` for uniqueness).

use super::{FieldError, GraphLaplacian, SolveResult};
use super::sparse_solver::{conjugate_gradient, CgConfig};

/// Solve the steady-state Helmholtz reduction
/// `(Γ · I + D · L) · δτ_c = S` on `graph` with diffusion `d`,
/// damping `gamma`, and source vector `source`.
///
/// Returns the recovered field plus convergence diagnostics.
///
/// # Errors
///
/// - [`FieldError::SourceLengthMismatch`] if `source.len() !=
///   graph.n()`.
/// - [`FieldError::NonPhysicalConstants`] if `d ≤ 0` or `gamma < 0`.
/// - [`FieldError::SingularOperator`] if `d == 0 && gamma == 0` (the
///   operator is the zero matrix; any field is a solution).
/// - [`FieldError::NotConverged`] if CG hits its iteration cap before
///   meeting the requested tolerance.
pub fn solve_helmholtz(
    graph: &GraphLaplacian,
    d: f64,
    gamma: f64,
    source: &[f64],
    config: CgConfig,
) -> Result<SolveResult, FieldError> {
    if source.len() != graph.n() {
        return Err(FieldError::SourceLengthMismatch {
            source_len: source.len(),
            node_count: graph.n(),
        });
    }
    // d == 0 && gamma == 0 is the literally-zero matrix; surface
    // that with a more descriptive error before the general
    // non-physical guard runs.
    if d == 0.0 && gamma == 0.0 {
        return Err(FieldError::SingularOperator);
    }
    if d <= 0.0 || gamma < 0.0 {
        return Err(FieldError::NonPhysicalConstants { d, gamma });
    }

    let n = graph.n();
    // Diagonal of (Γ · I + D · L) = Γ + D · degree.
    let mut diag = vec![0.0; n];
    for i in 0..n {
        diag[i] = gamma + d * graph.degree(i);
    }
    // Operator closure: y = (Γ · I + D · L) · x
    //                    = Γ · x + D · (L · x).
    let apply = |x: &[f64], y: &mut [f64]| {
        // Compute D · L · x first using the graph's matvec.
        graph.matvec(x, y);
        for (yi, xi) in y.iter_mut().zip(x.iter()) {
            *yi = gamma * xi + d * *yi;
        }
    };
    let result = conjugate_gradient(n, apply, &diag, source, config);
    if !result.converged {
        return Err(FieldError::NotConverged {
            iterations: result.iterations,
            residual: result.residual,
            tolerance: config.tolerance,
        });
    }
    Ok(SolveResult {
        field: result.x,
        residual: result.residual,
        iterations: result.iterations,
        converged: result.converged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_physical_constants() {
        let g = GraphLaplacian::new(4);
        let s = vec![0.0; 4];
        assert_eq!(
            solve_helmholtz(&g, -1.0, 0.0, &s, CgConfig::default()).unwrap_err(),
            FieldError::NonPhysicalConstants { d: -1.0, gamma: 0.0 }
        );
    }

    #[test]
    fn rejects_singular_operator() {
        let g = GraphLaplacian::new(2);
        let s = vec![0.0; 2];
        assert_eq!(
            solve_helmholtz(&g, 0.0, 0.0, &s, CgConfig::default()).unwrap_err(),
            FieldError::SingularOperator
        );
    }

    #[test]
    fn rejects_source_length_mismatch() {
        let g = GraphLaplacian::new(3);
        let s = vec![0.0; 5];
        assert!(matches!(
            solve_helmholtz(&g, 1.0, 1.0, &s, CgConfig::default()).unwrap_err(),
            FieldError::SourceLengthMismatch { .. }
        ));
    }

    #[test]
    fn pure_damping_equals_source_over_gamma() {
        // No edges → L = 0. Equation becomes Γ · δτ_c = S, so
        // δτ_c = S / Γ everywhere.
        let g = GraphLaplacian::new(5);
        let s = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let gamma = 2.0;
        let result = solve_helmholtz(&g, 1.0, gamma, &s, CgConfig::default()).unwrap();
        for (i, &si) in s.iter().enumerate() {
            assert!(
                (result.field[i] - si / gamma).abs() < 1e-7,
                "node {i}: got {:.6}, expected {:.6}",
                result.field[i],
                si / gamma
            );
        }
    }

    #[test]
    fn linear_chain_smooths_a_point_source() {
        // Path graph 0 — 1 — 2 — 3 — 4 with unit edge weights.
        // Point source at node 2. The recovered field should be
        // symmetric around node 2 and monotonically decreasing
        // outward.
        let n = 5;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let mut s = vec![0.0; n];
        s[2] = 1.0;
        let d = 1.0;
        let gamma = 0.5;
        let result = solve_helmholtz(&g, d, gamma, &s, CgConfig::default()).unwrap();
        // Symmetry: field[0] == field[4], field[1] == field[3].
        assert!((result.field[0] - result.field[4]).abs() < 1e-7);
        assert!((result.field[1] - result.field[3]).abs() < 1e-7);
        // Monotonic decay outward from node 2.
        assert!(result.field[2] > result.field[1]);
        assert!(result.field[1] > result.field[0]);
    }
}
