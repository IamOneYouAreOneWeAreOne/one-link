//! Poisson limit of the Helmholtz reduction.
//!
//! When the screening length `ell_screen = √(D / Γ)` is much larger
//! than the local graph radius, the damping term `Γ · δτ_c` becomes
//! negligible compared to the Laplacian term and the Helmholtz
//! equation
//!
//! ```text
//! (Γ · I + D · L) · δτ_c = S
//! ```
//!
//! reduces to the pure graph-Poisson equation
//!
//! ```text
//! D · L · δτ_c = S.
//! ```
//!
//! The S_One galaxy derivation calls this the **Poisson limit**: when
//! the cosmic-horizon-scale screening length swamps the galaxy radius,
//! the scalar response looks Newtonian-like. The network analog is a
//! swarm small enough that its diameter is well below `ell_screen` —
//! the coherence response is then long-range / Poisson-like.
//!
//! The pure Laplacian `D · L` has the constant vector in its kernel,
//! so a Poisson solve is only well-posed when the source is mean-zero
//! (Σᵢ Sᵢ = 0). We require it explicitly.

use super::sparse_solver::{conjugate_gradient, CgConfig};
use super::{FieldError, GraphLaplacian, SolveResult};

/// Solve the pure graph-Poisson `D · L · δτ_c = S`.
///
/// Requires the source to be mean-zero (Σᵢ Sᵢ ≈ 0); otherwise the
/// equation has no solution (the constant mode is in the kernel of
/// `L`). The caller may need to subtract the mean from `S` before
/// calling; we accept a small tolerance.
///
/// Solution is unique up to a constant; we anchor the kernel by
/// projecting out the mean of the recovered field at each CG step.
pub fn solve_poisson(
    graph: &GraphLaplacian,
    d: f64,
    source: &[f64],
    config: CgConfig,
) -> Result<SolveResult, FieldError> {
    if source.len() != graph.n() {
        return Err(FieldError::SourceLengthMismatch {
            source_len: source.len(),
            node_count: graph.n(),
        });
    }
    if d <= 0.0 {
        return Err(FieldError::NonPhysicalConstants { d, gamma: 0.0 });
    }
    let n = graph.n();
    if n == 0 {
        return Ok(SolveResult {
            field: Vec::new(),
            residual: 0.0,
            iterations: 0,
            converged: true,
        });
    }
    // Project source to mean-zero (well-posedness requirement).
    let s_mean: f64 = source.iter().sum::<f64>() / (n as f64);
    let s_zero: Vec<f64> = source.iter().map(|&s| s - s_mean).collect();

    // Diagonal: D · degree. Use 1.0 fallback for isolated nodes so
    // the preconditioner doesn't divide by zero.
    let diag: Vec<f64> = (0..n)
        .map(|i| {
            let deg = graph.degree(i);
            if deg > 0.0 {
                d * deg
            } else {
                1.0
            }
        })
        .collect();

    // Operator: y = D · L · x, projected to mean-zero.
    let apply = |x: &[f64], y: &mut [f64]| {
        graph.matvec(x, y);
        for yi in y.iter_mut() {
            *yi *= d;
        }
        let mean = y.iter().sum::<f64>() / (n as f64);
        for yi in y.iter_mut() {
            *yi -= mean;
        }
    };

    let result = conjugate_gradient(n, apply, &diag, &s_zero, config);
    if !result.converged {
        return Err(FieldError::NotConverged {
            iterations: result.iterations,
            residual: result.residual,
            tolerance: config.tolerance,
        });
    }
    // Anchor the kernel — pin the mean of the solution to 0 (the
    // physical convention is that δτ_c is a deviation from τ_∞, so
    // its swarm-average is identically zero).
    let mut field = result.x;
    let mean = field.iter().sum::<f64>() / (n as f64);
    for fi in field.iter_mut() {
        *fi -= mean;
    }
    Ok(SolveResult {
        field,
        residual: result.residual,
        iterations: result.iterations,
        converged: result.converged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisson_on_two_node_dipole() {
        // 2 nodes, edge weight 1. Source = (+1, -1). Solution
        // satisfies D · L · x = S, mean(x) = 0.
        // L = [[1, -1], [-1, 1]]; for D=1 and x = (a, -a) we get
        // (2a, -2a) = (1, -1) → a = 1/2.
        let mut g = GraphLaplacian::new(2);
        g.add_edge(0, 1, 1.0).unwrap();
        let s = vec![1.0, -1.0];
        let r = solve_poisson(&g, 1.0, &s, CgConfig::default()).unwrap();
        assert!((r.field[0] - 0.5).abs() < 1e-7);
        assert!((r.field[1] + 0.5).abs() < 1e-7);
    }

    #[test]
    fn poisson_source_mean_is_projected_out() {
        // 4-cycle. Source has nonzero mean; we still get a valid
        // solution because the routine subtracts it.
        let mut g = GraphLaplacian::new(4);
        g.add_edge(0, 1, 1.0).unwrap();
        g.add_edge(1, 2, 1.0).unwrap();
        g.add_edge(2, 3, 1.0).unwrap();
        g.add_edge(3, 0, 1.0).unwrap();
        let s = vec![10.0, 0.0, 0.0, 0.0]; // mean = 2.5
        let r = solve_poisson(&g, 1.0, &s, CgConfig::default()).unwrap();
        // Solution should be mean-zero.
        let mean = r.field.iter().sum::<f64>() / 4.0;
        assert!(mean.abs() < 1e-7);
    }
}
