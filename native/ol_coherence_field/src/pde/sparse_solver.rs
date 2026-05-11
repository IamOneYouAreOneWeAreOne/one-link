//! Conjugate-gradient solver for symmetric positive-definite linear
//! systems `A · x = b`. The operator `A` is supplied as a closure
//! (rather than a concrete matrix type) so the same routine drives the
//! Helmholtz, Poisson, and reaction-diffusion solves without
//! duplicating the iteration loop.
//!
//! Algorithm: standard CG with optional Jacobi (diagonal)
//! preconditioner. Stops on relative residual `||r|| / ||b||` below
//! the configured tolerance.

/// Configuration knobs for [`conjugate_gradient`].
#[derive(Debug, Clone, Copy)]
pub struct CgConfig {
    /// Maximum iterations. The solver returns the last iterate even
    /// if this is hit before convergence (caller decides whether to
    /// accept).
    pub max_iter: usize,
    /// Relative tolerance: stop when `||r||₂ / ||b||₂ < tolerance`.
    pub tolerance: f64,
}

impl Default for CgConfig {
    fn default() -> Self {
        Self {
            // 10·N steps is enough for most well-conditioned graphs
            // in our regime; cap it so a pathological condition
            // number can't hang the solver indefinitely.
            max_iter: 2000,
            tolerance: 1e-9,
        }
    }
}

/// Result returned by [`conjugate_gradient`].
#[derive(Debug, Clone)]
pub struct CgResult {
    /// Recovered solution vector.
    pub x: Vec<f64>,
    /// Final relative residual `||r||₂ / ||b||₂`.
    pub residual: f64,
    /// Iterations performed.
    pub iterations: usize,
    /// Did we hit the tolerance?
    pub converged: bool,
}

/// Solve `A · x = b` via conjugate gradient. `apply_a` computes
/// `y = A · x` for an arbitrary `x` (closure form means the operator
/// can be a matrix, a sum of matrices, a Laplacian-plus-shift, etc.).
///
/// `diag` is the diagonal of `A`; used as a Jacobi preconditioner.
/// If a strictly-positive diagonal isn't available, pass `&vec![1.0;
/// n]` to disable preconditioning.
pub fn conjugate_gradient<F>(
    n: usize,
    apply_a: F,
    diag: &[f64],
    b: &[f64],
    config: CgConfig,
) -> CgResult
where
    F: Fn(&[f64], &mut [f64]),
{
    debug_assert_eq!(b.len(), n);
    debug_assert_eq!(diag.len(), n);

    let mut x = vec![0.0; n];
    let mut r = b.to_vec(); // r = b - A · x; x = 0 so r = b
    let mut z = apply_preconditioner(diag, &r);
    let mut p = z.clone();
    let mut ap = vec![0.0; n];
    let mut r_dot_z = dot(&r, &z);
    let bnorm = norm2(b).max(1.0e-30);

    let mut iterations = 0;
    let mut residual = norm2(&r) / bnorm;
    let mut converged = residual <= config.tolerance;
    while !converged && iterations < config.max_iter {
        apply_a(&p, &mut ap);
        let p_ap = dot(&p, &ap);
        if p_ap.abs() < 1e-30 {
            // Operator is singular along p — can't make progress.
            break;
        }
        let alpha = r_dot_z / p_ap;
        for i in 0..n {
            x[i] += alpha * p[i];
            r[i] -= alpha * ap[i];
        }
        z = apply_preconditioner(diag, &r);
        let r_dot_z_new = dot(&r, &z);
        let beta = r_dot_z_new / r_dot_z.max(1.0e-30);
        for i in 0..n {
            p[i] = z[i] + beta * p[i];
        }
        r_dot_z = r_dot_z_new;
        iterations += 1;
        residual = norm2(&r) / bnorm;
        converged = residual <= config.tolerance;
    }

    CgResult {
        x,
        residual,
        iterations,
        converged,
    }
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn norm2(v: &[f64]) -> f64 {
    dot(v, v).sqrt()
}

fn apply_preconditioner(diag: &[f64], r: &[f64]) -> Vec<f64> {
    debug_assert_eq!(diag.len(), r.len());
    r.iter()
        .zip(diag.iter())
        .map(|(ri, di)| if di.abs() > 1e-30 { ri / di } else { *ri })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cg_solves_identity_matrix() {
        // A = I, b = (1, 2, 3) → x = (1, 2, 3).
        let n = 3;
        let b = vec![1.0, 2.0, 3.0];
        let diag = vec![1.0; n];
        let result = conjugate_gradient(
            n,
            |x, y| y.copy_from_slice(x),
            &diag,
            &b,
            CgConfig::default(),
        );
        assert!(result.converged);
        for i in 0..n {
            assert!((result.x[i] - b[i]).abs() < 1e-9);
        }
    }

    #[test]
    fn cg_solves_diagonal_matrix() {
        // A = diag(2, 4, 8), b = (4, 8, 16) → x = (2, 2, 2).
        let n = 3;
        let diag = vec![2.0, 4.0, 8.0];
        let b = vec![4.0, 8.0, 16.0];
        let result = conjugate_gradient(
            n,
            |x, y| {
                for i in 0..n {
                    y[i] = diag[i] * x[i];
                }
            },
            &diag,
            &b,
            CgConfig::default(),
        );
        assert!(result.converged);
        for i in 0..n {
            assert!((result.x[i] - 2.0).abs() < 1e-9);
        }
    }

    #[test]
    fn cg_reports_residual_when_not_converged() {
        // A = I, but cap iterations at 0 — solver returns initial
        // residual unchanged.
        let n = 2;
        let b = vec![1.0, 1.0];
        let diag = vec![1.0; n];
        let result = conjugate_gradient(
            n,
            |x, y| y.copy_from_slice(x),
            &diag,
            &b,
            CgConfig {
                max_iter: 0,
                tolerance: 1e-12,
            },
        );
        assert!(!result.converged);
        assert!(result.residual > 0.0);
    }
}
