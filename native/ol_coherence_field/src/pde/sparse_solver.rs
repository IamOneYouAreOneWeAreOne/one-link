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

/// Pre-allocated CG workspace.
///
/// For repeated solves on the same graph (Green-function adjoint
/// readouts, time-stepped reaction-diffusion, daemon field snapshots
/// every ~1s), allocating fresh `Vec<f64>` buffers per call wastes
/// ~5 × N × 8 bytes of allocator churn. A reusable workspace eliminates
/// that — call [`conjugate_gradient_with_workspace`] in a loop with
/// the same workspace and the only allocation cost is the initial
/// construction.
#[derive(Debug)]
pub struct CgWorkspace {
    n: usize,
    pub(crate) x: Vec<f64>,
    pub(crate) r: Vec<f64>,
    pub(crate) z: Vec<f64>,
    pub(crate) p: Vec<f64>,
    pub(crate) ap: Vec<f64>,
}

impl CgWorkspace {
    /// Allocate a workspace for problems over `n` unknowns.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            n,
            x: vec![0.0; n],
            r: vec![0.0; n],
            z: vec![0.0; n],
            p: vec![0.0; n],
            ap: vec![0.0; n],
        }
    }

    /// Size the workspace was allocated for.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Resize the workspace if `n` changed (e.g. graph topology grew).
    /// Cheap when already-sized; only reallocates on growth.
    pub fn resize(&mut self, n: usize) {
        if self.n == n {
            return;
        }
        self.x.resize(n, 0.0);
        self.r.resize(n, 0.0);
        self.z.resize(n, 0.0);
        self.p.resize(n, 0.0);
        self.ap.resize(n, 0.0);
        self.n = n;
    }

    /// Seed the solver's initial guess `x` with the caller's vector.
    /// Used for warm-starting from a previous solution when the
    /// underlying operator only changed incrementally.
    pub fn set_initial_guess(&mut self, x0: &[f64]) {
        debug_assert_eq!(x0.len(), self.n);
        self.x.copy_from_slice(x0);
    }

    /// Zero the initial guess (the default).
    pub fn zero_initial_guess(&mut self) {
        for xi in &mut self.x {
            *xi = 0.0;
        }
    }
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
    // One-shot path: allocate a workspace, run, return owned x. The
    // workspace is dropped on return.
    let mut ws = CgWorkspace::new(n);
    let (residual, iterations, converged) =
        conjugate_gradient_with_workspace(&mut ws, apply_a, diag, b, config);
    CgResult {
        x: std::mem::take(&mut ws.x),
        residual,
        iterations,
        converged,
    }
}

/// Workspace-flavoured CG. Same algorithm as [`conjugate_gradient`]
/// but the caller owns the workspace, eliminating per-call allocs.
/// Returns `(residual, iterations, converged)`; the recovered field
/// lives in `workspace.x` after the call (caller can read it via
/// `&workspace.x[..]`).
///
/// Warm-start: if the caller pre-set `workspace.x` to a non-zero
/// guess (via [`CgWorkspace::set_initial_guess`]), the solver uses it.
/// Otherwise call [`CgWorkspace::zero_initial_guess`] first.
pub fn conjugate_gradient_with_workspace<F>(
    workspace: &mut CgWorkspace,
    apply_a: F,
    diag: &[f64],
    b: &[f64],
    config: CgConfig,
) -> (f64, usize, bool)
where
    F: Fn(&[f64], &mut [f64]),
{
    let n = workspace.n;
    debug_assert_eq!(b.len(), n);
    debug_assert_eq!(diag.len(), n);

    // Borrow disjoint workspace fields. CG body does ZERO heap allocs.
    let CgWorkspace {
        n: _,
        x,
        r,
        z,
        p,
        ap,
    } = workspace;

    // r = b - A·x (where x is the caller's initial guess, possibly 0).
    // For warm-start cases we evaluate A·x explicitly; for the common
    // zero-start case we short-circuit to r = b.
    let zero_start = x.iter().all(|&v| v == 0.0);
    if zero_start {
        r.copy_from_slice(b);
    } else {
        apply_a(x, ap);
        for i in 0..n {
            r[i] = b[i] - ap[i];
        }
    }

    apply_preconditioner_into(diag, r, z);
    p.copy_from_slice(z);

    let mut r_dot_z = dot(r, z);
    let bnorm_sq = dot(b, b).max(1.0e-60);
    let tol_sq = config.tolerance * config.tolerance;

    let mut iterations = 0;
    let mut r_norm_sq = dot(r, r);
    let mut residual = (r_norm_sq / bnorm_sq).sqrt();
    let mut converged = r_norm_sq <= tol_sq * bnorm_sq;

    while !converged && iterations < config.max_iter {
        apply_a(p, ap);
        let p_ap = dot(p, ap);
        if p_ap.abs() < 1e-30 {
            // Operator is singular along p — can't make progress.
            break;
        }
        let alpha = r_dot_z / p_ap;
        // Fused x += α·p and r -= α·ap with running r·r accumulation
        // in the same pass — one walk of memory instead of three.
        let mut new_r_norm_sq = 0.0_f64;
        for i in 0..n {
            x[i] += alpha * p[i];
            let ri = r[i] - alpha * ap[i];
            r[i] = ri;
            new_r_norm_sq += ri * ri;
        }
        r_norm_sq = new_r_norm_sq;

        apply_preconditioner_into(diag, r, z);
        let r_dot_z_new = dot(r, z);
        let beta = r_dot_z_new / r_dot_z.max(1.0e-30);
        // p = z + β·p (in-place, one pass).
        for i in 0..n {
            p[i] = z[i] + beta * p[i];
        }
        r_dot_z = r_dot_z_new;
        iterations += 1;
        residual = (r_norm_sq / bnorm_sq).sqrt();
        converged = r_norm_sq <= tol_sq * bnorm_sq;
    }

    (residual, iterations, converged)
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    debug_assert_eq!(a.len(), b.len());
    // Manual unroll of 4 lanes; auto-vec picks this up as 2× f64x4
    // (AVX2) or 1× f64x8 (AVX-512). Without the unroll the iterator
    // fold defeats vectorization on some target features.
    let n = a.len();
    let chunk = 4;
    let mut s0 = 0.0_f64;
    let mut s1 = 0.0_f64;
    let mut s2 = 0.0_f64;
    let mut s3 = 0.0_f64;
    let blocks = n / chunk;
    for k in 0..blocks {
        let i = k * chunk;
        s0 += a[i] * b[i];
        s1 += a[i + 1] * b[i + 1];
        s2 += a[i + 2] * b[i + 2];
        s3 += a[i + 3] * b[i + 3];
    }
    let mut tail = (s0 + s1) + (s2 + s3);
    for i in (blocks * chunk)..n {
        tail += a[i] * b[i];
    }
    tail
}

fn apply_preconditioner_into(diag: &[f64], r: &[f64], z: &mut [f64]) {
    debug_assert_eq!(diag.len(), r.len());
    debug_assert_eq!(z.len(), r.len());
    for i in 0..r.len() {
        let di = diag[i];
        z[i] = if di.abs() > 1e-30 { r[i] / di } else { r[i] };
    }
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
        for (xi, bi) in result.x.iter().zip(b.iter()) {
            assert!((xi - bi).abs() < 1e-9);
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
