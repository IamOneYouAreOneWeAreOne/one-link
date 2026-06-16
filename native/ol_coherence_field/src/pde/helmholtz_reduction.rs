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

use super::sparse_solver::{
    conjugate_gradient, conjugate_gradient_with_workspace, CgConfig, CgWorkspace,
};
use super::{FieldError, GraphLaplacian, SolveResult};

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
    for (i, slot) in diag.iter_mut().enumerate() {
        *slot = gamma + d * graph.degree(i);
    }
    // Operator closure: y = (Γ · I + D · L) · x
    //                    = Γ · x + D · (L · x).
    //
    // Using serial `matvec` inside CG. Empirically the parallel
    // version regressed wall-clock at 50k peers (rayon dispatch
    // overhead × ~20 CG iters > the per-iter parallelism gain). The
    // parallel matvec stays available as a one-shot API for callers
    // that need a single large matvec — see [`GraphLaplacian::matvec_par`].
    let apply = |x: &[f64], y: &mut [f64]| {
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

/// Stateful Helmholtz solver with reusable CG workspace.
///
/// Use this for **repeated solves on the same (or incrementally-
/// changing) topology**:
///
/// - Green-function adjoint: one solve per source, N sources, shared
///   LHS.
/// - Daemon field snapshots: re-solve every ~1s as relay metrics
///   evolve.
/// - Time-stepped reaction-diffusion: each timestep is a fresh solve.
///
/// One-shot callers should keep using [`solve_helmholtz`] — the
/// allocation overhead is negligible for a single solve.
///
/// Warm-start: each successful solve caches its result. The next
/// solve uses it as the initial guess; on incrementally-changing
/// problems CG converges in **2-3 iterations** instead of 18-20.
/// Disable via [`Self::clear_warm_start`].
#[derive(Debug)]
pub struct HelmholtzSolver {
    workspace: CgWorkspace,
    /// Cached diagonal of `(Γ·I + D·L)` — invalidated when the
    /// caller's `(d, gamma, graph)` triple changes.
    diag: Vec<f64>,
    /// Whether to seed each solve from the previous solve's `x`.
    /// Cleared by `clear_warm_start`, set after the first successful
    /// solve.
    warm: bool,
}

impl HelmholtzSolver {
    /// Allocate a solver sized for graphs over `n` nodes.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            workspace: CgWorkspace::new(n),
            diag: vec![0.0; n],
            warm: false,
        }
    }

    /// Disable warm-start. The next solve starts from `x = 0`.
    pub fn clear_warm_start(&mut self) {
        self.warm = false;
        self.workspace.zero_initial_guess();
    }

    /// Resize for a new graph size. Cheap when already correct;
    /// reallocates only on growth. Implicitly clears warm-start
    /// (the cached solution dimension no longer matches).
    pub fn resize(&mut self, n: usize) {
        if self.workspace.n() == n {
            return;
        }
        self.workspace.resize(n);
        self.diag.resize(n, 0.0);
        self.warm = false;
    }

    /// Solve `(Γ·I + D·L) · δτ_c = S` for the supplied graph + source.
    /// Reuses the internal workspace; uses the previous solution as a
    /// warm-start when available.
    pub fn solve(
        &mut self,
        graph: &GraphLaplacian,
        d: f64,
        gamma: f64,
        source: &[f64],
        config: CgConfig,
    ) -> Result<SolveResult, FieldError> {
        let n = graph.n();
        if source.len() != n {
            return Err(FieldError::SourceLengthMismatch {
                source_len: source.len(),
                node_count: n,
            });
        }
        if d == 0.0 && gamma == 0.0 {
            return Err(FieldError::SingularOperator);
        }
        if d <= 0.0 || gamma < 0.0 {
            return Err(FieldError::NonPhysicalConstants { d, gamma });
        }
        self.resize(n);
        // Refresh diag = Γ + D·degree(i) each call (the graph's
        // degrees may change between solves).
        for i in 0..n {
            self.diag[i] = gamma + d * graph.degree(i);
        }
        // Warm-start: if we have a previous solution at the right
        // size, keep workspace.x; otherwise zero it.
        if !self.warm {
            self.workspace.zero_initial_guess();
        }
        let apply = |x: &[f64], y: &mut [f64]| {
            graph.matvec(x, y);
            for (yi, xi) in y.iter_mut().zip(x.iter()) {
                *yi = gamma * xi + d * *yi;
            }
        };
        let (residual, iterations, converged) = conjugate_gradient_with_workspace(
            &mut self.workspace,
            apply,
            &self.diag,
            source,
            config,
        );
        if !converged {
            // Don't trust the result for the next warm-start.
            self.warm = false;
            return Err(FieldError::NotConverged {
                iterations,
                residual,
                tolerance: config.tolerance,
            });
        }
        self.warm = true;
        Ok(SolveResult {
            field: self.workspace.x.clone(),
            residual,
            iterations,
            converged,
        })
    }

    /// Read-only access to the most-recent solved field (no clone).
    /// Returns the workspace's internal `x` buffer.
    #[must_use]
    pub fn last_field(&self) -> &[f64] {
        &self.workspace.x
    }
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
            FieldError::NonPhysicalConstants {
                d: -1.0,
                gamma: 0.0
            }
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
    fn solver_struct_matches_one_shot_for_first_solve() {
        // First solve with HelmholtzSolver must produce the same
        // numerical answer as the one-shot solve_helmholtz function.
        let n = 8;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let mut s = vec![0.0; n];
        s[3] = 1.0;
        let cfg = CgConfig::default();
        let one_shot = solve_helmholtz(&g, 1.0, 0.5, &s, cfg).unwrap();
        let mut solver = HelmholtzSolver::new(n);
        let from_struct = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
        for i in 0..n {
            assert!(
                (one_shot.field[i] - from_struct.field[i]).abs() < 1e-9,
                "node {i}: one-shot {:.9}, struct {:.9}",
                one_shot.field[i],
                from_struct.field[i],
            );
        }
    }

    #[test]
    fn solver_warm_start_cuts_iterations_on_repeated_solve() {
        // Second solve of the same problem (or a tiny perturbation of
        // it) must converge in fewer iterations when warm-started.
        let n = 64;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        // Add a few cross-edges to make the graph less trivial.
        for i in (0..n).step_by(7) {
            let j = (i + 17) % n;
            if i != j {
                let _ = g.add_edge(i, j, 0.5);
            }
        }
        let mut s = vec![0.0; n];
        s[n / 2] = 1.0;
        let cfg = CgConfig::default();
        let mut solver = HelmholtzSolver::new(n);
        let first = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
        // Perturb the source slightly, then re-solve. Warm-start
        // should converge much faster.
        let mut s2 = s.clone();
        s2[n / 2] = 1.01;
        let second = solver.solve(&g, 1.0, 0.5, &s2, cfg).unwrap();
        assert!(
            second.iterations < first.iterations,
            "warm-start failed: first {} iters, second {} iters",
            first.iterations,
            second.iterations
        );
    }

    #[test]
    fn solver_clear_warm_start_restores_cold_iteration_count() {
        let n = 32;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let mut s = vec![0.0; n];
        s[n / 2] = 1.0;
        let cfg = CgConfig::default();
        let mut solver = HelmholtzSolver::new(n);
        let cold = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
        solver.clear_warm_start();
        let recold = solver.solve(&g, 1.0, 0.5, &s, cfg).unwrap();
        // Same iteration count when explicitly cold-started.
        assert_eq!(cold.iterations, recold.iterations);
    }

    #[test]
    fn solver_resize_clears_warm_start() {
        let mut solver = HelmholtzSolver::new(16);
        let mut g = GraphLaplacian::new(16);
        for i in 0..15 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let s = vec![1.0; 16];
        solver.solve(&g, 1.0, 0.5, &s, CgConfig::default()).unwrap();
        // Resize to a different graph size; warm-start must be cleared
        // (the cached x would have the wrong length to seed from).
        solver.resize(8);
        let mut g2 = GraphLaplacian::new(8);
        for i in 0..7 {
            g2.add_edge(i, i + 1, 1.0).unwrap();
        }
        let s2 = vec![1.0; 8];
        let result = solver
            .solve(&g2, 1.0, 0.5, &s2, CgConfig::default())
            .unwrap();
        // Must converge without panicking from dimension mismatch.
        assert!(result.converged);
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
