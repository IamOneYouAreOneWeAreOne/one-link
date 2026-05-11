//! Full reaction-diffusion form. The unsteady PDE
//!
//! ```text
//! ∂_t δτ_c = D · ∇²(δτ_c) − Γ · δτ_c + S
//! ```
//!
//! discretised with forward-Euler timestepping on the graph
//! Laplacian:
//!
//! ```text
//! δτ_c^{n+1} = δτ_c^n + Δt · (D · ∇² δτ_c^n − Γ · δτ_c^n + S)
//!            = δτ_c^n + Δt · (−D · L · δτ_c^n − Γ · δτ_c^n + S)
//! ```
//!
//! Stable for `Δt ≤ 2 / (D · λ_max(L) + Γ)` where `λ_max(L)` is the
//! largest Laplacian eigenvalue (bounded by `2 · max_degree`).
//!
//! In the production hot path, the steady-state form
//! [`super::helmholtz_reduction::solve_helmholtz`] is what runs — the
//! field is re-solved on topology change, not stepped per chunk. The
//! timestepping form here is the reference implementation used to
//! verify the steady-state solver converges to the right fixed point.

use super::{FieldError, GraphLaplacian, SolveResult};

/// Configuration for the unsteady timestep loop.
#[derive(Debug, Clone, Copy)]
pub struct EulerConfig {
    /// Timestep size. Caller is responsible for satisfying the
    /// stability condition; pass `None` and we'll pick a safe default
    /// from the graph's max degree.
    pub dt: Option<f64>,
    /// Maximum number of iterations.
    pub max_iter: usize,
    /// L2-norm convergence tolerance on `δτ_c^{n+1} − δτ_c^n`.
    pub tolerance: f64,
}

impl Default for EulerConfig {
    fn default() -> Self {
        Self {
            dt: None,
            max_iter: 100_000,
            tolerance: 1e-9,
        }
    }
}

/// Step the unsteady reaction-diffusion PDE to (approximate)
/// steady state via forward Euler. Returns the final field plus
/// diagnostics. The output should match [`super::solve_helmholtz`]
/// up to numerical noise — verified by
/// `tests/reaction_diffusion_converges.rs`.
pub fn solve_reaction_diffusion_steady(
    graph: &GraphLaplacian,
    d: f64,
    gamma: f64,
    source: &[f64],
    config: EulerConfig,
) -> Result<SolveResult, FieldError> {
    if source.len() != graph.n() {
        return Err(FieldError::SourceLengthMismatch {
            source_len: source.len(),
            node_count: graph.n(),
        });
    }
    if d <= 0.0 || gamma < 0.0 {
        return Err(FieldError::NonPhysicalConstants { d, gamma });
    }
    if d == 0.0 && gamma == 0.0 {
        return Err(FieldError::SingularOperator);
    }
    let n = graph.n();
    // Stability default: λ_max(L) ≤ 2 · max_degree (Gershgorin).
    let dt = config.dt.unwrap_or_else(|| {
        let max_deg = (0..n).map(|i| graph.degree(i)).fold(0.0_f64, f64::max);
        let bound = d * 2.0 * max_deg + gamma;
        // 0.4 leaves headroom below the strict CFL boundary (2/bound)
        // so small numerical perturbations don't drive the iterate
        // unstable.
        if bound > 0.0 { 0.4 / bound } else { 1e-3 }
    });

    let mut x = vec![0.0; n];
    let mut lx = vec![0.0; n];
    let mut iterations = 0usize;
    let mut residual = f64::INFINITY;
    while iterations < config.max_iter && residual > config.tolerance {
        graph.matvec(&x, &mut lx);
        let mut sum_sq_delta = 0.0;
        for i in 0..n {
            let drift = -d * lx[i] - gamma * x[i] + source[i];
            let delta = dt * drift;
            x[i] += delta;
            sum_sq_delta += delta * delta;
        }
        residual = sum_sq_delta.sqrt();
        iterations += 1;
    }
    let converged = residual <= config.tolerance;
    Ok(SolveResult {
        field: x,
        residual,
        iterations,
        converged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn euler_no_edges_pure_damping_converges_to_source_over_gamma() {
        let n = 4;
        let g = GraphLaplacian::new(n);
        let s = vec![1.0, 2.0, 4.0, 8.0];
        let gamma = 3.0;
        let result = solve_reaction_diffusion_steady(
            &g,
            1.0,
            gamma,
            &s,
            EulerConfig::default(),
        )
        .unwrap();
        for i in 0..n {
            assert!(
                (result.field[i] - s[i] / gamma).abs() < 1e-5,
                "node {i}: got {}, expected {}",
                result.field[i],
                s[i] / gamma
            );
        }
    }
}
