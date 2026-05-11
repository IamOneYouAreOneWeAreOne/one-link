//! PDE solver layer: graph-Laplacian discretization of the
//! reaction-diffusion equation
//!
//! ```text
//! ∂_t δτ_c = D · ∇²(δτ_c) − Γ · δτ_c + S
//! ```
//!
//! and its quasi-static reduction (`∂_t δτ_c = 0`) to the Helmholtz
//! form
//!
//! ```text
//! (Γ · I + D · L) δτ_c = S
//! ```
//!
//! where `L` is the graph Laplacian (`L = D_diag − A`). Solved via
//! conjugate-gradient since the operator is symmetric positive
//! definite (Γ ≥ 0, D > 0, L positive semi-definite — Γ > 0 makes the
//! sum strictly positive definite).
//!
//! Sub-modules:
//!
//! - [`reaction_diffusion`] — the unsteady PDE form (Euler timestep
//!   reference; the production hot path is the steady-state Helmholtz
//!   solve).
//! - [`helmholtz_reduction`] — quasi-static reduction; the production
//!   path.
//! - [`poisson_limit`] — `ell_screen ≫ r_local` regime: the matrix
//!   reduces to pure `D · L`, solver becomes plain graph-Poisson.
//! - [`sparse_solver`] — conjugate-gradient implementation used by all
//!   of the above.

pub mod helmholtz_reduction;
pub mod poisson_limit;
pub mod reaction_diffusion;
pub mod sparse_solver;

use thiserror::Error;

pub use helmholtz_reduction::solve_helmholtz;
pub use reaction_diffusion::solve_reaction_diffusion_steady;
pub use sparse_solver::{conjugate_gradient, CgConfig, CgResult};

/// Errors the PDE solver layer can return.
#[derive(Debug, Error, PartialEq)]
pub enum FieldError {
    /// Caller supplied a graph with a different number of source
    /// entries than the graph has nodes.
    #[error("source vector length {source_len} != node count {node_count}")]
    SourceLengthMismatch {
        /// Length the caller supplied.
        source_len: usize,
        /// Number of nodes the graph carries.
        node_count: usize,
    },
    /// CG solver hit max iterations without converging to the
    /// requested tolerance.
    #[error("CG did not converge after {iterations} iters (residual {residual:.3e}, target {tolerance:.3e})")]
    NotConverged {
        /// Iterations performed.
        iterations: usize,
        /// Residual at the iteration cap.
        residual: f64,
        /// Tolerance the caller requested.
        tolerance: f64,
    },
    /// Caller supplied `D ≤ 0` or `Γ < 0`. Both must be physical.
    #[error("non-physical diffusion / damping constants: D={d}, Gamma={gamma}")]
    NonPhysicalConstants {
        /// Diffusion coefficient.
        d: f64,
        /// Damping rate.
        gamma: f64,
    },
    /// `Γ = 0` AND `D = 0` — operator is singular (the null vector
    /// is in the kernel of pure Laplacian). Caller must supply at
    /// least one of them positive.
    #[error("operator is singular: both D and Gamma are zero")]
    SingularOperator,
    /// Adjacency / degree mismatch — graph data structure
    /// inconsistent.
    #[error("graph has {node_count} nodes but {edge_count} edges reference out-of-range indices")]
    InvalidGraph {
        /// Number of declared nodes.
        node_count: usize,
        /// Edge count.
        edge_count: usize,
    },
}

/// Sparse graph Laplacian backing the field solve.
///
/// For each node `i`:
/// - `L[i, i] = sum of edge weights incident to i` (degree)
/// - `L[i, j] = -w(i, j)` for each neighbor `j`
///
/// The Laplacian is symmetric (we enforce by adding each edge to
/// both endpoints) and positive semi-definite. Stored in CSR-like
/// per-row neighbor lists; production swarms have low average degree
/// so dense rows aren't worth optimising for.
#[derive(Debug, Clone)]
pub struct GraphLaplacian {
    /// Number of nodes in the graph.
    n: usize,
    /// `neighbors[i] = Vec<(j, w)>` — outgoing edges from `i` to `j`
    /// with weight `w`. Stored symmetrically: every `(i, j, w)`
    /// implies `(j, i, w)`.
    neighbors: Vec<Vec<(usize, f64)>>,
    /// Diagonal entries (degrees), pre-computed.
    degrees: Vec<f64>,
}

impl GraphLaplacian {
    /// Build a Laplacian over `n` nodes with no edges. Use
    /// [`Self::add_edge`] to populate.
    #[must_use]
    pub fn new(n: usize) -> Self {
        Self {
            n,
            neighbors: vec![Vec::new(); n],
            degrees: vec![0.0; n],
        }
    }

    /// Add a weighted undirected edge `(i, j)`. Symmetric: stored on
    /// both endpoints. Self-loops are tolerated but contribute 0 to
    /// the Laplacian (they cancel in `L = D − A` because both the
    /// diagonal degree term and the off-diagonal `−A` term get +w).
    pub fn add_edge(&mut self, i: usize, j: usize, weight: f64) -> Result<(), FieldError> {
        if i >= self.n || j >= self.n {
            return Err(FieldError::InvalidGraph {
                node_count: self.n,
                edge_count: 1,
            });
        }
        if weight <= 0.0 {
            // Non-positive weight wouldn't preserve PSD; refuse.
            return Err(FieldError::NonPhysicalConstants {
                d: weight,
                gamma: 0.0,
            });
        }
        if i == j {
            // Self-loop: doesn't change the Laplacian; document the
            // behaviour by accepting the call.
            return Ok(());
        }
        self.neighbors[i].push((j, weight));
        self.neighbors[j].push((i, weight));
        self.degrees[i] += weight;
        self.degrees[j] += weight;
        Ok(())
    }

    /// Number of nodes.
    #[must_use]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Read-only access to one node's neighbor list.
    #[must_use]
    pub fn neighbors(&self, i: usize) -> &[(usize, f64)] {
        &self.neighbors[i]
    }

    /// Degree at node `i`.
    #[must_use]
    pub fn degree(&self, i: usize) -> f64 {
        self.degrees[i]
    }

    /// Compute `y = L · x` (sparse matrix-vector product). The
    /// Laplacian acts as `(L · x)[i] = degree[i] · x[i] − Σ_j w[i,j] · x[j]`.
    pub fn matvec(&self, x: &[f64], y: &mut [f64]) {
        debug_assert_eq!(x.len(), self.n);
        debug_assert_eq!(y.len(), self.n);
        for i in 0..self.n {
            let mut acc = self.degrees[i] * x[i];
            for &(j, w) in &self.neighbors[i] {
                acc -= w * x[j];
            }
            y[i] = acc;
        }
    }
}

/// Result of a field solve.
#[derive(Debug, Clone)]
pub struct SolveResult {
    /// The recovered field `δτ_c` (one entry per graph node).
    pub field: Vec<f64>,
    /// Final L2 residual of the operator equation.
    pub residual: f64,
    /// CG iterations performed.
    pub iterations: usize,
    /// `true` if the residual is below the caller's tolerance.
    pub converged: bool,
}
