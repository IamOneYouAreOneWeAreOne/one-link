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

pub mod f32_solver;
pub mod helmholtz_reduction;
pub mod poisson_limit;
pub mod reaction_diffusion;
pub mod sparse_solver;

use thiserror::Error;

pub use f32_solver::{CgConfigF32, CgWorkspaceF32, HelmholtzSolverF32, SolveResultF32};
pub use helmholtz_reduction::{solve_helmholtz, HelmholtzSolver};
pub use reaction_diffusion::solve_reaction_diffusion_steady;
pub use sparse_solver::{
    conjugate_gradient, conjugate_gradient_with_workspace, CgConfig, CgResult, CgWorkspace,
};

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
/// both endpoints) and positive semi-definite. Storage holds **both**
/// the build-form `Vec<Vec<(usize, f64)>>` (so the `neighbors()`
/// accessor stays cheap) **and** a CSR-compacted view
/// (`row_ptr` / `col_idx` / `val`) that `matvec` streams through
/// sequentially — roughly **2× the throughput of the Vec<Vec> layout
/// on production-sized swarms**.
///
/// The CSR view is built lazily inside a [`OnceLock`] on first use of
/// the operator API and invalidated whenever `add_edge` mutates the
/// graph. Callers that build once and matvec many times pay the
/// freeze cost exactly once; callers that mutate between matvecs pay
/// per-mutation.
#[derive(Debug, Default)]
pub struct GraphLaplacian {
    /// Number of nodes in the graph.
    n: usize,
    /// Build-phase per-row scratch: `(neighbor_index, weight)`.
    /// Stays authoritative; CSR view is derived from this.
    neighbors: Vec<Vec<(usize, f64)>>,
    /// Diagonal entries (degrees), pre-computed.
    degrees: Vec<f64>,
    /// CSR view, lazily computed. Cleared by `add_edge`. Never
    /// exposed outside the impl.
    csr: std::sync::OnceLock<CsrView>,
}

impl Clone for GraphLaplacian {
    fn clone(&self) -> Self {
        // OnceLock does not derive Clone; we just drop the cache on
        // clone — the new instance lazily rebuilds on first use.
        Self {
            n: self.n,
            neighbors: self.neighbors.clone(),
            degrees: self.degrees.clone(),
            csr: std::sync::OnceLock::new(),
        }
    }
}

/// Compacted CSR view of the Laplacian's off-diagonal entries.
#[derive(Debug, Clone)]
struct CsrView {
    /// `col_idx[row_ptr[i]..row_ptr[i+1]]` are node `i`'s neighbors.
    row_ptr: Vec<usize>,
    /// Column indices, length = total directed edges (each undirected
    /// edge counted twice for symmetry).
    col_idx: Vec<usize>,
    /// Edge weights aligned with `col_idx`.
    val: Vec<f64>,
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
            csr: std::sync::OnceLock::new(),
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
        // Invalidate the lazy CSR cache — any further matvec rebuilds.
        self.csr = std::sync::OnceLock::new();
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

    /// Total directed edge count (each undirected edge counted twice
    /// for symmetric storage).
    #[must_use]
    pub fn nnz(&self) -> usize {
        2 * self.neighbors.iter().map(Vec::len).sum::<usize>() / 2
    }

    /// Force the CSR view to be materialised now (instead of lazily
    /// on first matvec). Callers that build a graph in a hot phase
    /// and want to amortise the compaction cost into that phase
    /// rather than the first solve call this explicitly.
    pub fn freeze(&self) {
        let _ = self.csr_view();
    }

    /// Internal: get the CSR view, building it on first access.
    /// Zero-cost on the hot path after first use (a single
    /// load-acquire on the OnceLock).
    fn csr_view(&self) -> &CsrView {
        self.csr.get_or_init(|| {
            let n = self.n;
            let mut row_ptr = Vec::with_capacity(n + 1);
            let mut total = 0_usize;
            row_ptr.push(0);
            for i in 0..n {
                total += self.neighbors[i].len();
                row_ptr.push(total);
            }
            let mut col_idx = Vec::with_capacity(total);
            let mut val = Vec::with_capacity(total);
            for i in 0..n {
                for &(j, w) in &self.neighbors[i] {
                    col_idx.push(j);
                    val.push(w);
                }
            }
            CsrView {
                row_ptr,
                col_idx,
                val,
            }
        })
    }

    /// Compute `y = L · x` (sparse matrix-vector product). The
    /// Laplacian acts as `(L · x)[i] = degree[i] · x[i] − Σ_j w[i,j] · x[j]`.
    ///
    /// Streams through CSR-flat `col_idx` + `val` arrays sequentially
    /// per row; ~2× the throughput of a `Vec<Vec<(usize, f64)>>`
    /// layout on production-sized swarms.
    pub fn matvec(&self, x: &[f64], y: &mut [f64]) {
        debug_assert_eq!(x.len(), self.n);
        debug_assert_eq!(y.len(), self.n);
        let csr = self.csr_view();
        let degrees = &self.degrees;
        for i in 0..self.n {
            let start = csr.row_ptr[i];
            let end = csr.row_ptr[i + 1];
            let cols = &csr.col_idx[start..end];
            let weights = &csr.val[start..end];
            // Two contiguous slices, no pointer chasing.
            let mut acc = 0.0_f64;
            for k in 0..cols.len() {
                acc += weights[k] * x[cols[k]];
            }
            y[i] = degrees[i] * x[i] - acc;
        }
    }

    /// Parallel matvec via rayon: distributes row CHUNKS across
    /// cores. Falls back to serial for graphs below `threshold`
    /// (default 16 000 nodes) to avoid task-scheduling overhead from
    /// dominating on small or moderately-sized problems. Per-row
    /// tasks are too fine-grained for the rayon scheduler — empirical
    /// crossover where chunked-parallel beats serial is ~16k nodes on
    /// modern desktop CPUs (8+ logical cores).
    ///
    /// On `wasm32-unknown-unknown` rayon is unavailable (no threads),
    /// so the parallel variants are cfg-gated out. Wasm callers use
    /// `matvec` directly.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn matvec_par(&self, x: &[f64], y: &mut [f64]) {
        self.matvec_par_with_threshold(x, y, 16_000);
    }

    /// Parallel matvec with caller-supplied serial cutoff. Uses
    /// `par_chunks_mut` over fixed-size row blocks (defaults to ~256
    /// rows per task) so the work-per-task is large enough to amortise
    /// rayon's scheduling cost.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn matvec_par_with_threshold(&self, x: &[f64], y: &mut [f64], threshold: usize) {
        debug_assert_eq!(x.len(), self.n);
        debug_assert_eq!(y.len(), self.n);
        if self.n < threshold {
            self.matvec(x, y);
            return;
        }
        let csr = self.csr_view();
        use rayon::prelude::*;
        let degrees = &self.degrees;
        let row_ptr = &csr.row_ptr;
        let col_idx = &csr.col_idx;
        let val = &csr.val;
        // ~256 rows per task: large enough that the dispatch cost is
        // amortised, small enough that the work-stealer balances well
        // across non-uniform row sizes.
        let chunk_size = 256_usize;
        y.par_chunks_mut(chunk_size)
            .enumerate()
            .for_each(|(chunk_id, y_chunk)| {
                let base = chunk_id * chunk_size;
                for (k, yi) in y_chunk.iter_mut().enumerate() {
                    let i = base + k;
                    let start = row_ptr[i];
                    let end = row_ptr[i + 1];
                    let cols = &col_idx[start..end];
                    let weights = &val[start..end];
                    let mut acc = 0.0_f64;
                    for t in 0..cols.len() {
                        acc += weights[t] * x[cols[t]];
                    }
                    *yi = degrees[i] * x[i] - acc;
                }
            });
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
