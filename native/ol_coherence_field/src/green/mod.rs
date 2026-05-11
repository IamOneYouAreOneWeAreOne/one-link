//! Green-function nonlocal kernel evaluator.
//!
//! ## Theory
//!
//! From the S_One first-principles galaxy bridge (2026-03-28):
//!
//! ```text
//! g_coh(x) = (c² / (4π · D · τ_∞)) · ∫ S_b(x') · (x − x') / |x − x'|³ dx'
//! ```
//!
//! That's a 3D inverse-square kernel — the Poisson Green function of
//! free space. On a graph, the analog is the graph Green function:
//! the matrix `G = (Γ · I + D · L)⁻¹`, so that `δτ_c = G · S`.
//!
//! For routing decisions we don't usually need the full `G` matrix —
//! we need `(G · S)[i]` at one or a few destination nodes, which is
//! exactly what [`super::pde::solve_helmholtz`] computes. The Green-
//! function module exposes the explicit "field at destination node `i`
//! due to sources" view, which makes the multi-source routing
//! decision explicit (pick the K peers whose individual Green-function
//! contributions sum to the largest field response at the receiver).

use thiserror::Error;

use crate::pde::{
    helmholtz_reduction::solve_helmholtz,
    sparse_solver::CgConfig,
    FieldError, GraphLaplacian,
};

/// Errors the Green-function evaluator can return.
#[derive(Debug, Error)]
pub enum GreenError {
    /// Underlying PDE solve failed.
    #[error("Green-function PDE solve failed: {0}")]
    FieldError(#[from] FieldError),
    /// Caller asked for the field at an out-of-range node index.
    #[error("destination node {got} out of range (graph has {n} nodes)")]
    OutOfRange {
        /// Node index the caller asked for.
        got: usize,
        /// Total number of nodes in the graph.
        n: usize,
    },
}

/// Evaluate the Green-function response at `destination` due to unit
/// sources placed individually at each of the `sources`. Returns one
/// f64 per source: the contribution of that source to the field at
/// `destination`.
///
/// Production use: pick the K sources with the LARGEST individual
/// contributions; those are the K peers whose participation in
/// sourcing the requested chunk most improves the receiver's
/// coherence-field response.
///
/// Implementation: by linearity of the Helmholtz operator,
/// `G · (Σⱼ eⱼ · sⱼ) = Σⱼ (G · eⱼ) · sⱼ`. We solve N-source separate
/// unit-source problems? No — we leverage the **adjoint**: solve
/// `(Γ I + D L)ᵀ · z = e_destination` once (the operator is
/// symmetric so the adjoint equals the operator), then for each
/// source `j`, `field_at_destination = z[j]`. One solve, N readouts.
pub fn green_function(
    graph: &GraphLaplacian,
    d: f64,
    gamma: f64,
    destination: usize,
    sources: &[usize],
    config: CgConfig,
) -> Result<Vec<f64>, GreenError> {
    if destination >= graph.n() {
        return Err(GreenError::OutOfRange {
            got: destination,
            n: graph.n(),
        });
    }
    for &src in sources {
        if src >= graph.n() {
            return Err(GreenError::OutOfRange {
                got: src,
                n: graph.n(),
            });
        }
    }
    // Solve once with the adjoint source = δ_destination.
    let mut adj_source = vec![0.0; graph.n()];
    adj_source[destination] = 1.0;
    let solve = solve_helmholtz(graph, d, gamma, &adj_source, config)?;
    Ok(sources.iter().map(|&j| solve.field[j]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pde::sparse_solver::CgConfig;

    #[test]
    fn green_response_decreases_with_graph_distance() {
        // Path graph: 0 — 1 — 2 — 3 — 4. Destination = 0. Sources at
        // 1, 2, 3, 4. The Green-function response should decrease
        // monotonically with hop distance from the destination.
        let n = 5;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        let contributions =
            green_function(&g, 1.0, 0.5, 0, &[1, 2, 3, 4], CgConfig::default())
                .unwrap();
        for w in contributions.windows(2) {
            assert!(
                w[1] < w[0],
                "expected monotonic decrease, got {:?}",
                contributions
            );
        }
    }

    #[test]
    fn green_rejects_out_of_range_destination() {
        let g = GraphLaplacian::new(3);
        assert!(matches!(
            green_function(&g, 1.0, 0.5, 99, &[0], CgConfig::default()),
            Err(GreenError::OutOfRange { .. })
        ));
    }

    #[test]
    fn green_self_response_is_largest() {
        // The destination's own self-contribution should be the
        // largest of any source. Path graph.
        let n = 5;
        let mut g = GraphLaplacian::new(n);
        for i in 0..n - 1 {
            g.add_edge(i, i + 1, 1.0).unwrap();
        }
        // Destination = 2 (middle); sources = all nodes.
        let contributions = green_function(
            &g,
            1.0,
            0.5,
            2,
            &[0, 1, 2, 3, 4],
            CgConfig::default(),
        )
        .unwrap();
        let self_contribution = contributions[2];
        for (i, &c) in contributions.iter().enumerate() {
            if i != 2 {
                assert!(
                    self_contribution > c,
                    "self_contribution {self_contribution} should exceed {c} at node {i}"
                );
            }
        }
    }
}
