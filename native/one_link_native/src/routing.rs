//! `one_link_native.routing` — pyo3 binding for `ol_routing`.
//!
//! Surfaces tau-field routing primitives (ADR-0028) to the daemon:
//! cost math + Dijkstra shortest-path over adjacency-list graphs.

use ol_routing::{
    edge_cost, edge_weight, loss_penalty, max_byzantine_count, prefer_first, quorum_safe,
    rgg_connectivity_radius, rgg_mean_degree, shortest_path, should_swap_hop,
    tau_claim_corroborated, AdjacencyGraph as RustGraph,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyList;

#[pyclass(
    from_py_object,
    name = "AdjacencyGraph",
    module = "one_link_native.routing"
)]
#[derive(Debug, Clone)]
pub struct PyGraph {
    inner: RustGraph,
}

#[pymethods]
impl PyGraph {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustGraph::new(),
        }
    }

    fn add_edge(&mut self, from: String, to: String, cost: f64) {
        self.inner.add_edge(from, to, cost);
    }

    fn neighbors<'py>(&self, py: Python<'py>, node: &str) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty(py);
        for (to, cost) in self.inner.neighbors(node) {
            out.append((to.clone(), *cost))?;
        }
        Ok(out)
    }

    fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    /// Dijkstra shortest path. Returns ``(path: list[str], total_cost: float)``
    /// on success, raises ``ValueError`` when no path exists.
    fn shortest_path(&self, start: &str, goal: &str) -> PyResult<(Vec<String>, f64)> {
        match shortest_path(&self.inner, start, goal) {
            Ok(r) => Ok((r.path, r.total_cost)),
            Err(e) => Err(PyValueError::new_err(e.to_string())),
        }
    }

    fn __repr__(&self) -> String {
        format!("AdjacencyGraph(node_count={})", self.inner.node_count())
    }
}

// Cost-math helpers (free functions).

#[pyfunction]
#[pyo3(name = "edge_weight")]
fn py_edge_weight(tau_c_s: f64, dist_m: f64) -> f64 {
    edge_weight(tau_c_s, dist_m)
}

#[pyfunction]
#[pyo3(name = "loss_penalty")]
fn py_loss_penalty(loss_rate: f64) -> f64 {
    loss_penalty(loss_rate)
}

#[pyfunction]
#[pyo3(name = "edge_cost")]
fn py_edge_cost(tau_c_s: f64, dist_m: f64, loss_rate: f64) -> f64 {
    edge_cost(tau_c_s, dist_m, loss_rate)
}

#[pyfunction]
#[pyo3(name = "prefer_first")]
fn py_prefer_first(cost_a: f64, cost_b: f64) -> bool {
    prefer_first(cost_a, cost_b)
}

#[pyfunction]
#[pyo3(name = "should_swap_hop")]
fn py_should_swap_hop(current_cost: f64, candidate_cost: f64, hysteresis_factor: f64) -> bool {
    should_swap_hop(current_cost, candidate_cost, hysteresis_factor)
}

// Byzantine + RGG helpers.

#[pyfunction]
#[pyo3(name = "max_byzantine_count")]
fn py_max_byzantine_count(n_total: i64) -> i64 {
    max_byzantine_count(n_total)
}

#[pyfunction]
#[pyo3(name = "quorum_safe")]
fn py_quorum_safe(n_total: i64, f_faulty: i64) -> bool {
    quorum_safe(n_total, f_faulty)
}

#[pyfunction]
#[pyo3(name = "rgg_mean_degree")]
fn py_rgg_mean_degree(n_nodes: i64, radius: f64) -> f64 {
    rgg_mean_degree(n_nodes, radius)
}

#[pyfunction]
#[pyo3(name = "rgg_connectivity_radius")]
fn py_rgg_connectivity_radius(n_nodes: i64) -> f64 {
    rgg_connectivity_radius(n_nodes)
}

#[pyfunction]
#[pyo3(name = "tau_claim_corroborated")]
fn py_tau_claim_corroborated(
    claimed_tau_c_s: f64,
    observed_success_rate: f64,
    tolerance: f64,
) -> bool {
    tau_claim_corroborated(claimed_tau_c_s, observed_success_rate, tolerance)
}

/// Register the `routing` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_routing::VERSION)?;
    m.add_class::<PyGraph>()?;
    m.add_function(wrap_pyfunction!(py_edge_weight, m)?)?;
    m.add_function(wrap_pyfunction!(py_loss_penalty, m)?)?;
    m.add_function(wrap_pyfunction!(py_edge_cost, m)?)?;
    m.add_function(wrap_pyfunction!(py_prefer_first, m)?)?;
    m.add_function(wrap_pyfunction!(py_should_swap_hop, m)?)?;
    m.add_function(wrap_pyfunction!(py_max_byzantine_count, m)?)?;
    m.add_function(wrap_pyfunction!(py_quorum_safe, m)?)?;
    m.add_function(wrap_pyfunction!(py_rgg_mean_degree, m)?)?;
    m.add_function(wrap_pyfunction!(py_rgg_connectivity_radius, m)?)?;
    m.add_function(wrap_pyfunction!(py_tau_claim_corroborated, m)?)?;
    Ok(())
}
