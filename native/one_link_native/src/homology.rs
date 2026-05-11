//! `one_link_native.homology` — pyo3 binding for `ol_homology`.
//!
//! Surfaces the chunk-co-hold graph durability detectors (ADR-0033
//! Phase D #4).

use std::collections::HashMap;

use ol_homology::{components_of, fragility_score, ComponentReport, FragilityScore};
use pyo3::prelude::*;
use pyo3::types::PyList;

#[pyclass(name = "ComponentReport", module = "one_link_native.homology")]
#[derive(Debug, Clone)]
pub struct PyComponentReport {
    #[pyo3(get)]
    pub n_components: usize,
    #[pyo3(get)]
    pub sizes: Vec<usize>,
    #[pyo3(get)]
    pub singletons: Vec<String>,
}

impl From<ComponentReport> for PyComponentReport {
    fn from(r: ComponentReport) -> Self {
        Self {
            n_components: r.n_components,
            sizes: r.sizes,
            singletons: r.singletons,
        }
    }
}

#[pymethods]
impl PyComponentReport {
    fn __repr__(&self) -> String {
        format!(
            "ComponentReport(n_components={}, singletons={})",
            self.n_components,
            self.singletons.len()
        )
    }
}

#[pyclass(name = "FragilityScore", module = "one_link_native.homology")]
#[derive(Debug, Clone)]
pub struct PyFragilityScore {
    #[pyo3(get)]
    pub chunk_id: String,
    #[pyo3(get)]
    pub n_peers_holding: usize,
    #[pyo3(get)]
    pub is_bridge: bool,
    #[pyo3(get)]
    pub score: f64,
}

impl From<FragilityScore> for PyFragilityScore {
    fn from(s: FragilityScore) -> Self {
        Self {
            chunk_id: s.chunk_id,
            n_peers_holding: s.n_peers_holding,
            is_bridge: s.is_bridge,
            score: s.score,
        }
    }
}

#[pymethods]
impl PyFragilityScore {
    fn __repr__(&self) -> String {
        format!(
            "FragilityScore(chunk_id={:?}, n_peers_holding={}, is_bridge={}, score={:.3})",
            self.chunk_id, self.n_peers_holding, self.is_bridge, self.score
        )
    }
}

/// Compute union-find connected components of a chunk-co-hold graph.
#[pyfunction]
#[pyo3(name = "components_of")]
fn py_components_of(
    nodes: Vec<String>,
    edges: Vec<(String, String)>,
) -> PyComponentReport {
    components_of(&nodes, &edges).into()
}

/// Compute per-chunk fragility scores. Returns
/// ``(scores: list[FragilityScore], replication_priority: list[str])``.
#[pyfunction]
#[pyo3(name = "fragility_score")]
fn py_fragility_score<'py>(
    py: Python<'py>,
    nodes: Vec<String>,
    edges: Vec<(String, String)>,
    holders: HashMap<String, usize>,
) -> PyResult<(Bound<'py, PyList>, Vec<String>)> {
    let report = fragility_score(&nodes, &edges, &holders);
    let scores_py = PyList::empty_bound(py);
    for s in report.scores {
        let py_s: PyFragilityScore = s.into();
        scores_py.append(Py::new(py, py_s)?)?;
    }
    Ok((scores_py, report.replication_priority))
}

/// Register the `homology` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyComponentReport>()?;
    m.add_class::<PyFragilityScore>()?;
    m.add_function(wrap_pyfunction!(py_components_of, m)?)?;
    m.add_function(wrap_pyfunction!(py_fragility_score, m)?)?;
    Ok(())
}
