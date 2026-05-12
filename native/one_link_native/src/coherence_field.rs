//! `one_link_native.coherence_field` — pyo3 binding for
//! `ol_coherence_field` (Phase E of `FILE_ENGINE_V2_PLAN.md`).
//!
//! Surfaces the S_One canonical theorem stack to the daemon:
//!
//! 1. Helmholtz solve `(Γ·I + D·L)·δτ_c = S` on a graph Laplacian.
//! 2. BE-RAR interpolation `nu(y) = 1/(1 − exp(−√y))`.
//! 3. Screening length + apparent-horizon anchor calibration.
//! 4. Identity-sector dual source `S = α·ρ + β·|J|`.
//! 5. Cross-domain calibrations (One Link / OneField / BioMesh).
//! 6. Couplings: homology → field, field → prefetch, field → ratchet.

use ol_coherence_field::{
    apparent_horizon_anchor, be_rar, green_function, identity_dual_source,
    identity_dual_source_with_phase, inject_fragility_events, linear_source,
    prefetch_priorities, rotation_cadence_multiplier, screening_length, solve_helmholtz,
    support_phase_kernel,
    anchor::{ApparentHorizonInputs, G_A_GALAXY_PLANCK},
    calibration::{bio_mesh_calibration, one_field_calibration, one_link_calibration},
    pde::CgConfig,
    source::SupportPhaseConfig,
    Calibration, Domain, FragilityEvent, GraphLaplacian as RustGraphLaplacian,
    PrefetchPriority, RotationCadence,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyDict;

/// pyo3 wrapper around `GraphLaplacian`.
#[pyclass(name = "GraphLaplacian", module = "one_link_native.coherence_field")]
#[derive(Clone)]
pub struct PyGraphLaplacian {
    inner: RustGraphLaplacian,
}

#[pymethods]
impl PyGraphLaplacian {
    #[new]
    fn new(n: usize) -> Self {
        Self {
            inner: RustGraphLaplacian::new(n),
        }
    }

    fn add_edge(&mut self, i: usize, j: usize, weight: f64) -> PyResult<()> {
        self.inner
            .add_edge(i, j, weight)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn node_count(&self) -> usize {
        self.inner.n()
    }

    fn degree(&self, i: usize) -> PyResult<f64> {
        if i >= self.inner.n() {
            return Err(PyValueError::new_err(format!(
                "node index {i} out of range (n = {})",
                self.inner.n()
            )));
        }
        Ok(self.inner.degree(i))
    }

    fn __repr__(&self) -> String {
        format!("GraphLaplacian(node_count={})", self.inner.n())
    }
}

/// Solve the Helmholtz reduction on the given graph + source vector.
///
/// Returns a dict ``{"field": list[float], "residual": float,
/// "iterations": int, "converged": bool}``.
#[pyfunction]
#[pyo3(name = "solve_helmholtz")]
#[pyo3(signature = (graph, d, gamma, source, max_iters=2000, tolerance=1e-6))]
fn py_solve_helmholtz<'py>(
    py: Python<'py>,
    graph: &PyGraphLaplacian,
    d: f64,
    gamma: f64,
    source: Vec<f64>,
    max_iters: usize,
    tolerance: f64,
) -> PyResult<Bound<'py, PyDict>> {
    let cfg = CgConfig {
        max_iter: max_iters,
        tolerance,
    };
    let result = solve_helmholtz(&graph.inner, d, gamma, &source, cfg)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let out = PyDict::new_bound(py);
    out.set_item("field", result.field)?;
    out.set_item("residual", result.residual)?;
    out.set_item("iterations", result.iterations)?;
    out.set_item("converged", result.converged)?;
    Ok(out)
}

/// Green-function nonlocal kernel: compute the field response at
/// ``destination`` to point sources at each entry of ``sources``.
#[pyfunction]
#[pyo3(name = "green_function")]
#[pyo3(signature = (graph, d, gamma, destination, sources, max_iters=2000, tolerance=1e-6))]
fn py_green_function(
    graph: &PyGraphLaplacian,
    d: f64,
    gamma: f64,
    destination: usize,
    sources: Vec<usize>,
    max_iters: usize,
    tolerance: f64,
) -> PyResult<Vec<f64>> {
    let cfg = CgConfig {
        max_iter: max_iters,
        tolerance,
    };
    green_function(&graph.inner, d, gamma, destination, &sources, cfg)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(name = "be_rar")]
fn py_be_rar(y: f64) -> PyResult<f64> {
    be_rar(y).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(name = "screening_length")]
fn py_screening_length(d: f64, gamma: f64) -> Option<f64> {
    screening_length(d, gamma)
}

#[pyfunction]
#[pyo3(name = "apparent_horizon_anchor")]
fn py_apparent_horizon_anchor(c_wire: f64, h_swarm: f64) -> Option<f64> {
    apparent_horizon_anchor(ApparentHorizonInputs { c_wire, h_swarm })
}

#[pyfunction]
#[pyo3(name = "linear_source")]
fn py_linear_source(density: Vec<f64>, weight: f64) -> PyResult<Vec<f64>> {
    linear_source(&density, weight).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(name = "identity_dual_source")]
fn py_identity_dual_source(
    density: Vec<f64>,
    flux: Vec<f64>,
    alpha: f64,
    beta: f64,
) -> PyResult<Vec<f64>> {
    identity_dual_source(&density, &flux, alpha, beta)
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(name = "identity_dual_source_with_phase")]
#[pyo3(signature = (density, flux, c_support, alpha, beta, c0=0.80, w_phase=0.12))]
fn py_identity_dual_source_with_phase(
    density: Vec<f64>,
    flux: Vec<f64>,
    c_support: Vec<f64>,
    alpha: f64,
    beta: f64,
    c0: f64,
    w_phase: f64,
) -> PyResult<Vec<f64>> {
    identity_dual_source_with_phase(
        &density,
        &flux,
        &c_support,
        alpha,
        beta,
        SupportPhaseConfig { c0, w_phase },
    )
    .map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pyfunction]
#[pyo3(name = "support_phase_kernel")]
#[pyo3(signature = (c_support, c0=0.80, w_phase=0.12))]
fn py_support_phase_kernel(c_support: Vec<f64>, c0: f64, w_phase: f64) -> Vec<f64> {
    support_phase_kernel(&c_support, SupportPhaseConfig { c0, w_phase })
}

#[pyfunction]
#[pyo3(name = "inject_fragility_events")]
fn py_inject_fragility_events(
    mut source: Vec<f64>,
    events: Vec<(Vec<usize>, f64)>,
    coupling_strength: f64,
) -> (Vec<f64>, Vec<f64>) {
    let evs: Vec<FragilityEvent> = events
        .into_iter()
        .map(|(affected_nodes, severity)| FragilityEvent {
            affected_nodes,
            severity,
        })
        .collect();
    let applied = inject_fragility_events(&mut source, &evs, coupling_strength);
    (source, applied)
}

#[pyfunction]
#[pyo3(name = "prefetch_priorities")]
fn py_prefetch_priorities(
    field: Vec<f64>,
    requester: usize,
    holders: Vec<usize>,
    route_weight: f64,
) -> Vec<(usize, f64, f64)> {
    let result: Vec<PrefetchPriority> =
        prefetch_priorities(&field, requester, &holders, route_weight);
    result
        .into_iter()
        .map(|p| (p.holder, p.normalised_field, p.cost))
        .collect()
}

#[pyfunction]
#[pyo3(name = "rotation_cadence_multiplier")]
fn py_rotation_cadence_multiplier(
    field: Vec<f64>,
    baseline_bytes: u64,
    mu_max: f64,
    power: f64,
) -> Vec<(usize, f64, u64)> {
    let result: Vec<RotationCadence> =
        rotation_cadence_multiplier(&field, baseline_bytes, mu_max, power);
    result
        .into_iter()
        .map(|c| (c.peer, c.multiplier, c.bytes_between_rotations))
        .collect()
}

fn domain_to_str(domain: Domain) -> &'static str {
    match domain {
        Domain::OneLink => "one_link",
        Domain::OneField => "one_field",
        Domain::BioMesh => "bio_mesh",
    }
}

fn calibration_to_dict<'py>(
    py: Python<'py>,
    cal: &Calibration,
) -> PyResult<Bound<'py, PyDict>> {
    let out = PyDict::new_bound(py);
    out.set_item("domain", domain_to_str(cal.domain))?;
    out.set_item("d", cal.d)?;
    out.set_item("gamma", cal.gamma)?;
    out.set_item("alpha_density", cal.alpha_density)?;
    out.set_item("beta_flux", cal.beta_flux)?;
    out.set_item("support_phase_c0", cal.support_phase_c0)?;
    out.set_item("support_phase_w", cal.support_phase_w)?;
    out.set_item("c_propagation", cal.c_propagation)?;
    out.set_item("h_0_equivalent", cal.h_0_equivalent)?;
    out.set_item("screening_length", cal.screening_length())?;
    out.set_item("apparent_horizon_anchor", cal.apparent_horizon_anchor())?;
    Ok(out)
}

#[pyfunction]
#[pyo3(name = "one_link_calibration")]
fn py_one_link_calibration(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    calibration_to_dict(py, &one_link_calibration())
}

#[pyfunction]
#[pyo3(name = "one_field_calibration")]
fn py_one_field_calibration(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    calibration_to_dict(py, &one_field_calibration())
}

#[pyfunction]
#[pyo3(name = "bio_mesh_calibration")]
fn py_bio_mesh_calibration(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    calibration_to_dict(py, &bio_mesh_calibration())
}

/// Register the `coherence_field` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_coherence_field::VERSION)?;
    m.add("G_A_GALAXY_PLANCK", G_A_GALAXY_PLANCK)?;
    m.add_class::<PyGraphLaplacian>()?;
    m.add_function(wrap_pyfunction!(py_solve_helmholtz, m)?)?;
    m.add_function(wrap_pyfunction!(py_green_function, m)?)?;
    m.add_function(wrap_pyfunction!(py_be_rar, m)?)?;
    m.add_function(wrap_pyfunction!(py_screening_length, m)?)?;
    m.add_function(wrap_pyfunction!(py_apparent_horizon_anchor, m)?)?;
    m.add_function(wrap_pyfunction!(py_linear_source, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_dual_source, m)?)?;
    m.add_function(wrap_pyfunction!(py_identity_dual_source_with_phase, m)?)?;
    m.add_function(wrap_pyfunction!(py_support_phase_kernel, m)?)?;
    m.add_function(wrap_pyfunction!(py_inject_fragility_events, m)?)?;
    m.add_function(wrap_pyfunction!(py_prefetch_priorities, m)?)?;
    m.add_function(wrap_pyfunction!(py_rotation_cadence_multiplier, m)?)?;
    m.add_function(wrap_pyfunction!(py_one_link_calibration, m)?)?;
    m.add_function(wrap_pyfunction!(py_one_field_calibration, m)?)?;
    m.add_function(wrap_pyfunction!(py_bio_mesh_calibration, m)?)?;
    Ok(())
}
