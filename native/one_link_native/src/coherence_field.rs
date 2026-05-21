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
    anchor::{ApparentHorizonInputs, G_A_GALAXY_PLANCK},
    apparent_horizon_anchor, be_rar,
    calibration::{bio_mesh_calibration, one_field_calibration, one_link_calibration},
    green_function, identity_dual_source, identity_dual_source_with_phase, inject_fragility_events,
    linear_source,
    observations::{FieldObservations, ObservationError},
    pde::CgConfig,
    prefetch_priorities, rotation_cadence_multiplier, screening_length, solve_helmholtz,
    source::SupportPhaseConfig,
    support_phase_kernel,
    wave::{WaveError, WaveStepper as RustWaveStepper},
    Calibration, Domain, FragilityEvent, GraphLaplacian as RustGraphLaplacian, PrefetchPriority,
    RotationCadence,
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

fn calibration_to_dict<'py>(py: Python<'py>, cal: &Calibration) -> PyResult<Bound<'py, PyDict>> {
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

/// pyo3 wrapper around `FieldObservations` (D23 / D24).
///
/// Per-peer τ_c observation buffer with trust-weighted EWMA updates
/// (Gap 4 defense against field poisoning) + coherence-gradient
/// computation (Gap 25 — currently RESEARCH-GRADE, surface as soft
/// signal).
#[pyclass(name = "FieldObservations", module = "one_link_native.coherence_field")]
pub struct PyFieldObservations {
    inner: FieldObservations,
}

#[pymethods]
impl PyFieldObservations {
    /// Construct with a given EWMA learning rate.
    ///
    /// `alpha` must be in (0, 1]; 0.05 is the typical default.
    /// `initial_value` defaults to 0.5 (neutral cold-start).
    #[new]
    #[pyo3(signature = (alpha = 0.05, initial_value = 0.5))]
    fn new(alpha: f32, initial_value: f32) -> PyResult<Self> {
        let inner = FieldObservations::with_initial(alpha, initial_value)
            .map_err(observation_err_to_py)?;
        Ok(Self { inner })
    }

    /// Trust-weighted EWMA update for a peer.
    ///
    /// `trust_weight` in [0, 1]; 1.0 is the standard EWMA. The daemon
    /// computes this from align_native.trust_for(...) before calling
    /// this method.
    #[pyo3(signature = (peer_id, observed_tau, trust_weight = 1.0))]
    fn update(
        &mut self,
        peer_id: &str,
        observed_tau: f32,
        trust_weight: f32,
    ) -> PyResult<()> {
        self.inner
            .update(peer_id, observed_tau, trust_weight)
            .map_err(observation_err_to_py)
    }

    /// Current EWMA τ_c value for a peer, or None if never observed.
    fn tau_at(&self, peer_id: &str) -> Option<f32> {
        self.inner.tau_at(peer_id)
    }

    /// Replace the neighbor list used by gradient computation.
    ///
    /// Empty list disables gradient_at for that peer.
    fn set_neighbors(&mut self, peer_id: &str, neighbors: Vec<String>) {
        self.inner.set_neighbors(peer_id, neighbors);
    }

    /// Coherence-gradient magnitude squared at this peer (D24).
    ///
    /// Returns None if no neighbors configured or none observed.
    /// RESEARCH-GRADE per Gap 25: surface as a soft signal, do not
    /// gate production decisions on a binary threshold.
    fn gradient_at(&self, peer_id: &str) -> Option<f32> {
        self.inner.gradient_at(peer_id)
    }

    /// Number of peers with at least one observation.
    #[getter]
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff no peers observed yet.
    #[getter]
    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Configured EWMA learning rate.
    #[getter]
    fn alpha(&self) -> f32 {
        self.inner.alpha()
    }

    fn __repr__(&self) -> String {
        format!(
            "FieldObservations(len={}, alpha={})",
            self.inner.len(),
            self.inner.alpha()
        )
    }
}

fn observation_err_to_py(err: ObservationError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

fn wave_err_to_py(err: WaveError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// pyo3 wrapper around `WaveStepper` (D25 / RESEARCH-GRADE).
#[pyclass(name = "WaveStepper", module = "one_link_native.coherence_field")]
pub struct PyWaveStepper {
    inner: RustWaveStepper,
}

#[pymethods]
impl PyWaveStepper {
    #[new]
    fn new() -> Self {
        Self {
            inner: RustWaveStepper::new(),
        }
    }

    /// Override the wave speed `c`. Returns self for chaining.
    fn set_wave_speed(&mut self, c: f32) -> PyResult<()> {
        // Re-create with new parameter; with_wave_speed consumes self,
        // so swap inner via mem::take to honor the builder pattern.
        let current = std::mem::take(&mut self.inner);
        self.inner = current.with_wave_speed(c).map_err(wave_err_to_py)?;
        Ok(())
    }

    /// Override the damping coefficient.
    fn set_damping(&mut self, gamma: f32) -> PyResult<()> {
        let current = std::mem::take(&mut self.inner);
        self.inner = current.with_damping(gamma).map_err(wave_err_to_py)?;
        Ok(())
    }

    /// Override the cascade-warning threshold.
    fn set_threshold(&mut self, threshold: f32) {
        let current = std::mem::take(&mut self.inner);
        self.inner = current.with_threshold(threshold);
    }

    /// Configure a value clamp range [min, max]. Pass (min, max) to
    /// enable, or omit to disable. step() will return an error when
    /// any field value drifts outside the range.
    #[pyo3(signature = (min=None, max=None))]
    fn set_clamp_range(&mut self, min: Option<f32>, max: Option<f32>) {
        let current = std::mem::take(&mut self.inner);
        let range = match (min, max) {
            (Some(lo), Some(hi)) => Some((lo, hi)),
            _ => None,
        };
        self.inner = current.with_clamp_range(range);
    }

    /// Configure CFL enforcement. Default true; only disable for
    /// advanced callers (e.g. golden-vector regression).
    fn set_cfl_enforce(&mut self, enforce: bool) {
        let current = std::mem::take(&mut self.inner);
        self.inner = current.with_cfl_enforce(enforce);
    }

    /// Seed the current snapshot from a {node_id: tau} dict.
    fn seed(&mut self, values: std::collections::HashMap<String, f32>) {
        self.inner.seed(&values);
    }

    /// Advance one time step. ``neighbors`` is a {node: [neighbor_ids]}
    /// mapping. Returns the number of nodes whose disturbance crossed
    /// the threshold during this step.
    fn step(
        &mut self,
        dt: f32,
        neighbors: std::collections::HashMap<String, Vec<String>>,
    ) -> PyResult<u32> {
        self.inner.step(dt, &neighbors).map_err(wave_err_to_py)
    }

    /// Current field value at `node`. None if untracked.
    fn psi_at(&self, node: &str) -> Option<f32> {
        self.inner.psi_at(node)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    #[getter]
    fn wave_speed(&self) -> f32 {
        self.inner.wave_speed()
    }

    #[getter]
    fn damping(&self) -> f32 {
        self.inner.damping()
    }

    #[getter]
    fn cascade_threshold(&self) -> f32 {
        self.inner.cascade_threshold()
    }

    #[getter]
    fn cascade_warnings(&self) -> u64 {
        self.inner.cascade_warnings()
    }

    fn reset_warnings(&mut self) {
        self.inner.reset_warnings();
    }

    /// Number of successful step() calls since construction/seed.
    #[getter]
    fn step_count(&self) -> u64 {
        self.inner.step_count()
    }

    /// Courant number `c·dt·√λ_max` for a given dt. Stability
    /// requires this be ≤ 1.
    fn courant_number(&self, dt: f32) -> f32 {
        self.inner.courant_number(dt)
    }

    /// Maximum stable dt for this stepper's wave speed. Returns
    /// +inf when wave_speed is 0.
    fn max_stable_dt(&self) -> f32 {
        self.inner.max_stable_dt()
    }

    /// Total field energy (kinetic + potential). Approximately
    /// conserved when damping is zero; decays monotonically when
    /// damping is positive.
    fn total_energy(
        &self,
        dt: f32,
        neighbors: std::collections::HashMap<String, Vec<String>>,
    ) -> f32 {
        self.inner.total_energy(dt, &neighbors)
    }

    /// Snapshot of all (node, ψ) pairs as a dict.
    fn snapshot(&self) -> std::collections::HashMap<String, f32> {
        self.inner.iter().map(|(k, &v)| (k.clone(), v)).collect()
    }
}

/// Register the `coherence_field` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_coherence_field::VERSION)?;
    m.add("G_A_GALAXY_PLANCK", G_A_GALAXY_PLANCK)?;
    m.add_class::<PyGraphLaplacian>()?;
    m.add_class::<PyFieldObservations>()?;
    m.add_class::<PyWaveStepper>()?;
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
