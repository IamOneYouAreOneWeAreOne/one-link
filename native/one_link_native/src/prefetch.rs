//! `one_link_native.prefetch` — pyo3 binding for `ol_prefetch`.
//!
//! Surfaces the active-inference prefetch predictor (ADR-0033 Phase D #3).

use ol_prefetch::{Prediction, PrefetchPredictor as RustPredictor};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

#[pyclass(
    from_py_object,
    name = "Predictor",
    module = "one_link_native.prefetch"
)]
#[derive(Debug, Clone)]
pub struct PyPredictor {
    inner: RustPredictor,
}

fn bytes_to_32(b: &[u8], field: &str) -> PyResult<[u8; 32]> {
    if b.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "{field} must be exactly 32 bytes, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(out)
}

#[pymethods]
impl PyPredictor {
    #[new]
    #[pyo3(signature = (half_life_ms=60_000, decay_factor=0.5))]
    fn new(half_life_ms: u64, decay_factor: f64) -> PyResult<Self> {
        RustPredictor::new(half_life_ms, decay_factor)
            .map(|inner| Self { inner })
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Record one access: peer P accessed file F at time `t_ms`.
    fn observe(&mut self, peer: &[u8], file_id: &[u8], t_ms: u64) -> PyResult<()> {
        let p = bytes_to_32(peer, "peer")?;
        let f = bytes_to_32(file_id, "file_id")?;
        self.inner.observe(&p, f, t_ms);
        Ok(())
    }

    /// Predict the top-N next files for ``peer``. Returns a list of
    /// ``(file_id_bytes, confidence_float)`` tuples sorted by confidence.
    fn predict_top_n<'py>(
        &self,
        py: Python<'py>,
        peer: &[u8],
        n: usize,
    ) -> PyResult<Bound<'py, PyList>> {
        let p = bytes_to_32(peer, "peer")?;
        let preds = self.inner.predict_top_n(&p, n);
        let out = PyList::empty(py);
        for Prediction {
            file_id,
            confidence,
        } in preds
        {
            let fid_py = PyBytes::new(py, &file_id);
            out.append((fid_py, confidence))?;
        }
        Ok(out)
    }

    fn decay_counts(&mut self) {
        self.inner.decay_counts();
    }

    /// Bootstrap a fresh peer (``target_peer``) by mixing
    /// ``source_peer``'s accumulated pairs in at ``weight``.
    fn transfer_prior_from(
        &mut self,
        source_peer: &[u8],
        target_peer: &[u8],
        weight: f64,
    ) -> PyResult<()> {
        let s = bytes_to_32(source_peer, "source_peer")?;
        let t = bytes_to_32(target_peer, "target_peer")?;
        self.inner.transfer_prior_from(&s, t, weight);
        Ok(())
    }

    fn storage_entries(&self) -> usize {
        self.inner.storage_entries()
    }

    #[getter]
    fn half_life_ms(&self) -> u64 {
        self.inner.half_life_ms
    }

    #[getter]
    fn decay_factor(&self) -> f64 {
        self.inner.decay_factor
    }

    fn __repr__(&self) -> String {
        format!(
            "Predictor(half_life_ms={}, decay_factor={})",
            self.inner.half_life_ms, self.inner.decay_factor
        )
    }
}

/// Register the `prefetch` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_prefetch::VERSION)?;
    m.add(
        "MAX_CO_OCCURRENCE_GAP_MS",
        ol_prefetch::MAX_CO_OCCURRENCE_GAP_MS,
    )?;
    m.add_class::<PyPredictor>()?;
    Ok(())
}
