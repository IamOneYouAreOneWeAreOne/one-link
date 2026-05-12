//! `one_link_native.erasure` — Python binding for `ol_erasure`.
//!
//! Exposes chunk-level Reed-Solomon stripe encode + decode per
//! ADR-0018. Python callers provide a plaintext + `StripeParams` and
//! receive a list of `Shard` objects; decode reverses with any
//! `k`-of-`k+m` subset.

use ol_erasure::{
    decode_stripe as rust_decode, encode_stripe as rust_encode, stripe::stripe_id_of, ErasureError,
    Shard as RustShard, ShardRole, StripeParams,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

/// Python-visible stripe parameters. Three canonical profiles are
/// exposed as classmethods; arbitrary `(k, m)` via the constructor.
#[pyclass(name = "StripeParams", module = "one_link_native.erasure")]
#[derive(Debug, Clone, Copy)]
pub struct PyStripeParams {
    inner: StripeParams,
}

#[pymethods]
impl PyStripeParams {
    #[new]
    fn new(k: usize, m: usize) -> Self {
        Self {
            inner: StripeParams { k, m },
        }
    }

    /// `EPHEMERAL` profile (9 + 1; 1.11x).
    #[classattr]
    const EPHEMERAL: Self = Self {
        inner: StripeParams::EPHEMERAL,
    };

    /// `STANDARD` profile (10 + 4; 1.40x).
    #[classattr]
    const STANDARD: Self = Self {
        inner: StripeParams::STANDARD,
    };

    /// `ARCHIVAL` profile (6 + 6; 2.00x).
    #[classattr]
    const ARCHIVAL: Self = Self {
        inner: StripeParams::ARCHIVAL,
    };

    #[getter]
    fn k(&self) -> usize {
        self.inner.k
    }

    #[getter]
    fn m(&self) -> usize {
        self.inner.m
    }

    fn __repr__(&self) -> String {
        format!("StripeParams(k={}, m={})", self.inner.k, self.inner.m)
    }
}

/// Python-visible shard. Exposes the bytes + role + index + stripe id.
#[pyclass(name = "Shard", module = "one_link_native.erasure")]
#[derive(Debug, Clone)]
pub struct PyShard {
    inner: RustShard,
}

#[pymethods]
impl PyShard {
    #[getter]
    fn bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.bytes)
    }

    /// `"data"` or `"parity"`.
    #[getter]
    fn role(&self) -> &'static str {
        match self.inner.role {
            ShardRole::Data => "data",
            ShardRole::Parity => "parity",
        }
    }

    #[getter]
    fn index(&self) -> u8 {
        self.inner.index
    }

    #[getter]
    fn plaintext_len(&self) -> u64 {
        self.inner.plaintext_len
    }

    #[getter]
    fn stripe_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.stripe_id)
    }

    fn __repr__(&self) -> String {
        format!(
            "Shard(role={}, index={}, len={})",
            self.role(),
            self.inner.index,
            self.inner.bytes.len()
        )
    }
}

/// Encode `plaintext` into a stripe of `k + m` shards.
#[pyfunction]
fn encode_stripe<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    params: &PyStripeParams,
) -> PyResult<Bound<'py, PyList>> {
    let shards = py
        .allow_threads(|| rust_encode(plaintext, params.inner))
        .map_err(erasure_err_to_py)?;
    let out = PyList::empty_bound(py);
    for shard in shards {
        out.append(Py::new(py, PyShard { inner: shard })?)?;
    }
    Ok(out)
}

/// Decode a stripe back to plaintext. `present` is a list of length
/// `k + m`; entries may be `Shard` or `None`.
#[pyfunction]
fn decode_stripe<'py>(
    py: Python<'py>,
    params: &PyStripeParams,
    present: &Bound<'py, PyList>,
) -> PyResult<Bound<'py, PyBytes>> {
    let total = params.inner.k + params.inner.m;
    if present.len() != total {
        return Err(PyValueError::new_err(format!(
            "expected {total} present slots, got {}",
            present.len()
        )));
    }
    // Extract owned PyShard refs to keep them alive across the call.
    let mut owned: Vec<Option<PyShard>> = Vec::with_capacity(total);
    for item in present.iter() {
        if item.is_none() {
            owned.push(None);
        } else {
            let shard: PyShard = item.extract()?;
            owned.push(Some(shard));
        }
    }
    let view: Vec<Option<&RustShard>> =
        owned.iter().map(|o| o.as_ref().map(|s| &s.inner)).collect();
    let plaintext = py
        .allow_threads(|| rust_decode(params.inner, &view))
        .map_err(erasure_err_to_py)?;
    Ok(PyBytes::new_bound(py, &plaintext))
}

/// Compute the canonical StripeId for `(plaintext, params)`.
#[pyfunction]
fn stripe_id<'py>(
    py: Python<'py>,
    plaintext: &[u8],
    params: &PyStripeParams,
) -> Bound<'py, PyBytes> {
    let id = stripe_id_of(plaintext, params.inner);
    PyBytes::new_bound(py, &id)
}

fn erasure_err_to_py(err: ErasureError) -> PyErr {
    crate::errors::OlErasureError::new_err(err.to_string())
}

/// Register the `erasure` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_erasure::VERSION)?;
    m.add_class::<PyStripeParams>()?;
    m.add_class::<PyShard>()?;
    m.add_function(wrap_pyfunction!(encode_stripe, m)?)?;
    m.add_function(wrap_pyfunction!(decode_stripe, m)?)?;
    m.add_function(wrap_pyfunction!(stripe_id, m)?)?;
    Ok(())
}
