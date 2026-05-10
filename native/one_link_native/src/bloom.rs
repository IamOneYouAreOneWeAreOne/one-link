//! `one_link_native.bloom` — Python binding for the `ol_bloom` crate.
//!
//! Surfaces the content-addressed Bloom filter used by ADR-0011's
//! transfer-init handshake. Python callers build a filter, insert
//! chunk_ids (32-byte BLAKE3 addresses), and encode/decode the wire
//! format.

use ol_bloom::{Bloom, MAX_FILTER_BYTES};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::bloom_error_to_pyerr;

/// Python-visible Bloom filter sized for a target false-positive rate.
#[pyclass(name = "Bloom", module = "one_link_native.bloom")]
#[derive(Debug)]
pub struct PyBloom {
    inner: Bloom,
}

#[pymethods]
impl PyBloom {
    /// Build an empty Bloom filter sized for `n` chunk_ids at 1% FP rate.
    #[new]
    #[pyo3(signature = (n, target_fp = None))]
    fn new(n: usize, target_fp: Option<f64>) -> Self {
        let inner = match target_fp {
            Some(p) => Bloom::with_target_fp(n, p),
            None => Bloom::new(n),
        };
        Self { inner }
    }

    /// Insert a 32-byte chunk_id.
    fn insert(&mut self, py: Python<'_>, chunk_id: &Bound<'_, PyAny>) -> PyResult<()> {
        let id = chunk_id_from_buffer(py, chunk_id)?;
        self.inner.insert(&id);
        Ok(())
    }

    /// Test whether a 32-byte chunk_id is (probably) present.
    fn contains(&self, py: Python<'_>, chunk_id: &Bound<'_, PyAny>) -> PyResult<bool> {
        let id = chunk_id_from_buffer(py, chunk_id)?;
        Ok(self.inner.contains(&id))
    }

    /// Number of bits in the filter.
    #[getter]
    fn m_bits(&self) -> u32 {
        self.inner.m_bits()
    }

    /// Number of hash functions.
    #[getter]
    fn k(&self) -> u32 {
        self.inner.k()
    }

    /// Number of bits currently set.
    fn popcount(&self) -> u64 {
        self.inner.popcount()
    }

    /// On-wire byte length (header + bit array).
    fn encoded_len(&self) -> usize {
        self.inner.encoded_len()
    }

    /// Encode to wire bytes per ADR-0011.
    fn encode<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner.encode().map_err(bloom_error_to_pyerr)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Decode from wire bytes per ADR-0011.
    #[staticmethod]
    fn decode(py: Python<'_>, encoded: &Bound<'_, PyAny>) -> PyResult<Self> {
        let buf = PyBuffer::<u8>::get_bound(encoded)?;
        if buf.len_bytes() > MAX_FILTER_BYTES {
            return Err(PyValueError::new_err(format!(
                "encoded bloom exceeds {} byte cap",
                MAX_FILTER_BYTES
            )));
        }
        let slice = unsafe {
            std::slice::from_raw_parts(buf.buf_ptr() as *const u8, buf.len_bytes())
        };
        let inner = py
            .allow_threads(|| Bloom::decode(slice))
            .map_err(bloom_error_to_pyerr)?;
        Ok(Self { inner })
    }

    fn __repr__(&self) -> String {
        format!(
            "Bloom(m_bits={}, k={}, popcount={})",
            self.inner.m_bits(),
            self.inner.k(),
            self.inner.popcount(),
        )
    }
}

fn chunk_id_from_buffer(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<[u8; 32]> {
    let buf = PyBuffer::<u8>::get_bound(obj)?;
    if buf.len_bytes() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id must be exactly 32 bytes, got {}",
            buf.len_bytes()
        )));
    }
    let mut out = [0u8; 32];
    let _ = py; // GIL token not needed for this short copy
    let slice = unsafe {
        std::slice::from_raw_parts(buf.buf_ptr() as *const u8, 32)
    };
    out.copy_from_slice(slice);
    Ok(out)
}

/// Sizing helper: optimal `m_bits` for `n` elements + target FP rate.
#[pyfunction]
#[pyo3(signature = (n, target_fp = 0.01))]
fn optimal_m_bits(n: usize, target_fp: f64) -> u32 {
    ol_bloom::optimal_m_bits(n, target_fp)
}

/// Sizing helper: optimal `k` (hash count) for `n` elements + `m_bits`.
#[pyfunction]
fn optimal_k(n: usize, m_bits: u32) -> u32 {
    ol_bloom::optimal_k(n, m_bits)
}

/// Default target false-positive rate (1%).
#[pyfunction]
fn default_target_fp_rate() -> f64 {
    ol_bloom::target_fp_rate()
}

/// Register the `bloom` submodule on the given `PyModule`.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_bloom::VERSION)?;
    m.add("BLOOM_HEADER_LEN", ol_bloom::BLOOM_HEADER_LEN)?;
    m.add("MAX_FILTER_BYTES", ol_bloom::MAX_FILTER_BYTES)?;
    m.add_class::<PyBloom>()?;
    m.add_function(wrap_pyfunction!(optimal_m_bits, m)?)?;
    m.add_function(wrap_pyfunction!(optimal_k, m)?)?;
    m.add_function(wrap_pyfunction!(default_target_fp_rate, m)?)?;
    Ok(())
}
