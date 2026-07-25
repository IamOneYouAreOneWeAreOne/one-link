//! `one_link_native.fec` — Python binding for the `ol_fec` Rust crate.
//!
//! Surfaces Reed-Solomon encode + decode for the durability layer per
//! ADR-0016. Python callers build a `Codec(k, m)`, pass data shards
//! (`list[bytes]`), and receive the parity shards (`list[bytes]`).
//! Decoding takes the same `(k, m)` codec + a `list[bytes | None]` of
//! `k + m` slots and returns the recovered data shards.

use ol_fec::{Codec, FecError, MAX_FEC_SHARD_BYTES, MAX_FEC_WORKING_SET_BYTES};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

/// Python-visible Reed-Solomon codec.
#[pyclass(name = "Codec", module = "one_link_native.fec")]
#[derive(Debug)]
pub struct PyCodec {
    inner: Codec,
}

#[pymethods]
impl PyCodec {
    /// Build a codec for `(k, m)`.
    #[new]
    fn new(k: usize, m: usize) -> PyResult<Self> {
        Codec::new(k, m)
            .map(|inner| Self { inner })
            .map_err(fec_err_to_py)
    }

    /// Data-shard count.
    #[getter]
    fn k(&self) -> usize {
        self.inner.k()
    }

    /// Parity-shard count.
    #[getter]
    fn m(&self) -> usize {
        self.inner.m()
    }

    /// Total shards = k + m.
    #[getter]
    fn total_shards(&self) -> usize {
        self.inner.total_shards()
    }

    /// Encode `data_shards` (length-k list of equal-length `bytes`) into
    /// m parity shards (returned as a `list[bytes]`).
    fn encode<'py>(
        &self,
        py: Python<'py>,
        data_shards: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyList>> {
        if data_shards.len() != self.inner.k() {
            return Err(fec_err_to_py(FecError::DataShardCount {
                expected: self.inner.k(),
                got: data_shards.len(),
            }));
        }
        let mut shards = Vec::with_capacity(self.inner.k());
        for item in data_shards.iter() {
            let shard = item.extract::<&[u8]>()?;
            if shard.len() > MAX_FEC_SHARD_BYTES {
                return Err(fec_err_to_py(FecError::ShardTooLarge {
                    got: shard.len(),
                    max: MAX_FEC_SHARD_BYTES,
                }));
            }
            shards.push(shard.to_vec());
        }
        let refs: Vec<&[u8]> = shards.iter().map(std::vec::Vec::as_slice).collect();
        let parity = py
            .detach(|| self.inner.encode(&refs))
            .map_err(fec_err_to_py)?;
        let out = PyList::empty(py);
        for p in parity {
            out.append(PyBytes::new(py, &p))?;
        }
        Ok(out)
    }

    /// Decode from a `list[bytes | None]` of length `k + m`. Returns
    /// the recovered k data shards as `list[bytes]`.
    fn decode<'py>(
        &self,
        py: Python<'py>,
        present: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyList>> {
        let total = self.inner.total_shards();
        if present.len() != total {
            return Err(PyValueError::new_err(format!(
                "present must have exactly {total} slots, got {}",
                present.len()
            )));
        }
        let mut owned: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
        for item in present.iter() {
            if item.is_none() {
                owned.push(None);
            } else {
                let shard = item.extract::<&[u8]>()?;
                if shard.len() > MAX_FEC_SHARD_BYTES {
                    return Err(fec_err_to_py(FecError::ShardTooLarge {
                        got: shard.len(),
                        max: MAX_FEC_SHARD_BYTES,
                    }));
                }
                owned.push(Some(shard.to_vec()));
            }
        }
        let view: Vec<Option<&[u8]>> = owned
            .iter()
            .map(|o| o.as_ref().map(std::vec::Vec::as_slice))
            .collect();
        let data = py
            .detach(|| self.inner.decode(&view))
            .map_err(fec_err_to_py)?;
        let out = PyList::empty(py);
        for d in data {
            out.append(PyBytes::new(py, &d))?;
        }
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!("Codec(k={}, m={})", self.inner.k(), self.inner.m())
    }
}

fn fec_err_to_py(err: FecError) -> PyErr {
    crate::errors::OlFecError::new_err(crate::errors::owned_error_message(err))
}

/// Register the `fec` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_fec::VERSION)?;
    m.add("MAX_FEC_SHARD_BYTES", MAX_FEC_SHARD_BYTES)?;
    m.add("MAX_FEC_WORKING_SET_BYTES", MAX_FEC_WORKING_SET_BYTES)?;
    m.add_class::<PyCodec>()?;
    Ok(())
}
