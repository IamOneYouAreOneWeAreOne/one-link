//! `one_link_native.ratchet` — Python binding for `ol_ratchet`.
//!
//! Exposes the per-chunk forward-secret chain ratchet (ADR-0020).
//! Python callers bootstrap a `Chain` from a shared secret and call
//! `next_message_key()` per chunk.

use ::zeroize::Zeroizing;
use ol_ratchet::{Chain, MessageKey, RatchetError, SkippedKeyStore};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Python-visible chain ratchet.
#[pyclass(name = "Chain", module = "one_link_native.ratchet")]
#[derive(Debug)]
pub struct PyChain {
    inner: Chain,
}

#[pymethods]
impl PyChain {
    /// Bootstrap a chain from a 32-byte shared secret.
    #[staticmethod]
    fn from_shared_secret(shared_secret: &[u8]) -> Self {
        Self {
            inner: Chain::from_shared_secret(shared_secret),
        }
    }

    /// Current step counter.
    #[getter]
    fn step(&self) -> u64 {
        self.inner.step()
    }

    /// Advance the chain and return the message key for the current step.
    fn next_message_key<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let mk = self.inner.next_message_key();
        PyBytes::new(py, &mk[..])
    }

    /// Fast-forward the chain to `target_step` without emitting keys.
    fn fast_forward(&mut self, target_step: u64) -> PyResult<()> {
        self.inner
            .fast_forward(target_step)
            .map_err(ratchet_err_to_py)
    }

    /// Peek at the message key for a future step without mutating state.
    fn peek_message_key<'py>(
        &self,
        py: Python<'py>,
        target_step: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mk = self
            .inner
            .peek_message_key(target_step)
            .map_err(ratchet_err_to_py)?;
        Ok(PyBytes::new(py, &mk[..]))
    }

    fn __repr__(&self) -> String {
        format!("Chain(step={})", self.inner.step())
    }
}

/// Python-visible skipped-key store.
#[pyclass(name = "SkippedKeyStore", module = "one_link_native.ratchet")]
#[derive(Debug)]
pub struct PySkippedKeyStore {
    inner: SkippedKeyStore,
}

#[pymethods]
impl PySkippedKeyStore {
    /// Build a store with `cap` slots.
    #[new]
    #[pyo3(signature = (cap = ol_ratchet::DEFAULT_SKIPPED_CAP))]
    fn new(cap: usize) -> Self {
        Self {
            inner: SkippedKeyStore::with_capacity(cap),
        }
    }

    /// Number of keys held.
    fn __len__(&self) -> usize {
        self.inner.len()
    }

    /// Capacity.
    #[getter]
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Store a 32-byte key for `step`. Evicts oldest if at capacity.
    fn insert(&mut self, step: u64, key: &[u8]) -> PyResult<()> {
        if key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "key must be 32 bytes, got {}",
                key.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        let mk: MessageKey = Zeroizing::new(arr);
        self.inner.insert(step, mk).map_err(ratchet_err_to_py)
    }

    /// Pop the key for `step`. Raises if not found.
    fn take<'py>(&mut self, py: Python<'py>, step: u64) -> PyResult<Bound<'py, PyBytes>> {
        let mk = self.inner.take(step).map_err(ratchet_err_to_py)?;
        Ok(PyBytes::new(py, &mk[..]))
    }

    /// Drop any keys older than `min_step`.
    fn drop_older_than(&mut self, min_step: u64) {
        self.inner.drop_older_than(min_step);
    }
}

fn ratchet_err_to_py(err: RatchetError) -> PyErr {
    crate::errors::OlRatchetError::new_err(crate::errors::owned_error_message(err))
}

/// Register the `ratchet` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_ratchet::VERSION)?;
    m.add("DEFAULT_SKIPPED_CAP", ol_ratchet::DEFAULT_SKIPPED_CAP)?;
    m.add_class::<PyChain>()?;
    m.add_class::<PySkippedKeyStore>()?;
    Ok(())
}
