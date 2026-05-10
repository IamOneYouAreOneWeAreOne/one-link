//! Python exception hierarchy for `one_link_native`.
//!
//! Per [ADR-0008](../../../docs/decisions/0008-ffi-contract.md), every
//! Rust crate's error type maps to a Python exception subclass under a
//! common `OlError` base. Python callers catch the specific subclass for
//! fine-grained handling or `OlError` for catch-all logic.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(one_link_native, OlError, PyException);
create_exception!(one_link_native, OlChunkError, OlError);
create_exception!(one_link_native, OlAeadError, OlError);
create_exception!(one_link_native, OlWalError, OlError);
create_exception!(one_link_native, OlChunkStoreError, OlError);

/// Register all `one_link_native.*` exception classes on the given
/// top-level module.
pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("OlError", m.py().get_type_bound::<OlError>())?;
    m.add("OlChunkError", m.py().get_type_bound::<OlChunkError>())?;
    m.add("OlAeadError", m.py().get_type_bound::<OlAeadError>())?;
    m.add("OlWalError", m.py().get_type_bound::<OlWalError>())?;
    m.add(
        "OlChunkStoreError",
        m.py().get_type_bound::<OlChunkStoreError>(),
    )?;
    Ok(())
}

/// Convert a `ol_chunk::ChunkError` to a Python `OlChunkError`.
///
/// Cannot use `impl From<ol_chunk::ChunkError> for PyErr` because both
/// types are foreign to this crate (orphan-rule violation). Call this
/// helper directly at error-mapping sites instead.
#[inline]
#[allow(dead_code)]
pub fn chunk_error_to_pyerr(err: ol_chunk::ChunkError) -> PyErr {
    OlChunkError::new_err(err.to_string())
}

/// Convert an `ol_aead::AeadError` to a Python `OlAeadError`.
///
/// Same orphan-rule rationale as `chunk_error_to_pyerr`.
#[inline]
pub fn aead_error_to_pyerr(err: ol_aead::AeadError) -> PyErr {
    OlAeadError::new_err(err.to_string())
}

/// Convert an `ol_wal::WalError` to a Python `OlWalError`.
#[inline]
pub fn wal_error_to_pyerr(err: ol_wal::WalError) -> PyErr {
    OlWalError::new_err(err.to_string())
}

/// Convert an `ol_chunk_store::ChunkStoreError` to a Python `OlChunkStoreError`.
#[inline]
pub fn chunk_store_error_to_pyerr(err: ol_chunk_store::ChunkStoreError) -> PyErr {
    OlChunkStoreError::new_err(err.to_string())
}
