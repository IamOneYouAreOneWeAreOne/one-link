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
create_exception!(one_link_native, OlQuicError, OlError);
create_exception!(one_link_native, OlBloomError, OlError);
create_exception!(one_link_native, OlFountainError, OlError);
create_exception!(one_link_native, OlFecError, OlError);
create_exception!(one_link_native, OlRatchetError, OlError);
create_exception!(one_link_native, OlPqKemError, OlError);
create_exception!(one_link_native, OlErasureError, OlError);
create_exception!(one_link_native, OlBanditError, OlError);
create_exception!(one_link_native, OlCapabilityError, OlError);
create_exception!(one_link_native, OlCrdtError, OlError);
create_exception!(one_link_native, OlHwKeyError, OlError);

/// Register all `one_link_native.*` exception classes on the given
/// top-level module.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("OlError", m.py().get_type_bound::<OlError>())?;
    m.add("OlChunkError", m.py().get_type_bound::<OlChunkError>())?;
    m.add("OlAeadError", m.py().get_type_bound::<OlAeadError>())?;
    m.add("OlWalError", m.py().get_type_bound::<OlWalError>())?;
    m.add(
        "OlChunkStoreError",
        m.py().get_type_bound::<OlChunkStoreError>(),
    )?;
    m.add("OlQuicError", m.py().get_type_bound::<OlQuicError>())?;
    m.add("OlBloomError", m.py().get_type_bound::<OlBloomError>())?;
    m.add("OlFountainError", m.py().get_type_bound::<OlFountainError>())?;
    m.add("OlFecError", m.py().get_type_bound::<OlFecError>())?;
    m.add("OlRatchetError", m.py().get_type_bound::<OlRatchetError>())?;
    m.add("OlPqKemError", m.py().get_type_bound::<OlPqKemError>())?;
    m.add("OlErasureError", m.py().get_type_bound::<OlErasureError>())?;
    m.add("OlBanditError", m.py().get_type_bound::<OlBanditError>())?;
    m.add(
        "OlCapabilityError",
        m.py().get_type_bound::<OlCapabilityError>(),
    )?;
    m.add("OlCrdtError", m.py().get_type_bound::<OlCrdtError>())?;
    m.add("OlHwKeyError", m.py().get_type_bound::<OlHwKeyError>())?;
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

/// Convert an `ol_quic::QuicError` to a Python `OlQuicError`.
#[inline]
pub fn quic_error_to_pyerr(err: ol_quic::QuicError) -> PyErr {
    OlQuicError::new_err(err.to_string())
}

/// Convert an `ol_bloom::BloomError` to a Python `OlBloomError`.
#[inline]
pub fn bloom_error_to_pyerr(err: ol_bloom::BloomError) -> PyErr {
    OlBloomError::new_err(err.to_string())
}

/// Convert an `ol_fountain::FountainError` to a Python `OlFountainError`.
#[inline]
pub fn fountain_error_to_pyerr(err: ol_fountain::FountainError) -> PyErr {
    OlFountainError::new_err(err.to_string())
}
