//! `one_link_native.wal` — Python binding for the `ol_wal` crash-only WAL.
//!
//! Surfaces the WAL writer (append + flush + rotate) and the crash-only
//! replay routine. Per [ADR-0008](../../../docs/decisions/0008-ffi-contract.md):
//!
//! - I/O-bound operations (write + fsync + replay) release the GIL.
//! - Errors map to `one_link_native.OlWalError`.
//! - Higher-level `chunk_store` + `manifest_log` layers (Phase A1 next)
//!   consume this surface.

use std::path::PathBuf;

use ol_wal::{
    replay_log_dir as rust_replay_log_dir, LogKind, Record as RustRecord, Wal as RustWal,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::wal_error_to_pyerr;

fn parse_kind(s: &str) -> PyResult<LogKind> {
    match s {
        "chunk" | "chunk_log" | "ChunkLog" => Ok(LogKind::ChunkLog),
        "manifest" | "manifest_log" | "ManifestLog" => Ok(LogKind::ManifestLog),
        other => Err(PyValueError::new_err(format!(
            "unknown log kind '{other}'; expected 'chunk' or 'manifest'"
        ))),
    }
}

fn kind_to_str(k: LogKind) -> &'static str {
    match k {
        LogKind::ChunkLog => "chunk",
        LogKind::ManifestLog => "manifest",
    }
}

/// Python-visible WAL record. Wraps `(kind, flags, payload)`.
#[pyclass(
    from_py_object,
    name = "WalRecord",
    module = "one_link_native.wal",
    frozen
)]
#[derive(Debug, Clone)]
pub struct PyWalRecord {
    /// Per-log-kind record kind byte.
    #[pyo3(get)]
    pub kind: u8,
    /// Per-log-kind flags byte.
    #[pyo3(get)]
    pub flags: u8,
    payload: Vec<u8>,
}

#[pymethods]
impl PyWalRecord {
    #[new]
    #[pyo3(signature = (kind, flags, payload))]
    fn new(kind: u8, flags: u8, payload: &[u8]) -> PyResult<Self> {
        if payload.len() > ol_wal::MAX_PAYLOAD_LEN {
            return Err(PyValueError::new_err(format!(
                "payload too large: {} > {}",
                payload.len(),
                ol_wal::MAX_PAYLOAD_LEN
            )));
        }
        Ok(Self {
            kind,
            flags,
            payload: payload.to_vec(),
        })
    }

    /// Payload bytes.
    #[getter]
    fn payload<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.payload)
    }

    /// Payload length.
    #[getter]
    fn length(&self) -> usize {
        self.payload.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "WalRecord(kind=0x{:02x}, flags=0x{:02x}, length={})",
            self.kind,
            self.flags,
            self.payload.len(),
        )
    }
}

impl From<&PyWalRecord> for RustRecord {
    fn from(r: &PyWalRecord) -> Self {
        Self {
            kind: r.kind,
            flags: r.flags,
            payload: r.payload.clone(),
        }
    }
}

/// WAL writer handle.
///
/// Construct via :func:`create` or :func:`open`. Append records via
/// :meth:`append`, batch them, and call :meth:`flush` to make them durable.
/// Rotation is automatic when an append reaches the active-file cap;
/// :meth:`rotate` remains available for an explicit early seal.
#[pyclass(name = "Wal", module = "one_link_native.wal", unsendable)]
pub struct PyWal {
    inner: Option<RustWal>,
}

#[pymethods]
impl PyWal {
    /// Active file id (1-based).
    fn active_file_id(&self) -> PyResult<u64> {
        self.inner
            .as_ref()
            .map(ol_wal::Wal::active_file_id)
            .ok_or_else(|| PyValueError::new_err("WAL is closed"))
    }

    /// Current size of the active file in bytes (including pending bytes
    /// not yet flushed).
    fn active_file_size(&self) -> PyResult<u64> {
        self.inner
            .as_ref()
            .map(ol_wal::Wal::active_file_size)
            .ok_or_else(|| PyValueError::new_err("WAL is closed"))
    }

    /// Append a record to the in-memory pending buffer. Does not fsync.
    fn append(&mut self, record: &PyWalRecord) -> PyResult<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("WAL is closed"))?;
        let r = RustRecord::from(record);
        inner.append(&r).map(|_| ()).map_err(wal_error_to_pyerr)
    }

    /// Flush pending records to durable storage in a single barrier.
    fn flush(&mut self, py: Python<'_>) -> PyResult<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("WAL is closed"))?;
        py.detach(|| inner.flush()).map_err(wal_error_to_pyerr)
    }

    /// Rotate to the next file id (flushes pending first, then allocates
    /// a fresh file with a new header).
    fn rotate(&mut self, py: Python<'_>) -> PyResult<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| PyValueError::new_err("WAL is closed"))?;
        py.detach(|| inner.rotate()).map_err(wal_error_to_pyerr)
    }

    /// Close the WAL writer, flushing pending records.
    fn close(&mut self, py: Python<'_>) -> PyResult<()> {
        if let Some(mut inner) = self.inner.take() {
            py.detach(|| inner.flush()).map_err(wal_error_to_pyerr)?;
        }
        Ok(())
    }
}

/// Create a new WAL writer rooted at `dir` for the given log kind.
/// The directory is created if absent; the first file (000001.wal) is
/// allocated with the canonical 64-byte header fsync'd.
#[pyfunction]
fn create(py: Python<'_>, dir: &str, kind: &str) -> PyResult<PyWal> {
    let kind = parse_kind(kind)?;
    let path = PathBuf::from(dir);
    let inner = py
        .detach(|| RustWal::create(&path, kind))
        .map_err(wal_error_to_pyerr)?;
    Ok(PyWal { inner: Some(inner) })
}

/// Open an existing WAL log dir for appending. Discovers the highest
/// file id, validates its header, and seeks to its end.
///
/// Note: callers should run :func:`replay_log_dir` BEFORE opening for
/// append, to recover any crash-truncated tail first.
#[pyfunction]
fn open(py: Python<'_>, dir: &str, kind: &str) -> PyResult<PyWal> {
    let kind = parse_kind(kind)?;
    let path = PathBuf::from(dir);
    let inner = py
        .detach(|| RustWal::open(&path, kind))
        .map_err(wal_error_to_pyerr)?;
    Ok(PyWal { inner: Some(inner) })
}

/// Replay every WAL file in `dir` (ascending file-id order). Returns
/// a list of `WalRecord` instances in append order. Truncates the tail
/// of the last file if the last record's CRC fails (the canonical
/// crash-recovery action).
#[pyfunction]
fn replay_log_dir(py: Python<'_>, dir: &str, kind: &str) -> PyResult<Vec<PyWalRecord>> {
    let kind = parse_kind(kind)?;
    let path = PathBuf::from(dir);
    let outcome = py
        .detach(|| rust_replay_log_dir(&path, kind))
        .map_err(wal_error_to_pyerr)?;
    Ok(outcome
        .records
        .into_iter()
        .map(|r| PyWalRecord {
            kind: r.kind,
            flags: r.flags,
            payload: r.payload,
        })
        .collect())
}

/// Look up the on-disk magic for a given log kind.
#[pyfunction]
fn log_kind_magic<'py>(py: Python<'py>, kind: &str) -> PyResult<Bound<'py, PyBytes>> {
    let kind = parse_kind(kind)?;
    Ok(PyBytes::new(py, &kind.magic()))
}

/// Register the wal submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    use ol_wal::{
        FILE_HEADER_LEN, MAX_PAYLOAD_LEN, RECORD_HEADER_LEN, RECORD_TRAILER_LEN, ROTATION_SIZE,
    };

    m.add("FILE_HEADER_LEN", FILE_HEADER_LEN)?;
    m.add("RECORD_HEADER_LEN", RECORD_HEADER_LEN)?;
    m.add("RECORD_TRAILER_LEN", RECORD_TRAILER_LEN)?;
    m.add("MAX_PAYLOAD_LEN", MAX_PAYLOAD_LEN)?;
    m.add("ROTATION_SIZE", ROTATION_SIZE)?;

    m.add_class::<PyWalRecord>()?;
    m.add_class::<PyWal>()?;
    m.add_function(wrap_pyfunction!(create, m)?)?;
    m.add_function(wrap_pyfunction!(open, m)?)?;
    m.add_function(wrap_pyfunction!(replay_log_dir, m)?)?;
    m.add_function(wrap_pyfunction!(log_kind_magic, m)?)?;

    let _ = kind_to_str; // referenced in repr-style helpers; keep visible for future use
    Ok(())
}
