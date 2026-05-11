//! `one_link_native.crdt` — Python binding for `ol_crdt`.
//!
//! Surfaces the Folder CRDT (ADR-0022) to the daemon: replacement for
//! the existing `foldersync.py` vector-clock manifest.

use ol_crdt::{Folder, Lattice, ReplicaId};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};

/// Python-visible Folder CRDT.
#[pyclass(name = "Folder", module = "one_link_native.crdt")]
#[derive(Debug, Clone, Default)]
pub struct PyFolder {
    inner: Folder,
}

#[pymethods]
impl PyFolder {
    #[new]
    fn new() -> Self {
        Self {
            inner: Folder::new(),
        }
    }

    /// Add a file. `replica` and `file_id` must be exactly 32 bytes.
    fn add_file(
        &mut self,
        replica: &[u8],
        file_id: &[u8],
        display_name: String,
        size_bytes: u64,
        last_modified_ms: u64,
    ) -> PyResult<()> {
        let rid = ReplicaId(bytes_to_32(replica, "replica")?);
        let fid = bytes_to_32(file_id, "file_id")?;
        self.inner
            .add_file(&rid, fid, display_name, size_bytes, last_modified_ms);
        Ok(())
    }

    /// Remove a file (add-wins OR-set: concurrent re-adds win).
    fn remove_file(&mut self, replica: &[u8], file_id: &[u8]) -> PyResult<()> {
        let rid = ReplicaId(bytes_to_32(replica, "replica")?);
        let fid = bytes_to_32(file_id, "file_id")?;
        self.inner.remove_file(&rid, &fid);
        Ok(())
    }

    /// True iff `file_id` is currently in the folder.
    fn contains(&self, file_id: &[u8]) -> PyResult<bool> {
        let fid = bytes_to_32(file_id, "file_id")?;
        Ok(self.inner.contains(&fid))
    }

    /// Merge another folder into this one (commutative, associative, idempotent).
    fn merge(&mut self, other: &PyFolder) {
        self.inner.merge(&other.inner);
    }

    /// Number of present files.
    fn len(&self) -> usize {
        self.inner.iter().count()
    }

    /// List of currently-present (file_id, display_name, size, mtime) tuples.
    fn entries<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let out = PyList::empty_bound(py);
        for (fid, entry) in self.inner.iter() {
            let item = (
                PyBytes::new_bound(py, fid),
                &entry.display_name.value,
                entry.size_bytes.value,
                entry.last_modified_ms.value,
            );
            out.append(item)?;
        }
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!("Folder(present_files={})", self.inner.iter().count())
    }
}

fn bytes_to_32(bytes: &[u8], field: &str) -> PyResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "{field} must be exactly 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Register the `crdt` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyFolder>()?;
    Ok(())
}
