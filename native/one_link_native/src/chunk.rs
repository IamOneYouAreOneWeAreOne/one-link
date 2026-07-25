//! `one_link_native.chunk` — Python binding for the `ol_chunk` Rust crate.
//!
//! Surfaces `FastCDC` + BLAKE3 chunk addressing + domain-separated key
//! derivation. Per [ADR-0008](../../../docs/decisions/0008-ffi-contract.md):
//!
//! - Long-running operations detach from the interpreter via `py.detach`.
//! - Buffer arguments use the Python buffer protocol (`bytes`, `bytearray`,
//!   `memoryview`) for zero-copy ingest.
//! - Errors map to `one_link_native.OlChunkError` (subclass of `OlError`).

use ol_chunk::{
    blake3_wrap, frame_count_for_plaintext, scan_to_vec_parallel, AEAD_FRAME_PLAINTEXT_LEN,
    AEAD_TAG_LEN,
};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

/// Python-visible boundary record. Wraps `(start, end, blake3_hash)`.
#[pyclass(
    from_py_object,
    name = "Boundary",
    frozen,
    module = "one_link_native.chunk"
)]
#[derive(Debug, Clone)]
pub struct PyBoundary {
    /// Inclusive start byte offset.
    #[pyo3(get)]
    start: usize,
    /// Exclusive end byte offset.
    #[pyo3(get)]
    end: usize,
    /// BLAKE3-256 raw chunk address (32 bytes).
    raw_address: [u8; 32],
}

#[pymethods]
impl PyBoundary {
    /// Length of the chunk in bytes.
    #[getter]
    fn length(&self) -> usize {
        self.end - self.start
    }

    /// Raw chunk address as a 32-byte `bytes` object.
    #[getter]
    fn raw_address<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.raw_address)
    }

    /// Hex-encoded raw address (lowercase, no separators).
    fn raw_address_hex(&self) -> String {
        hex_lower(&self.raw_address)
    }

    fn __repr__(&self) -> String {
        format!(
            "Boundary(start={}, end={}, length={}, raw={})",
            self.start,
            self.end,
            self.end - self.start,
            self.raw_address_hex(),
        )
    }
}

/// Chunk-content-defined-chunking iterator over a contiguous byte buffer.
///
/// Yields :class:`Boundary` objects until the buffer is exhausted.
/// Created via :func:`cdc_iter`.
#[pyclass(
    name = "BoundaryIterator",
    module = "one_link_native.chunk",
    unsendable
)]
pub struct PyBoundaryIterator {
    /// Eagerly-collected boundaries. We collect once at construction time
    /// so the underlying buffer's lifetime doesn't have to outlive the
    /// iterator. Memory: 32 bytes hash + 32 bytes positional = 64 B per
    /// boundary; a 1 GiB buffer with 64 KiB mean chunks → ~16K boundaries
    /// → 1 MB. Acceptable.
    boundaries: std::vec::IntoIter<PyBoundary>,
}

#[pymethods]
impl PyBoundaryIterator {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }
    fn __next__(mut slf: PyRefMut<'_, Self>) -> Option<PyBoundary> {
        slf.boundaries.next()
    }
    fn __len__(&self) -> usize {
        self.boundaries.len()
    }
}

/// Scan a byte buffer with the default ADR-0001 CDC parameters (8 KiB
/// min, 64 KiB avg, 256 KiB max) and return an iterator of
/// :class:`Boundary` objects.
///
/// **Zero-copy immutable fast path.** Python ``bytes`` are borrowed
/// directly. Mutable exporters (``bytearray`` and writable/readonly
/// views over mutable storage) are snapshotted before the interpreter
/// is detached; a buffer export prevents resize but does not prevent a
/// second Python thread from mutating existing bytes.
///
/// Releases the GIL while scanning. The buffer must be a contiguous,
/// readable Python object (``bytes``, ``bytearray``, ``memoryview``).
///
/// :param buf: input buffer
/// :return: an iterator over Boundary instances
/// :raises `OlChunkError`: if the buffer cannot be read as a contiguous u8 slice
#[pyfunction]
pub fn cdc_iter(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<PyBoundaryIterator> {
    let boundaries = if let Ok(bytes) = obj.cast::<PyBytes>() {
        let immutable = PyBackedBytes::from(bytes.to_owned());
        py.detach(move || scan_boundaries(&immutable))
    } else {
        let owned = contiguous_buffer_snapshot(py, obj)?;
        py.detach(|| scan_boundaries(&owned))
    };
    Ok(PyBoundaryIterator {
        boundaries: boundaries.into_iter(),
    })
}

/// Compute the raw BLAKE3-256 chunk address for a buffer.
///
/// Equivalent to `blake3.hash(buf).digest()` but exposed via the engine's
/// canonical entry point. Zero-copy; see [`cdc_iter`] safety note.
#[pyfunction]
pub fn chunk_address_raw<'py>(
    py: Python<'py>,
    obj: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let addr = if let Ok(bytes) = obj.cast::<PyBytes>() {
        let immutable = PyBackedBytes::from(bytes.to_owned());
        py.detach(move || blake3_wrap::chunk_address_raw(&immutable))
    } else {
        let owned = contiguous_buffer_snapshot(py, obj)?;
        py.detach(|| blake3_wrap::chunk_address_raw(&owned))
    };
    Ok(PyBytes::new(py, &addr))
}

/// Compute the convergent BLAKE3-256 chunk address for a buffer.
///
/// Same plaintext from any peer produces the same address. Domain-separated
/// from `chunk_address_raw`. Zero-copy.
#[pyfunction]
pub fn chunk_address_convergent<'py>(
    py: Python<'py>,
    obj: &Bound<'_, PyAny>,
) -> PyResult<Bound<'py, PyBytes>> {
    let addr = if let Ok(bytes) = obj.cast::<PyBytes>() {
        let immutable = PyBackedBytes::from(bytes.to_owned());
        py.detach(move || blake3_wrap::chunk_address_convergent(&immutable))
    } else {
        let owned = contiguous_buffer_snapshot(py, obj)?;
        py.detach(|| blake3_wrap::chunk_address_convergent(&owned))
    };
    Ok(PyBytes::new(py, &addr))
}

fn contiguous_buffer_snapshot(py: Python<'_>, obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let buf = PyBuffer::<u8>::get(obj)?;
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err(
            "buffer must be C-contiguous (got fortran-order or non-contiguous)",
        ));
    }
    buf.to_vec(py)
}

fn scan_boundaries(bytes: &[u8]) -> Vec<PyBoundary> {
    scan_to_vec_parallel(bytes)
        .into_iter()
        .map(|b| PyBoundary {
            start: b.start,
            end: b.end,
            raw_address: b.raw_address,
        })
        .collect()
}

/// Derive a per-chunk AEAD key from a ratchet chain key + chunk address
/// per [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 3.
///
/// Both arguments must be exactly 32 bytes.
#[pyfunction]
pub fn derive_aead_key<'py>(
    py: Python<'py>,
    ratchet_chain_key: &[u8],
    chunk_id_full: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if ratchet_chain_key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "ratchet_chain_key must be 32 bytes, got {}",
            ratchet_chain_key.len(),
        )));
    }
    if chunk_id_full.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id_full must be 32 bytes, got {}",
            chunk_id_full.len(),
        )));
    }
    let mut chain = [0u8; 32];
    chain.copy_from_slice(ratchet_chain_key);
    let mut chunk = [0u8; 32];
    chunk.copy_from_slice(chunk_id_full);
    let key = blake3_wrap::derive_aead_key(&chain, &chunk);
    Ok(PyBytes::new(py, &key))
}

/// Derive the 16-byte `ratchet_key_id` for a chunk per
/// [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 4.
#[pyfunction]
pub fn derive_ratchet_key_id<'py>(
    py: Python<'py>,
    ratchet_chain_key: &[u8],
    chunk_id_full: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    if ratchet_chain_key.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "ratchet_chain_key must be 32 bytes, got {}",
            ratchet_chain_key.len(),
        )));
    }
    if chunk_id_full.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id_full must be 32 bytes, got {}",
            chunk_id_full.len(),
        )));
    }
    let mut chain = [0u8; 32];
    chain.copy_from_slice(ratchet_chain_key);
    let mut chunk = [0u8; 32];
    chunk.copy_from_slice(chunk_id_full);
    let id = blake3_wrap::derive_ratchet_key_id(&chain, &chunk);
    Ok(PyBytes::new(py, &id))
}

/// Derive the stripe seed and within-stripe position for a chunk per
/// [ADR-0004](../../../docs/decisions/0004-stripe-layout.md) and
/// [ADR-0006](../../../docs/decisions/0006-blake3-derive-scheme.md) Rule 5.
///
/// Returns `(stripe_seed, position)` where `stripe_seed` has the low 6
/// bits cleared and `position` is in `[0, stripe_k)`.
#[pyfunction]
pub fn derive_stripe_seed(chunk_id_full: &[u8], stripe_k: u8) -> PyResult<(u64, u8)> {
    if chunk_id_full.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id_full must be 32 bytes, got {}",
            chunk_id_full.len(),
        )));
    }
    if stripe_k == 0 {
        return Err(PyValueError::new_err("stripe_k must be ≥ 1"));
    }
    let mut chunk = [0u8; 32];
    chunk.copy_from_slice(chunk_id_full);
    Ok(blake3_wrap::derive_stripe_seed(&chunk, stripe_k))
}

/// Compute the number of AEAD frames a chunk plaintext needs.
///
/// One frame per `AEAD_FRAME_PLAINTEXT_LEN` bytes (16 KiB), rounded up.
#[pyfunction]
pub fn frame_count(plaintext_len: usize) -> usize {
    frame_count_for_plaintext(plaintext_len)
}

/// Register the chunk submodule on the given Python module.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Constants (per ADR-0001 + ADR-0002).
    m.add("CDC_MIN_SIZE", 8 * 1024usize)?;
    m.add("CDC_AVG_SIZE", 64 * 1024usize)?;
    m.add("CDC_MAX_SIZE", 256 * 1024usize)?;
    m.add("AEAD_FRAME_PLAINTEXT_LEN", AEAD_FRAME_PLAINTEXT_LEN)?;
    m.add("AEAD_TAG_LEN", AEAD_TAG_LEN)?;

    // Types.
    m.add_class::<PyBoundary>()?;
    m.add_class::<PyBoundaryIterator>()?;

    // Functions.
    m.add_function(wrap_pyfunction!(cdc_iter, m)?)?;
    m.add_function(wrap_pyfunction!(chunk_address_raw, m)?)?;
    m.add_function(wrap_pyfunction!(chunk_address_convergent, m)?)?;
    m.add_function(wrap_pyfunction!(derive_aead_key, m)?)?;
    m.add_function(wrap_pyfunction!(derive_ratchet_key_id, m)?)?;
    m.add_function(wrap_pyfunction!(derive_stripe_seed, m)?)?;
    m.add_function(wrap_pyfunction!(frame_count, m)?)?;

    Ok(())
}

/// Local lowercase hex encoder. Avoid pulling the `hex` crate into the
/// binding crate just for one display function.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
