//! `one_link_native.aead` — Python binding for the `ol_aead` Rust crate.
//!
//! Surfaces per-chunk AEAD encrypt / decrypt + per-frame random-access
//! decrypt + the host-preferred AEAD selector. Per
//! [ADR-0008](../../../docs/decisions/0008-ffi-contract.md):
//!
//! - GIL released for encrypt / decrypt of large chunks.
//! - Buffer arguments take `bytes`/`bytearray`/`memoryview` (zero-copy
//!   ingest where Python permits; we copy into owned Rust Vec for
//!   safety because in-place AEAD mutates the buffer).
//! - Errors map to `one_link_native.OlAeadError`.

use ol_aead::{
    cipher::{AeadCipher as RustAeadCipher, AeadKind},
    decrypt_chunk as rust_decrypt_chunk, decrypt_frame as rust_decrypt_frame,
    encrypt_chunk as rust_encrypt_chunk, encrypt_frame as rust_encrypt_frame,
    frame::{
        decrypt_chunks_par as rust_decrypt_chunks_par,
        encrypt_chunks_par as rust_encrypt_chunks_par,
    },
    key::{ChunkAeadKey, FRAME_KEY_LEN as RUST_FRAME_KEY_LEN},
    AEAD_TAG_LEN as RUST_AEAD_TAG_LEN,
};
use ol_chunk::AEAD_FRAME_PLAINTEXT_LEN as RUST_AEAD_FRAME_PLAINTEXT_LEN;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};
use pyo3::types::{PyList, PyTupleMethods};

use crate::errors::aead_error_to_pyerr;

/// Map a string AEAD kind to the underlying enum.
fn parse_kind(s: &str) -> PyResult<AeadKind> {
    match s {
        "aes" | "AES" | "AES-GCM" | "aes-gcm" | "aes-256-gcm" | "AES-256-GCM" => {
            Ok(AeadKind::AesGcm256)
        }
        "chacha" | "ChaCha20" | "chacha20" | "chacha20-poly1305" | "ChaCha20Poly1305" => {
            Ok(AeadKind::ChaCha20Poly1305)
        }
        other => Err(PyValueError::new_err(format!(
            "unknown AEAD kind '{other}'; expected 'aes' or 'chacha'"
        ))),
    }
}

fn kind_to_str(k: AeadKind) -> &'static str {
    match k {
        AeadKind::AesGcm256 => "aes",
        AeadKind::ChaCha20Poly1305 => "chacha",
    }
}

fn copy_buffer(py: Python<'_>, buf: PyBuffer<u8>) -> PyResult<Vec<u8>> {
    if !buf.is_c_contiguous() {
        return Err(PyValueError::new_err("buffer must be C-contiguous"));
    }
    let mut owned = vec![0u8; buf.item_count()];
    buf.copy_to_slice(py, &mut owned)
        .map_err(|e| PyValueError::new_err(format!("buffer copy failed: {e}")))?;
    Ok(owned)
}

fn check_chunk_id(chunk_id: &[u8]) -> PyResult<[u8; 32]> {
    if chunk_id.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "chunk_id must be 32 bytes (BLAKE3-256), got {}",
            chunk_id.len(),
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(chunk_id);
    Ok(out)
}

fn check_key(key: &[u8]) -> PyResult<ChunkAeadKey> {
    if key.len() != RUST_FRAME_KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "key must be {RUST_FRAME_KEY_LEN} bytes, got {}",
            key.len(),
        )));
    }
    let mut bytes = [0u8; RUST_FRAME_KEY_LEN];
    bytes.copy_from_slice(key);
    Ok(ChunkAeadKey::from_bytes(bytes))
}

fn check_tag(tag: &[u8]) -> PyResult<[u8; RUST_AEAD_TAG_LEN]> {
    if tag.len() != RUST_AEAD_TAG_LEN {
        return Err(PyValueError::new_err(format!(
            "tag must be {RUST_AEAD_TAG_LEN} bytes, got {}",
            tag.len(),
        )));
    }
    let mut out = [0u8; RUST_AEAD_TAG_LEN];
    out.copy_from_slice(tag);
    Ok(out)
}

/// AEAD cipher initialized with a 32-byte key.
///
/// Construct via :func:`new_cipher` or :func:`default_cipher_for_host`.
/// Reuse across many encrypt / decrypt calls; cipher state is the
/// expanded round keys derived once at construction.
///
/// Wraps the inner cipher in an Arc so the pyo3 binding can clone
/// cheaply (refcount bump) for ``py.allow_threads`` closures that
/// release the GIL. The ring-backed `AeadCipher` itself is not Clone
/// because `ring::aead::LessSafeKey` doesn't expose its key bytes —
/// the Arc sidesteps that without compromising key isolation.
#[pyclass(
    name = "AeadCipher",
    module = "one_link_native.aead",
    frozen,
    unsendable
)]
#[derive(Debug, Clone)]
pub struct PyAeadCipher {
    inner: std::sync::Arc<RustAeadCipher>,
}

#[pymethods]
impl PyAeadCipher {
    /// Which AEAD kind this cipher dispatches to (``"aes"`` or ``"chacha"``).
    #[getter]
    fn kind(&self) -> &'static str {
        kind_to_str(self.inner.kind())
    }

    /// Encrypt a complete chunk plaintext into the on-wire layout.
    ///
    /// :param chunk_id: 32-byte BLAKE3 chunk address (used as AAD + nonce input).
    /// :param plaintext: the chunk's plaintext bytes (≤ 256 KiB).
    /// :return: ciphertext bytes = ``len(plaintext) + frame_count * 16``.
    /// :raises OlAeadError: on encrypt failure.
    fn encrypt_chunk<'py>(
        &self,
        py: Python<'py>,
        chunk_id: &[u8],
        plaintext: PyBuffer<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = check_chunk_id(chunk_id)?;
        let pt = copy_buffer(py, plaintext)?;
        let cipher = self.inner.clone();
        let ct = py
            .allow_threads(|| rust_encrypt_chunk(&cipher, &id, &pt))
            .map_err(aead_error_to_pyerr)?;
        Ok(PyBytes::new_bound(py, &ct))
    }

    /// Decrypt a complete chunk ciphertext.
    ///
    /// :param chunk_id: 32-byte BLAKE3 chunk address (must match the
    ///     value used at encrypt time).
    /// :param plaintext_len: original plaintext length (used to drive
    ///     frame layout reconstruction).
    /// :param ciphertext: the on-wire ciphertext bytes.
    /// :return: plaintext bytes.
    /// :raises OlAeadError: on tag verification failure.
    fn decrypt_chunk<'py>(
        &self,
        py: Python<'py>,
        chunk_id: &[u8],
        plaintext_len: usize,
        ciphertext: PyBuffer<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = check_chunk_id(chunk_id)?;
        let ct = copy_buffer(py, ciphertext)?;
        let cipher = self.inner.clone();
        let pt = py
            .allow_threads(|| rust_decrypt_chunk(&cipher, &id, plaintext_len, &ct))
            .map_err(aead_error_to_pyerr)?;
        Ok(PyBytes::new_bound(py, &pt))
    }

    /// Encrypt a single frame (≤ 16 KiB plaintext). Returns
    /// ``(ciphertext, tag)`` where ``len(tag) == 16``.
    fn encrypt_frame<'py>(
        &self,
        py: Python<'py>,
        chunk_id: &[u8],
        frame_index: u64,
        plaintext: PyBuffer<u8>,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let id = check_chunk_id(chunk_id)?;
        let pt = copy_buffer(py, plaintext)?;
        let cipher = self.inner.clone();
        let (ct, tag) = py
            .allow_threads(|| rust_encrypt_frame(&cipher, &id, frame_index, &pt))
            .map_err(aead_error_to_pyerr)?;
        let ct_py = PyBytes::new_bound(py, &ct);
        let tag_py = PyBytes::new_bound(py, &tag);
        Ok(PyTuple::new_bound(
            py,
            vec![ct_py.into_any(), tag_py.into_any()],
        ))
    }

    /// Decrypt a single frame.
    ///
    /// :param chunk_id: 32-byte BLAKE3 chunk address.
    /// :param frame_index: zero-based frame index within the chunk.
    /// :param ciphertext: frame ciphertext (≤ 16 KiB).
    /// :param tag: 16-byte AEAD authentication tag.
    /// :return: frame plaintext.
    /// :raises OlAeadError: on tag verification failure.
    fn decrypt_frame<'py>(
        &self,
        py: Python<'py>,
        chunk_id: &[u8],
        frame_index: u64,
        ciphertext: PyBuffer<u8>,
        tag: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let id = check_chunk_id(chunk_id)?;
        let ct = copy_buffer(py, ciphertext)?;
        let tag_arr = check_tag(tag)?;
        let cipher = self.inner.clone();
        let pt = py
            .allow_threads(|| rust_decrypt_frame(&cipher, &id, frame_index, &ct, &tag_arr))
            .map_err(aead_error_to_pyerr)?;
        Ok(PyBytes::new_bound(py, &pt))
    }

    /// Encrypt many chunks in parallel via rayon. Wave 2h: lets
    /// the daemon hand the AEAD layer a whole window of chunks
    /// at once + amortise the per-chunk Python/FFI overhead
    /// across the work.
    ///
    /// :param chunks: list of ``(chunk_id, plaintext)`` 2-tuples.
    ///     ``chunk_id`` must be 32 bytes; ``plaintext`` is any
    ///     bytes-like with len ≤ 256 KiB.
    /// :return: list of ciphertext bytes in input order. On any
    ///     per-chunk failure the entire call raises
    ///     ``OlAeadError`` — the caller's responsibility is to
    ///     retry or fall back to the sequential path.
    fn encrypt_chunks<'py>(
        &self,
        py: Python<'py>,
        chunks: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyList>> {
        // Materialise the Python list into owned Rust buffers so
        // we can drop the GIL during the parallel encrypt. The
        // owned (id_array, plaintext_vec) pairs keep ownership in
        // this stack frame; we pass borrowed slices to the rayon
        // closure.
        let mut owned: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(chunks.len());
        for item in chunks.iter() {
            let tup = item.downcast::<PyTuple>().map_err(|_| {
                PyValueError::new_err("each chunk must be a (chunk_id, plaintext) tuple")
            })?;
            if tup.len() != 2 {
                return Err(PyValueError::new_err(
                    "each chunk tuple must have exactly 2 elements",
                ));
            }
            let chunk_id_obj = tup.get_item(0)?;
            let plaintext_obj = tup.get_item(1)?;
            let chunk_id_buf: PyBuffer<u8> = PyBuffer::get_bound(&chunk_id_obj)?;
            let plaintext_buf: PyBuffer<u8> = PyBuffer::get_bound(&plaintext_obj)?;
            let id_bytes = copy_buffer(py, chunk_id_buf)?;
            let id = check_chunk_id(&id_bytes)?;
            let pt = copy_buffer(py, plaintext_buf)?;
            owned.push((id, pt));
        }
        let cipher = self.inner.clone();
        let ciphertexts = py
            .allow_threads(|| -> Result<Vec<Vec<u8>>, _> {
                let borrowed: Vec<(&[u8; 32], &[u8])> =
                    owned.iter().map(|(id, pt)| (id, pt.as_slice())).collect();
                rust_encrypt_chunks_par(&cipher, &borrowed)
            })
            .map_err(aead_error_to_pyerr)?;
        let out = PyList::empty_bound(py);
        for ct in ciphertexts {
            out.append(PyBytes::new_bound(py, &ct))?;
        }
        Ok(out)
    }

    /// Decrypt many chunks in parallel via rayon. Mirror of
    /// :meth:`encrypt_chunks`.
    ///
    /// :param chunks: list of ``(chunk_id, plaintext_len, ciphertext)``
    ///     3-tuples.
    /// :return: list of plaintext bytes in input order. On any
    ///     per-chunk tag-verification failure the call raises
    ///     ``OlAeadError``.
    fn decrypt_chunks<'py>(
        &self,
        py: Python<'py>,
        chunks: &Bound<'py, PyList>,
    ) -> PyResult<Bound<'py, PyList>> {
        let mut owned: Vec<([u8; 32], usize, Vec<u8>)> = Vec::with_capacity(chunks.len());
        for item in chunks.iter() {
            let tup = item.downcast::<PyTuple>().map_err(|_| {
                PyValueError::new_err(
                    "each chunk must be a (chunk_id, plaintext_len, ciphertext) tuple",
                )
            })?;
            if tup.len() != 3 {
                return Err(PyValueError::new_err(
                    "each chunk tuple must have exactly 3 elements",
                ));
            }
            let chunk_id_obj = tup.get_item(0)?;
            let pt_len_obj = tup.get_item(1)?;
            let ciphertext_obj = tup.get_item(2)?;
            let chunk_id_buf: PyBuffer<u8> = PyBuffer::get_bound(&chunk_id_obj)?;
            let id_bytes = copy_buffer(py, chunk_id_buf)?;
            let id = check_chunk_id(&id_bytes)?;
            let pt_len: usize = pt_len_obj.extract()?;
            let ct_buf: PyBuffer<u8> = PyBuffer::get_bound(&ciphertext_obj)?;
            let ct = copy_buffer(py, ct_buf)?;
            owned.push((id, pt_len, ct));
        }
        let cipher = self.inner.clone();
        let plaintexts = py
            .allow_threads(|| -> Result<Vec<Vec<u8>>, _> {
                let borrowed: Vec<(&[u8; 32], usize, &[u8])> = owned
                    .iter()
                    .map(|(id, pt_len, ct)| (id, *pt_len, ct.as_slice()))
                    .collect();
                rust_decrypt_chunks_par(&cipher, &borrowed)
            })
            .map_err(aead_error_to_pyerr)?;
        let out = PyList::empty_bound(py);
        for pt in plaintexts {
            out.append(PyBytes::new_bound(py, &pt))?;
        }
        Ok(out)
    }

    fn __repr__(&self) -> String {
        format!("AeadCipher(kind='{}')", self.kind())
    }
}

/// Construct an AeadCipher of the named kind (``"aes"`` or ``"chacha"``).
#[pyfunction]
fn new_cipher(key: &[u8], kind: &str) -> PyResult<PyAeadCipher> {
    let key = check_key(key)?;
    let kind = parse_kind(kind)?;
    Ok(PyAeadCipher {
        inner: std::sync::Arc::new(RustAeadCipher::with_kind(kind, &key)),
    })
}

/// Construct an AeadCipher with the host's preferred AEAD (AES-256-GCM
/// when AES-NI / ARM crypto extensions are available; ChaCha20-Poly1305
/// fallback otherwise).
#[pyfunction]
fn default_cipher_for_host(key: &[u8]) -> PyResult<PyAeadCipher> {
    let key = check_key(key)?;
    Ok(PyAeadCipher {
        inner: std::sync::Arc::new(RustAeadCipher::default_for_host(&key)),
    })
}

/// Return the host's preferred AEAD kind without constructing a cipher.
#[pyfunction]
fn default_aead_kind() -> &'static str {
    kind_to_str(AeadKind::default_for_host())
}

/// Return whether the host has hardware AES (AES-NI / ARM crypto ext)
/// detected at runtime.
#[pyfunction]
fn host_has_hardware_aes() -> bool {
    ol_aead::cipher::has_hardware_aes()
}

/// Register the aead submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Constants per ADR-0002.
    m.add("FRAME_KEY_LEN", RUST_FRAME_KEY_LEN)?;
    m.add("AEAD_TAG_LEN", RUST_AEAD_TAG_LEN)?;
    m.add("AEAD_FRAME_PLAINTEXT_LEN", RUST_AEAD_FRAME_PLAINTEXT_LEN)?;
    m.add(
        "MAX_CHUNK_PLAINTEXT_LEN",
        ol_aead::frame::MAX_CHUNK_PLAINTEXT_LEN,
    )?;

    // Types and functions.
    m.add_class::<PyAeadCipher>()?;
    m.add_function(wrap_pyfunction!(new_cipher, m)?)?;
    m.add_function(wrap_pyfunction!(default_cipher_for_host, m)?)?;
    m.add_function(wrap_pyfunction!(default_aead_kind, m)?)?;
    m.add_function(wrap_pyfunction!(host_has_hardware_aes, m)?)?;

    Ok(())
}
