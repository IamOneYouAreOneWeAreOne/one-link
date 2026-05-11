//! `one_link_native.pqkem` — Python binding for `ol_pqkem`.
//!
//! Exposes the ML-KEM-768 + X25519 hybrid KEM per ADR-0017. Python
//! callers generate keypairs, encapsulate against a peer's public key,
//! and decapsulate ciphertexts to recover a 32-byte shared secret.
//!
//! The pyo3 binding owns its own RNG (`rand::thread_rng`) for randomness
//! sourcing; deterministic test vectors come through the Rust-side
//! crate directly.

use ol_pqkem::{
    decapsulate as rust_decapsulate, encapsulate as rust_encapsulate, keypair as rust_keypair,
    HybridCiphertext, HybridPublicKey, HybridSecretKey, HYBRID_CIPHERTEXT_LEN,
    HYBRID_PUBLIC_KEY_LEN, HYBRID_SECRET_KEY_LEN, SHARED_SECRET_LEN,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

/// Python-visible hybrid public key.
#[pyclass(name = "HybridPublicKey", module = "one_link_native.pqkem")]
#[derive(Debug, Clone)]
pub struct PyHybridPublicKey {
    inner: HybridPublicKey,
}

#[pymethods]
impl PyHybridPublicKey {
    /// Parse from `HYBRID_PUBLIC_KEY_LEN` wire bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        HybridPublicKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(pqkem_err_to_py)
    }

    /// Serialize to wire bytes.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.to_bytes())
    }

    fn __repr__(&self) -> String {
        format!("HybridPublicKey({} bytes)", HYBRID_PUBLIC_KEY_LEN)
    }
}

/// Python-visible hybrid secret key. The inner key material is
/// zeroized on drop via the `ol_pqkem` newtype's internal `Zeroizing`.
#[pyclass(name = "HybridSecretKey", module = "one_link_native.pqkem")]
pub struct PyHybridSecretKey {
    inner: HybridSecretKey,
}

impl std::fmt::Debug for PyHybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PyHybridSecretKey")
            .field("len", &HYBRID_SECRET_KEY_LEN)
            .finish_non_exhaustive()
    }
}

#[pymethods]
impl PyHybridSecretKey {
    /// Parse from `HYBRID_SECRET_KEY_LEN` wire bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        HybridSecretKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(pqkem_err_to_py)
    }

    /// Serialize to wire bytes. Caller is responsible for storing
    /// these securely + clearing the returned bytes when done.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let buf = self.inner.to_bytes();
        PyBytes::new_bound(py, &buf[..])
    }

    fn __repr__(&self) -> &str {
        "HybridSecretKey(<redacted>)"
    }
}

/// Python-visible hybrid ciphertext.
#[pyclass(name = "HybridCiphertext", module = "one_link_native.pqkem")]
#[derive(Debug, Clone)]
pub struct PyHybridCiphertext {
    inner: HybridCiphertext,
}

#[pymethods]
impl PyHybridCiphertext {
    /// Parse from `HYBRID_CIPHERTEXT_LEN` wire bytes.
    #[staticmethod]
    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        HybridCiphertext::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(pqkem_err_to_py)
    }

    /// Serialize to wire bytes.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.to_bytes())
    }

    fn __repr__(&self) -> String {
        format!("HybridCiphertext({} bytes)", HYBRID_CIPHERTEXT_LEN)
    }
}

/// Generate a fresh hybrid keypair via the OS RNG.
#[pyfunction]
fn keypair<'py>(py: Python<'py>) -> (PyHybridPublicKey, PyHybridSecretKey) {
    let _ = py;
    let mut rng = rand_core_06::OsRng;
    let (pk, sk) = rust_keypair(&mut rng);
    (
        PyHybridPublicKey { inner: pk },
        PyHybridSecretKey { inner: sk },
    )
}

/// Encapsulate against `pk`. Returns `(ciphertext, shared_secret_bytes)`.
/// The shared secret is the 32-byte BLAKE3-derived hybrid key suitable
/// for direct use as an AEAD key.
#[pyfunction]
fn encapsulate<'py>(
    py: Python<'py>,
    pk: &PyHybridPublicKey,
) -> PyResult<(PyHybridCiphertext, Bound<'py, PyBytes>)> {
    let mut rng = rand_core_06::OsRng;
    let (ct, ss) = rust_encapsulate(&pk.inner, &mut rng).map_err(pqkem_err_to_py)?;
    let py_ct = PyHybridCiphertext { inner: ct };
    let ss_bytes = PyBytes::new_bound(py, &ss[..]);
    Ok((py_ct, ss_bytes))
}

/// Decapsulate `ct` with `sk`. Returns the 32-byte shared secret.
///
/// Per FIPS 203 implicit rejection, a malformed ciphertext still
/// returns a (pseudo-random) secret rather than erroring; callers must
/// rely on the AEAD auth tag to detect tampering.
#[pyfunction]
fn decapsulate<'py>(
    py: Python<'py>,
    sk: &PyHybridSecretKey,
    ct: &PyHybridCiphertext,
) -> PyResult<Bound<'py, PyBytes>> {
    let ss = rust_decapsulate(&sk.inner, &ct.inner).map_err(pqkem_err_to_py)?;
    Ok(PyBytes::new_bound(py, &ss[..]))
}

fn pqkem_err_to_py(err: ol_pqkem::PqKemError) -> PyErr {
    crate::errors::OlPqKemError::new_err(err.to_string())
}

/// Register the `pqkem` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_pqkem::VERSION)?;
    m.add("HYBRID_PUBLIC_KEY_LEN", HYBRID_PUBLIC_KEY_LEN)?;
    m.add("HYBRID_SECRET_KEY_LEN", HYBRID_SECRET_KEY_LEN)?;
    m.add("HYBRID_CIPHERTEXT_LEN", HYBRID_CIPHERTEXT_LEN)?;
    m.add("SHARED_SECRET_LEN", SHARED_SECRET_LEN)?;
    m.add_class::<PyHybridPublicKey>()?;
    m.add_class::<PyHybridSecretKey>()?;
    m.add_class::<PyHybridCiphertext>()?;
    m.add_function(wrap_pyfunction!(keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(decapsulate, m)?)?;
    Ok(())
}

// We need a `__repr__` returning `String` because pyo3's `&str`
// requires the slot's signature to use a borrow-able type. Keep this
// fn as `String` form for consistency with the other classes.
