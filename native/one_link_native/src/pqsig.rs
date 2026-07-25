//! pyo3 wrapper for `ol_pqsig` — Ed25519 + ML-DSA-65 hybrid signatures.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand_core_06::OsRng;

use ol_pqsig::{
    HybridSigningKey, HybridVerifyingKey, PqSigError, HYBRID_SIG_LEN, HYBRID_SK_LEN, HYBRID_VK_LEN,
};

fn map_err(e: PqSigError) -> PyErr {
    PyValueError::new_err(crate::errors::owned_error_message(e))
}

/// Generate a fresh hybrid keypair. Returns (`sk_64`, `vk_1984`).
#[pyfunction]
fn generate_keypair(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (sk, vk) = HybridSigningKey::generate(&mut OsRng);
    (
        PyBytes::new(py, &sk.to_bytes()),
        PyBytes::new(py, &vk.to_bytes()),
    )
}

/// Derive the verifying key from a 64-byte hybrid signing key.
#[pyfunction]
fn derive_vk<'py>(py: Python<'py>, sk_bytes: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sk = HybridSigningKey::from_bytes(sk_bytes).map_err(map_err)?;
    Ok(PyBytes::new(py, &sk.verifying_key().to_bytes()))
}

/// Sign `message` with the 64-byte hybrid signing key. Returns the
/// 3373-byte hybrid signature.
#[pyfunction]
fn sign<'py>(py: Python<'py>, sk_bytes: &[u8], message: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let sk = HybridSigningKey::from_bytes(sk_bytes).map_err(map_err)?;
    let sig = sk.sign(message).map_err(map_err)?;
    Ok(PyBytes::new(py, &sig))
}

/// Verify a hybrid signature. Raises `ValueError` on any failure.
#[pyfunction]
fn verify(vk_bytes: &[u8], message: &[u8], sig: &[u8]) -> PyResult<()> {
    let vk = HybridVerifyingKey::from_bytes(vk_bytes).map_err(map_err)?;
    vk.verify(message, sig).map_err(map_err)?;
    Ok(())
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(derive_vk, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add("HYBRID_SK_LEN", HYBRID_SK_LEN)?;
    m.add("HYBRID_VK_LEN", HYBRID_VK_LEN)?;
    m.add("HYBRID_SIG_LEN", HYBRID_SIG_LEN)?;
    Ok(())
}
