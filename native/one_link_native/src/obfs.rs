//! pyo3 wrapper for `ol_onion::transport_obfs` — row 7 pluggable
//! transport obfuscation primitive.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ol_onion::transport_obfs::{
    deobfuscate as core_deobfuscate, derive_nonce as core_derive_nonce,
    obfuscate as core_obfuscate, OBFS_KEY_LEN, OBFS_NONCE_LEN,
};

fn check_key_nonce(key: &[u8], nonce: &[u8]) -> PyResult<()> {
    if key.len() != OBFS_KEY_LEN {
        return Err(PyValueError::new_err(format!(
            "key must be {OBFS_KEY_LEN} bytes, got {}",
            key.len()
        )));
    }
    if nonce.len() != OBFS_NONCE_LEN {
        return Err(PyValueError::new_err(format!(
            "nonce must be {OBFS_NONCE_LEN} bytes, got {}",
            nonce.len()
        )));
    }
    Ok(())
}

/// Obfuscate `data` with the (key, nonce) pair. Returns a new bytes
/// object of the same length. Length-preserving XOR; same op for
/// deobfuscate.
#[pyfunction]
fn obfuscate<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    check_key_nonce(key, nonce)?;
    let mut key_arr = [0u8; OBFS_KEY_LEN];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; OBFS_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let out = core_obfuscate(&key_arr, &nonce_arr, data);
    Ok(PyBytes::new_bound(py, &out))
}

/// Deobfuscate `data` with the (key, nonce) pair. Symmetric with
/// `obfuscate`; same key + nonce recovers the original bytes.
#[pyfunction]
fn deobfuscate<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    check_key_nonce(key, nonce)?;
    let mut key_arr = [0u8; OBFS_KEY_LEN];
    key_arr.copy_from_slice(key);
    let mut nonce_arr = [0u8; OBFS_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);
    let out = core_deobfuscate(&key_arr, &nonce_arr, data);
    Ok(PyBytes::new_bound(py, &out))
}

/// Derive a per-packet nonce from (conn_id, counter). Returns the
/// 12-byte ChaCha20 nonce. Daemons SHOULD use this rather than
/// rolling their own to avoid (key, nonce) reuse.
#[pyfunction]
fn derive_nonce<'py>(
    py: Python<'py>,
    conn_id: u32,
    packet_counter: u64,
) -> Bound<'py, PyBytes> {
    let n = core_derive_nonce(conn_id, packet_counter);
    PyBytes::new_bound(py, &n)
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(obfuscate, m)?)?;
    m.add_function(wrap_pyfunction!(deobfuscate, m)?)?;
    m.add_function(wrap_pyfunction!(derive_nonce, m)?)?;
    m.add("OBFS_KEY_LEN", OBFS_KEY_LEN)?;
    m.add("OBFS_NONCE_LEN", OBFS_NONCE_LEN)?;
    Ok(())
}
