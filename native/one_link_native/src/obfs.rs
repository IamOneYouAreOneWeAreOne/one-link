//! pyo3 wrapper for `ol_onion::transport_obfs` — row 7 pluggable
//! transport. Exposes:
//! - Primitive byte XOR (`obfuscate` / `deobfuscate` / `derive_nonce`).
//! - Handshake (BridgeKeypair, ClientHandshake, ServerHandshake).
//! - Session (per-direction seal/open with handshake-derived keys).

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand_core_06::OsRng;

use ol_onion::transport_obfs::{
    deobfuscate as core_deobfuscate, derive_nonce as core_derive_nonce,
    obfuscate as core_obfuscate, BridgeKeypair, ClientHandshake as RustClientHandshake,
    HandshakeError, ServerHandshake as RustServerHandshake, Session as RustSession,
    BRIDGE_ID_LEN, BRIDGE_PUBKEY_LEN, BRIDGE_SECRET_LEN, HANDSHAKE_EPOCH_SECS, HANDSHAKE_LEN,
    HANDSHAKE_MAC_LEN, OBFS_KEY_LEN, OBFS_NONCE_LEN, SESSION_KEY_LEN,
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

fn map_hs_err(e: HandshakeError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

// ── Primitive ───────────────────────────────────────────────────

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

#[pyfunction]
fn derive_nonce<'py>(
    py: Python<'py>,
    conn_id: u32,
    packet_counter: u64,
) -> Bound<'py, PyBytes> {
    let n = core_derive_nonce(conn_id, packet_counter);
    PyBytes::new_bound(py, &n)
}

// ── Handshake / Session ────────────────────────────────────────

/// Generate a fresh bridge keypair. Returns (secret_seed_32, public_32, id_32).
#[pyfunction]
fn generate_bridge_keypair<'py>(
    py: Python<'py>,
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
)> {
    let kp = BridgeKeypair::generate(&mut OsRng);
    Ok((
        PyBytes::new_bound(py, &kp.secret_bytes()),
        PyBytes::new_bound(py, &kp.public_bytes()),
        PyBytes::new_bound(py, &kp.id_bytes()),
    ))
}

/// Bidirectional obfuscation session.
#[pyclass(name = "Session")]
pub struct PySession {
    inner: Option<RustSession>,
}

#[pymethods]
impl PySession {
    /// Seal outbound data with the given packet counter.
    fn seal_outbound<'py>(
        &self,
        py: Python<'py>,
        plaintext: &[u8],
        counter: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let session = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("session is closed"))?;
        let out = session.seal_outbound(plaintext, counter);
        Ok(PyBytes::new_bound(py, &out))
    }

    /// Open inbound data with the peer's packet counter.
    fn open_inbound<'py>(
        &self,
        py: Python<'py>,
        ciphertext: &[u8],
        counter: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let session = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("session is closed"))?;
        let out = session
            .open_inbound(ciphertext, counter)
            .map_err(|_| PyValueError::new_err("session open failed"))?;
        Ok(PyBytes::new_bound(py, &out))
    }

    /// Explicitly close the session, zeroizing the keys on drop.
    fn close(&mut self) {
        let _ = self.inner.take();
    }

    /// True iff the session is still active.
    fn is_open(&self) -> bool {
        self.inner.is_some()
    }
}

/// Client handshake state held across the start → finish round trip.
#[pyclass(name = "ClientHandshake")]
pub struct PyClientHandshake {
    inner: Option<RustClientHandshake>,
    first_message: [u8; HANDSHAKE_LEN],
}

#[pymethods]
impl PyClientHandshake {
    #[new]
    fn new(bridge_public: &[u8], bridge_id: &[u8], now_unix: u64) -> PyResult<Self> {
        if bridge_public.len() != BRIDGE_PUBKEY_LEN {
            return Err(PyValueError::new_err(format!(
                "bridge_public must be {BRIDGE_PUBKEY_LEN} bytes"
            )));
        }
        if bridge_id.len() != BRIDGE_ID_LEN {
            return Err(PyValueError::new_err(format!(
                "bridge_id must be {BRIDGE_ID_LEN} bytes"
            )));
        }
        let mut pk = [0u8; BRIDGE_PUBKEY_LEN];
        pk.copy_from_slice(bridge_public);
        let mut id = [0u8; BRIDGE_ID_LEN];
        id.copy_from_slice(bridge_id);
        let inner = RustClientHandshake::start(&mut OsRng, &pk, &id, now_unix);
        let first_message = *inner.first_message();
        Ok(Self {
            inner: Some(inner),
            first_message,
        })
    }

    /// The bytes the daemon transmits to the bridge.
    fn first_message<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.first_message)
    }

    /// Complete the handshake using the bridge's reply. Consumes
    /// the handshake state and returns a Session.
    fn finish(&mut self, server_reply: &[u8]) -> PyResult<PySession> {
        let inner = self
            .inner
            .take()
            .ok_or_else(|| PyRuntimeError::new_err("handshake already finished"))?;
        let session = inner.finish(server_reply).map_err(map_hs_err)?;
        Ok(PySession {
            inner: Some(session),
        })
    }
}

/// Server-side accept: pure static fn.
#[pyfunction]
fn server_accept<'py>(
    py: Python<'py>,
    bridge_secret: &[u8],
    bridge_id: &[u8],
    client_first_message: &[u8],
    now_unix: u64,
) -> PyResult<(Bound<'py, PyBytes>, PySession)> {
    if bridge_secret.len() != BRIDGE_SECRET_LEN {
        return Err(PyValueError::new_err(format!(
            "bridge_secret must be {BRIDGE_SECRET_LEN} bytes"
        )));
    }
    if bridge_id.len() != BRIDGE_ID_LEN {
        return Err(PyValueError::new_err(format!(
            "bridge_id must be {BRIDGE_ID_LEN} bytes"
        )));
    }
    let mut sk = [0u8; BRIDGE_SECRET_LEN];
    sk.copy_from_slice(bridge_secret);
    let mut id = [0u8; BRIDGE_ID_LEN];
    id.copy_from_slice(bridge_id);
    let bridge = BridgeKeypair::from_parts(sk, id);
    let (reply, session) =
        RustServerHandshake::accept(&mut OsRng, &bridge, client_first_message, now_unix)
            .map_err(map_hs_err)?;
    Ok((
        PyBytes::new_bound(py, &reply),
        PySession {
            inner: Some(session),
        },
    ))
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(obfuscate, m)?)?;
    m.add_function(wrap_pyfunction!(deobfuscate, m)?)?;
    m.add_function(wrap_pyfunction!(derive_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(generate_bridge_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(server_accept, m)?)?;
    m.add_class::<PyClientHandshake>()?;
    m.add_class::<PySession>()?;
    m.add("OBFS_KEY_LEN", OBFS_KEY_LEN)?;
    m.add("OBFS_NONCE_LEN", OBFS_NONCE_LEN)?;
    m.add("BRIDGE_PUBKEY_LEN", BRIDGE_PUBKEY_LEN)?;
    m.add("BRIDGE_SECRET_LEN", BRIDGE_SECRET_LEN)?;
    m.add("BRIDGE_ID_LEN", BRIDGE_ID_LEN)?;
    m.add("HANDSHAKE_LEN", HANDSHAKE_LEN)?;
    m.add("HANDSHAKE_MAC_LEN", HANDSHAKE_MAC_LEN)?;
    m.add("HANDSHAKE_EPOCH_SECS", HANDSHAKE_EPOCH_SECS)?;
    m.add("SESSION_KEY_LEN", SESSION_KEY_LEN)?;
    Ok(())
}
