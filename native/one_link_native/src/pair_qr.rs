//! pyo3 wrapper for [`ol_pair_qr`] — Coherence Mesh F2.
//!
//! Exposes the pair-by-QR flow to the Python daemon as a pair of
//! stateful classes (`PyInviter`, `PyScanner`) plus convenience
//! free functions for the SAS / transcript / chain-key derivations.
//!
//! The daemon supplies a 32-byte identity Ed25519 signing-key seed
//! (already managed by `one_link.master_seed`) and gets back the
//! QR-encodable invite bytes + a state machine handle.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use ed25519_dalek::SigningKey;
use rand_core_06::OsRng;

use ol_pair_qr::invite::{CapabilityScope, Invite};
use ol_pair_qr::sas::Sas;
use ol_pair_qr::{Inviter, PairError, Scanner};

// ── Helpers ───────────────────────────────────────────────────────

fn map_err(e: PairError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn signing_key_from_seed(seed: &[u8]) -> PyResult<SigningKey> {
    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "signing-key seed must be 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(seed);
    Ok(SigningKey::from_bytes(&arr))
}

// ── Inviter side ─────────────────────────────────────────────────

/// Stateful inviter (the QR-generating side).
///
/// Lifecycle:
/// 1. `PyInviter(id_seed, expiry_unix, scope=b"")` — generate.
/// 2. `.invite_bytes()` — bytes to encode as QR.
/// 3. `.receive_response(response_bytes)` → returns SAS string.
/// 4. After user confirms SAS: `.confirm()` or
///    `.confirm_with_factor2(factor2_key)` →
///    `(confirm_bytes, chain_key)`.
#[pyclass(name = "Inviter")]
pub struct PyInviter {
    inner: Option<Inviter>,
}

#[pymethods]
impl PyInviter {
    /// Generate a new invite + return the inviter handle.
    #[new]
    #[pyo3(signature = (id_seed, expiry_unix, scope = None))]
    fn new(id_seed: &[u8], expiry_unix: u64, scope: Option<&[u8]>) -> PyResult<Self> {
        let sk = signing_key_from_seed(id_seed)?;
        let scope_obj = match scope {
            Some(b) => CapabilityScope::from_bytes(b).map_err(map_err)?,
            None => CapabilityScope::empty(),
        };
        let inner = Inviter::new(sk, &mut OsRng, expiry_unix, scope_obj);
        Ok(Self { inner: Some(inner) })
    }

    /// Encoded invite bytes — what the QR layer encodes.
    fn invite_bytes<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inv = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        Ok(PyBytes::new_bound(py, &inv.invite_bytes()))
    }

    /// Identity pubkey baked into the invite.
    fn id_pubkey<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inv = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        Ok(PyBytes::new_bound(py, &inv.invite().id_pubkey))
    }

    /// Current state name (for logging).
    fn state(&self) -> PyResult<String> {
        let inv = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        Ok(format!("{:?}", inv.state()))
    }

    /// Process the scanner's response. Returns the SAS the user
    /// should display + read aloud.
    fn receive_response(&mut self, response_bytes: &[u8]) -> PyResult<String> {
        let inv = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        let sas = inv.receive_response(response_bytes).map_err(map_err)?;
        Ok(sas.display())
    }

    /// SAS to display in the UI (callable after `receive_response`).
    fn sas(&self) -> PyResult<Option<String>> {
        let inv = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        Ok(inv.sas().map(|s| s.display()))
    }

    /// User confirmed the SAS matches. Sign the final confirm + emit
    /// the chain key. Returns (confirm_bytes, chain_key) as bytes.
    fn confirm<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let inv = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        let (confirm_bytes, key) = inv.confirm().map_err(map_err)?;
        Ok((
            PyBytes::new_bound(py, &confirm_bytes),
            PyBytes::new_bound(py, key.as_bytes()),
        ))
    }

    /// Like `confirm()` but mixes in a 32-byte Factor-2 key.
    fn confirm_with_factor2<'py>(
        &mut self,
        py: Python<'py>,
        factor2_key: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        if factor2_key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "factor2_key must be 32 bytes, got {}",
                factor2_key.len()
            )));
        }
        let mut f2 = [0u8; 32];
        f2.copy_from_slice(factor2_key);
        let inv = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Inviter already consumed"))?;
        let (confirm_bytes, key) = inv.confirm_with_factor2(&f2).map_err(map_err)?;
        Ok((
            PyBytes::new_bound(py, &confirm_bytes),
            PyBytes::new_bound(py, key.as_bytes()),
        ))
    }

    /// User said the SAS doesn't match (or aborted out-of-band).
    fn abort(&mut self) {
        if let Some(inv) = self.inner.as_mut() {
            inv.abort();
        }
    }
}

// ── Scanner side ─────────────────────────────────────────────────

/// Stateful scanner (the QR-reading side).
///
/// Lifecycle:
/// 1. `PyScanner.scan(id_seed, invite_bytes, now_unix)` →
///    `(scanner, response_bytes)`.
/// 2. UI displays `.sas()`, user compares with inviter's display.
/// 3. After user confirms SAS: `.receive_confirm(confirm_bytes)`
///    or `.receive_confirm_with_factor2(confirm_bytes, factor2_key)`
///    → `chain_key`.
#[pyclass(name = "Scanner")]
pub struct PyScanner {
    inner: Option<Scanner>,
}

#[pymethods]
impl PyScanner {
    /// Scan + verify an invite; produce the response bytes to send.
    #[staticmethod]
    #[pyo3(signature = (id_seed, invite_bytes, now_unix))]
    fn scan<'py>(
        py: Python<'py>,
        id_seed: &[u8],
        invite_bytes: &[u8],
        now_unix: u64,
    ) -> PyResult<(Self, Bound<'py, PyBytes>)> {
        let sk = signing_key_from_seed(id_seed)?;
        let (scanner, response_bytes) =
            Scanner::scan(sk, invite_bytes, now_unix, &mut OsRng).map_err(map_err)?;
        Ok((
            Self {
                inner: Some(scanner),
            },
            PyBytes::new_bound(py, &response_bytes),
        ))
    }

    /// SAS to display in the UI.
    fn sas(&self) -> PyResult<String> {
        let s = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Scanner already consumed"))?;
        Ok(s.sas().display())
    }

    /// Inviter identity pubkey (32 bytes; for UI / pin record).
    fn inviter_pubkey<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let s = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Scanner already consumed"))?;
        Ok(PyBytes::new_bound(py, s.inviter_pubkey()))
    }

    /// Current state name (for logging).
    fn state(&self) -> PyResult<String> {
        let s = self
            .inner
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("Scanner already consumed"))?;
        Ok(format!("{:?}", s.state()))
    }

    /// Accept inviter's confirm, return the final chain key.
    fn receive_confirm<'py>(
        &mut self,
        py: Python<'py>,
        confirm_bytes: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let s = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Scanner already consumed"))?;
        let key = s.receive_confirm(confirm_bytes).map_err(map_err)?;
        Ok(PyBytes::new_bound(py, key.as_bytes()))
    }

    /// Accept inviter's confirm + mix in factor-2 key.
    fn receive_confirm_with_factor2<'py>(
        &mut self,
        py: Python<'py>,
        confirm_bytes: &[u8],
        factor2_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        if factor2_key.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "factor2_key must be 32 bytes, got {}",
                factor2_key.len()
            )));
        }
        let mut f2 = [0u8; 32];
        f2.copy_from_slice(factor2_key);
        let s = self
            .inner
            .as_mut()
            .ok_or_else(|| PyRuntimeError::new_err("Scanner already consumed"))?;
        let key = s
            .receive_confirm_with_factor2(confirm_bytes, &f2)
            .map_err(map_err)?;
        Ok(PyBytes::new_bound(py, key.as_bytes()))
    }

    /// User said the SAS doesn't match (or aborted out-of-band).
    fn abort(&mut self) {
        if let Some(s) = self.inner.as_mut() {
            s.abort();
        }
    }
}

// ── Free functions ───────────────────────────────────────────────

/// Decode + verify an invite from its QR bytes. Returns
/// `(id_pubkey, ephemeral_x25519_pk, nonce, expiry_unix,
/// scope_bytes)`. Useful for UI display before the scanner agrees.
#[pyfunction]
fn decode_invite<'py>(
    py: Python<'py>,
    invite_bytes: &[u8],
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    u64,
    Bound<'py, PyBytes>,
)> {
    let inv = Invite::decode_and_verify(invite_bytes).map_err(map_err)?;
    Ok((
        PyBytes::new_bound(py, &inv.id_pubkey),
        PyBytes::new_bound(py, &inv.ephemeral_x25519_pk),
        PyBytes::new_bound(py, &inv.nonce),
        inv.expiry_unix,
        PyBytes::new_bound(py, inv.scope.as_bytes()),
    ))
}

/// Derive the SAS for a 32-byte transcript hash. Useful for tests
/// that want to compute the SAS from a known transcript.
#[pyfunction]
fn sas_from_transcript<'py>(_py: Python<'py>, transcript: &[u8]) -> PyResult<String> {
    if transcript.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "transcript must be 32 bytes, got {}",
            transcript.len()
        )));
    }
    let mut t = [0u8; 32];
    t.copy_from_slice(transcript);
    let th = ol_pair_qr::TranscriptHash::from_bytes(t);
    let sas = Sas::derive(&th);
    Ok(sas.display())
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyInviter>()?;
    m.add_class::<PyScanner>()?;
    m.add_function(wrap_pyfunction!(decode_invite, m)?)?;
    m.add_function(wrap_pyfunction!(sas_from_transcript, m)?)?;
    m.add("SAS_WORD_COUNT", ol_pair_qr::SAS_WORD_COUNT)?;
    m.add("SAS_BITS", ol_pair_qr::SAS_BITS)?;
    m.add("CHAIN_KEY_LEN", ol_pair_qr::CHAIN_KEY_LEN)?;
    m.add("INVITE_NONCE_LEN", ol_pair_qr::INVITE_NONCE_LEN)?;
    m.add("INVITE_MAX_BYTES", ol_pair_qr::INVITE_MAX_BYTES)?;
    m.add("INVITE_VERSION", ol_pair_qr::INVITE_VERSION)?;
    Ok(())
}
