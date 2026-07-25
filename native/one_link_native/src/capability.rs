//! `one_link_native.capability` — Python binding for `ol_capability`.
//!
//! Surfaces macaroon-style first-party capabilities (ADR-0021) to the
//! daemon: `Capability` minted from a root key + caveats; the existing
//! Ed25519 grant scheme is migrated against this in Phase C.

use ol_capability::{CapError, Capability, Caveat, Context};
use ol_capability::{
    CAP_ID_LEN, MAX_CAVEATS, MAX_OPERATION_NAMES, MAX_WIRE_BYTES, ROOT_KEY_LEN, SIGNATURE_LEN,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroizing;

/// Python-visible cap. Wraps `ol_capability::Capability` and carries a
/// `Vec<u8>` representation of each caveat for round-trip diagnostics.
#[pyclass(
    from_py_object,
    name = "Capability",
    module = "one_link_native.capability"
)]
#[derive(Debug, Clone)]
pub struct PyCapability {
    inner: Capability,
}

#[pymethods]
impl PyCapability {
    /// Mint a fresh root capability with no caveats.
    ///
    /// `id` must be exactly 32 bytes; `root_key` must be exactly 32 bytes.
    #[staticmethod]
    fn root(id: &[u8], root_key: &[u8]) -> PyResult<Self> {
        let id_arr = bytes_to_array::<CAP_ID_LEN>(id, "id")?;
        let key_arr = bytes_to_array::<ROOT_KEY_LEN>(root_key, "root_key")?;
        let zk = Zeroizing::new(key_arr);
        Ok(Self {
            inner: Capability::root(id_arr, &zk),
        })
    }

    /// Decode from wire bytes.
    #[staticmethod]
    fn decode(bytes: &[u8]) -> PyResult<Self> {
        Capability::decode(bytes)
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Encode to wire bytes.
    fn encode<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.encode())
    }

    /// 32-byte capability identifier.
    fn cap_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.id())
    }

    /// 32-byte current HMAC chain signature.
    fn signature<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.signature())
    }

    /// Number of caveats.
    fn num_caveats(&self) -> usize {
        self.inner.caveats().len()
    }

    /// Attenuate with an `expires_at` (Unix-ms) caveat.
    fn attenuate_expires_at(&self, ms: u64) -> PyResult<Self> {
        self.inner
            .attenuate(Caveat::ExpiresAt(ms))
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Attenuate with a peer-fingerprint caveat.
    fn attenuate_peer(&self, fp: &[u8]) -> PyResult<Self> {
        let arr = bytes_to_array::<32>(fp, "peer fingerprint")?;
        self.inner
            .attenuate(Caveat::PeerFingerprint(arr))
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Attenuate with a path-prefix caveat.
    fn attenuate_path_prefix(&self, prefix: &str) -> PyResult<Self> {
        self.inner
            .attenuate(Caveat::PathPrefix(prefix.to_string()))
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Attenuate with an operation-allowlist caveat.
    fn attenuate_operation_in(&self, ops: Vec<String>) -> PyResult<Self> {
        self.inner
            .attenuate(Caveat::OperationIn(ops))
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Attenuate with an audit-tag caveat (never rejects, logs only).
    fn attenuate_audit_tag(&self, tag: &str) -> PyResult<Self> {
        self.inner
            .attenuate(Caveat::AuditTag(tag.to_string()))
            .map(|inner| Self { inner })
            .map_err(cap_err_to_py)
    }

    /// Verify against a root key + optional context fields.
    #[pyo3(signature = (root_key, now_ms=None, peer=None, path=None, operation=None))]
    fn verify(
        &self,
        root_key: &[u8],
        now_ms: Option<u64>,
        peer: Option<&[u8]>,
        path: Option<&str>,
        operation: Option<&str>,
    ) -> PyResult<()> {
        let key_arr = bytes_to_array::<ROOT_KEY_LEN>(root_key, "root_key")?;
        let zk = Zeroizing::new(key_arr);
        let peer_arr = match peer {
            Some(p) => Some(bytes_to_array::<32>(p, "peer fingerprint")?),
            None => None,
        };
        let mut ctx = Context::new();
        if let Some(ms) = now_ms {
            ctx = ctx.with_now(ms);
        }
        if let Some(fp) = peer_arr {
            ctx = ctx.with_peer(fp);
        }
        if let Some(p) = path {
            ctx = ctx.with_path(p);
        }
        if let Some(op) = operation {
            ctx = ctx.with_operation(op);
        }
        self.inner.verify(&zk, &ctx).map_err(cap_err_to_py)
    }

    /// Boolean form of `verify`: True iff the cap accepts.
    #[pyo3(signature = (root_key, now_ms=None, peer=None, path=None, operation=None))]
    fn accepts(
        &self,
        root_key: &[u8],
        now_ms: Option<u64>,
        peer: Option<&[u8]>,
        path: Option<&str>,
        operation: Option<&str>,
    ) -> PyResult<bool> {
        let key_arr = bytes_to_array::<ROOT_KEY_LEN>(root_key, "root_key")?;
        let zk = Zeroizing::new(key_arr);
        let peer_arr = match peer {
            Some(p) => Some(bytes_to_array::<32>(p, "peer fingerprint")?),
            None => None,
        };
        let mut ctx = Context::new();
        if let Some(ms) = now_ms {
            ctx = ctx.with_now(ms);
        }
        if let Some(fp) = peer_arr {
            ctx = ctx.with_peer(fp);
        }
        if let Some(p) = path {
            ctx = ctx.with_path(p);
        }
        if let Some(op) = operation {
            ctx = ctx.with_operation(op);
        }
        Ok(self.inner.accepts(&zk, &ctx))
    }

    fn __repr__(&self) -> String {
        format!(
            "Capability(num_caveats={}, sig=<32 bytes>)",
            self.inner.caveats().len()
        )
    }
}

fn bytes_to_array<const N: usize>(bytes: &[u8], field: &str) -> PyResult<[u8; N]> {
    if bytes.len() != N {
        return Err(PyValueError::new_err(format!(
            "{field} must be exactly {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn cap_err_to_py(err: CapError) -> PyErr {
    crate::errors::OlCapabilityError::new_err(crate::errors::owned_error_message(err))
}

/// Sanity-check: signature length matches the expectation.
#[allow(dead_code)]
const _: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];

/// Register the `capability` submodule.
pub(crate) fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", ol_capability::VERSION)?;
    m.add("CAP_ID_LEN", CAP_ID_LEN)?;
    m.add("ROOT_KEY_LEN", ROOT_KEY_LEN)?;
    m.add("SIGNATURE_LEN", SIGNATURE_LEN)?;
    m.add("MAX_CAVEATS", MAX_CAVEATS)?;
    m.add("MAX_OPERATION_NAMES", MAX_OPERATION_NAMES)?;
    m.add("MAX_WIRE_BYTES", MAX_WIRE_BYTES)?;
    m.add_class::<PyCapability>()?;
    Ok(())
}
