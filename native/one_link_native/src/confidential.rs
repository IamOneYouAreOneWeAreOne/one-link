//! pyo3 wrapper for `ol_confidential` — Row 10 confidential-compute
//! daemon (sealed-op surface + remote attestation).
//!
//! ## Surface
//!
//! - `SoftwareProvider` — software-baseline tier. Generate from
//!   CSPRNG, seal a master seed, derive child seeds, sealed-sign
//!   transcripts, derive verifying keys, issue attestation docs.
//! - `AttestationDoc` — the wire envelope (provider tag, master
//!   verifying key, peer nonce, freshness window, optional field-
//!   witness commitment, optional platform quote, master signature).
//! - `verify_attestation` — peer-side validator with peer-nonce
//!   binding, freshness window enforcement, and optional field-
//!   witness binding check.
//! - `attestation_nonce` — fresh 32-byte peer nonce convenience.
//! - `fresh_software_provider`, `software_provider_from_seed` —
//!   construction helpers.
//!
//! All sealed-key blobs cross the FFI as opaque `bytes`. The daemon
//! treats them as round-trippable wire form; it never inspects them.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use rand_core_06::OsRng;

use ol_confidential::{
    fresh_attestation_nonce, verify_attestation, AttestationDoc, AttestationNonce,
    ConfidentialError, ConfidentialProvider, ProviderTag, SealedKey, SoftwareProvider,
    ATTESTATION_FRESHNESS_WINDOW_SECS, ATTESTATION_NONCE_LEN,
};
use ol_pqsig::HybridVerifyingKey;

fn map_err(e: ConfidentialError) -> PyErr {
    PyValueError::new_err(e.to_string())
}

fn nonce_from_bytes(b: &[u8]) -> PyResult<AttestationNonce> {
    if b.len() != ATTESTATION_NONCE_LEN {
        return Err(PyValueError::new_err(format!(
            "peer_nonce must be {ATTESTATION_NONCE_LEN} bytes, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; ATTESTATION_NONCE_LEN];
    out.copy_from_slice(b);
    Ok(out)
}

fn provider_tag_from_u8(b: u8) -> PyResult<ProviderTag> {
    ProviderTag::from_u8(b)
        .ok_or_else(|| PyValueError::new_err(format!("unknown ProviderTag byte: {b}")))
}

fn field_witness_from_bytes(b: Option<&[u8]>) -> PyResult<Option<[u8; 32]>> {
    let Some(slice) = b else { return Ok(None) };
    if slice.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "field_witness must be exactly 32 bytes, got {}",
            slice.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(Some(out))
}

// ── SoftwareProvider opaque handle ────────────────────────────────

#[pyclass(module = "one_link_native.confidential")]
struct PySoftwareProvider {
    inner: SoftwareProvider,
}

#[pymethods]
impl PySoftwareProvider {
    /// Tier code for this provider. `1` = Software.
    fn tier_byte(&self) -> u8 {
        self.inner.tier() as u8
    }

    /// Wire tag byte. `1` = Software.
    fn tag_byte(&self) -> u8 {
        self.inner.tag().as_u8()
    }

    /// Seal a 32-byte master seed. Returns the opaque sealed bytes
    /// + the provider tag byte (so callers can round-trip via
    /// `SealedKey`).
    fn seal_master<'py>(
        &self,
        py: Python<'py>,
        seed: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, u8)> {
        if seed.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "seed must be exactly 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let sealed = self.inner.seal_master(&arr).map_err(map_err)?;
        Ok((
            PyBytes::new_bound(py, &sealed.bytes),
            sealed.provider_tag.as_u8(),
        ))
    }

    /// Derive a child SealedKey from a sealed master + context tag.
    fn derive_child<'py>(
        &self,
        py: Python<'py>,
        sealed_master_bytes: &[u8],
        sealed_master_tag: u8,
        context_tag: &[u8],
    ) -> PyResult<(Bound<'py, PyBytes>, u8)> {
        let tag = provider_tag_from_u8(sealed_master_tag)?;
        let sealed_master = SealedKey {
            provider_tag: tag,
            bytes: sealed_master_bytes.to_vec(),
        };
        let child = self
            .inner
            .derive_child(&sealed_master, context_tag)
            .map_err(map_err)?;
        Ok((
            PyBytes::new_bound(py, &child.bytes),
            child.provider_tag.as_u8(),
        ))
    }

    /// Sign `transcript` under a sealed master. Returns the hybrid
    /// signature bytes.
    fn sealed_sign<'py>(
        &self,
        py: Python<'py>,
        sealed_bytes: &[u8],
        sealed_tag: u8,
        transcript: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let tag = provider_tag_from_u8(sealed_tag)?;
        let sealed = SealedKey {
            provider_tag: tag,
            bytes: sealed_bytes.to_vec(),
        };
        let sig = self.inner.sealed_sign(&sealed, transcript).map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &sig))
    }

    /// Recover the verifying key for a sealed master. Returns the
    /// 1984-byte hybrid VK bytes.
    fn verifying_key<'py>(
        &self,
        py: Python<'py>,
        sealed_bytes: &[u8],
        sealed_tag: u8,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let tag = provider_tag_from_u8(sealed_tag)?;
        let sealed = SealedKey {
            provider_tag: tag,
            bytes: sealed_bytes.to_vec(),
        };
        let vk = self.inner.verifying_key(&sealed).map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &vk.to_bytes()))
    }

    /// Issue an attestation doc. Returns the encoded fields as a
    /// tuple `(provider_tag_u8, master_vk_bytes, peer_nonce,
    /// issued_unix, deadline_unix, field_witness_commitment_or_none,
    /// platform_quote_bytes, master_sig_bytes)` — the Python daemon
    /// reassembles into its own typed wrapper.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[pyo3(signature = (
        sealed_bytes,
        sealed_tag,
        peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness=None,
    ))]
    fn attest<'py>(
        &self,
        py: Python<'py>,
        sealed_bytes: &[u8],
        sealed_tag: u8,
        peer_nonce: &[u8],
        issued_unix: u64,
        deadline_unix: u64,
        field_witness: Option<&[u8]>,
    ) -> PyResult<(
        u8,
        Bound<'py, PyBytes>,
        Bound<'py, PyBytes>,
        u64,
        u64,
        Option<Bound<'py, PyBytes>>,
        Bound<'py, PyBytes>,
        Bound<'py, PyBytes>,
    )> {
        let tag = provider_tag_from_u8(sealed_tag)?;
        let sealed = SealedKey {
            provider_tag: tag,
            bytes: sealed_bytes.to_vec(),
        };
        let nonce = nonce_from_bytes(peer_nonce)?;
        let witness = field_witness_from_bytes(field_witness)?;
        let doc = self
            .inner
            .attest(&sealed, nonce, issued_unix, deadline_unix, witness.as_ref())
            .map_err(map_err)?;
        let cmt = doc.field_witness_commitment.map(|c| PyBytes::new_bound(py, &c));
        Ok((
            doc.provider_tag.as_u8(),
            PyBytes::new_bound(py, &doc.master_vk.to_bytes()),
            PyBytes::new_bound(py, &doc.peer_nonce),
            doc.issued_unix,
            doc.deadline_unix,
            cmt,
            PyBytes::new_bound(py, &doc.platform_quote),
            PyBytes::new_bound(py, &doc.master_sig),
        ))
    }
}

// ── Free functions ────────────────────────────────────────────────

/// Generate a fresh `SoftwareProvider` from the OS CSPRNG.
#[pyfunction]
fn fresh_software_provider() -> PySoftwareProvider {
    PySoftwareProvider {
        inner: SoftwareProvider::generate(&mut OsRng),
    }
}

/// Deterministic constructor for KAT vectors and incident-response
/// replay — `seed` is a 32-byte hex-or-bytes value.
#[pyfunction]
fn software_provider_from_seed(seed: &[u8]) -> PyResult<PySoftwareProvider> {
    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "provider seed must be exactly 32 bytes, got {}",
            seed.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(seed);
    Ok(PySoftwareProvider {
        inner: SoftwareProvider::from_seed(&arr),
    })
}

/// Generate a fresh 32-byte attestation nonce.
#[pyfunction]
fn attestation_nonce(py: Python<'_>) -> Bound<'_, PyBytes> {
    let n = fresh_attestation_nonce(&mut OsRng);
    PyBytes::new_bound(py, &n)
}

/// Verify a (deconstructed) AttestationDoc. Pass the same field
/// tuple shape as returned by `attest`.
#[allow(clippy::too_many_arguments)]
#[pyfunction]
#[pyo3(signature = (
    provider_tag,
    master_vk,
    peer_nonce,
    issued_unix,
    deadline_unix,
    field_witness_commitment,
    platform_quote,
    master_sig,
    expected_peer_nonce,
    now_unix,
    expected_field_witness=None,
))]
fn verify(
    provider_tag: u8,
    master_vk: &[u8],
    peer_nonce: &[u8],
    issued_unix: u64,
    deadline_unix: u64,
    field_witness_commitment: Option<&[u8]>,
    platform_quote: &[u8],
    master_sig: &[u8],
    expected_peer_nonce: &[u8],
    now_unix: u64,
    expected_field_witness: Option<&[u8]>,
) -> PyResult<()> {
    let tag = provider_tag_from_u8(provider_tag)?;
    let vk = HybridVerifyingKey::from_bytes(master_vk)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let nonce = nonce_from_bytes(peer_nonce)?;
    let expected_nonce = nonce_from_bytes(expected_peer_nonce)?;
    let fwc = match field_witness_commitment {
        None => None,
        Some(b) => {
            if b.len() != 32 {
                return Err(PyValueError::new_err(
                    "field_witness_commitment must be 32 bytes",
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(b);
            Some(arr)
        }
    };
    let expected_fw = field_witness_from_bytes(expected_field_witness)?;
    let doc = AttestationDoc {
        provider_tag: tag,
        master_vk: vk,
        peer_nonce: nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment: fwc,
        platform_quote: platform_quote.to_vec(),
        master_sig: master_sig.to_vec(),
    };
    verify_attestation(&doc, &expected_nonce, expected_fw.as_ref(), now_unix)
        .map_err(map_err)
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySoftwareProvider>()?;
    m.add_function(wrap_pyfunction!(fresh_software_provider, m)?)?;
    m.add_function(wrap_pyfunction!(software_provider_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add("ATTESTATION_NONCE_LEN", ATTESTATION_NONCE_LEN)?;
    m.add(
        "ATTESTATION_FRESHNESS_WINDOW_SECS",
        ATTESTATION_FRESHNESS_WINDOW_SECS,
    )?;
    // Provider tag wire bytes (for daemons that need to round-trip
    // doc bytes through the network).
    m.add("PROVIDER_TAG_SOFTWARE", ProviderTag::Software.as_u8())?;
    m.add("PROVIDER_TAG_WINDOWS_TPM", ProviderTag::WindowsTpm.as_u8())?;
    m.add(
        "PROVIDER_TAG_APPLE_SE",
        ProviderTag::AppleSecureEnclave.as_u8(),
    )?;
    m.add(
        "PROVIDER_TAG_ANDROID_STRONGBOX",
        ProviderTag::AndroidStrongBox.as_u8(),
    )?;
    m.add("PROVIDER_TAG_INTEL_SGX", ProviderTag::IntelSgx.as_u8())?;
    m.add("PROVIDER_TAG_AMD_SEV_SNP", ProviderTag::AmdSevSnp.as_u8())?;
    m.add("PROVIDER_TAG_ARM_TRUSTZONE", ProviderTag::ArmTrustZone.as_u8())?;
    Ok(())
}
