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
use zeroize::Zeroize;

use ol_confidential::{
    fresh_attestation_nonce, verify_attestation, AttestationDoc, AttestationNonce,
    ConfidentialError, ConfidentialProvider, ConfidentialTier, IssuerSdpPubkey, ProviderTag,
    SealedKey, SoftwareProvider, ATTESTATION_FRESHNESS_WINDOW_SECS, ATTESTATION_NONCE_LEN,
    ISSUER_SDP_PUBKEY_LEN,
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

fn issuer_sdp_pubkey_from_bytes(b: &[u8]) -> PyResult<IssuerSdpPubkey> {
    if b.len() != ISSUER_SDP_PUBKEY_LEN {
        return Err(PyValueError::new_err(format!(
            "issuer_sdp_pubkey must be exactly {ISSUER_SDP_PUBKEY_LEN} bytes, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; ISSUER_SDP_PUBKEY_LEN];
    out.copy_from_slice(b);
    Ok(out)
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
        // Zeroize the local copy of the master seed before returning.
        // Without this, a core dump captured between this fn's return
        // and the next stack write recovers the seed bytes verbatim
        // (audit finding M5, May 14 2026).
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let sealed_result = self.inner.seal_master(&arr);
        arr.zeroize();
        let sealed = sealed_result.map_err(map_err)?;
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
    /// platform_quote_bytes, issuer_sdp_pubkey_bytes, master_sig_bytes)`
    /// — the Python daemon reassembles into its own typed wrapper.
    ///
    /// `issuer_sdp_pubkey` is the 32-byte Ed25519 SDP-layer pubkey of
    /// the issuer's channel identity (audit C1). The master signature
    /// binds to it so a verifier rejects any doc whose embedded SDP
    /// pubkey does not match the channel they're actually talking to.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[pyo3(signature = (
        sealed_bytes,
        sealed_tag,
        peer_nonce,
        issued_unix,
        deadline_unix,
        issuer_sdp_pubkey,
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
        issuer_sdp_pubkey: &[u8],
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
        Bound<'py, PyBytes>,
    )> {
        let tag = provider_tag_from_u8(sealed_tag)?;
        let sealed = SealedKey {
            provider_tag: tag,
            bytes: sealed_bytes.to_vec(),
        };
        let nonce = nonce_from_bytes(peer_nonce)?;
        let witness = field_witness_from_bytes(field_witness)?;
        let sdp = issuer_sdp_pubkey_from_bytes(issuer_sdp_pubkey)?;
        let doc = self
            .inner
            .attest(
                &sealed,
                nonce,
                issued_unix,
                deadline_unix,
                witness.as_ref(),
                sdp,
            )
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
            PyBytes::new_bound(py, &doc.issuer_sdp_pubkey),
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
///
/// **Audit M7 May 2026 — gated**: gated behind the
/// `unstable-deterministic-provider` Cargo feature, which is OFF in
/// the default `maturin develop --release` build. Production wheels
/// raise a runtime error when callers reach this function. Test
/// wheels (built with `--features unstable-deterministic-provider`)
/// get the real constructor. The Python wrapper documents this in
/// its docstring.
#[pyfunction]
fn software_provider_from_seed(_seed: &[u8]) -> PyResult<PySoftwareProvider> {
    #[cfg(feature = "unstable-deterministic-provider")]
    {
        if _seed.len() != 32 {
            return Err(PyValueError::new_err(format!(
                "provider seed must be exactly 32 bytes, got {}",
                _seed.len()
            )));
        }
        // Zeroize the local seed copy after the provider has taken it
        // (audit finding M5, May 14 2026).
        let mut arr = [0u8; 32];
        arr.copy_from_slice(_seed);
        let provider = SoftwareProvider::from_seed(&arr);
        arr.zeroize();
        return Ok(PySoftwareProvider { inner: provider });
    }
    #[cfg(not(feature = "unstable-deterministic-provider"))]
    {
        Err(PyValueError::new_err(
            "software_provider_from_seed is disabled in this build. \
             It is a deterministic-seed constructor intended for \
             KAT vectors only and is gated behind the \
             `unstable-deterministic-provider` Cargo feature \
             (audit M7 May 2026). Use fresh_software_provider for \
             production callers.",
        ))
    }
}

/// Generate a fresh 32-byte attestation nonce.
#[pyfunction]
fn attestation_nonce(py: Python<'_>) -> Bound<'_, PyBytes> {
    let n = fresh_attestation_nonce(&mut OsRng);
    PyBytes::new_bound(py, &n)
}

/// Verify a (deconstructed) AttestationDoc. Pass the same field
/// tuple shape as returned by `attest`, plus the verifier's expected
/// channel-identity SDP pubkey (audit C1).
///
/// `min_tier_byte` enforces the provider-tier floor (audit H4):
/// `1` = Software (any tier accepted), `2` = HardwareBound, `3` =
/// HardwareAttested.
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
    issuer_sdp_pubkey,
    master_sig,
    expected_peer_nonce,
    now_unix,
    expected_issuer_sdp_pubkey,
    expected_field_witness=None,
    min_tier_byte=1u8,
))]
fn verify(
    provider_tag: u8,
    master_vk: &[u8],
    peer_nonce: &[u8],
    issued_unix: u64,
    deadline_unix: u64,
    field_witness_commitment: Option<&[u8]>,
    platform_quote: &[u8],
    issuer_sdp_pubkey: &[u8],
    master_sig: &[u8],
    expected_peer_nonce: &[u8],
    now_unix: u64,
    expected_issuer_sdp_pubkey: &[u8],
    expected_field_witness: Option<&[u8]>,
    min_tier_byte: u8,
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
    let doc_sdp = issuer_sdp_pubkey_from_bytes(issuer_sdp_pubkey)?;
    let expected_sdp = issuer_sdp_pubkey_from_bytes(expected_issuer_sdp_pubkey)?;
    let min_tier = match min_tier_byte {
        1 => ConfidentialTier::Software,
        2 => ConfidentialTier::HardwareBound,
        3 => ConfidentialTier::HardwareAttested,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown ConfidentialTier byte: {other}"
            )));
        }
    };
    let doc = AttestationDoc {
        provider_tag: tag,
        master_vk: vk,
        peer_nonce: nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment: fwc,
        platform_quote: platform_quote.to_vec(),
        issuer_sdp_pubkey: doc_sdp,
        master_sig: master_sig.to_vec(),
    };
    verify_attestation(
        &doc,
        &expected_nonce,
        expected_fw.as_ref(),
        now_unix,
        min_tier,
        &expected_sdp,
    )
    .map_err(map_err)
}

// ── Audit M6: Windows TPM-hardened provider pyo3 surface ───────────
//
// The hardened provider operates IDENTICALLY to PySoftwareProvider
// from the daemon's perspective — same `seal_master` / `derive_child`
// / `sealed_sign` / `verifying_key` / `attest` shape — but with
// `tier_byte()` reporting HardwareBound (= 2) and the returned
// attestation doc carrying a TPM-signed `platform_quote`. The peer
// verifier uses the same `verify()` free function with
// `min_tier_byte=2` to enforce the upgrade.
//
// Gated behind the `windows-tpm` Cargo feature so non-Windows hosts
// can build the rest of `one_link_native` without pulling in the
// Microsoft `windows` crate. A runtime caller on a wheel that wasn't
// built with the feature gets a friendly `PyValueError` from the
// fallback `fresh_windows_hardened_provider` stub.

#[cfg(feature = "windows-tpm")]
#[pyclass(module = "one_link_native.confidential")]
struct PyWindowsHardenedProvider {
    inner: ol_confidential::WindowsHardenedProvider,
}

#[cfg(feature = "windows-tpm")]
#[pymethods]
impl PyWindowsHardenedProvider {
    /// Tier code. `2` = HardwareBound.
    fn tier_byte(&self) -> u8 {
        self.inner.tier() as u8
    }

    /// Wire tag byte. `4` = WindowsTpm.
    fn tag_byte(&self) -> u8 {
        self.inner.tag().as_u8()
    }

    /// Seal a 32-byte master seed. Returns `(sealed_bytes, tag_byte)`
    /// with tag = WindowsTpm so future round-trips bind to this
    /// provider class.
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
        let sealed_result = self.inner.seal_master(&arr);
        arr.zeroize();
        let sealed = sealed_result.map_err(map_err)?;
        Ok((
            PyBytes::new_bound(py, &sealed.bytes),
            sealed.provider_tag.as_u8(),
        ))
    }

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

    /// Issue a TPM-rooted attestation doc. Same return tuple as
    /// PySoftwareProvider.attest, but the `platform_quote` field
    /// carries the ECDSA-P256 signature produced by the TPM-resident
    /// attestation key.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    #[pyo3(signature = (
        sealed_bytes,
        sealed_tag,
        peer_nonce,
        issued_unix,
        deadline_unix,
        issuer_sdp_pubkey,
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
        issuer_sdp_pubkey: &[u8],
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
        Bound<'py, PyBytes>,
    )> {
        let tag = provider_tag_from_u8(sealed_tag)?;
        let sealed = SealedKey {
            provider_tag: tag,
            bytes: sealed_bytes.to_vec(),
        };
        let nonce = nonce_from_bytes(peer_nonce)?;
        let witness = field_witness_from_bytes(field_witness)?;
        let sdp = issuer_sdp_pubkey_from_bytes(issuer_sdp_pubkey)?;
        let doc = self
            .inner
            .attest(
                &sealed,
                nonce,
                issued_unix,
                deadline_unix,
                witness.as_ref(),
                sdp,
            )
            .map_err(map_err)?;
        let cmt = doc
            .field_witness_commitment
            .map(|c| PyBytes::new_bound(py, &c));
        Ok((
            doc.provider_tag.as_u8(),
            PyBytes::new_bound(py, &doc.master_vk.to_bytes()),
            PyBytes::new_bound(py, &doc.peer_nonce),
            doc.issued_unix,
            doc.deadline_unix,
            cmt,
            PyBytes::new_bound(py, &doc.platform_quote),
            PyBytes::new_bound(py, &doc.issuer_sdp_pubkey),
            PyBytes::new_bound(py, &doc.master_sig),
        ))
    }
}

/// Construct a fresh `WindowsHardenedProvider`. Generates a per-
/// process software AEAD sealing key + acquires (or creates) the
/// TPM-resident ECDSA-P256 attestation key under `tpm_key_name`.
///
/// `tpm_key_name` is the NCrypt key handle name; daemons should use
/// a stable per-install identifier (e.g. `"OL-confidential-attest-v1"`)
/// so the same TPM key survives across daemon restarts.
#[cfg(feature = "windows-tpm")]
#[pyfunction]
fn fresh_windows_hardened_provider(tpm_key_name: &str) -> PyResult<PyWindowsHardenedProvider> {
    let provider =
        ol_confidential::WindowsHardenedProvider::create(&mut OsRng, tpm_key_name)
            .map_err(map_err)?;
    Ok(PyWindowsHardenedProvider { inner: provider })
}

/// Fallback when the wheel wasn't built with `--features windows-tpm`.
/// Surfaces a friendly error rather than a NameError on import.
#[cfg(not(feature = "windows-tpm"))]
#[pyfunction]
fn fresh_windows_hardened_provider(_tpm_key_name: &str) -> PyResult<PyObject> {
    Err(PyValueError::new_err(
        "WindowsHardenedProvider is disabled in this build. \
         Build the native wheel with `--features windows-tpm` on a \
         Windows host with TPM 2.0 (audit M6 May 2026).",
    ))
}

pub fn register(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySoftwareProvider>()?;
    #[cfg(feature = "windows-tpm")]
    m.add_class::<PyWindowsHardenedProvider>()?;
    m.add_function(wrap_pyfunction!(fresh_software_provider, m)?)?;
    m.add_function(wrap_pyfunction!(software_provider_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(fresh_windows_hardened_provider, m)?)?;
    m.add_function(wrap_pyfunction!(attestation_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    // Surface the build-time feature gate so Python callers can
    // check capability availability without trying-and-catching.
    m.add("HAS_WINDOWS_TPM_PROVIDER", cfg!(feature = "windows-tpm"))?;
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
