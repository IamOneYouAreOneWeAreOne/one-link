//! Windows TPM-bound attestation key via the `NCrypt` Platform Crypto
//! Provider ("Microsoft Platform Crypto Provider", aka PCP).
//!
//! ## What this module gives us
//!
//! - An ECDSA-P256 signing key requested from Windows' Microsoft Platform
//!   Crypto Provider. On a correctly configured supported host, private-key
//!   operations are intended to be TPM-backed and private material is not
//!   exportable through this API.
//! - The current wire envelope exports a CNG public blob and signature but no
//!   EK/vendor certificate or standard TPM quote. A remote verifier therefore
//!   proves possession/continuity of that ECDSA key, not TPM residency or a
//!   specific physical host, unless an external enrollment validates and pins
//!   hardware provenance.
//! - A way to **anchor the `platform_quote` field** of
//!   [`crate::AttestationDoc`] in real hardware. The master sig still
//!   covers the entire transcript including `platform_quote` bytes, so
//!   the two signatures bind the document to the master key and included
//!   platform public key. Hardware provenance remains a separate gate.
//!
//! ## What it does NOT give us (yet)
//!
//! - The TPM **cannot** sign Ed25519 or ML-DSA-65, so `sealed_sign`
//!   still happens in software. Closing T-LOCAL-MAL-ROOT for the
//!   master sign path is a larger architectural change (split
//!   signing: TPM signs ECDSA, software signs PQ, both validate at
//!   peer) and lands as a separate ship.
//!
//! ## Admin / permission requirements
//!
//! No admin needed. The Platform Crypto Provider runs in user mode
//! and the per-user key store accepts `NCrypt` operations without
//! elevation on consumer Windows.

#![allow(unsafe_code)] // FFI into the OS crypto API.

use windows::core::PCWSTR;
use windows::Win32::Security::Cryptography::{
    NCryptCreatePersistedKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSignHash, CERT_KEY_SPEC, NCRYPT_FLAGS, NCRYPT_HANDLE,
    NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE,
};

use crate::errors::{ConfidentialError, ConfidentialResult};

/// Provider name for the Windows Platform Crypto Provider — the user-
/// mode `NCrypt` KSP that backs keys with the TPM.
const PROVIDER_NAME: &str = "Microsoft Platform Crypto Provider";

/// `NCrypt` algorithm identifier for ECDSA over the P-256 curve.
const ECDSA_P256_ALG: &str = "ECDSA_P256";

/// `NCrypt` blob type for the public-key portion of an ECC key.
const ECC_PUBLIC_BLOB: &str = "ECCPUBLICBLOB";

/// HRESULT returned by `NCryptOpenKey` when the named key doesn't
/// exist in the keyset yet. HRESULT values are 32-bit signed
/// integers in Windows headers, but the canonical hex form is
/// unsigned; the cast preserves the bit pattern.
const NTE_BAD_KEYSET: i32 = i32::from_ne_bytes(0x8009_0016_u32.to_ne_bytes());

/// Wide-string helper. `NCrypt` APIs take `PCWSTR` (null-terminated
/// UTF-16). The vector must outlive the FFI call.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn internal(msg: String) -> ConfidentialError {
    // Audit L6 May 2026: was previously
    // `ConfidentialError::Internal(Box::leak(msg.into_boxed_str()))`,
    // which leaked one boxed-str per error path. Hardware TPM
    // errors are rare in steady state but can still pile up under
    // device-state churn or repeated probe failures. Use the new
    // `InternalOwned(String)` variant — same Display output, no leak.
    ConfidentialError::InternalOwned(msg)
}

/// A TPM-resident ECDSA-P256 signing key, looked up by per-user key
/// name in the Platform Crypto Provider.
///
/// On drop, the `NCrypt` key + provider handles are closed (the
/// persisted key itself remains in the user's key store for future
/// runs — that's the whole point of "persisted").
pub struct TpmAttestationKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl std::fmt::Debug for TpmAttestationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmAttestationKey")
            .field("provider", &self.provider.0)
            .field("key", &self.key.0)
            .finish()
    }
}

impl Drop for TpmAttestationKey {
    fn drop(&mut self) {
        // SAFETY: handles are valid for the lifetime of `self`;
        // NCryptFreeObject is the documented release call for both
        // provider and key handles. Errors during free are ignored —
        // there's nothing useful to do at drop time.
        unsafe {
            if self.key.0 != 0 {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.key.0));
            }
            if self.provider.0 != 0 {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.provider.0));
            }
        }
    }
}

impl TpmAttestationKey {
    /// Acquire an existing TPM-backed ECDSA-P256 key by name, or
    /// create one if it doesn't exist. Idempotent across runs.
    ///
    /// `key_name` is a per-user identifier. Consumers SHOULD use a
    /// stable string like `"OL-confidential-attestation-v1"` so the
    /// same key persists across daemon restarts.
    ///
    /// # Errors
    /// Returns `Internal` if `NCrypt` fails (TPM unavailable, KSP
    /// refused the create operation, etc.).
    pub fn acquire_or_create(key_name: &str) -> ConfidentialResult<Self> {
        let provider_name_w = wide(PROVIDER_NAME);
        let key_name_w = wide(key_name);
        let alg_w = wide(ECDSA_P256_ALG);

        let mut provider = NCRYPT_PROV_HANDLE::default();
        // SAFETY: pointers point at valid wide buffers we own.
        unsafe {
            NCryptOpenStorageProvider(&raw mut provider, PCWSTR(provider_name_w.as_ptr()), 0)
                .map_err(|e| internal(format!("NCryptOpenStorageProvider: {e}")))?;
        }

        let mut key = NCRYPT_KEY_HANDLE::default();
        // SAFETY: provider handle valid; key_name wide-encoded.
        let open_status = unsafe {
            NCryptOpenKey(
                provider,
                &raw mut key,
                PCWSTR(key_name_w.as_ptr()),
                CERT_KEY_SPEC(0),
                NCRYPT_FLAGS(0),
            )
        };
        if let Err(e) = open_status {
            if e.code().0 == NTE_BAD_KEYSET {
                // Key doesn't exist — create + finalize.
                // SAFETY: provider valid; alg + key_name wide-encoded.
                unsafe {
                    NCryptCreatePersistedKey(
                        provider,
                        &raw mut key,
                        PCWSTR(alg_w.as_ptr()),
                        PCWSTR(key_name_w.as_ptr()),
                        CERT_KEY_SPEC(0),
                        NCRYPT_FLAGS(0),
                    )
                    .map_err(|e| internal(format!("NCryptCreatePersistedKey: {e}")))?;
                    NCryptFinalizeKey(key, NCRYPT_FLAGS(0))
                        .map_err(|e| internal(format!("NCryptFinalizeKey: {e}")))?;
                }
            } else {
                // SAFETY: drop frees provider handle.
                return Err(internal(format!("NCryptOpenKey: {e}")));
            }
        }
        Ok(Self { provider, key })
    }

    /// Export the public key in CNG `BCRYPT_ECCKEY_BLOB` form.
    ///
    /// # Errors
    /// Returns `Internal` if `NCryptExportKey` fails.
    pub fn public_blob(&self) -> ConfidentialResult<Vec<u8>> {
        let blob_type_w = wide(ECC_PUBLIC_BLOB);
        let mut needed: u32 = 0;
        // SAFETY: key handle valid; output None is the documented
        // "ask for required size" idiom.
        unsafe {
            NCryptExportKey(
                self.key,
                None,
                PCWSTR(blob_type_w.as_ptr()),
                None,
                None,
                &raw mut needed,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| internal(format!("NCryptExportKey(size): {e}")))?;
        }
        let mut buf = vec![0u8; needed as usize];
        // SAFETY: buf has exactly `needed` bytes allocated.
        unsafe {
            NCryptExportKey(
                self.key,
                None,
                PCWSTR(blob_type_w.as_ptr()),
                None,
                Some(&mut buf),
                &raw mut needed,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| internal(format!("NCryptExportKey: {e}")))?;
        }
        buf.truncate(needed as usize);
        Ok(buf)
    }

    /// Sign a 32-byte digest. The TPM produces a raw ECDSA-P256
    /// signature `r || s` (64 bytes, big-endian).
    ///
    /// # Errors
    /// Returns `Internal` if `NCryptSignHash` fails.
    pub fn sign(&self, digest: &[u8; 32]) -> ConfidentialResult<Vec<u8>> {
        let mut needed: u32 = 0;
        // SAFETY: digest is a 32-byte buffer; None output is the
        // documented "ask for required size" idiom.
        unsafe {
            NCryptSignHash(
                self.key,
                None,
                digest,
                None,
                &raw mut needed,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| internal(format!("NCryptSignHash(size): {e}")))?;
        }
        let mut sig = vec![0u8; needed as usize];
        // SAFETY: sig has `needed` bytes allocated.
        unsafe {
            NCryptSignHash(
                self.key,
                None,
                digest,
                Some(&mut sig),
                &raw mut needed,
                NCRYPT_FLAGS(0),
            )
            .map_err(|e| internal(format!("NCryptSignHash: {e}")))?;
        }
        sig.truncate(needed as usize);
        Ok(sig)
    }
}

// SAFETY: NCrypt handles are thread-safe per MSDN guidance. The
// kernel resolves the opaque handle integers; multiple threads can
// hold and use them simultaneously.
unsafe impl Send for TpmAttestationKey {}
unsafe impl Sync for TpmAttestationKey {}

/// Produce a `platform_quote` payload that binds a doc-level digest
/// to the TPM-resident ECDSA-P256 key. Wire layout:
///
/// ```text
/// platform_quote := u16(pub_len) || pub_blob || u16(sig_len) || sig
/// ```
///
/// # Errors
/// Returns `Internal` if either `public_blob` or `sign` fails.
pub fn produce_platform_quote(
    key: &TpmAttestationKey,
    digest: &[u8; 32],
) -> ConfidentialResult<Vec<u8>> {
    let pub_blob = key.public_blob()?;
    let sig = key.sign(digest)?;
    let pub_len = u16::try_from(pub_blob.len())
        .map_err(|_| internal("public_blob too large for u16 length prefix".into()))?;
    let sig_len = u16::try_from(sig.len())
        .map_err(|_| internal("sig too large for u16 length prefix".into()))?;
    let mut out = Vec::with_capacity(2 + pub_blob.len() + 2 + sig.len());
    out.extend_from_slice(&pub_len.to_be_bytes());
    out.extend_from_slice(&pub_blob);
    out.extend_from_slice(&sig_len.to_be_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Audit L6 May 2026: deleted duplicate `parse_platform_quote`
/// implementation. The canonical parser lives in
/// [`crate::platform_quote::parse_platform_quote`]; this module
/// re-exports it for back-compat with callers that imported through
/// `windows_tpm`. The duplicate also held a `Box::leak`-based
/// `internal()` helper that leaked per-error allocations; that's
/// gone too.
pub use crate::platform_quote::parse_platform_quote;

/// Caller-supplied claims bound into one TPM-backed attestation.
#[derive(Debug, Clone, Copy)]
pub struct TpmAttestationClaims<'a> {
    /// Fresh challenge supplied by the verifying peer.
    pub peer_nonce: crate::AttestationNonce,
    /// Issuance time as Unix seconds.
    pub issued_unix: u64,
    /// Expiration deadline as Unix seconds.
    pub deadline_unix: u64,
    /// Optional field-witness digest input.
    pub field_witness: Option<&'a [u8; 32]>,
    /// Session-description public key bound to the attestation.
    pub issuer_sdp_pubkey: crate::attestation::IssuerSdpPubkey,
}

/// Produce a fully TPM-rooted [`crate::AttestationDoc`].
///
/// Flow:
/// 1. Compute the TPM sub-transcript via
///    [`crate::canonical_platform_quote_subtranscript`].
/// 2. TPM signs that digest; package as `platform_quote` envelope.
/// 3. Call [`crate::ConfidentialProvider::attest`] with the
///    `platform_quote` already wired in by way of a custom
///    issue path — the master sig over the full canonical
///    transcript now transitively commits to the TPM sig.
///
/// The returned doc's `platform_quote` field carries the TPM
/// signature; peers verify it via
/// [`crate::verify_platform_quote`] in addition to the master sig.
///
/// # Errors
/// Returns whatever [`crate::ConfidentialProvider::attest`] or the
/// TPM `produce_platform_quote` call returns.
pub fn attest_with_tpm(
    provider: &crate::SoftwareProvider,
    sealed_master: &crate::SealedKey,
    tpm: &TpmAttestationKey,
    claims: TpmAttestationClaims<'_>,
) -> ConfidentialResult<crate::AttestationDoc> {
    use crate::attestation::{canonical_attestation_transcript, AttestationDoc};
    use crate::ProviderTag;

    let TpmAttestationClaims {
        peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness,
        issuer_sdp_pubkey,
    } = claims;

    // Single unseal of the master — used for both verifying-key
    // derivation and final hybrid signature. Replaces the earlier
    // pair of `provider.verifying_key()` + `provider.sealed_sign()`
    // calls (which each unsealed independently).
    let (sk, master_vk) = provider.derive_hybrid_pair(sealed_master)?;
    let master_vk_bytes = master_vk.to_bytes();
    let field_witness_commitment = field_witness.map(|w| {
        let mut h = blake3::Hasher::new();
        h.update(crate::attestation::ATTESTATION_FIELD_WITNESS_DOMAIN);
        h.update(w);
        *h.finalize().as_bytes()
    });
    // (1) TPM sub-transcript over the doc's metadata.
    let sub_digest = crate::platform_quote::canonical_platform_quote_subtranscript(
        ProviderTag::WindowsTpm,
        &master_vk_bytes,
        &peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment.as_ref(),
    );
    // (2) TPM signs the sub-digest; package as platform_quote bytes.
    let platform_quote = produce_platform_quote(tpm, &sub_digest)?;

    // (3) Master hybrid sig over the full transcript including
    //     platform_quote. Transitively commits to the TPM sig.
    let full_transcript = canonical_attestation_transcript(
        ProviderTag::WindowsTpm,
        &master_vk,
        &peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness,
        &platform_quote,
        &issuer_sdp_pubkey,
    );
    let master_sig = sk.sign(&full_transcript)?.to_vec();

    Ok(AttestationDoc {
        provider_tag: ProviderTag::WindowsTpm,
        master_vk,
        peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment,
        platform_quote,
        issuer_sdp_pubkey,
        master_sig,
    })
}

/// Verify a [`crate::AttestationDoc`] that carries a TPM-rooted
/// `platform_quote`. Performs BOTH layers of validation:
///
/// 1. [`crate::verify_attestation`] for the master hybrid sig +
///    nonce binding + freshness window + field-witness binding.
/// 2. [`crate::verify_platform_quote`] for the TPM ECDSA sig over
///    the sub-transcript.
///
/// On success returns the TPM's public-key blob so the caller can
/// pin it for trust-on-first-use binding (subsequent verifies can
/// then refuse docs that change TPM identity).
///
/// # Errors
/// Returns the first layered failure (master sig or TPM sig).
pub fn verify_attestation_with_tpm(
    doc: &crate::AttestationDoc,
    expected_peer_nonce: &crate::AttestationNonce,
    expected_field_witness: Option<&[u8; 32]>,
    now_unix: u64,
    min_tier: crate::tier::ConfidentialTier,
    expected_issuer_sdp_pubkey: &crate::attestation::IssuerSdpPubkey,
) -> ConfidentialResult<Vec<u8>> {
    use crate::ProviderTag;

    if doc.provider_tag != ProviderTag::WindowsTpm {
        return Err(ConfidentialError::AttestationProviderTagMismatch);
    }
    // (1) Layered master sig + nonce + freshness + witness + tier + SDP binding.
    crate::verify_attestation(
        doc,
        expected_peer_nonce,
        expected_field_witness,
        now_unix,
        min_tier,
        expected_issuer_sdp_pubkey,
    )?;
    // (2) TPM platform_quote chain.
    crate::verify_platform_quote(
        &doc.platform_quote,
        doc.provider_tag,
        &doc.master_vk.to_bytes(),
        &doc.peer_nonce,
        doc.issued_unix,
        doc.deadline_unix,
        doc.field_witness_commitment.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests requiring TPM hardware are marked #[ignore] so default
    // `cargo test` skips them. Run with `--ignored` to exercise.

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn tpm_acquire_export_sign() {
        let key =
            TpmAttestationKey::acquire_or_create("OL-confidential-test-acquire-export-sign-v1")
                .expect("TPM key creation");
        let pub_blob = key.public_blob().expect("public_blob");
        assert!(!pub_blob.is_empty());
        let digest = [0x42u8; 32];
        let sig = key.sign(&digest).expect("TPM sign");
        assert!(!sig.is_empty());
    }

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn tpm_platform_quote_round_trip() {
        let key = TpmAttestationKey::acquire_or_create("OL-confidential-test-platform-quote-v1")
            .expect("TPM key creation");
        let digest = [0x77u8; 32];
        let quote = produce_platform_quote(&key, &digest).expect("platform_quote");
        let (pub_blob, sig) = parse_platform_quote(&quote).expect("parse");
        assert!(!pub_blob.is_empty());
        assert!(!sig.is_empty());
    }

    #[test]
    fn parse_rejects_truncated_quote() {
        let r = parse_platform_quote(&[0u8; 2]);
        assert!(r.is_err());
    }

    #[test]
    fn parse_rejects_bad_pub_len() {
        // pub_len says 1000 but only 10 bytes follow.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1000u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 10]);
        let r = parse_platform_quote(&bytes);
        assert!(r.is_err());
    }
}
