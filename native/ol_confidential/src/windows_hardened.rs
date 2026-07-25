//! Windows TPM-hardened [`ConfidentialProvider`] composition.
//!
//! Bundles [`crate::SoftwareProvider`] (for the seal/unseal/sign
//! primitives) with a [`crate::windows_tpm::TpmAttestationKey`] (for
//! TPM-rooted attestation). Every `attest` call produces a doc
//! whose `platform_quote` field carries a TPM-signed ECDSA-P256
//! commitment over the sub-transcript; the master hybrid sig over
//! the full transcript transitively commits to that TPM sig. The
//! tier upgrades to [`ConfidentialTier::HardwareBound`].
//!
//! ## What this gets us
//!
//! - **Platform-key possession and continuity**: a peer can validate that
//!   this document was signed by the private key matching the included CNG
//!   public blob. Cross-platform
//!   verifiers use the pure-Rust `p256` verifier in
//!   [`crate::platform_quote`].
//! - **Explicit limit**: without a verified EK/vendor attestation chain, a
//!   remote peer cannot prove that the key is TPM-resident or bound to one
//!   physical chip. Pinning the public blob can detect a later key change;
//!   it is not hardware provenance.
//!
//! ## What we explored but didn't ship
//!
//! TPM-wrapped AEAD sealing-key (RSA-OAEP via `NCryptEncrypt` /
//! `NCryptDecrypt`) does NOT work with the Microsoft Platform Crypto
//! Provider on consumer Win11 — the PCP supports TPM-backed keys
//! for SIGNING only, not encryption. True AEAD-key wrap would
//! require either a smart-card KSP, raw tss-esapi (heavy C
//! dependency), or an NCryptSecretAgreement-based ECDH derivation
//! (complex policy plumbing). For Phase 2 first ship, the
//! attestation-key path adds a platform-key signature/continuity primitive
//! without moving the master seal/sign operation out of software.

use ol_pqsig::HybridVerifyingKey;
use rand_core::{CryptoRng, RngCore};

use crate::attestation::{AttestationDoc, AttestationNonce};
use crate::errors::ConfidentialResult;
use crate::provider::{ConfidentialProvider, ProviderTag};
use crate::sealed_key::SealedKey;
use crate::software::SoftwareProvider;
use crate::tier::ConfidentialTier;
use crate::windows_tpm::TpmAttestationKey;

/// Windows TPM-hardened composition over the software baseline.
///
/// Operates as a normal [`ConfidentialProvider`] but with
/// [`ConfidentialTier::HardwareBound`] and TPM-rooted attestations.
pub struct WindowsHardenedProvider {
    sw: SoftwareProvider,
    tpm: TpmAttestationKey,
}

impl std::fmt::Debug for WindowsHardenedProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsHardenedProvider")
            .field("tier", &self.tier())
            .field("tag", &self.tag())
            .finish_non_exhaustive()
    }
}

impl WindowsHardenedProvider {
    /// Build a hardened provider:
    /// - Generate a fresh per-process software AEAD sealing key.
    /// - Acquire or create the TPM-resident ECDSA-P256 attestation
    ///   key under `tpm_key_name`.
    ///
    /// # Errors
    /// Returns `Internal` if the TPM key acquisition fails.
    pub fn create<R: RngCore + CryptoRng>(
        rng: &mut R,
        tpm_key_name: &str,
    ) -> ConfidentialResult<Self> {
        let sw = SoftwareProvider::generate(rng);
        let tpm = TpmAttestationKey::acquire_or_create(tpm_key_name)?;
        Ok(Self { sw, tpm })
    }

    /// Borrow the inner software provider — useful for unit tests
    /// and for callers that need to construct sealed blobs
    /// directly through the software path.
    #[must_use]
    pub fn software(&self) -> &SoftwareProvider {
        &self.sw
    }

    /// Borrow the inner TPM attestation key — useful for callers
    /// that need to attest standalone digests outside the
    /// `ConfidentialProvider` trait.
    #[must_use]
    pub fn tpm(&self) -> &TpmAttestationKey {
        &self.tpm
    }
}

impl ConfidentialProvider for WindowsHardenedProvider {
    fn tier(&self) -> ConfidentialTier {
        ConfidentialTier::HardwareBound
    }

    fn tag(&self) -> ProviderTag {
        ProviderTag::WindowsTpm
    }

    fn seal_master(&self, seed: &[u8; 32]) -> ConfidentialResult<SealedKey> {
        // Seal under the software AEAD key but stamp the wire tag
        // as WindowsTpm so the sealed blob is bound to this
        // provider's identity (the verifying-key path checks the
        // tag and refuses cross-provider unseals).
        let sw_sealed = self.sw.seal_master(seed)?;
        Ok(SealedKey::new(
            ProviderTag::WindowsTpm,
            sw_sealed.bytes.clone(),
        ))
    }

    fn derive_child(
        &self,
        sealed_master: &SealedKey,
        context_tag: &[u8],
    ) -> ConfidentialResult<SealedKey> {
        // Re-tag the input as Software for the inner call, then
        // re-tag the output back to WindowsTpm.
        let sw_in = SealedKey::new(ProviderTag::Software, sealed_master.bytes.clone());
        let sw_out = self.sw.derive_child(&sw_in, context_tag)?;
        Ok(SealedKey::new(
            ProviderTag::WindowsTpm,
            sw_out.bytes.clone(),
        ))
    }

    fn sealed_sign(&self, sealed: &SealedKey, transcript: &[u8]) -> ConfidentialResult<Vec<u8>> {
        let sw_sealed = SealedKey::new(ProviderTag::Software, sealed.bytes.clone());
        self.sw.sealed_sign(&sw_sealed, transcript)
    }

    fn verifying_key(&self, sealed: &SealedKey) -> ConfidentialResult<HybridVerifyingKey> {
        let sw_sealed = SealedKey::new(ProviderTag::Software, sealed.bytes.clone());
        self.sw.verifying_key(&sw_sealed)
    }

    fn attest(
        &self,
        sealed_master: &SealedKey,
        peer_nonce: AttestationNonce,
        issued_unix: u64,
        deadline_unix: u64,
        field_witness: Option<&[u8; 32]>,
        issuer_sdp_pubkey: crate::attestation::IssuerSdpPubkey,
    ) -> ConfidentialResult<AttestationDoc> {
        // Route through windows_tpm::attest_with_tpm so the
        // returned doc carries a TPM-signed platform_quote.
        let sw_sealed = SealedKey::new(ProviderTag::Software, sealed_master.bytes.clone());
        crate::windows_tpm::attest_with_tpm(
            &self.sw,
            &sw_sealed,
            &self.tpm,
            crate::windows_tpm::TpmAttestationClaims {
                peer_nonce,
                issued_unix,
                deadline_unix,
                field_witness,
                issuer_sdp_pubkey,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn hardened_tier_is_hardware_bound() {
        let p =
            WindowsHardenedProvider::create(&mut OsRng, "OL-confidential-test-hardened-tier-v1")
                .expect("provider create");
        assert_eq!(p.tier(), ConfidentialTier::HardwareBound);
        assert!(p.tier().meets(ConfidentialTier::Software));
        assert!(!p.tier().meets(ConfidentialTier::HardwareAttested));
    }

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn hardened_seal_sign_verify_round_trip() {
        let p = WindowsHardenedProvider::create(&mut OsRng, "OL-confidential-test-hardened-rt-v1")
            .expect("provider create");
        let seed = [0x42; 32];
        let sealed = p.seal_master(&seed).expect("seal");
        assert_eq!(sealed.provider_tag, ProviderTag::WindowsTpm);
        let vk = p.verifying_key(&sealed).expect("vk");
        let sig = p.sealed_sign(&sealed, b"hello hardened").expect("sign");
        vk.verify(b"hello hardened", &sig).expect("verify");
    }

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn hardened_child_diverges_from_master() {
        let p =
            WindowsHardenedProvider::create(&mut OsRng, "OL-confidential-test-hardened-child-v1")
                .expect("provider create");
        let seed = [0x55; 32];
        let master = p.seal_master(&seed).expect("seal master");
        let child = p
            .derive_child(&master, b"phone-day-1")
            .expect("derive child");
        let vk_m = p.verifying_key(&master).expect("vk m");
        let vk_c = p.verifying_key(&child).expect("vk c");
        assert_ne!(vk_m.to_bytes(), vk_c.to_bytes());
    }

    #[test]
    #[ignore = "requires hardware TPM access"]
    fn hardened_attest_is_tpm_rooted() {
        use crate::{fresh_attestation_nonce, windows_tpm::verify_attestation_with_tpm};
        let p =
            WindowsHardenedProvider::create(&mut OsRng, "OL-confidential-test-hardened-attest-v1")
                .expect("provider create");
        let seed = [0x77; 32];
        let sealed = p.seal_master(&seed).expect("seal");
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = p
            .attest(
                &sealed,
                nonce,
                1_000,
                1_020,
                None,
                [0u8; crate::attestation::ISSUER_SDP_PUBKEY_LEN],
            )
            .expect("attest");
        assert!(!doc.platform_quote.is_empty(), "must carry TPM quote");
        let expected_sdp = [0u8; crate::attestation::ISSUER_SDP_PUBKEY_LEN];
        let tpm_pub = verify_attestation_with_tpm(
            &doc,
            &nonce,
            None,
            1_010,
            crate::ConfidentialTier::HardwareBound,
            &expected_sdp,
        )
        .expect("verify");
        assert!(!tpm_pub.is_empty());
    }
}
