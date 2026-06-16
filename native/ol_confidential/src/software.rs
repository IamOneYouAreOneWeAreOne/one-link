//! Software-only [`ConfidentialProvider`] baseline.
//!
//! ## Threat model
//!
//! - **Defeats**: user-mode malware reading the master key from process
//!   memory. The master never appears in plaintext at rest; sealing
//!   uses a per-process ephemeral key that itself only lives in
//!   `Zeroize`-protected memory and is dropped when the provider is.
//! - **Does NOT defeat**: root malware / kernel debugger / cold-boot
//!   / `/proc/mem` capture. Those need a hardware enclave, which
//!   ships in Phase 2 backends.
//!
//! ## Sealing primitive
//!
//! `seal(plaintext) = ChaCha20Poly1305(K_ephemeral, nonce, plaintext)`
//! where `K_ephemeral` is `BLAKE3(domain_tag`, `raw_ephemeral_seed`). The
//! seed is sampled from the supplied [`rand_core::CryptoRng`] at
//! provider construction and lives only in
//! [`ChaCha20Poly1305`]'s expanded form.
//!
//! Nonces are random per call (12 bytes from the AEAD's required
//! width). With ~2^96 nonces the collision probability is negligible
//! for any realistic call count.
//!
//! ## Child key derivation
//!
//! `child = HKDF(ikm = unsealed_master, salt = ChildKeyDomain, info = context_tag)`
//! implemented via BLAKE3-keyed XOF as `ol_pqsig` and the rest of the
//! Coherence Mesh already use. The intermediate IKM is held in a
//! [`Zeroize`]-clearing buffer and dropped before return.

use blake3::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ol_pqsig::{HybridSigningKey, HybridVerifyingKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::attestation::{
    canonical_attestation_transcript, AttestationDoc, AttestationNonce,
    ATTESTATION_FRESHNESS_WINDOW_SECS,
};
use crate::errors::{ConfidentialError, ConfidentialResult};
use crate::provider::{ConfidentialProvider, ProviderTag};
use crate::sealed_key::SealedKey;
use crate::tier::ConfidentialTier;

/// Domain tag for the ephemeral sealing key (binds the AEAD key to
/// this crate so a future provider can't reuse the same primitive
/// for a different purpose in the same process).
const SEALING_KEY_DOMAIN: &[u8] = b"OL-confidential-software-sealing-v1";
/// Domain tag for child-key derivation.
const CHILD_KEY_DOMAIN: &[u8] = b"OL-confidential-software-child-v1";
/// Domain tag for sealing-blob AAD.
const SEALED_AAD: &[u8] = b"OL-confidential-software-aad-v1";

/// ChaCha20-Poly1305 nonce width (12 bytes).
const NONCE_LEN: usize = 12;
/// Poly1305 authentication tag width (16 bytes).
const TAG_LEN: usize = 16;
/// Sealed master payload = master seed (32B) + length-tagged structure
/// indicator. We keep the payload size deterministic at 32 bytes.
const MASTER_PT_LEN: usize = 32;

/// Software-baseline [`ConfidentialProvider`].
///
/// Construct via [`SoftwareProvider::generate`] (CSPRNG-sourced
/// ephemeral key) or [`SoftwareProvider::from_seed`] (deterministic
/// for test vectors only — DO NOT use in production).
pub struct SoftwareProvider {
    /// AEAD instance bound to this provider's ephemeral key. Drop
    /// zeroizes via [`ChaCha20Poly1305`]'s own zeroize impl.
    aead: ChaCha20Poly1305,
}

impl std::fmt::Debug for SoftwareProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareProvider")
            .field("tag", &ProviderTag::Software)
            .finish_non_exhaustive()
    }
}

impl SoftwareProvider {
    /// Construct with a fresh ephemeral key sourced from `rng`. The
    /// recommended path for production.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let provider = Self::from_seed_internal(&seed);
        seed.zeroize();
        provider
    }

    /// Internal deterministic constructor used by [`Self::generate`].
    /// Always available because production CSPRNG-based construction
    /// needs to derive an `aead` from a fresh-random seed.
    fn from_seed_internal(seed: &[u8; 32]) -> Self {
        let mut h = Hasher::new();
        h.update(SEALING_KEY_DOMAIN);
        h.update(seed);
        let key_bytes = h.finalize();
        let key = Key::from_slice(key_bytes.as_bytes());
        let aead = ChaCha20Poly1305::new(key);
        Self { aead }
    }

    /// Construct deterministically from a 32-byte seed. Useful for
    /// test KAT vectors and for replays during incident response;
    /// callers MUST NOT use a static seed in production.
    ///
    /// **Audit M7 May 2026 — gated**: this constructor is only
    /// exposed under `#[cfg(any(test, feature =
    /// "unstable-deterministic-provider"))]` so an accidental
    /// production call site can't compile. Test fixtures get it
    /// automatically; production crates must opt in via the
    /// Cargo feature, which is also off-by-default on the
    /// pyo3-built wheel.
    #[cfg(any(test, feature = "unstable-deterministic-provider"))]
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self::from_seed_internal(seed)
    }

    /// Seal `plaintext` under this provider's ephemeral key with a
    /// fresh random nonce. The output layout is
    /// `nonce(12) || ciphertext_with_tag(N + 16)`.
    fn seal_with_rng<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> ConfidentialResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .aead
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: SEALED_AAD,
                },
            )
            .map_err(|_| ConfidentialError::Internal("AEAD encrypt"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a sealed blob into its plaintext. The caller's buffer
    /// receives the plaintext; the caller is responsible for
    /// [`Zeroize`]-ing it.
    ///
    /// **Audit H5 May 2026 — error-collapsing**: every failure mode
    /// returns the same external `SealedKeyAuthFail` so an attacker
    /// who corrupts only the tag byte (or only the length) cannot
    /// distinguish "wrong provider tag" / "wrong length" / "AEAD
    /// reject" via the returned error variant — closes the typed-
    /// error oracle that lets an attacker probe the layout of a
    /// sealed-blob storage record. The granular variants
    /// (`SealedKeyWrongProvider`, `SealedKeyBadLength`) remain in
    /// the enum for ergonomic internal diagnostics but `unseal`
    /// never returns them externally.
    fn unseal(&self, sealed: &SealedKey, expected_pt_len: usize) -> ConfidentialResult<Vec<u8>> {
        if sealed.provider_tag != ProviderTag::Software {
            return Err(ConfidentialError::SealedKeyAuthFail);
        }
        if sealed.bytes.len() != NONCE_LEN + expected_pt_len + TAG_LEN {
            return Err(ConfidentialError::SealedKeyAuthFail);
        }
        let nonce = Nonce::from_slice(&sealed.bytes[..NONCE_LEN]);
        let ct = &sealed.bytes[NONCE_LEN..];
        let pt = self
            .aead
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: SEALED_AAD,
                },
            )
            .map_err(|_| ConfidentialError::SealedKeyAuthFail)?;
        Ok(pt)
    }

    /// Derive a 32-byte child seed from an unsealed master seed +
    /// context tag. Pure function — caller manages secret hygiene
    /// on the IKM input.
    fn derive_child_seed(master_seed: &[u8; 32], context_tag: &[u8]) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(CHILD_KEY_DOMAIN);
        h.update(master_seed);
        h.update(
            &u32::try_from(context_tag.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        h.update(context_tag);
        let out = h.finalize();
        let mut child = [0u8; 32];
        child.copy_from_slice(out.as_bytes());
        child
    }

    /// Turn a 32-byte seed into a deterministic `HybridSigningKey` via
    /// the standard `ol_pqsig` deterministic-seed constructor. Returns
    /// `(signing_key, verifying_key)` from the underlying generator.
    fn signing_key_from_seed(seed: &[u8; 32]) -> (HybridSigningKey, HybridVerifyingKey) {
        use rand_core::SeedableRng;
        let mut prng = rand_chacha::ChaCha20Rng::from_seed(*seed);
        HybridSigningKey::generate(&mut prng)
    }

    fn seal_with_os_rng(&self, plaintext: &[u8]) -> ConfidentialResult<Vec<u8>> {
        use rand_core::OsRng;
        self.seal_with_rng(plaintext, &mut OsRng)
    }

    /// Derive the `(signing_key, verifying_key)` pair from a sealed
    /// master with a single unseal pass. Useful for callers that
    /// need both halves at once (e.g.,
    /// [`crate::windows_tpm::attest_with_tpm`]) to avoid the
    /// double-unseal cost.
    ///
    /// # Errors
    /// Returns `SealedKeyAuthFail` if the blob can't be unsealed.
    pub fn derive_hybrid_pair(
        &self,
        sealed: &SealedKey,
    ) -> ConfidentialResult<(HybridSigningKey, HybridVerifyingKey)> {
        let mut unsealed = self.unseal(sealed, MASTER_PT_LEN)?;
        let seed: &[u8; 32] = unsealed
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::Internal("unseal returned wrong length"))?;
        let pair = Self::signing_key_from_seed(seed);
        unsealed.zeroize();
        Ok(pair)
    }
}

impl ConfidentialProvider for SoftwareProvider {
    fn tier(&self) -> ConfidentialTier {
        ConfidentialTier::Software
    }

    fn tag(&self) -> ProviderTag {
        ProviderTag::Software
    }

    fn seal_master(&self, seed: &[u8; 32]) -> ConfidentialResult<SealedKey> {
        let bytes = self.seal_with_os_rng(seed)?;
        Ok(SealedKey::new(ProviderTag::Software, bytes))
    }

    fn derive_child(
        &self,
        sealed_master: &SealedKey,
        context_tag: &[u8],
    ) -> ConfidentialResult<SealedKey> {
        let master_seed = self.unseal(sealed_master, MASTER_PT_LEN)?;
        let master_arr: &[u8; 32] = master_seed
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::Internal("unseal returned wrong length"))?;
        let child_seed = Self::derive_child_seed(master_arr, context_tag);
        // Zeroize the unsealed master immediately after deriving the
        // child; we don't need it any longer.
        let mut master_seed = master_seed;
        master_seed.zeroize();
        let sealed_child_bytes = self.seal_with_os_rng(&child_seed)?;
        // Same for the child seed — it's already sealed; clear the
        // plaintext copy.
        let mut child_seed_zero = child_seed;
        child_seed_zero.zeroize();
        Ok(SealedKey::new(ProviderTag::Software, sealed_child_bytes))
    }

    fn sealed_sign(&self, sealed: &SealedKey, transcript: &[u8]) -> ConfidentialResult<Vec<u8>> {
        let mut unsealed = self.unseal(sealed, MASTER_PT_LEN)?;
        let seed: &[u8; 32] = unsealed
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::Internal("unseal returned wrong length"))?;
        let (sk, _vk) = Self::signing_key_from_seed(seed);
        unsealed.zeroize();
        let sig = sk.sign(transcript)?;
        Ok(sig.to_vec())
    }

    fn verifying_key(&self, sealed: &SealedKey) -> ConfidentialResult<HybridVerifyingKey> {
        let mut unsealed = self.unseal(sealed, MASTER_PT_LEN)?;
        let seed: &[u8; 32] = unsealed
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::Internal("unseal returned wrong length"))?;
        let (_sk, vk) = Self::signing_key_from_seed(seed);
        unsealed.zeroize();
        Ok(vk)
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
        if deadline_unix <= issued_unix {
            return Err(ConfidentialError::AttestationBadFreshnessWindow {
                issued_unix,
                deadline_unix,
            });
        }
        let window = deadline_unix - issued_unix;
        if window > ATTESTATION_FRESHNESS_WINDOW_SECS {
            return Err(ConfidentialError::AttestationFreshnessWindowTooWide {
                got: window,
                max: ATTESTATION_FRESHNESS_WINDOW_SECS,
            });
        }
        // Single unseal pass for both VK derivation and signing —
        // shaves ~360 µs off the attest_issue hot path vs the
        // earlier "verifying_key() then sealed_sign()" sequence.
        let mut unsealed = self.unseal(sealed_master, MASTER_PT_LEN)?;
        let seed: &[u8; 32] = unsealed
            .as_slice()
            .try_into()
            .map_err(|_| ConfidentialError::Internal("unseal returned wrong length"))?;
        let (sk, master_vk) = Self::signing_key_from_seed(seed);
        unsealed.zeroize();
        // The software provider has no platform quote to embed.
        let platform_quote: Vec<u8> = Vec::new();
        let transcript = canonical_attestation_transcript(
            ProviderTag::Software,
            &master_vk,
            &peer_nonce,
            issued_unix,
            deadline_unix,
            field_witness,
            &platform_quote,
            &issuer_sdp_pubkey,
        );
        // Reuse the freshly-derived signing key from the single
        // unseal above — no need to round-trip through sealed_sign
        // (which would unseal a second time).
        let master_sig = sk.sign(&transcript)?.to_vec();
        Ok(AttestationDoc {
            provider_tag: ProviderTag::Software,
            master_vk,
            peer_nonce,
            issued_unix,
            deadline_unix,
            field_witness_commitment: field_witness.map(|w| {
                let mut h = Hasher::new();
                h.update(b"OL-confidential-field-witness-commitment-v1");
                h.update(w);
                *h.finalize().as_bytes()
            }),
            platform_quote,
            issuer_sdp_pubkey,
            master_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn seal_unseal_round_trip() {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x42u8; 32];
        let sealed = provider.seal_master(&seed).unwrap();
        // Direct unseal — we don't expose this in the public API, but
        // we verify it for tests.
        let opened = provider.unseal(&sealed, 32).unwrap();
        assert_eq!(opened, seed);
    }

    #[test]
    fn unseal_rejects_wrong_provider_tag() {
        // Audit H5 May 2026: this used to assert
        // SealedKeyWrongProvider, but unseal now collapses every
        // failure mode to SealedKeyAuthFail externally so an
        // attacker cannot use the error variant as a typed oracle
        // for "tag byte was corrupted" vs "ciphertext was tampered".
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x42u8; 32];
        let mut sealed = provider.seal_master(&seed).unwrap();
        sealed.provider_tag = ProviderTag::WindowsTpm;
        let r = provider.unseal(&sealed, 32);
        assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
    }

    #[test]
    fn unseal_rejects_wrong_length_with_same_variant() {
        // H5 regression: a sealed blob with the right tag but
        // truncated/extended must produce SealedKeyAuthFail —
        // indistinguishable from a wrong-tag or tampered-ciphertext
        // failure at the API surface.
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x42u8; 32];
        let mut sealed = provider.seal_master(&seed).unwrap();
        // Truncate the sealed bytes by one.
        sealed.bytes.pop();
        let r = provider.unseal(&sealed, 32);
        assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
    }

    #[test]
    fn unseal_rejects_tampered_ciphertext() {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x42u8; 32];
        let mut sealed = provider.seal_master(&seed).unwrap();
        // Flip a ciphertext bit.
        sealed.bytes[NONCE_LEN + 3] ^= 0x01;
        let r = provider.unseal(&sealed, 32);
        assert!(matches!(r, Err(ConfidentialError::SealedKeyAuthFail)));
    }

    #[test]
    fn sealed_sign_round_trip_under_vk() {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x55u8; 32];
        let sealed = provider.seal_master(&seed).unwrap();
        let vk = provider.verifying_key(&sealed).unwrap();
        let sig = provider.sealed_sign(&sealed, b"hello world").unwrap();
        vk.verify(b"hello world", &sig).unwrap();
    }

    #[test]
    fn child_key_diverges_from_master() {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x77u8; 32];
        let sealed_master = provider.seal_master(&seed).unwrap();
        let sealed_child = provider
            .derive_child(&sealed_master, b"phone-day-7")
            .unwrap();
        let master_vk = provider.verifying_key(&sealed_master).unwrap();
        let child_vk = provider.verifying_key(&sealed_child).unwrap();
        assert_ne!(master_vk.to_bytes(), child_vk.to_bytes());
    }

    #[test]
    fn distinct_context_tags_yield_distinct_children() {
        let provider = SoftwareProvider::generate(&mut OsRng);
        let seed = [0x99u8; 32];
        let sealed_master = provider.seal_master(&seed).unwrap();
        let c1 = provider.derive_child(&sealed_master, b"channel-a").unwrap();
        let c2 = provider.derive_child(&sealed_master, b"channel-b").unwrap();
        let vk1 = provider.verifying_key(&c1).unwrap();
        let vk2 = provider.verifying_key(&c2).unwrap();
        assert_ne!(vk1.to_bytes(), vk2.to_bytes());
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed_a = [0xABu8; 32];
        let provider_a1 = SoftwareProvider::from_seed(&seed_a);
        let provider_a2 = SoftwareProvider::from_seed(&seed_a);
        let master_seed = [0xCDu8; 32];
        // Both providers can seal+unseal each other's blobs because
        // they derive the same AEAD key from the same provider seed.
        let sealed = provider_a1.seal_master(&master_seed).unwrap();
        let opened = provider_a2.unseal(&sealed, 32).unwrap();
        assert_eq!(opened, master_seed);
    }
}
