//! Remote attestation doc — peer-verifiable proof that the daemon
//! is running under a specific [`crate::ConfidentialProvider`] and
//! that its master identity is fresh-bound to the peer's nonce.
//!
//! ## Wire shape
//!
//! ```text
//! AttestationDoc {
//!     provider_tag       : u8   — which provider produced this
//!     master_vk          : 1984 — Ed25519 (32) || ML-DSA-65 VK
//!     peer_nonce         : 32   — peer-supplied nonce (anti-replay)
//!     issued_unix        : 8    — issue wall-clock
//!     deadline_unix      : 8    — `<= issued + FRESHNESS_WINDOW`
//!     field_witness_cmt  : 33   — option<32> BLAKE3 commit on field
//!     platform_quote_len : u32  — bytes that follow
//!     platform_quote     : N    — provider-specific (SGX quote, etc.)
//!     master_sig         : 3357 — hybrid Ed25519 + ML-DSA sig
//! }
//! ```
//!
//! The master's hybrid signature covers a canonical transcript of
//! every field except itself, so any wire tamper invalidates the
//! signature and the verifier rejects.
//!
//! ## Replay defense
//!
//! - `peer_nonce` MUST be a freshly generated 32-byte value the peer
//!   sent over a fresh channel; the verifier confirms it matches the
//!   nonce it sent.
//! - `deadline_unix` MUST be `<= issued_unix + ATTESTATION_FRESHNESS_WINDOW_SECS`
//!   (default 30s); the verifier rejects any doc past its deadline.
//! - `field_witness_commitment` MAY bind the doc to a coherence-field
//!   witness so the doc is non-transferable across hosts (Row 9
//!   field-binding extended to attestation).

use blake3::Hasher;
use ol_pqsig::{HybridVerifyingKey, HYBRID_SIG_LEN, HYBRID_VK_LEN};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;

use crate::errors::{ConfidentialError, ConfidentialResult};
use crate::provider::ProviderTag;

/// Length of an attestation peer-nonce in bytes.
pub const ATTESTATION_NONCE_LEN: usize = 32;

/// Per-doc peer-supplied nonce. The peer generates this and sends it
/// to the prover; the prover binds it into the attestation transcript
/// so a captured doc can't be replayed against a later peer challenge.
pub type AttestationNonce = [u8; ATTESTATION_NONCE_LEN];

/// Max allowed `deadline_unix - issued_unix`. Bounds the replay
/// window — beyond 30s an attacker can record a fresh attestation and
/// race it against another verifier's challenge. Tighter is safer.
pub const ATTESTATION_FRESHNESS_WINDOW_SECS: u64 = 30;

/// Audit I3 May 2026 — maximum tolerated clock skew between issuer
/// and verifier. If `doc.issued_unix > now_unix + MAX_CLOCK_SKEW_SECS`,
/// the doc is rejected — a forward-skewed issuer clock could
/// otherwise issue docs that won't appear "expired" to a verifier with
/// a backward-skewed clock until much later. Bounding the issuer's
/// future-projection keeps the freshness window honest in absolute
/// wall-clock terms.
pub const ATTESTATION_MAX_CLOCK_SKEW_SECS: u64 = 5;

/// Audit I3 May 2026 — hard floor on how stale a doc may be at
/// verify time, independent of `deadline_unix`. A doc whose
/// `issued_unix` is more than this many seconds before `now_unix`
/// is rejected even if its deadline somehow lies in the future
/// (clock-skew adversary). Set to 24 hours to absorb daylight-
/// savings and zone-config errors while still rejecting ancient
/// replays.
pub const ATTESTATION_MAX_AGE_SECS: u64 = 24 * 3600;

/// Domain-separation prefix for the canonical attestation transcript
/// — distinct from every other transcript-builder in the workspace.
///
/// Bumped to `-v2` on 2026-05-14 (audit C1) when the issuer's SDP
/// pubkey was added to the transcript. Old `-v1` docs are unforgeable
/// under the new domain so they cannot be replayed against a `-v2`
/// verifier; old verifiers will reject `-v2` docs the same way.
pub const ATTESTATION_DOMAIN: &[u8] = b"OL-confidential-attestation-v2";

/// Length of the issuer's SDP-layer Ed25519 pubkey (raw, no header).
pub const ISSUER_SDP_PUBKEY_LEN: usize = 32;

/// Type alias for the issuer's SDP-layer Ed25519 pubkey. This is the
/// 32-byte raw Ed25519 verifying-key the issuer uses to sign the
/// WebRTC SDP offer/answer envelope (NOT the master VK). The
/// attestation transcript binds the master signature to THIS
/// SDP-identity so a peer cannot lift an attestation off one channel
/// and replay it against another channel that authenticates a
/// different SDP key (audit C1 May 2026).
pub type IssuerSdpPubkey = [u8; ISSUER_SDP_PUBKEY_LEN];

/// Domain prefix for the field-witness commitment leaf inside the doc.
pub const ATTESTATION_FIELD_WITNESS_DOMAIN: &[u8] =
    b"OL-confidential-field-witness-commitment-v1";

/// Signed attestation envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationDoc {
    /// Which provider produced this doc.
    pub provider_tag: ProviderTag,
    /// Master verifying key — the peer pins this out-of-band.
    pub master_vk: HybridVerifyingKey,
    /// The peer's challenge nonce.
    pub peer_nonce: AttestationNonce,
    /// Issuance wall-clock (seconds).
    pub issued_unix: u64,
    /// Expiry wall-clock (seconds). Must be `> issued_unix` and
    /// `<= issued_unix + ATTESTATION_FRESHNESS_WINDOW_SECS`.
    pub deadline_unix: u64,
    /// Optional BLAKE3 commitment over the local coherence-field
    /// witness. When present, the verifier checks the commitment
    /// against its own witness — useful for refusing to accept docs
    /// that were minted at a different physical location.
    pub field_witness_commitment: Option<[u8; 32]>,
    /// Provider-specific platform quote bytes. Empty for the
    /// software provider; non-empty for hardware providers (SGX
    /// quote, TPM2 quote, etc.).
    pub platform_quote: Vec<u8>,
    /// The issuer's SDP-layer Ed25519 pubkey (raw 32 bytes). The
    /// master signature commits to this binding so a verifier can
    /// confirm the master at the OTHER end is endorsing the very
    /// channel identity the verifier is talking to — defeats the
    /// "Alice attests with someone else's master_vk under her own
    /// SDP identity" identity-confusion attack (audit C1).
    pub issuer_sdp_pubkey: IssuerSdpPubkey,
    /// Hybrid signature over the canonical transcript, by the master.
    pub master_sig: Vec<u8>,
}

/// Build the canonical bytes a master signs to issue an
/// [`AttestationDoc`]. Pure function: identical inputs produce
/// identical output bytes.
///
/// `issuer_sdp_pubkey` is the 32-byte Ed25519 verifying-key of the
/// issuer's SDP-layer identity (the key that signs the WebRTC
/// offer/answer envelope). Mixing it into the transcript binds the
/// master signature to "this SDP identity" so a verifier rejects
/// any attestation whose embedded SDP pubkey does not match the
/// channel they are actually talking to (audit C1).
#[must_use]
pub fn canonical_attestation_transcript(
    provider_tag: ProviderTag,
    master_vk: &HybridVerifyingKey,
    peer_nonce: &AttestationNonce,
    issued_unix: u64,
    deadline_unix: u64,
    field_witness: Option<&[u8; 32]>,
    platform_quote: &[u8],
    issuer_sdp_pubkey: &IssuerSdpPubkey,
) -> Vec<u8> {
    let mut h = Hasher::new();
    h.update(ATTESTATION_DOMAIN);
    h.update(&[provider_tag.as_u8()]);
    h.update(&master_vk.to_bytes());
    h.update(peer_nonce);
    h.update(&issued_unix.to_be_bytes());
    h.update(&deadline_unix.to_be_bytes());
    match field_witness {
        None => {
            h.update(&[0u8]);
        }
        Some(witness) => {
            h.update(&[1u8]);
            let mut wh = Hasher::new();
            wh.update(ATTESTATION_FIELD_WITNESS_DOMAIN);
            wh.update(witness);
            h.update(wh.finalize().as_bytes());
        }
    }
    let qlen = u32::try_from(platform_quote.len()).unwrap_or(u32::MAX);
    h.update(&qlen.to_be_bytes());
    h.update(platform_quote);
    // Issuer-SDP-pubkey leaf. Fixed-length, so no length prefix.
    h.update(issuer_sdp_pubkey);
    h.finalize().as_bytes().to_vec()
}

/// Generate a fresh attestation nonce. Convenience wrapper for peers
/// constructing a challenge.
#[must_use]
pub fn fresh_attestation_nonce<R: RngCore + CryptoRng>(rng: &mut R) -> AttestationNonce {
    let mut n = [0u8; ATTESTATION_NONCE_LEN];
    rng.fill_bytes(&mut n);
    n
}

/// Convenience helper for callers that hold a [`ol_pqsig::HybridSigningKey`]
/// directly (e.g., the Phase-2 wired daemon path). Most callers go
/// through [`crate::ConfidentialProvider::attest`] instead.
///
/// # Errors
/// Returns `AttestationBadFreshnessWindow` if `deadline_unix <= issued_unix`,
/// `AttestationFreshnessWindowTooWide` if the window exceeds policy,
/// or `PqSig` if the signing primitive errs.
pub fn sign_attestation(
    signing_key: &ol_pqsig::HybridSigningKey,
    provider_tag: ProviderTag,
    peer_nonce: AttestationNonce,
    issued_unix: u64,
    deadline_unix: u64,
    field_witness: Option<&[u8; 32]>,
    platform_quote: Vec<u8>,
    issuer_sdp_pubkey: IssuerSdpPubkey,
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
    let master_vk = signing_key.verifying_key();
    let transcript = canonical_attestation_transcript(
        provider_tag,
        &master_vk,
        &peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness,
        &platform_quote,
        &issuer_sdp_pubkey,
    );
    let sig = signing_key.sign(&transcript)?;
    Ok(AttestationDoc {
        provider_tag,
        master_vk,
        peer_nonce,
        issued_unix,
        deadline_unix,
        field_witness_commitment: field_witness.map(|w| {
            let mut h = Hasher::new();
            h.update(ATTESTATION_FIELD_WITNESS_DOMAIN);
            h.update(w);
            *h.finalize().as_bytes()
        }),
        platform_quote,
        issuer_sdp_pubkey,
        master_sig: sig.to_vec(),
    })
}

/// Verify an attestation doc.
///
/// - `expected_peer_nonce`: the nonce THIS verifier sent in the
///   challenge round — MUST match the doc's `peer_nonce`.
/// - `now_unix`: verifier's wall clock; must be `<= deadline_unix`.
/// - `expected_field_witness`: if `Some`, the local coherence-field
///   witness — the doc's commitment must match.
/// - `min_tier`: minimum provider tier the verifier requires; the
///   doc's `provider_tag` must map to a tier `>= min_tier`.
/// - `expected_issuer_sdp_pubkey`: the SDP-layer Ed25519 pubkey the
///   verifier is actually talking to on the channel. The doc's
///   `issuer_sdp_pubkey` MUST byte-equal this — defeats the
///   "Alice attests with someone else's master under her own SDP
///   identity" identity-confusion attack (audit C1).
///
/// # Errors
/// Returns a typed error if any check fails: peer-nonce mismatch,
/// expired, freshness window too wide, master-sig invalid,
/// field-witness mismatch, provider tier too low, or
/// `AttestationIssuerSdpPubkeyMismatch` if the doc's claimed SDP
/// pubkey doesn't match the channel identity.
pub fn verify_attestation(
    doc: &AttestationDoc,
    expected_peer_nonce: &AttestationNonce,
    expected_field_witness: Option<&[u8; 32]>,
    now_unix: u64,
    min_tier: crate::tier::ConfidentialTier,
    expected_issuer_sdp_pubkey: &IssuerSdpPubkey,
) -> ConfidentialResult<()> {
    // (0) Sanity shape.
    if doc.master_sig.len() != HYBRID_SIG_LEN {
        return Err(ConfidentialError::AttestationMasterSigFail);
    }
    if doc.deadline_unix <= doc.issued_unix {
        return Err(ConfidentialError::AttestationBadFreshnessWindow {
            issued_unix: doc.issued_unix,
            deadline_unix: doc.deadline_unix,
        });
    }
    let window = doc.deadline_unix - doc.issued_unix;
    if window > ATTESTATION_FRESHNESS_WINDOW_SECS {
        return Err(ConfidentialError::AttestationFreshnessWindowTooWide {
            got: window,
            max: ATTESTATION_FRESHNESS_WINDOW_SECS,
        });
    }
    // (1) Peer nonce binds the doc to this challenge.
    if doc.peer_nonce.ct_eq(expected_peer_nonce).unwrap_u8() == 0 {
        return Err(ConfidentialError::AttestationPeerNonceMismatch);
    }
    // (2) Freshness vs verifier clock.
    if now_unix > doc.deadline_unix {
        return Err(ConfidentialError::AttestationExpired {
            deadline_unix: doc.deadline_unix,
            now_unix,
        });
    }
    // (2a) Audit I3 May 2026 — issuer-clock skew bound. Reject docs
    //      whose `issued_unix` lies more than MAX_CLOCK_SKEW_SECS
    //      in the future relative to the verifier. Without this, a
    //      forward-skewed issuer could mint a doc claiming
    //      issued=now+1day, deadline=issued+30s, and the verifier
    //      would refuse to reject for ~24h.
    if doc.issued_unix > now_unix
        && doc.issued_unix - now_unix > ATTESTATION_MAX_CLOCK_SKEW_SECS
    {
        return Err(ConfidentialError::AttestationIssuerClockSkew {
            issued_unix: doc.issued_unix,
            now_unix,
            max_skew_secs: ATTESTATION_MAX_CLOCK_SKEW_SECS,
        });
    }
    // (2b) Audit I3 May 2026 — hard floor on doc age independent of
    //      `deadline_unix`. Defends against an adversary who crafts a
    //      backward-issued / forward-deadlined doc that survives the
    //      window check but is actually weeks old.
    if doc.issued_unix < now_unix
        && now_unix - doc.issued_unix > ATTESTATION_MAX_AGE_SECS
    {
        return Err(ConfidentialError::AttestationTooOld {
            issued_unix: doc.issued_unix,
            now_unix,
            max_age_secs: ATTESTATION_MAX_AGE_SECS,
        });
    }
    // (3) Field-witness binding. Default-deny semantics (audit L5
    //     May 2026): if the doc CARRIES a field_witness_commitment
    //     but the verifier passes `expected_field_witness=None`,
    //     REJECT. Previously a doc that advertised binding could be
    //     accepted by a verifier that didn't actually check it —
    //     cross-host replay slipped through silently. Callers that
    //     genuinely want to accept an unbound view of a bound doc
    //     must pass a sentinel witness AND consciously evaluate the
    //     mismatch themselves (or just don't issue with binding).
    if let Some(local_witness) = expected_field_witness {
        let local_commitment = {
            let mut h = Hasher::new();
            h.update(ATTESTATION_FIELD_WITNESS_DOMAIN);
            h.update(local_witness);
            *h.finalize().as_bytes()
        };
        match doc.field_witness_commitment {
            None => return Err(ConfidentialError::AttestationFieldWitnessMismatch),
            Some(cmt) => {
                if cmt.ct_eq(&local_commitment).unwrap_u8() == 0 {
                    return Err(ConfidentialError::AttestationFieldWitnessMismatch);
                }
            }
        }
    } else if doc.field_witness_commitment.is_some() {
        // Doc claims a field-witness binding but verifier didn't
        // provide a witness to check it. Default deny (audit L5).
        return Err(ConfidentialError::AttestationFieldWitnessMismatch);
    }
    // (4) Provider-tier floor — enforced HERE, not by callers (audit
    //     finding H4 May 2026). A doc with provider_tag mapping to a
    //     tier below the verifier's required floor is rejected. This
    //     closes the silent-TPM-downgrade vector where a peer pins
    //     master_vk after a HardwareBound attestation and a later
    //     Software-tier doc would otherwise replace it.
    let doc_tier = crate::tier::ConfidentialTier::from_provider_tag(doc.provider_tag);
    if !doc_tier.meets(min_tier) {
        return Err(ConfidentialError::AttestationProviderTierTooLow {
            got: doc_tier,
            min: min_tier,
        });
    }
    // (5) Issuer-SDP-pubkey binding (audit C1). The doc's claimed
    //     SDP pubkey MUST equal the channel identity the verifier
    //     is actually talking to. Constant-time compare.
    if doc
        .issuer_sdp_pubkey
        .ct_eq(expected_issuer_sdp_pubkey)
        .unwrap_u8()
        == 0
    {
        return Err(ConfidentialError::AttestationIssuerSdpPubkeyMismatch);
    }
    // (6) Master signature.
    if doc.master_vk.to_bytes().len() != HYBRID_VK_LEN {
        return Err(ConfidentialError::Internal("master_vk bad length"));
    }
    let transcript = canonical_attestation_transcript(
        doc.provider_tag,
        &doc.master_vk,
        &doc.peer_nonce,
        doc.issued_unix,
        doc.deadline_unix,
        // Re-derive the witness from the commitment ONLY by trusting
        // the commitment field as authoritative; if the verifier
        // requested witness binding it was checked at step (3).
        // Pass the witness only if the doc claims one.
        if doc.field_witness_commitment.is_some() {
            expected_field_witness
        } else {
            None
        },
        &doc.platform_quote,
        &doc.issuer_sdp_pubkey,
    );
    doc.master_vk
        .verify(&transcript, &doc.master_sig)
        .map_err(|_| ConfidentialError::AttestationMasterSigFail)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier::ConfidentialTier;
    use ol_pqsig::HybridSigningKey;
    use rand::rngs::OsRng;

    /// Default test floor — matches what most tests expect (any tier).
    const TIER_ANY: ConfidentialTier = ConfidentialTier::Software;

    /// Fixed test SDP pubkey for sign/verify round-trips. Real callers
    /// pass the daemon's own Ed25519 SDP-layer pubkey.
    const TEST_SDP_PUBKEY: IssuerSdpPubkey = [0x77u8; ISSUER_SDP_PUBKEY_LEN];

    fn fresh_key() -> HybridSigningKey {
        let (sk, _vk) = HybridSigningKey::generate(&mut OsRng);
        sk
    }

    #[test]
    fn round_trip_no_witness() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk,
            ProviderTag::Software,
            nonce,
            100,
            120,
            None,
            Vec::new(),
            TEST_SDP_PUBKEY,
        )
        .unwrap();
        verify_attestation(&doc, &nonce, None, 110, TIER_ANY, &TEST_SDP_PUBKEY).unwrap();
    }

    #[test]
    fn round_trip_with_field_witness() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let witness = [0xAB; 32];
        let doc = sign_attestation(
            &sk,
            ProviderTag::Software,
            nonce,
            100,
            120,
            Some(&witness),
            Vec::new(),
            TEST_SDP_PUBKEY,
        )
        .unwrap();
        verify_attestation(&doc, &nonce, Some(&witness), 110, TIER_ANY, &TEST_SDP_PUBKEY).unwrap();
    }

    #[test]
    fn wrong_peer_nonce_rejected() {
        let sk = fresh_key();
        let nonce_a = fresh_attestation_nonce(&mut OsRng);
        let nonce_b = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce_a, 100, 120, None, Vec::new(), TEST_SDP_PUBKEY,
        )
        .unwrap();
        let r = verify_attestation(&doc, &nonce_b, None, 110, TIER_ANY, &TEST_SDP_PUBKEY);
        assert!(matches!(r, Err(ConfidentialError::AttestationPeerNonceMismatch)));
    }

    #[test]
    fn expired_doc_rejected() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 120, None, Vec::new(), TEST_SDP_PUBKEY,
        )
        .unwrap();
        let r = verify_attestation(&doc, &nonce, None, 130, TIER_ANY, &TEST_SDP_PUBKEY);
        assert!(matches!(r, Err(ConfidentialError::AttestationExpired { .. })));
    }

    #[test]
    fn too_wide_window_rejected_at_sign() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let r = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 100 + 31, None, Vec::new(), TEST_SDP_PUBKEY,
        );
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationFreshnessWindowTooWide { .. })
        ));
    }

    #[test]
    fn deadline_equal_issue_rejected_at_sign() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let r = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 100, None, Vec::new(), TEST_SDP_PUBKEY,
        );
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationBadFreshnessWindow { .. })
        ));
    }

    #[test]
    fn tampered_master_sig_rejected() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let mut doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 120, None, Vec::new(), TEST_SDP_PUBKEY,
        )
        .unwrap();
        doc.master_sig[0] ^= 0x01;
        let r = verify_attestation(&doc, &nonce, None, 110, TIER_ANY, &TEST_SDP_PUBKEY);
        assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
    }

    #[test]
    fn witness_mismatch_rejected() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let witness_a = [0xAA; 32];
        let witness_b = [0xBB; 32];
        let doc = sign_attestation(
            &sk,
            ProviderTag::Software,
            nonce,
            100,
            120,
            Some(&witness_a),
            Vec::new(),
            TEST_SDP_PUBKEY,
        )
        .unwrap();
        let r = verify_attestation(&doc, &nonce, Some(&witness_b), 110, TIER_ANY, &TEST_SDP_PUBKEY);
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationFieldWitnessMismatch)
        ));
    }

    #[test]
    fn verifier_demanding_witness_against_witnessless_doc_rejected() {
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 120, None, Vec::new(), TEST_SDP_PUBKEY,
        )
        .unwrap();
        let witness = [0xCC; 32];
        let r = verify_attestation(&doc, &nonce, Some(&witness), 110, TIER_ANY, &TEST_SDP_PUBKEY);
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationFieldWitnessMismatch)
        ));
    }

    #[test]
    fn software_tier_doc_rejected_against_hardware_bound_floor() {
        // Regression test for audit finding H4 (May 14 2026): a
        // Software-tier doc must be rejected when the verifier
        // requires HardwareBound. Otherwise an attacker who can
        // produce Software-tier docs (e.g., after a backup restore
        // on a machine without TPM) can silently impersonate a
        // peer that previously pinned at HardwareBound.
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk, ProviderTag::Software, nonce, 100, 120, None, Vec::new(), TEST_SDP_PUBKEY,
        )
        .unwrap();
        let r = verify_attestation(
            &doc,
            &nonce,
            None,
            110,
            ConfidentialTier::HardwareBound,
            &TEST_SDP_PUBKEY,
        );
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationProviderTierTooLow { .. })
        ));
    }

    #[test]
    fn hardware_tier_doc_accepted_at_software_floor() {
        // Defense-in-depth: HardwareBound docs MUST still pass the
        // Software floor. Floor semantics are "≥ min", not "==".
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let doc = sign_attestation(
            &sk,
            ProviderTag::WindowsTpm,
            nonce,
            100,
            120,
            None,
            Vec::new(),
            TEST_SDP_PUBKEY,
        )
        .unwrap();
        verify_attestation(
            &doc,
            &nonce,
            None,
            110,
            ConfidentialTier::Software,
            &TEST_SDP_PUBKEY,
        )
        .unwrap();
    }

    #[test]
    fn issuer_sdp_pubkey_mismatch_rejected() {
        // Regression test for audit C1 (May 14 2026): if the doc's
        // embedded issuer_sdp_pubkey doesn't match the channel
        // identity the verifier is talking to, the doc MUST be
        // rejected — even if everything else (master_vk, nonce,
        // master_sig over the issuer-claimed transcript) is valid.
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let issuer_sdp_pubkey: IssuerSdpPubkey = [0xAAu8; ISSUER_SDP_PUBKEY_LEN];
        let doc = sign_attestation(
            &sk,
            ProviderTag::Software,
            nonce,
            100,
            120,
            None,
            Vec::new(),
            issuer_sdp_pubkey,
        )
        .unwrap();
        // Issuer signed under AA-pubkey, verifier's channel is BB-pubkey
        let verifier_channel_pubkey: IssuerSdpPubkey = [0xBBu8; ISSUER_SDP_PUBKEY_LEN];
        let r = verify_attestation(
            &doc,
            &nonce,
            None,
            110,
            TIER_ANY,
            &verifier_channel_pubkey,
        );
        assert!(matches!(
            r,
            Err(ConfidentialError::AttestationIssuerSdpPubkeyMismatch)
        ));
    }

    #[test]
    fn issuer_sdp_pubkey_in_transcript_tamper_breaks_sig() {
        // Even more aggressive: confirm the master sig actually
        // commits to issuer_sdp_pubkey, by post-construction mutation.
        // If the verifier's channel matches the tampered value, the
        // SDP-check passes but the sig fails — proving the sig binds
        // to the pubkey.
        let sk = fresh_key();
        let nonce = fresh_attestation_nonce(&mut OsRng);
        let original_sdp: IssuerSdpPubkey = [0xAAu8; ISSUER_SDP_PUBKEY_LEN];
        let mut doc = sign_attestation(
            &sk,
            ProviderTag::Software,
            nonce,
            100,
            120,
            None,
            Vec::new(),
            original_sdp,
        )
        .unwrap();
        // Tamper: change both the doc field AND the verifier's
        // expected channel to a different value. Sig was signed
        // over original_sdp so it must now fail.
        let tampered_sdp: IssuerSdpPubkey = [0xBBu8; ISSUER_SDP_PUBKEY_LEN];
        doc.issuer_sdp_pubkey = tampered_sdp;
        let r = verify_attestation(&doc, &nonce, None, 110, TIER_ANY, &tampered_sdp);
        assert!(matches!(r, Err(ConfidentialError::AttestationMasterSigFail)));
    }
}
