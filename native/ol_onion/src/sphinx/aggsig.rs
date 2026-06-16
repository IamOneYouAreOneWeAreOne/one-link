//! Sphinx Coherence T1.5 — Schnorr signature aggregation + batch
//! verification over Ristretto255.
//!
//! ## What this is for
//!
//! Sphinx hops produce per-layer Poly1305 MACs that authenticate
//! each peel. T1.5 adds an ORTHOGONAL property: **end-to-end
//! auditable processing proof**. Each hop on a self-mesh route
//! signs the routing transcript with a long-term Schnorr key
//! under [`SchnorrSigningKey`]; the destination aggregates the
//! per-hop sigs into a single short proof and the verifier
//! confirms the whole path with one multi-scalar multiplication.
//!
//! Two primitives ship:
//!
//! 1. **Independent Schnorr** (`sign` / `verify`) — single-key
//!    signatures over Ristretto255. The building block.
//! 2. **Batch verification** (`batch_verify`) — accepts N
//!    `(pubkey, msg, sig)` triples and verifies all of them with
//!    a single random-weighted multi-scalar multiplication. ~O(1)
//!    constant-factor verifier-side win over N independent
//!    verifies.
//!
//! ## Why not full `MuSig2` / Bellare-Neven aggregation
//!
//! Full multi-signature aggregation (single 64-byte sig across N
//! signers under a group pubkey) requires either a multi-round
//! commitment protocol (`MuSig2`) or careful key-tagging to defeat
//! the rogue-key attack. Both add wire round-trips + state.
//! Sphinx hops don't communicate with each other directly — they
//! just process the packet — so a non-interactive scheme is
//! required. Bellare-Neven with key-prefixed hashing
//! (BN-with-key-tag) is the right fit and ships in
//! [`bn_aggregate`] / [`bn_verify`].
//!
//! Reference: M. Bellare, G. Neven, "Multi-signatures in the
//! plain public-key model and a general forking lemma," CCS 2006.
//! Rogue-key defence via per-signer hash tag: `H(pk_i || L)` where
//! L is the ordered list of all participant pubkeys.

use blake3::Hasher;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::errors::OnionError;

/// Domain prefix for the Schnorr challenge hash.
pub const SCHNORR_CHALLENGE_DOMAIN: &[u8] = b"OL-sphinx-aggsig-challenge-v1";
/// Domain prefix for the Bellare-Neven per-signer key-tag hash.
pub const BN_KEY_TAG_DOMAIN: &[u8] = b"OL-sphinx-aggsig-bn-key-tag-v1";
/// Domain prefix for the batch-verify random weighting.
pub const BATCH_WEIGHT_DOMAIN: &[u8] = b"OL-sphinx-aggsig-batch-weight-v1";

/// 32-byte Schnorr signing key (Ristretto255 scalar).
///
/// Deliberately does not implement `Debug` so the key material can't
/// be accidentally logged. Use `verifying_key()` for a debuggable
/// public handle.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SchnorrSigningKey(pub(crate) Scalar);

impl core::fmt::Debug for SchnorrSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SchnorrSigningKey(<redacted>)")
    }
}

/// 32-byte Schnorr verifying key (compressed Ristretto255 point).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrVerifyingKey(pub [u8; 32]);

/// 64-byte Schnorr signature: 32-byte R (compressed point) + 32-byte s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchnorrSignature(pub [u8; 64]);

impl SchnorrSigningKey {
    /// Generate from a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let s = Scalar::from_bytes_mod_order_wide(&bytes);
        bytes.zeroize();
        Self(s)
    }

    /// Deterministic constructor for KAT vectors / test replay.
    /// `seed` must be 32 bytes. NOT for production.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = Hasher::new();
        h.update(b"OL-sphinx-aggsig-seed-v1");
        h.update(seed);
        let mut wide = [0u8; 64];
        h.finalize_xof().fill(&mut wide);
        let s = Scalar::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        Self(s)
    }

    /// Derive the verifying key from this signing key.
    #[must_use]
    pub fn verifying_key(&self) -> SchnorrVerifyingKey {
        let p = basepoint_mul(&self.0);
        SchnorrVerifyingKey(p.compress().to_bytes())
    }

    /// Sign `msg` under this key. The nonce is derived
    /// deterministically from `(sk, vk, msg)` via BLAKE3-XOF so the
    /// signature is reproducible across runs and the nonce is bound
    /// to the verifying key (audit M1 May 2026 — closes the
    /// cross-key-rotation nonce-reuse vector where a signer that
    /// rotates VK while keeping SK temporarily would produce two
    /// signatures with the same k under different c, leaking sk
    /// via `(s_1 - s_2)/(c_1 - c_2)`).
    pub fn sign(&self, msg: &[u8]) -> SchnorrSignature {
        let vk = self.verifying_key();
        let nonce_scalar = deterministic_nonce(&self.0, &vk.0, msg);
        let r_point = basepoint_mul(&nonce_scalar);
        let r_bytes = r_point.compress().to_bytes();
        let c = challenge_hash(&r_bytes, &vk.0, msg);
        let s = nonce_scalar + c * self.0;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r_bytes);
        out[32..].copy_from_slice(s.as_bytes());
        SchnorrSignature(out)
    }
}

impl SchnorrVerifyingKey {
    /// Decode bytes into a point. Validates the encoding AND rejects
    /// the identity element.
    ///
    /// Identity-VK rejection is load-bearing: with `vk = O`,
    /// the verify equation `s*G == R + c*PK` collapses to
    /// `s*G == R` (the `c*PK` term is the identity), so ANY
    /// `(R, s)` with `s = nonce, R = nonce*G` would verify under
    /// the identity VK — trivially forging signatures without
    /// knowing any signing key. Rejecting at decode closes the
    /// forgery, in line with BIP-340 §3.2 group-element validation.
    fn point(&self) -> Result<RistrettoPoint, OnionError> {
        let p = CompressedRistretto(self.0)
            .decompress()
            .ok_or(OnionError::Internal("bad Schnorr VK encoding"))?;
        if p == RistrettoPoint::identity() {
            return Err(OnionError::Internal("identity Schnorr VK rejected"));
        }
        Ok(p)
    }
}

/// Verify a single signature. Constant-time scalar comparison.
///
/// # Errors
/// Returns `Internal` on encoding failure, or
/// `SignatureInvalid` if the signature is mathematically invalid.
pub fn verify(
    vk: &SchnorrVerifyingKey,
    msg: &[u8],
    sig: &SchnorrSignature,
) -> Result<(), OnionError> {
    let r_bytes: [u8; 32] = sig.0[..32].try_into().unwrap();
    let s_bytes: [u8; 32] = sig.0[32..].try_into().unwrap();
    let pk = vk.point()?;
    // R is only used for the byte-equality check below; decompress
    // here to validate the encoding so an invalid R encoding is
    // rejected as Internal rather than silently as SignatureInvalid.
    let _r = CompressedRistretto(r_bytes)
        .decompress()
        .ok_or(OnionError::Internal("bad Schnorr R encoding"))?;
    let s_opt = Scalar::from_canonical_bytes(s_bytes);
    let s = if s_opt.is_some().into() {
        s_opt.unwrap()
    } else {
        return Err(OnionError::Internal("non-canonical Schnorr s"));
    };
    let c = challenge_hash(&r_bytes, &vk.0, msg);
    // Verify: s*G == R + c*PK  ⇔  s*G - c*PK == R.
    let g = basepoint_mul(&s);
    let lhs = g - c * pk;
    if lhs.compress().to_bytes().ct_eq(&r_bytes).unwrap_u8() == 1 {
        Ok(())
    } else {
        Err(OnionError::SignatureInvalid)
    }
}

/// Batch-verify N independent `(vk, msg, sig)` triples in a single
/// random-weighted multi-scalar multiplication. ~O(1) constant-
/// factor verifier-side win over N independent
/// [`verify`] calls when N ≥ 4.
///
/// Returns `Ok(())` only if ALL signatures verify; on any failure
/// the entire batch is rejected (callers should fall back to
/// per-sig verify to locate the offending entry).
///
/// # Errors
/// Returns `Internal` on encoding failures or empty input
/// (audit M3 May 2026 — closes the fail-open vector where a caller
/// who accidentally filters their entries to zero believed they had
/// proof-of-N-signers from a `Ok(())` return). Returns
/// `SignatureInvalid` if any sig is invalid.
pub fn batch_verify(
    entries: &[(SchnorrVerifyingKey, &[u8], SchnorrSignature)],
) -> Result<(), OnionError> {
    if entries.is_empty() {
        return Err(OnionError::Internal("batch_verify of empty set"));
    }
    // Derive per-entry random weights from BLAKE3 over the full
    // batch transcript so different verifier sessions can't be
    // tricked into accepting batches that fail under a different
    // weighting. Public coin — no need for verifier randomness.
    let mut transcript = Hasher::new();
    transcript.update(BATCH_WEIGHT_DOMAIN);
    transcript.update(
        &u32::try_from(entries.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (vk, msg, sig) in entries {
        transcript.update(&vk.0);
        transcript.update(&u32::try_from(msg.len()).unwrap_or(u32::MAX).to_be_bytes());
        transcript.update(msg);
        transcript.update(&sig.0);
    }
    let mut weights_xof = transcript.finalize_xof();

    // Equation we verify:  Σ w_i * (s_i * G) == Σ w_i * (R_i + c_i * PK_i)
    // Rearranged:  (Σ w_i * s_i) * G  -  Σ w_i * R_i  -  Σ (w_i * c_i) * PK_i  ==  0
    //
    // We pre-collect (scalar, point) pairs for the two negative
    // accumulators and dispatch them through `vartime_multiscalar_mul`
    // (Pippenger / Straus inside curve25519-dalek), which is the
    // primitive that gives batch verification its asymptotic edge
    // over N independent single-pair scalar mults. The constant
    // factor saved is large: ~2.5× over the naive `+=` loop at N=32.
    let mut accum_s = Scalar::ZERO;
    let mut scalars: Vec<Scalar> = Vec::with_capacity(entries.len() * 2);
    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(entries.len() * 2);
    for (vk, msg, sig) in entries {
        let r_bytes: [u8; 32] = sig.0[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig.0[32..].try_into().unwrap();
        let pk = vk.point()?;
        let r = CompressedRistretto(r_bytes)
            .decompress()
            .ok_or(OnionError::Internal("bad Schnorr R encoding"))?;
        let s_opt = Scalar::from_canonical_bytes(s_bytes);
        let s = if s_opt.is_some().into() {
            s_opt.unwrap()
        } else {
            return Err(OnionError::Internal("non-canonical Schnorr s"));
        };
        let c = challenge_hash(&r_bytes, &vk.0, msg);

        // Read 64 bytes of weight randomness; reduce mod order.
        let mut wide = [0u8; 64];
        weights_xof.fill(&mut wide);
        let w = Scalar::from_bytes_mod_order_wide(&wide);

        accum_s += w * s;
        // Negate weights for R (we'll subtract its accumulation).
        scalars.push(-w);
        points.push(r);
        // Negate (w*c) for PK side too.
        scalars.push(-(w * c));
        points.push(pk);
    }
    // residual = s_sum*G + Σ(-w*R) + Σ(-w*c*PK) — must equal identity.
    // We feed BasepointTable-mul as a single extra (scalar, point) pair.
    scalars.push(accum_s);
    points.push(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);
    let residual = RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter());
    if residual == RistrettoPoint::identity() {
        Ok(())
    } else {
        Err(OnionError::SignatureInvalid)
    }
}

// ── Bellare-Neven aggregate signature ─────────────────────────────

/// Bellare-Neven-style aggregate over N independent Schnorr signatures.
///
/// Wire shape: `32 bytes (s_agg) || N * 32 bytes (R_i in sort order
/// by pubkey)`. Total `32 * (1 + N)` bytes, versus `64 * N` for a
/// `batch_verify` payload — ~2× wire saving at large N.
///
/// Each signer produces a normal Schnorr signature INDEPENDENTLY
/// (no nonce coordination). The aggregator sorts entries by pubkey
/// to fix a canonical order, derives a participant-list digest
/// `L = H("OL-sphinx-aggsig-participant-list-v1" || sorted_pubkeys)`,
/// computes per-signer tags `a_i = H("OL-sphinx-aggsig-bn-key-tag-v1"
/// || pk_i || L)`, and emits `s_agg = Σ a_i · s_i` plus the per-signer
/// `R_i` values in sort order.
///
/// Verifier reconstructs the same `(L, a_i)`, computes per-entry
/// `c_i = challenge_hash(R_i, pk_i, msg_i)`, and checks the equation
///
/// ```text
///   s_agg · G  ==  Σ a_i · R_i  +  Σ a_i · c_i · PK_i
/// ```
///
/// via a single `vartime_multiscalar_mul`.
///
/// **Why both [`batch_verify`] AND BN aggregate ship:**
/// - [`batch_verify`] keeps full per-sig info (each input is still a
///   64-byte sig; caller can fall back to per-sig verify to locate
///   a malformed entry) and is fastest verifier-side.
/// - [`bn_aggregate`] / [`bn_verify`] win on WIRE size at the cost
///   of throwing away the ability to recover an individual signer's
///   sig.
///
/// Rogue-key defence is the key-tag construction `a_i = H(pk_i || L)`
/// from Bellare-Neven 2006 — a participant who registered an
/// adversarial pubkey can't tune their own contribution to forge
/// against an honest signer's slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BnAggregateSignature {
    /// `Σ a_i · s_i mod q` (32 bytes, canonical encoding).
    pub s_agg: [u8; 32],
    /// Per-signer `R_i` values in sort-order by pubkey. Length must
    /// match the number of `(vk, msg)` entries passed to
    /// [`bn_verify`]. Each entry is 32 bytes (compressed Ristretto255
    /// point).
    pub r_per_signer: Vec<[u8; 32]>,
}

impl BnAggregateSignature {
    /// Number of signers this aggregate covers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.r_per_signer.len()
    }

    /// True if the aggregate covers zero signers (always invalid).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.r_per_signer.is_empty()
    }

    /// Encode to a flat byte vector: `s_agg || R_1 || R_2 || … R_N`.
    /// Total length `32 * (1 + N)`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * (1 + self.r_per_signer.len()));
        out.extend_from_slice(&self.s_agg);
        for r in &self.r_per_signer {
            out.extend_from_slice(r);
        }
        out
    }

    /// Decode from a flat byte vector. `expected_signers` is the
    /// caller's known signer count (the wire format itself doesn't
    /// carry a count — the caller's `(vk, msg)` list provides it).
    ///
    /// # Errors
    /// Returns `Internal` if `bytes.len() != 32 * (1 + expected_signers)`.
    pub fn decode(bytes: &[u8], expected_signers: usize) -> Result<Self, OnionError> {
        let want = 32 * (1 + expected_signers);
        if bytes.len() != want {
            return Err(OnionError::Internal(
                "BnAggregateSignature decode: wire size != 32 * (1 + N)",
            ));
        }
        let mut s_agg = [0u8; 32];
        s_agg.copy_from_slice(&bytes[..32]);
        let mut r_per_signer = Vec::with_capacity(expected_signers);
        for i in 0..expected_signers {
            let start = 32 * (1 + i);
            let mut r = [0u8; 32];
            r.copy_from_slice(&bytes[start..start + 32]);
            r_per_signer.push(r);
        }
        Ok(Self {
            s_agg,
            r_per_signer,
        })
    }
}

/// Aggregate N independent `(vk, msg, sig)` triples into a single
/// [`BnAggregateSignature`]. Sorts by pubkey internally so the
/// caller can pass entries in any order; the wire output is
/// canonical regardless of input order.
///
/// # Errors
/// - `Internal` for empty input
/// - `Internal` for duplicate participants (closes the audit H1
///   "one key controlling N slots" vector)
/// - `Internal` for any encoding failure (bad R or s in an input sig)
/// - `Internal` for identity-VK participants (closes the audit H2
///   forgery-under-identity-VK vector — verify equation collapses
///   to `s · G == R_aggregate` which any attacker can satisfy)
pub fn bn_aggregate(
    entries: &[(SchnorrVerifyingKey, &[u8], SchnorrSignature)],
) -> Result<BnAggregateSignature, OnionError> {
    if entries.is_empty() {
        return Err(OnionError::Internal("BN aggregate of empty set"));
    }
    // Sort entries by pubkey to produce a canonical wire form. We
    // index sort *positions* rather than reordering the slice so
    // the caller's slice stays untouched.
    let n = entries.len();
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_unstable_by_key(|&i| entries[i].0 .0);
    // Reject duplicate pubkeys (audit H1).
    for w in indices.windows(2) {
        if entries[w[0]].0 .0 == entries[w[1]].0 .0 {
            return Err(OnionError::Internal(
                "duplicate participant in BN aggregate",
            ));
        }
    }
    // Collect sorted pubkeys for the participant-list digest, and
    // co-indexed per-signer message hashes (audit L4 May 2026 — bind
    // msg_i into L so a swap of (vk_i, msg_i) pairs breaks the BN
    // tags as well as the c_i challenges).
    let sorted_pubkeys: Vec<[u8; 32]> = indices.iter().map(|&i| entries[i].0 .0).collect();
    let sorted_msg_hashes: Vec<[u8; 32]> =
        indices.iter().map(|&i| msg_digest(entries[i].1)).collect();
    let participant_l = participant_list_digest(&sorted_pubkeys, &sorted_msg_hashes);

    let mut accum_s = Scalar::ZERO;
    let mut r_per_signer: Vec<[u8; 32]> = Vec::with_capacity(n);
    for &i in &indices {
        let (vk, _msg, sig) = &entries[i];
        let r_bytes: [u8; 32] = sig.0[..32].try_into().unwrap();
        let s_bytes: [u8; 32] = sig.0[32..].try_into().unwrap();
        // Validate the input R encoding by decompressing once.
        let _r = CompressedRistretto(r_bytes)
            .decompress()
            .ok_or(OnionError::Internal("bad Schnorr R encoding"))?;
        let s_opt = Scalar::from_canonical_bytes(s_bytes);
        let s = if s_opt.is_some().into() {
            s_opt.unwrap()
        } else {
            return Err(OnionError::Internal("non-canonical Schnorr s"));
        };
        // Validate the input VK (delegates to `point()` which rejects
        // identity, audit H2).
        let _pk = vk.point()?;
        let a = bn_key_tag(&vk.0, &participant_l);
        accum_s += a * s;
        r_per_signer.push(r_bytes);
    }

    Ok(BnAggregateSignature {
        s_agg: *accum_s.as_bytes(),
        r_per_signer,
    })
}

/// Verify a [`BnAggregateSignature`] produced by [`bn_aggregate`].
///
/// `entries` is the `(vk, msg)` list — order does NOT matter; this
/// function sorts internally and the aggregate's `r_per_signer` is
/// already in sort order from the aggregator. The number of
/// `entries` MUST match `aggregate.len()` or verification fails.
///
/// # Errors
/// - `Internal` for empty input or signer-count mismatch
/// - `Internal` for duplicate participants
/// - `Internal` for identity-VK in entries
/// - `Internal` for any encoding failure (bad R or s in aggregate)
/// - [`OnionError::SignatureInvalid`] if the verify equation fails.
pub fn bn_verify(
    entries: &[(SchnorrVerifyingKey, &[u8])],
    aggregate: &BnAggregateSignature,
) -> Result<(), OnionError> {
    if entries.is_empty() {
        return Err(OnionError::Internal("BN verify of empty set"));
    }
    if entries.len() != aggregate.r_per_signer.len() {
        return Err(OnionError::Internal(
            "BN verify: entry count != aggregate R count",
        ));
    }
    // Sort entry indices by pubkey to align with the aggregator's
    // canonical order.
    let n = entries.len();
    let mut indices: Vec<usize> = (0..n).collect();
    indices.sort_unstable_by_key(|&i| entries[i].0 .0);
    for w in indices.windows(2) {
        if entries[w[0]].0 .0 == entries[w[1]].0 .0 {
            return Err(OnionError::Internal("duplicate participant in BN verify"));
        }
    }
    let sorted_pubkeys: Vec<[u8; 32]> = indices.iter().map(|&i| entries[i].0 .0).collect();
    // Audit L4 May 2026: verifier mirrors aggregator's per-signer
    // msg-hash mixin into L. Must use the same sort + the same
    // domain-tagged msg_digest as bn_aggregate.
    let sorted_msg_hashes: Vec<[u8; 32]> =
        indices.iter().map(|&i| msg_digest(entries[i].1)).collect();
    let participant_l = participant_list_digest(&sorted_pubkeys, &sorted_msg_hashes);

    // Decode the s-aggregate. Reject non-canonical scalars (audit
    // defense-in-depth — even though aggregator wrote canonical
    // bytes, a tampered wire could ship garbage).
    let s_opt = Scalar::from_canonical_bytes(aggregate.s_agg);
    let s_agg = if s_opt.is_some().into() {
        s_opt.unwrap()
    } else {
        return Err(OnionError::Internal("non-canonical aggregate s"));
    };

    // Build the verify equation as a single multi-scalar mult:
    //   0  ==  s_agg · G  -  Σ a_i · R_i  -  Σ a_i · c_i · PK_i
    // We accumulate (scalar, point) pairs and dispatch one MSM.
    let mut scalars: Vec<Scalar> = Vec::with_capacity(2 * n + 1);
    let mut points: Vec<RistrettoPoint> = Vec::with_capacity(2 * n + 1);
    for (sort_pos, &i) in indices.iter().enumerate() {
        let (vk, msg) = entries[i];
        // The aggregator stored R_i at sort_pos in r_per_signer.
        let r_bytes = aggregate.r_per_signer[sort_pos];
        let r = CompressedRistretto(r_bytes)
            .decompress()
            .ok_or(OnionError::Internal("bad aggregate R_i encoding"))?;
        let pk = vk.point()?;
        let a = bn_key_tag(&vk.0, &participant_l);
        let c = challenge_hash(&r_bytes, &vk.0, msg);
        scalars.push(-a);
        points.push(r);
        scalars.push(-(a * c));
        points.push(pk);
    }
    scalars.push(s_agg);
    points.push(curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT);
    let residual = RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points.iter());
    if residual == RistrettoPoint::identity() {
        Ok(())
    } else {
        Err(OnionError::SignatureInvalid)
    }
}

// ── Internal helpers ─────────────────────────────────────────────

fn challenge_hash(r_bytes: &[u8; 32], vk_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Hasher::new();
    h.update(SCHNORR_CHALLENGE_DOMAIN);
    h.update(r_bytes);
    h.update(vk_bytes);
    h.update(&u32::try_from(msg.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn deterministic_nonce(sk: &Scalar, vk_bytes: &[u8; 32], msg: &[u8]) -> Scalar {
    // Audit M1 May 2026: domain bumped `-v1` → `-v2` because the
    // input shape changed (vk is now mixed in). Old `-v1` signers
    // and `-v2` signers under the same key produce DIFFERENT
    // signatures over the same message — but verifiers don't see
    // the nonce directly so the only observable change is the
    // KAT vectors regenerated for `-v2`.
    let mut h = Hasher::new();
    h.update(b"OL-sphinx-aggsig-nonce-v2");
    h.update(sk.as_bytes());
    h.update(vk_bytes);
    h.update(&u32::try_from(msg.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(msg);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    let s = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    s
}

fn participant_list_digest(pubkeys: &[[u8; 32]], msg_hashes: &[[u8; 32]]) -> [u8; 32] {
    // Audit L4 May 2026 — additionally bind per-entry message
    // digests into the participant list. Without this, two BN
    // aggregates with the SAME signer set but DIFFERENT per-signer
    // messages share the same `a_i = H(pk_i || L)` tags; the
    // sig-binding via `c_i = challenge_hash(R_i, vk_i, msg_i)`
    // still rejects a swap, but binding messages into L is
    // defense-in-depth (a future protocol mistake that loses
    // `msg_i` in `c_i` derivation still gets caught).
    //
    // Domain bumped `-v1` -> `-v2`. BN multi-sig only shipped
    // working `bn_verify` in e5f58f7 (May 14 2026) so no aggregates
    // have made it past the dev tree under `-v1`.
    debug_assert_eq!(
        pubkeys.len(),
        msg_hashes.len(),
        "participant_list_digest invariant: pubkeys and msg_hashes co-indexed",
    );
    let mut h = Hasher::new();
    h.update(b"OL-sphinx-aggsig-participant-list-v2");
    h.update(
        &u32::try_from(pubkeys.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for (pk, mh) in pubkeys.iter().zip(msg_hashes.iter()) {
        h.update(pk);
        h.update(mh);
    }
    *h.finalize().as_bytes()
}

fn msg_digest(msg: &[u8]) -> [u8; 32] {
    // Domain-tagged BLAKE3 digest of a single per-entry message. Used
    // to bind per-signer messages into participant_list_digest (L4).
    let mut h = Hasher::new();
    h.update(b"OL-sphinx-aggsig-msg-digest-v1");
    h.update(&u32::try_from(msg.len()).unwrap_or(u32::MAX).to_be_bytes());
    h.update(msg);
    *h.finalize().as_bytes()
}

fn bn_key_tag(pk: &[u8; 32], participant_l: &[u8; 32]) -> Scalar {
    let mut h = Hasher::new();
    h.update(BN_KEY_TAG_DOMAIN);
    h.update(pk);
    h.update(participant_l);
    let mut wide = [0u8; 64];
    h.finalize_xof().fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

// ── Helpers for the basepoint table ──────────────────────────────
//
// curve25519-dalek 4.x does basepoint multiplication via the
// `Mul` impl on `&RistrettoBasepointTable`. Wrap it in a tiny
// helper so call sites read naturally.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;

#[inline]
fn basepoint_mul(k: &Scalar) -> RistrettoPoint {
    RISTRETTO_BASEPOINT_TABLE * k
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn keygen_produces_distinct_vks() {
        let sk_a = SchnorrSigningKey::generate(&mut OsRng);
        let sk_b = SchnorrSigningKey::generate(&mut OsRng);
        assert_ne!(sk_a.verifying_key().0, sk_b.verifying_key().0);
    }

    #[test]
    fn from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        let a = SchnorrSigningKey::from_seed(&seed);
        let b = SchnorrSigningKey::from_seed(&seed);
        assert_eq!(a.verifying_key().0, b.verifying_key().0);
    }

    #[test]
    fn sign_verify_round_trip() {
        let sk = SchnorrSigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let msg = b"hello sphinx";
        let sig = sk.sign(msg);
        verify(&vk, msg, &sig).unwrap();
    }

    #[test]
    fn sign_verify_deterministic_across_runs() {
        let sk = SchnorrSigningKey::from_seed(&[0x55; 32]);
        let msg = b"determinism";
        let sig1 = sk.sign(msg);
        let sig2 = sk.sign(msg);
        assert_eq!(
            sig1.0, sig2.0,
            "sign must be deterministic for same (sk, msg)"
        );
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = SchnorrSigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let sig = sk.sign(b"msg-a");
        assert!(verify(&vk, b"msg-b", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_vk() {
        let sk_a = SchnorrSigningKey::generate(&mut OsRng);
        let sk_b = SchnorrSigningKey::generate(&mut OsRng);
        let sig = sk_a.sign(b"x");
        assert!(verify(&sk_b.verifying_key(), b"x", &sig).is_err());
    }

    #[test]
    fn verify_rejects_tampered_sig() {
        let sk = SchnorrSigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let mut sig = sk.sign(b"x");
        sig.0[3] ^= 0x01;
        assert!(verify(&vk, b"x", &sig).is_err());
    }

    #[test]
    fn batch_verify_round_trip_4_signers() {
        let mut entries = Vec::new();
        let msgs = [b"a".as_slice(), b"bb", b"ccc", b"dddd"];
        let mut sks = Vec::new();
        for _ in 0..4 {
            sks.push(SchnorrSigningKey::generate(&mut OsRng));
        }
        for (i, sk) in sks.iter().enumerate() {
            let vk = sk.verifying_key();
            let sig = sk.sign(msgs[i]);
            entries.push((vk, msgs[i], sig));
        }
        batch_verify(&entries).unwrap();
    }

    #[test]
    fn batch_verify_rejects_empty_input() {
        // Regression test for audit M3 (May 14 2026): batch_verify
        // used to return Ok(()) on empty input, which let a caller
        // who accidentally filtered to zero entries believe they had
        // proof-of-N-signers. Now Internal-errors.
        let entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = Vec::new();
        assert!(matches!(
            batch_verify(&entries),
            Err(OnionError::Internal(_))
        ));
    }

    #[test]
    fn batch_verify_rejects_one_bad_sig() {
        let mut entries = Vec::new();
        let sks: Vec<_> = (0..4)
            .map(|_| SchnorrSigningKey::generate(&mut OsRng))
            .collect();
        for sk in &sks {
            let vk = sk.verifying_key();
            entries.push((vk, b"msg".as_slice(), sk.sign(b"msg")));
        }
        // Corrupt the third entry's sig.
        let mut bad = entries[2].2;
        bad.0[5] ^= 0xFF;
        entries[2] = (entries[2].0, entries[2].1, bad);
        assert!(batch_verify(&entries).is_err());
    }

    #[test]
    fn batch_verify_rejects_swapped_msgs() {
        // Two signers, but verifier passes the SWAPPED messages.
        // Each individual sig is valid for its OWN msg, but the
        // (vk, msg) pairing is wrong → batch must reject.
        let sk_a = SchnorrSigningKey::generate(&mut OsRng);
        let sk_b = SchnorrSigningKey::generate(&mut OsRng);
        let sig_a = sk_a.sign(b"alpha");
        let sig_b = sk_b.sign(b"beta");
        let entries = vec![
            (sk_a.verifying_key(), b"beta".as_slice(), sig_a),
            (sk_b.verifying_key(), b"alpha".as_slice(), sig_b),
        ];
        assert!(batch_verify(&entries).is_err());
    }

    // ── Bellare-Neven multi-sig round trip ──────────────────────

    fn bn_setup(
        n: usize,
    ) -> (
        Vec<SchnorrSigningKey>,
        Vec<Vec<u8>>,
        Vec<(SchnorrVerifyingKey, Vec<u8>, SchnorrSignature)>,
    ) {
        let sks: Vec<SchnorrSigningKey> = (0..n)
            .map(|_| SchnorrSigningKey::generate(&mut OsRng))
            .collect();
        let msgs: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let mut v = b"BN-msg-".to_vec();
                v.push(i as u8);
                v
            })
            .collect();
        let owned: Vec<(SchnorrVerifyingKey, Vec<u8>, SchnorrSignature)> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| (sk.verifying_key(), m.clone(), sk.sign(m)))
            .collect();
        (sks, msgs, owned)
    }

    fn bn_borrow(
        owned: &[(SchnorrVerifyingKey, Vec<u8>, SchnorrSignature)],
    ) -> Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> {
        owned
            .iter()
            .map(|(vk, m, s)| (*vk, m.as_slice(), *s))
            .collect()
    }

    fn bn_borrow_verify(
        owned: &[(SchnorrVerifyingKey, Vec<u8>, SchnorrSignature)],
    ) -> Vec<(SchnorrVerifyingKey, &[u8])> {
        owned.iter().map(|(vk, m, _)| (*vk, m.as_slice())).collect()
    }

    #[test]
    fn bn_round_trip_n_equals_2() {
        let (_sks, _msgs, owned) = bn_setup(2);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        assert_eq!(agg.len(), 2);
        assert_eq!(agg.encode().len(), 32 * (1 + 2));
        bn_verify(&bn_borrow_verify(&owned), &agg).unwrap();
    }

    #[test]
    fn bn_round_trip_n_equals_3() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        bn_verify(&bn_borrow_verify(&owned), &agg).unwrap();
    }

    #[test]
    fn bn_round_trip_n_equals_8() {
        let (_sks, _msgs, owned) = bn_setup(8);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        bn_verify(&bn_borrow_verify(&owned), &agg).unwrap();
    }

    #[test]
    fn bn_round_trip_n_equals_32_wire_size() {
        // Confirm the wire-size win at N=32: BN aggregate is
        // 32*(1+32) = 1056 bytes vs 64*32 = 2048 bytes for the
        // batch_verify payload — ~1.94× smaller.
        let (_sks, _msgs, owned) = bn_setup(32);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        assert_eq!(agg.encode().len(), 32 * (1 + 32));
        bn_verify(&bn_borrow_verify(&owned), &agg).unwrap();
    }

    #[test]
    fn bn_round_trip_order_independent_at_verify() {
        // The aggregator sorts by pubkey, so the verifier can pass
        // entries in ANY order and the result must match.
        let (_sks, _msgs, owned) = bn_setup(5);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let mut reversed: Vec<(SchnorrVerifyingKey, &[u8])> = bn_borrow_verify(&owned);
        reversed.reverse();
        bn_verify(&reversed, &agg).unwrap();
    }

    #[test]
    fn bn_round_trip_aggregator_input_order_independent() {
        // The aggregator should produce an IDENTICAL aggregate
        // regardless of input order — sort_unstable_by_key is the
        // canonicalizer.
        let (_sks, _msgs, owned) = bn_setup(4);
        let mut shuffled = owned.clone();
        shuffled.swap(0, 3);
        shuffled.swap(1, 2);
        let agg_orig = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let agg_shuf = bn_aggregate(&bn_borrow(&shuffled)).unwrap();
        assert_eq!(agg_orig, agg_shuf);
    }

    #[test]
    fn bn_rejects_empty_aggregate() {
        let entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = Vec::new();
        assert!(bn_aggregate(&entries).is_err());
    }

    #[test]
    fn bn_rejects_empty_verify() {
        let (_sks, _msgs, owned) = bn_setup(2);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let entries: Vec<(SchnorrVerifyingKey, &[u8])> = Vec::new();
        assert!(bn_verify(&entries, &agg).is_err());
    }

    #[test]
    fn bn_rejects_count_mismatch() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        // Pass only the first 2 entries to verify — count mismatch.
        let truncated = bn_borrow_verify(&owned[..2]);
        let r = bn_verify(&truncated, &agg);
        assert!(matches!(r, Err(OnionError::Internal(_))));
    }

    #[test]
    fn bn_rejects_tampered_s_agg() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let mut agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        agg.s_agg[0] ^= 0x01;
        let r = bn_verify(&bn_borrow_verify(&owned), &agg);
        assert!(matches!(r, Err(OnionError::SignatureInvalid)));
    }

    #[test]
    fn bn_rejects_tampered_r_i() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let mut agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        // Flip a bit in the middle R_i.
        agg.r_per_signer[1][3] ^= 0x10;
        let r = bn_verify(&bn_borrow_verify(&owned), &agg);
        assert!(matches!(
            r,
            Err(OnionError::SignatureInvalid) | Err(OnionError::Internal(_))
        ));
    }

    #[test]
    fn bn_rejects_swapped_r_i() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let mut agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        // Swap two R_i values. Since they bind to DIFFERENT pubkeys
        // via the sort-order pairing, this MUST reject.
        agg.r_per_signer.swap(0, 2);
        let r = bn_verify(&bn_borrow_verify(&owned), &agg);
        assert!(matches!(r, Err(OnionError::SignatureInvalid)));
    }

    #[test]
    fn bn_rejects_swapped_messages() {
        let (_sks, _msgs, owned) = bn_setup(2);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        // Verifier passes swapped messages — c_i derivation breaks.
        let mut entries = bn_borrow_verify(&owned);
        let m_a = entries[0].1;
        let m_b = entries[1].1;
        entries[0].1 = m_b;
        entries[1].1 = m_a;
        let r = bn_verify(&entries, &agg);
        assert!(matches!(r, Err(OnionError::SignatureInvalid)));
    }

    #[test]
    fn bn_rejects_wrong_vk_at_verify() {
        let (sks, _msgs, owned) = bn_setup(2);
        // Verifier swaps in an UNRELATED VK for the second slot.
        let unrelated = SchnorrSigningKey::generate(&mut OsRng).verifying_key();
        let mut entries = bn_borrow_verify(&owned);
        entries[1].0 = unrelated;
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let r = bn_verify(&entries, &agg);
        // Could be SignatureInvalid or Internal depending on sort
        // order — both are acceptable rejections.
        assert!(matches!(
            r,
            Err(OnionError::SignatureInvalid) | Err(OnionError::Internal(_))
        ));
        let _ = sks;
    }

    #[test]
    fn bn_rejects_duplicate_participants_at_aggregate() {
        let sk_a = SchnorrSigningKey::generate(&mut OsRng);
        let vk_a = sk_a.verifying_key();
        let sig_1 = sk_a.sign(b"m1");
        let sig_2 = sk_a.sign(b"m2");
        let entries: Vec<(SchnorrVerifyingKey, &[u8], SchnorrSignature)> = vec![
            (vk_a, b"m1".as_slice(), sig_1),
            (vk_a, b"m2".as_slice(), sig_2),
        ];
        assert!(bn_aggregate(&entries).is_err());
    }

    #[test]
    fn bn_rejects_duplicate_participants_at_verify() {
        let sk_a = SchnorrSigningKey::generate(&mut OsRng);
        let vk_a = sk_a.verifying_key();
        // Build a fake aggregate manually to bypass the aggregator's
        // dedup check, so we can test that bn_verify ALSO catches
        // duplicates (defense in depth).
        let agg = BnAggregateSignature {
            s_agg: [0u8; 32],
            r_per_signer: vec![[0u8; 32], [0u8; 32]],
        };
        let entries: Vec<(SchnorrVerifyingKey, &[u8])> =
            vec![(vk_a, b"m1".as_slice()), (vk_a, b"m2".as_slice())];
        let r = bn_verify(&entries, &agg);
        assert!(matches!(r, Err(OnionError::Internal(_))));
    }

    #[test]
    fn bn_aggregate_wire_round_trip() {
        let (_sks, _msgs, owned) = bn_setup(5);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let bytes = agg.encode();
        let decoded = BnAggregateSignature::decode(&bytes, 5).unwrap();
        assert_eq!(decoded, agg);
        bn_verify(&bn_borrow_verify(&owned), &decoded).unwrap();
    }

    #[test]
    fn bn_aggregate_decode_rejects_wrong_size() {
        let (_sks, _msgs, owned) = bn_setup(3);
        let agg = bn_aggregate(&bn_borrow(&owned)).unwrap();
        let mut bytes = agg.encode();
        bytes.push(0); // too long
        assert!(BnAggregateSignature::decode(&bytes, 3).is_err());
        bytes.pop();
        bytes.pop(); // too short
        assert!(BnAggregateSignature::decode(&bytes, 3).is_err());
        // Wrong claimed signer count.
        assert!(BnAggregateSignature::decode(&agg.encode(), 7).is_err());
    }
}
