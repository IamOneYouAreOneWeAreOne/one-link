//! The `Capability` type — macaroon-style cap with HMAC-chained caveats.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::caveat::Caveat;
use crate::context::Context;
use crate::error::CapError;

/// Length of the root HMAC key in bytes.
pub const ROOT_KEY_LEN: usize = 32;
/// Length of the cap identifier in bytes.
pub const CAP_ID_LEN: usize = 32;
/// Length of the HMAC chain signature in bytes.
pub const SIGNATURE_LEN: usize = 32;

/// Maximum number of caveats accepted by [`Capability::decode`].
/// `verify` re-derives the HMAC chain in O(n caveats), so allowing
/// an attacker-controlled count enables a DoS (audit H15 May 2026).
/// 32 is well above any legitimate delegation chain depth.
pub const MAX_CAVEATS: usize = 32;

/// Maximum total wire bytes accepted by [`Capability::decode`]. Acts
/// as a belt-and-suspenders cap for the per-caveat parser plus the
/// `MAX_CAVEATS` count check (audit H15). 8 KiB is comfortable for
/// 32 caveats with reasonable payload sizes.
pub const MAX_WIRE_BYTES: usize = 8 * 1024;

/// BLAKE3 derive_key context for the root → initial-signature derivation.
const ROOT_HMAC_CONTEXT: &str = "ol-capability-root-v1";
/// BLAKE3 derive_key context for each caveat-step in the chain.
const STEP_HMAC_CONTEXT: &str = "ol-capability-step-v1";

/// A 32-byte root HMAC key. Issuer keeps this secret. Zeroized on drop.
pub type RootKey = Zeroizing<[u8; ROOT_KEY_LEN]>;

/// A capability: identifier + ordered caveats + HMAC chain signature.
///
/// Equality compares identifier + caveats + signature; constant-time
/// signature compare is in [`Self::verify`], not in `PartialEq`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Capability {
    /// 32-byte cap identifier. Public; identifies the cap without
    /// revealing the root key. Often `BLAKE3.derive_key("ol-cap-id-v1",
    /// root_key || nonce)` so the issuer can look up the right key.
    id: [u8; CAP_ID_LEN],
    /// Caveats appended in chain order.
    caveats: Vec<Caveat>,
    /// HMAC chain signature; the keyed-hash of the terminal caveat.
    signature: [u8; SIGNATURE_LEN],
}

impl Capability {
    /// Mint a fresh root capability with NO caveats.
    ///
    /// `id` identifies the cap (e.g. BLAKE3 of root + a nonce). Pick
    /// a fresh nonce per cap so identical caveat chains don't collide.
    pub fn root(id: [u8; CAP_ID_LEN], root_key: &RootKey) -> Self {
        // Initial signature = derive_key("ol-capability-root-v1", root_key || id)
        let mut input = Vec::with_capacity(ROOT_KEY_LEN + CAP_ID_LEN);
        input.extend_from_slice(&root_key[..]);
        input.extend_from_slice(&id);
        let signature = blake3::derive_key(ROOT_HMAC_CONTEXT, &input);
        Self {
            id,
            caveats: Vec::new(),
            signature,
        }
    }

    /// Borrow the cap identifier.
    #[inline]
    #[must_use]
    pub fn id(&self) -> &[u8; CAP_ID_LEN] {
        &self.id
    }

    /// Borrow the caveats in chain order.
    #[inline]
    #[must_use]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Borrow the current HMAC chain signature.
    #[inline]
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// Attenuate: append a new caveat, advancing the HMAC chain. The
    /// returned cap is verifiable under the SAME root key — the chain
    /// re-derives identically because each step is deterministic in
    /// `(prev_sig, caveat_bytes)`.
    pub fn attenuate(&self, caveat: Caveat) -> Self {
        let caveat_bytes = caveat.encode();
        let mut input = Vec::with_capacity(SIGNATURE_LEN + caveat_bytes.len());
        input.extend_from_slice(&self.signature);
        input.extend_from_slice(&caveat_bytes);
        let new_sig = blake3::derive_key(STEP_HMAC_CONTEXT, &input);

        let mut caveats = self.caveats.clone();
        caveats.push(caveat);
        Self {
            id: self.id,
            caveats,
            signature: new_sig,
        }
    }

    /// Verify this capability against `root_key` + a runtime `ctx`.
    ///
    /// Two checks:
    /// 1. **Signature check** (constant-time): recompute the HMAC
    ///    chain from `root_key` over the carried caveats; compare to
    ///    the carried signature via `subtle::ConstantTimeEq`.
    /// 2. **Caveat check**: for each caveat, evaluate against `ctx`.
    ///    Any caveat failing rejects the cap.
    ///
    /// # Errors
    ///
    /// - [`CapError::SignatureMismatch`] on signature failure.
    /// - [`CapError::CaveatRejected`] on caveat failure.
    pub fn verify(&self, root_key: &RootKey, ctx: &Context) -> Result<(), CapError> {
        // Re-derive the expected signature.
        let mut expected = {
            let mut input = Vec::with_capacity(ROOT_KEY_LEN + CAP_ID_LEN);
            input.extend_from_slice(&root_key[..]);
            input.extend_from_slice(&self.id);
            blake3::derive_key(ROOT_HMAC_CONTEXT, &input)
        };
        for caveat in &self.caveats {
            let caveat_bytes = caveat.encode();
            let mut input = Vec::with_capacity(SIGNATURE_LEN + caveat_bytes.len());
            input.extend_from_slice(&expected);
            input.extend_from_slice(&caveat_bytes);
            expected = blake3::derive_key(STEP_HMAC_CONTEXT, &input);
        }
        // Constant-time compare.
        if expected.ct_eq(&self.signature).unwrap_u8() != 1 {
            return Err(CapError::SignatureMismatch);
        }
        // Per-caveat check.
        for (idx, caveat) in self.caveats.iter().enumerate() {
            if let Err(reason) = caveat.check(ctx) {
                return Err(CapError::CaveatRejected { idx, reason });
            }
        }
        Ok(())
    }

    /// Returns true iff this cap accepts `ctx` (under `root_key`).
    /// Convenience around [`Self::verify`].
    #[must_use]
    pub fn accepts(&self, root_key: &RootKey, ctx: &Context) -> bool {
        self.verify(root_key, ctx).is_ok()
    }

    /// Encode to wire bytes:
    /// `[id (32 B)][caveat_count u32 LE][caveat_1 .. caveat_n][signature (32 B)]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CAP_ID_LEN + 4 + 1024 + SIGNATURE_LEN);
        out.extend_from_slice(&self.id);
        let count = u32::try_from(self.caveats.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for caveat in &self.caveats {
            out.extend_from_slice(&caveat.encode());
        }
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode from wire bytes. Does NOT verify the signature — caller
    /// must invoke `verify` separately.
    ///
    /// Bounded on both the caveat count (`MAX_CAVEATS`) and the wire
    /// size (`MAX_WIRE_BYTES`) so an attacker can't ship a malicious
    /// capability that costs O(N) HMAC steps to validate against an
    /// attacker-supplied N (audit H15 May 2026).
    ///
    /// # Errors
    ///
    /// [`CapError::Malformed`] / [`CapError::UnknownCaveat`] on
    /// structural failures, or [`CapError::Malformed`] with a
    /// resource-bound reason if the wire is over-budget.
    pub fn decode(bytes: &[u8]) -> Result<Self, CapError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(CapError::Malformed {
                reason: "wire bytes exceed MAX_WIRE_BYTES",
            });
        }
        if bytes.len() < CAP_ID_LEN + 4 + SIGNATURE_LEN {
            return Err(CapError::Malformed {
                reason: "wire bytes shorter than minimum header + footer",
            });
        }
        let mut id = [0u8; CAP_ID_LEN];
        id.copy_from_slice(&bytes[..CAP_ID_LEN]);
        // External audit 2026-05-18 ES-31: was `.expect("4 bytes")` which
        // panics on malformed input. The bounds check above already
        // proves the slice is exactly 4 bytes, so the expect WAS
        // unreachable in practice — but in a remote-decoder a panic
        // converts to a worker-thread crash (or in pyo3, a measurable
        // latency spike under flood). Replace with explicit `?` so the
        // decoder fail-fast path is uniform.
        let count_bytes: [u8; 4] =
            bytes[CAP_ID_LEN..CAP_ID_LEN + 4]
                .try_into()
                .map_err(|_| CapError::Malformed {
                    reason: "count field not 4 bytes (bounds-check invariant violated)",
                })?;
        let count = u32::from_le_bytes(count_bytes) as usize;
        if count > MAX_CAVEATS {
            return Err(CapError::Malformed {
                reason: "caveat count exceeds MAX_CAVEATS",
            });
        }

        let mut caveats = Vec::with_capacity(count);
        let mut cursor = CAP_ID_LEN + 4;
        for _ in 0..count {
            if bytes.len() < cursor + SIGNATURE_LEN {
                return Err(CapError::Malformed {
                    reason: "caveat list overruns wire bytes",
                });
            }
            let (caveat, consumed) = Caveat::decode(&bytes[cursor..bytes.len() - SIGNATURE_LEN])?;
            caveats.push(caveat);
            cursor += consumed;
        }
        if bytes.len() != cursor + SIGNATURE_LEN {
            return Err(CapError::Malformed {
                reason: "wire bytes do not end with signature exactly",
            });
        }
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[cursor..cursor + SIGNATURE_LEN]);
        Ok(Self {
            id,
            caveats,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn fixed_root() -> RootKey {
        Zeroizing::new([0x42u8; ROOT_KEY_LEN])
    }
    fn fixed_id() -> [u8; CAP_ID_LEN] {
        let mut id = [0u8; CAP_ID_LEN];
        id[0] = 0xCD;
        id
    }

    #[test]
    fn root_cap_verifies_with_no_caveats() {
        let root = fixed_root();
        let cap = Capability::root(fixed_id(), &root);
        let ctx = Context::new();
        assert!(cap.verify(&root, &ctx).is_ok());
    }

    #[test]
    fn attenuated_cap_verifies_when_context_satisfies_caveat() {
        let root = fixed_root();
        let cap = Capability::root(fixed_id(), &root).attenuate(Caveat::ExpiresAt(1_000_000));
        let ctx_ok = Context::new().with_now(500_000);
        assert!(cap.verify(&root, &ctx_ok).is_ok());

        let ctx_expired = Context::new().with_now(2_000_000);
        let r = cap.verify(&root, &ctx_expired);
        assert!(matches!(r, Err(CapError::CaveatRejected { .. })));
    }

    #[test]
    fn cap_with_wrong_root_key_fails_signature() {
        let root_a = fixed_root();
        let cap = Capability::root(fixed_id(), &root_a);
        let root_b: RootKey = Zeroizing::new([0x99u8; 32]);
        let ctx = Context::new();
        let r = cap.verify(&root_b, &ctx);
        assert!(matches!(r, Err(CapError::SignatureMismatch)));
    }

    #[test]
    fn tampered_caveat_breaks_signature() {
        let root = fixed_root();
        let cap =
            Capability::root(fixed_id(), &root).attenuate(Caveat::PathPrefix("/safe".to_string()));
        // Tamper: rewrite caveat without recomputing signature.
        let mut tampered = cap.clone();
        tampered.caveats[0] = Caveat::PathPrefix("/danger".to_string());
        let ctx = Context::new().with_path("/safe/file.txt");
        let r = tampered.verify(&root, &ctx);
        assert!(matches!(r, Err(CapError::SignatureMismatch)));
    }

    #[test]
    fn wire_round_trip() {
        let root = fixed_root();
        let cap = Capability::root(fixed_id(), &root)
            .attenuate(Caveat::ExpiresAt(123))
            .attenuate(Caveat::PathPrefix("/a/b".to_string()))
            .attenuate(Caveat::OperationIn(vec![
                "read".to_string(),
                "list".to_string(),
            ]))
            .attenuate(Caveat::PeerFingerprint([0x77u8; 32]))
            .attenuate(Caveat::AuditTag("share-from-alice".to_string()));
        let bytes = cap.encode();
        let decoded = Capability::decode(&bytes).unwrap();
        assert_eq!(decoded, cap);
        // Verify still passes after wire round-trip.
        let ctx = Context::new()
            .with_now(100)
            .with_path("/a/b/c")
            .with_operation("read")
            .with_peer([0x77u8; 32]);
        assert!(decoded.verify(&root, &ctx).is_ok());
    }

    #[test]
    fn path_prefix_caveat_rejects_non_matching() {
        let root = fixed_root();
        let cap =
            Capability::root(fixed_id(), &root).attenuate(Caveat::PathPrefix("/a/b".to_string()));
        let ctx_ok = Context::new().with_path("/a/b/c");
        let ctx_bad = Context::new().with_path("/a/c");
        assert!(cap.verify(&root, &ctx_ok).is_ok());
        assert!(cap.verify(&root, &ctx_bad).is_err());
    }

    #[test]
    fn operation_in_caveat_works() {
        let root = fixed_root();
        let cap = Capability::root(fixed_id(), &root)
            .attenuate(Caveat::OperationIn(vec!["read".to_string()]));
        assert!(cap
            .verify(&root, &Context::new().with_operation("read"))
            .is_ok());
        assert!(cap
            .verify(&root, &Context::new().with_operation("write"))
            .is_err());
    }

    #[test]
    fn audit_tag_never_rejects() {
        let root = fixed_root();
        let cap = Capability::root(fixed_id(), &root)
            .attenuate(Caveat::AuditTag("for-tax-audit".to_string()));
        assert!(cap.verify(&root, &Context::new()).is_ok());
    }

    #[test]
    fn cap_missing_context_field_rejects() {
        let root = fixed_root();
        // ExpiresAt caveat but Context has no `now_unix_ms`.
        let cap = Capability::root(fixed_id(), &root).attenuate(Caveat::ExpiresAt(1000));
        assert!(cap.verify(&root, &Context::new()).is_err());
    }

    #[test]
    fn decode_rejects_max_wire_bytes_overflow() {
        // Regression test for audit H15 (May 14 2026): an attacker
        // can't ship a 10 MiB blob and force us to verify it.
        let oversized = vec![0u8; MAX_WIRE_BYTES + 1];
        match Capability::decode(&oversized) {
            Err(CapError::Malformed { reason }) => {
                assert!(reason.contains("MAX_WIRE_BYTES"), "{}", reason);
            }
            Ok(_) => panic!("oversized wire bytes must be rejected"),
            Err(e) => panic!("expected Malformed, got {:?}", e),
        }
    }

    #[test]
    fn decode_rejects_max_caveats_overflow() {
        // Regression test for audit H15: forged count=1_000_000 must
        // be rejected before we walk the (claimed) caveat list.
        let mut bytes = vec![0u8; CAP_ID_LEN];
        bytes.extend_from_slice(&u32::to_le_bytes(1_000_000));
        // Pad with enough trailing bytes to satisfy the min-length
        // check; the count-check fires first.
        bytes.extend_from_slice(&[0u8; SIGNATURE_LEN]);
        match Capability::decode(&bytes) {
            Err(CapError::Malformed { reason }) => {
                assert!(reason.contains("MAX_CAVEATS"), "{}", reason);
            }
            Ok(_) => panic!("MAX_CAVEATS overflow must be rejected"),
            Err(e) => panic!("expected Malformed, got {:?}", e),
        }
    }
}
