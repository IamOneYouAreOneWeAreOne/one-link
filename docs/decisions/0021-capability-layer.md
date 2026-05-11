# ADR-0021: Capability Layer — Macaroon-style HMAC-chained caveats

**Status:** ACCEPTED (Phase C-3)
**Phase:** C (item #3: capability layer wiring)
**Depends on:** ADR-0006 (BLAKE3 derive scheme)
**Supersedes:** `One_link/src/one_link/{capabilities, cap_store, caps_grants}.py` (Phase A1 Ed25519-grant scheme).

---

## Context

The Phase C plan (line 135) calls for macaroon-style capabilities replacing the daemon's Ed25519 grant scheme. The Phase C acceptance gate (line 289):

> Macaroon attenuation: property test that no derived cap exceeds parent rights across ≥1M random delegation chains.

The original plan envisioned `coherence_lang/std/capability/*.cl` as the spec with Rust types codegen'd. Since the codegen tool is itself substantial scope (3-5K LoC) and the CL definitions are PROTOTYPE-status (blocked on `intrinsic_random_u128` + `intrinsic_hash_capability`), we ship `ol_capability` as a **native Rust implementation** with the CL files retained as design references.

The Rust types remain canonical; if a codegen tool ships later, it consumes the CL spec and emits matching Rust — same byte-equivalence CI gate as ADR-0006 envisions.

## Decision

**Ship `ol_capability`: macaroon-style first-party capabilities with HMAC-chained caveats over BLAKE3.**

### Capability model

A capability is an **unforgeable token** carrying:

1. **Identifier** — 32 bytes; binds the cap to a root key without revealing it.
2. **Caveats** — ordered list of restrictions (time-bound, scope-bound, peer-bound, audit-tagged).
3. **Signature** — BLAKE3 keyed-HMAC chain over the caveats, anchored at the issuer's root HMAC key.

The macaroon trick: each caveat's signature is `BLAKE3.keyed_hash(prev_signature, encoded_caveat)`. Appending a caveat is local — the holder XORs in a new restriction without consulting the issuer. The new signature is **provably bounded by the previous one** (one-way), so attenuated caps cannot be lifted back to broader rights.

### Caveat catalog

```rust
pub enum Caveat {
    /// Cap expires at this absolute Unix-ms timestamp.
    ExpiresAt(u64),
    /// Cap is bound to a peer fingerprint.
    PeerFingerprint([u8; 32]),
    /// Cap is restricted to paths starting with this prefix.
    PathPrefix(String),
    /// Operation must be one of these (e.g., "read", "write").
    OperationIn(Vec<String>),
    /// Audit tag — logged on every use; doesn't restrict, but ties the
    /// invocation to a specific delegation chain.
    AuditTag(String),
}
```

### Verification

`Capability::verify(root_key, context)`:

1. Re-compute the HMAC chain starting from `root_key` over the caveats.
2. **Constant-time compare** the recomputed signature to the carried one (via `subtle::ConstantTimeEq`).
3. For each caveat, evaluate against `context` (current time, path, peer, operation). If any fails, reject.

The constant-time signature check is critical: the plan's item #9 gate requires < 1% timing variance on cap validity checks.

### Attenuation

`Capability::attenuate(caveat)`:

1. Compute `new_sig = BLAKE3.keyed_hash(current_sig, encode(caveat))`.
2. Append `caveat` to the caveat list.
3. Replace `signature` with `new_sig`.

The original signature is forgotten; only the chain's terminal signature is carried. **The new cap is verifiable under the same root key** (the chain re-derives identically), but no caveat can be removed (would break the HMAC chain — verification would fail).

### Acceptance gate

> Macaroon attenuation: no derived cap exceeds parent rights across ≥1M random delegation chains.

Test setup:
- Generate a fresh root key.
- Issue a parent cap with random initial caveats.
- Generate a child cap by appending 0-10 random additional caveats.
- For ≥1,000,000 random (parent, child, context) tuples, assert: **child accepts only contexts that the parent ALSO accepts**.

In other words: `child.accepts(ctx) ⇒ parent.accepts(ctx)` (the soundness invariant). Verified in `ol_capability/tests/attenuation_soundness.rs`.

## Consequences

**Positive:**
- HMAC chain is fast (~200 ns per caveat at BLAKE3 speed).
- Attenuation is offline + cheap; no issuer round-trip needed for delegation.
- Caveats are extensible — adding new caveat kinds doesn't break existing caps.
- Audit tags provide chain provenance without revealing the chain structure publicly.

**Negative:**
- Single-issuer scope: cross-daemon delegation needs third-party caveats (Phase C-4+).
- Root key is sensitive — issuer must protect it. (Same as any HMAC-based scheme; mitigated by Phase C-1 hardware-bound keys when available.)
- HMAC chain doesn't natively support revocation — needs a separate `Revocation` log (see `ol_capability::Revocation`).

## References

- Macaroons paper: Birgisson, Politz, Erlingsson et al., "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud" (NDSS 2014).
- ADR-0006 (BLAKE3 derive scheme).
- `FILE_ENGINE_V2_PLAN.md` line 135 (item #3) + 289 (acceptance gate).
