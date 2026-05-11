# ADR-0023: Hardware-bound keys (TOFU-degrading)

**Status:** ACCEPTED (Phase C-3)
**Phase:** C (item #8: hardware-bound keys)
**Depends on:** ADR-0021 (capability layer — the issuer-root key is what's bound).

---

## Context

The Phase C plan (line 142) originally said "hardware-attested" keys. Stress-test #4 of the file-engine-v2 plan rephrased this to **"hardware-bound keys, TOFU-degrading"** because vendor attestation chains (Apple App Attest, Android Play Integrity, Windows TPM EK certificates) all require online vendor CAs to verify, which would breach the sovereignty principle in `One_link/docs/PRINCIPLES.md` ("Defang corporate substrate").

Concretely:

- Apple Secure Enclave attestation requires Apple's CA online.
- Android StrongBox key attestation chains to Google's CA.
- Windows TPM EK attestation requires the OEM CA.

We want the *hardware-binding* property (key never leaves the secure element, OS-mediated process identity gate) without the *vendor-attestation* dependency.

## Decision

**Ship `ol_hwkey`: a `KeyStore` trait + always-available software TOFU fallback. Platform backends (Secure Enclave, StrongBox, NCrypt-TPM) are added as feature-gated implementations later; vendor attestation is OPTIONAL.**

### Guarantee enum

```rust
pub enum KeyGuarantee {
    /// Software-only TOFU.
    TofuOnly,
    /// Key held by hardware; OS gates use by process identity.
    HardwareBound,
    /// Hardware-bound AND vendor attestation chain verified.
    HardwareAttested,
}
```

`KeyStore::guarantee()` returns the strongest level a backend can offer. Callers can downgrade their threat model if the value isn't what they hoped — no silent degradation, no false-claim attestation.

### TOFU semantics

On first use a `(label, public_key)` pair is recorded. Any subsequent presentation of a *different* public key for the same label returns `HwKeyError::TofuMismatch` — the rotation signal that any pairing layer needs to refuse to upgrade trust.

The TOFU compare is **constant-time** (`subtle::ConstantTimeEq`) so an attacker can't probe the stored fingerprint byte-by-byte through timing.

### Attestation is optional

Backends that don't implement attestation return `BackendUnavailable` from `attest()`. Callers that wanted `HardwareAttested` see this and decide to either:

- Downgrade to `HardwareBound` or `TofuOnly`, or
- Refuse to proceed (their threat model demands attestation).

This is exactly the "TOFU-degrading" property the plan calls for.

### What this drop ships

- `KeyStore` trait + `KeyGuarantee` enum + `TofuStore` (software-only fallback).
- No platform backends in this drop; they slot in behind Cargo features as separate modules. Skeleton is intentional — we ship the abstraction so the rest of the engine code can target it.

### Acceptance gate

The plan's item #8 doesn't have a quantitative acceptance number (unlike RaptorQ or Reed-Solomon). The structural gates we set are:

1. **Trait surface stable**: `KeyStore::{guarantee, get_or_create, public_key, attest, check_tofu}` — any platform backend implements this contract.
2. **TOFU rotation-detection invariant**: presenting a non-matching public key for an existing label produces `TofuMismatch`. Unit-tested in `tofu::tests::tofu_rejects_rotated_key`.
3. **Constant-time TOFU compare**: byte-level XOR accumulator via `subtle::ConstantTimeEq`; same primitive that ADR-0021's signature check uses, same ≤1 % timing-variance gate from Phase C item #9.
4. **No vendor CA dependency at module-level**: `ol_hwkey/Cargo.toml` declares zero dependencies on `apple-*`, `android-*`, `windows-tpm-*`. Sovereignty preserved at the workspace level.

### Performance

Criterion benches at [`ol_hwkey/benches/hwkey_bench.rs`](../../native/ol_hwkey/benches/hwkey_bench.rs): `check_tofu` 134 ns (match) / 111 ns (mismatch) — within 21% of each other; difference is the BLAKE3 derivation on first lookup, not the CT compare itself. `get_or_create` (existing label) 44 ns. The TOFU path is fast enough for every pair-up flow to invoke it without metering.

## Consequences

**Positive:**
- Day-1 cross-platform: every host runs the TOFU store; no platform-specific bring-up needed before the daemon can ship to that platform.
- Threat-model honesty: `guarantee()` tells callers exactly what they get.
- Future platform backends slot in as feature flags without rewriting call sites.

**Negative:**
- TOFU-only mode binds keys to disk; root-on-host attacker can copy them. Acceptable: the hardware-bound modes (when implemented) raise this floor; TOFU is the fallback, not the design target.
- Vendor attestation off-by-default means we don't catch "rooted/jailbroken device with a compromised TEE." Callers who need this property can demand `HardwareAttested` and refuse to run on backends that don't supply it.

## References

- Apple Platform Security Guide, "Secure Enclave."
- Android Key Attestation, https://developer.android.com/training/articles/security-key-attestation.
- TCG TPM 2.0 Library, Part 1 (Architecture), Chapter 22 (Attestation).
- `FILE_ENGINE_V2_PLAN.md` line 142 (item #8) + stress-test #4 rephrasing in `Risks & Mitigations`.
- ADR-0021 (capability layer).
