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

**Ship `ol_hwkey` as a trait plus bounded, process-local TOFU prototype.**
Platform backends (Secure Enclave, StrongBox, NCrypt-TPM), durable authenticated
pin storage, and production daemon wiring remain future work; vendor
attestation is optional.

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

### Prototype TOFU semantics

Within one `TofuStore` object, a `(label, public_key)` pair is recorded. Any subsequent presentation of a *different* public key for the same label returns `HwKeyError::TofuMismatch` — the rotation signal that a pairing layer could use to refuse a trust upgrade.

The TOFU compare is **constant-time** (`subtle::ConstantTimeEq`) so an attacker can't probe the stored fingerprint byte-by-byte through timing.

This proves the mismatch invariant within one store lifetime. It does **not**
provide durable first-use pinning across restart: `TofuStore` is in-memory and
its derived `PublicKey` is not a real signing keypair. Production TOFU closure
requires authenticated persistence and explicit daemon integration.

### Attestation is optional

Backends that don't implement attestation return `BackendUnavailable` from `attest()`. Callers that wanted `HardwareAttested` see this and decide to either:

- Downgrade to `HardwareBound` or `TofuOnly`, or
- Refuse to proceed (their threat model demands attestation).

### What this drop ships

- `KeyStore` trait + `KeyGuarantee` enum + bounded, process-local `TofuStore`.
- No platform backend, durable pin database, or production daemon callsite is included in this drop.

### Acceptance gate

The plan's item #8 doesn't have a quantitative acceptance number (unlike LT fountain decoding or Reed-Solomon). The structural gates we set are:

1. **Trait surface stable**: `KeyStore::{guarantee, get_or_create, public_key, attest, check_tofu}` — any platform backend implements this contract.
2. **Process-local mismatch invariant**: presenting a non-matching public key for an existing label produces `TofuMismatch`. Unit-tested in `tofu::tests::tofu_rejects_rotated_key`.
3. **Constant-time comparison primitive**: key bytes are compared with `subtle::ConstantTimeEq`. An end-to-end timing proof for map lookup, locking, and error paths is not claimed.
4. **No vendor CA dependency at module-level**: `ol_hwkey/Cargo.toml` declares zero dependencies on `apple-*`, `android-*`, `windows-tpm-*`. Sovereignty preserved at the workspace level.

### Performance

Criterion coverage lives at [`ol_hwkey/benches/hwkey_bench.rs`](../../native/ol_hwkey/benches/hwkey_bench.rs). Historical local numbers are not a release SLO, and there is currently no production pair-up callsite to characterize.

## Consequences

**Positive:**
- Cross-platform primitive tests can use the in-memory store without platform SDKs. The daemon must not advertise this as durable or hardware-bound protection.
- Threat-model honesty: `guarantee()` tells callers exactly what they get.
- Future platform backends slot in as feature flags without rewriting call sites.

**Negative:**
- Persistent software TOFU and hardware-bound modes are not implemented in this crate yet. Shipping either requires authenticated persistence, restart tests, and platform integration evidence.
- Vendor attestation off-by-default means we don't catch "rooted/jailbroken device with a compromised TEE." Callers who need this property can demand `HardwareAttested` and refuse to run on backends that don't supply it.

## References

- Apple Platform Security Guide, "Secure Enclave."
- Android Key Attestation, https://developer.android.com/training/articles/security-key-attestation.
- TCG TPM 2.0 Library, Part 1 (Architecture), Chapter 22 (Attestation).
- `FILE_ENGINE_V2_PLAN.md` line 142 (item #8) + stress-test #4 rephrasing in `Risks & Mitigations`.
- ADR-0021 (capability layer).
