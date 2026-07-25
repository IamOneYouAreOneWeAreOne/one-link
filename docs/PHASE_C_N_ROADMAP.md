# Phase C-N Roadmap — items deferred from C-1 / C-2

`FILE_ENGINE_V2_PLAN.md` lists 12 Phase C items. Phase C-1 and C-2 ship items **1, 2, 5, 6, 7, 9**. The remaining six are documented here with explicit status, blockers, and acceptance gates.

Truth review: 2026-07-24. “Shipped” in this document means the named
primitive or integration scope, not product-wide post-quantum protection,
packaged-platform qualification, or a verified production release.

---

## Status summary

| # | Item | Status | Phase |
|---|---|---|---|
| 1 | Reed-Solomon FEC over chunk stream | ✅ shipped | C-1 |
| 2 | Erasure-coded durability | ✅ shipped | C-2 |
| 3 | Capability layer wiring | ⏳ blocked (codegen + intrinsics) | C-3 |
| 4 | CRDT shared folders | ⏳ blocked (codegen + intrinsics) | C-3 |
| 5 | Multi-armed bandit auto-tuning | 🟡 route selection shipped; non-route knob controllers deferred | C-2 + future |
| 6 | Per-chunk forward-secret ratchet | ✅ shipped (symmetric chain) | C-2 |
| 7 | PQ-hybrid daemon session KEM | ✅ current signed v3 daemon channel when native ABI qualifies; Ed25519 identity and browser/WebRTC remain non-PQ | C-1 + current integration |
| 8 | Hardware-bound keys (TOFU-degrading) | ⏳ platform-specific side track | C-N |
| 9 | Constant-time crypto + cap checks | 🟡 Python ratchet done; full sweep pending | C-3 |
| 10 | Continuous structure-aware fuzzing in CI | 🟡 proptest equivalent in place; cargo-fuzz pending | C-3 |
| 11 | Property-based testing — full surface | 🟡 wire formats + KEM + ratchet covered; lattice + cap gated on 3/4 | C-3 |
| 12 | Reproducible builds + multi-party signing | ⏳ CI infra | C-N |

**Historical primitive/milestone count: 5 of 12 fully landed; item 5 partial.**
This is not a product qualification count. The generic bandit and
route-choice controller are live, while chunk-size, parallelism, FEC-ratio,
prefetch, pacing, and compression controllers remain deferred. Other remaining
items either need infrastructure not in scope for a single session (CI matrix,
Sigstore setup) or are blocked on the **`coherence_lang` → Rust codegen tool**
which is itself a substantial separate workstream.

---

## Item 3 — Capability layer (`ol_capability`)

**Plan reference (line 135):**

> `coherence_lang/std/capability/{cap, delegate, grant, revoke}.cl` becomes authoritative; existing Ed25519 grants migrated. Macaroon-style caveats (time-bound, scope-bound, attenuable, audit-tagged, delegatable). Replaces `src/one_link/{capabilities, cap_store, caps_grants}.py`.

**Plan acceptance gate (line 289):**

> Macaroon attenuation: property test that no derived cap exceeds parent rights across ≥1M random delegation chains.

**Blocker:** the `coherence_lang/std/capability/*.cl` files are PROTOTYPE-status; they depend on Coherence intrinsics `intrinsic_random_u128` and `intrinsic_hash_capability` that the Coherence runtime doesn't yet ship. Per the plan's "Coherence ↔ Rust Split Strategy" (line 555), we resolve this by:

1. Implementing the intrinsics in Rust.
2. Building a codegen tool that reads `.cl` definitions and emits matching Rust types + serde + canonical encoders.
3. Wiring a byte-equivalence CI gate so Rust + Coherence stay aligned.

**Estimated scope:** the codegen tool is ~3-5K LoC (lexer + simple parser for the CL subset used by `std/capability` + Rust emitter); intrinsics + serde wiring is another ~500 LoC. Capability layer itself on top of the generated types is ~1K LoC including macaroon-style caveats + property tests.

**Recommended sequencing:** treat the codegen tool as its own phase C-3a; capability + CRDT crates land in C-3b once the tool stabilizes.

---

## Item 4 — CRDT shared folders (`ol_crdt`)

**Plan reference (line 136):**

> `coherence_lang/std/crdt/{lattice, causality, vector_clock, sync}.cl` as authoritative. Folder = CRDT lattice. Manifest = chunk-ref list.

**Blocker:** same as item #3 — gates on `intrinsic_unix_timestamp_ms` and the codegen tool. The `lattice.cl` file itself is PRODUCTION-READY (pure mathematical primitives, no intrinsics); `causality.cl` / `vector_clock.cl` / `sync.cl` block on the timestamp intrinsic.

**Plan acceptance gate (line 144 — "lattice merge laws"):**

Property: any two states `a, b` of a CRDT folder satisfy `merge(a, b) == merge(b, a)` (commutativity), `merge(a, merge(b, c)) == merge(merge(a, b), c)` (associativity), and `merge(a, a) == a` (idempotency). Verified via proptest across ≥1M random states once `ol_crdt` exists.

**Recommended sequencing:** lands together with item #3 (same codegen path).

---

## Item 8 — Hardware-bound keys (TOFU-degrading)

**Plan reference (line 140):**

> Apple Secure Enclave / Android StrongBox / Windows TPM bind keys; vendor attestation chain is optional.

**Why deferred:** each platform has its own SDK + signing key flow:

- Apple Secure Enclave: requires `Security.framework` (Swift/ObjC FFI) and `kSecAttrTokenIDSecureEnclave`. Working on macOS + iOS only.
- Android StrongBox: requires Android Keystore + `setIsStrongBoxBacked(true)`. JNI bindings from the Android daemon.
- Windows TPM: requires `Tpm2Lib` or `tpm-rs` crate; PCR attestation chain is optional.

Each is its own SDK integration. The plan acknowledges this by tagging the item as TOFU-degrading: peers without hardware-bound keys still pair (just without the attestation bonus).

**Recommended sequencing:** Phase C-N or D, depending on platform priority. iOS + macOS daemon ship is likely first.

---

## Item 9 — Constant-time crypto + capability checks (continued from C-1)

**C-1 status:**
- ✅ `double_ratchet._is_small_order_x25519` rewritten using `hmac.compare_digest`.
- ✅ 5 new Python tests verify the rewrite (semantic + loose timing variance).

**Pending C-3 sweep:**
- Capability check paths (gates on item #3 — can't audit code that doesn't exist yet).
- AEAD path: confirm `subtle::ConstantTimeEq` is used for tag compare in `ol_aead` (RustCrypto handles this; spot-verify in audit).
- QUIC peer fingerprint compare in `ol_quic::tls`: verify constant-time check.
- ML-KEM decapsulate timing variance (the `ml-kem` crate implements implicit rejection per FIPS 203 — verify via timing-test in Criterion).

**Plan acceptance gate (line 291):** timing variance across cap-validity / crypto-input-validity < 1% of mean.

---

## Item 10 — Continuous structure-aware fuzzing in CI

**C-1/2 status:**
- ✅ 12 proptest harnesses over wire decoders (Phase B-2 gap closure).
- ✅ 2 proptest harnesses over the GF(2^8) arithmetic + Cauchy matrix invertibility (Phase C-1).

**Pending C-3:**
- cargo-fuzz harnesses for the wire decoders. Same input space as proptest but with coverage-guided mutation (libFuzzer / AFL backend).
- GitHub Actions matrix to run 4-8h fuzz sessions per PR + 24h+ continuous fuzz on `master`.
- Fuzz crash artifacts auto-uploaded to issues.

**Plan acceptance gate (line 292):** ≥48h since last fuzzer crash before release.

---

## Item 11 — Property-based testing (full surface)

**C-1/2 status:**
- ✅ Wire formats (Bloom, Fountain, Chunk*, ScopedBloom, Missing, FountainPacket).
- ✅ KEM round trip across 10K seeds.
- ✅ Ratchet step determinism + uniqueness.
- ✅ FEC any-erasure recovery + Cauchy submatrix invertibility.

**Pending C-3 (when 3/4 land):**
- **Lattice merge laws** (CRDT): commutativity, associativity, idempotency across ≥1M random state pairs.
- **Capability attenuation soundness**: no derived cap exceeds parent rights across ≥1M random delegation chains.

---

## Item 12 — Reproducible builds + multi-party signing

**Plan reference (line 144):**

> Sigstore-style transparency log; multi-signer release.

**Status:** not started. Requires:

1. Bit-for-bit reproducible builds across Linux x86_64 / macOS arm64 / Windows. Rust supports this when `RUSTFLAGS=-Crelocation-model=pic -Ccodegen-units=1` + pinned toolchain + `--locked`.
2. CI matrix that builds the same `cargo build --release` artifact independently on each platform + diffs the output bytes.
3. Sigstore (`cosign`) integration for keyless signing via OIDC identity. Multi-signer means a release is only published when N maintainers have signed via their respective OIDC providers.
4. Transparency log entries (Rekor) for every signature.

**Recommended sequencing:** runs in parallel with code work; not gating on Phase C completion. Implementation is mostly CI YAML + GitHub Actions cookbook.

---

## Verified primitive gates

The following primitive-level acceptance numbers have been verified. Passing a
primitive gate does not imply that every proposed production consumer is wired:

| Plan acceptance number | Status |
|---|---|
| RS(10,4) survives any 4-erasure × 10K seeds | ✅ PASSED (ADR-0016, `ol_fec`) |
| Generic bandit converges ≤200 interactions × 100 seeds (≥95%) | ✅ PASSED (ADR-0019, `ol_bandit`); production consumer is route selection only |
| ML-KEM-768 + X25519 hybrid handshake completes | ✅ PASSED (ADR-0017, `ol_pqkem`) |
| Macaroon attenuation property × ≥1M chains | ⏳ pending item #3 |
| Constant-time variance < 1% of mean | 🟡 Python ratchet rewritten; full sweep pending |
| Fuzzer ≥48h clean before release | ⏳ proptest in place; cargo-fuzz CI pending |
