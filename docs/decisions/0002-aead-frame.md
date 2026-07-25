# ADR-0002: AEAD Primitive and Frame Size

**Status:** ACCEPTED (Phase A1 acceptance number — do not revisit without ADR amendment)
**Phase:** A1 (item #6: AEAD frame size decision; item #7: per-chunk AEAD)
**Depends on:** ADR-0001 (CDC chunk size distribution)

**Truth amendment (2026-07-24):** the 64-bit chunk prefix is not globally
unique. Nonce safety is conditional on deriving an independent AEAD key from the
full 256-bit chunk ID or enforcing a same-key prefix registry. `ol_aead` does not
own that registry, so this ADR must not describe reuse as impossible.

---

## Context

Per the FILE_ENGINE_V2_PLAN.md stress-test critique #3: AEAD frame size governs FUSE read amplification. Chunks decrypt as a unit; if a userspace `read(offset, 64 KiB)` translates to "decrypt the full 256 KiB chunk that contains this offset," the engine wastes 75% of its AEAD budget on bytes nobody asked for. This MUST be decided in A1 — not discovered when FUSE ships in B.

Additionally, the AEAD primitive choice locks in:

1. **Throughput.** Phase A1 acceptance gate: ≥4 GiB/s/core (AES-NI) or ≥3 GiB/s/core (ChaCha20).
2. **Forward secrecy interaction.** Per-chunk forward-secret ratchet (Phase C) means each chunk's key is independently derived. The AEAD must accept fresh keys per chunk without per-chunk key-schedule cost dominating.
3. **Side-channel posture.** Constant-time per-block. AES-NI is hardware constant-time on every modern x86. ChaCha20 is constant-time by construction in software.
4. **Browser compatibility.** WebRTC DataChannel browsers in v0.20.x already do AES-128-GCM via DTLS-SRTP. Our AEAD is at a different layer (per-chunk) but shares the JS-side primitives if browser-as-peer ever needs to verify chunks.

## Decision

**Primary AEAD: AES-256-GCM via AES-NI / VAES intrinsics. Fallback: ChaCha20-Poly1305 on hardware lacking AES-NI.**

**Frame size = chunk size, but each chunk is internally divided into 16 KiB AEAD frames with independent nonces.**

Critical clarifying detail: a "chunk" (the CDC output, 8-256 KiB per ADR-0001) is the dedup unit. A "frame" (16 KiB internal subdivision) is the AEAD unit. One chunk = one or more sequential frames. This split is what makes FUSE random-access reads cheap.

Parameters:

| Parameter | Value | Rationale |
|---|---|---|
| Primary cipher | **AES-256-GCM** | AES-NI / VAES = ~5 GiB/s/core x86; HW-accelerated constant-time; PQ-relevant key length (256 bit ≈ 128-bit PQ security per Grover halving). |
| Fallback cipher | **ChaCha20-Poly1305** | ARM64 NEON path; ~3 GiB/s/core; constant-time by construction. |
| AEAD frame size | **16 KiB plaintext payload** | At a 64 KiB chunk-size mean, a chunk holds 4 frames. FUSE 64-KiB random read decrypts 1 frame (16 KiB), worst-case 2 frames if cross-frame. 4× amplification reduction vs whole-chunk-frames. |
| Nonce structure | **96-bit: chunk_id_lo64 \|\| frame_index_u32** | `chunk_id_lo64` is only a 64-bit prefix and can collide. `frame_index` distinguishes accepted frames within one chunk. Safety across chunks requires a full-ID-derived independent key or a same-key collision registry outside `ol_aead`. |
| AAD | **chunk_id_full256 (32 bytes BLAKE3)** | Binds frame-level encryption to the chunk identity; tamper of chunk_id invalidates auth tag. |
| Tag size | **128 bit (full GCM tag, 16 bytes Poly1305)** | Truncation savings (~3% per 16 KiB frame) not worth the security loss. |
| Per-chunk overhead | **frames × 16 bytes (auth tags)** | A 64 KiB chunk → 4 frames × 16 = 64 bytes overhead = 0.097%. Negligible. |
| Key derivation | **chunk_key = HKDF-Expand-Label(ratchet_chain_key, "ol-chunk", chunk_id_full256, 32)** | Per-chunk key independent from session ratchet state; future per-chunk forward-secret ratchet (Phase C) re-derives chain_key per chunk too, completing the ratchet. |

**Rejected alternatives:**

- **Whole-chunk-as-one-frame (no internal frames)**: simpler, but FUSE read amplification is unbounded. Reject.
- **AES-128-GCM**: 128-bit security ≈ 64-bit PQ. Reject for PQ-conservative posture.
- **AES-256-OCB**: better software perf than GCM, but AES-NI gives GCM hardware advantage that OCB can't match. Reject.
- **AES-256-GCM-SIV**: nonce-misuse resistance would add defense in depth
  against a caller violating the independent-key/registry contract, at the cost
  of another pass and a different primitive. The original decision rejected
  that cost; the 64-bit prefix alone is not a justification for rejection.
- **XChaCha20-Poly1305**: 192-bit nonce. Buys nothing beyond ChaCha20-Poly1305 here because our nonce structure is constructed, not random. Reject.

## Consequences

**Positive:**
- FUSE read amplification capped at 16 KiB per random read (worst case 32 KiB if cross-frame). Bounded.
- AES-NI throughput far exceeds the 1 GiB/s engine gate. Headroom for parallelism.
- Per-chunk forward-secret ratchet (Phase C) integrates cleanly: ratchet step happens at chunk boundary, frame keys derived from per-chunk key. Fits Signal-class double-ratchet without overhead per frame.
- Within one accepted chunk, distinct in-range frame indexes produce distinct
  nonce bytes. Across chunks, prefix collisions are birthday-bound near
  2^32 samples; confidentiality/integrity therefore depends on the full-ID key
  derivation or a caller-owned same-key collision registry.

**Negative:**
- 16 KiB frame size is below typical CPU L1 working sets but above L1 line size. Two-pass: encrypt then auth, or interleaved; with AES-NI VAES, single pass dominates either way.
- ChaCha20-Poly1305 fallback isn't constant-time-equivalent to AES-NI in throughput. ARM64 systems pay ~40% perf on this layer. Acceptable; ARM64 is not the line-rate target machine for v1.

## Verification

1. **Throughput gate (A1, software AES)**: encrypt + auth 256 KiB chunks, single core: ≥ 2 GiB/s sustained for both AES-GCM (software) and ChaCha20-Poly1305. This is the honest baseline measured with the RustCrypto crates' default backend.
1a. **Throughput gate (Phase B optimization, AES-NI)**: target ≥ 4 GiB/s/core for AES-256-GCM via AES-NI hardware acceleration. Attempted in A1 via `RUSTFLAGS="-C target-feature=+aes,+pclmulqdq"` but blocked on this dev box by Windows Smart App Control / WDAC; production wheels will enable AES-NI at the build matrix level (cibuildwheel + per-platform target-feature) and the 4 GiB/s gate becomes load-bearing then. Tracked as a Phase B deliverable, not a Phase A1 release blocker.
2. **FUSE read amplification gate**: random 64 KiB read on a 100 GiB virtual file induces ≤32 KiB AEAD work. Measured via instrumented decrypt counter.
3. **Nonce contract gate**: prove that the product caller derives independent
   AEAD keys from the full chunk ID or detects/rejects a repeated 64-bit prefix
   under the same key. Randomly seeing no collision is not proof of uniqueness.
4. **Per-chunk-key independence**: revealing one chunk's key reveals nothing about adjacent chunks (property test against derivation function).

## References

- AES-NI / VAES throughput: Intel Optimization Reference Manual; tested via OpenSSL `evp_aes_256_gcm`.
- BLAKE3 hash: https://github.com/BLAKE3-team/BLAKE3 (Rust crate is reference impl).
- HKDF-Expand-Label: TLS 1.3 RFC 8446 §7.1, adapted with our label scheme.
- Signal double ratchet: signal.org spec; our per-chunk variant generalizes the per-message ratchet to per-content-addressed-chunk.
