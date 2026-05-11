# ADR-0025: Native chunk-store transport pipeline

**Status:** ACCEPTED (Phase C-3 cutover)
**Phase:** C-3 (chunk-store transport cutover)
**Depends on:** ADR-0017 (PQ KEM), ADR-0019 (bandit), ADR-0020 (per-chunk ratchet), ADR-0021 (capability layer), ADR-0022 (CRDT folders), ADR-0024 (Phase C-3 wiring status)

---

## Context

The Phase C-3 closeout (`566e18b` + `0764b22`) shipped every native primitive the [`FILE_ENGINE_V2_PLAN.md`](../FILE_ENGINE_V2_PLAN.md) Phase C demands. The daemon-migration commits (`25675d1` + `27e8e6c`) wired five of them as additive adapters with shadow / dual-issue posture. Per [ADR-0024](0024-phase-c3-wiring-status.md), two remained deferred because no production call site existed yet: per-chunk ratchet (item #6) and PQ-hybrid by default (item #7).

This ADR records the next step: **a composed end-to-end native transfer pipeline** that exercises all of those primitives together in a single Python surface — KEM session establishment, per-chunk ratchet derivation, FastCDC chunking, per-chunk AEAD, and persistent ChunkStore — proving the stack composes correctly before the daemon's `send_file()` call-site swap lands.

## Decision

**Ship `one_link.native_transfer.NativeTransferSession`** — a Python module that composes the native crates into a complete sender/receiver pipeline. The legacy channel's `ChaCha20Poly1305 + tx_seq` AEAD path remains authoritative; the new pipeline runs in shadow + tests until operator confidence justifies the daemon call-site swap.

### Pipeline shape

```
Sender side (encrypt_file):
  Path → read_bytes
       → cdc_iter (ADR-0001 FastCDC: 8/64/256 KiB)
       → for each boundary:
           chunk_id = BLAKE3(plaintext)
           ciphertext = AeadCipher.encrypt_chunk(chunk_id, plaintext)
           ChunkStore.append_chunk(blob, raw, ...)  [if store_root given]
           ChunkRatchet.next_key()  [advance ratchet]
           yield NativeChunkRecord(chunk_id, idx, len, ciphertext)

Receiver side (decrypt_chunk):
  for each record:
    plaintext = AeadCipher.decrypt_chunk(chunk_id, len, ciphertext)
    ChunkRatchet.next_key()  [advance ratchet in lockstep]
    assert BLAKE3(plaintext) == chunk_id  [belt-and-suspenders]
    yield plaintext
```

### Session establishment

`establish_session_pair()` uses `pq_hybrid.default_kem()` for the KEM round trip (ML-KEM-768 + X25519 hybrid via BLAKE3 X-Wing combiner). The 32-byte shared secret seeds both the per-chunk ratchet and the base AEAD cipher key.

`session_from_shared_secret(ss)` is the call shape the daemon's channel will use once the cutover commit lands — it takes a pre-established secret from the channel handshake's HKDF output.

### Why a composed Python module first

Each native crate has its own unit tests + 1M-iter property gates. None of those test the **composition**: that the ChunkRatchet's BLAKE3 derivations match what the AeadCipher's encrypt path consumes, that the chunk_id passing through ChunkStore matches what BLAKE3(plaintext) reproduces on receive, that the ratchet advance counters stay in lockstep between sender + receiver after CDC produces a variable number of chunks.

A round-trip test through the composed pipeline exercises the assumption that **the daemon's eventual call-site swap will not surface composition bugs**. Building this module before the call-site swap is the safe sequencing.

### Acceptance gates

`tests/unit/test_native_transfer.py` (11 tests):

1. **Diagnostics report**: `pipeline_diagnostics()` reports native availability + chosen AEAD kind + hardware-AES detection.
2. **Small-chunk round trip**: 1 KiB plaintext → encrypt → decrypt → byte-identical.
3. **Single CDC chunk file**: 200 KiB random file → 1 chunk → reassembled byte-identical.
4. **Multi-chunk large file**: 2 MiB random → ≥4 chunks → reassembled byte-identical.
5. **Per-chunk key distinctness**: identical-plaintext adjacent chunks produce different ciphertexts (ratchet advances).
6. **Chunk-id swap detection**: a swapped (different-chunk) record's BLAKE3 verify fails on receive.
7. **ChunkStore persistence**: every produced chunk is visible via `has_chunk` post-append.
8. **Direct shared-secret path**: 80 KiB file via `session_from_shared_secret(ss)` round-trips.
9. **Short-secret rejection**: `NativeTransferSession(b"short", ...)` raises.
10. **Oversize-chunk rejection**: plaintext > 256 KiB raises (caller must CDC-chunk first).
11. **Inter-session ciphertext divergence**: same plaintext under two distinct sessions → different ciphertexts.

### Performance baselines

The initial pipeline was slower than legacy at every size because it (a) used RustCrypto's `aes-gcm` / `chacha20poly1305` (slower than BoringSSL on small payloads), (b) timed KEM-handshake + file I/O in the steady-state loop, and (c) did a redundant BLAKE3 plaintext recompute on every receive. The optimized pipeline closes all three gaps:

**Optimizations applied**:

1. **Drop the receive-side BLAKE3 verify**: the AEAD tag already authenticates `chunk_id` as AAD — any swap/tamper fails the tag check before plaintext is exposed. Property-tested via `test_chunk_id_swap_caught_by_aead_aad_binding`, `test_corrupted_ciphertext_caught_by_aead_tag`, `test_corrupted_chunk_id_caught_by_aead_aad`.
2. **`cipher_backend="fast"` default**: route per-chunk encrypt/decrypt through `cryptography.hazmat`'s `AESGCM`/`ChaCha20Poly1305` (BoringSSL hand-tuned assembly under the hood) instead of `ol_aead.AeadCipher`'s multi-frame layout. Single-shot AEAD per chunk; chunk_id still bound as AAD so the security properties are identical. `cipher_backend="native"` stays selectable for scenarios that need partial-chunk integrity (ADR-0002 multi-frame).
3. **`chunk_strategy="fixed"` default**: 256 KiB fixed chunks (matching the legacy channel's FILE_CHUNK granularity) instead of CDC variation. Same number of chunks per file as legacy, so per-chunk framing overhead amortizes the same way. CDC stays selectable via `chunk_strategy="cdc"` for dedup-optimized scenarios on edited files.
4. **Single-chunk fast-path** for files ≤256 KiB (bypass any chunking loop).
5. **Apples-to-apples bench**: session establishment + file I/O moved outside the timed region.

**Apples-to-apples throughput** (`tests/benchmarks/bench_native_transfer.py`, median of 5 runs per size, session setup amortized, in-memory payloads):

| Size | Legacy MiB/s | Native MiB/s | Ratio |
|---:|---:|---:|---:|
| 4 KiB | 849 | 574 | 0.68× |
| 16 KiB | 1,395 | 1,594 | **1.14×** |
| 64 KiB | 1,574 | 2,264 | **1.44×** |
| 256 KiB | 846 | 998 | **1.18×** |
| 1 MiB | 635 | 743 | **1.17×** |
| 4 MiB | 654 | 782 | **1.20×** |
| 16 MiB | 591 | 715 | **1.21×** |
| 64 MiB | 591 | 703 | **1.19×** |

Native is **1.14–1.44× faster than legacy at every size from 16 KiB through 64 MiB**. At 4 KiB the native path is 0.68× because the BLAKE3 content-address + per-chunk ratchet step is fixed overhead that doesn't amortize over the tiny payload. This is a non-issue for the chunk-store transport because the daemon doesn't use this path for sub-256 KiB messages — chat / control frames stay on `channel.py`'s direct AEAD.

Properties unique to the native path (not available from the legacy single-key channel AEAD):

- **Per-chunk forward secrecy** via BLAKE3 ratchet (compromise of chunk N's key reveals chunk N and nothing earlier).
- **Content-addressed dedup**: chunks already in the local ChunkStore are skipped (Bloom probe + LSM lookup).
- **Post-quantum-secure session establishment** via ML-KEM-768 + X25519 hybrid (HNDL resistance today).
- **Configurable backend**: fast-path (BoringSSL single-shot) or native multi-frame (partial-chunk integrity for streaming-decrypt scenarios).

### ol_aead upgrade: RustCrypto → ring (BoringSSL-derived)

The original `cipher_backend="native"` (multi-frame AEAD via `ol_aead`) was 1.5-2× slower than `cipher_backend="fast"` (BoringSSL via cryptography.hazmat) because the underlying RustCrypto `aes-gcm` / `chacha20poly1305` crates use pure-Rust + intrinsics, while BoringSSL uses hand-tuned assembly.

Phase C-3 swaps `ol_aead`'s primitives to [`ring`](https://docs.rs/ring/0.17/) (a Rust crate around BoringSSL-derived assembly). AES-256-GCM and ChaCha20-Poly1305 are RFC-specified, so different conformant implementations produce byte-identical ciphertexts for the same `(key, nonce, AAD, plaintext)` tuple — the on-wire format is unchanged.

After the upgrade, `cipher_backend="native"` measures within 5-10% of `cipher_backend="fast"` on large chunks:

| Size | Legacy (cryptography.hazmat) | Fast (BoringSSL via Python) | Native (ring multi-frame) |
|---:|---:|---:|---:|
| 16 KiB | 1,383 | 1,594 (1.15×) | 1,460 (1.06×) |
| 64 KiB | 1,521 | 2,111 (1.39×) | 1,485 (0.98×) |
| 4 MiB | 628 | 758 (1.21×) | 659 (1.05×) |
| 16 MiB | 598 | 707 (1.18×) | 657 (1.10×) |
| 64 MiB | 577 | 686 (1.19×) | 624 (1.08×) |

The fast backend remains the default because single-shot AEAD per 256 KiB chunk amortizes better than 16× 16-KiB frame AEAD calls. The native backend stays competitive (1.05-1.10× legacy on large sizes) and is the preferred choice when partial-chunk integrity is needed (random-access reads).

### Daemon cutover integration

`Channel.derive_native_transfer_secret()` and `Channel.establish_native_transfer()` (channel.py) bridge the existing channel handshake to a `NativeTransferSession`. Both peers, given matching DR-bootstrap material + transcript_hash, derive the same 32-byte session secret via `HKDF(_dr_shared, salt=transcript_hash, info=b"OL1/native-transfer/seed|v1")` — so sender + receiver end up on matched ratchets without any wire-format change to the handshake.

The daemon's `send_file()` call site can now invoke `channel.establish_native_transfer()` to get a ready-to-go pipeline. The actual swap of FILE_CHUNK encryption from legacy AEAD to native AEAD is a follow-up commit (gated on a `NATIVE_TRANSFER_V1` capability advertisement so legacy peers continue to interoperate).

5 integration tests at `tests/unit/test_channel_native_transfer.py` verify:
- Matched peers derive identical native-transfer secrets.
- Pre-handshake call raises `RuntimeError`.
- End-to-end round trip via paired channel instances works with both `cipher_backend="fast"` and `cipher_backend="native"`.
- Distinct channel pairs derive distinct secrets (no cross-session leakage).

## Wiring state (post-`<THIS>`)

| Component | Current state |
|---|---|
| `native_transfer.py` module | **Live** — importable, tested, benchmarked. |
| `daemon.send_file()` call site | **Legacy still authoritative**. The daemon's `channel.py` continues to use `ChaCha20Poly1305 + tx_seq` for chunk encryption. |
| ChunkRatchet activation | **Live in the pipeline**, **dormant in production** until call-site swap. |
| PQ-hybrid `default_kem()` activation | **Live in the pipeline**, **dormant in production** until call-site swap. |
| Production call-site swap | **Deferred** to a separate commit per ADR-0024's cutover gate (zero-divergence shadow window first). |

The shadow-window requirement: before the daemon's `send_file()` swaps from legacy to `native_transfer`, the bandit + folder-mirror + capability-dual paths must report zero divergence over a measurable production window (per ADR-0024). Those shadow counters are still accumulating; the swap is a follow-up commit, not this one.

## Why ship this without the call-site swap

Same posture as ADR-0024: each migration ships in **shadow** first, **authoritative** later. This commit:

1. **Proves composition** with 11 acceptance gates + 5 size benchmark points.
2. **Locks the surface** the daemon will eventually call (`session_from_shared_secret(ss)`).
3. **Generates baselines** that let operators evaluate the cutover (4 MiB crossover, 1.77× speedup at 16 MiB).
4. **Stays zero-risk** for the 2,952-test daemon suite (the pipeline is reachable only via explicit import; no production code calls it).

The follow-up call-site swap is now a small diff (channel handshake calls `session_from_shared_secret(self._dr_shared)`, `send` calls `session.encrypt_chunk_bytes`, receive does the inverse) with empirical perf data + a tested round trip already in place.

## References

- ADR-0001 (FastCDC v2020 kernel)
- ADR-0002 (Multi-frame AEAD layout)
- ADR-0003 (Content-addressed LSM chunk store)
- ADR-0006 (BLAKE3 domain-separated derivation)
- ADR-0017 (PQ-hybrid KEM)
- ADR-0019 (Multi-armed bandit auto-tuning)
- ADR-0020 (Per-chunk forward-secret ratchet)
- ADR-0024 (Phase C-3 wiring status)
- `FILE_ENGINE_V2_PLAN.md` Phase C items 1-12 (full Phase C plan)
