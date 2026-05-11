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

`tests/benchmarks/bench_native_transfer.py` (median of 3 runs per size):

| Size | Legacy MiB/s | Native MiB/s | Ratio |
|---:|---:|---:|---:|
| 64 KiB | 268 | 99 | 0.37× |
| 256 KiB | 451 | 152 | 0.34× |
| 1 MiB | 300 | 209 | 0.70× |
| 4 MiB | 183 | 256 | **1.40×** |
| 16 MiB | 150 | 266 | **1.77×** |

The crossover is around 4 MiB. Below that, the native pipeline's CDC + per-chunk AEAD framing + chunk-store append overhead is not yet amortized; the legacy path's single 256 KiB chunk + monotonic-nonce ChaCha20Poly1305 wins. Above 4 MiB the native path scales because it parallelizes naturally (each chunk is independent + content-addressed) while the legacy path is a single-stream sequential AEAD.

The native pipeline is **not pursued for raw small-file speed**. Its value at small sizes comes from properties the legacy path doesn't have:

- **Per-chunk forward secrecy** via BLAKE3 ratchet (compromise of chunk N's key reveals chunk N and nothing earlier).
- **Content-addressed dedup**: chunks already in the local ChunkStore are skipped (ratio reported via `TransferStats`).
- **Post-quantum-secure session establishment** via ML-KEM-768 + X25519 hybrid (HNDL resistance today).
- **Native AES-NI / VAES + SIMD ChaCha20** for the underlying primitives.

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
