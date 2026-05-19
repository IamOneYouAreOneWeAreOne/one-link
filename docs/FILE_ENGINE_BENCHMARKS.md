# File-engine benchmark results

> Run with `python scripts/bench_file_engine.py --json results.json`.
> The numbers below are from a Windows 11 laptop on loopback (no
> real network), Python 3.14, native crate built in release mode.
> Use as a baseline for regression detection; absolute numbers
> will vary by hardware. Updated 2026-05-19 on
> commit b03fbe0 (`push-relay-health`).

## Headline numbers

| Metric | Value | What this proves |
|---|---|---|
| **256 MiB receiver RSS peak** | 90.6 MiB | Stream-to-disk works. Pre-Wave-1d this would have been ~340 MiB (full file in heap + base RSS). Overhead ratio **0.354×** — receiver uses LESS memory than the file size. |
| **256 MiB sender RSS peak** | 94.0 MiB | Sender also streams; overhead ratio **0.367×**. Symmetric memory hygiene end-to-end. |
| **64 MiB sustained throughput** | 92.7-107 MiB/s | Steady-state on loopback (~LAN line rate). |
| **Concurrent 4×8 MiB aggregate** | 80.8 MiB/s | Multi-transfer per peer serializes through one channel; aggregate is in the same range as single-transfer because the per-peer send-lock is the gate. |
| **Warm dedup speedup @ 16 MiB** | 1.42× | Cache works; residual time is reassembly from cache. Hardlink-based dedup would push this to ~10×. |
| **Resume completion** | 3.4 s | Time from receiver restart to verified file (after sender retries via `_schedule_resume_paused`). |
| **Resume sidecar persist** | 805 µs/op | At the 64-chunk debounce cadence, resume overhead is <1 % of wall time. |
| **Resume sidecar load** | 80 µs/op | Startup scan of 1000 sidecars: ~80 ms. |
| **Chunk cache GC eviction** | 8022 files/s | 500-entry eviction (~31 MiB) in 62 ms. Daemon startup pass on a saturated cache is sub-second. |

## Raw cold-transfer ladder (median of 3 runs)

| Size | Median time | Best | Median throughput |
|------|-------------|------|-------------------|
| 1 KiB | 56 ms | 33 ms | 17.9 KiB/s |
| 1 MiB | 50 ms | 25 ms | 20.1 MiB/s |
| 16 MiB | 163 ms | — | 97.9 MiB/s |
| 64 MiB | 660 ms | 600 ms | 96.9 MiB/s (best 107 MiB/s) |
| 256 MiB | 4.0 s | — | 63.9 MiB/s (best 66.2 MiB/s) |

**Interpretation:**
- Small-file latency (≤ 1 MiB) is handshake-dominated: the FILE_OFFER round-trip is ~50 ms, so transfers under ~5 MiB don't have time to saturate the path.
- 16-64 MiB sits at ~95-107 MiB/s — the steady-state.
- 256 MiB drops to ~64 MiB/s. Bottleneck appears to be Python-side per-chunk framing accumulating at 1000+ chunks. Future work: binary-frame batched receive path or QUIC cutover.

## Memory benches

| Side | File size | Peak RSS | Mean RSS | Overhead ratio |
|---|---|---|---|---|
| Receiver | 64 MiB | 88.2 MiB | 85.9 MiB | 1.378× |
| Receiver | 256 MiB | 90.6 MiB | 87.6 MiB | **0.354×** |
| Sender | 64 MiB | 92.3 MiB | 88.5 MiB | 1.442× |
| Sender | 256 MiB | 94.0 MiB | 91.5 MiB | **0.367×** |

The overhead ratio drops below 1× at 256 MiB because the base
process RSS (~85 MiB) is essentially fixed and the per-transfer
overhead is bounded by Wave 1d's stream-to-disk: only one chunk's
plaintext (~256 KiB) is in heap at any given moment.

## Concurrent transfers

4 × 8 MiB sent in parallel from A → B:

| Metric | Value |
|---|---|
| Total bytes | 32 MiB |
| Wall time | 0.40 s |
| Aggregate throughput | 80.8 MiB/s |
| Completion rate | 4/4 |

A single 8 MiB transfer runs at ~100 MiB/s in 80 ms; 4 in parallel
take 400 ms instead of the perfect-parallel 80 ms. The per-peer
send-lock serializes work through one channel. The architecture
fights the bench here; this isn't a defect to fix in the engine,
it's a property of the WebRTC datagram channel that QUIC's
multi-stream model would unlock.

## Resume effectiveness

A 16 MiB file is started; receiver is hard-killed mid-transfer
once chunks begin landing in the cache; receiver is restarted on
the same home dir; bench waits for the sender's auto-retry.

| Metric | Value |
|---|---|
| Chunks cached at kill | 1 (timing-dependent) |
| Completion after restart | ✓ |
| Time from restart to completed file | 3.4 s |

The sender's `_schedule_resume_paused` fires on the session-up
hook when discovery sees B again; the receiver's resume registry
(loaded at startup) matches the FILE_OFFER and answers with a
FILE_WANTS covering only the gap. End-to-end recovery is
sub-5-seconds for moderate files.

## Microbenchmarks

### Resume sidecar (1000 round-trips, fresh inbox)

| Op | Time | Per-op |
|---|---|---|
| Persist | 0.81 s | 805 µs |
| Load | 0.08 s | 80 µs |

The persist cost is dominated by `os.replace` (atomic rename). At
the daemon's 64-chunk debounce, a 256-chunk transfer pays ~3 ms
of sidecar overhead total — well under 1 % of wall time.

### Chunk cache GC (1000 chunks @ 64 KiB each)

| Metric | Value |
|---|---|
| Evicted files | 500 |
| Evicted bytes | 31.2 MiB |
| Total time | 62 ms |
| Eviction rate | 8022 files/s |

Daemon startup runs this synchronously after the resume registry
loads. Even on a cache that's grown to 10000 entries the GC pass
completes in roughly a second.

## How to reproduce

```bash
# All scenarios at default sizes (1 KiB → 256 MiB)
python scripts/bench_file_engine.py --json bench.json

# Median-of-N to filter wall-clock variance
python scripts/bench_file_engine.py --scenario cold --repeat 3

# Faster smoke run (≤ 16 MiB sizes)
python scripts/bench_file_engine.py --quick

# Single scenario
python scripts/bench_file_engine.py --scenario cold
python scripts/bench_file_engine.py --scenario memory          # receiver
python scripts/bench_file_engine.py --scenario sender_memory
python scripts/bench_file_engine.py --scenario concurrent
python scripts/bench_file_engine.py --scenario warm
python scripts/bench_file_engine.py --scenario resume
python scripts/bench_file_engine.py --scenario sidecar
python scripts/bench_file_engine.py --scenario cache
```

Wall-clock numbers are sensitive to other system load; close
browsers + indexers before a regression run.

## Test posture (correctness, not perf)

| Suite | Count | Status |
|---|---|---|
| Resume unit | 18 | ✓ green |
| Chunk cache GC unit | 9 | ✓ green |
| Two-device soak | 12 | ✓ green |
| Perf regression gates | 4 | ✓ green |
| **Total** | **43** | **✓** |

## Where bottlenecks live (future work)

1. **Python per-chunk overhead** at ≥ 256 MiB. CDC chunks framed
   individually; for 1000+ chunks the per-frame Python work adds
   up. A pyo3-exposed binary-frame batched receive + SIMD batch
   decrypt would push the steady-state above 200 MiB/s.

2. **FILE_OFFER round-trip** is ~50 ms on loopback. For
   many-small-files workflows (a folder of photos), this is the
   dominant cost. `FILE_OFFER_BATCH` would amortize.

3. **Warm dedup reassembly cost** at 16 MiB is ~50 ms, dominated
   by re-reading + re-writing chunks from cache to a new unique
   inbox path. Hardlinking when the source partial still exists
   would make warm dedup near-instant.

4. **Per-peer send-lock serializes concurrent transfers**.
   QUIC's native multi-stream model would let 4 transfers
   actually run in parallel instead of queueing through one
   channel. Multi-day.

5. **State DB writes** were batched in Wave 1n — chunk arrival no
   longer pays one SQLite commit per chunk. The per-op cost is
   still cheap (~10 µs in autocommit), so the wall-clock gain on
   loopback is within noise, but smaller WAL log + atomic batch
   semantics + reduced lock contention are still wins.

## Wave 2 shipped (8 additional commits on `push-relay-health`)

Wave 2 layered on top of Wave 1 with three deeper features +
the bench-validated foundation for two more:

| Wave | What ships |
|---|---|
| **2a** | Hardlink fast-path on warm dedup — re-receiving an already-cached file hardlinks an existing local copy instead of paying a cache→disk reassembly write. Verified live in receiver logs; warm speedup ~1.46× → 1.76×. |
| **2b** | `FILE_OFFER_BATCH` wire frame: N file offers bundled in one round-trip. Receiver dispatches each through the existing FILE_OFFER pipeline. Caps + hardening (256-offer ceiling, empty-batch rejection, per-offer try/except). 3 integration tests + new `FILE_OFFER_BATCH_V1` capability. |
| **2c** | QUIC Identity bridge — `peer_quic.make_endpoint` no longer a stub. `make_server_endpoint` / `make_client_endpoint` factory the daemon uses + 5 unit tests including a real loopback handshake between two endpoints in one process. |
| **2d** | Daemon brings up a QUIC server endpoint at startup, runs an `accept_blocking` loop in `asyncio.to_thread`, exposes the OS-assigned port for advertisement, tears everything down cleanly in `stop()`. |
| **2e** | Two halves: (1) `quic_port` rides the existing `ENDPOINT_UPDATE` so paired peers learn each other's QUIC binds; per-peer `_get_or_dial_quic` outbound cache; `pin_peer` + `quic_ping` control commands; per-connection inbound frame loop responds to PING/PONG. (2) **Inbound chunk routing** — accept loop binds inbound Connections to peer_fp via a bounded recent-deque populated by the is_paired callback; `FRAME_CHUNK_REQUEST` carries serialised `FILE_NATIVE_CHUNK` payloads and routes through the existing `_handle_file_native_chunk`; `FRAME_CHUNK_RESPONSE` carries the ACK. Sender-side end-to-end wiring lands in 2e-extension. |
| **2g** | **Share-link mode**: 32-byte bearer tokens + 8-word SAS phrases (derived from `identity_sas.SAS_VOCAB`), one-time, TTL-bounded (default 24 h, max 30 days), persistent across daemon restart via per-blob JSON sidecars under `data/share_links/`. Four new control commands (`create_share_link`, `redeem_share_link`, `list_share_links`, `revoke_share_link`). 16 unit tests + 7 daemon-integration tests covering mint, lookup, single-use redeem, expiry, revoke, persistence, snapshot-omits-token, corrupt-sidecar resilience. |

## Post-Wave-2 measured numbers (median of 2 runs, --quick)

| Metric | Value |
|---|---|
| 1 KiB cold transfer | 53 ms median |
| 1 MiB cold | 46 ms median (21.7 MiB/s) |
| 16 MiB cold | 188 ms median (85 MiB/s) |
| 4×8 MiB concurrent aggregate | 87.2 MiB/s |
| Warm dedup @ 16 MiB | **1.76× speedup** (was 1.46× before Wave 2a hardlink) |
| Resume after kill+restart | 3.0 s |
| 64 MiB receiver RSS peak | 88.5 MiB (overhead 1.383×) |
| 64 MiB sender RSS peak | 90.8 MiB (overhead 1.418×) |
| Sidecar persist | 725 µs/op |
| Cache GC eviction | 8867 files/s |

## Test posture after Wave 2

| Suite | Count | Notes |
|---|---|---|
| Resume unit | 18 | green |
| Chunk cache GC unit | 9 | green |
| Two-device soak | 12 | green |
| Perf regression gates | 4 | green |
| QUIC bridge unit | 5 | includes real loopback handshake |
| QUIC daemon E2E | 3 | 2 green, 1 skipped (harness timing follow-up) |
| FILE_OFFER_BATCH integration | 3 | green |
| Share-link unit | 16 | green |
| Share-link daemon integration | 7 | green |
| **Total** | **77** | **74 pass, 1 skip, 0 fail** |

## Wave 1 shipped (14 commits on `push-relay-health`)

- `f5a6f13` resume primitive (ResumeSidecar + ResumeRegistry, 13 unit tests)
- `d1201e8` daemon wiring (3-way FILE_OFFER fork + sidecar lifecycle + startup scan)
- `5705137` TTL prune + UI snapshot + resumable_transfers control API
- `d456d4a` stream-to-disk + sidecar touch + memory hygiene
- `806f99e` BLAKE3 integrity tag on sidecars
- `6397198` chunk-cache LRU with protected hashes + State DB cleanup
- `155200b` validate partial bytes on cross-restart resume
- `443e5ed` enriched snapshot with cache-hit progress for UI
- `97481cd` move CDC finish disk I/O off the event loop
- `ebb9949` `cancel_resumable_transfer` control command
- `3ce85f1` comprehensive bench suite + this doc
- `d9025f3` perf regression gates as pytest soak tests
- `26c22fa` batch chunk_availability State DB writes + bench --repeat
- `b03fbe0` pre-allocate CDC partial + 1 MiB BLAKE3 finish-read
