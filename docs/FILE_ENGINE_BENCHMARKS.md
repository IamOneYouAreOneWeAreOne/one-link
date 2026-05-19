# File-engine benchmark results

> Run with `python scripts/bench_file_engine.py --json results.json`.
> The numbers below are from a Windows 11 laptop on loopback (no
> real network), Python 3.14, native crate built in release mode.
> Use as a baseline for regression detection; absolute numbers
> will vary by hardware. Updated 2026-05-19 on
> commit ebb9949 (`push-relay-health`).

## Headline numbers

| Metric | Value | What this proves |
|---|---|---|
| **256 MiB receiver RSS peak** | 88.9 MiB | Stream-to-disk works. Pre-Wave-1d this would have been ~340 MiB (full file in heap + base RSS). Overhead ratio is **0.347×** — the receiver process uses LESS RAM than the file it's receiving. |
| **64 MiB receiver RSS peak** | 86.3 MiB | RSS doesn't scale with file size. Same base + chunk-sized working set as 256 MiB. |
| **Sustained throughput @ 64 MiB** | 106.7 MiB/s | The CDC path's steady-state on loopback. |
| **Sustained throughput @ 16 MiB** | 104.8 MiB/s | Same ceiling at smaller working sets — handshake amortizes within the first few MiB. |
| **Warm dedup speedup** | 1.46× | A re-send of a previously-received file skips network entirely; cost shifts to reassembly from chunk cache. |
| **Resume completion** | 3.2 s | Time from receiver restart to verified-received file (after the sender retries via `_schedule_resume_paused`). |
| **Resume sidecar write** | 740 µs/op | At the every-64-chunks debounce cadence, a typical transfer's resume overhead is well under 1 % of wall time. |
| **Resume sidecar read** | 72 µs/op | Startup scan of 1000 sidecars: ~72 ms. |
| **Chunk cache GC eviction** | 7790 files/s | Eviction of 500 chunks (~31 MiB) in 64 ms. Startup pass on a full cache (5000+ chunks) is well under a second. |

## Raw cold-transfer ladder

| Size | Time | Throughput |
|------|------|------------|
| 1 KiB | 63 ms | 15.8 KiB/s |
| 1 MiB | 51 ms | 19.4 MiB/s |
| 16 MiB | 153 ms | 104.8 MiB/s |
| 64 MiB | 600 ms | 106.7 MiB/s |
| 256 MiB | 3.63 s | 70.5 MiB/s |

**Interpretation:**
- Small-file latency (≤ 1 MiB) is handshake-dominated: the FILE_OFFER round-trip is ~50 ms, so transfers under ~5 MiB don't have time to saturate the path.
- 16-64 MiB sits at ~105 MiB/s — the steady-state.
- 256 MiB drops to 70 MiB/s. Suspect Python-side per-chunk overhead (base64, JSON, `make_msg`) accumulating at 4000+ chunks. Future work: SIMD batch decrypt + a binary frame format would push this back up.

## Memory bench

| File size | Peak RSS | Mean RSS | Overhead ratio |
|---|---|---|---|
| 64 MiB | 86.3 MiB | 85.9 MiB | 1.349× |
| 256 MiB | 88.9 MiB | 87.5 MiB | 0.347× |

The overhead ratio drops as file size grows because the receiver's
base RSS (~85 MiB) is essentially fixed. The PER-TRANSFER overhead
is bounded by Wave 1d's stream-to-disk — a single chunk's
plaintext (~64 KiB) is the only file-data in heap at any moment.

## Resume effectiveness

A 16 MiB file is started; the receiver is hard-killed mid-transfer
once chunks begin landing in the cache; receiver is restarted on
the same home dir; the bench waits for the sender's auto-retry to
complete.

| Metric | Value |
|---|---|
| Chunks cached at kill | 1 (timing-dependent on this run) |
| Completion after restart | ✓ |
| Time after restart to completed file | 3.2 s |

The sender's `_schedule_resume_paused` path triggers automatically
on peer reconnect; the receiver's resume registry (loaded at
startup) matches the FILE_OFFER and answers with FILE_WANTS
covering only the gap. End-to-end recovery is sub-5-seconds for
moderate files.

## Microbenchmarks

### Resume sidecar (1000 round-trips, fresh inbox)

| Op | Time | Per-op |
|---|---|---|
| Persist | 0.74 s | 740 µs |
| Load | 0.07 s | 72 µs |

The persist cost is dominated by `os.replace` (atomic rename) on
each write. At the daemon's debounce cadence (every 64 chunks),
a 256-chunk transfer pays ~3 ms of sidecar overhead total — well
below 1 % of wall time.

### Chunk cache GC (1000 chunks @ 64 KiB each = 64 MiB cache)

| Metric | Value |
|---|---|
| Evicted files | 500 |
| Evicted bytes | 31.2 MiB |
| Total time | 64 ms |
| Eviction rate | 7790 files/s |

Daemon startup runs this synchronously after the resume registry
loads; even on a cache that's grown to 10000 entries the GC pass
completes in roughly a second. Periodic GC (every 20 s) handles
in-session growth without ever stalling the event loop noticeably.

## How to reproduce

```bash
# All scenarios at default sizes (1 KiB → 256 MiB)
python scripts/bench_file_engine.py --json bench.json

# Faster smoke run (≤ 16 MiB sizes)
python scripts/bench_file_engine.py --quick

# Just one scenario
python scripts/bench_file_engine.py --scenario cold
python scripts/bench_file_engine.py --scenario memory
python scripts/bench_file_engine.py --scenario resume
python scripts/bench_file_engine.py --scenario warm
python scripts/bench_file_engine.py --scenario sidecar
python scripts/bench_file_engine.py --scenario cache
```

Wall-clock numbers are sensitive to other system load; close
browsers + indexers before a regression run.

## Test posture (correctness, not perf)

- 18 resume unit tests
- 9 chunk-cache GC unit tests
- 12 two-device soak tests

All green on `push-relay-health` HEAD as of 2026-05-19.

## Where bottlenecks live (future work)

1. **Python per-chunk overhead** dominates at ≥ 256 MiB. CDC
   chunks are framed individually as JSON + base64; for 4000+
   chunks the per-frame Python work adds up. A binary
   `FILE_CDC_CHUNK` frame (already partially shipped as
   `_encode_binary_frame`) + SIMD batch decrypt on the receiver
   would push the steady-state above 200 MiB/s.

2. **FILE_OFFER round-trip** is ~50 ms on loopback. For
   many-small-files workflows (a folder of photos), this is
   the dominant cost. `FILE_OFFER_BATCH` would amortize.

3. **Warm dedup reassembly cost** at 16 MiB is ~50 ms, dominated
   by re-reading + re-writing 16 MiB from the cache to a new
   unique inbox path. Hardlinking when the source partial still
   exists would make warm dedup near-instant.

4. **QUIC cutover** would replace the WebRTC DTLS-SRTP datagram
   path with QUIC streams; the underlying transport probably
   ceilings the WebRTC datagram approach somewhere above 200
   MiB/s. Not measured directly.
