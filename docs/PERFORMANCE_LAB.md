# Performance Lab

Status: in_progress for v0.11.0.

Correctness tests prove One Link should work. The performance lab proves whether
it is getting faster, tighter, and more efficient.

## Run

```powershell
python scripts\perf_lab.py --scale quick
python scripts\perf_lab.py --scale standard
python scripts\perf_lab.py --scale standard --compare benchmarks\results\older.json
```

Reports are written to `benchmarks/results/*.json` and ignored by git.
Use `--compare` to print speed ratios against an older report. That gives us a
simple before/after view after each optimization pass.

## What It Measures

- **Hash-only manifest throughput**: how fast One Link can identify a file
  without building a chunk manifest.
- **Fixed-manifest throughput**: how fast One Link can build aligned block
  manifests for large media.
- **CDC indexing throughput**: how fast One Link can split and hash a file for
  prior-knowledge dedup.
- **Prior-knowledge savings**: how many bytes can be skipped when the receiver
  already has a related object.
- **Swarm scheduler throughput**: how quickly One Link can assign chunks across
  trusted devices.
- **Never-lose torture sim**: whether retry, corruption, and offline behavior
  still delivers.
- **SQLite transfer ledger pressure**: how many transfer updates per second the
  durable ledger can absorb.
- **Compression throughput**: zlib level-1 speed and ratio for easy data.
- **Adaptive transfer brain**: whether local cost planning chooses fast lanes
  when prior knowledge is low and CDC/swarm when prior knowledge is high.
- **Stream pipeline profile**: the adaptive chunk/window plan for keeping
  baseline sends saturated without unbounded memory.

## How To Read The Report

Useful first-pass signals:

- `hash_only_manifest.metrics.mib_per_s`: higher is better.
- `fixed_indexing.metrics.mib_per_s`: higher is better.
- `cdc_indexing.metrics.mib_per_s`: higher is better, but CDC should only be
  selected when its skipped bytes justify its CPU cost.
- `prior_knowledge_dedup.metrics.bandwidth_reduction`: closer to `1.0` is
  better when files are related.
- `swarm_scheduler.metrics.chunks_per_s`: higher means the planner can scale
  to very large transfers and many helpers.
- `never_lose_torture_sim.metrics.delivered`: must be `true`.
- `sqlite_transfer_ledger.metrics.writes_per_s`: higher means smoother live UI
  updates under many transfers.
- `zlib_level1_compression.metrics.mib_per_s`: higher means compression is less
  likely to become the bottleneck.
- `adaptive_transfer_brain.metrics.low_prior_mode`: should prefer a fast lane.
- `adaptive_transfer_brain.metrics.high_prior_python_mode`: shows the honest
  decision with today's Python CDC speed.
- `adaptive_transfer_brain.metrics.high_prior_accelerated_mode`: shows the
  target decision once native/GPU CDC lands.
- `stream_pipeline_profiles.metrics.huge_window_bytes`: maximum baseline stream
  bytes in flight for huge sends.

## What Is Not Yet Measured

This lab is local and deterministic. It does not yet replace:

- two-machine LAN throughput;
- relay/rendezvous internet throughput;
- Windows/macOS/Linux power usage;
- browser frame-time profiling;
- real multi-GB disk send/receive benchmarks;
- CI regression thresholds.

Those are the next performance gates.

## Current Local Snapshot

On the current Windows dev machine, `quick` scale after the v0.11.0 fast-lane
work produced:

- Hash-only manifest: about `1.6 GiB/s`.
- Fixed manifest: about `1.2 GiB/s`.
- CDC indexing: about `8 MiB/s`.
- Adaptive transfer brain: thousands of local decisions per second; with
  current Python CDC it still often chooses hash-stream for huge fast-LAN
  transfers, while accelerated CDC flips high-prior cases to CDC/swarm.
- Stream pipeline: huge sends use up to `4 MiB` chunks with a bounded
  `24 MiB` in-flight window.

On the same machine before this work, `standard` scale produced:

- Prior-knowledge related-file savings: about `99%` bytes skipped.
- Swarm scheduling: about `388k chunks/s`.
- SQLite transfer ledger: about `17k writes/s`.
- Compression: several GiB/s on easy data.

Interpretation: the scheduler and ledger are not the bottleneck right now. The
largest obvious optimization target was blindly paying CDC indexing cost. v0.11
adds the fast lanes and transfer brain needed to stop doing that for peers or
files that cannot benefit from CDC.
