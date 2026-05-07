# Performance Lab

Status: in_progress for v0.10.9.

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

- **CDC indexing throughput**: how fast One Link can split and hash a file.
- **Prior-knowledge savings**: how many bytes can be skipped when the receiver
  already has a related object.
- **Swarm scheduler throughput**: how quickly One Link can assign chunks across
  trusted devices.
- **Never-lose torture sim**: whether retry, corruption, and offline behavior
  still delivers.
- **SQLite transfer ledger pressure**: how many transfer updates per second the
  durable ledger can absorb.
- **Compression throughput**: zlib level-1 speed and ratio for easy data.

## How To Read The Report

Useful first-pass signals:

- `cdc_indexing.metrics.mib_per_s`: higher is better.
- `prior_knowledge_dedup.metrics.bandwidth_reduction`: closer to `1.0` is
  better when files are related.
- `swarm_scheduler.metrics.chunks_per_s`: higher means the planner can scale
  to very large transfers and many helpers.
- `never_lose_torture_sim.metrics.delivered`: must be `true`.
- `sqlite_transfer_ledger.metrics.writes_per_s`: higher means smoother live UI
  updates under many transfers.
- `zlib_level1_compression.metrics.mib_per_s`: higher means compression is less
  likely to become the bottleneck.

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

On the current Windows dev machine, `standard` scale produced:

- CDC indexing: about `8 MiB/s`.
- Prior-knowledge related-file savings: about `99%` bytes skipped.
- Swarm scheduling: about `388k chunks/s`.
- SQLite transfer ledger: about `17k writes/s`.
- Compression: several GiB/s on easy data.

Interpretation: the scheduler and ledger are not the bottleneck right now. The
largest obvious optimization target is CDC indexing throughput, followed by
real two-device LAN transfer throughput and browser UI pressure under many live
transfer events.
