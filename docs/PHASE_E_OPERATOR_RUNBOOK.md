# Phase E Operator Runbook

> Quick reference for diagnosing the coherence-field substrate in
> production. Read this BEFORE the field is acting up.

## What Phase E actually does (in 30 seconds)

The daemon owns a background-ticking `FieldSnapshotManager` that:
1. Mirrors the current peer-graph (peers + edge weights).
2. Every 5 seconds, solves the Helmholtz equation
   `(Γ·I + D·L)·δτ_c = S` to recover a per-peer "coherence" scalar.
3. Caches the result.

Downstream consumers (relay scoring via BE-RAR, ratchet cadence, bandit
priors, prefetch ranking) read the cache. Without the field, the daemon
falls back to Phase D heuristics. Nothing in Phase E is on the critical
send path.

## "Is it working?"

Hit `/api/metrics` on the daemon (UI port, auth-token gated):

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:$UI_PORT/api/metrics
```

Healthy output snippet:

```json
{
  "native": {
    "coherence_field": {
      "available": true,
      "calibration": {"d": 100.0, "gamma": 0.01, "screening_length": 100.0, ...},
      "snapshot_metrics": {
        "field_solve_count": 47,
        "field_solve_failures": 0,
        "field_snapshot_age_ms": 2103.5,
        "field_snapshot_peer_count": 12,
        "field_snapshot_iterations": 18,
        "field_snapshot_residual": 7.3e-7
      }
    }
  },
  "per_peer_field_advisories": {
    "abc12345": {"cadence_bytes": 250000, "field_score": 0.42}
  }
}
```

Green flags:
- `coherence_field.available: true`
- `field_solve_count` increasing over time
- `field_solve_failures` stays at 0
- `field_snapshot_age_ms < 6000` (one update_interval + a tick budget)
- `field_snapshot_residual < 1e-5`
- `field_snapshot_iterations <= 50`

Red flags (and what they mean):

| Symptom | Likely cause | Fix |
|---|---|---|
| `available: false` | `ol_coherence_field` not built | `cd native && maturin develop --release` |
| `field_solve_count: 0` after several minutes | No peers yet, or `field_topology_edge_count` is zero | Verify peers actually paired; field skips solve below `min_peers=3` |
| `field_solve_failures` climbing | Non-convergent solves (probably degenerate topology — disconnected components or zero-weight edges) | Check `/api/peers` for connectivity; bump CG max_iter if topology is large + weakly-connected |
| `field_snapshot_age_ms > 30000` | Background loop stuck or thread died | Look for "field snapshot tick failed" in daemon logs; restart daemon |
| `field_snapshot_residual > 1e-3` | Operator badly conditioned (D ≫ Γ or both → 0) | Verify calibration constants match expected One Link defaults (D=100, Γ=0.01) |

## "Routing decisions look weird"

Phase E's BE-RAR scorer can pick paths that look counter-intuitive vs.
the heuristic `1/(1−loss)²`. Specifically:

- BE-RAR's penalty is **softer at moderate loss** (10–40%): it ranks
  near-tie relays by RTT rather than over-weighting loss.
- BE-RAR's penalty **diverges at extreme loss** (>80%): pathological
  relays still get rejected.
- **BE-RAR can pick a low-RTT, moderately-lossy relay over a high-RTT,
  low-loss one.** This is the correct math, not a bug. If you want the
  heuristic back, set `ONE_LINK_DISABLE_BE_RAR=1`.

To compare picks:
1. Capture `/api/metrics` + `per_peer_field_advisories` while the
   weird pick happens.
2. Note the peer's `field_score` (0..1) and `cadence_bytes`.
3. Cross-reference with `_relay_metrics` (RTT + loss for each
   relay) — see daemon logs at DEBUG.

## "Daemon CPU is spiking"

The field solve at 100 peers takes ~17µs through the pyo3 surface.
At 10k peers it takes ~33µs (warm-start) or ~1.5ms (cold). A solve
every 5s means **steady-state field CPU is < 0.1%**.

If you see CPU spikes correlated with field solves:
1. Check `field_snapshot_peer_count` — anything > 10k is outside the
   benchmarked range.
2. Bump `update_interval_s` in `FieldConfig` (default 5s).
3. If still bad, set `update_interval_s = 60.0` and report a perf bug.

## "Convergent-encryption chunks aren't deduping"

Files now flow through `convergent` or `raw` BLAKE3 addressing based on
extension (see `NativeTransferSession._resolve_address_kind`). To check
which scheme a file used:

- `.mp4/.mov/.h264/.wav/.flac/.jpg/.png/...` → `convergent` →
  cross-sender dedup works.
- `.docx/.pdf/.zip/.rs/.py/...` → `raw` → per-recipient keys, no
  cross-sender dedup (intentional, privacy-preserving default).

If a file you expect to dedup isn't, verify:
1. Both senders have the same extension (case-insensitive).
2. Plaintext is byte-identical (any metadata embedded in the file
   header — Premiere project IDs, exif timestamps — breaks dedup
   even at convergent).
3. `/api/metrics` shows `coherence_field.available: true` on both
   senders (the dispatch helper is gated on Phase E in spirit; the
   address kind itself ships standalone).

## "Ratchet keys feel like they're rotating too often"

The field-driven cadence advisory shrinks the chunk size sent to
peers in low-coherence wells, which (via the per-chunk ratchet)
makes rotation faster per byte. Floor is 64 KiB so framing
overhead never dominates.

The advisory is **actively wired** into `Daemon.send_file`: after
`_fast_fixed_chunk_size_for_peer` picks the baseline, the daemon
queries `Daemon.cadence_for_peer(peer_short_id)` and clamps down
when the field reports a smaller cadence.

To investigate or force baseline:

1. `/api/metrics` — check `per_peer_field_advisories[peer].cadence_bytes`.
2. Compare with baseline 1,000,000 bytes (1 MiB).
3. To bypass entirely set `ONE_LINK_FIELD_CADENCE_DISABLE=1` —
   `cadence_for_peer` will return `None` and `send_file` keeps the
   peer-version-derived baseline.

## Field-snapshot manager doesn't seem to be updating

The manager runs on a Python `threading.Thread`. To prove it's alive:

```python
# In a daemon REPL (or via an admin endpoint if exposed):
mgr = daemon._field_snapshot
print(mgr is not None)        # True if started
print(mgr._thread.is_alive()) # True if loop is running
print(mgr.metrics())          # Should show non-stale numbers
```

If `_thread.is_alive() == False`, the loop crashed. Daemon logs at
DEBUG level should show the traceback. The manager is engineered to
swallow per-tick errors and continue, so a hard thread death is rare.

## Calibration mismatch across daemons

The Helmholtz calibration `(D, Γ)` is compile-time-frozen in
`ol_coherence_field::calibration::one_link`. Two daemons running
**the same build** must report identical calibration. The subprocess
smoke test enforces this:

```bash
pytest tests/test_phase_e_subprocess_smoke.py::test_daemon_pair_field_calibration_matches_across_daemons
```

If two daemons in production disagree, one of them is on a stale
build. Check `/api/status` → `app_version` + `native_status` →
`coherence_field.calibration` on each.

## Tests + benches that gate Phase E health

| What | Where | Threshold |
|---|---|---|
| Native unit + integration | `cargo test -p ol_coherence_field --release` | 91 pass / 0 fail |
| Property invariants | `cargo test --release --test pde_invariants_proptest` | 8 properties × 48 cases |
| Dense-linalg cross-check | `cargo test --release --test dense_reference_cross_check` | 5 regimes, ≤1e-6 abs error |
| Fragile-swarm gate | `scripts/phase_e_live_demo.py` | ≥ 80% chunk-loss reduction |
| Cross-domain demo | `scripts/phase_e_cross_domain_demo.py` | All 3 domains converge |
| Adversarial fuzz | `scripts/adversarial_field_fuzz.py --quick` | 8/8 regimes pass |
| Per-PR perf gate | `scripts/coherence_field_perf_snapshot.py` + `bench_gate.py` | ≤ 5% regression vs baseline |
| Bandit-field consistency | `pytest tests/unit/test_phase_e_demos.py` | both demos green |
| Subprocess smoke | `pytest tests/test_phase_e_subprocess_smoke.py` | daemon pair reports field |

Run the lot before any release that touches `ol_coherence_field`,
`field_snapshot.py`, or the BE-RAR daemon wiring.

## Emergency: disable Phase E entirely

If the field is misbehaving and you need to drop to Phase D
heuristics immediately:

1. Stop the daemon.
2. Run `pip uninstall one_link_native` (the wheel that ships
   `ol_coherence_field`).
3. Restart the daemon. It auto-detects the missing crate and falls
   back to Phase D paths everywhere (relay scoring uses the
   `1/(1-loss)²` heuristic, no field-driven cadences, no bandit
   priors).

The daemon stays fully functional; you lose only the Phase E
performance + alignment gains.

## Per-feature operator escape hatches (env kill-switches)

Each Phase E coupling has its own env-var disable so a misbehaving
coupling can be flipped off without rebuilding the crate or
restarting users. All read at the call site, so toggling takes
effect on the next solve / consumer call.

| Env var | Effect when set to `1` / `true` / `yes` / `on` |
|---|---|
| `ONE_LINK_FIELD_DISABLE` | Pauses the whole solve loop. Manager stays running so consumers still query without crashing (they get safe-default fallbacks). Flipping back off resumes solving on the next tick. |
| `ONE_LINK_DISABLE_BE_RAR` | Relay scoring falls back to the heuristic `1 / (1 − loss)²` penalty. |
| `ONE_LINK_FIELD_CADENCE_DISABLE` | `cadence_for_peer` returns `None`; `send_file` keeps the peer-version-derived baseline chunk size. |
| `ONE_LINK_FIELD_HOMOLOGY_DISABLE` | Homology feeder tick still fires but skips the fragility computation. No fragility events get injected. |
| `ONE_LINK_FIELD_PREFETCH_DISABLE` | `field_rank_holders` returns the input order unchanged (any future multi-holder fetch path gets bandit-only ranking). |

## Snapshot persistence across daemon restart

The manager now writes its latest snapshot to
`data_dir() / "field-snapshot.json"` after every successful solve
(atomic tempfile + `os.replace`). On boot, the constructor reads
that file and seeds `_current` so consumers get field guidance
**before** the first post-restart solve completes — no 5-second
post-restart gap.

A malformed or absent file is silently ignored; the daemon falls
back to "no snapshot until the first tick."

## Upstream feature wirings (now also complete)

The two upstream features the field couplings depend on are also
wired into production code paths:

- **Multi-holder swarm fetch** — `Daemon.pull_swarm_missing_chunks`
  (the production swarm-fetch path that fans a query out to peers,
  collects claims, plans assignments via `plan_swarm_sources`, and
  pulls in parallel) now passes `coherence_score=field_score_for_peer(fp[:8])`
  into each `ChunkSource`. The planner's `route_score` already had
  a coherence slot ranked above bandwidth/latency, so a high-τ_c
  peer is automatically promoted over a low-τ_c one when trust
  ties. Honors `ONE_LINK_FIELD_PREFETCH_DISABLE=1`.
- **Chunk-holder gossip (for the homology feeder)** — every swarm
  query response (`_collect_swarm_chunk_claims`) now folds the
  returned claims into `_chunk_holders`. The homology feeder's
  cohold-graph view is no longer limited to locally-observed
  FILE_DONE events — every swarm query brightens the picture.

## Things that DON'T exist yet (and why)

These are on the production roadmap but NOT shipped:

- **Prometheus / OpenMetrics text format** — `/api/metrics` returns
  JSON only. Wrap externally with a Prometheus exporter if you need
  scraping.

See [FILE_ENGINE_V2_PLAN.md](FILE_ENGINE_V2_PLAN.md) for the full
remaining-work picture.
