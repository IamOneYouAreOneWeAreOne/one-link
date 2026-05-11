# ADR-0024: Phase C-3 daemon-wiring status

**Status:** ACCEPTED (Phase C-3 wiring)
**Phase:** C-3 (daemon migration call-site wiring)
**Companion to:** ADR-0017 (PQ KEM), ADR-0019 (bandit), ADR-0020 (per-chunk ratchet), ADR-0021 (capability layer), ADR-0022 (CRDT folders)

---

## Context

Phase C-3 shipped five native primitives in [`commit 25675d1`](../../). Each primitive landed as a Python *adapter* leaving the legacy code path untouched. After the polish pass in `commit <THIS>`, the call sites in `daemon.py` / `foldersync.py` / `transfer_brain.py` were updated to actually invoke the adapters in shadow / dual-issue mode. This ADR records the current wiring state per migration so future operators don't have to grep five modules to find out what's live.

## Wiring matrix

| Migration | Native primitive | Production call site | Wiring state |
|---|---|---|---|
| #1 PQ-hybrid (ADR-0017) | `ol_pqkem` ML-KEM-768 + X25519 | None on the channel hot path | **Deferred** — `pq_hybrid.py` has no production callers in the daemon today (only an audit-endpoint reference). The new `default_kem()` factory + `NativeHybridKEM` are ready; activation requires the chunk-store transport cutover (a future commit) to choose a KEM and call `default_kem()`. |
| #2 Bandit (ADR-0019) | `ol_bandit` Thompson sampler | `AdaptiveTransferBrain.observe()` | **Shadow** — every legacy observation now also feeds a `BanditRouteSelector`. The EMA-driven pareto-frontier is still authoritative for `.decide()`. `best_route_bandit()` exposes the bandit pick for diagnostics. Cutover replaces the pareto code with a bandit-first selection. |
| #3 Per-chunk ratchet (ADR-0020) | `ol_ratchet` BLAKE3 chain | None on the chunk hot path | **Deferred** — `channel.py` still uses per-message Double Ratchet for text. Per-chunk forward secrecy applies to the chunk-store AEAD path which isn't live yet. `chunk_ratchet.ChunkRatchet` is ready; activation lands with the chunk-store cutover. |
| #4 Capability layer (ADR-0021) | `ol_capability` macaroons | `Daemon.send_share_grant` (daemon.py:5394) | **Dual-issue** — every share mint emits the legacy Ed25519 grant on the wire AND stashes a macaroon-style `Capability` in `self._last_minted_macaroon`. Future commit advertises the macaroon in the share frame so capable peers can verify the new format; the cutover collapses to macaroon-only once all paired peers advertise support. |
| #5 CRDT folders (ADR-0022) | `ol_crdt.Folder` | `FolderEngine._merge_manifest_loop` (foldersync.py:300) | **Shadow** — every merge winner is reflected into per-folder `NativeManifestMirror` instances. `native_folder_snapshot(name)` + `native_mirror_stats()` expose the state. Divergence between legacy + native paths is counted (`_native_mirror_divergence`) but never acted on. Cutover replaces the legacy merge with the native one. |

## Why shadow / dual-issue first

Each migration touches code that the daemon's 2,952-test integration suite exercises. A full cutover-in-one-commit would either break those tests or require parallel updates to the 23 call sites the survey identified. The shadow / dual-issue posture gives:

1. **Zero behavior change**: legacy path is still authoritative. The 2,952 tests pass unchanged.
2. **Production exercise**: the native primitives run in real daemon flows on every observation / merge / mint, exposing edge cases that unit tests don't reach.
3. **Reversible cutover**: when the native code is the obvious choice, the cutover is a small diff (swap `legacy_call(...)` for `native_call(...)`) instead of a 23-site forklift.

## Verification

- **Tests**: 39 migration unit tests + 5 call-site wiring integration tests + 2,952 daemon regression tests pass.
- **Benchmarks** (`tests/benchmarks/bench_phase_c3_migration.py`): native paths are 3–16× faster on the operations that matter (capability mint+verify 16×, chunk-key derivation 8×, route selection 3×). PQ-hybrid is slower than the `NullKEM` placeholder because `NullKEM` is a no-op; the native path does real ML-KEM-768 + X25519 work and costs ~135 µs end-to-end.
- **Type checks**: `mypy --config-file pyproject.toml` is clean on all nine adapter modules (`cap_migration.py`, `chunk_ratchet.py`, `folder_native.py`, plus the six `*_native.py` adapters).
- **Stubs**: hand-written `.pyi` files under `stubs/one_link_native-stubs/` for pyright / IDE autocomplete; PEP 561 compliant.

## What it would take to fully cut over

Per migration, the cutover commit looks like:

| # | Cutover step |
|---|---|
| #1 PQ-hybrid | Wait for chunk-store transport. When it ships, call `pq_hybrid.default_kem()` once at channel startup. |
| #2 Bandit | Replace `AdaptiveTransferBrain.decide()`'s pareto-frontier ordering with `BanditRouteSelector.select_route()` for the route axis. Keep pareto for the mode axis. |
| #3 Per-chunk ratchet | When the chunk-store AEAD path is active, derive each chunk key via `ChunkRatchet.next_key()` keyed off the channel's KEM shared secret. |
| #4 Capability layer | Advertise `macaroon` in the share frame; on the receiver side prefer macaroon verification when present, fall back to Ed25519 grant. |
| #5 CRDT folders | Replace `merge_manifest_entries` in the manifest-receive loop with `NativeManifestMirror.merge_from(remote_folder)`, then read winners back from the native folder. |

Each cutover gates on the previous migration's shadow mode reporting **zero divergence** over a measurable production window. The shadow counters + `native_mirror_stats()` are the signal.

## References

- ADR-0017 (PQ-hybrid KEM)
- ADR-0019 (Multi-armed bandit auto-tuning)
- ADR-0020 (Per-chunk forward-secret ratchet)
- ADR-0021 (Capability layer)
- ADR-0022 (CRDT folders)
- `FILE_ENGINE_V2_PLAN.md` Phase C items 3, 4, 5, 6, 7
