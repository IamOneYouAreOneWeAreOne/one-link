"""Production-side coherence-field snapshot manager.

The daemon owns one ``FieldSnapshotManager`` that:

1. Mirrors the current peer-graph (relay metrics → adjacency).
2. Periodically (default every 5s) solves the Helmholtz field via
   :mod:`one_link.coherence_field_native`.
3. Caches the recovered field for downstream consumers.
4. Exposes query helpers for the ratchet-cadence advisory and the
   bandit-prior shaper.

Without this hub, every consumer (ratchet manager, bandit, prefetch
scheduler) would have to know how to build the graph + solve the
field. With the hub, each consumer queries a precomputed snapshot —
keeping per-consumer cost at O(1).

The manager is **never on the critical send path**. Its update tick
runs on a background coroutine; consumers always read the most-recent
snapshot (possibly stale by < update_interval seconds). If the field
crate isn't installed, all queries return safe defaults (uniform
multipliers) so callers behave as if Phase E weren't active.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class FieldSnapshot:
    """One frozen field-solve result, keyed by the peer set that
    produced it."""

    peers: tuple[str, ...]
    """Stable peer ordering used to index into ``field`` / ``cadences``."""

    field: tuple[float, ...]
    """Recovered δτ_c value per peer (length == len(peers))."""

    cadences: tuple[tuple[int, float, int], ...]
    """One ``(peer_idx, multiplier, bytes_between_rotations)`` triple
    per peer. Output of `rotation_cadence_multiplier`."""

    solve_iterations: int
    solve_residual: float
    solve_wall_ns: int
    captured_at_ns: int
    """Monotonic timestamp; downstream consumers compare to
    `time.perf_counter_ns()` to compute staleness."""


@dataclass
class FieldConfig:
    """Tunable knobs for the snapshot loop."""

    update_interval_s: float = 5.0
    """How often the background loop re-solves. Bumping this trades
    snapshot freshness for CPU. Default 5s matches the plan's
    `~1 Hz` field-snapshot cadence."""

    baseline_chunk_size: int = 1_000_000
    """Bytes between baseline ratchet rotations (1 MiB). Per-peer
    cadence is `baseline / multiplier` per `rotation_cadence_multiplier`."""

    mu_max: float = 4.0
    """Maximum rotation-rate multiplier (cap at 4× per the plan)."""

    cadence_power: float = 2.0
    """Quadratic contrast on the field deficit (per Phase E coupling)."""

    helmholtz_d: float = 100.0
    """Diffusion coefficient. Picked up from
    `coherence_field_native.one_link_calibration()` at startup; this
    is the fallback if calibration is unavailable."""

    helmholtz_gamma: float = 0.01
    """Damping coefficient. Same fallback semantics."""

    min_peers: int = 3
    """Below this peer count, snapshots are skipped (the field math
    is degenerate on tiny graphs and Phase E doesn't add value)."""


class FieldSnapshotManager:
    """Owns the daemon-side periodic field solve.

    Thread-safe: the background tick updates an `_current` snapshot
    under a lock; queries take the lock briefly to read it.
    """

    def __init__(self, config: Optional[FieldConfig] = None) -> None:
        self._config = config or FieldConfig()
        self._current: Optional[FieldSnapshot] = None
        self._lock = threading.Lock()
        # The "what does the daemon think the peer graph is" surface,
        # set by the daemon via `update_topology()`. Stored as a list
        # of `(peer_a, peer_b, edge_weight)` triples. The manager
        # converts to a `GraphLaplacian` at solve time.
        self._topology: list[tuple[str, str, float]] = []
        # Per-peer source contribution (`(peer, density, flux)`).
        # The daemon updates these as relay metrics evolve.
        self._sources: dict[str, tuple[float, float]] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Counters surfaced via /api/metrics.
        self.solve_count = 0
        self.solve_failures = 0
        self.last_solve_wall_ns = 0
        # Try to apply One Link calibration at construction.
        self._apply_calibration()

    def _apply_calibration(self) -> None:
        """Replace the fallback (D, gamma) with the canonical One Link
        calibration if the native crate is available."""
        try:
            from one_link import coherence_field_native as cf

            if cf.HAS_NATIVE:
                cal = cf.one_link_calibration()
                self._config.helmholtz_d = float(cal["d"])
                self._config.helmholtz_gamma = float(cal["gamma"])
        except Exception:
            # Stays on the dataclass defaults; not fatal.
            pass

    # ── topology + source updates (called from daemon) ─────────────

    def update_topology(self, edges: list[tuple[str, str, float]]) -> None:
        """Replace the current peer-graph adjacency. Triples are
        ``(peer_a, peer_b, edge_weight)`` and treated as undirected."""
        with self._lock:
            self._topology = list(edges)

    def update_peer_source(self, peer: str, *, density: float, flux: float) -> None:
        """Update one peer's source-term contribution (density + flux).
        Both are non-negative; the manager clamps internally."""
        with self._lock:
            self._sources[peer] = (max(density, 0.0), max(flux, 0.0))

    def forget_peer(self, peer: str) -> None:
        """Drop a peer's source-term entry (e.g. on disconnect)."""
        with self._lock:
            self._sources.pop(peer, None)

    # ── lifecycle ───────────────────────────────────────────────────

    def start(self) -> None:
        """Spawn the background tick. Idempotent; multiple calls
        re-use the running thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name="ol-field-snapshot",
            daemon=True,
        )
        self._thread.start()

    def stop(self, *, join_timeout: float = 2.0) -> None:
        """Signal the loop to exit. Waits up to `join_timeout` seconds."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=join_timeout)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:  # pragma: no cover
                self.solve_failures += 1
                log.debug("field snapshot tick failed: %s", exc)
            self._stop.wait(self._config.update_interval_s)

    def _tick(self) -> None:
        """One snapshot. Skips when not enough peers / native crate
        missing. Run on the background thread; never on the hot path."""
        try:
            from one_link import coherence_field_native as cf

            if not cf.HAS_NATIVE:
                return
        except ImportError:
            return

        with self._lock:
            edges = list(self._topology)
            sources = dict(self._sources)

        # Collect the peer set referenced by either the topology or
        # the source map. Stable-sorted for reproducibility.
        peer_set: set[str] = set()
        for a, b, _ in edges:
            peer_set.add(a)
            peer_set.add(b)
        peer_set.update(sources.keys())
        if len(peer_set) < self._config.min_peers:
            return
        peers = tuple(sorted(peer_set))
        index = {p: i for i, p in enumerate(peers)}

        # Build the graph + source vector.
        g = cf.graph_laplacian(len(peers))
        for a, b, w in edges:
            if a == b:
                continue
            try:
                g.add_edge(index[a], index[b], float(w))
            except Exception:
                # Duplicate edges from the daemon's view: tolerate.
                pass
        density = [0.0] * len(peers)
        flux = [0.0] * len(peers)
        for p, (d, f) in sources.items():
            i = index[p]
            density[i] = d
            flux[i] = f

        # Use the bare identity-dual source; phase-kernel modulation
        # is the right call for swarms with a clear core/edge
        # topology, but in production we don't know c_support yet.
        from one_link_native import coherence_field as _native_cf  # type: ignore[attr-defined]

        source_vec = _native_cf.identity_dual_source(density, flux, 0.5, 0.5)
        t0 = time.perf_counter_ns()
        try:
            result = cf.solve_helmholtz(
                g,
                self._config.helmholtz_d,
                self._config.helmholtz_gamma,
                source_vec,
            )
        except Exception:
            self.solve_failures += 1
            return
        wall_ns = time.perf_counter_ns() - t0
        self.last_solve_wall_ns = wall_ns

        if not result["converged"]:
            self.solve_failures += 1
            return

        field_vec: list[float] = list(result["field"])
        cadences = cf.rotation_cadence_multiplier(
            field_vec,
            baseline_bytes=self._config.baseline_chunk_size,
            mu_max=self._config.mu_max,
            power=self._config.cadence_power,
        )

        snapshot = FieldSnapshot(
            peers=peers,
            field=tuple(field_vec),
            cadences=tuple(cadences),
            solve_iterations=result["iterations"],
            solve_residual=result["residual"],
            solve_wall_ns=wall_ns,
            captured_at_ns=time.perf_counter_ns(),
        )
        with self._lock:
            self._current = snapshot
        self.solve_count += 1

    # ── query API (called from consumers) ──────────────────────────

    def snapshot(self) -> Optional[FieldSnapshot]:
        """Current snapshot or ``None`` if not yet solved."""
        with self._lock:
            return self._current

    def cadence_for_peer(self, peer: str) -> Optional[int]:
        """Recommended bytes-between-rotations for the given peer, or
        ``None`` if no snapshot or the peer isn't in it. Callers
        treating `None` as "use baseline" preserve correctness."""
        snap = self.snapshot()
        if snap is None:
            return None
        try:
            idx = snap.peers.index(peer)
        except ValueError:
            return None
        for peer_idx, _mult, bytes_btw in snap.cadences:
            if peer_idx == idx:
                return bytes_btw
        return None

    def field_score_for_peer(self, peer: str) -> Optional[float]:
        """Normalised field value at `peer` ∈ (0, 1], 1 = highest
        coherence in the swarm. Used by the bandit-prior shaper to
        scale arm exploration on field-correlated routes."""
        snap = self.snapshot()
        if snap is None:
            return None
        try:
            idx = snap.peers.index(peer)
        except ValueError:
            return None
        f_min = min(snap.field)
        f_max = max(snap.field)
        span = max(f_max - f_min, 1e-9)
        normalized = (snap.field[idx] - f_min) / span
        return max(normalized, 1e-9)

    def metrics(self) -> dict[str, float | int]:
        """Operator-facing telemetry. Surfaced via the daemon's
        `/api/metrics` route."""
        snap = self.snapshot()
        d: dict[str, float | int] = {
            "field_solve_count": self.solve_count,
            "field_solve_failures": self.solve_failures,
            "field_last_solve_ns": self.last_solve_wall_ns,
            "field_topology_edge_count": len(self._topology),
            "field_source_peer_count": len(self._sources),
        }
        if snap is not None:
            d["field_snapshot_peer_count"] = len(snap.peers)
            d["field_snapshot_iterations"] = snap.solve_iterations
            d["field_snapshot_residual"] = snap.solve_residual
            d["field_snapshot_age_ms"] = (
                time.perf_counter_ns() - snap.captured_at_ns
            ) / 1e6
        else:
            d["field_snapshot_peer_count"] = 0
            d["field_snapshot_age_ms"] = -1.0
        return d
