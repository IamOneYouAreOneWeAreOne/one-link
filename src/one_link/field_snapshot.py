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

import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from one_link.fault_observability import report_best_effort_failure

log = logging.getLogger(__name__)


def _env_disabled(name: str) -> bool:
    """Truthy environment-variable kill-switch reader.

    A coupling is "disabled" when its env var is set to anything in
    ``{"1", "true", "yes", "on"}`` (case-insensitive). All four
    coupling switches honour this:

    * ``ONE_LINK_FIELD_DISABLE``           — disable the whole manager
    * ``ONE_LINK_DISABLE_BE_RAR``          — relay scoring fallback
    * ``ONE_LINK_FIELD_CADENCE_DISABLE``   — ratchet cadence advisory
    * ``ONE_LINK_FIELD_HOMOLOGY_DISABLE``  — homology → source injection
    * ``ONE_LINK_FIELD_PREFETCH_DISABLE``  — field-distance holder rank

    Operator escape hatch: a noisy / suspected-broken coupling can be
    flipped off without rebuilding the crate or restarting the user."""
    val = os.environ.get(name, "").strip().lower()
    return val in ("1", "true", "yes", "on")


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

    def __init__(
        self,
        config: Optional[FieldConfig] = None,
        *,
        persist_path: Optional[Path] = None,
    ) -> None:
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
        # Phase E homology coupling: pending fragility events to inject
        # into the source vector at the next solve. Each event is
        # ``(peer_short_ids, weight)`` — peers in the affected cycle,
        # and how strongly to suppress the field there. The manager
        # converts to per-peer index space at solve time.
        self._fragility_events: list[tuple[list[str], float]] = []
        self._fragility_coupling_strength: float = 1.0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        # Counters surfaced via /api/metrics.
        self.solve_count = 0
        self.solve_failures = 0
        self.last_solve_wall_ns = 0
        # Optional persistence path for save-on-shutdown / load-on-boot.
        # When set, the first solve doesn't have to wait 5s after a
        # daemon restart — the previous snapshot warms the cache.
        self._persist_path = persist_path
        # Try to apply One Link calibration at construction.
        self._apply_calibration()
        # Try to warm-start from the persisted snapshot, if any.
        if persist_path is not None:
            self._try_load_persisted_snapshot()

    def _apply_calibration(self) -> None:
        """Replace the fallback (D, gamma) with the canonical One Link
        calibration if the native crate is available."""
        try:
            from one_link import coherence_field_native as cf

            if cf.HAS_NATIVE:
                cal = cf.one_link_calibration()
                self._config.helmholtz_d = float(cal["d"])
                self._config.helmholtz_gamma = float(cal["gamma"])
        except Exception as exc:
            # Stays on the dataclass defaults; not fatal.
            report_best_effort_failure(
                log,
                "field_native_calibration",
                exc,
                level=logging.DEBUG,
            )

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

    def update_fragility_events(
        self,
        events: list[tuple[list[str], float]],
        *,
        coupling_strength: float = 1.0,
    ) -> None:
        """Replace the pending fragility-event list.

        Each event is a ``(peer_short_ids, weight)`` pair describing
        peers that participate in a closing-loop fragility cycle
        detected by ``ol_homology``. At the next ``_tick``, the manager
        translates short-ids to peer indices and calls
        ``inject_fragility_events()`` to negatively spike the source
        vector at those nodes. The field then re-equilibrates so that
        routes naturally avoid the fragile region BEFORE the partition
        actually completes.

        Replaces the entire pending list, so the caller can pass an
        empty list to clear events (e.g. after the fragility resolved).
        ``coupling_strength`` scales the spike magnitude — operators
        can dial it down if the field over-reacts."""
        with self._lock:
            self._fragility_events = list(events)
            self._fragility_coupling_strength = float(coupling_strength)

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
            # Master env kill-switch: skip the solve entirely. The
            # manager keeps running so consumers can still query
            # (they'll get None / safe-default fallbacks); flipping
            # the switch back off resumes solving on the next tick.
            if not _env_disabled("ONE_LINK_FIELD_DISABLE"):
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
            pending_fragility = list(self._fragility_events)
            fragility_strength = self._fragility_coupling_strength

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
            except (IndexError, KeyError, RuntimeError, TypeError, ValueError) as exc:
                # Duplicate edges from the daemon's view: tolerate.
                report_best_effort_failure(
                    log,
                    "field_graph_edge",
                    exc,
                    level=logging.DEBUG,
                )
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

        # Phase E #2 coupling — homology fragility events negatively
        # spike S at affected nodes so the next solve re-equilibrates
        # away from the fragile region. Operator escape hatch:
        # ONE_LINK_FIELD_HOMOLOGY_DISABLE=1 skips injection.
        if (
            pending_fragility
            and not _env_disabled("ONE_LINK_FIELD_HOMOLOGY_DISABLE")
        ):
            translated: list[tuple[list[int], float]] = []
            for peer_ids, weight in pending_fragility:
                idx_list: list[int] = []
                for pid in peer_ids:
                    idx = index.get(pid)
                    if idx is not None:
                        idx_list.append(idx)
                if idx_list:
                    translated.append((idx_list, float(weight)))
            if translated:
                try:
                    source_vec_out, _penalties = cf.inject_fragility_events(
                        list(source_vec),
                        translated,
                        coupling_strength=fragility_strength,
                    )
                    source_vec = source_vec_out
                except Exception as exc:  # pragma: no cover
                    # Native crate raised; fall through with the
                    # un-injected source. Couplings degrade gracefully.
                    report_best_effort_failure(
                        log,
                        "field_fragility_injection",
                        exc,
                        level=logging.DEBUG,
                    )

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
        # Persistence: after each successful solve, atomically write
        # the snapshot to disk so a daemon restart can warm-start
        # instead of waiting 5s for the next tick. Best-effort; a
        # disk write failure is not fatal.
        if self._persist_path is not None:
            try:
                self._save_snapshot_to_disk(snapshot)
            except Exception:  # pragma: no cover
                log.debug("snapshot persistence write failed", exc_info=True)

    # ── persistence (warm-start across daemon restart) ─────────────

    def _save_snapshot_to_disk(self, snap: FieldSnapshot) -> None:
        """Atomically serialize ``snap`` to ``self._persist_path``.

        Uses tempfile + os.replace for atomicity: a daemon kill in
        the middle of the write leaves the previous good snapshot
        untouched. Format is plain JSON — the snapshot is small
        (O(peers²) floats) so binary packing isn't worth the cost."""
        if self._persist_path is None:
            return
        payload = {
            "version": 1,
            "peers": list(snap.peers),
            "field": list(snap.field),
            "cadences": [
                [int(idx), float(mult), int(btw)]
                for idx, mult, btw in snap.cadences
            ],
            "solve_iterations": int(snap.solve_iterations),
            "solve_residual": float(snap.solve_residual),
            "solve_wall_ns": int(snap.solve_wall_ns),
            "saved_at_ns": time.perf_counter_ns(),
        }
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=".field-snapshot-",
            suffix=".json.tmp",
            dir=str(self._persist_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp_path, self._persist_path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:  # pragma: no cover
                pass
            raise

    def _try_load_persisted_snapshot(self) -> None:
        """Read the on-disk snapshot at construction time, if present.

        Best-effort: a malformed file is silently ignored — the
        manager falls back to "no snapshot until the first solve."
        This is a UX win (first 5s of post-restart life has guidance
        from the previous run) not a correctness requirement."""
        if self._persist_path is None or not self._persist_path.exists():
            return
        try:
            payload = json.loads(
                self._persist_path.read_text(encoding="utf-8")
            )
        except Exception:
            log.debug(
                "discarding malformed persisted field snapshot at %s",
                self._persist_path,
                exc_info=True,
            )
            return
        if not isinstance(payload, dict) or payload.get("version") != 1:
            return
        try:
            snap = FieldSnapshot(
                peers=tuple(payload["peers"]),
                field=tuple(float(x) for x in payload["field"]),
                cadences=tuple(
                    (int(c[0]), float(c[1]), int(c[2]))
                    for c in payload["cadences"]
                ),
                solve_iterations=int(payload["solve_iterations"]),
                solve_residual=float(payload["solve_residual"]),
                solve_wall_ns=int(payload["solve_wall_ns"]),
                captured_at_ns=time.perf_counter_ns(),
            )
        except (KeyError, TypeError, ValueError):
            log.debug(
                "persisted field snapshot at %s has unexpected shape",
                self._persist_path,
                exc_info=True,
            )
            return
        with self._lock:
            self._current = snap
        log.info(
            "field snapshot warm-started from %s (%d peers)",
            self._persist_path,
            len(snap.peers),
        )

    # ── query API (called from consumers) ──────────────────────────

    def snapshot(self) -> Optional[FieldSnapshot]:
        """Current snapshot or ``None`` if not yet solved."""
        with self._lock:
            return self._current

    def cadence_for_peer(self, peer: str) -> Optional[int]:
        """Recommended bytes-between-rotations for the given peer, or
        ``None`` if no snapshot or the peer isn't in it. Callers
        treating `None` as "use baseline" preserve correctness.

        Operator escape hatch: ``ONE_LINK_FIELD_CADENCE_DISABLE=1``
        forces ``None`` regardless of snapshot — useful when the
        cadence advisory is suspected of misbehaving on production."""
        if _env_disabled("ONE_LINK_FIELD_CADENCE_DISABLE"):
            return None
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
