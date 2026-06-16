"""Production runtime adapter for the Call Immune System.

The :class:`one_link.call_immune.ImmuneSystem` is the pure decision
engine. :func:`one_link.call_vitals.read_call_vitals` composes the
daemon-state read. This module wires them together:

  - :class:`BrowserMetricsCache` holds per-call WebRTC stats the
    browser POSTs each window (rtt, loss, jitter, audio confirm
    ratio). The vitals composer can't see these directly because
    the browser owns the RTC peer connection.
  - :func:`drive_immune_tick_for_call` reads vitals via
    ``read_call_vitals``, overlays browser metrics, ticks the
    Immune System, and persists the decision through
    :class:`AuditLogger`.

Doctrine: SHADOW-mode controllers never speak user-facing language.
Audit entries are engineer artifacts; tail events are the
user-facing translation layer.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.1 (Immune System SHADOW)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, is_dataclass, replace
from pathlib import Path
from typing import Any, Optional

from one_link.call_immune import (
    ImmuneAction,
    ImmuneDecision,
    ImmuneSystem,
)
from one_link.call_vitals import CallVitals, read_call_vitals

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Browser metrics cache
# ---------------------------------------------------------------------------

class BrowserMetricsCache:
    """Per-call cache of browser-reported WebRTC stats.

    The daemon doesn't see live RTC media; the browser does, via
    ``RTCPeerConnection.getStats``. Each attestation window the
    browser POSTs the relevant counters to ``action: report_metrics``
    which lands here. The runtime overlays this cache onto the
    daemon-state vitals each tick.

    Thread-safe. Per-call entries persist between reports until
    the call is cleared.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, float]] = {}

    def update(
        self,
        *,
        call_id: str,
        rtt_ms: Optional[float] = None,
        loss_rate: Optional[float] = None,
        jitter_ms: Optional[float] = None,
        confirm_ratio_voice: Optional[float] = None,
        bandwidth_estimate_kbps: Optional[float] = None,
    ) -> None:
        with self._lock:
            d = self._data.setdefault(call_id, {})
            if rtt_ms is not None:
                d["rtt_ms"] = float(rtt_ms)
            if loss_rate is not None:
                d["loss_rate"] = max(0.0, min(1.0, float(loss_rate)))
            if jitter_ms is not None:
                d["jitter_ms"] = float(jitter_ms)
            if confirm_ratio_voice is not None:
                d["confirm_ratio_voice"] = max(
                    0.0, min(1.0, float(confirm_ratio_voice))
                )
            if bandwidth_estimate_kbps is not None:
                d["bandwidth_estimate_kbps"] = float(bandwidth_estimate_kbps)

    def get(self, call_id: str) -> dict[str, float]:
        with self._lock:
            return dict(self._data.get(call_id, {}))

    def clear_call(self, call_id: str) -> None:
        with self._lock:
            self._data.pop(call_id, None)

    def overlay(self, vitals: CallVitals) -> CallVitals:
        """Return a copy of ``vitals`` with any cached browser stats
        substituted in. Fields whose browser equivalent isn't present
        retain their daemon-side value."""
        bm = self.get(vitals.call_id)
        if not bm:
            return vitals
        updates: dict[str, Any] = {}
        if "rtt_ms" in bm:
            updates["rtt_ewma_ms"] = bm["rtt_ms"]
        if "loss_rate" in bm:
            updates["loss_rate_ewma"] = bm["loss_rate"]
        if "jitter_ms" in bm:
            updates["jitter_ms"] = bm["jitter_ms"]
        if "confirm_ratio_voice" in bm:
            updates["confirm_ratio_voice"] = bm["confirm_ratio_voice"]
        if "bandwidth_estimate_kbps" in bm:
            updates["bandwidth_estimate_kbps"] = bm["bandwidth_estimate_kbps"]
        if not updates:
            return vitals
        return replace(vitals, **updates)


# ---------------------------------------------------------------------------
# Audit logger — rotating JSONL on disk
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only JSONL log of every emitted ImmuneDecision.

    Doctrine: internal-only. Never surfaced to the user. Engineers
    read it to validate Immune behaviour during SHADOW + ASSIST
    dogfooding.

    Rotation: when the active file exceeds :attr:`max_bytes`, it's
    renamed with a timestamp suffix and a fresh file is opened.
    The :attr:`max_files` oldest rotations are deleted on the next
    rotation event so disk usage stays bounded.

    Thread-safe.
    """

    def __init__(
        self,
        *,
        path: Path,
        max_bytes: int = 4 * 1024 * 1024,
        max_files: int = 8,
    ) -> None:
        self._path = Path(path)
        self._max_bytes = int(max_bytes)
        self._max_files = int(max_files)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, decision: ImmuneDecision) -> None:
        with self._lock:
            try:
                self._rotate_if_oversize_locked()
                with self._path.open("a", encoding="utf-8") as f:
                    json.dump(_serialize(decision), f, separators=(",", ":"))
                    f.write("\n")
            except OSError as exc:
                log.warning("audit log write failed: %s", exc)

    def read_recent(self, n: int = 64) -> list[dict]:
        with self._lock:
            if not self._path.exists():
                return []
            try:
                lines = self._path.read_text(encoding="utf-8").splitlines()
            except OSError:
                return []
            out: list[dict] = []
            for raw in lines[-n:]:
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
            return out

    def _rotate_if_oversize_locked(self) -> None:
        try:
            size = self._path.stat().st_size
        except FileNotFoundError:
            return
        if size < self._max_bytes:
            return
        suffix = time.strftime("%Y%m%d-%H%M%S")
        rotated = self._path.with_suffix(self._path.suffix + f".{suffix}")
        try:
            os.replace(self._path, rotated)
        except OSError as exc:
            log.warning("audit log rotate failed: %s", exc)
            return
        try:
            siblings = sorted(
                self._path.parent.glob(f"{self._path.name}.*"),
                key=lambda p: p.stat().st_mtime,
            )
            for old in siblings[: -self._max_files]:
                try:
                    old.unlink()
                except OSError:
                    pass
        except OSError:
            pass


def _serialize(decision: ImmuneDecision) -> dict:
    if is_dataclass(decision):
        d = asdict(decision)
    else:
        d = dict(decision.__dict__)
    if "action" in d:
        try:
            d["action_name"] = ImmuneAction(d["action"]).name
            d["action"] = int(d["action"])
        except (ValueError, TypeError):
            pass
    if "vitals_hash" in d and isinstance(d["vitals_hash"], (bytes, bytearray)):
        d["vitals_hash"] = bytes(d["vitals_hash"]).hex()
    return d


# ---------------------------------------------------------------------------
# Top-level tick driver
# ---------------------------------------------------------------------------

class _TickCounter:
    """Per-call monotonic tick counter the runtime threads into
    each :func:`read_call_vitals` call."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}

    def next_for(self, call_id: str) -> int:
        with self._lock:
            n = self._counters.get(call_id, 0)
            self._counters[call_id] = n + 1
            return n

    def reset(self, call_id: str) -> None:
        with self._lock:
            self._counters.pop(call_id, None)


def drive_immune_tick_for_call(
    *,
    daemon: Any,
    immune: ImmuneSystem,
    metrics: BrowserMetricsCache,
    tick_counter: _TickCounter,
    audit: Optional[AuditLogger],
    call_id: str,
    peer_master_vk_hex: str,
) -> ImmuneDecision:
    """One tick for one active call.

    Reads daemon-state vitals, overlays browser-reported WebRTC
    metrics, ticks the Immune System, persists the decision.
    Returns the decision so the caller can act on it (e.g.,
    inject a ManagerEvent into the CallManager when ASSIST/
    AUTOPILOT modes emit actions).
    """
    tick = tick_counter.next_for(call_id)
    vitals = read_call_vitals(
        daemon, peer_fp=peer_master_vk_hex, tick=tick, call_id=call_id,
    )
    vitals = metrics.overlay(vitals)
    decision = immune.tick(vitals)
    if audit is not None:
        try:
            audit.append(decision)
        except Exception as exc:
            log.warning("audit append raised: %s", exc)
    return decision
