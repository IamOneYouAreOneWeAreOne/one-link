"""Tests for the live-daemon Immune System runtime.

Covers:
  - BrowserMetricsCache overlay onto daemon-state CallVitals.
  - AuditLogger persistence + rotation.
  - drive_immune_tick_for_call end-to-end on a SHADOW-mode system.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
    Thresholds,
)
from one_link.call_immune_runtime import (
    AuditLogger,
    BrowserMetricsCache,
    _TickCounter,
    drive_immune_tick_for_call,
)
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import PathClass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _empty_vitals(call_id: str = "c1", peer_fp: str = "pf") -> CallVitals:
    return CallVitals(
        call_id=call_id,
        peer_fp=peer_fp,
        tick=0,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=2.0,
        bandwidth_estimate_kbps=500.0,
        reliability=0.95,
        last_alive_ms=1_700_000_000_000,
        path_class=PathClass.DIRECT,
        path_fragility_score=0.1,
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=None,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=True,
        audio_frames_received=0,
        audio_frames_dropped=0,
        video_frames_received=0,
        video_frames_predicted=0,
        confirm_ratio_voice=1.0,
        confirm_ratio_video=1.0,
        path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )


class _FakeDaemon:
    """Minimal daemon stand-in for the vitals composer."""

    def __init__(self, peer_fp: str) -> None:
        self._pair_health = {
            peer_fp: {
                "latency_ewma_ms": 60.0,
                "reliability": 0.92,
                "bandwidth_bps": 800_000,
                "last_alive_ms": 1_700_000_000_000,
            },
        }
        self._relay_metrics = {}


# ---------------------------------------------------------------------------
# BrowserMetricsCache
# ---------------------------------------------------------------------------

def test_browser_metrics_cache_overlay_substitutes_rtt() -> None:
    cache = BrowserMetricsCache()
    cache.update(call_id="c1", rtt_ms=300.0)
    v = _empty_vitals(call_id="c1")
    out = cache.overlay(v)
    assert out.rtt_ewma_ms == 300.0
    # other fields unchanged
    assert out.bandwidth_estimate_kbps == 500.0


def test_browser_metrics_cache_clamps_loss_rate() -> None:
    cache = BrowserMetricsCache()
    cache.update(call_id="c1", loss_rate=1.5)  # above 1.0
    out = cache.overlay(_empty_vitals("c1"))
    assert out.loss_rate_ewma == 1.0
    cache.update(call_id="c1", loss_rate=-0.5)  # below 0.0
    out2 = cache.overlay(_empty_vitals("c1"))
    assert out2.loss_rate_ewma == 0.0


def test_browser_metrics_cache_clamps_confirm_ratio() -> None:
    cache = BrowserMetricsCache()
    cache.update(call_id="c1", confirm_ratio_voice=1.7)
    out = cache.overlay(_empty_vitals("c1"))
    assert out.confirm_ratio_voice == 1.0


def test_browser_metrics_cache_empty_returns_original() -> None:
    cache = BrowserMetricsCache()
    v = _empty_vitals("c1")
    out = cache.overlay(v)
    assert out is v


def test_browser_metrics_clear_call_drops_entries() -> None:
    cache = BrowserMetricsCache()
    cache.update(call_id="c1", rtt_ms=100.0)
    cache.clear_call("c1")
    out = cache.overlay(_empty_vitals("c1"))
    assert out.rtt_ewma_ms == 50.0  # original


def test_browser_metrics_independent_per_call() -> None:
    cache = BrowserMetricsCache()
    cache.update(call_id="c1", rtt_ms=200.0)
    cache.update(call_id="c2", rtt_ms=400.0)
    assert cache.overlay(_empty_vitals("c1")).rtt_ewma_ms == 200.0
    assert cache.overlay(_empty_vitals("c2")).rtt_ewma_ms == 400.0


# ---------------------------------------------------------------------------
# AuditLogger
# ---------------------------------------------------------------------------

def test_audit_logger_appends_decisions(tmp_path: Path) -> None:
    audit = AuditLogger(path=tmp_path / "audit.jsonl")
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    decision = immune.tick(_empty_vitals())
    audit.append(decision)

    recent = audit.read_recent(n=10)
    assert len(recent) == 1
    assert "action_name" in recent[0]
    assert isinstance(recent[0]["vitals_hash"], str)


def test_audit_logger_rotates_when_oversize(tmp_path: Path) -> None:
    audit = AuditLogger(
        path=tmp_path / "audit.jsonl", max_bytes=512, max_files=4,
    )
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    for _ in range(50):
        decision = immune.tick(_empty_vitals())
        audit.append(decision)
    # The active file plus rotations exist.
    files = list(tmp_path.glob("audit.jsonl*"))
    assert len(files) >= 2


def test_audit_logger_caps_rotation_count(tmp_path: Path) -> None:
    audit = AuditLogger(
        path=tmp_path / "audit.jsonl", max_bytes=128, max_files=3,
    )
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    for _ in range(200):
        audit.append(immune.tick(_empty_vitals()))
    rotations = [
        p for p in tmp_path.glob("audit.jsonl*")
        if str(p).endswith("audit.jsonl") is False
    ]
    # Bounded to ~max_files rotations.
    assert len(rotations) <= 3 + 1  # 3 + active file slack


def test_audit_logger_read_recent_returns_last_n(tmp_path: Path) -> None:
    audit = AuditLogger(path=tmp_path / "audit.jsonl")
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    for i in range(20):
        audit.append(immune.tick(_empty_vitals()))
    last5 = audit.read_recent(n=5)
    assert len(last5) == 5


def test_audit_logger_read_recent_returns_empty_when_no_file(
    tmp_path: Path,
) -> None:
    audit = AuditLogger(path=tmp_path / "never.jsonl")
    assert audit.read_recent(n=10) == []


# ---------------------------------------------------------------------------
# drive_immune_tick_for_call
# ---------------------------------------------------------------------------

def test_drive_immune_tick_emits_decision(tmp_path: Path) -> None:
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    metrics = BrowserMetricsCache()
    counter = _TickCounter()
    audit = AuditLogger(path=tmp_path / "audit.jsonl")
    daemon = _FakeDaemon(peer_fp="peer-fp-hex")

    decision = drive_immune_tick_for_call(
        daemon=daemon, immune=immune, metrics=metrics,
        tick_counter=counter, audit=audit,
        call_id="c1", peer_master_vk_hex="peer-fp-hex",
    )
    assert decision is not None
    # SHADOW mode → emitted=False
    assert decision.emitted is False
    # Audit log has the entry
    assert len(audit.read_recent(n=10)) == 1


def test_drive_immune_tick_uses_browser_metrics(tmp_path: Path) -> None:
    """When the browser reports high loss, the Immune System sees
    it (overlay) and the decision reflects it."""
    immune = ImmuneSystem(
        mode=GraduationMode.AUTOPILOT,
        thresholds=Thresholds(),
    )
    metrics = BrowserMetricsCache()
    metrics.update(call_id="c1", loss_rate=0.15, rtt_ms=350.0)
    counter = _TickCounter()
    daemon = _FakeDaemon(peer_fp="peer-fp")

    decision = drive_immune_tick_for_call(
        daemon=daemon, immune=immune, metrics=metrics,
        tick_counter=counter, audit=None,
        call_id="c1", peer_master_vk_hex="peer-fp",
    )
    # With loss 15% + RTT 350ms, the transport controller should
    # have raised SOMETHING (lower-fidelity or async). It's not HOLD.
    assert decision.action != ImmuneAction.HOLD


def test_drive_immune_tick_advances_tick_counter(tmp_path: Path) -> None:
    immune = ImmuneSystem(mode=GraduationMode.SHADOW)
    metrics = BrowserMetricsCache()
    counter = _TickCounter()
    daemon = _FakeDaemon(peer_fp="peer-fp")

    d1 = drive_immune_tick_for_call(
        daemon=daemon, immune=immune, metrics=metrics,
        tick_counter=counter, audit=None,
        call_id="c1", peer_master_vk_hex="peer-fp",
    )
    d2 = drive_immune_tick_for_call(
        daemon=daemon, immune=immune, metrics=metrics,
        tick_counter=counter, audit=None,
        call_id="c1", peer_master_vk_hex="peer-fp",
    )
    assert d1.tick == 0
    assert d2.tick == 1
