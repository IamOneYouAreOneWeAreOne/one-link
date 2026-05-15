"""CallVitals — pure read-only view over daemon state.

The Immune System (Tier γ SHADOW → ASSIST → AUTOPILOT) ticks every
100 ms. On each tick it reads a :class:`CallVitals` snapshot and
emits a :class:`ImmuneDecision`. The Arbitrator + soak-replay both
require this read to be **pure** (no I/O, no async, no hidden
state) so the same vitals deterministically yield the same
decision.

This module is the ground-truth composer. It reads existing daemon
state — ``_pair_health``, ``_relay_metrics``, the ``ProvenanceStore``,
``ol_routing`` / ``ol_homology`` scores when available, the linked-
mesh device list — and packs the result into a frozen dataclass.

Tier α-pre fills the fields it can today (transport health, trust
state) and uses sentinel zero values for fields whose substrate is
still under construction (real-time media frame counters, device
thermal/battery — Tier β+).

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.1
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional, Protocol

from one_link.frame_provenance import PathClass


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class DeviceRole(IntEnum):
    """The role this device plays in the call, per the
    Multi-Device Body Engine. INACTIVE means the call is not using
    this device's hardware."""

    MIC      = 0
    CAM      = 1
    DISPLAY  = 2
    SPEAKER  = 3
    RELAY    = 4
    HELPER   = 5
    INACTIVE = 6


class ThermalState(IntEnum):
    """Coarse thermal classification surfaced by the OS. The Body
    Engine prefers cooler devices when deciding which surface holds
    a role."""

    NOMINAL  = 0
    WARM     = 1
    HOT      = 2
    CRITICAL = 3


# ---------------------------------------------------------------------------
# Capability snapshot
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilitySnapshot:
    """Subset of the peer's advertised capabilities the Immune System
    cares about. Frozen so hashes are stable across ticks."""

    semantic_media_v1: bool
    predictive_continuity_v1: bool
    frame_provenance_v1: bool
    onefield_radio_v1: bool
    confidential_tier: int  # 0=software, 1=TPM, 2=SGX/SEV, 3=Secure Enclave
    model_pack_hash: Optional[str]

    @classmethod
    def empty(cls) -> "CapabilitySnapshot":
        return cls(
            semantic_media_v1=False,
            predictive_continuity_v1=False,
            frame_provenance_v1=False,
            onefield_radio_v1=False,
            confidential_tier=0,
            model_pack_hash=None,
        )


# ---------------------------------------------------------------------------
# The CallVitals snapshot
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CallVitals:
    """Snapshot of all health signals at a single tick.

    Pure read; composes from existing daemon state. Hashable for
    soak-replay determinism (the Arbitrator's vitals_hash field
    closes over this).
    """

    # Identity
    call_id: str
    peer_fp: str
    tick: int

    # Transport health (from _pair_health + _relay_metrics)
    rtt_ewma_ms: float
    loss_rate_ewma: float           # 0.0..1.0
    jitter_ms: float                # frame-arrival std-dev
    bandwidth_estimate_kbps: float
    reliability: float              # 0.0..1.0, from _pair_health
    last_alive_ms: int              # 0 if never seen

    # Path topology (from ol_routing + ol_homology)
    path_class: PathClass
    path_fragility_score: float     # 0=robust 1=critical
    backup_routes_warm: int

    # Device state (from linked-mesh)
    own_device_role: DeviceRole
    own_battery_pct: Optional[float]
    own_thermal_state: ThermalState
    peer_device_present: bool

    # Media health (from in-call instrumentation; Tier β+ fills these)
    audio_frames_received: int
    audio_frames_dropped: int
    video_frames_received: int
    video_frames_predicted: int
    confirm_ratio_voice: float      # 1.0 when no media yet
    confirm_ratio_video: float

    # Trust state (from attestation + ProvenanceStore)
    path_attested: bool
    capability_state: CapabilitySnapshot

    def vitals_hash(self) -> str:
        """Stable BLAKE2b digest of all fields. The Arbitrator embeds
        this in every ImmuneDecision so soak-replay can verify
        determinism: same vitals → same decision, byte-equal."""
        h = hashlib.blake2b(digest_size=16)
        h.update(self.call_id.encode("utf-8"))
        h.update(self.peer_fp.encode("utf-8"))
        h.update(self.tick.to_bytes(8, "big", signed=False))
        # Floats: round to 6 decimals so trivial FP jitter doesn't
        # destabilise the hash. Underflow at 1e-6 is well below any
        # threshold the Immune System cares about.
        def f6(x: float) -> bytes:
            return f"{x:.6f}".encode("ascii")
        h.update(f6(self.rtt_ewma_ms))
        h.update(f6(self.loss_rate_ewma))
        h.update(f6(self.jitter_ms))
        h.update(f6(self.bandwidth_estimate_kbps))
        h.update(f6(self.reliability))
        h.update(self.last_alive_ms.to_bytes(8, "big", signed=False))
        h.update(bytes([int(self.path_class)]))
        h.update(f6(self.path_fragility_score))
        h.update(self.backup_routes_warm.to_bytes(4, "big", signed=False))
        h.update(bytes([int(self.own_device_role)]))
        h.update(f6(self.own_battery_pct if self.own_battery_pct is not None else -1.0))
        h.update(bytes([int(self.own_thermal_state)]))
        h.update(bytes([1 if self.peer_device_present else 0]))
        h.update(self.audio_frames_received.to_bytes(8, "big", signed=False))
        h.update(self.audio_frames_dropped.to_bytes(8, "big", signed=False))
        h.update(self.video_frames_received.to_bytes(8, "big", signed=False))
        h.update(self.video_frames_predicted.to_bytes(8, "big", signed=False))
        h.update(f6(self.confirm_ratio_voice))
        h.update(f6(self.confirm_ratio_video))
        h.update(bytes([1 if self.path_attested else 0]))
        cs = self.capability_state
        h.update(bytes([
            1 if cs.semantic_media_v1 else 0,
            1 if cs.predictive_continuity_v1 else 0,
            1 if cs.frame_provenance_v1 else 0,
            1 if cs.onefield_radio_v1 else 0,
            cs.confidential_tier & 0xff,
        ]))
        if cs.model_pack_hash is not None:
            h.update(cs.model_pack_hash.encode("ascii", errors="replace"))
        return h.hexdigest()


# ---------------------------------------------------------------------------
# Composers — pure functions for tests
# ---------------------------------------------------------------------------

class _DaemonLike(Protocol):
    """Structural type so this module doesn't import the full
    Daemon class (avoids a cycle + lets tests pass any object with
    the right shape)."""

    _pair_health: dict[str, Any]
    _relay_metrics: dict[str, Any]


def _peer_caps_features(daemon: _DaemonLike, peer_fp: str) -> list[str]:
    """Best-effort extraction of the peer's advertised capability
    list from whatever the daemon has cached. Returns [] on any
    missing structure — never raises."""
    try:
        # The daemon caches caps on each Channel via channel.peer_caps.
        # We don't have a direct peer_fp → channel lookup here without
        # importing the full state, so we look it up via outbound
        # session if available. Returns empty list on miss.
        sessions = getattr(daemon, "_outbound_sessions", {})
        sess = sessions.get(peer_fp) if isinstance(sessions, dict) else None
        if sess is None:
            return []
        channel = getattr(sess, "channel", None)
        if channel is None:
            return []
        caps = getattr(channel, "peer_caps", None) or {}
        return list(caps.get("features") or [])
    except Exception:
        return []


def _capability_snapshot(
    features: list[str],
    *,
    confidential_tier: int = 0,
    model_pack_hash: Optional[str] = None,
) -> CapabilitySnapshot:
    fs = set(features)
    return CapabilitySnapshot(
        semantic_media_v1=("semantic_media_v1" in fs),
        predictive_continuity_v1=("predictive_continuity_v1" in fs),
        frame_provenance_v1=("frame_provenance_v1" in fs),
        onefield_radio_v1=("onefield_radio_v1" in fs),
        confidential_tier=int(confidential_tier),
        model_pack_hash=model_pack_hash,
    )


def read_call_vitals(
    daemon: _DaemonLike,
    *,
    peer_fp: str,
    tick: int,
    call_id: str = "",
) -> CallVitals:
    """Compose a :class:`CallVitals` from current daemon state.

    Pure read. Returns zero/sentinel values for fields whose
    substrate is not yet wired (Tier β+ media stats, device thermal/
    battery sensors).

    Never raises on missing state — every field has a defined zero
    behaviour so the Immune System can tick from the very first
    handshake, before any peer health data has accumulated.
    """
    ph = (getattr(daemon, "_pair_health", {}) or {}).get(peer_fp) or {}
    # _pair_health uses TypedDict; access via dict-get with defaults.
    rtt = float(ph.get("latency_ewma_ms") or 0.0)
    reliability = float(ph.get("reliability") or 0.0)
    bw_bps = float(ph.get("bandwidth_bps") or 0.0)
    bw_kbps = bw_bps / 1000.0
    last_alive_ms = int(ph.get("last_alive_ms") or 0)
    # Loss rate isn't tracked in _pair_health today (Tier α only
    # sees PING liveness). The relay-level metric is the closest
    # proxy; fall back to 0.0 when unknown.
    relay_metrics = getattr(daemon, "_relay_metrics", {}) or {}
    best_route = str(ph.get("best_route") or "")
    relay = relay_metrics.get(best_route) if best_route else None
    if isinstance(relay, dict):
        loss = float(relay.get("loss_rate_ewma") or 0.0)
        if not bw_kbps:
            bw_kbps = float(relay.get("bandwidth_kbps") or 0.0)
    else:
        loss = 0.0

    # Path class: we infer a coarse value from best_route. A relay
    # path means RELAY; otherwise we assume DIRECT for paired peers.
    # ol_routing exposes finer detail; reading it requires the
    # native crate's score map, which lives off the daemon as
    # routing_native — we attempt that read, but Tier α-pre falls
    # back to the heuristic.
    path_class = PathClass.RELAY if relay else PathClass.DIRECT
    fragility = 0.0  # ol_homology score; Tier β reads via routing_native

    features = _peer_caps_features(daemon, peer_fp)
    cap_state = _capability_snapshot(features)

    # `path_attested` is true when the peer holds an attestation
    # heartbeat (Row 10). Tier α-pre defaults to False.
    path_attested = False

    return CallVitals(
        call_id=call_id,
        peer_fp=peer_fp,
        tick=int(tick),
        rtt_ewma_ms=rtt,
        loss_rate_ewma=loss,
        jitter_ms=0.0,                # Tier β+ media instrumentation
        bandwidth_estimate_kbps=bw_kbps,
        reliability=reliability,
        last_alive_ms=last_alive_ms,
        path_class=path_class,
        path_fragility_score=fragility,
        backup_routes_warm=0,         # Tier ε+ Route Brain
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=None,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=(last_alive_ms > 0),
        audio_frames_received=0,
        audio_frames_dropped=0,
        video_frames_received=0,
        video_frames_predicted=0,
        confirm_ratio_voice=1.0,      # no media yet = trivially confirmed
        confirm_ratio_video=1.0,
        path_attested=path_attested,
        capability_state=cap_state,
    )


# ---------------------------------------------------------------------------
# Plain-language UI labels (Doctrine §3.6.c, §3.9.a)
# ---------------------------------------------------------------------------

def device_role_label(r: DeviceRole) -> str:
    return {
        DeviceRole.MIC:      "Mic",
        DeviceRole.CAM:      "Camera",
        DeviceRole.DISPLAY:  "Display",
        DeviceRole.SPEAKER:  "Speaker",
        DeviceRole.RELAY:    "Relay",
        DeviceRole.HELPER:   "Helper",
        DeviceRole.INACTIVE: "Idle",
    }[r]


def thermal_label(t: ThermalState) -> str:
    return {
        ThermalState.NOMINAL:  "Cool",
        ThermalState.WARM:     "Warm",
        ThermalState.HOT:      "Hot",
        ThermalState.CRITICAL: "Very hot",
    }[t]
