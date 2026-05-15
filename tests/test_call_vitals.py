"""Tests for CallVitals — pure read over daemon state.

Covers:
    - Default snapshot for a daemon with no state
    - Composes RTT / reliability / bandwidth from _pair_health
    - Composes loss / bandwidth from _relay_metrics best_route
    - PathClass inference (RELAY when best_route is in relay_metrics, DIRECT otherwise)
    - peer_device_present = (last_alive_ms > 0)
    - CapabilitySnapshot composition from outbound session's channel.peer_caps
    - vitals_hash determinism: same inputs → same digest
    - vitals_hash separates on every signed field (tamper detection)
    - Plain-language UI labels never leak doctrine-forbidden tokens
"""

from __future__ import annotations

import pytest

from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
    _capability_snapshot,
    device_role_label,
    read_call_vitals,
    thermal_label,
)
from one_link.frame_provenance import PathClass


# ---------------------------------------------------------------------------
# Fake daemon objects
# ---------------------------------------------------------------------------

class _FakeChannel:
    def __init__(self, features: list[str]) -> None:
        self.peer_caps = {"features": features}


class _FakeSession:
    def __init__(self, features: list[str]) -> None:
        self.channel = _FakeChannel(features)


class _FakeDaemon:
    def __init__(
        self,
        *,
        pair_health: dict | None = None,
        relay_metrics: dict | None = None,
        outbound_sessions: dict | None = None,
    ) -> None:
        self._pair_health = pair_health or {}
        self._relay_metrics = relay_metrics or {}
        self._outbound_sessions = outbound_sessions or {}


# ---------------------------------------------------------------------------
# Default / empty-state behaviour
# ---------------------------------------------------------------------------

def test_empty_daemon_yields_defaults() -> None:
    """A freshly-constructed daemon with no peer state yields a
    well-defined zero snapshot — every field has a value, no
    exceptions."""
    d = _FakeDaemon()
    v = read_call_vitals(d, peer_fp="abc123", tick=0)
    assert v.peer_fp == "abc123"
    assert v.tick == 0
    assert v.rtt_ewma_ms == 0.0
    assert v.loss_rate_ewma == 0.0
    assert v.jitter_ms == 0.0
    assert v.bandwidth_estimate_kbps == 0.0
    assert v.reliability == 0.0
    assert v.last_alive_ms == 0
    assert v.path_class == PathClass.DIRECT
    assert v.path_fragility_score == 0.0
    assert v.backup_routes_warm == 0
    assert v.own_device_role == DeviceRole.INACTIVE
    assert v.own_battery_pct is None
    assert v.own_thermal_state == ThermalState.NOMINAL
    assert v.peer_device_present is False
    assert v.audio_frames_received == 0
    assert v.confirm_ratio_voice == 1.0
    assert v.confirm_ratio_video == 1.0
    assert v.path_attested is False
    assert v.capability_state == CapabilitySnapshot.empty()


# ---------------------------------------------------------------------------
# Transport health composition
# ---------------------------------------------------------------------------

def test_pair_health_composition() -> None:
    d = _FakeDaemon(pair_health={
        "peer-abc": {
            "last_alive_ms": 1_700_000_000_000,
            "latency_ewma_ms": 73.4,
            "bandwidth_bps": 1_500_000,   # 1500 kbps
            "reliability": 0.92,
            "best_route": "",  # no relay
        }
    })
    v = read_call_vitals(d, peer_fp="peer-abc", tick=5)
    assert v.rtt_ewma_ms == pytest.approx(73.4)
    assert v.reliability == pytest.approx(0.92)
    assert v.bandwidth_estimate_kbps == pytest.approx(1500.0)
    assert v.last_alive_ms == 1_700_000_000_000
    assert v.peer_device_present is True
    # No best_route in relay_metrics → DIRECT.
    assert v.path_class == PathClass.DIRECT


def test_pair_health_missing_for_peer() -> None:
    """A peer the daemon has never heard from yields zero state."""
    d = _FakeDaemon(pair_health={"someone-else": {"latency_ewma_ms": 100.0}})
    v = read_call_vitals(d, peer_fp="unknown-peer", tick=0)
    assert v.rtt_ewma_ms == 0.0
    assert v.last_alive_ms == 0
    assert v.peer_device_present is False


def test_partial_pair_health_uses_zero_defaults() -> None:
    """_PairHealth is TypedDict total=False; fields are populated
    incrementally. Missing keys must yield zero defaults, not
    KeyError."""
    d = _FakeDaemon(pair_health={"peer-x": {"last_alive_ms": 12345}})
    v = read_call_vitals(d, peer_fp="peer-x", tick=0)
    assert v.last_alive_ms == 12345
    assert v.rtt_ewma_ms == 0.0
    assert v.reliability == 0.0
    assert v.bandwidth_estimate_kbps == 0.0
    assert v.peer_device_present is True


# ---------------------------------------------------------------------------
# Path topology (relay inference)
# ---------------------------------------------------------------------------

def test_relay_path_class_when_best_route_is_relay() -> None:
    d = _FakeDaemon(
        pair_health={
            "peer-y": {
                "last_alive_ms": 1,
                "best_route": "relay-east-1",
            }
        },
        relay_metrics={
            "relay-east-1": {
                "loss_rate_ewma": 0.07,
                "rtt_ewma_ms": 220.0,
                "bandwidth_kbps": 600.0,
            }
        },
    )
    v = read_call_vitals(d, peer_fp="peer-y", tick=0)
    assert v.path_class == PathClass.RELAY
    assert v.loss_rate_ewma == pytest.approx(0.07)
    assert v.bandwidth_estimate_kbps == pytest.approx(600.0)


def test_relay_path_falls_back_to_direct_when_relay_unknown() -> None:
    """best_route names a relay we have no metrics for. The path
    class falls back to DIRECT rather than fabricating loss data."""
    d = _FakeDaemon(
        pair_health={"peer-z": {"best_route": "ghost-relay"}},
        relay_metrics={},
    )
    v = read_call_vitals(d, peer_fp="peer-z", tick=0)
    assert v.path_class == PathClass.DIRECT
    assert v.loss_rate_ewma == 0.0


# ---------------------------------------------------------------------------
# Capability snapshot composition
# ---------------------------------------------------------------------------

def test_capability_snapshot_from_features() -> None:
    d = _FakeDaemon(
        outbound_sessions={
            "peer-q": _FakeSession([
                "frame_provenance_v1",
                "semantic_media_v1",
                "chat",
                "files",
            ]),
        },
    )
    v = read_call_vitals(d, peer_fp="peer-q", tick=0)
    assert v.capability_state.frame_provenance_v1 is True
    assert v.capability_state.semantic_media_v1 is True
    assert v.capability_state.predictive_continuity_v1 is False
    assert v.capability_state.onefield_radio_v1 is False


def test_capability_snapshot_empty_when_session_missing() -> None:
    d = _FakeDaemon()
    v = read_call_vitals(d, peer_fp="never-connected", tick=0)
    assert v.capability_state == CapabilitySnapshot.empty()


def test_capability_snapshot_when_session_has_no_caps() -> None:
    """An outbound session exists but the peer hasn't completed
    CAPS handshake yet. capability_state must be empty, not
    None / not crashing."""
    session = _FakeSession([])
    session.channel.peer_caps = None  # not yet received
    d = _FakeDaemon(outbound_sessions={"peer-r": session})
    v = read_call_vitals(d, peer_fp="peer-r", tick=0)
    assert v.capability_state == CapabilitySnapshot.empty()


def test_capability_snapshot_helper_direct() -> None:
    snap = _capability_snapshot(
        ["frame_provenance_v1", "predictive_continuity_v1"],
        confidential_tier=2,
        model_pack_hash="blake3:abc",
    )
    assert snap.frame_provenance_v1 is True
    assert snap.predictive_continuity_v1 is True
    assert snap.confidential_tier == 2
    assert snap.model_pack_hash == "blake3:abc"


# ---------------------------------------------------------------------------
# vitals_hash — soak-replay determinism
# ---------------------------------------------------------------------------

def _make_vitals(**over: object) -> CallVitals:
    base: dict[str, object] = dict(
        call_id="call-0",
        peer_fp="peer-fp-0",
        tick=0,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=0.0,
        bandwidth_estimate_kbps=1000.0,
        reliability=1.0,
        last_alive_ms=1_700_000_000_000,
        path_class=PathClass.DIRECT,
        path_fragility_score=0.0,
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
    base.update(over)
    return CallVitals(**base)  # type: ignore[arg-type]


def test_vitals_hash_deterministic() -> None:
    a = _make_vitals()
    b = _make_vitals()
    assert a.vitals_hash() == b.vitals_hash()


def test_vitals_hash_changes_on_every_signed_field() -> None:
    """A hash collision on a tick-relevant field would mean the
    Arbitrator emits identical decisions for different conditions —
    that breaks soak replay. Every primary field must move the hash."""
    base_hash = _make_vitals().vitals_hash()
    mutations = [
        {"call_id": "call-1"},
        {"peer_fp": "different-peer"},
        {"tick": 1},
        {"rtt_ewma_ms": 51.0},
        {"loss_rate_ewma": 0.01},
        {"jitter_ms": 1.0},
        {"bandwidth_estimate_kbps": 999.0},
        {"reliability": 0.99},
        {"last_alive_ms": 0},
        {"path_class": PathClass.RELAY},
        {"path_fragility_score": 0.5},
        {"backup_routes_warm": 1},
        {"own_device_role": DeviceRole.MIC},
        {"own_battery_pct": 50.0},
        {"own_thermal_state": ThermalState.WARM},
        {"peer_device_present": False},
        {"audio_frames_received": 1},
        {"audio_frames_dropped": 1},
        {"video_frames_received": 1},
        {"video_frames_predicted": 1},
        {"confirm_ratio_voice": 0.99},
        {"confirm_ratio_video": 0.99},
        {"path_attested": True},
        {"capability_state": _capability_snapshot(["frame_provenance_v1"])},
    ]
    seen: set[str] = {base_hash}
    for kw in mutations:
        h = _make_vitals(**kw).vitals_hash()
        assert h != base_hash, f"hash unchanged for mutation {kw}"
        seen.add(h)
    # Sanity: not just every mutation differs from base, but most
    # also differ from each other.
    assert len(seen) >= len(mutations), (
        "hash collisions detected between mutations"
    )


def test_vitals_hash_stable_under_trivial_fp_jitter() -> None:
    """Floats are rounded to 6 decimals before hashing so a
    1e-9 jitter in EWMA values doesn't destabilise the hash.
    Mathematically irrelevant noise should not flap decisions."""
    a = _make_vitals(rtt_ewma_ms=50.0000001)
    b = _make_vitals(rtt_ewma_ms=50.0000002)
    assert a.vitals_hash() == b.vitals_hash()


# ---------------------------------------------------------------------------
# UI labels — doctrine compliance
# ---------------------------------------------------------------------------

_FORBIDDEN_UI_TOKENS = (
    "wi-fi", "wifi", "cellular", "5g", "4g", "lte",
    "hex", "blake3", "ratchet",
)


def test_device_role_labels_plain_language() -> None:
    for r in DeviceRole:
        label = device_role_label(r).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, (
                f"device_role_label({r.name}) leaks {tok!r}: {label!r}"
            )


def test_thermal_labels_plain_language() -> None:
    for t in ThermalState:
        label = thermal_label(t).lower()
        for tok in _FORBIDDEN_UI_TOKENS:
            assert tok not in label, f"thermal_label({t.name}) leaks {tok!r}: {label!r}"


# ---------------------------------------------------------------------------
# Defensive: bad daemon types don't crash
# ---------------------------------------------------------------------------

def test_daemon_missing_attributes_is_safe() -> None:
    """If a caller passes an object lacking ``_pair_health`` or
    ``_relay_metrics``, read_call_vitals returns a sensible
    zero snapshot rather than AttributeError. This protects the
    Immune System tick loop from crashing during daemon startup
    races."""
    class _Bare:
        pass
    v = read_call_vitals(_Bare(), peer_fp="x", tick=0)  # type: ignore[arg-type]
    assert v.rtt_ewma_ms == 0.0
    assert v.path_class == PathClass.DIRECT


def test_daemon_outbound_sessions_malformed_is_safe() -> None:
    """An outbound_sessions value of the wrong shape (e.g., a list
    instead of a dict) must not crash the cap snapshot extraction."""
    class _Weird:
        _pair_health = {}
        _relay_metrics = {}
        _outbound_sessions = ["not", "a", "dict"]
    v = read_call_vitals(_Weird(), peer_fp="x", tick=0)  # type: ignore[arg-type]
    assert v.capability_state == CapabilitySnapshot.empty()
