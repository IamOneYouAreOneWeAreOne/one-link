"""Tests for the Multi-Device Body Engine.

Covers:
    - score_device_for_role: fundamentally unable → 0, basic ordering
    - thermal, battery, network, recency penalties
    - Single device: gets every role it's capable of
    - Two devices: better-scored wins
    - Handoff margin: small improvements don't force flicker
    - Hot phone yields mic to laptop
    - Display picked by screen-area, not by anything else
    - Add/remove device round-trip with OR-set add-wins
    - Determinism: two arbitrators against same state → same result
    - Cross-device convergence: device A and device B both arrive at
      the same ParticipantState after each compute the merged view
    - Initial assignment fires SurfaceHandoff with from=None
    - Stable state: no spurious handoffs when nothing changed
"""

from __future__ import annotations

import pytest

from one_link.body_engine import (
    BodyEngine,
    DeviceCapability,
    ScoringWeights,
    SurfaceHandoff,
    score_device_for_role,
)
from one_link.call_session import ParticipantState
from one_link.call_vitals import DeviceRole, ThermalState
from one_link.frame_provenance import PathClass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = 1_700_000_000_000


def _phone(**over) -> DeviceCapability:
    base = dict(
        device_id="phone001",
        has_mic=True, has_cam=True, has_display=True, has_speaker=True,
        can_relay=False,
        mic_quality=0.85,           # phones tend to have good mic arrays
        cam_quality=0.80,
        display_size_px_area=1_500_000,
        speaker_quality=0.50,
        is_battery_powered=True,
        battery_pct=80.0,
        is_charging=False,
        thermal_state=ThermalState.NOMINAL,
        network_class=PathClass.LAN,
        alive_at_ms=NOW,
    )
    base.update(over)
    return DeviceCapability(**base)


def _laptop(**over) -> DeviceCapability:
    base = dict(
        device_id="laptop01",
        has_mic=True, has_cam=True, has_display=True, has_speaker=True,
        can_relay=True,
        mic_quality=0.60,
        cam_quality=0.70,
        display_size_px_area=2_073_600,   # 1920x1080
        speaker_quality=0.65,
        is_battery_powered=True,
        battery_pct=95.0,
        is_charging=True,
        thermal_state=ThermalState.NOMINAL,
        network_class=PathClass.LAN,
        alive_at_ms=NOW,
    )
    base.update(over)
    return DeviceCapability(**base)


def _tv(**over) -> DeviceCapability:
    base = dict(
        device_id="tv000001",
        has_mic=False, has_cam=False, has_display=True, has_speaker=True,
        can_relay=False,
        mic_quality=0.0,
        cam_quality=0.0,
        display_size_px_area=8_294_400,   # 4K
        speaker_quality=0.80,
        is_battery_powered=False,
        battery_pct=None,
        is_charging=None,
        thermal_state=ThermalState.NOMINAL,
        network_class=PathClass.LAN,
        alive_at_ms=NOW,
    )
    base.update(over)
    return DeviceCapability(**base)


def _empty_state() -> ParticipantState:
    return ParticipantState(master_vk=b"alice-vk")


# ---------------------------------------------------------------------------
# Scoring primitives
# ---------------------------------------------------------------------------

def test_no_mic_scores_zero_for_mic_role() -> None:
    tv = _tv()
    assert score_device_for_role(tv, DeviceRole.MIC, now_ms=NOW) == 0.0


def test_no_cam_scores_zero_for_cam_role() -> None:
    tv = _tv()
    assert score_device_for_role(tv, DeviceRole.CAM, now_ms=NOW) == 0.0


def test_phone_beats_laptop_on_mic_quality() -> None:
    phone = _phone()
    laptop = _laptop()
    phone_score = score_device_for_role(phone, DeviceRole.MIC, now_ms=NOW)
    laptop_score = score_device_for_role(laptop, DeviceRole.MIC, now_ms=NOW)
    assert phone_score > laptop_score


def test_laptop_beats_phone_on_display_size() -> None:
    phone = _phone()
    laptop = _laptop()
    assert score_device_for_role(laptop, DeviceRole.DISPLAY, now_ms=NOW) > \
           score_device_for_role(phone, DeviceRole.DISPLAY, now_ms=NOW)


def test_hot_phone_score_drops() -> None:
    cool = _phone(thermal_state=ThermalState.NOMINAL)
    hot = _phone(thermal_state=ThermalState.HOT)
    assert score_device_for_role(cool, DeviceRole.MIC, now_ms=NOW) > \
           score_device_for_role(hot, DeviceRole.MIC, now_ms=NOW)


def test_critical_battery_drops_score() -> None:
    full = _phone(battery_pct=90.0, is_charging=False)
    dying = _phone(battery_pct=5.0, is_charging=False)
    assert score_device_for_role(full, DeviceRole.MIC, now_ms=NOW) > \
           score_device_for_role(dying, DeviceRole.MIC, now_ms=NOW)


def test_charging_negates_battery_penalty() -> None:
    """A plugged-in phone scores like a desktop — battery isn't a
    factor."""
    discharging = _phone(battery_pct=5.0, is_charging=False)
    charging = _phone(battery_pct=5.0, is_charging=True)
    assert score_device_for_role(charging, DeviceRole.MIC, now_ms=NOW) > \
           score_device_for_role(discharging, DeviceRole.MIC, now_ms=NOW)


def test_stale_device_recency_zero() -> None:
    """Device that hasn't heartbeated in 30+ seconds gets recency 0."""
    stale = _phone(alive_at_ms=NOW - 60_000)
    fresh = _phone(alive_at_ms=NOW)
    assert score_device_for_role(fresh, DeviceRole.MIC, now_ms=NOW) > \
           score_device_for_role(stale, DeviceRole.MIC, now_ms=NOW)


def test_never_alive_device_recency_zero() -> None:
    """alive_at_ms=0 means we've never heard from this device."""
    never = _phone(alive_at_ms=0)
    s = score_device_for_role(never, DeviceRole.MIC, now_ms=NOW)
    # Score is non-zero (other factors > 0) but reduced.
    assert s < score_device_for_role(_phone(), DeviceRole.MIC, now_ms=NOW)


# ---------------------------------------------------------------------------
# Arbitration: single device
# ---------------------------------------------------------------------------

def test_single_device_gets_every_capable_role() -> None:
    eng = BodyEngine()
    devices = {"phone001": _phone()}
    new_state, handoffs = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_mic.value == "phone001"
    assert new_state.primary_cam.value == "phone001"
    assert new_state.primary_display.value == "phone001"
    assert new_state.primary_speaker.value == "phone001"
    # No relay — phone says can_relay=False
    assert new_state.preferred_relay.value is None
    # Four roles initially-assigned = four handoffs with from=None
    assert len(handoffs) == 4
    for h in handoffs:
        assert h.from_device_id is None
        assert h.to_device_id == "phone001"


def test_tv_only_gets_display_and_speaker() -> None:
    eng = BodyEngine()
    devices = {"tv000001": _tv()}
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_mic.value is None  # no mic
    assert new_state.primary_cam.value is None
    assert new_state.primary_display.value == "tv000001"
    assert new_state.primary_speaker.value == "tv000001"


# ---------------------------------------------------------------------------
# Arbitration: two devices
# ---------------------------------------------------------------------------

def test_phone_wins_mic_against_laptop() -> None:
    eng = BodyEngine()
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_mic.value == "phone001"


def test_laptop_wins_display_against_phone() -> None:
    eng = BodyEngine()
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_display.value == "laptop01"


def test_only_laptop_can_relay() -> None:
    eng = BodyEngine()
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.preferred_relay.value == "laptop01"


# ---------------------------------------------------------------------------
# Hot-phone handoff
# ---------------------------------------------------------------------------

def test_hot_phone_yields_mic_to_laptop() -> None:
    """Phone normally wins mic. When it gets HOT, laptop overtakes."""
    eng = BodyEngine()
    devices = {
        "phone001": _phone(thermal_state=ThermalState.HOT),
        "laptop01": _laptop(),
    }
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_mic.value == "laptop01"


def test_critical_phone_yields_to_laptop_for_everything() -> None:
    eng = BodyEngine()
    devices = {
        "phone001": _phone(thermal_state=ThermalState.CRITICAL),
        "laptop01": _laptop(),
    }
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    # Phone is unusable; laptop should hold every role it can do.
    assert new_state.primary_mic.value == "laptop01"
    assert new_state.primary_cam.value == "laptop01"
    assert new_state.primary_display.value == "laptop01"
    assert new_state.primary_speaker.value == "laptop01"


# ---------------------------------------------------------------------------
# Handoff margin: prevent flicker
# ---------------------------------------------------------------------------

def test_small_improvement_does_not_trigger_handoff() -> None:
    """The current holder must lose by at least the handoff margin
    before being replaced — otherwise two near-equal devices ping
    back and forth on noise.

    To isolate the mic_quality comparison we charge the phone too,
    so the only differing factor is the mic-quality input."""
    eng = BodyEngine(handoff_margin=0.10)
    state = _empty_state()
    # Initial: phone wins mic by 0.10 quality margin
    devices1 = {
        "phone001": _phone(mic_quality=0.85, is_charging=True),
        "laptop01": _laptop(mic_quality=0.65),
    }
    state, _ = eng.arbitrate(devices=devices1, state=state, now_ms=NOW)
    assert state.primary_mic.value == "phone001"
    # Flip slightly: laptop now better but only marginally
    devices2 = {
        "phone001": _phone(mic_quality=0.65, is_charging=True),
        "laptop01": _laptop(mic_quality=0.68),
    }
    state2, handoffs = eng.arbitrate(devices=devices2, state=state, now_ms=NOW + 1)
    # Margin not met → no handoff
    assert state2.primary_mic.value == "phone001"
    assert not any(h.role == DeviceRole.MIC for h in handoffs)


def test_large_improvement_does_trigger_handoff() -> None:
    eng = BodyEngine(handoff_margin=0.10)
    state = _empty_state()
    # Initial: phone wins by mic_quality (charged so the battery
    # factor matches the laptop's).
    devices1 = {
        "phone001": _phone(mic_quality=0.80, is_charging=True),
        "laptop01": _laptop(mic_quality=0.50),
    }
    state, _ = eng.arbitrate(devices=devices1, state=state, now_ms=NOW)
    assert state.primary_mic.value == "phone001"
    # Now make laptop massively better — by a clear margin.
    devices2 = {
        "phone001": _phone(mic_quality=0.30, is_charging=True),
        "laptop01": _laptop(mic_quality=0.95),
    }
    state2, handoffs = eng.arbitrate(devices=devices2, state=state, now_ms=NOW + 1)
    assert state2.primary_mic.value == "laptop01"
    mic_handoff = next(h for h in handoffs if h.role == DeviceRole.MIC)
    assert mic_handoff.from_device_id == "phone001"
    assert mic_handoff.to_device_id == "laptop01"


def test_stable_state_emits_no_handoffs() -> None:
    """Re-arbitrating with the same inputs as before must not emit
    any new handoffs."""
    eng = BodyEngine()
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    state, _ = eng.arbitrate(devices=devices, state=_empty_state(), now_ms=NOW)
    state2, handoffs = eng.arbitrate(devices=devices, state=state, now_ms=NOW + 1)
    assert handoffs == []
    assert state2.primary_mic == state.primary_mic
    assert state2.primary_display == state.primary_display


# ---------------------------------------------------------------------------
# Deterministic tiebreak
# ---------------------------------------------------------------------------

def test_tiebreak_is_lex_min_device_id() -> None:
    """Two devices with identical scores: tiebreak picks the
    lex-smaller device_id. This is what makes the arbitration
    deterministic across all participants."""
    eng = BodyEngine()
    devices = {
        "zzzzzzzz": _phone(device_id="zzzzzzzz", mic_quality=0.70),
        "aaaaaaaa": _phone(device_id="aaaaaaaa", mic_quality=0.70),
    }
    new_state, _ = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert new_state.primary_mic.value == "aaaaaaaa"


def test_two_arbitrators_same_inputs_same_output() -> None:
    """Determinism: two BodyEngine instances against the same
    inputs produce byte-identical results. This is load-bearing
    for cross-device convergence without a synchronous round-trip."""
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    eng_a = BodyEngine()
    eng_b = BodyEngine()
    state_a, handoffs_a = eng_a.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    state_b, handoffs_b = eng_b.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    assert state_a == state_b
    assert handoffs_a == handoffs_b


# ---------------------------------------------------------------------------
# Cross-device convergence (the load-bearing CRDT property)
# ---------------------------------------------------------------------------

def test_devices_converge_to_same_state_after_merge() -> None:
    """Device A and device B start from the same empty state. Each
    runs its OWN BodyEngine independently against the merged view
    of devices. The two outputs are merged via the underlying CRDT.
    The merged state must be the same regardless of merge order."""
    devices = {"phone001": _phone(), "laptop01": _laptop()}
    eng_a = BodyEngine()
    eng_b = BodyEngine()
    base = _empty_state()

    # Device A computes (slightly newer timestamp)
    state_a, _ = eng_a.arbitrate(devices=devices, state=base, now_ms=NOW + 10)
    # Device B computes
    state_b, _ = eng_b.arbitrate(devices=devices, state=base, now_ms=NOW + 5)

    merged_ab = state_a.merge(state_b)
    merged_ba = state_b.merge(state_a)
    assert merged_ab == merged_ba


# ---------------------------------------------------------------------------
# OR-set device add/remove
# ---------------------------------------------------------------------------

def test_add_device_idempotent_with_same_token() -> None:
    """Re-adding with the same token doesn't create a duplicate
    entry — the OR-set dedups by (value, token)."""
    state = _empty_state()
    state = BodyEngine.add_device(state, device_id="phone001", add_token="t1")
    state = BodyEngine.add_device(state, device_id="phone001", add_token="t1")
    assert state.active_devices.contains("phone001")


def test_remove_then_readd_with_new_token_succeeds() -> None:
    """Device leaves and rejoins the call. Fresh add_token
    re-establishes (add-wins property)."""
    state = _empty_state()
    state = BodyEngine.add_device(state, device_id="phone001", add_token="t1")
    state = BodyEngine.remove_device(state, device_id="phone001")
    assert not state.active_devices.contains("phone001")
    state = BodyEngine.add_device(state, device_id="phone001", add_token="t2")
    assert state.active_devices.contains("phone001")


# ---------------------------------------------------------------------------
# Surface handoff event shape
# ---------------------------------------------------------------------------

def test_handoff_carries_role_and_reason() -> None:
    eng = BodyEngine()
    state = _empty_state()
    devices = {"phone001": _phone()}
    _, handoffs = eng.arbitrate(devices=devices, state=state, now_ms=NOW)
    for h in handoffs:
        assert isinstance(h, SurfaceHandoff)
        assert h.crossfade_ms == 200
        assert h.decided_at_ms == NOW
        assert h.reason_code in ("initial_assignment", "score_better")


def test_initial_assignment_handoff_has_no_predecessor() -> None:
    eng = BodyEngine()
    devices = {"phone001": _phone()}
    _, handoffs = eng.arbitrate(
        devices=devices, state=_empty_state(), now_ms=NOW,
    )
    for h in handoffs:
        assert h.from_device_id is None
        assert h.reason_code == "initial_assignment"


def test_subsequent_handoff_records_predecessor() -> None:
    eng = BodyEngine()
    state = _empty_state()
    # Initial: phone wins
    state, _ = eng.arbitrate(
        devices={"phone001": _phone()}, state=state, now_ms=NOW,
    )
    # Phone goes critically hot; laptop arrives.
    state, handoffs = eng.arbitrate(
        devices={
            "phone001": _phone(thermal_state=ThermalState.CRITICAL),
            "laptop01": _laptop(),
        },
        state=state,
        now_ms=NOW + 100,
    )
    mic_handoff = next(h for h in handoffs if h.role == DeviceRole.MIC)
    assert mic_handoff.from_device_id == "phone001"
    assert mic_handoff.to_device_id == "laptop01"
    assert mic_handoff.reason_code == "score_better"
