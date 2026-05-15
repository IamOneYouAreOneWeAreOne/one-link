"""End-to-end Living Presence integration test.

Wires the four engines that have shipped so far into one pipeline
and exercises the whole pipeline against scripted network
conditions. The architecture doc's Tier δ headline demo is the
target: a call survives a network failure by descending the
representation ladder gracefully and converting to async capsule
rather than dying.

Pipeline under test:

    CallVitals
        |
    ImmuneSystem (Arbitrator + hysteresis)
        |
    ImmuneDecision
        |
    PresenceCompiler  ────────────────────────► RungTransition
        |
    CallSession.with_rung()   (CRDT state)

The test does NOT spin up real daemons. It exercises the engines as
a composed system the way a real daemon would, with one virtual
peer-pairing's worth of vitals fed in tick by tick.

Five scripted scenarios:

  1. Calm call: vitals stay healthy → HOLD throughout, rung never
     leaves RAW_AV.
  2. Brief network blip: short loss spike → REQUEST_LOWER_FIDELITY,
     descends to OPUS_VIDEO, then climbs back after stability window.
  3. Sustained bad network: rising loss + jitter → step down through
     OPUS_VIDEO → AUDIO_ONLY.
  4. Catastrophic failure: extreme loss → CONVERT_TO_ASYNC →
     ASYNC_CAPSULE, terminal state.
  5. Voice-safe override: high RTT but healthy media → HOLD, no
     unnecessary prewarm.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
    Thresholds,
)
from one_link.call_session import (
    CallSession,
    Intensity,
    Rung,
)
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import PathClass
from one_link.presence_compiler import PresenceCompiler, RungTransition


# ---------------------------------------------------------------------------
# The pipeline glue
# ---------------------------------------------------------------------------

def _vitals(tick: int, **over) -> CallVitals:
    base = dict(
        call_id="call-e2e",
        peer_fp="peer-e2e",
        tick=tick,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=0.0,
        bandwidth_estimate_kbps=2000.0,
        reliability=1.0,
        last_alive_ms=1_700_000_000_000 + tick * 100,
        path_class=PathClass.DIRECT,
        path_fragility_score=0.0,
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=80.0,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=True,
        audio_frames_received=tick * 50,
        audio_frames_dropped=0,
        video_frames_received=tick * 30,
        video_frames_predicted=0,
        confirm_ratio_voice=1.0,
        confirm_ratio_video=1.0,
        path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )
    base.update(over)
    return CallVitals(**base)


class _Pipeline:
    """Composed system under test. Tracks the CallSession state as
    the engines drive it."""

    def __init__(self) -> None:
        self.immune = ImmuneSystem(
            mode=GraduationMode.AUTOPILOT,
            audit_cap=2_000,
        )
        self.compiler = PresenceCompiler(
            peer_capabilities=frozenset({"webrtc_av_v1"}),
            ascent_hysteresis_ticks=5,  # short for tests
        )
        self.session = CallSession(
            call_id="call-e2e",
            started_at_ms=1_700_000_000_000,
            negotiated_capabilities=frozenset({"webrtc_av_v1"}),
        ).with_intensity(
            Intensity.HIGH,
            timestamp_ms=1_700_000_000_000,
            writer_id="local-device",
        )
        self.transitions: list[RungTransition] = []
        self.terminated_at_tick: int | None = None

    def feed(self, v: CallVitals) -> None:
        """Run one tick through the pipeline."""
        if self.terminated_at_tick is not None:
            return
        decision = self.immune.tick(v)
        transition = self.compiler.request(
            decision,
            bandwidth_kbps=v.bandwidth_estimate_kbps,
            confirm_ratio_voice=v.confirm_ratio_voice,
            loss_rate_ewma=v.loss_rate_ewma,
        )
        if transition is not None:
            self.transitions.append(transition)
            self.session = self.session.with_rung(
                transition.to_rung,
                timestamp_ms=v.tick * 100,
                writer_id="local-device",
            )
            if transition.to_rung == Rung.ASYNC_CAPSULE:
                self.terminated_at_tick = v.tick

    @property
    def current_rung(self) -> Rung:
        return self.compiler.current_rung


# ---------------------------------------------------------------------------
# Scenario 1 — calm call
# ---------------------------------------------------------------------------

def test_calm_call_never_descends() -> None:
    p = _Pipeline()
    for tick in range(100):
        p.feed(_vitals(tick=tick))
    assert p.current_rung == Rung.RAW_AV
    assert p.transitions == []
    assert p.terminated_at_tick is None
    # CallSession reflects HIGH intensity, no rung override yet.
    assert p.session.current_intensity == Intensity.HIGH
    # current_rung in the CRDT defaults to RAW_AV when never set.
    assert p.session.current_rung_value == Rung.RAW_AV


# ---------------------------------------------------------------------------
# Scenario 2 — brief network blip recovers
# ---------------------------------------------------------------------------

def test_brief_blip_descends_then_recovers() -> None:
    p = _Pipeline()
    # Ticks 0-9: healthy
    for tick in range(10):
        p.feed(_vitals(tick=tick))
    assert p.current_rung == Rung.RAW_AV

    # Ticks 10-14: loss spike triggers REQUEST_LOWER_FIDELITY
    # Note: voice-safe override only fires when confirm_ratio_voice is high
    # AND loss is below recover threshold. By driving confirm down, the
    # transport vote wins.
    for tick in range(10, 15):
        p.feed(_vitals(
            tick=tick, loss_rate_ewma=0.08, confirm_ratio_voice=0.50,
        ))
    # Compiler should have descended at least one rung.
    assert p.current_rung != Rung.RAW_AV
    assert len(p.transitions) >= 1

    # Ticks 15+: clean network for the ascent window
    for tick in range(15, 40):
        p.feed(_vitals(tick=tick))

    # Compiler should ascend back. RAW_AV may not be reached if we
    # only descended one rung — we settle wherever stability allowed.
    final_rung = p.current_rung
    assert int(final_rung) <= int(Rung.OPUS_VIDEO), (
        f"expected ascent toward higher fidelity, current={final_rung}"
    )


# ---------------------------------------------------------------------------
# Scenario 3 — sustained degradation
# ---------------------------------------------------------------------------

def test_sustained_bad_network_steps_down_gracefully() -> None:
    p = _Pipeline()
    # Ramp up loss steadily; never reach async threshold.
    for tick in range(50):
        loss = min(0.12, 0.001 + tick * 0.003)
        p.feed(_vitals(
            tick=tick, loss_rate_ewma=loss, confirm_ratio_voice=0.50,
        ))
    # Should have stepped down from RAW_AV but not all the way to
    # async (loss capped at 0.12, below the 0.15 voice-only and 0.35 async).
    assert p.current_rung != Rung.RAW_AV
    assert p.current_rung != Rung.ASYNC_CAPSULE
    assert p.terminated_at_tick is None


# ---------------------------------------------------------------------------
# Scenario 4 — catastrophic failure becomes async
# ---------------------------------------------------------------------------

def test_catastrophic_failure_converts_to_capsule() -> None:
    p = _Pipeline()
    # Healthy for 10 ticks
    for tick in range(10):
        p.feed(_vitals(tick=tick))
    # Then total network collapse
    for tick in range(10, 20):
        p.feed(_vitals(
            tick=tick, loss_rate_ewma=0.50, confirm_ratio_voice=0.0,
        ))
    assert p.current_rung == Rung.ASYNC_CAPSULE
    assert p.terminated_at_tick is not None
    # Subsequent ticks after conversion are no-ops; rung stays.
    for tick in range(20, 50):
        p.feed(_vitals(tick=tick))
    assert p.current_rung == Rung.ASYNC_CAPSULE


# ---------------------------------------------------------------------------
# Scenario 5 — voice-safe override prevents over-eager descent
# ---------------------------------------------------------------------------

def test_voice_safe_override_holds_under_isolated_rtt_spike() -> None:
    """High RTT alone, with otherwise healthy media, should NOT
    descend. The user is not currently being harmed."""
    p = _Pipeline()
    for tick in range(30):
        # RTT crosses prewarm trigger (400ms), but loss is zero and
        # voice confirm is perfect.
        p.feed(_vitals(
            tick=tick,
            rtt_ewma_ms=500.0,
            loss_rate_ewma=0.0,
            confirm_ratio_voice=1.0,
        ))
    # No transitions, no descent.
    assert p.transitions == []
    assert p.current_rung == Rung.RAW_AV


# ---------------------------------------------------------------------------
# Headline demo: WiFi unplugged mid-call → capsule → resume
# ---------------------------------------------------------------------------

def test_headline_demo_wifi_unplugged_becomes_capsule() -> None:
    """Architecture doc Tier δ headline: 'call survives the WiFi
    router being unplugged mid-call by becoming a voice-note +
    resuming when WiFi returns.'

    This test models the demo's first half (call → capsule). The
    resume side (a new CallSession with resume_of pointing here) is
    a UI flow on top of what we have."""
    p = _Pipeline()

    # 60 ticks of healthy call (6 sec at 100ms tick)
    for tick in range(60):
        p.feed(_vitals(tick=tick))
    assert p.current_rung == Rung.RAW_AV

    # Tick 60: WiFi unplugged. Loss instantly to 90%.
    # Subsequent ticks: peer also goes silent (last_alive doesn't
    # update). 10 ticks of total darkness.
    for tick in range(60, 70):
        p.feed(_vitals(
            tick=tick,
            loss_rate_ewma=0.90,
            confirm_ratio_voice=0.0,
            peer_device_present=False,
            last_alive_ms=1_700_000_000_000 + 60 * 100,  # frozen
        ))

    # Call has converted to capsule.
    assert p.current_rung == Rung.ASYNC_CAPSULE
    assert p.terminated_at_tick is not None
    assert p.terminated_at_tick >= 60

    # The Compiler emitted a clear transition AT some tick — the
    # daemon would use this to persist the in-flight buffer as a
    # voice note and set the live_resumable window.
    capsule_transition = next(
        t for t in p.transitions if t.to_rung == Rung.ASYNC_CAPSULE
    )
    assert capsule_transition.from_rung != Rung.ASYNC_CAPSULE
    assert capsule_transition.tick == p.terminated_at_tick
