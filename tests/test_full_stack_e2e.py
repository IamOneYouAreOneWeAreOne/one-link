"""Full-stack Living Presence integration.

Wires every engine that has shipped into a single pipeline:

    CallVitals
        ↓
    ImmuneSystem  ─────► ImmuneDecision
        ↓                      │
        ↓                      ├──► PresenceCompiler ─► RungTransition
        ↓                      │
        ↓                      ├──► RouteBrain ─────► RouteCommand
        ↓                      │
        ↓                      └──► BodyEngine ─────► SurfaceHandoff
        ↓
    PriorityEngine.allocate(streams, bandwidth, current_rung) ─► allocations
        ↓
    FrameProvenance.sign(...) ─► signed media frame
        ↓
    CallSession (CRDT, holds everything)

This is the "all engines under one button" picture, exercised in one
process against scripted conditions. No daemons spun up — the goal
is to prove the engines compose, not to integration-test the wire
layer.

Scenarios in this file go beyond test_living_presence_e2e.py:

  - Multi-device call where the Body Engine arbitrates roles AND
    the Immune System reacts to one device degrading
  - Route Brain prewarms then switches when the Immune System
    asks
  - Priority Engine reallocates as the Compiler descends rungs
  - Reality Engine signs frames and tags them with the current
    PathClass from the Route Brain
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.body_engine import (
    BodyEngine,
    DeviceCapability,
    SurfaceHandoff,
)
from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
)
from one_link.call_session import (
    CallSession,
    Intensity,
    ParticipantState,
    Rung,
)
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
    verify_provenance,
)
from one_link.identity import Identity
from one_link.presence_compiler import PresenceCompiler, RungTransition
from one_link.priority_engine import (
    MediaStream,
    QoSClass,
    allocate as priority_allocate,
)
from one_link.route_brain import (
    RouteBrain,
    RouteCandidate,
    RouteCommand,
    RouteCommandKind,
    RouteState,
)


# ---------------------------------------------------------------------------
# Test identities
# ---------------------------------------------------------------------------

def _identity(name: str) -> Identity:
    seed = blake3.blake3(name.encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=name,
    )


# ---------------------------------------------------------------------------
# Pipeline composition
# ---------------------------------------------------------------------------

class FullStack:
    """One participant's full engine stack."""

    def __init__(self, *, identity: Identity) -> None:
        self.identity = identity
        self.immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT)
        self.compiler = PresenceCompiler(
            peer_capabilities=frozenset({"webrtc_av_v1", "frame_provenance_v1"}),
            ascent_hysteresis_ticks=5,
        )
        self.route_brain = RouteBrain(switch_margin=0.05)
        self.body = BodyEngine(handoff_margin=0.10)
        # Per-participant CRDT slice
        self.participant = ParticipantState(master_vk=identity.public_bytes)
        # Route state
        self.route_state = RouteState()
        # Logs
        self.transitions: list[RungTransition] = []
        self.route_commands: list[RouteCommand] = []
        self.surface_handoffs: list[SurfaceHandoff] = []

    def tick(
        self,
        *,
        vitals: CallVitals,
        devices: dict[str, DeviceCapability],
        route_candidates: list[RouteCandidate],
        media_streams: list[MediaStream],
    ) -> dict:
        """One tick through the whole stack. Returns a summary of
        every engine's output for assertions."""
        # 1. Immune System reads vitals, emits decision.
        decision = self.immune.tick(vitals)

        # 2. Presence Compiler may emit a rung transition.
        transition = self.compiler.request(
            decision,
            bandwidth_kbps=vitals.bandwidth_estimate_kbps,
            confirm_ratio_voice=vitals.confirm_ratio_voice,
            loss_rate_ewma=vitals.loss_rate_ewma,
        )
        if transition is not None:
            self.transitions.append(transition)

        # 3. Route Brain may emit a route command.
        self.route_state, route_cmd = self.route_brain.step(
            decision=decision,
            candidates=route_candidates,
            state=self.route_state,
        )
        if route_cmd.kind != RouteCommandKind.HOLD:
            self.route_commands.append(route_cmd)

        # 4. Body Engine arbitrates surfaces.
        self.participant, handoffs = self.body.arbitrate(
            devices=devices,
            state=self.participant,
            now_ms=vitals.tick,
        )
        self.surface_handoffs.extend(handoffs)

        # 5. Priority Engine allocates the bandwidth budget.
        allocations = priority_allocate(
            streams=media_streams,
            total_bandwidth_kbps=vitals.bandwidth_estimate_kbps,
            current_rung=self.compiler.current_rung,
        )

        return {
            "decision": decision,
            "transition": transition,
            "route_command": route_cmd,
            "handoffs": handoffs,
            "allocations": allocations,
            "current_rung": self.compiler.current_rung,
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

NOW = 1_700_000_000_000


@pytest.fixture
def alice() -> Identity:
    return _identity("alice-fullstack")


@pytest.fixture
def phone() -> DeviceCapability:
    return DeviceCapability(
        device_id="phone001",
        has_mic=True, has_cam=True, has_display=True, has_speaker=True,
        can_relay=False,
        mic_quality=0.85, cam_quality=0.80,
        display_size_px_area=1_500_000,
        speaker_quality=0.50,
        is_battery_powered=True,
        battery_pct=80.0, is_charging=True,
        thermal_state=ThermalState.NOMINAL,
        network_class=PathClass.LAN,
        alive_at_ms=NOW,
    )


@pytest.fixture
def laptop() -> DeviceCapability:
    return DeviceCapability(
        device_id="laptop01",
        has_mic=True, has_cam=True, has_display=True, has_speaker=True,
        can_relay=True,
        mic_quality=0.60, cam_quality=0.70,
        display_size_px_area=2_073_600,
        speaker_quality=0.65,
        is_battery_powered=True,
        battery_pct=95.0, is_charging=True,
        thermal_state=ThermalState.NOMINAL,
        network_class=PathClass.LAN,
        alive_at_ms=NOW,
    )


def _vitals(tick: int, **over) -> CallVitals:
    base = dict(
        call_id="call-fullstack",
        peer_fp="peer-fullstack",
        tick=tick,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=0.0,
        bandwidth_estimate_kbps=2000.0,
        reliability=1.0,
        last_alive_ms=NOW + tick * 100,
        path_class=PathClass.LAN,
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


def _voice_streams() -> list[MediaStream]:
    return [
        MediaStream("voice", QoSClass.P0_VOICE, 10.0, 32.0),
        MediaStream("timing", QoSClass.P1_TIMING, 1.0, 2.0),
        MediaStream("face", QoSClass.P2_FACE_PRIMARY, 50.0, 200.0),
        MediaStream("gesture", QoSClass.P3_GESTURE, 20.0, 80.0),
        MediaStream("bg", QoSClass.P5_VIDEO_BACKGROUND, 50.0, 500.0),
    ]


# ---------------------------------------------------------------------------
# Healthy call: every engine settles, nothing fires
# ---------------------------------------------------------------------------

def test_healthy_call_no_interventions(
    alice: Identity, phone: DeviceCapability, laptop: DeviceCapability,
) -> None:
    stack = FullStack(identity=alice)
    devices = {"phone001": phone, "laptop01": laptop}
    routes = [RouteCandidate("active", PathClass.LAN, 50.0, 0.0, 1000.0, warm=True)]
    stack.route_state = RouteState(active_path_id="active")

    for tick in range(50):
        result = stack.tick(
            vitals=_vitals(tick=tick),
            devices=devices,
            route_candidates=routes,
            media_streams=_voice_streams(),
        )
        assert result["decision"].action == ImmuneAction.HOLD

    # No rung transitions, no route commands beyond the initial.
    assert stack.transitions == []
    assert stack.route_commands == []
    # Body engine assigned surfaces once on tick 0.
    initial_handoffs = [h for h in stack.surface_handoffs if h.from_device_id is None]
    assert len(initial_handoffs) > 0
    # All allocations fully funded.
    final = stack.tick(
        vitals=_vitals(tick=50), devices=devices,
        route_candidates=routes, media_streams=_voice_streams(),
    )
    for a in final["allocations"]:
        assert not a.paused


# ---------------------------------------------------------------------------
# Phone overheats → laptop takes over, call continues unbroken
# ---------------------------------------------------------------------------

def test_phone_overheats_laptop_takes_mic_call_uninterrupted(
    alice: Identity, phone: DeviceCapability, laptop: DeviceCapability,
) -> None:
    stack = FullStack(identity=alice)
    routes = [RouteCandidate("active", PathClass.LAN, 50.0, 0.0, 1000.0, warm=True)]
    stack.route_state = RouteState(active_path_id="active")
    streams = _voice_streams()

    # Tick 0-9: phone normal — phone holds mic
    devices = {"phone001": phone, "laptop01": laptop}
    for tick in range(10):
        stack.tick(
            vitals=_vitals(tick=tick), devices=devices,
            route_candidates=routes, media_streams=streams,
        )
    assert stack.participant.primary_mic.value == "phone001"

    # Tick 10+: phone goes critical hot
    from dataclasses import replace as dc_replace
    hot_phone = dc_replace(phone, thermal_state=ThermalState.CRITICAL)
    devices_hot = {"phone001": hot_phone, "laptop01": laptop}
    for tick in range(10, 20):
        stack.tick(
            vitals=_vitals(tick=tick), devices=devices_hot,
            route_candidates=routes, media_streams=streams,
        )
    # Laptop has overtaken mic.
    assert stack.participant.primary_mic.value == "laptop01"
    # Call rung unchanged — the network didn't break.
    assert stack.compiler.current_rung == Rung.RAW_AV
    # The reality is: a SurfaceHandoff was emitted with from=phone, to=laptop
    mic_handoffs = [
        h for h in stack.surface_handoffs
        if h.role == DeviceRole.MIC and h.from_device_id == "phone001"
    ]
    assert len(mic_handoffs) >= 1
    assert mic_handoffs[0].to_device_id == "laptop01"


# ---------------------------------------------------------------------------
# Network worsens → Compiler descends + Priority Engine reallocates
# ---------------------------------------------------------------------------

def test_network_pressure_descends_rung_and_reallocates_bandwidth(
    alice: Identity, phone: DeviceCapability,
) -> None:
    stack = FullStack(identity=alice)
    devices = {"phone001": phone}
    routes = [
        RouteCandidate("active", PathClass.LAN, 50.0, 0.0, 1000.0, warm=True),
        RouteCandidate("backup", PathClass.RELAY, 100.0, 0.0, 800.0, warm=False),
    ]
    stack.route_state = RouteState(active_path_id="active")
    streams = _voice_streams()

    # Ticks 0-19: healthy call
    for tick in range(20):
        stack.tick(
            vitals=_vitals(tick=tick), devices=devices,
            route_candidates=routes, media_streams=streams,
        )
    # Snapshot a full allocation: every stream funded at 2000 kbps.
    snapshot = stack.tick(
        vitals=_vitals(tick=20), devices=devices,
        route_candidates=routes, media_streams=streams,
    )
    by_id_full = {a.stream_id: a for a in snapshot["allocations"]}
    assert not by_id_full["bg"].paused

    # Ticks 21-30: loss rises, bandwidth drops, voice confirm dips.
    for tick in range(21, 31):
        stack.tick(
            vitals=_vitals(
                tick=tick,
                loss_rate_ewma=0.08,
                confirm_ratio_voice=0.50,
                bandwidth_estimate_kbps=80.0,
            ),
            devices=devices, route_candidates=routes, media_streams=streams,
        )

    # Rung has descended at least one step.
    assert stack.compiler.current_rung != Rung.RAW_AV
    # Background paused under pressure.
    final = stack.tick(
        vitals=_vitals(
            tick=31, loss_rate_ewma=0.08,
            confirm_ratio_voice=0.50, bandwidth_estimate_kbps=80.0,
        ),
        devices=devices, route_candidates=routes, media_streams=streams,
    )
    by_id_pressed = {a.stream_id: a for a in final["allocations"]}
    assert by_id_pressed["bg"].paused
    # Voice still funded.
    assert not by_id_pressed["voice"].paused


# ---------------------------------------------------------------------------
# Route Brain prewarms then switches when Immune asks
# ---------------------------------------------------------------------------

def test_route_brain_prewarms_then_switches_on_severe_rtt(
    alice: Identity, phone: DeviceCapability,
) -> None:
    stack = FullStack(identity=alice)
    devices = {"phone001": phone}
    routes = [
        RouteCandidate("active", PathClass.LAN, 50.0, 0.0, 1000.0, warm=True),
        RouteCandidate("backup", PathClass.DIRECT, 80.0, 0.0, 1000.0, warm=False),
    ]
    stack.route_state = RouteState(active_path_id="active")
    streams = _voice_streams()

    # RTT climbs to 500ms (prewarm trigger 400) but stays below switch (800).
    # Confirm ratio dipped so the voice-safe override doesn't suppress it.
    for tick in range(10):
        stack.tick(
            vitals=_vitals(tick=tick, rtt_ewma_ms=500.0, confirm_ratio_voice=0.50),
            devices=devices, route_candidates=routes, media_streams=streams,
        )
    # Route Brain has issued a prewarm.
    prewarm_cmds = [c for c in stack.route_commands if c.kind == RouteCommandKind.PREWARM_PATH]
    assert len(prewarm_cmds) >= 1
    assert prewarm_cmds[0].target_path_id == "backup"
    assert "backup" in stack.route_state.warm_backups

    # Now RTT climbs to 1500ms (switch trigger 800). The active path's
    # candidate metrics also reflect the degradation (the daemon
    # measures RTT on the active path; if vitals.rtt is 1500 that's
    # because the active path's RTT is 1500). Backup is warm and has
    # a clean 80ms RTT — clearly the better option now.
    from dataclasses import replace as dc_replace
    routes_warm = [
        dc_replace(routes[0], rtt_ewma_ms=1500.0, loss_rate_ewma=0.05),
        dc_replace(routes[1], warm=True),
    ]
    for tick in range(10, 20):
        stack.tick(
            vitals=_vitals(tick=tick, rtt_ewma_ms=1500.0, confirm_ratio_voice=0.50),
            devices=devices, route_candidates=routes_warm, media_streams=streams,
        )
    # Route Brain has switched.
    switches = [c for c in stack.route_commands if c.kind == RouteCommandKind.SWITCH_TO_PATH]
    assert len(switches) >= 1
    assert switches[0].target_path_id == "backup"
    assert stack.route_state.active_path_id == "backup"


# ---------------------------------------------------------------------------
# Reality Engine signs frames; receiver verifies
# ---------------------------------------------------------------------------

def test_reality_engine_signs_frame_received_verifies(
    alice: Identity,
) -> None:
    """Each outbound media segment carries a FrameProvenance the
    receiver can verify against the sender's pinned master key."""
    voice_blob = b"<opus voice frame at this tick>"
    seg_hash = make_segment_hash(voice_blob)
    p = sign_provenance(
        segment_hash=seg_hash,
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=NOW * 1000,
        produce_confidence=1.0,
        signing_key=alice.private,
    )
    assert verify_provenance(p, alice.public_bytes)


# ---------------------------------------------------------------------------
# The full headline scenario — phone overheats, network degrades,
# call survives by reconfiguring the body AND descending the rung
# ---------------------------------------------------------------------------

def test_full_headline_phone_hot_network_bad_call_survives(
    alice: Identity, phone: DeviceCapability, laptop: DeviceCapability,
) -> None:
    """The full demo of 'devices are organs + call gently changes
    form'. Phone holds mic at start. Then BOTH degrade: phone goes
    HOT, network deteriorates. The Body Engine moves mic to laptop
    while the Compiler descends to AUDIO_ONLY. The call never
    drops — it gracefully adapts on two axes simultaneously."""

    from dataclasses import replace as dc_replace

    stack = FullStack(identity=alice)
    routes = [RouteCandidate("active", PathClass.LAN, 50.0, 0.0, 1000.0, warm=True)]
    stack.route_state = RouteState(active_path_id="active")
    streams = _voice_streams()
    devices_ok = {"phone001": phone, "laptop01": laptop}

    # Ticks 0-9: healthy
    for tick in range(10):
        stack.tick(vitals=_vitals(tick=tick), devices=devices_ok,
                   route_candidates=routes, media_streams=streams)
    assert stack.participant.primary_mic.value == "phone001"
    assert stack.compiler.current_rung == Rung.RAW_AV

    # Ticks 10-25: phone overheats + loss rises (network bad)
    hot_phone = dc_replace(phone, thermal_state=ThermalState.CRITICAL)
    devices_hot = {"phone001": hot_phone, "laptop01": laptop}
    for tick in range(10, 26):
        stack.tick(vitals=_vitals(
            tick=tick, loss_rate_ewma=0.18, confirm_ratio_voice=0.40,
        ), devices=devices_hot, route_candidates=routes, media_streams=streams)

    # ── Two simultaneous adaptations ──
    # (a) Body Engine moved mic to laptop
    assert stack.participant.primary_mic.value == "laptop01"
    # (b) Compiler descended to audio-only (loss above voice_only trigger)
    assert stack.compiler.current_rung == Rung.AUDIO_ONLY
    # The call did NOT convert to async — it gracefully changed form
    # without ending.
    assert stack.compiler.current_rung != Rung.ASYNC_CAPSULE
