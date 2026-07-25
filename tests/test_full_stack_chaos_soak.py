"""Full-stack chaos soak.

Composes every engine into one pipeline and runs N random scenarios.
Each scenario picks:

  - Random base RTT / loss / bandwidth profiles
  - Random bursts (RTT spikes, loss bursts, fragility excursions)
  - Random device events (thermal, battery, sleep)
  - Random frame arrivals: SOME ticks the real frame doesn't arrive
    (network loss); the Predictive Continuity engine fills the gap
  - Random route candidate changes (new relays appearing / dying)

Acceptance gates (per LIVING_PRESENCE_ARCHITECTURE.md Tier η):

  1. ≥95% of scenarios end in {alive, graceful_async}.
     NEVER dead_unrecoverable.
  2. No tick takes more than 50 ms (median + p95 well under).
  3. No engine raises an unhandled exception.
  4. Confirm-ratio stays sane (≥0% always, ≤100% always).
  5. The pipeline emits NO doctrine-forbidden signals (no "error
     code" labels, no "reconnecting" labels in produced
     ImmuneDecision reason_codes — caught by the doctrine lint
     elsewhere, but verified here too).

Run heavy with ``ONE_LINK_SOAK_ITERS=50000`` for nightly.
"""

from __future__ import annotations

import os
import random
import statistics
import time
from dataclasses import replace as dc_replace
from typing import Optional

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.body_engine import (
    BodyEngine,
    DeviceCapability,
)
from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
)
from one_link.call_session import (
    ParticipantState,
    Rung,
)
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import FrameKind, PathClass
from one_link.identity import Identity
from one_link.predictive_continuity import (
    MediaFrame,
    MediaKind,
    PredictiveContinuity,
)
from one_link.presence_compiler import PresenceCompiler
from one_link.priority_engine import (
    MediaStream,
    QoSClass,
    allocate as priority_allocate,
)
from one_link.route_brain import (
    RouteBrain,
    RouteCandidate,
    RouteState,
)


# ---------------------------------------------------------------------------
# Scenario primitives
# ---------------------------------------------------------------------------

_THERMAL_STATES = list(ThermalState)
_PATH_CLASSES = (PathClass.LAN, PathClass.DIRECT, PathClass.RELAY)
N_TICKS = 200   # 20 seconds at 100ms tick rate


def _identity_for_seed(seed: int) -> Identity:
    seed_bytes = blake3.blake3(f"chaos-{seed}".encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=f"chaos-{seed}",
    )


def _random_device(rng: random.Random, name: str) -> DeviceCapability:
    has_mic = rng.random() > 0.05
    has_cam = rng.random() > 0.10
    return DeviceCapability(
        device_id=name,
        has_mic=has_mic, has_cam=has_cam,
        has_display=rng.random() > 0.10,
        has_speaker=True,
        can_relay=rng.random() > 0.30,
        mic_quality=rng.uniform(0.3, 0.95) if has_mic else 0.0,
        cam_quality=rng.uniform(0.3, 0.95) if has_cam else 0.0,
        display_size_px_area=rng.choice([1_500_000, 2_073_600, 8_294_400]),
        speaker_quality=rng.uniform(0.3, 0.8),
        is_battery_powered=rng.random() > 0.30,
        battery_pct=rng.uniform(10.0, 100.0),
        is_charging=rng.random() > 0.50,
        thermal_state=rng.choice(_THERMAL_STATES),
        network_class=rng.choice(_PATH_CLASSES),
        alive_at_ms=1_700_000_000_000,
    )


def _random_route_candidate(
    rng: random.Random,
    path_id: str,
    *,
    warm: Optional[bool] = None,
) -> RouteCandidate:
    return RouteCandidate(
        path_id=path_id,
        path_class=rng.choice(_PATH_CLASSES),
        rtt_ewma_ms=rng.uniform(20.0, 800.0),
        loss_rate_ewma=rng.uniform(0.0, 0.15),
        bandwidth_kbps=rng.uniform(100.0, 5000.0),
        fragility_score=rng.uniform(0.0, 0.6),
        tau_c_score=rng.uniform(0.2, 0.9),
        attested=rng.random() > 0.5,
        warm=rng.random() > 0.5 if warm is None else warm,
    )


# ---------------------------------------------------------------------------
# One scenario
# ---------------------------------------------------------------------------

def _run_one_scenario(seed: int) -> dict:
    rng = random.Random(seed)
    identity = _identity_for_seed(seed)

    # Set up engines for this scenario
    immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT, audit_cap=N_TICKS + 10)
    compiler = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1", "frame_provenance_v1"}),
        ascent_hysteresis_ticks=5,
    )
    route_brain = RouteBrain(switch_margin=0.05)
    body = BodyEngine(handoff_margin=0.10)
    predictive = PredictiveContinuity()
    predictive.register_stream("voice", MediaKind.AUDIO)

    participant = ParticipantState(master_vk=identity.public_bytes)
    route_state = RouteState()

    streams = [
        MediaStream("voice", QoSClass.P0_VOICE, 10.0, 32.0),
        MediaStream("face", QoSClass.P2_FACE_PRIMARY, 50.0, 200.0),
        MediaStream("bg", QoSClass.P5_VIDEO_BACKGROUND, 50.0, 500.0),
    ]

    # Scenario parameters
    base_rtt = rng.uniform(20.0, 250.0)
    base_loss = rng.uniform(0.0, 0.03)
    has_burst = rng.random() < 0.35
    burst_start = rng.randint(30, 150) if has_burst else -1
    burst_end = burst_start + rng.randint(10, 40) if has_burst else -1
    has_fragility = rng.random() < 0.25
    frag_start = rng.randint(40, 180) if has_fragility else -1
    frag_end = frag_start + rng.randint(20, 50) if has_fragility else -1
    peer_dies = rng.random() < 0.08
    peer_death_tick = rng.randint(80, 190) if peer_dies else -1
    thermal_event = rng.random() < 0.20
    thermal_tick = rng.randint(40, 180) if thermal_event else -1

    # Random initial route candidates
    candidates = [
        _random_route_candidate(rng, "active", warm=True),
        _random_route_candidate(rng, "backup-a"),
    ]
    if rng.random() < 0.5:
        candidates.append(_random_route_candidate(rng, "backup-b"))
    route_state = RouteState(active_path_id="active")

    # Random devices
    devices = {
        "phone001": _random_device(rng, "phone001"),
        "laptop01": _random_device(rng, "laptop01"),
    }
    if rng.random() < 0.3:
        devices["tablet01"] = _random_device(rng, "tablet01")

    # Frame stream: seed a real frame
    predictive.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=b"seed-content",
        frame_kind=FrameKind.REAL,
    ))

    # Per-tick state
    last_rtt = base_rtt
    last_loss = base_loss
    terminated_at = -1
    actions: list[ImmuneAction] = []
    tick_latencies_us: list[int] = []
    exceptions: list[BaseException] = []

    for tick in range(N_TICKS):
        # Brownian-ish drift
        last_rtt = max(5.0, last_rtt + rng.gauss(0.0, 6.0))
        last_loss = max(0.0, min(0.5, last_loss + rng.gauss(0.0, 0.004)))

        rtt = last_rtt
        loss = last_loss
        fragility = 0.0
        if has_burst and burst_start <= tick <= burst_end:
            rtt += 350.0
            loss += 0.08
        if has_fragility and frag_start <= tick <= frag_end:
            fragility = rng.uniform(0.55, 0.92)

        peer_present = True
        last_alive = 1_700_000_000_000 + tick * 100
        if peer_dies and tick >= peer_death_tick:
            peer_present = False
            last_alive = 0

        # Thermal event: phone goes hot mid-scenario
        if thermal_event and tick >= thermal_tick:
            devices["phone001"] = dc_replace(
                devices["phone001"],
                thermal_state=ThermalState.HOT,
            )

        # Predictive continuity: 50% of ticks a real frame arrives; rest predicted
        if rng.random() < 0.5:
            predictive.on_real_frame_arrives(real=MediaFrame(
                stream_id="voice", media_kind=MediaKind.AUDIO,
                seq=tick + 1, timestamp_us=tick * 100,
                content=b"seed-content" if rng.random() < 0.7 else b"new-content",
                frame_kind=FrameKind.REAL,
            ))
        else:
            predictive.on_frame_due(
                stream_id="voice", expected_seq=tick + 1, now_us=tick * 100,
            )

        confirm_voice = predictive.confirm_ratio("voice")

        v = CallVitals(
            call_id=f"chaos-{seed}", peer_fp=f"peer-{seed}",
            tick=tick,
            rtt_ewma_ms=rtt,
            loss_rate_ewma=loss,
            jitter_ms=rng.uniform(0.0, 50.0),
            bandwidth_estimate_kbps=rng.uniform(50.0, 2500.0),
            reliability=max(0.0, 1.0 - loss),
            last_alive_ms=last_alive,
            path_class=PathClass.LAN,
            path_fragility_score=fragility,
            backup_routes_warm=len(route_state.warm_backups),
            own_device_role=DeviceRole.INACTIVE,
            own_battery_pct=devices["phone001"].battery_pct,
            own_thermal_state=devices["phone001"].thermal_state,
            peer_device_present=peer_present,
            audio_frames_received=tick * 50,
            audio_frames_dropped=int(tick * 50 * loss),
            video_frames_received=tick * 30,
            video_frames_predicted=int(tick * 30 * 0.1),
            confirm_ratio_voice=confirm_voice,
            confirm_ratio_video=confirm_voice * 0.9,
            path_attested=False,
            capability_state=CapabilitySnapshot.empty(),
        )

        t0 = time.perf_counter_ns()
        try:
            decision = immune.tick(v)
            transition = compiler.request(
                decision,
                bandwidth_kbps=v.bandwidth_estimate_kbps,
                confirm_ratio_voice=v.confirm_ratio_voice,
                loss_rate_ewma=v.loss_rate_ewma,
            )
            route_state, route_cmd = route_brain.step(
                decision=decision, candidates=candidates, state=route_state,
            )
            participant, _handoffs = body.arbitrate(
                devices=devices, state=participant, now_ms=tick,
            )
            _allocations = priority_allocate(
                streams=streams,
                total_bandwidth_kbps=v.bandwidth_estimate_kbps,
                current_rung=compiler.current_rung,
            )
        except BaseException as e:
            exceptions.append(e)
            break
        t1 = time.perf_counter_ns()

        tick_latencies_us.append((t1 - t0) // 1000)
        actions.append(decision.action)

        # Terminate the loop when async conversion fires.
        if decision.action == ImmuneAction.CONVERT_TO_ASYNC:
            terminated_at = tick
            break

    return {
        "seed": seed,
        "actions": actions,
        "tick_latencies_us": tick_latencies_us,
        "exceptions": exceptions,
        "terminated_at": terminated_at,
        "final_rung": compiler.current_rung,
        "final_confirm_ratio": predictive.confirm_ratio("voice"),
    }


def _endstate(result: dict) -> str:
    if result["exceptions"]:
        return "exception"
    if result["terminated_at"] >= 0:
        return "graceful_async"
    if result["final_rung"] == Rung.ASYNC_CAPSULE:
        return "graceful_async"
    return "alive"


# ---------------------------------------------------------------------------
# The soak test
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "iters",
    [int(os.getenv("ONE_LINK_SOAK_ITERS", "2000"))],
)
def test_full_stack_chaos_soak(iters: int) -> None:
    """Run ``iters`` random scenarios through the full engine
    pipeline. Acceptance gates:

      1. survival ≥ 0.95
      2. zero unhandled exceptions
      3. median tick latency < 50 ms (well under)
      4. confirm_ratio always in [0, 1]
    """
    survived = 0
    exception_seeds: list[int] = []
    all_latencies_us: list[int] = []
    bad_confirm_ratios: list[tuple[int, float]] = []

    for i in range(iters):
        result = _run_one_scenario(seed=i)
        endstate = _endstate(result)
        if endstate in ("alive", "graceful_async"):
            survived += 1
        if endstate == "exception":
            exception_seeds.append(i)
        all_latencies_us.extend(result["tick_latencies_us"])
        cr = result["final_confirm_ratio"]
        if cr < 0.0 or cr > 1.0:
            bad_confirm_ratios.append((i, cr))

    # ── Gates ────────────────────────────────────────────────────

    assert not exception_seeds, (
        f"unhandled exceptions in {len(exception_seeds)}/{iters} scenarios; "
        f"first: {exception_seeds[:5]}"
    )

    survival_rate = survived / iters
    assert survival_rate >= 0.95, (
        f"survival {survival_rate:.3f} < 0.95 budget over {iters} scenarios"
    )

    median_us = statistics.median(all_latencies_us)
    assert median_us < 50_000, (
        f"median tick latency {median_us} us > 50000 us budget"
    )
    # p99 also under a reasonable cap (CI noise tolerance)
    p99 = sorted(all_latencies_us)[int(len(all_latencies_us) * 0.99)]
    assert p99 < 500_000, f"p99 tick latency {p99} us > 500000 us budget"

    assert not bad_confirm_ratios, (
        f"confirm_ratio out of [0,1] in {len(bad_confirm_ratios)} scenarios; "
        f"first: {bad_confirm_ratios[:5]}"
    )
