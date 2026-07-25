"""Deterministic soak harness for the call reliability backend.

This module exercises the same backend logic the live browser feeds with
WebRTC stats. It is intentionally synthetic and privacy-safe: scenarios
contain only counters and state-machine facts, never media, SDP, ICE
candidate strings, IP addresses, device names, or user content.
"""

from __future__ import annotations

import random
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from one_link.call_reliability import CallReliabilityBackend


@dataclass(frozen=True)
class ReliabilitySoakScenario:
    """One deterministic call-health sequence."""

    seed: int
    call_id: str
    samples: tuple[dict[str, Any], ...]
    expects_relay: bool
    expects_auto_trace: bool
    expects_recovery: bool = True


@dataclass(frozen=True)
class ReliabilitySoakReport:
    """Aggregate result for a reliability soak run."""

    iterations: int
    passed: bool
    latency_p50_us: int
    latency_p95_us: int
    max_latency_us: int
    auto_trace_calls: int
    relay_escalation_calls: int
    recovery_calls: int
    failures: tuple[str, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "passed": self.passed,
            "latency_p50_us": self.latency_p50_us,
            "latency_p95_us": self.latency_p95_us,
            "max_latency_us": self.max_latency_us,
            "auto_trace_calls": self.auto_trace_calls,
            "relay_escalation_calls": self.relay_escalation_calls,
            "recovery_calls": self.recovery_calls,
            "failures": list(self.failures),
        }


def build_reliability_soak_scenario(seed: int) -> ReliabilitySoakScenario:
    """Build a repeatable degradation-and-recovery sequence.

    The shape is:
      healthy warmup -> one of several degradation families -> recovery.

    Each call gets a unique call_id so backend throttling cannot hide an
    incident that should be captured for that scenario.
    """
    # Deterministic synthetic soak data; never used for a security decision.
    rng = random.Random(seed)  # nosec B311
    call_id = f"reliability-soak-{seed}"
    family = seed % 4
    relay_ready = rng.random() < 0.75
    best_relay_health = "healthy" if relay_ready and rng.random() < 0.85 else "poor"
    route = "host"
    samples: list[dict[str, Any]] = []
    audio_packets = 0
    video_packets = 0
    video_frames = 0

    def sample(
        *,
        health: str = "healthy",
        severity: int = 0,
        ice: str = "connected",
        conn: str = "connected",
        rtt: float = 22.0,
        jitter: float = 4.0,
        loss: float = 0.0,
        video_frame_delta: int = 30,
        video_packet_delta: int = 90,
        audio_packet_delta: int = 120,
        selected_route: str | None = None,
    ) -> dict[str, Any]:
        nonlocal audio_packets, video_packets, video_frames
        audio_packets += max(0, audio_packet_delta)
        video_packets += max(0, video_packet_delta)
        video_frames += max(0, video_frame_delta)
        return {
            "call_id": call_id,
            "media_health_state": health,
            "media_health_severity": severity,
            "ice_connection_state": ice,
            "connection_state": conn,
            "signaling_state": "stable",
            "selected_candidate_type": selected_route or route,
            "rtt_ms": rtt,
            "jitter_ms": jitter,
            "loss_rate": loss,
            "bandwidth_estimate_kbps": max(64, 4200 - int(rtt * 3)),
            "remote_live_audio_tracks": 1,
            "remote_live_video_tracks": 1,
            "remote_audio_tracks": 1,
            "remote_video_tracks": 1,
            "remote_video_width": 1280 if video_frames > 0 else 0,
            "remote_video_height": 720 if video_frames > 0 else 0,
            "remote_video_src_attached": True,
            "remote_audio_src_attached": True,
            "inbound_audio_packets": audio_packets,
            "inbound_video_packets": video_packets,
            "inbound_video_frames_decoded": video_frames,
            "ice_relay_ready": relay_ready,
            "best_relay_health": best_relay_health if relay_ready else "unknown",
            "best_relay_score": 0.05 if best_relay_health == "healthy" else 0.95,
        }

    for _ in range(4):
        samples.append(sample(
            rtt=rng.uniform(12, 35),
            jitter=rng.uniform(1, 8),
            loss=rng.uniform(0, 0.004),
        ))

    expects_auto_trace = True
    expects_relay = False
    if family == 0:
        for _ in range(4):
            samples.append(sample(
                health="playback_frozen",
                severity=2,
                rtt=rng.uniform(30, 90),
                jitter=rng.uniform(8, 40),
                loss=rng.uniform(0, 0.015),
                video_frame_delta=0,
                video_packet_delta=60,
            ))
        expects_relay = relay_ready and best_relay_health != "poor"
    elif family == 1:
        for _ in range(8):
            samples.append(sample(
                health="healthy",
                severity=1,
                rtt=rng.uniform(1200, 1800),
                jitter=rng.uniform(750, 1200),
                loss=rng.uniform(0.16, 0.32),
            ))
        expects_relay = relay_ready and best_relay_health != "poor"
    elif family == 2:
        for ice in ("disconnected", "disconnected", "failed"):
            samples.append(sample(
                health="healthy",
                severity=2,
                ice=ice,
                conn="disconnected" if ice == "disconnected" else "failed",
                rtt=rng.uniform(120, 260),
                jitter=rng.uniform(45, 130),
                loss=rng.uniform(0.03, 0.09),
                video_frame_delta=0,
                video_packet_delta=0,
            ))
        expects_relay = relay_ready and best_relay_health != "poor"
    else:
        for _ in range(4):
            samples.append(sample(
                health="renderer_detached",
                severity=1,
                rtt=rng.uniform(18, 45),
                jitter=rng.uniform(2, 14),
                loss=rng.uniform(0, 0.006),
                video_frame_delta=0,
                video_packet_delta=80,
            ))
        expects_relay = False

    for _ in range(7):
        samples.append(sample(
            health="healthy",
            severity=0,
            ice="connected",
            conn="connected",
            rtt=rng.uniform(12, 45),
            jitter=rng.uniform(1, 10),
            loss=rng.uniform(0, 0.006),
            selected_route="relay" if expects_relay else route,
            video_frame_delta=35,
            video_packet_delta=100,
            audio_packet_delta=130,
        ))

    return ReliabilitySoakScenario(
        seed=seed,
        call_id=call_id,
        samples=tuple(samples),
        expects_relay=expects_relay,
        expects_auto_trace=expects_auto_trace,
    )


def run_reliability_soak(
    *,
    iterations: int = 250,
    log_path: Path | None = None,
) -> ReliabilitySoakReport:
    """Run a deterministic reliability soak and return gate evidence."""
    backend = CallReliabilityBackend(log_path=log_path, max_rows_per_call=96)
    failures: list[str] = []
    latencies_us: list[int] = []
    auto_trace_calls = 0
    relay_escalation_calls = 0
    recovery_calls = 0

    for seed in range(max(1, int(iterations))):
        scenario = build_reliability_soak_scenario(seed)
        saw_relay_escalation = False
        for sample in scenario.samples:
            start = time.perf_counter_ns()
            rec = backend.record_metrics(sample)
            stop = time.perf_counter_ns()
            latencies_us.append((stop - start) // 1000)
            intent = backend.recovery_intent_for(scenario.call_id)
            if (
                rec.route_preference == "relay"
                or intent.get("route_preference") == "relay"
            ):
                saw_relay_escalation = True

        trace = backend.trace_for(scenario.call_id)
        incident_count = int(trace.get("auto_trace", {}).get("incident_count") or 0)
        session = trace.get("session_authority") or {}
        intent = trace.get("recovery_intent") or {}

        if scenario.expects_auto_trace and incident_count <= 0:
            failures.append(f"{scenario.call_id}: missing auto_trace incident")
        else:
            auto_trace_calls += 1
        if scenario.expects_relay:
            if not saw_relay_escalation:
                failures.append(f"{scenario.call_id}: failed to escalate usable relay")
            else:
                relay_escalation_calls += 1
        if scenario.expects_recovery:
            if session.get("state") not in {"connected", "recovered"}:
                failures.append(f"{scenario.call_id}: did not recover, state={session.get('state')}")
            elif intent.get("action") != "hold":
                failures.append(f"{scenario.call_id}: final intent not hold, action={intent.get('action')}")
            else:
                recovery_calls += 1

    p50 = int(statistics.median(latencies_us)) if latencies_us else 0
    p95 = _percentile(latencies_us, 95)
    max_latency = max(latencies_us) if latencies_us else 0
    if p95 > 5_000:
        failures.append(f"p95 latency too high: {p95}us")
    return ReliabilitySoakReport(
        iterations=max(1, int(iterations)),
        passed=not failures,
        latency_p50_us=p50,
        latency_p95_us=p95,
        max_latency_us=max_latency,
        auto_trace_calls=auto_trace_calls,
        relay_escalation_calls=relay_escalation_calls,
        recovery_calls=recovery_calls,
        failures=tuple(failures[:64]),
    )


def _percentile(values: list[int], pct: int) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    idx = int(round((len(ordered) - 1) * (pct / 100.0)))
    return int(ordered[max(0, min(len(ordered) - 1, idx))])
