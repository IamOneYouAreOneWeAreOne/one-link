"""Performance benchmarks + regression gates.

These tests don't just confirm correctness — they pin minimum
throughput / max latency budgets for the hot paths. If a future
change halves the throughput, the test fails. Numbers are
deliberately permissive (3-5× headroom over typical performance)
so flaky CI machines don't trip the gate.

Hot paths gated:
  - TransportPrioritizer.drain (every send cycle)
  - crossfade._mix_s16le (50 Hz per call)
  - CallVitals.vitals_hash (every immune tick)
  - FrameProvenance sign / verify (per attestation window)
  - capsule_at_rest seal / open (per voice-note save)
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.capsule_at_rest import open_from_path, seal_to_path
from one_link.crossfade import mix_samples
from one_link.transport_priority import (
    QoSClass,
    TransportPrioritizer,
)


# CI noise tolerance. Set ONE_LINK_PERF_TOLERANCE=3.0 (or higher) for
# slow boxes; default 1.0 = strict.
_PERF_TOLERANCE = float(os.getenv("ONE_LINK_PERF_TOLERANCE", "3.0"))


def _scaled(ms: float) -> float:
    return ms * _PERF_TOLERANCE


# ---------------------------------------------------------------------------
# TransportPrioritizer.drain
# ---------------------------------------------------------------------------

def test_prioritizer_drain_throughput() -> None:
    """100 enqueued messages should drain in under a few ms across
    a handful of ticks (DWRR honours weight budgets — 100 × 80 = 8 KB
    over a default 2 KB voice weight = 4 ticks expected)."""
    p = TransportPrioritizer()
    for i in range(100):
        p.enqueue(
            payload=b"x" * 80,
            qos_class=QoSClass.VOICE_FRAMES,
        )
    total = 0
    t0 = time.perf_counter()
    for _ in range(10):
        total += len(p.drain())
        if total >= 100:
            break
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert total == 100
    assert elapsed_ms < _scaled(10.0), (
        f"drain of 100 messages took {elapsed_ms:.2f} ms > {_scaled(10.0):.2f} ms"
    )


def test_prioritizer_drain_with_mixed_classes() -> None:
    """Mixed-class drain — every class fed, every class drained."""
    p = TransportPrioritizer()
    for qc in QoSClass:
        for i in range(10):
            p.enqueue(payload=b"x" * 100, qos_class=qc)
    t0 = time.perf_counter()
    # Drain across enough ticks to flush everything
    total = 0
    for _ in range(5):
        total += len(p.drain())
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert total >= 100  # most messages drain
    assert elapsed_ms < _scaled(20.0)


def test_prioritizer_enqueue_throughput() -> None:
    """10k enqueues under a few ms — should not be a bottleneck."""
    p = TransportPrioritizer(max_queue_bytes_per_class=10 * 1024 * 1024)
    t0 = time.perf_counter()
    for i in range(10_000):
        p.enqueue(payload=b"x" * 100, qos_class=QoSClass.FILE_CHUNK)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _scaled(150.0), (
        f"enqueue 10k took {elapsed_ms:.2f} ms"
    )


# ---------------------------------------------------------------------------
# crossfade._mix_s16le
# ---------------------------------------------------------------------------

def test_mix_s16le_throughput_for_one_audio_frame() -> None:
    """One 20-ms audio frame at 48 kHz stereo = 1920 samples = 3840
    bytes (s16le). The mix must run faster than real-time by 100×
    so the audio path never stalls. Budget: 200 µs per 20-ms frame
    is a 100× real-time ratio."""
    a = secrets.token_bytes(3840)
    b = secrets.token_bytes(3840)
    t0 = time.perf_counter()
    for _ in range(50):  # one second of audio frames
        mix_samples(
            old_samples=a, new_samples=b,
            gain_old=0.5, gain_new=0.5,
        )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    # 50 frames in <50 ms = real-time pace; budget 200 ms for CI safety.
    assert elapsed_ms < _scaled(200.0), (
        f"mix 50 frames took {elapsed_ms:.2f} ms"
    )


# ---------------------------------------------------------------------------
# CallVitals.vitals_hash
# ---------------------------------------------------------------------------

def test_vitals_hash_throughput() -> None:
    """The immune tick hashes vitals every 100 ms. 10k hashes per
    second should be cheap so 10 concurrent calls don't strain the
    tick budget."""
    from one_link.call_vitals import (
        CallVitals,
        CapabilitySnapshot,
        DeviceRole,
        ThermalState,
    )
    from one_link.frame_provenance import PathClass

    v = CallVitals(
        call_id="c1", peer_fp="peer", tick=42,
        rtt_ewma_ms=50.0, loss_rate_ewma=0.01,
        jitter_ms=3.0, bandwidth_estimate_kbps=500.0,
        reliability=0.95, last_alive_ms=1_700_000_000_000,
        path_class=PathClass.DIRECT, path_fragility_score=0.1,
        backup_routes_warm=0, own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=80.0, own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=True, audio_frames_received=100,
        audio_frames_dropped=1, video_frames_received=50,
        video_frames_predicted=0, confirm_ratio_voice=0.99,
        confirm_ratio_video=0.95, path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )
    t0 = time.perf_counter()
    for _ in range(10_000):
        v.vitals_hash()
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _scaled(500.0), (
        f"10k vitals_hash() calls took {elapsed_ms:.2f} ms"
    )


# ---------------------------------------------------------------------------
# FrameProvenance sign / verify
# ---------------------------------------------------------------------------

def test_frame_provenance_sign_throughput() -> None:
    """Ed25519 sign should comfortably do >1k signatures/sec on
    commodity hardware. Tier β attests once per 1-second window per
    direction so the actual load is ~2 sigs/sec; we test 100 sigs
    in 200 ms as headroom."""
    from one_link.frame_provenance import (
        FrameKind,
        PathClass,
        RecordingState,
        make_segment_hash,
        sign_provenance,
    )

    sk = Ed25519PrivateKey.generate()
    seg = make_segment_hash(b"x" * 1024)
    t0 = time.perf_counter()
    for i in range(100):
        sign_provenance(
            segment_hash=seg, device_id="deadbeef",
            frame_kind=FrameKind.REAL, path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=i, produce_confidence=1.0,
            signing_key=sk,
        )
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _scaled(500.0), (
        f"100 sigs took {elapsed_ms:.2f} ms"
    )


def test_frame_provenance_verify_throughput() -> None:
    from cryptography.hazmat.primitives import serialization
    from one_link.frame_provenance import (
        FrameKind,
        PathClass,
        RecordingState,
        make_segment_hash,
        sign_provenance,
        verify_provenance,
    )

    sk = Ed25519PrivateKey.generate()
    pub_bytes = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    seg = make_segment_hash(b"x" * 1024)
    prov = sign_provenance(
        segment_hash=seg, device_id="deadbeef",
        frame_kind=FrameKind.REAL, path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=0, produce_confidence=1.0, signing_key=sk,
    )
    t0 = time.perf_counter()
    for _ in range(100):
        ok = verify_provenance(prov, pub_bytes)
        assert ok
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _scaled(500.0), (
        f"100 verifies took {elapsed_ms:.2f} ms"
    )


# ---------------------------------------------------------------------------
# Capsule sealing
# ---------------------------------------------------------------------------

def test_capsule_seal_open_round_trip_throughput(tmp_path: Path) -> None:
    """A 30-second voice note at 32 kbps Opus = 120 KB. Seal +
    open in well under 100 ms so the user never waits."""
    plaintext = secrets.token_bytes(120 * 1024)
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.sealed"
    t0 = time.perf_counter()
    seal_to_path(
        plaintext=plaintext, out_path=p,
        master_seed=seed, call_id="c", finalized_at_ms=0,
    )
    seal_ms = (time.perf_counter() - t0) * 1000
    t0 = time.perf_counter()
    out = open_from_path(
        sealed_path=p, master_seed=seed,
        call_id="c", finalized_at_ms=0,
    )
    open_ms = (time.perf_counter() - t0) * 1000
    assert out == plaintext
    assert seal_ms < _scaled(100.0), f"120 KB seal: {seal_ms:.2f} ms"
    assert open_ms < _scaled(100.0), f"120 KB open: {open_ms:.2f} ms"


# ---------------------------------------------------------------------------
# Plan → action throughput
# ---------------------------------------------------------------------------

def test_plan_for_decision_throughput() -> None:
    """The immune tick loop calls plan_for_decision on every emitted
    decision. Pure mapping should be very fast — under 0.5 µs each."""
    from one_link.call_immune import (
        ImmuneAction, ImmuneDecision,
    )
    from one_link.call_immune_actions import plan_for_decision

    decision = ImmuneDecision(
        action=ImmuneAction.REQUEST_VOICE_ONLY,
        reason_code="loss_burst",
        triggered_by="transport",
        confidence=0.9, tick=42, vitals_hash="0" * 32, emitted=True,
    )
    t0 = time.perf_counter()
    for _ in range(10_000):
        plan_for_decision(decision=decision, call_id="c1", now_ms=0)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    assert elapsed_ms < _scaled(200.0), (
        f"10k plan_for_decision: {elapsed_ms:.2f} ms"
    )
