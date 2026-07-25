"""Predictive Continuity ↔ Reality Engine ↔ Immune System integration.

The Predictive Continuity engine is upstream of two other systems:

  - The Reality Engine: every predicted frame must be tagged
    ``FrameKind.PREDICTED`` so the Reality dot in the UI never
    claims a predicted frame is real.

  - The Immune System: the confirm_ratio metric flows BACK into
    CallVitals as ``confirm_ratio_voice`` / ``confirm_ratio_video``.
    The Immune System's voice-safe override consults this — if
    voice prediction is locked at near-perfect confirm, RTT spikes
    can be deferred (the user is fine).

These integration tests prove both wirings.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_immune import (
    Arbitrator,
    ImmuneAction,
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
from one_link.predictive_continuity import (
    MediaFrame,
    MediaKind,
    PredictiveContinuity,
)


# ---------------------------------------------------------------------------
# Fixtures
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


@pytest.fixture
def alice() -> Identity:
    return _identity("alice-predcont")


def _vitals(tick: int, **over) -> CallVitals:
    base = dict(
        call_id="call-0",
        peer_fp="peer-0",
        tick=tick,
        rtt_ewma_ms=50.0,
        loss_rate_ewma=0.0,
        jitter_ms=0.0,
        bandwidth_estimate_kbps=2000.0,
        reliability=1.0,
        last_alive_ms=1_700_000_000_000 + tick * 100,
        path_class=PathClass.LAN,
        path_fragility_score=0.0,
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=80.0,
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
    return CallVitals(**base)


# ---------------------------------------------------------------------------
# Reality Engine integration: predicted frames are tagged
# ---------------------------------------------------------------------------

def test_predicted_frame_carries_predicted_frame_kind() -> None:
    """The Reality Engine reads frame_kind to render the badge.
    Every output of Predictive Continuity must be unambiguously
    tagged so the user never sees a predicted frame labeled
    'Real'."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)

    # Real seed
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=10, timestamp_us=0, content=b"steady",
        frame_kind=FrameKind.REAL,
    ))

    # Predicted frame for the next slot
    result = eng.on_frame_due(stream_id="voice", expected_seq=11, now_us=100)
    assert result.frame is not None
    assert result.frame.frame_kind == FrameKind.PREDICTED


def test_blank_frame_carries_blank_frame_kind() -> None:
    """When lookahead budget exhausts, the BLANK frame is tagged
    accordingly. The Reality dot then shows 'Blank' so the user
    knows the channel is silent."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=10, timestamp_us=0, content=b"seed",
        frame_kind=FrameKind.REAL,
    ))
    # Burn through the audio lookahead budget (4 frames)
    for i in range(4):
        eng.on_frame_due(stream_id="voice", expected_seq=11 + i, now_us=100)
    # Next call: BLANK
    result = eng.on_frame_due(stream_id="voice", expected_seq=15, now_us=100)
    assert result.frame is not None
    assert result.frame.frame_kind == FrameKind.BLANK


def test_predicted_frame_signed_by_reality_engine(alice: Identity) -> None:
    """A predicted frame ALSO carries FrameProvenance from the
    sender (in real usage, the sender's daemon predicts forward of
    its own pipeline too, and signs the predicted output). The
    receiver verifies — and reads frame_kind=PREDICTED, so the
    Reality dot says 'Predicted' rather than 'Real'."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=10, timestamp_us=0, content=b"seed-content",
        frame_kind=FrameKind.REAL,
    ))
    result = eng.on_frame_due(stream_id="voice", expected_seq=11, now_us=100)
    assert result.frame is not None

    # Sender signs the predicted content with frame_kind=PREDICTED.
    prov = sign_provenance(
        segment_hash=make_segment_hash(result.frame.content),
        device_id=alice.short_id,
        frame_kind=result.frame.frame_kind,    # PREDICTED — never REAL
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=100,
        produce_confidence=0.85,                # lower confidence for predictions
        signing_key=alice.private,
    )
    # Receiver verifies the signature — but reads frame_kind to
    # render the Reality dot correctly.
    assert verify_provenance(prov, alice.public_bytes)
    assert prov.frame_kind == FrameKind.PREDICTED


# ---------------------------------------------------------------------------
# Immune System integration: confirm_ratio_voice from PredictiveContinuity
# feeds into CallVitals → voice-safe override
# ---------------------------------------------------------------------------

def test_high_confirm_ratio_lets_immune_defer_prewarm() -> None:
    """When voice prediction is locked (confirm ~ 1.0), the Immune
    System's voice-safe override should defer prewarm requests
    even if RTT is high — the user is not being harmed.

    The integration: PredictiveContinuity.confirm_ratio('voice') →
    fed into CallVitals.confirm_ratio_voice → the Arbitrator's
    voice-safe override fires."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)

    # Establish a long stable run of confirmed predictions.
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=b"steady",
        frame_kind=FrameKind.REAL,
    ))
    for seq in range(1, 20):
        eng.on_frame_due(stream_id="voice", expected_seq=seq, now_us=0)
        eng.on_real_frame_arrives(real=MediaFrame(
            stream_id="voice", media_kind=MediaKind.AUDIO,
            seq=seq, timestamp_us=0, content=b"steady",
            frame_kind=FrameKind.REAL,
        ))
    ratio = eng.confirm_ratio("voice")
    assert ratio >= 0.98

    # Now build CallVitals with this confirm ratio + a high RTT.
    arb = Arbitrator()
    v = _vitals(
        tick=0,
        rtt_ewma_ms=500.0,           # crosses prewarm trigger
        confirm_ratio_voice=ratio,    # but voice is locked
        loss_rate_ewma=0.0,
    )
    decision = arb.decide(v)
    # Voice-safe override fires; HOLD instead of PREWARM.
    assert decision.action == ImmuneAction.HOLD
    assert decision.reason_code == "voice_safe_override"


def test_low_confirm_ratio_lets_immune_act_on_rtt() -> None:
    """When voice prediction is struggling (lots of corrections),
    confirm_ratio drops; the voice-safe override no longer fires,
    and the Immune System acts on RTT crossings."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)

    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=b"\x00\x00",
        frame_kind=FrameKind.REAL,
    ))
    # Predict + correct repeatedly — predictions wrong.
    for seq in range(1, 20):
        eng.on_frame_due(stream_id="voice", expected_seq=seq, now_us=0)
        eng.on_real_frame_arrives(real=MediaFrame(
            stream_id="voice", media_kind=MediaKind.AUDIO,
            seq=seq, timestamp_us=0,
            content=bytes([seq % 256, (seq * 7) % 256]),  # different each time
            frame_kind=FrameKind.REAL,
        ))
    low_ratio = eng.confirm_ratio("voice")
    assert low_ratio < 0.5

    arb = Arbitrator()
    v = _vitals(tick=0, rtt_ewma_ms=500.0, confirm_ratio_voice=low_ratio)
    decision = arb.decide(v)
    # No voice-safe override — Immune System acts.
    assert decision.action == ImmuneAction.PREWARM_BACKUP_ROUTE


# ---------------------------------------------------------------------------
# Predictive negative latency: ratio > 0.98 IS the goal
# ---------------------------------------------------------------------------

def test_perfectly_stable_voice_hits_negative_latency_threshold() -> None:
    """At confirm_ratio >= 0.98, the receiver is rendering AHEAD
    of the wire — the Living Presence 'predictive negative
    latency' guarantee. This test is the inequality check."""
    eng = PredictiveContinuity()
    eng.register_stream("voice", MediaKind.AUDIO)
    eng.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=0, timestamp_us=0, content=b"silence",
        frame_kind=FrameKind.REAL,
    ))
    # 100 ticks of stable-content confirmations.
    for seq in range(1, 101):
        eng.on_frame_due(stream_id="voice", expected_seq=seq, now_us=0)
        eng.on_real_frame_arrives(real=MediaFrame(
            stream_id="voice", media_kind=MediaKind.AUDIO,
            seq=seq, timestamp_us=0, content=b"silence",
            frame_kind=FrameKind.REAL,
        ))
    assert eng.confirm_ratio("voice") >= 0.98
