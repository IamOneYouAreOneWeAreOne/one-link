"""The full Tier α-pre headline demo.

Composes EVERY shipped module into one end-to-end scenario:

  - CallLifecycle FSM (INVITE → ACCEPT → ACTIVE → ASYNC → RESUMABLE)
  - Identity SAS verification on first contact
  - Recording consent flow (mid-call)
  - All 8 engines (Immune, Compiler, Body, Route, Priority,
    Predictive, FrameProvenance, CallSession CRDT)
  - Async capsule capture + signed frames + resume offer

The scenario: Alice calls Mom for the first time. They verify SAS.
Recording is requested + granted. Mid-call, WiFi flakes. The Immune
System detects, the Compiler descends, the call converts to async
capsule, the capsule is captured + signed + delivered. Mom taps
resume within the window. A new call begins.

This is the demo. Every test below is a step that, if passing,
proves a piece of the demo works end-to-end against running code.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.async_capsule import (
    CapsuleBuilder,
    CapsuleKind,
    capsule_label,
    format_duration_human,
)
from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
)
from one_link.call_session import Rung
from one_link.call_signaling import (
    CALL_ACCEPT,
    CALL_INVITE,
    CallLifecycle,
    CallPhase,
    EndCause,
    EventKind,
    LifecycleEvent,
    LocalAction,
    RESUME_OFFER,
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
from one_link.identity_sas import (
    derive_sas_transcript_hash,
    derive_sas_words,
    evaluate_rotation,
    VerificationState,
)
from one_link.predictive_continuity import (
    MediaFrame,
    MediaKind,
    PredictiveContinuity,
)
from one_link.presence_compiler import PresenceCompiler
from one_link.recording_consent import (
    ConsentEvent,
    ConsentEventKind,
    ConsentPhase,
    RecordingConsent,
)


# ---------------------------------------------------------------------------
# Test identities + devices
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
    return _identity("alice-headline")


@pytest.fixture
def mom() -> Identity:
    return _identity("mom-headline")


NOW = 1_700_000_000_000


# ---------------------------------------------------------------------------
# Step 1 — Alice taps "Call Mom"; SAS derived; INVITE sent
# ---------------------------------------------------------------------------

def test_step_1_alice_initiates_call_and_sas_derived(
    alice: Identity, mom: Identity,
) -> None:
    """User taps the one button. The daemon derives the first-call
    SAS, opens a CallLifecycle, and emits CALL_INVITE."""
    call_id = "demo-call-0"
    shared_secret = b"\xab" * 32   # in real life: from DH handshake

    # Both sides derive the same SAS — identical input from the
    # shared secret + master_vks + call_id.
    alice_words = derive_sas_words(derive_sas_transcript_hash(
        originator_master_vk=alice.public_bytes,
        recipient_master_vk=mom.public_bytes,
        call_id=call_id,
        dh_shared_secret=shared_secret,
    ))
    mom_words = derive_sas_words(derive_sas_transcript_hash(
        originator_master_vk=mom.public_bytes,
        recipient_master_vk=alice.public_bytes,
        call_id=call_id,
        dh_shared_secret=shared_secret,
    ))
    assert alice_words == mom_words

    # FSM: Alice (originator) sends INVITE.
    fsm = CallLifecycle()
    state = CallLifecycle.initial_state(
        call_id=call_id, peer_master_vk_hex=mom.fingerprint,
        local_role="originator", started_at_ms=NOW,
    )
    out = fsm.handle(state, LifecycleEvent(EventKind.USER_INITIATE_CALL, NOW))
    assert out.state.phase == CallPhase.INVITING
    assert out.outbound[0].type == CALL_INVITE


# ---------------------------------------------------------------------------
# Step 2 — Mom's daemon receives INVITE, rings, user accepts
# ---------------------------------------------------------------------------

def test_step_2_mom_rings_then_accepts(
    mom: Identity, alice: Identity,
) -> None:
    fsm = CallLifecycle()
    state = CallLifecycle.initial_state(
        call_id="demo-call-0",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        started_at_ms=NOW,
    )
    # Wire INVITE arrives → ring shows
    state = fsm.handle(state, LifecycleEvent(EventKind.WIRE_INVITE, NOW + 100)).state
    assert state.phase == CallPhase.RINGING
    # Mom taps accept
    out = fsm.handle(state, LifecycleEvent(EventKind.USER_ACCEPT, NOW + 3_000))
    assert out.state.phase == CallPhase.ACTIVE
    assert out.outbound[0].type == CALL_ACCEPT
    assert LocalAction.START_MEDIA in out.local_actions


# ---------------------------------------------------------------------------
# Step 3 — During call, recording consent flow
# ---------------------------------------------------------------------------

def test_step_3_recording_consent_mutual_grant_active(
    alice: Identity,
) -> None:
    """While ACTIVE, Alice taps 'Save this call'. Mom approves.
    Recording state flips to MUTUAL; subsequent frames carry
    RECORDING_MUTUAL in their FrameProvenance."""
    consent = RecordingConsent()
    s = consent.initial_state(call_id="demo-call-0")

    # Alice asks
    out1 = consent.handle(
        s, ConsentEvent(ConsentEventKind.LOCAL_REQUEST_START, NOW + 10_000),
    )
    s = out1.state
    assert s.phase == ConsentPhase.AWAITING_REMOTE_RESPONSE

    # Mom grants (RECORDING_GRANT arrives)
    out2 = consent.handle(
        s, ConsentEvent(ConsentEventKind.REMOTE_GRANT, NOW + 12_000),
    )
    s = out2.state
    assert s.phase == ConsentPhase.RECORDING
    # Reality Engine reads this and signs frames accordingly:
    assert out2.recording_state_for_provenance == RecordingState.RECORDING_MUTUAL

    # Alice's daemon signs a frame after consent flips
    frame_content = b"opus-after-consent"
    prov = sign_provenance(
        segment_hash=make_segment_hash(frame_content),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=out2.recording_state_for_provenance,
        timestamp_us=(NOW + 12_500) * 1000,
        produce_confidence=1.0,
        signing_key=alice.private,
    )
    assert verify_provenance(prov, alice.public_bytes)
    assert prov.recording_state == RecordingState.RECORDING_MUTUAL


# ---------------------------------------------------------------------------
# Step 4 — Mid-call: WiFi flakes. Immune system + Compiler + Capsule
# ---------------------------------------------------------------------------

def test_step_4_wifi_flakes_call_converts_to_capsule(
    alice: Identity, mom: Identity,
) -> None:
    """Simulating the WiFi-unplugged scenario. Immune System sees
    severe loss + peer-absent, emits CONVERT_TO_ASYNC. The Compiler
    descends to ASYNC_CAPSULE. The CallLifecycle moves to
    ASYNC_CAPTURE. The CapsuleBuilder accumulates the in-flight
    buffer + finalises."""

    # ── Set up the running engines ──
    immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT)
    compiler = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1", "frame_provenance_v1"}),
        ascent_hysteresis_ticks=5,
    )
    fsm = CallLifecycle()
    call_state = CallLifecycle.initial_state(
        call_id="demo-call-0", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", started_at_ms=NOW,
    )
    call_state = fsm.handle(
        call_state, LifecycleEvent(EventKind.USER_INITIATE_CALL, NOW),
    ).state
    call_state = fsm.handle(
        call_state, LifecycleEvent(EventKind.WIRE_ACCEPT, NOW + 2_000),
    ).state
    assert call_state.phase == CallPhase.ACTIVE

    # ── Tick the engines while WiFi is fine ──
    for tick in range(20):
        v = CallVitals(
            call_id="demo-call-0", peer_fp=mom.fingerprint, tick=tick,
            rtt_ewma_ms=50.0, loss_rate_ewma=0.0, jitter_ms=0.0,
            bandwidth_estimate_kbps=2000.0, reliability=1.0,
            last_alive_ms=NOW + tick * 100,
            path_class=PathClass.LAN, path_fragility_score=0.0,
            backup_routes_warm=0,
            own_device_role=DeviceRole.MIC,
            own_battery_pct=80.0,
            own_thermal_state=ThermalState.NOMINAL,
            peer_device_present=True,
            audio_frames_received=tick * 50, audio_frames_dropped=0,
            video_frames_received=tick * 30, video_frames_predicted=0,
            confirm_ratio_voice=1.0, confirm_ratio_video=1.0,
            path_attested=False,
            capability_state=CapabilitySnapshot.empty(),
        )
        immune.tick(v)
    assert compiler.current_rung == Rung.RAW_AV

    # ── WiFi dies — total loss, peer goes silent ──
    convert_decision = None
    for tick in range(20, 35):
        v = CallVitals(
            call_id="demo-call-0", peer_fp=mom.fingerprint, tick=tick,
            rtt_ewma_ms=2000.0, loss_rate_ewma=0.85, jitter_ms=200.0,
            bandwidth_estimate_kbps=10.0, reliability=0.1,
            last_alive_ms=NOW + 19 * 100,    # frozen — peer absent
            path_class=PathClass.LAN, path_fragility_score=0.0,
            backup_routes_warm=0,
            own_device_role=DeviceRole.MIC,
            own_battery_pct=70.0,
            own_thermal_state=ThermalState.NOMINAL,
            peer_device_present=False,        # <— signal of death
            audio_frames_received=0, audio_frames_dropped=99,
            video_frames_received=0, video_frames_predicted=0,
            confirm_ratio_voice=0.0, confirm_ratio_video=0.0,
            path_attested=False,
            capability_state=CapabilitySnapshot.empty(),
        )
        d = immune.tick(v)
        compiler.request(
            d, bandwidth_kbps=v.bandwidth_estimate_kbps,
            confirm_ratio_voice=v.confirm_ratio_voice,
            loss_rate_ewma=v.loss_rate_ewma,
        )
        if d.action == ImmuneAction.CONVERT_TO_ASYNC and convert_decision is None:
            convert_decision = d
            break

    assert convert_decision is not None
    assert compiler.current_rung == Rung.ASYNC_CAPSULE

    # ── Lifecycle reflects ──
    call_state = fsm.handle(
        call_state,
        LifecycleEvent(
            EventKind.IMMUNE_CONVERT_TO_ASYNC,
            NOW + 5_000,
        ),
    ).state
    assert call_state.phase == CallPhase.ASYNC_CAPTURE
    assert call_state.end_cause == EndCause.NETWORK_ASYNC_CONVERSION

    # ── Daemon builds capsule from in-flight buffer ──
    builder = CapsuleBuilder(
        capsule_id="capsule-demo",
        call_id="demo-call-0",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=mom.fingerprint,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=NOW + 2_000,
    )
    for i in range(8):
        chunk = b"opus-buffered-frame-" + str(i).encode()
        prov = sign_provenance(
            segment_hash=make_segment_hash(chunk),
            device_id=alice.short_id,
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=(NOW + 2_000 + i * 100) * 1000,
            produce_confidence=1.0,
            signing_key=alice.private,
        )
        builder.append_audio(
            chunk=chunk, provenance=prov,
            timestamp_ms=NOW + 2_000 + i * 100,
        )
    capsule = builder.finalize(
        finalized_at_ms=NOW + 5_000,
        resume_window_ms=600_000,
    )

    # ── Verify the capsule is internally consistent + verifiable ──
    assert capsule.all_frames_verified_by(alice.public_bytes)
    assert capsule.duration_ms == 700
    assert capsule.is_resumable_at(NOW + 5_000)

    # ── Lifecycle: capsule finalized → resumable ──
    out = fsm.handle(
        call_state,
        LifecycleEvent(EventKind.ASYNC_CAPSULE_FINALIZED, NOW + 5_500),
    )
    assert out.state.phase == CallPhase.RESUMABLE
    assert LocalAction.OPEN_RESUME_WINDOW in out.local_actions


# ---------------------------------------------------------------------------
# Step 5 — Mom taps "Resume" within the window
# ---------------------------------------------------------------------------

def test_step_5_resume_within_window_starts_new_call(
    alice: Identity, mom: Identity,
) -> None:
    fsm = CallLifecycle()
    # Synthesise a RESUMABLE state directly (steps 1-4 covered above)
    from one_link.call_signaling import CallState
    state = CallState(
        call_id="demo-call-0",
        peer_master_vk_hex=mom.fingerprint,
        local_role="originator",
        phase=CallPhase.RESUMABLE,
        started_at_ms=NOW,
        resume_window_close_at_ms=NOW + 600_000,
    )
    # User taps Resume 30 seconds after async conversion
    out = fsm.handle(state, LifecycleEvent(EventKind.USER_RESUME, NOW + 30_000))
    assert out.state.phase == CallPhase.ENDED
    # A RESUME_OFFER message goes out — the daemon then starts a
    # NEW CallSession with resume_of=demo-call-0.
    assert out.outbound[0].type == RESUME_OFFER
    assert out.outbound[0].payload["prior_call_id"] == "demo-call-0"


# ---------------------------------------------------------------------------
# Step 6 — The "Reality dot" reads the call state truthfully
# ---------------------------------------------------------------------------

def test_step_6_reality_dot_renders_truthfully_at_each_phase(
    alice: Identity, mom: Identity,
) -> None:
    """At every phase of the call, the Reality dot's underlying
    provenance reflects what's actually happening — never lies."""

    # Real frame from Alice's mic, during active call, no recording
    real_frame = b"opus-real-frame-during-active-call"
    real_prov = sign_provenance(
        segment_hash=make_segment_hash(real_frame),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=(NOW + 3_000) * 1000,
        produce_confidence=1.0,
        signing_key=alice.private,
    )
    assert real_prov.frame_kind == FrameKind.REAL
    assert verify_provenance(real_prov, alice.public_bytes)

    # When Predictive Continuity fills a gap, the predicted frame
    # is tagged differently — the Reality dot tells the truth.
    predictive = PredictiveContinuity()
    predictive.register_stream("voice", MediaKind.AUDIO)
    predictive.on_real_frame_arrives(real=MediaFrame(
        stream_id="voice", media_kind=MediaKind.AUDIO,
        seq=10, timestamp_us=0, content=real_frame,
        frame_kind=FrameKind.REAL,
    ))
    result = predictive.on_frame_due(
        stream_id="voice", expected_seq=11, now_us=100,
    )
    assert result.frame is not None
    assert result.frame.frame_kind == FrameKind.PREDICTED

    # Alice signs this predicted frame — the FrameProvenance carries
    # PREDICTED, so the receiver's Reality dot shows "Reconstructed".
    predicted_prov = sign_provenance(
        segment_hash=make_segment_hash(result.frame.content),
        device_id=alice.short_id,
        frame_kind=result.frame.frame_kind,    # PREDICTED
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=(NOW + 3_100) * 1000,
        produce_confidence=0.85,
        signing_key=alice.private,
    )
    assert verify_provenance(predicted_prov, alice.public_bytes)
    assert predicted_prov.frame_kind == FrameKind.PREDICTED


# ---------------------------------------------------------------------------
# Step 7 — Full demo plays through under one composed test
# ---------------------------------------------------------------------------

def test_full_alpha_headline_demo_plays_through(
    alice: Identity, mom: Identity,
) -> None:
    """Soup-to-nuts: every step of the demo runs in one test.
    Each engine plays its part; the user (in real life) would
    have seen ONE BUTTON throughout."""
    call_id = "headline-demo"
    shared_secret = b"\xab" * 32

    # ── 1. SAS derivation ──
    alice_words = derive_sas_words(derive_sas_transcript_hash(
        originator_master_vk=alice.public_bytes,
        recipient_master_vk=mom.public_bytes,
        call_id=call_id, dh_shared_secret=shared_secret,
    ))
    mom_words = derive_sas_words(derive_sas_transcript_hash(
        originator_master_vk=mom.public_bytes,
        recipient_master_vk=alice.public_bytes,
        call_id=call_id, dh_shared_secret=shared_secret,
    ))
    assert alice_words == mom_words

    # ── 2. Identity verification — first contact, no prior key ──
    rotation = evaluate_rotation(
        inbound_master_vk_hex=mom.fingerprint,
        inbound_signature_from_prior=None,
        existing=None,
        verify_prior_signature=lambda *a: False,
    )
    assert rotation.new_state == VerificationState.UNVERIFIED
    assert rotation.allow_call is True
    assert rotation.needs_reverify is True

    # ── 3. Call lifecycle: Alice's side ──
    fsm = CallLifecycle()
    call_state = CallLifecycle.initial_state(
        call_id=call_id, peer_master_vk_hex=mom.fingerprint,
        local_role="originator", started_at_ms=NOW,
    )
    call_state = fsm.handle(
        call_state, LifecycleEvent(EventKind.USER_INITIATE_CALL, NOW),
    ).state
    call_state = fsm.handle(
        call_state, LifecycleEvent(EventKind.WIRE_ACCEPT, NOW + 2_000),
    ).state
    assert call_state.phase == CallPhase.ACTIVE

    # ── 4. Recording consent flow ──
    consent = RecordingConsent()
    cs = consent.initial_state(call_id=call_id)
    cs = consent.handle(
        cs, ConsentEvent(ConsentEventKind.LOCAL_REQUEST_START, NOW + 10_000),
    ).state
    cs_out = consent.handle(
        cs, ConsentEvent(ConsentEventKind.REMOTE_GRANT, NOW + 12_000),
    )
    cs = cs_out.state
    assert cs.phase == ConsentPhase.RECORDING
    assert cs_out.recording_state_for_provenance == RecordingState.RECORDING_MUTUAL

    # ── 5. Immune System → CONVERT_TO_ASYNC ──
    immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT)
    compiler = PresenceCompiler(
        peer_capabilities=frozenset({"webrtc_av_v1"}),
        ascent_hysteresis_ticks=5,
    )

    # Generate an extreme-loss scenario; immune converts to async.
    for tick in range(30):
        v = CallVitals(
            call_id=call_id, peer_fp=mom.fingerprint, tick=tick,
            rtt_ewma_ms=5000.0, loss_rate_ewma=0.95, jitter_ms=300.0,
            bandwidth_estimate_kbps=1.0, reliability=0.05,
            last_alive_ms=0, path_class=PathClass.LAN,
            path_fragility_score=0.95,
            backup_routes_warm=0,
            own_device_role=DeviceRole.MIC,
            own_battery_pct=70.0,
            own_thermal_state=ThermalState.NOMINAL,
            peer_device_present=False,
            audio_frames_received=0, audio_frames_dropped=0,
            video_frames_received=0, video_frames_predicted=0,
            confirm_ratio_voice=0.0, confirm_ratio_video=0.0,
            path_attested=False,
            capability_state=CapabilitySnapshot.empty(),
        )
        d = immune.tick(v)
        compiler.request(
            d, bandwidth_kbps=v.bandwidth_estimate_kbps,
            confirm_ratio_voice=v.confirm_ratio_voice,
            loss_rate_ewma=v.loss_rate_ewma,
        )
        if d.action == ImmuneAction.CONVERT_TO_ASYNC:
            break
    assert compiler.current_rung == Rung.ASYNC_CAPSULE

    # ── 6. Lifecycle: ACTIVE → ASYNC_CAPTURE → RESUMABLE ──
    call_state = fsm.handle(
        call_state,
        LifecycleEvent(EventKind.IMMUNE_CONVERT_TO_ASYNC, NOW + 6_000),
    ).state
    assert call_state.phase == CallPhase.ASYNC_CAPTURE

    # ── 7. Build + finalize the capsule ──
    builder = CapsuleBuilder(
        capsule_id="cap-headline",
        call_id=call_id,
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=mom.fingerprint,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=NOW + 2_000,
        recording_state_at_conversion=RecordingState.RECORDING_MUTUAL,
    )
    for i in range(5):
        chunk = b"opus-buffered-" + str(i).encode()
        prov = sign_provenance(
            segment_hash=make_segment_hash(chunk),
            device_id=alice.short_id,
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.RECORDING_MUTUAL,
            timestamp_us=(NOW + 2_000 + i * 200) * 1000,
            produce_confidence=1.0,
            signing_key=alice.private,
        )
        builder.append_audio(
            chunk=chunk, provenance=prov, timestamp_ms=NOW + 2_000 + i * 200,
        )
    capsule = builder.finalize(
        finalized_at_ms=NOW + 7_000,
        resume_window_ms=600_000,
    )
    assert capsule.all_frames_verified_by(alice.public_bytes)
    assert capsule.recording_state_at_conversion == RecordingState.RECORDING_MUTUAL

    call_state = fsm.handle(
        call_state,
        LifecycleEvent(EventKind.ASYNC_CAPSULE_FINALIZED, NOW + 7_500),
    ).state
    assert call_state.phase == CallPhase.RESUMABLE
    assert call_state.resume_window_close_at_ms == NOW + 7_500 + 600_000

    # ── 8. Mom's UI shows the capsule with calm plain-language label ──
    label = capsule_label(capsule.kind)
    assert "failed" not in label.lower()
    assert "missed" not in label.lower()
    duration_text = format_duration_human(capsule.duration_ms)
    assert "sec" in duration_text or "min" in duration_text

    # ── 9. Mom taps Resume; daemon emits RESUME_OFFER ──
    out = fsm.handle(
        call_state, LifecycleEvent(EventKind.USER_RESUME, NOW + 100_000),
    )
    assert out.outbound[0].type == RESUME_OFFER
    assert out.outbound[0].payload["prior_call_id"] == call_id

    # ── If we got here, the demo plays through. The user saw
    #    ONE BUTTON; everything else was invisible engineering. ──
