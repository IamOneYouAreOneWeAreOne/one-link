"""Tests for the CallManager — the per-call orchestrator."""

from __future__ import annotations

import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.async_capsule import CapsuleKind
from one_link.call_manager import (
    CallManager,
    CallManagerRegistry,
    ManagerEvent,
    ManagerEventKind,
    ManagerOutput,
    TailEventKind,
)
from one_link.call_session import EndReason, Intensity
from one_link.call_signaling import (
    CALL_ACCEPT,
    CALL_END,
    CALL_INVITE,
    CallPhase,
    EndCause,
    LocalAction,
    RESUME_OFFER,
)
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)
from one_link.identity import Identity
from one_link.recording_consent import (
    RECORDING_GRANT,
    RECORDING_REQUEST,
    RECORDING_STOP,
    ConsentPhase,
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
    return _identity("alice-mgr")


@pytest.fixture
def mom() -> Identity:
    return _identity("mom-mgr")


def _new_originator(alice: Identity, mom: Identity) -> CallManager:
    return CallManager(
        call_id="call-mgr-test",
        peer_master_vk_hex=mom.fingerprint,
        local_role="originator",
        local_master_vk_hex=alice.fingerprint,
        started_at_ms=1_000,
        negotiated_capabilities=frozenset({"webrtc_av_v1", "frame_provenance_v1"}),
    )


def _new_recipient(mom: Identity, alice: Identity) -> CallManager:
    return CallManager(
        call_id="call-mgr-test",
        peer_master_vk_hex=alice.fingerprint,
        local_role="recipient",
        local_master_vk_hex=mom.fingerprint,
        started_at_ms=1_000,
        negotiated_capabilities=frozenset({"webrtc_av_v1", "frame_provenance_v1"}),
    )


# ---------------------------------------------------------------------------
# Initial state
# ---------------------------------------------------------------------------

def test_originator_initial_state(alice: Identity, mom: Identity) -> None:
    m = _new_originator(alice, mom)
    assert m.phase == CallPhase.INVITING
    assert m.consent_phase == ConsentPhase.NONE
    assert m.current_recording_state == RecordingState.NOT_RECORDING
    # Originator opened the dial to HIGH on construction.
    s = m.session_snapshot()
    assert s.current_intensity == Intensity.HIGH


def test_recipient_initial_state(mom: Identity, alice: Identity) -> None:
    m = _new_recipient(mom, alice)
    assert m.phase == CallPhase.INVITING
    # Recipient hasn't opened the dial yet.
    s = m.session_snapshot()
    assert s.current_intensity == Intensity.AMBIENT


def test_call_manager_holds_negotiated_capabilities(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    s = m.session_snapshot()
    assert "frame_provenance_v1" in s.negotiated_capabilities


# ---------------------------------------------------------------------------
# Originator happy path
# ---------------------------------------------------------------------------

def test_originator_user_initiate_emits_invite(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.USER_INITIATE_CALL, occurred_at_ms=2_000,
    ))
    assert len(out.outbound_msgs) == 1
    assert out.outbound_msgs[0].type == CALL_INVITE
    assert LocalAction.START_INVITE_TIMER in out.local_actions
    # No phase change yet (still INVITING).
    phase_events = [e for e in out.tail_events if e.kind == TailEventKind.PHASE_CHANGED]
    assert phase_events == []


def test_originator_active_on_wire_accept(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 2_000))
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.WIRE_CALL_ACCEPT, occurred_at_ms=3_500,
    ))
    assert m.phase == CallPhase.ACTIVE
    # Tail event: phase changed.
    phase_events = [e for e in out.tail_events if e.kind == TailEventKind.PHASE_CHANGED]
    assert len(phase_events) == 1
    assert phase_events[0].payload["new_phase"] == "active"


def test_originator_hangup_ends_clean(alice: Identity, mom: Identity) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 3_500))
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.USER_HANGUP, occurred_at_ms=10_000,
    ))
    assert m.phase == CallPhase.ENDED
    assert out.outbound_msgs[0].type == CALL_END
    assert out.call_complete is True


# ---------------------------------------------------------------------------
# Recipient flow
# ---------------------------------------------------------------------------

def test_recipient_wire_invite_shows_ring(
    mom: Identity, alice: Identity,
) -> None:
    m = _new_recipient(mom, alice)
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.WIRE_CALL_INVITE, occurred_at_ms=1_500,
    ))
    assert m.phase == CallPhase.RINGING
    ring_events = [e for e in out.tail_events if e.kind == TailEventKind.SHOW_RING]
    assert len(ring_events) == 1
    assert LocalAction.SHOW_RING in out.local_actions


def test_recipient_accept_emits_accept_and_phase_event(
    mom: Identity, alice: Identity,
) -> None:
    m = _new_recipient(mom, alice)
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 1_500))
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.USER_ACCEPT, occurred_at_ms=3_000,
    ))
    assert m.phase == CallPhase.ACTIVE
    assert out.outbound_msgs[0].type == CALL_ACCEPT
    assert LocalAction.START_MEDIA in out.local_actions


# ---------------------------------------------------------------------------
# Recording consent flow integrated
# ---------------------------------------------------------------------------

def test_consent_request_flips_provenance_tag(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    # Alice asks
    m.handle(ManagerEvent(ManagerEventKind.USER_REQUEST_RECORDING, 5_000))
    # Mom grants
    m.handle(ManagerEvent(ManagerEventKind.WIRE_RECORDING_GRANT, 6_000))
    assert m.consent_phase == ConsentPhase.RECORDING
    assert m.current_recording_state == RecordingState.RECORDING_MUTUAL


def test_consent_request_emits_outbound_message(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.USER_REQUEST_RECORDING, occurred_at_ms=5_000,
    ))
    assert len(out.consent_msgs) == 1
    assert out.consent_msgs[0].type == RECORDING_REQUEST


def test_consent_stop_either_side_ends_recording(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.USER_REQUEST_RECORDING, 5_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_RECORDING_GRANT, 6_000))

    # Mom stops on her side
    m.handle(ManagerEvent(ManagerEventKind.WIRE_RECORDING_STOP, 10_000))
    assert m.consent_phase == ConsentPhase.NONE
    assert m.current_recording_state == RecordingState.NOT_RECORDING


# ---------------------------------------------------------------------------
# Async capsule integration
# ---------------------------------------------------------------------------

def _signed(alice: Identity, content: bytes, ts_us: int = 0):
    return sign_provenance(
        segment_hash=make_segment_hash(content),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=ts_us,
        produce_confidence=1.0,
        signing_key=alice.private,
    )


def test_immune_convert_opens_capsule_builder(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, 5_000))
    assert m.phase == CallPhase.ASYNC_CAPTURE
    assert m.state.capsule_builder is not None
    assert m.state.capsule_builder.is_empty()


def test_audio_segments_flow_into_capsule(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, 5_000))

    for i in range(3):
        chunk = b"opus-frame-" + str(i).encode()
        m.handle(ManagerEvent(
            kind=ManagerEventKind.CAPTURE_AUDIO_SEGMENT,
            occurred_at_ms=5_100 + i * 100,
            data={"chunk": chunk, "provenance": _signed(alice, chunk, ts_us=i)},
        ))
    assert m.state.capsule_builder.total_bytes() > 0


def test_capsule_finalize_transitions_to_resumable(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, 5_000))
    # Feed segments
    for i in range(3):
        chunk = b"opus-" + str(i).encode()
        m.handle(ManagerEvent(
            kind=ManagerEventKind.CAPTURE_AUDIO_SEGMENT,
            occurred_at_ms=5_100 + i * 100,
            data={"chunk": chunk, "provenance": _signed(alice, chunk, ts_us=i)},
        ))
    # Finalize
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.CAPSULE_FINALIZED, occurred_at_ms=6_000,
    ))
    assert m.phase == CallPhase.RESUMABLE
    assert out.finalized_capsule is not None
    assert out.finalized_capsule.all_frames_verified_by(alice.public_bytes)
    # Tail event: CAPSULE_CAPTURED + RESUME_OFFER_AVAILABLE
    captured = [e for e in out.tail_events if e.kind == TailEventKind.CAPSULE_CAPTURED]
    resume_avail = [e for e in out.tail_events if e.kind == TailEventKind.RESUME_OFFER_AVAILABLE]
    assert len(captured) == 1
    assert len(resume_avail) == 1


def test_capsule_finalize_with_empty_builder_is_noop(
    alice: Identity, mom: Identity,
) -> None:
    """If async-capture is opened but no segments are fed, finalize
    must NOT crash. The lifecycle stays in ASYNC_CAPTURE."""
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, 5_000))
    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.CAPSULE_FINALIZED, occurred_at_ms=6_000,
    ))
    assert m.phase == CallPhase.ASYNC_CAPTURE     # unchanged
    assert out.finalized_capsule is None


# ---------------------------------------------------------------------------
# Resume flow
# ---------------------------------------------------------------------------

def test_user_resume_emits_resume_offer(alice: Identity, mom: Identity) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC, 5_000))
    chunk = b"opus"
    m.handle(ManagerEvent(
        kind=ManagerEventKind.CAPTURE_AUDIO_SEGMENT,
        occurred_at_ms=5_100,
        data={"chunk": chunk, "provenance": _signed(alice, chunk)},
    ))
    m.handle(ManagerEvent(ManagerEventKind.CAPSULE_FINALIZED, 6_000))
    assert m.is_resumable

    out = m.handle(ManagerEvent(
        kind=ManagerEventKind.USER_RESUME, occurred_at_ms=30_000,
    ))
    assert out.outbound_msgs[0].type == RESUME_OFFER
    assert m.phase == CallPhase.ENDED


# ---------------------------------------------------------------------------
# CRDT mirrors lifecycle end
# ---------------------------------------------------------------------------

def test_session_crdt_reflects_call_ended(alice: Identity, mom: Identity) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.USER_HANGUP, 5_000))
    s = m.session_snapshot()
    assert s.ended_at_ms.value == 5_000
    assert s.end_reason.value == int(EndReason.USER_HANGUP_LOCAL)
    assert not s.is_active


def test_session_crdt_reflects_recording_state(
    alice: Identity, mom: Identity,
) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.USER_REQUEST_RECORDING, 3_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_RECORDING_GRANT, 3_500))
    s = m.session_snapshot()
    assert s.recording_state.value == int(RecordingState.RECORDING_MUTUAL)


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_handle_does_not_corrupt(alice: Identity, mom: Identity) -> None:
    m = _new_originator(alice, mom)
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2))

    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for i in range(50):
                # Stale events get no-op'd cleanly
                m.handle(ManagerEvent(
                    kind=ManagerEventKind.WIRE_CALL_INVITE, occurred_at_ms=i,
                ))
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    # Phase still ACTIVE — wire invites mid-call are no-ops.
    assert m.phase == CallPhase.ACTIVE


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_open_get_close(alice: Identity, mom: Identity) -> None:
    reg = CallManagerRegistry()
    m1 = reg.open(
        call_id="c1", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", local_master_vk_hex=alice.fingerprint,
        started_at_ms=1_000,
    )
    assert reg.get("c1") is m1
    assert len(reg) == 1
    reg.close("c1")
    assert reg.get("c1") is None
    assert len(reg) == 0


def test_registry_open_returns_existing_for_same_call_id(
    alice: Identity, mom: Identity,
) -> None:
    reg = CallManagerRegistry()
    m1 = reg.open(
        call_id="c1", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", local_master_vk_hex=alice.fingerprint,
        started_at_ms=1_000,
    )
    m2 = reg.open(
        call_id="c1", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", local_master_vk_hex=alice.fingerprint,
        started_at_ms=2_000,
    )
    assert m1 is m2


def test_registry_reaps_completed_calls(alice: Identity, mom: Identity) -> None:
    reg = CallManagerRegistry()
    m = reg.open(
        call_id="c-done", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", local_master_vk_hex=alice.fingerprint,
        started_at_ms=1_000,
    )
    m.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    m.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    m.handle(ManagerEvent(ManagerEventKind.USER_HANGUP, 3_000))
    assert m.is_complete

    # Open a second, leave it in progress
    m2 = reg.open(
        call_id="c-active", peer_master_vk_hex=mom.fingerprint,
        local_role="originator", local_master_vk_hex=alice.fingerprint,
        started_at_ms=5_000,
    )
    m2.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 5_000))

    removed = reg.reap_completed()
    assert removed == ("c-done",)
    assert len(reg) == 1
    assert reg.get("c-done") is None
    assert reg.get("c-active") is m2
