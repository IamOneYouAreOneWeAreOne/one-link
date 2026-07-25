"""Tests for the async capsule format + builder."""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.async_capsule import (
    AsyncCapsule,
    CAPSULE_OFFER,
    CapsuleBuilder,
    CapsuleKind,
    capsule_label,
    capsule_to_offer_msg,
    format_duration_human,
)
from one_link.frame_provenance import (
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)
from one_link.identity import Identity

PEER_FP = "b" * 64


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
    return _identity("alice-capsule")


@pytest.fixture
def bob() -> Identity:
    return _identity("bob-capsule")


def _signed_provenance(
    identity: Identity, content: bytes, timestamp_us: int = 0,
) -> FrameProvenance:
    return sign_provenance(
        segment_hash=make_segment_hash(content),
        device_id=identity.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=timestamp_us,
        produce_confidence=1.0,
        signing_key=identity.private,
    )


# ---------------------------------------------------------------------------
# Builder basics
# ---------------------------------------------------------------------------

def test_empty_builder_cannot_finalize(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=1_000,
    )
    assert b.is_empty()
    with pytest.raises(ValueError, match="empty"):
        b.finalize(finalized_at_ms=2_000, resume_window_ms=600_000)


def test_builder_accumulates_chunks(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=1_000,
    )
    for i in range(5):
        chunk = bytes([i]) * 100
        b.append_audio(
            chunk=chunk,
            provenance=_signed_provenance(alice, chunk, timestamp_us=i * 1000),
            timestamp_ms=1_000 + i * 100,
        )
    assert not b.is_empty()
    assert b.total_bytes() == 500
    # Duration: last_ms - started_ms = (1000 + 4*100) - 1000 = 400
    assert b.duration_ms() == 400


def test_empty_chunk_skipped(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=1_000,
    )
    b.append_audio(
        chunk=b"",
        provenance=_signed_provenance(alice, b""),
        timestamp_ms=1_000,
    )
    assert b.is_empty()


# ---------------------------------------------------------------------------
# Finalization
# ---------------------------------------------------------------------------

def test_finalize_produces_immutable_capsule(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=1_000,
    )
    chunks = [b"opus-1", b"opus-2", b"opus-3"]
    for i, ch in enumerate(chunks):
        b.append_audio(
            chunk=ch,
            provenance=_signed_provenance(alice, ch, timestamp_us=i * 1000),
            timestamp_ms=1_000 + i * 100,
        )
    cap = b.finalize(finalized_at_ms=2_500, resume_window_ms=600_000)
    assert isinstance(cap, AsyncCapsule)
    assert cap.audio_payload == b"opus-1opus-2opus-3"
    assert cap.duration_ms == 200   # 1200 - 1000
    assert cap.finalized_at_ms == 2_500
    assert cap.resumable_until_ms == 2_500 + 600_000
    assert len(cap.provenance_chain) == 3
    assert cap.provenance_segment_sizes == tuple(len(chunk) for chunk in chunks)


def test_capsule_schema_rejects_invalid_recipient_and_provenance_boundaries(
    alice: Identity,
) -> None:
    builder = CapsuleBuilder(
        capsule_id="cap-boundaries",
        call_id="call-boundaries",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=1_000,
    )
    first = b"first-segment"
    second = b"second-segment"
    for index, chunk in enumerate((first, second)):
        builder.append_audio(
            chunk=chunk,
            provenance=_signed_provenance(alice, chunk, timestamp_us=index),
            timestamp_ms=1_100 + index * 100,
        )
    capsule = builder.finalize(
        finalized_at_ms=1_500,
        resume_window_ms=60_000,
    )

    with pytest.raises(ValueError, match="recipient identity"):
        replace(capsule, recipient_master_vk_hex="not-a-fingerprint")
    with pytest.raises(ValueError, match="segment count"):
        replace(capsule, provenance_segment_sizes=(len(capsule.audio_payload),))
    with pytest.raises(ValueError, match="does not cover audio"):
        replace(
            capsule,
            provenance_segment_sizes=(len(first) + 1, len(second) - 1),
        )
    with pytest.raises(ValueError, match="must be a tuple"):
        replace(  # type: ignore[arg-type]
            capsule,
            provenance_segment_sizes=[len(first), len(second)],
        )
    with pytest.raises(ValueError, match="capsule_id"):
        replace(capsule, capsule_id="unsafe capsule id")
    with pytest.raises(ValueError, match="call_id"):
        replace(capsule, call_id="unsafe/call")
    with pytest.raises(ValueError, match="precedes started"):
        replace(capsule, finalized_at_ms=capsule.started_at_ms - 1)
    with pytest.raises(ValueError, match="resume window"):
        replace(
            capsule,
            resumable_until_ms=(
                capsule.finalized_at_ms + 30 * 24 * 60 * 60 * 1000 + 1
            ),
        )
    with pytest.raises(ValueError, match="non-empty"):
        replace(
            capsule,
            audio_payload=b"",
            provenance_chain=(),
            provenance_segment_sizes=(),
            payload_hash=make_segment_hash(b"").hex(),
        )


def test_builder_rejects_provenance_bound_to_another_device(
    alice: Identity,
    bob: Identity,
) -> None:
    builder = CapsuleBuilder(
        capsule_id="cap-device-binding",
        call_id="call-device-binding",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=0,
    )
    chunk = b"signed-by-bob"
    with pytest.raises(ValueError, match="another device"):
        builder.append_audio(
            chunk=chunk,
            provenance=_signed_provenance(bob, chunk),
            timestamp_ms=1,
        )


def test_payload_hash_blake3_of_concatenated_payload(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    chunk = b"audio-payload"
    b.append_audio(
        chunk=chunk, provenance=_signed_provenance(alice, chunk), timestamp_ms=100,
    )
    cap = b.finalize(finalized_at_ms=200, resume_window_ms=600_000)
    expected = blake3.blake3(b"audio-payload").hexdigest()
    assert cap.payload_hash == expected


# ---------------------------------------------------------------------------
# Resume window
# ---------------------------------------------------------------------------

def test_is_resumable_within_window(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    chunk = b"x"
    b.append_audio(chunk=chunk, provenance=_signed_provenance(alice, chunk), timestamp_ms=10)
    cap = b.finalize(finalized_at_ms=100, resume_window_ms=600_000)
    assert cap.is_resumable_at(100)
    assert cap.is_resumable_at(100 + 599_999)
    assert not cap.is_resumable_at(100 + 600_000)
    assert not cap.is_resumable_at(100 + 700_000)


# ---------------------------------------------------------------------------
# Provenance verification
# ---------------------------------------------------------------------------

def test_capsule_verifies_with_correct_sender_key(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    for i in range(3):
        chunk = bytes([i] * 8)
        b.append_audio(
            chunk=chunk, provenance=_signed_provenance(alice, chunk),
            timestamp_ms=i * 50,
        )
    cap = b.finalize(finalized_at_ms=200, resume_window_ms=600_000)
    assert cap.all_frames_verified_by(alice.public_bytes) is True

    # A declared identity with the same short id is still not the pinned full
    # fingerprint and must not inherit the valid signatures.
    colliding_declared_fp = alice.fingerprint[:8] + (
        "0" if alice.fingerprint[8] != "0" else "1"
    ) + alice.fingerprint[9:]
    relabelled = replace(cap, sender_master_vk_hex=colliding_declared_fp)
    assert relabelled.all_frames_verified_by(alice.public_bytes) is False


def test_capsule_rejects_attacker_key(alice: Identity, bob: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    chunk = b"x"
    b.append_audio(
        chunk=chunk, provenance=_signed_provenance(alice, chunk), timestamp_ms=10,
    )
    cap = b.finalize(finalized_at_ms=100, resume_window_ms=600_000)
    # Bob's key isn't Alice's. Verification fails.
    assert cap.all_frames_verified_by(bob.public_bytes) is False


def test_capsule_rejects_tampered_chain(alice: Identity, bob: Identity) -> None:
    """One frame in the chain is signed by an attacker. The whole
    capsule's verification must fail."""
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    # First two: alice's signatures
    for i in range(2):
        chunk = bytes([i] * 8)
        b.append_audio(
            chunk=chunk, provenance=_signed_provenance(alice, chunk),
            timestamp_ms=i * 10,
        )
    # Third: bob impersonates
    chunk = bytes([99] * 8)
    forged = sign_provenance(
        segment_hash=make_segment_hash(chunk),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=20,
        produce_confidence=1.0,
        signing_key=bob.private,
    )
    b.append_audio(
        chunk=chunk, provenance=forged,
        timestamp_ms=20,
    )
    cap = b.finalize(finalized_at_ms=100, resume_window_ms=600_000)
    # Verifying against Alice's key rejects the chain.
    assert cap.all_frames_verified_by(alice.public_bytes) is False


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

def test_offer_msg_has_required_fields(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="cap-001", call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING, started_at_ms=0,
    )
    chunk = b"opus-payload-bytes"
    b.append_audio(chunk=chunk, provenance=_signed_provenance(alice, chunk), timestamp_ms=200)
    cap = b.finalize(finalized_at_ms=300, resume_window_ms=600_000)
    msg = capsule_to_offer_msg(cap, alice.short_id)
    assert msg["t"] == CAPSULE_OFFER
    assert msg["from"] == alice.short_id
    assert msg["capsule_id"] == "cap-001"
    assert msg["call_id"] == "call-x"
    assert msg["payload_hash"] == cap.payload_hash
    assert msg["size"] == len(chunk)
    assert msg["codec"] == "opus"
    assert len(msg["provenance_chain"]) == 1
    assert msg["provenance_segment_sizes"] == [len(chunk)]


# ---------------------------------------------------------------------------
# UI labels
# ---------------------------------------------------------------------------

def test_capsule_labels_doctrine_compliant() -> None:
    """No 'failed', 'missed', 'error' in any label. Doctrine §3.2.e + §3.10."""
    forbidden = ("failed", "missed", "error", "lost")
    for kind in CapsuleKind:
        label = capsule_label(kind).lower()
        for tok in forbidden:
            assert tok not in label, f"{kind.name} leaks {tok!r}: {label!r}"


def test_duration_human_seconds_only() -> None:
    assert format_duration_human(23_000) == "23 sec"
    assert format_duration_human(0) == "0 sec"


def test_duration_human_minutes() -> None:
    assert format_duration_human(60_000) == "1 min"
    assert format_duration_human(125_000) == "2 min 5 sec"
    assert format_duration_human(120_000) == "2 min"


def test_duration_human_hours() -> None:
    assert format_duration_human(60 * 60 * 1000) == "1 hr 0 min"
    assert format_duration_human(90 * 60 * 1000) == "1 hr 30 min"


def test_duration_human_never_negative() -> None:
    assert format_duration_human(-5_000) == "0 sec"


# ---------------------------------------------------------------------------
# Receiver flow: verify + render
# ---------------------------------------------------------------------------

def test_receiver_can_verify_and_render(alice: Identity) -> None:
    """End-to-end: Alice builds a capsule, ships it to Bob, Bob
    verifies + renders. The Reality dot reads recording_state from
    the capsule, the UI shows the duration in plain language."""
    b = CapsuleBuilder(
        capsule_id="cap-real",
        call_id="call-real",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=PEER_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=1_000,
        recording_state_at_conversion=RecordingState.NOT_RECORDING,
    )
    for i in range(5):
        chunk = b"opus-frame-" + str(i).encode()
        b.append_audio(
            chunk=chunk,
            provenance=_signed_provenance(alice, chunk, timestamp_us=i * 20_000),
            timestamp_ms=1_000 + i * 100,
        )
    cap = b.finalize(finalized_at_ms=2_000, resume_window_ms=600_000)

    # Bob receives + verifies
    assert cap.all_frames_verified_by(alice.public_bytes)
    # Bob renders the chat surface
    label = capsule_label(cap.kind)
    duration = format_duration_human(cap.duration_ms)
    assert label == "You left a voice note"
    # 1400 - 1000 = 400ms = 0 sec under integer division
    assert "sec" in duration
    # Resumable within the 10-min window
    assert cap.is_resumable_at(2_000)
