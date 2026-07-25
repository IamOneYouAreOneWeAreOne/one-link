"""Tests for capsule transport: stream + reassemble + verify."""

from __future__ import annotations

import base64
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.async_capsule import (
    CAPSULE_CHUNK,
    CAPSULE_COMPLETE,
    CAPSULE_OFFER,
    AsyncCapsule,
    CapsuleBuilder,
    CapsuleKind,
)
from one_link.capsule_transport import (
    InboundCapsule,
    InboundCapsuleRegistry,
    InboundError,
    MAX_CAPSULE_BYTES,
    MAX_CAPSULE_CHUNK_BYTES,
    MAX_CAPSULE_CHUNKS,
    parse_inbound_chunk,
    parse_inbound_complete,
    parse_inbound_offer,
    stream_capsule_to_messages,
)
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)
from one_link.identity import Identity

BOB_FP = "b" * 64


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
    return _identity("alice-cap-tx")


@pytest.fixture
def bob() -> Identity:
    return _identity("bob-cap-tx")


def _signed(identity: Identity, content: bytes, ts_us: int = 0):
    return sign_provenance(
        segment_hash=make_segment_hash(content),
        device_id=identity.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=ts_us,
        produce_confidence=1.0,
        signing_key=identity.private,
    )


def _build_capsule(alice: Identity, *, n_frames: int = 5) -> AsyncCapsule:
    b = CapsuleBuilder(
        capsule_id="cap-001",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=BOB_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=1_000,
    )
    for i in range(n_frames):
        chunk = b"opus-payload-" + str(i).encode()
        b.append_audio(
            chunk=chunk,
            provenance=_signed(alice, chunk, ts_us=i * 1000),
            timestamp_ms=1_000 + i * 100,
        )
    return b.finalize(finalized_at_ms=2_000, resume_window_ms=600_000)


def _registry_offer_kwargs(
    alice: Identity,
    *,
    capsule_id: str = "x",
) -> dict:
    payload = b"x"
    return {
        "capsule_id": capsule_id,
        "sender_master_vk_hex": alice.fingerprint,
        "expected_payload_hash": make_segment_hash(payload).hex(),
        "declared_size": len(payload),
        "declared_duration_ms": 0,
        "declared_recording_state": 0,
        "declared_resumable_until_ms": 0,
        "declared_kind": 0,
        "declared_codec": "opus",
        "declared_sample_rate": 48_000,
        "declared_call_id": "call-x",
        "declared_started_at_ms": 0,
        "declared_finalized_at_ms": 0,
        "recipient_master_vk_hex": BOB_FP,
        "provenance_chain": (_signed(alice, payload),),
        "provenance_segment_sizes": (len(payload),),
    }


# ---------------------------------------------------------------------------
# Outbound stream
# ---------------------------------------------------------------------------

def test_stream_emits_offer_chunks_complete(alice: Identity) -> None:
    cap = _build_capsule(alice)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))
    assert msgs[0]["t"] == CAPSULE_OFFER
    assert msgs[-1]["t"] == CAPSULE_COMPLETE
    middle = msgs[1:-1]
    assert all(m["t"] == CAPSULE_CHUNK for m in middle)


def test_stream_has_correct_total_chunks(alice: Identity) -> None:
    cap = _build_capsule(alice)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))
    chunks = [m for m in msgs if m["t"] == CAPSULE_CHUNK]
    # Payload is small (each opus-payload-N is ~14 bytes), so one chunk fits.
    assert len(chunks) == 1
    assert chunks[0]["total"] == 1
    assert chunks[0]["seq"] == 0


def test_stream_chunks_a_large_payload(alice: Identity) -> None:
    b = CapsuleBuilder(
        capsule_id="big",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=BOB_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=0,
    )
    # 100 KB payload
    chunk = b"\xab" * 100_000
    b.append_audio(chunk=chunk, provenance=_signed(alice, chunk), timestamp_ms=100)
    cap = b.finalize(finalized_at_ms=200, resume_window_ms=600_000)
    msgs = list(stream_capsule_to_messages(
        cap, sender_short_id=alice.short_id,
        chunk_size=16_384,
    ))
    chunks = [m for m in msgs if m["t"] == CAPSULE_CHUNK]
    # 100000 / 16384 ≈ 6.1 → 7 chunks
    assert len(chunks) >= 6
    assert chunks[0]["total"] == len(chunks)
    assert all(c["seq"] == i for i, c in enumerate(chunks))


def test_stream_rejects_invalid_chunk_size(alice: Identity) -> None:
    cap = _build_capsule(alice)
    with pytest.raises(ValueError, match="chunk_size"):
        list(stream_capsule_to_messages(cap, sender_short_id="a", chunk_size=0))
    with pytest.raises(ValueError, match="chunk_size"):
        list(stream_capsule_to_messages(cap, sender_short_id="a", chunk_size=True))


def test_stream_rejects_chunk_layout_above_wire_sequence_limit(
    alice: Identity,
) -> None:
    payload = b"x" * (MAX_CAPSULE_CHUNKS + 1)
    builder = CapsuleBuilder(
        capsule_id="too-many-wire-chunks",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=BOB_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=0,
    )
    builder.append_audio(
        chunk=payload,
        provenance=_signed(alice, payload),
        timestamp_ms=1,
    )
    cap = builder.finalize(finalized_at_ms=2, resume_window_ms=1)
    with pytest.raises(ValueError, match="limit"):
        list(stream_capsule_to_messages(
            cap,
            sender_short_id=alice.short_id,
            chunk_size=1,
        ))


# ---------------------------------------------------------------------------
# Inbound: round-trip
# ---------------------------------------------------------------------------

def test_round_trip_assembles_and_verifies(alice: Identity) -> None:
    cap = _build_capsule(alice)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))

    # Receiver side
    reg = InboundCapsuleRegistry()
    offer = parse_inbound_offer(msgs[0])
    inbound = reg.open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    for m in msgs[1:-1]:
        parsed = parse_inbound_chunk(m)
        inbound.add_chunk(
            seq=parsed["seq"],
            data=parsed["data"],
            declared_total=parsed["total"],
        )
    completed = parse_inbound_complete(msgs[-1])
    final_cap = inbound.verify_and_finalize(
        sender_public_bytes=alice.public_bytes,
    )
    assert final_cap.payload_hash == cap.payload_hash
    assert final_cap.audio_payload == cap.audio_payload
    assert len(final_cap.provenance_chain) == len(cap.provenance_chain)


def test_verification_binds_public_key_to_full_declared_fingerprint(
    alice: Identity,
) -> None:
    kwargs = _registry_offer_kwargs(alice)
    kwargs["sender_master_vk_hex"] = alice.fingerprint[:8] + (
        "0" if alice.fingerprint[8] != "0" else "1"
    ) + alice.fingerprint[9:]
    inbound = InboundCapsule(**kwargs)
    inbound.add_chunk(seq=0, data=b"x", declared_total=1)
    with pytest.raises(InboundError, match="does not match capsule identity"):
        inbound.verify_and_finalize(sender_public_bytes=alice.public_bytes)


def test_round_trip_with_large_payload_succeeds(alice: Identity) -> None:
    """Multi-chunk transfer reassembles correctly."""
    b = CapsuleBuilder(
        capsule_id="multi",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=BOB_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=0,
    )
    # Multi-chunk content with multiple frames
    for i in range(5):
        chunk = bytes([i]) * 20_000
        b.append_audio(
            chunk=chunk, provenance=_signed(alice, chunk, ts_us=i),
            timestamp_ms=100 + i * 50,
        )
    cap = b.finalize(finalized_at_ms=500, resume_window_ms=600_000)
    msgs = list(stream_capsule_to_messages(
        cap, sender_short_id=alice.short_id, chunk_size=10_000,
    ))

    reg = InboundCapsuleRegistry()
    offer = parse_inbound_offer(msgs[0])
    inbound = reg.open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    for m in msgs[1:-1]:
        parsed = parse_inbound_chunk(m)
        inbound.add_chunk(
            seq=parsed["seq"], data=parsed["data"],
            declared_total=parsed["total"],
        )
    final_cap = inbound.verify_and_finalize(
        sender_public_bytes=alice.public_bytes,
    )
    assert final_cap.payload_hash == cap.payload_hash
    assert len(final_cap.audio_payload) == 5 * 20_000


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------

def test_corrupted_payload_fails_hash_check(alice: Identity) -> None:
    cap = _build_capsule(alice)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))

    reg = InboundCapsuleRegistry()
    offer = parse_inbound_offer(msgs[0])
    inbound = reg.open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    # Tamper the chunk
    chunk_msg = msgs[1].copy()
    original = base64.b64decode(chunk_msg["data_b64"], validate=True)
    chunk_msg["data_b64"] = base64.b64encode(
        bytes([original[0] ^ 1]) + original[1:]
    ).decode("ascii")
    parsed = parse_inbound_chunk(chunk_msg)
    inbound.add_chunk(
        seq=parsed["seq"], data=parsed["data"],
        declared_total=parsed["total"],
    )
    with pytest.raises(InboundError, match="hash mismatch"):
        inbound.verify_and_finalize(sender_public_bytes=alice.public_bytes)


def test_provenance_from_wrong_signer_rejected(
    alice: Identity, bob: Identity,
) -> None:
    """An attacker substitutes Bob-signed provenance into a chunk;
    the receiver verifies against Alice's key and rejects."""
    b = CapsuleBuilder(
        capsule_id="att",
        call_id="call-x",
        sender_master_vk_hex=alice.fingerprint,
        recipient_master_vk_hex=BOB_FP,
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        started_at_ms=0,
    )
    # Build with Bob's signature instead of Alice's
    chunk = b"opus-fake"
    forged = sign_provenance(
        segment_hash=make_segment_hash(chunk),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=100,
        produce_confidence=1.0,
        signing_key=bob.private,
    )
    b.append_audio(chunk=chunk, provenance=forged, timestamp_ms=100)
    cap = b.finalize(finalized_at_ms=200, resume_window_ms=600_000)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))

    reg = InboundCapsuleRegistry()
    offer = parse_inbound_offer(msgs[0])
    inbound = reg.open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    for m in msgs[1:-1]:
        parsed = parse_inbound_chunk(m)
        inbound.add_chunk(
            seq=parsed["seq"], data=parsed["data"],
            declared_total=parsed["total"],
        )
    with pytest.raises(InboundError, match="provenance verification failed"):
        inbound.verify_and_finalize(sender_public_bytes=alice.public_bytes)


def test_valid_signatures_from_wrong_payload_slices_are_rejected(
    alice: Identity,
) -> None:
    cap = _build_capsule(alice, n_frames=2)
    messages = list(stream_capsule_to_messages(
        cap,
        sender_short_id=alice.short_id,
    ))
    tampered_offer = dict(messages[0])
    first_size, second_size = tampered_offer["provenance_segment_sizes"]
    tampered_offer["provenance_segment_sizes"] = [
        first_size + 1,
        second_size - 1,
    ]
    offer = parse_inbound_offer(tampered_offer)
    inbound = InboundCapsuleRegistry().open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    for message in messages[1:-1]:
        parsed = parse_inbound_chunk(message)
        inbound.add_chunk(
            seq=parsed["seq"],
            data=parsed["data"],
            declared_total=parsed["total"],
        )
    with pytest.raises(InboundError, match="does not cover payload"):
        inbound.verify_and_finalize(sender_public_bytes=alice.public_bytes)


# ---------------------------------------------------------------------------
# Defensive parsers — never raise on malformed wire input (raise InboundError)
# ---------------------------------------------------------------------------

def test_parse_offer_rejects_wrong_type() -> None:
    with pytest.raises(InboundError, match="not a"):
        parse_inbound_offer({"t": "TEXT"})


def test_parse_offer_rejects_missing_capsule_id() -> None:
    with pytest.raises(InboundError, match="capsule_id"):
        parse_inbound_offer({"t": CAPSULE_OFFER, "payload_hash": "a" * 64})


def test_parse_offer_rejects_short_payload_hash() -> None:
    with pytest.raises(InboundError, match="payload_hash"):
        parse_inbound_offer({
            "t": CAPSULE_OFFER, "capsule_id": "x", "payload_hash": "short",
        })


def test_parse_chunk_rejects_invalid_base64() -> None:
    with pytest.raises(InboundError, match="base64"):
        parse_inbound_chunk({
            "t": CAPSULE_CHUNK, "capsule_id": "x", "seq": 0,
            "data_b64": "@@@not-base64@@@",
        })


def test_parse_chunk_rejects_negative_seq() -> None:
    with pytest.raises(InboundError, match="seq"):
        parse_inbound_chunk({
            "t": CAPSULE_CHUNK, "capsule_id": "x", "seq": -1,
            "data_b64": "",
        })


def test_parse_offer_rejects_malformed_provenance_chain_entry() -> None:
    """The chain lives in the OFFER now. A malformed entry must be
    rejected — but the parse never raises an unhandled exception."""
    with pytest.raises(InboundError, match="provenance_chain"):
        parse_inbound_offer({
            "t": CAPSULE_OFFER,
            "capsule_id": "x",
            "payload_hash": "0" * 64,
            "size": 1, "duration_ms": 0,
            "recording_state": 0, "resumable_until_ms": 0,
            "kind": 0, "codec": "opus", "sample_rate": 48_000,
            "call_id": "call-x", "started_at_ms": 0, "finalized_at_ms": 0,
            "provenance_chain": [{"v": "not-an-int"}],
            "provenance_segment_sizes": [1],
        })


def test_parse_offer_rejects_non_list_provenance_chain() -> None:
    with pytest.raises(InboundError, match="provenance_chain"):
        parse_inbound_offer({
            "t": CAPSULE_OFFER,
            "capsule_id": "x",
            "payload_hash": "0" * 64,
            "size": 1, "duration_ms": 0,
            "recording_state": 0, "resumable_until_ms": 0,
            "kind": 0, "codec": "opus", "sample_rate": 48_000,
            "call_id": "call-x", "started_at_ms": 0, "finalized_at_ms": 0,
            "provenance_chain": "not-a-list",
            "provenance_segment_sizes": [1],
        })


def test_parse_offer_missing_provenance_boundaries_is_rejected(
    alice: Identity,
) -> None:
    """The capability version never accepts unverifiable legacy coverage."""
    offer = next(stream_capsule_to_messages(
        _build_capsule(alice, n_frames=1),
        sender_short_id=alice.short_id,
    ))
    offer.pop("provenance_segment_sizes")
    with pytest.raises(InboundError, match="provenance_segment_sizes"):
        parse_inbound_offer(offer)


def test_parse_offer_rejects_unbounded_or_inconsistent_segment_sizes(
    alice: Identity,
) -> None:
    offer = next(stream_capsule_to_messages(
        _build_capsule(alice, n_frames=2),
        sender_short_id=alice.short_id,
    ))
    with pytest.raises(InboundError, match="must be an integer"):
        parse_inbound_offer({
            **offer,
            "provenance_segment_sizes": [True, offer["size"] - 1],
        })
    with pytest.raises(InboundError, match="segment count"):
        parse_inbound_offer({
            **offer,
            "provenance_segment_sizes": [offer["size"]],
        })
    with pytest.raises(InboundError, match="do not cover"):
        parse_inbound_offer({
            **offer,
            "provenance_segment_sizes": [1, 1],
        })


def test_parse_offer_rejects_type_confused_and_inconsistent_time_contract(
    alice: Identity,
) -> None:
    offer = next(stream_capsule_to_messages(
        _build_capsule(alice, n_frames=1),
        sender_short_id=alice.short_id,
    ))
    with pytest.raises(InboundError, match="must be an integer"):
        parse_inbound_offer({**offer, "recording_state": True})
    with pytest.raises(InboundError, match="capture timestamps"):
        parse_inbound_offer({**offer, "finalized_at_ms": offer["started_at_ms"] - 1})
    with pytest.raises(InboundError, match="resume window"):
        parse_inbound_offer({
            **offer,
            "resumable_until_ms": (
                offer["finalized_at_ms"] + 30 * 24 * 60 * 60 * 1000 + 1
            ),
        })
    with pytest.raises(InboundError, match="call_id"):
        parse_inbound_offer({**offer, "call_id": "unsafe/call"})


# ---------------------------------------------------------------------------
# Idempotent chunk replay
# ---------------------------------------------------------------------------

def test_exact_duplicate_chunk_is_accepted_idempotently(alice: Identity) -> None:
    """A retransmitted chunk with the same seq should NOT fail."""
    cap = _build_capsule(alice)
    msgs = list(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))

    reg = InboundCapsuleRegistry()
    offer = parse_inbound_offer(msgs[0])
    inbound = reg.open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    parsed = parse_inbound_chunk(msgs[1])
    # Add the SAME chunk twice
    inbound.add_chunk(
        seq=parsed["seq"], data=parsed["data"],
        declared_total=parsed["total"],
    )
    inbound.add_chunk(
        seq=parsed["seq"], data=parsed["data"],
        declared_total=parsed["total"],
    )
    final_cap = inbound.verify_and_finalize(
        sender_public_bytes=alice.public_bytes,
    )
    assert final_cap.payload_hash == cap.payload_hash


def test_duplicate_chunk_with_changed_bytes_is_rejected(alice: Identity) -> None:
    cap = _build_capsule(alice)
    messages = list(stream_capsule_to_messages(
        cap,
        sender_short_id=alice.short_id,
    ))
    offer = parse_inbound_offer(messages[0])
    inbound = InboundCapsuleRegistry().open_inbound(
        capsule_id=offer["capsule_id"],
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash=offer["payload_hash"],
        declared_size=offer["size"],
        declared_duration_ms=offer["duration_ms"],
        declared_recording_state=offer["recording_state"],
        declared_resumable_until_ms=offer["resumable_until_ms"],
        declared_kind=offer["kind"],
        declared_codec=offer["codec"],
        declared_sample_rate=offer["sample_rate"],
        declared_call_id=offer["call_id"],
        declared_started_at_ms=offer["started_at_ms"],
        declared_finalized_at_ms=offer["finalized_at_ms"],
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=offer["provenance_chain"],
        provenance_segment_sizes=offer["provenance_segment_sizes"],
    )
    parsed = parse_inbound_chunk(messages[1])
    inbound.add_chunk(
        seq=parsed["seq"],
        data=parsed["data"],
        declared_total=parsed["total"],
    )
    changed = bytes([parsed["data"][0] ^ 1]) + parsed["data"][1:]
    with pytest.raises(InboundError, match="changed content"):
        inbound.add_chunk(
            seq=parsed["seq"],
            data=changed,
            declared_total=parsed["total"],
        )


def test_inconsistent_declared_total_rejected(alice: Identity) -> None:
    inbound = InboundCapsule(
        capsule_id="x",
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash="0" * 64,
        declared_size=100,
        declared_duration_ms=0,
        declared_recording_state=0,
        declared_resumable_until_ms=0,
        declared_kind=0,
        declared_codec="opus",
        declared_sample_rate=48_000,
        declared_call_id="call-x",
        declared_started_at_ms=0,
        declared_finalized_at_ms=0,
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=(_signed(alice, b"a" * 100),),
        provenance_segment_sizes=(100,),
    )
    inbound.add_chunk(seq=0, data=b"a", declared_total=3)
    with pytest.raises(InboundError, match="flipped"):
        inbound.add_chunk(seq=1, data=b"b", declared_total=5)


def test_seq_above_declared_total_rejected(alice: Identity) -> None:
    inbound = InboundCapsule(
        capsule_id="x",
        sender_master_vk_hex=alice.fingerprint,
        expected_payload_hash="0" * 64,
        declared_size=100,
        declared_duration_ms=0,
        declared_recording_state=0,
        declared_resumable_until_ms=0,
        declared_kind=0,
        declared_codec="opus",
        declared_sample_rate=48_000,
        declared_call_id="call-x",
        declared_started_at_ms=0,
        declared_finalized_at_ms=0,
        recipient_master_vk_hex=BOB_FP,
        provenance_chain=(_signed(alice, b"a" * 100),),
        provenance_segment_sizes=(100,),
    )
    with pytest.raises(InboundError, match="declared total"):
        inbound.add_chunk(seq=5, data=b"a", declared_total=3)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_registry_open_idempotent(alice: Identity) -> None:
    reg = InboundCapsuleRegistry()
    a = reg.open_inbound(**_registry_offer_kwargs(alice))
    b = reg.open_inbound(**_registry_offer_kwargs(alice))
    assert a is b


def test_registry_rejects_conflicting_capsule_id_replay(alice: Identity) -> None:
    reg = InboundCapsuleRegistry()
    kwargs = _registry_offer_kwargs(alice)
    reg.open_inbound(**kwargs)

    with pytest.raises(InboundError, match="conflicting offer"):
        reg.open_inbound(**{**kwargs, "expected_payload_hash": "f" * 64})


def test_capsule_parsers_enforce_memory_and_integer_bounds() -> None:
    offer = {
        "t": CAPSULE_OFFER,
        "capsule_id": "bounded",
        "payload_hash": "0" * 64,
        "size": MAX_CAPSULE_BYTES + 1,
        "duration_ms": 1,
        "recording_state": 0,
        "resumable_until_ms": 1,
        "kind": 0,
        "codec": "opus",
        "sample_rate": 48_000,
        "call_id": "call-x",
        "started_at_ms": 0,
        "finalized_at_ms": 0,
        "provenance_chain": [],
        "provenance_segment_sizes": [],
    }
    with pytest.raises(InboundError, match="size outside"):
        parse_inbound_offer(offer)
    with pytest.raises(InboundError, match="must be an integer"):
        parse_inbound_offer({**offer, "size": True})
    with pytest.raises(InboundError, match="duration_ms must be an integer"):
        parse_inbound_offer({key: value for key, value in offer.items() if key != "duration_ms"})

    oversized_b64 = "A" * ((((MAX_CAPSULE_CHUNK_BYTES + 2) // 3) * 4) + 4)
    with pytest.raises(InboundError, match="chunk size limit"):
        parse_inbound_chunk({
            "t": CAPSULE_CHUNK,
            "capsule_id": "bounded",
            "seq": 0,
            "total": 1,
            "data_b64": oversized_b64,
        })
    with pytest.raises(InboundError, match="chunk limit"):
        parse_inbound_chunk({
            "t": CAPSULE_CHUNK,
            "capsule_id": "bounded",
            "seq": MAX_CAPSULE_CHUNKS,
            "total": MAX_CAPSULE_CHUNKS,
            "data_b64": "",
        })
    with pytest.raises(InboundError, match="n_chunks must be an integer"):
        parse_inbound_complete({
            "t": CAPSULE_COMPLETE,
            "capsule_id": "bounded",
            "payload_hash": "0" * 64,
        })


def test_registry_rejects_new_offer_at_capacity_without_eviction(
    alice: Identity,
) -> None:
    reg = InboundCapsuleRegistry(max_inflight=3)
    for i in range(3):
        reg.open_inbound(**_registry_offer_kwargs(alice, capsule_id=f"cap-{i}"))
    with pytest.raises(InboundError, match="capacity"):
        reg.open_inbound(**_registry_offer_kwargs(alice, capsule_id="cap-3"))
    assert len(reg) == 3
    assert all(reg.get(f"cap-{i}") is not None for i in range(3))
    assert reg.get("cap-3") is None


def test_registry_thread_safe_concurrent_opens(alice: Identity) -> None:
    reg = InboundCapsuleRegistry(max_inflight=1024)
    errors: list[BaseException] = []

    def worker(start: int) -> None:
        try:
            for i in range(50):
                reg.open_inbound(**_registry_offer_kwargs(
                    alice,
                    capsule_id=f"cap-{start * 50 + i}",
                ))
        except BaseException as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(reg) == 400
