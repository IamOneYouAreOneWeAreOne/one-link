"""Daemon-level async-capsule durability and delivery integration tests."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.async_capsule import AsyncCapsule, CapsuleKind
from one_link.capabilities import ASYNC_CAPSULE_V1
from one_link.capsule_store import CapsuleRepository
from one_link.capsule_transport import stream_capsule_to_messages
from one_link.daemon import Daemon
from one_link.discovery import Peer
from one_link.frame_provenance import (
    FrameKind,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)
from one_link.identity import Identity
from one_link.wire import decode_msg


def _identity(name: str) -> Identity:
    private = Ed25519PrivateKey.from_private_bytes(
        blake3.blake3(name.encode()).digest()[:32]
    )
    public = private.public_key()
    public_bytes = public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fingerprint = blake3.blake3(public_bytes).hexdigest()
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=name,
    )


def _capsule(sender: Identity, recipient: Identity) -> AsyncCapsule:
    payload = b"bounded-opus-capsule" * 128
    provenance = sign_provenance(
        segment_hash=make_segment_hash(payload),
        device_id=sender.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=10_100_000,
        produce_confidence=1.0,
        signing_key=sender.private,
    )
    return AsyncCapsule(
        capsule_id="capsule-e2e-1",
        call_id="call-e2e-1",
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        sender_master_vk_hex=sender.fingerprint,
        recipient_master_vk_hex=recipient.fingerprint,
        started_at_ms=10_000,
        finalized_at_ms=11_000,
        duration_ms=900,
        audio_payload=payload,
        audio_codec="opus",
        sample_rate_hz=48_000,
        provenance_chain=(provenance,),
        provenance_segment_sizes=(len(payload),),
        recording_state_at_conversion=RecordingState.NOT_RECORDING,
        resumable_until_ms=611_000,
        payload_hash=make_segment_hash(payload).hex(),
    )


def _ready_daemon(identity: Identity, repo: CapsuleRepository) -> Daemon:
    daemon = Daemon(identity)
    daemon._capsule_store = repo
    daemon._is_pinned = lambda _peer_fp: True  # type: ignore[method-assign]
    daemon._capability_allowed = (  # type: ignore[method-assign]
        lambda _peer_fp, _cap, scope=b"": True
    )
    daemon._save_call_resume_ledger = lambda: None  # type: ignore[method-assign]
    return daemon


class _InboundChannel:
    def __init__(self, peer: Identity, send_callback=None) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.peer_caps = {"features": [ASYNC_CAPSULE_V1]}
        self._send_callback = send_callback
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        message = decode_msg(payload)
        self.sent.append(message)
        if self._send_callback is not None:
            await self._send_callback(message)


@pytest.mark.asyncio
async def test_finalized_capsule_is_sealed_delivered_receipted_and_replay_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "runtime"))
    alice = _identity("capsule-alice")
    mom = _identity("capsule-mom")
    sender_repo = CapsuleRepository(tmp_path / "sender", master_seed=b"a" * 32)
    receiver_repo = CapsuleRepository(tmp_path / "receiver", master_seed=b"m" * 32)
    sender = _ready_daemon(alice, sender_repo)
    receiver = _ready_daemon(mom, receiver_repo)
    sender_events: list[dict] = []
    receiver_events: list[dict] = []
    sender._broadcast_tail = sender_events.append  # type: ignore[method-assign]
    receiver._broadcast_tail = receiver_events.append  # type: ignore[method-assign]

    async def deliver_receipt(message: dict) -> None:
        receipt_channel = _InboundChannel(mom)
        await sender._handle_capsule_transport_message(
            channel=receipt_channel,
            msg=message,
            peer_fp=mom.fingerprint,
        )

    inbound_channel = _InboundChannel(alice, deliver_receipt)

    async def route_to_receiver(_peer, messages: list[dict]) -> list[dict]:
        for message in messages:
            await receiver._handle_capsule_transport_message(
                channel=inbound_channel,
                msg=message,
                peer_fp=alice.fingerprint,
            )
        return [{"t": "ACK", "ok": True}]

    sender.send_to = route_to_receiver  # type: ignore[method-assign]
    sender._resolve_peer_for_outbound = lambda _peer_fp: object()  # type: ignore[method-assign]
    sender._peer_advertised_caps = (  # type: ignore[method-assign]
        lambda _peer_fp: frozenset({ASYNC_CAPSULE_V1})
    )

    # Exercise the production CallManager-output bridge, not a direct store.
    cap = _capsule(alice, mom)
    mgr = sender._call_registry.open(
        call_id=cap.call_id,
        peer_master_vk_hex=mom.fingerprint,
        local_role="originator",
        local_master_vk_hex=alice.fingerprint,
        started_at_ms=1_000,
    )
    output = type("_Output", (), {
        "finalized_capsule": cap,
        "outbound_msgs": (),
        "consent_msgs": (),
        "tail_events": (),
        "call_complete": False,
    })()
    await sender._flush_manager_output(mgr, output)
    pending = sender_repo.due_outbound(now_ms=2**63 - 1)
    assert len(pending) == 1
    assert cap.audio_payload not in (
        sender_repo.sealed_root / pending[0].sealed_name
    ).read_bytes()

    await sender._deliver_capsule_record(pending[0])
    sent = sender_repo.get(cap.capsule_id)
    received = receiver_repo.get(cap.capsule_id)
    assert sent is not None and sent.status == "delivered"
    assert received is not None and received.status == "received"
    incoming = receiver_repo.load_capsule(received)
    assert incoming.kind == CapsuleKind.VOICE_NOTE_INCOMING
    assert incoming.audio_payload == cap.audio_payload
    assert any(event.get("tail_kind") == "capsule_delivered" for event in sender_events)
    assert any(event.get("tail_kind") == "capsule_received" for event in receiver_events)

    # Full wire replay after commit is content-bound, produces a new receipt,
    # and cannot create a second row or second chat artifact.
    receipt_count = len(inbound_channel.sent)
    for message in stream_capsule_to_messages(cap, sender_short_id=alice.short_id):
        await receiver._handle_capsule_transport_message(
            channel=inbound_channel,
            msg=message,
            peer_fp=alice.fingerprint,
        )
    assert len(receiver_repo.list_records()) == 1
    assert len(inbound_channel.sent) == receipt_count + 1
    sender_repo.close()
    receiver_repo.close()


@pytest.mark.asyncio
async def test_interrupted_delivery_retries_after_restart_without_duplication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "runtime"))
    alice = _identity("restart-alice")
    mom = _identity("restart-mom")
    cap = _capsule(alice, mom)
    cap = AsyncCapsule(**{**cap.__dict__, "capsule_id": "capsule-restart-1"})
    sender_root = tmp_path / "sender"
    sender_repo = CapsuleRepository(sender_root, master_seed=b"s" * 32)
    receiver_repo = CapsuleRepository(tmp_path / "receiver", master_seed=b"r" * 32)
    sender = _ready_daemon(alice, sender_repo)
    receiver = _ready_daemon(mom, receiver_repo)
    sender._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    receiver._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    pending = sender_repo.store_capsule(
        cap,
        peer_fp=mom.fingerprint,
        direction="outbound",
        now_ms=0,
    )

    inbound_channel = _InboundChannel(alice)
    frames_seen = 0

    async def interrupt(_peer, messages: list[dict]) -> list[dict]:
        nonlocal frames_seen
        frames_seen += 1
        if frames_seen > 1:
            raise ConnectionError("simulated link loss")
        await receiver._handle_capsule_transport_message(
            channel=inbound_channel,
            msg=messages[0],
            peer_fp=alice.fingerprint,
        )
        return [{"t": "ACK", "ok": True}]

    sender.send_to = interrupt  # type: ignore[method-assign]
    sender._resolve_peer_for_outbound = lambda _peer_fp: object()  # type: ignore[method-assign]
    sender._peer_advertised_caps = lambda _peer_fp: frozenset({ASYNC_CAPSULE_V1})  # type: ignore[method-assign]
    await sender._deliver_capsule_record(pending)
    failed = sender_repo.get(cap.capsule_id)
    assert failed is not None and failed.status == "pending" and failed.attempts == 1
    sender_repo.close()

    # A new daemon process discovers the pending row. The receiver still has
    # the prior offer, so repeated offer/chunks collapse idempotently.
    restarted_repo = CapsuleRepository(sender_root, master_seed=b"s" * 32)
    restarted = _ready_daemon(alice, restarted_repo)
    restarted._broadcast_tail = lambda _event: None  # type: ignore[method-assign]

    async def receipt(message: dict) -> None:
        await restarted._handle_capsule_transport_message(
            channel=_InboundChannel(mom),
            msg=message,
            peer_fp=mom.fingerprint,
        )

    inbound_channel._send_callback = receipt

    async def succeed(_peer, messages: list[dict]) -> list[dict]:
        await receiver._handle_capsule_transport_message(
            channel=inbound_channel,
            msg=messages[0],
            peer_fp=alice.fingerprint,
        )
        return [{"t": "ACK", "ok": True}]

    restarted.send_to = succeed  # type: ignore[method-assign]
    restarted._resolve_peer_for_outbound = lambda _peer_fp: object()  # type: ignore[method-assign]
    restarted._peer_advertised_caps = lambda _peer_fp: frozenset({ASYNC_CAPSULE_V1})  # type: ignore[method-assign]
    due = restarted_repo.due_outbound(now_ms=failed.next_attempt_ms)
    assert len(due) == 1
    await restarted._deliver_capsule_record(due[0])
    assert restarted_repo.get(cap.capsule_id).status == "delivered"  # type: ignore[union-attr]
    assert len(receiver_repo.list_records()) == 1
    restarted_repo.close()
    receiver_repo.close()


@pytest.mark.asyncio
async def test_spoofed_receipt_and_unnegotiated_offer_do_not_mutate_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "runtime"))
    alice = _identity("spoof-alice")
    mom = _identity("spoof-mom")
    mallory = _identity("spoof-mallory")
    repo = CapsuleRepository(tmp_path / "sender", master_seed=b"k" * 32)
    sender = _ready_daemon(alice, repo)
    sender._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    cap = _capsule(alice, mom)
    repo.store_capsule(cap, peer_fp=mom.fingerprint, direction="outbound")
    receipt = {
        "t": "CAPSULE_RECEIPT",
        "capsule_id": cap.capsule_id,
        "call_id": cap.call_id,
        "payload_hash": cap.payload_hash,
        "durable": True,
    }
    await sender._handle_capsule_transport_message(
        channel=_InboundChannel(mallory),
        msg=receipt,
        peer_fp=mallory.fingerprint,
    )
    assert repo.get(cap.capsule_id).status == "pending"  # type: ignore[union-attr]

    receiver_repo = CapsuleRepository(tmp_path / "receiver", master_seed=b"v" * 32)
    receiver = _ready_daemon(mom, receiver_repo)
    receiver._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    no_cap_channel = _InboundChannel(alice)
    no_cap_channel.peer_caps = {"features": []}
    offer = next(stream_capsule_to_messages(cap, sender_short_id=alice.short_id))
    await receiver._handle_capsule_transport_message(
        channel=no_cap_channel,
        msg=offer,
        peer_fp=alice.fingerprint,
    )
    assert len(receiver._inbound_capsules) == 0
    assert receiver._capsule_inbound_meta == {}
    repo.close()
    receiver_repo.close()


@pytest.mark.asyncio
async def test_outbound_commit_rejects_provenance_not_signed_by_local_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "runtime"))
    alice = _identity("forged-local-alice")
    mom = _identity("forged-local-mom")
    mallory = _identity("forged-local-mallory")
    repo = CapsuleRepository(tmp_path / "sender", master_seed=b"f" * 32)
    sender = _ready_daemon(alice, repo)
    sender._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    capsule = _capsule(alice, mom)
    forged_provenance = sign_provenance(
        segment_hash=make_segment_hash(capsule.audio_payload),
        device_id=alice.short_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LAN,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=10_100_000,
        produce_confidence=1.0,
        signing_key=mallory.private,
    )
    forged = replace(capsule, provenance_chain=(forged_provenance,))
    with pytest.raises(ValueError, match="not locally authentic"):
        await sender._commit_outbound_capsule(None, forged)
    assert repo.list_records() == ()
    repo.close()


@pytest.mark.asyncio
async def test_real_send_to_dispatches_durable_receipt_before_transport_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the real reusable-session ACK loop end to end.

    CAPSULE_COMPLETE intentionally causes the receiver to emit the durable
    receipt *before* its ordinary frame ACK.  ``send_to`` must dispatch that
    out-of-band receipt, ACK the receipt in the reverse direction, and then
    keep reading until the ACK for CAPSULE_COMPLETE arrives.  This is the
    production ordering that a direct ``send_to`` test double cannot prove.
    """

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "runtime"))
    alice = _identity("ack-loop-alice")
    mom = _identity("ack-loop-mom")
    sender_repo = CapsuleRepository(tmp_path / "sender", master_seed=b"x" * 32)
    receiver_repo = CapsuleRepository(tmp_path / "receiver", master_seed=b"y" * 32)
    sender = _ready_daemon(alice, sender_repo)
    receiver = _ready_daemon(mom, receiver_repo)
    sender._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    receiver._broadcast_tail = lambda _event: None  # type: ignore[method-assign]
    sender._schedule_resume_paused = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    sender._schedule_outbox_flush = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
    sender._check_outbound_trust = lambda _peer: None  # type: ignore[method-assign]
    sender._inbound_is_rejected = lambda _peer_fp: False  # type: ignore[method-assign]
    receiver._inbound_is_rejected = lambda _peer_fp: False  # type: ignore[method-assign]

    receiver_to_sender: asyncio.Queue[bytes] = asyncio.Queue()

    class ReceiverChannel(_InboundChannel):
        async def send(self, payload: bytes) -> None:
            self.sent.append(decode_msg(payload))
            await receiver_to_sender.put(payload)

    receiver_channel = ReceiverChannel(alice)

    class OutboundChannel(_InboundChannel):
        async def send(self, payload: bytes) -> None:
            message = decode_msg(payload)
            self.sent.append(message)
            await receiver._on_peer_message(receiver_channel, message)

        async def recv(self) -> bytes:
            return await receiver_to_sender.get()

    outbound_channel = OutboundChannel(mom)
    peer = Peer(
        short_id=mom.short_id,
        hostname=mom.hostname,
        address="127.0.0.1",
        port=1,
        ed_pub_hex=mom.public_bytes.hex(),
    )
    session = type("LoopbackSession", (), {
        "peer_fp": mom.fingerprint,
        "peer": peer,
        "channel": outbound_channel,
        "lock": asyncio.Lock(),
        "last_used": 0.0,
        "messages_sent": 0,
        "regime": "loopback",
    })()

    async def get_session(_peer, **_kwargs):
        return session

    sender._get_outbound_session = get_session  # type: ignore[method-assign]
    sender._resolve_peer_for_outbound = lambda _peer_fp: peer  # type: ignore[method-assign]
    sender._peer_advertised_caps = (  # type: ignore[method-assign]
        lambda _peer_fp: frozenset({ASYNC_CAPSULE_V1})
    )

    capsule = AsyncCapsule(**{
        **_capsule(alice, mom).__dict__,
        "capsule_id": "capsule-real-ack-loop",
    })
    pending = sender_repo.store_capsule(
        capsule,
        peer_fp=mom.fingerprint,
        direction="outbound",
    )
    await sender._deliver_capsule_record(pending)

    sent = sender_repo.get(capsule.capsule_id)
    received = receiver_repo.get(capsule.capsule_id)
    assert sent is not None and sent.status == "delivered"
    assert received is not None and received.status == "received"
    assert receiver_channel.sent[-2]["t"] == "CAPSULE_RECEIPT"
    assert receiver_channel.sent[-1]["t"] == "ACK"
    receipt_id = receiver_channel.sent[-2]["id"]
    reverse_acks = [
        message for message in outbound_channel.sent
        if message.get("t") == "ACK" and message.get("of") == receipt_id
    ]
    assert len(reverse_acks) == 1
    assert session.messages_sent >= 3
    assert receiver_to_sender.empty()
    sender_repo.close()
    receiver_repo.close()
