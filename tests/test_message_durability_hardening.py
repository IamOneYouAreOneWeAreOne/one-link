"""Adversarial receipt, idempotency, and bounded-TEXT regression tests."""

from __future__ import annotations

import time
from collections import deque
from pathlib import Path

import blake3
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.discovery import Peer
from one_link.identity import Identity
from one_link.state import State
from one_link.wire import decode_msg, make_msg


def _identity(label: str) -> Identity:
    private = Ed25519PrivateKey.from_private_bytes(
        blake3.blake3(label.encode()).digest()[:32],
    )
    public = private.public_key()
    raw = public.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    fingerprint = blake3.blake3(raw).hexdigest()
    return Identity(
        private=private,
        public=public,
        public_bytes=raw,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=label,
    )


class _Channel:
    def __init__(self, peer: Identity) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.peer_caps = {"features": ["chat"]}
        self.sent: list[bytes] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(payload)


@pytest.fixture
def durable_daemon(tmp_path: Path):
    local = _identity("durable-local")
    remote = _identity("durable-remote")
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint=remote.fingerprint,
        short_id=remote.short_id,
        pubkey=remote.public_bytes,
    )
    state.set_peer_trust(remote.fingerprint, "pinned")
    daemon = Daemon(me=local)
    daemon.state = state
    daemon._capability_allowed = lambda *_args, **_kwargs: True  # type: ignore[method-assign]
    yield daemon, state, local, remote
    state.close()


@pytest.mark.asyncio
async def test_inbound_text_is_committed_before_durable_ack(durable_daemon):
    daemon, state, _local, remote = durable_daemon
    channel = _Channel(remote)
    broadcasts: list[dict] = []
    daemon._broadcast_tail = broadcasts.append  # type: ignore[method-assign]
    msg = make_msg("TEXT", remote.short_id, id="durable-text-0001", body="hello")

    await daemon._on_peer_message(channel, msg)

    stored = state.get_message("durable-text-0001")
    assert stored is not None and stored.body == "hello"
    ack = decode_msg(channel.sent[-1])
    assert ack["of"] == msg["id"] and ack["durable"] is True
    assert len(broadcasts) == 1


@pytest.mark.asyncio
async def test_persist_failure_sends_negative_receipt_and_never_broadcasts(
    durable_daemon, monkeypatch: pytest.MonkeyPatch,
):
    daemon, state, _local, remote = durable_daemon
    channel = _Channel(remote)
    broadcasts: list[dict] = []
    daemon._broadcast_tail = broadcasts.append  # type: ignore[method-assign]
    monkeypatch.setattr(
        state, "record_message", lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    msg = make_msg("TEXT", remote.short_id, id="durable-text-0002", body="hello")

    await daemon._on_peer_message(channel, msg)

    ack = decode_msg(channel.sent[-1])
    assert ack["rejected"] == "message_persistence_failed"
    assert broadcasts == []


@pytest.mark.asyncio
async def test_exact_replay_is_acked_without_duplicate_render_and_conflict_fails(
    durable_daemon,
):
    daemon, _state, _local, remote = durable_daemon
    channel = _Channel(remote)
    broadcasts: list[dict] = []

    class _Ui:
        @staticmethod
        def broadcast(event):
            broadcasts.append(event)

    daemon.ui_server = _Ui()
    original = make_msg(
        "TEXT", remote.short_id, id="durable-text-0003", body="original",
    )
    await daemon._on_peer_message(channel, original)
    await daemon._on_peer_message(channel, dict(original))
    assert len(broadcasts) == 1
    assert decode_msg(channel.sent[-1])["durable"] is True

    conflict = {**original, "body": "replacement"}
    await daemon._on_peer_message(channel, conflict)
    assert decode_msg(channel.sent[-1])["rejected"] == "message_id_conflict"
    assert len(broadcasts) == 1


@pytest.mark.asyncio
async def test_text_schema_and_size_reject_before_state_mutation(durable_daemon):
    daemon, state, _local, remote = durable_daemon
    channel = _Channel(remote)
    malformed = make_msg(
        "TEXT", remote.short_id, id="durable-text-0004", body="hello",
        attacker_extension=True,
    )
    await daemon._on_peer_message(channel, malformed)
    assert decode_msg(channel.sent[-1])["rejected"] == "malformed_text"
    assert state.get_message("durable-text-0004") is None

    oversized = make_msg(
        "TEXT", remote.short_id, id="durable-text-0005", body="x" * (64 * 1024 + 1),
    )
    await daemon._on_peer_message(channel, oversized)
    assert decode_msg(channel.sent[-1])["rejected"] == "malformed_text"
    assert state.get_message("durable-text-0005") is None


@pytest.mark.asyncio
async def test_outbound_text_exists_on_disk_before_network_send(durable_daemon):
    daemon, state, _local, remote = durable_daemon
    peer = Peer(
        short_id=remote.short_id,
        hostname=remote.hostname,
        address="127.0.0.1",
        port=1,
        ed_pub_hex=remote.public_bytes.hex(),
    )

    async def _send(_peer, messages):
        stored = state.get_message("durable-text-0006")
        assert stored is not None and stored.body == "before wire"
        return [{"t": "ACK", "of": messages[0]["id"], "durable": True}]

    daemon.send_to = _send  # type: ignore[method-assign]
    result = await daemon.send_text(
        peer, "before wire", client_msg_id="durable-text-0006",
    )
    assert result["sent"]["id"] == "durable-text-0006"


@pytest.mark.asyncio
async def test_outbound_retry_reuses_original_timestamp_and_rejects_id_conflict(
    durable_daemon,
):
    daemon, _state, _local, remote = durable_daemon
    peer = Peer(
        short_id=remote.short_id,
        hostname=remote.hostname,
        address="127.0.0.1",
        port=1,
        ed_pub_hex=remote.public_bytes.hex(),
    )
    observed: list[dict] = []

    async def _send(_peer, messages):
        observed.append(dict(messages[0]))
        return [{"t": "ACK", "of": messages[0]["id"], "durable": True}]

    daemon.send_to = _send  # type: ignore[method-assign]
    await daemon.send_text(peer, "same", client_msg_id="durable-text-0007")
    await daemon.send_text(peer, "same", client_msg_id="durable-text-0007")
    assert observed[0] == observed[1]
    with pytest.raises(ValueError, match="reused for different content"):
        await daemon.send_text(peer, "different", client_msg_id="durable-text-0007")


@pytest.mark.asyncio
async def test_reaction_exact_replay_is_acked_after_target_disappears(
    durable_daemon,
):
    daemon, state, _local, remote = durable_daemon
    state.record_message(
        id="reaction-target-1", ts_ms=1, direction="out",
        peer_fp=remote.fingerprint, msg_type="TEXT", body="target",
    )
    channel = _Channel(remote)
    msg = make_msg(
        "REACTION", remote.short_id, id="durable-reaction-1",
        target="reaction-target-1", emoji="👍", op="add",
    )
    await daemon._on_peer_message(channel, msg)
    assert decode_msg(channel.sent[-1])["durable"] is True
    daemon._text_rate_per_peer = {
        remote.fingerprint: deque([time.monotonic()] * 240),
    }

    # Model a later retention/clear operation removing the mutable target while
    # leaving the immutable action receipt. The exact retransmission still
    # needs its ACK so the sender can stop retrying.
    state._conn.execute(
        "DELETE FROM message_reactions WHERE target_msg_id = ?",
        ("reaction-target-1",),
    )
    state._conn.execute(
        "DELETE FROM messages WHERE id = ?", ("reaction-target-1",),
    )
    await daemon._on_peer_message(channel, dict(msg))
    replay_ack = decode_msg(channel.sent[-1])
    assert replay_ack["of"] == msg["id"]
    assert replay_ack["durable"] is True
    assert "rejected" not in replay_ack
