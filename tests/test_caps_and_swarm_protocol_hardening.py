from __future__ import annotations

import asyncio
import base64
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as channel_module
from one_link import daemon as daemon_module
from one_link.blobstore import BlobStore
from one_link.capabilities import LOCAL_CAPABILITIES
from one_link.daemon import Daemon, MAX_INCOMING_FILE_BYTES
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg


def _identity(hostname: str) -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname=hostname,
    )


class _NegotiationChannel:
    def __init__(self, replies: list[dict]) -> None:
        self.replies = list(replies)
        self.sent: list[dict] = []
        self.caps_sent = 0
        self.activation_checks = 0

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        if not self.replies:
            await asyncio.Future()
        return encode_msg(self.replies.pop(0))

    def note_caps_sent(self) -> None:
        self.caps_sent += 1

    def maybe_activate_ratchet(self) -> bool:
        self.activation_checks += 1
        return False


@pytest.mark.asyncio
async def test_outbound_caps_negotiation_requires_caps_as_first_frame() -> None:
    daemon = Daemon.__new__(Daemon)
    daemon._build_my_caps_for_channel = MagicMock(
        return_value=make_msg("CAPS", "local", features=[]),
    )
    daemon._on_peer_message = AsyncMock()
    channel = _NegotiationChannel([make_msg("PONG", "peer")])

    with pytest.raises(RuntimeError, match="expected CAPS, got PONG"):
        await daemon._negotiate_outbound_caps(
            channel,  # type: ignore[arg-type]
            peer_label="peer",
            timeout_s=0.1,
        )

    assert channel.sent[0]["t"] == "CAPS"
    assert channel.caps_sent == 1
    daemon._on_peer_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_outbound_caps_negotiation_dispatches_validated_preface() -> None:
    daemon = Daemon.__new__(Daemon)
    local_caps = make_msg("CAPS", "local", features=[])
    peer_caps = make_msg("CAPS", "peer", features=[])
    daemon._build_my_caps_for_channel = MagicMock(return_value=local_caps)
    daemon._on_peer_message = AsyncMock()
    channel = _NegotiationChannel([peer_caps])

    result = await daemon._negotiate_outbound_caps(
        channel,  # type: ignore[arg-type]
        peer_label="peer",
        timeout_s=0.1,
    )

    assert result == peer_caps
    assert channel.sent == [local_caps]
    assert channel.caps_sent == 1
    daemon._on_peer_message.assert_awaited_once_with(channel, peer_caps)


@pytest.mark.asyncio
async def test_inbound_channel_rejects_application_frame_before_bound_caps(
    tmp_path: Path,
) -> None:
    receiver = _identity("receiver")
    initiator = _identity("initiator")
    daemon = Daemon(receiver)
    state = State(db_path=tmp_path / "reject-before-caps.db")
    daemon.state = state
    server = await asyncio.start_server(
        daemon._handle_peer, host="127.0.0.1", port=0,
    )
    port = int(server.sockets[0].getsockname()[1])
    client = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = await channel_module.initiate(
            reader,
            writer,
            initiator,
            expected_responder_ed_pub=receiver.public_bytes,
        )
        server_caps = decode_msg(await asyncio.wait_for(client.recv(), timeout=1.0))
        assert server_caps["t"] == "CAPS"

        await client.send(encode_msg(make_msg("PING", initiator.short_id)))
        with pytest.raises(
            (asyncio.IncompleteReadError, ConnectionError, RuntimeError),
        ):
            await asyncio.wait_for(client.recv(), timeout=1.0)
    finally:
        if client is not None:
            await client.close()
        server.close()
        await server.wait_closed()
        state.close()


@pytest.mark.asyncio
async def test_live_bound_caps_unlocks_post_handshake_ping(tmp_path: Path) -> None:
    receiver = _identity("receiver")
    initiator = _identity("initiator")
    daemon = Daemon(receiver)
    state = State(db_path=tmp_path / "valid-caps.db")
    daemon.state = state
    server = await asyncio.start_server(
        daemon._handle_peer, host="127.0.0.1", port=0,
    )
    port = int(server.sockets[0].getsockname()[1])
    client = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = await channel_module.initiate(
            reader,
            writer,
            initiator,
            expected_responder_ed_pub=receiver.public_bytes,
        )
        server_caps = decode_msg(await asyncio.wait_for(client.recv(), timeout=1.0))
        assert server_caps["t"] == "CAPS"
        client.note_caps_received(list(server_caps.get("features") or []))

        caps = make_msg(
            "CAPS",
            initiator.short_id,
            protocol="OL1.2",
            features=list(LOCAL_CAPABILITIES),
            channel_bind={
                "self_fp": initiator.fingerprint,
                "peer_fp": receiver.fingerprint,
                "transcript": client.transcript_hex,
                "features": list(LOCAL_CAPABILITIES),
            },
        )
        await client.send(encode_msg(caps))
        client.note_caps_sent()
        client.maybe_activate_ratchet()
        ping = make_msg("PING", initiator.short_id)
        await client.send(encode_msg(ping))

        response = decode_msg(await asyncio.wait_for(client.recv(), timeout=1.0))
        assert response["t"] == "PONG"
        assert response["of"] == ping["id"]
    finally:
        if client is not None:
            await client.close()
        server.close()
        await server.wait_closed()
        state.close()


class _Writer:
    def close(self) -> None:
        pass

    async def wait_closed(self) -> None:
        pass


class _PullChannel:
    def __init__(self, peer: Identity, frames: list[dict]) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.frames = list(frames)
        self.sent: list[dict] = []
        self.closed = False

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        if not self.frames:
            await asyncio.Future()
        return encode_msg(self.frames.pop(0))

    async def close(self) -> None:
        self.closed = True


def _pull_daemon(tmp_path: Path, peer: Identity) -> Daemon:
    daemon = Daemon(_identity("local"))
    daemon.blob_store = BlobStore(root=tmp_path / "blobs")
    daemon.state = None
    daemon._dial_peer = AsyncMock(return_value=(object(), _Writer()))
    daemon._peer_fp_from_peer = MagicMock(return_value=peer.fingerprint)
    daemon._is_pinned = MagicMock(return_value=True)
    daemon._verify_channel_peer = MagicMock(return_value=peer.fingerprint)
    daemon._negotiate_outbound_caps = AsyncMock()
    return daemon


def _peer(identity: Identity) -> Peer:
    return Peer(
        short_id=identity.short_id,
        hostname=identity.hostname,
        address="127.0.0.1",
        port=9,
        ed_pub_hex=identity.public_bytes.hex(),
    )


@pytest.mark.asyncio
async def test_swarm_pull_streams_zero_byte_blob_to_cas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_identity = _identity("peer")
    blob_hash = blake3.blake3(b"").hexdigest()
    channel = _PullChannel(peer_identity, [
        make_msg("BLOB_OFFER", peer_identity.short_id, blob=blob_hash, size=0),
        make_msg(
            "BLOB_CHUNK", peer_identity.short_id,
            blob=blob_hash, seq=0, data="", eof=True,
        ),
    ])
    daemon = _pull_daemon(tmp_path, peer_identity)

    async def initiate(*_args, **_kwargs):
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", initiate)
    assert await daemon._request_blob_from_peer(
        _peer(peer_identity), blob_hash, timeout_s=1.0,
    )
    assert daemon.blob_store is not None
    assert daemon.blob_store.read_bytes(blob_hash) == b""
    assert channel.closed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "frames_factory",
    [
        lambda peer, blob: [
            make_msg("BLOB_OFFER", peer.short_id, blob=blob, size=3),
            make_msg(
                "BLOB_CHUNK", peer.short_id,
                blob=blob, seq=1,
                data=base64.b64encode(b"abc").decode("ascii"), eof=True,
            ),
        ],
        lambda peer, blob: [
            make_msg(
                "BLOB_OFFER", peer.short_id,
                blob=blob, size=MAX_INCOMING_FILE_BYTES + 1,
            ),
        ],
        lambda peer, blob: [
            make_msg("BLOB_OFFER", peer.short_id, blob=blob, size=3),
            make_msg(
                "BLOB_CHUNK", peer.short_id,
                blob=blob, seq=0, data="%%%not-base64%%%", eof=True,
            ),
        ],
    ],
)
async def test_swarm_pull_rejects_malformed_or_resource_abusive_streams(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    frames_factory,
) -> None:
    peer_identity = _identity("peer")
    blob_hash = blake3.blake3(b"abc").hexdigest()
    channel = _PullChannel(
        peer_identity,
        frames_factory(peer_identity, blob_hash),
    )
    daemon = _pull_daemon(tmp_path, peer_identity)

    async def initiate(*_args, **_kwargs):
        return channel

    monkeypatch.setattr(daemon_module.ch, "initiate", initiate)
    assert not await daemon._request_blob_from_peer(
        _peer(peer_identity), blob_hash, timeout_s=1.0,
    )
    assert daemon.blob_store is not None
    assert not daemon.blob_store.has(blob_hash)
    assert channel.closed
