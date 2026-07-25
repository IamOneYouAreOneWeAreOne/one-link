"""Fault-injection coverage for transport-bound chunk commit receipts."""

from __future__ import annotations

import asyncio
import base64
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon, IncomingFile, OutboundSession
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg


def _identity() -> Identity:
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
        hostname="receipt-test",
    )


def _native_chunk(
    msg_id: str,
    *,
    seq: int = 0,
    eof: bool = False,
    payload_byte: int = 1,
    blob: str = "ab" * 32,
) -> dict[str, Any]:
    return {
        "t": "FILE_NATIVE_CHUNK",
        "id": msg_id,
        "ts": 1,
        "from": "sender",
        "blob": blob,
        "seq": seq,
        "chunk_index": seq,
        "chunk_id": f"{payload_byte:02x}" * 32,
        "plaintext_len": 3,
        "data": base64.b64encode(bytes([payload_byte]) * 32).decode("ascii"),
        "eof": eof,
    }


class _ReceiptConnection:
    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[str] = []
        self.closed = False
        self._lock = threading.Lock()

    def send_frame_round_trip(self, _kind: int, payload: bytes):
        msg = decode_msg(payload)
        with self._lock:
            self.calls.append(str(msg["id"]))
        return self.responder(msg)

    def close(self, _code: int, _reason: bytes) -> None:
        self.closed = True


def _patch_quic_constants(monkeypatch) -> tuple[int, int]:
    from one_link import peer_quic

    request_kind = 41
    response_kind = 42
    monkeypatch.setattr(peer_quic, "HAS_NATIVE", True)
    monkeypatch.setattr(peer_quic, "FRAME_CHUNK_REQUEST", request_kind)
    monkeypatch.setattr(peer_quic, "FRAME_CHUNK_RESPONSE", response_kind)
    return request_kind, response_kind


@pytest.mark.asyncio
async def test_parallel_lane_failure_retries_only_unresolved_chunk(
    monkeypatch,
) -> None:
    """A lost response after commit must not replay successful lanes."""
    _request_kind, response_kind = _patch_quic_constants(monkeypatch)
    daemon = Daemon(_identity())
    chunks = [_native_chunk("chunk-0"), _native_chunk("chunk-1", seq=1, payload_byte=2)]

    def first_responder(msg: dict):
        if msg["id"] == "chunk-1":
            # Receiver committed, but this lane's response vanished.
            raise OSError("injected response loss after commit")
        receipt = daemon._make_quic_chunk_receipt(
            msg,
            status="committed",
            committed_offset=3,
        )
        return response_kind, encode_msg(receipt)

    def retry_responder(msg: dict):
        receipt = daemon._make_quic_chunk_receipt(
            msg,
            status="duplicate",
            committed_offset=6,
        )
        return response_kind, encode_msg(receipt)

    first = _ReceiptConnection(first_responder)
    retry = _ReceiptConnection(retry_responder)
    connections = iter((first, retry))

    async def _dial(_peer_fp: str, _peer: Any):
        return next(connections)

    monkeypatch.setattr(daemon, "_get_or_dial_quic", _dial)
    result = await daemon.send_chunks_via_quic_parallel(
        "peer-fingerprint",
        SimpleNamespace(short_id="peer"),
        chunks,
        lanes=2,
    )

    assert result["ok"] is True
    assert result["committed_indices"] == [0, 1]
    assert sorted(first.calls) == ["chunk-0", "chunk-1"]
    assert retry.calls == ["chunk-1"]
    assert "chunk-0" not in retry.calls


@pytest.mark.asyncio
async def test_receiver_rejection_is_not_counted_or_retried(monkeypatch) -> None:
    _request_kind, response_kind = _patch_quic_constants(monkeypatch)
    daemon = Daemon(_identity())
    chunk = _native_chunk("rejected")

    def responder(msg: dict):
        receipt = daemon._make_quic_chunk_receipt(
            msg,
            status="rejected",
            committed_offset=0,
            reason="native_chunk_decrypt_failed",
        )
        return response_kind, encode_msg(receipt)

    conn = _ReceiptConnection(responder)

    async def _dial(_peer_fp: str, _peer: Any):
        return conn

    monkeypatch.setattr(daemon, "_get_or_dial_quic", _dial)
    result = await daemon.send_chunk_via_quic(
        "peer-fingerprint", SimpleNamespace(short_id="peer"), chunk,
    )

    assert result["ok"] is False
    assert result["rejected"] is True
    assert "decrypt_failed" in result["error"]
    assert conn.calls == ["rejected"]


@pytest.mark.asyncio
async def test_opaque_legacy_response_is_commit_unknown_not_success(monkeypatch) -> None:
    _request_kind, response_kind = _patch_quic_constants(monkeypatch)
    daemon = Daemon(_identity())
    first = _ReceiptConnection(lambda _msg: (response_kind, b"ok"))
    retry = _ReceiptConnection(lambda _msg: (response_kind, b"ok"))
    connections = iter((first, retry))

    async def _dial(_peer_fp: str, _peer: Any):
        return next(connections)

    monkeypatch.setattr(daemon, "_get_or_dial_quic", _dial)
    result = await daemon.send_chunks_via_quic_parallel(
        "peer-fingerprint",
        SimpleNamespace(short_id="peer"),
        [_native_chunk("legacy")],
        lanes=1,
    )

    assert result["ok"] is False
    assert result["commit_unknown_indices"] == [0]
    assert result["frames"] == 0


def test_receipt_binding_rejects_crossed_response() -> None:
    daemon = Daemon(_identity())
    requested = _native_chunk("wanted")
    crossed = _native_chunk("other")
    response = daemon._make_quic_chunk_receipt(
        crossed,
        status="committed",
        committed_offset=3,
    )

    result = daemon._validate_quic_chunk_receipt(requested, encode_msg(response))

    assert result["ok"] is False
    assert result["commit_unknown"] is True
    assert "of mismatch" in result["error"]


class _FakeNativeSession:
    def __init__(self, plaintext: bytes) -> None:
        self.plaintext = plaintext
        self.decrypt_calls = 0

    def decrypt_chunk(self, _record) -> bytes:
        self.decrypt_calls += 1
        return self.plaintext


class _CaptureChannel:
    def __init__(self, session: _FakeNativeSession) -> None:
        self.session = session
        self.sent: list[dict[str, Any]] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    def get_or_create_native_transfer_session(self):
        return self.session


def _incoming_file(
    tmp_path: Path,
    *,
    blob: str,
    size: int,
) -> IncomingFile:
    out_path = tmp_path / "incoming.partial"
    return IncomingFile(
        name="incoming.bin",
        size=size,
        blob_hex=blob,
        out_path=out_path,
        handle=open(out_path, "x+b"),
        hasher=blake3.blake3(),
        transfer_id=f"in:{blob}",
        acceptance_granted=True,
    )


@pytest.mark.asyncio
async def test_committed_native_replay_skips_decrypt_write_and_sequence_abort(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    daemon = Daemon(_identity())
    monkeypatch.setattr(daemon, "_capability_allowed", lambda *_a, **_k: True)
    monkeypatch.setattr(daemon, "_update_transfer", lambda *_a, **_k: None)
    blob = "cd" * 32
    incoming = _incoming_file(tmp_path, blob=blob, size=6)
    daemon._incoming_files[blob] = incoming
    session = _FakeNativeSession(b"abc")
    channel = _CaptureChannel(session)
    msg = _native_chunk("same-content-new-id", blob=blob)

    await daemon._handle_file_native_chunk(channel, msg, "peer-fp", "peer")
    # Simulate fallback/retry of the exact encrypted request after its first
    # transport response vanished.
    replay = dict(msg)
    replay["id"] = "fallback-id"
    await daemon._handle_file_native_chunk(channel, replay, "peer-fp", "peer")

    assert session.decrypt_calls == 1
    assert incoming.received == 3
    assert incoming.next_seq == 1
    assert daemon._incoming_files[blob] is incoming
    assert channel.sent[-1]["duplicate_success"] is True
    assert channel.sent[-1]["of"] == "fallback-id"
    incoming.handle.close()


@pytest.mark.asyncio
async def test_native_eof_hash_mismatch_sends_rejection_and_no_commit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    daemon = Daemon(_identity())
    monkeypatch.setattr(daemon, "_capability_allowed", lambda *_a, **_k: True)
    monkeypatch.setattr(daemon, "_update_transfer", lambda *_a, **_k: None)
    monkeypatch.setattr(daemon, "_persist", lambda **_k: {})
    monkeypatch.setattr(daemon, "_broadcast_tail", lambda *_a, **_k: None)
    monkeypatch.setattr(daemon, "_quarantine_failed_inbox", lambda *_a, **_k: None)
    blob = "00" * 32  # deliberately not BLAKE3("abc")
    incoming = _incoming_file(tmp_path, blob=blob, size=3)
    daemon._incoming_files[blob] = incoming
    channel = _CaptureChannel(_FakeNativeSession(b"abc"))
    msg = _native_chunk("bad-eof", eof=True, blob=blob)

    await daemon._handle_file_native_chunk(channel, msg, "peer-fp", "peer")

    assert channel.sent[-1]["rejected"] == "file_native_eof_integrity_failure"
    assert daemon._lookup_quic_chunk_commit("peer-fp", msg) is None
    assert blob not in daemon._incoming_files


class _InboundQuicConnection:
    def __init__(self, request_kind: int, request: dict) -> None:
        self.request_kind = request_kind
        self.request = request
        self.recv_count = 0
        self.responses: list[tuple[int, int, bytes]] = []

    def recv_frame_blocking(self, _timeout_ms: int):
        self.recv_count += 1
        if self.recv_count == 1:
            return 7, self.request_kind, encode_msg(self.request)
        return None

    def is_connected(self) -> bool:
        return False

    def send_response_on(self, stream_id: int, kind: int, payload: bytes) -> None:
        self.responses.append((stream_id, kind, payload))

    def close(self, _code: int, _reason: bytes) -> None:
        return None


@pytest.mark.asyncio
async def test_inbound_dispatcher_propagates_handler_rejection(
    tmp_path: Path,
    monkeypatch,
) -> None:
    request_kind, response_kind = _patch_quic_constants(monkeypatch)
    from one_link import peer_quic

    monkeypatch.setattr(peer_quic, "FRAME_PING", 40)
    monkeypatch.setattr(peer_quic, "FRAME_PONG", 43)
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "home"))
    daemon = Daemon(_identity())
    monkeypatch.setattr(daemon, "_capability_allowed", lambda *_a, **_k: True)
    monkeypatch.setattr(daemon, "_update_transfer", lambda *_a, **_k: None)
    blob = "ef" * 32
    daemon._incoming_files[blob] = _incoming_file(tmp_path, blob=blob, size=3)
    request = _native_chunk("no-native-session", eof=True, blob=blob)
    conn = _InboundQuicConnection(request_kind, request)

    await daemon._quic_inbound_frame_loop(conn, "127.0.0.1", "peer-fp")

    assert len(conn.responses) == 1
    stream_id, kind, payload = conn.responses[0]
    receipt = decode_msg(payload)
    assert stream_id == 7
    assert kind == response_kind
    assert receipt["t"] == "FILE_CHUNK_RECEIPT"
    assert receipt["status"] == "rejected"
    assert receipt["reason"] == "native_transfer_unavailable"
    assert receipt["of"] == request["id"]


class _DynamicAckChannel:
    def __init__(self, peer: Identity, *, reject_chunk: bool = False) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.peer_caps = {"features": ["files"]}
        self.sent: list[dict[str, Any]] = []
        self.recv_calls = 0
        self.reject_chunk = reject_chunk
        self.closed = False

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        self.recv_calls += 1
        latest = self.sent[-1]
        if self.recv_calls == 1 and not self.reject_chunk:
            # This used to be accepted as the offer ACK despite having no
            # correlation id.  The sender must ignore it and wait for exact.
            return encode_msg(make_msg("ACK", self.peer_short_id))
        fields: dict[str, Any] = {"of": latest["id"]}
        if self.reject_chunk and latest["t"] != "FILE_OFFER":
            fields["rejected"] = "receiver_disk_write_failed"
        return encode_msg(make_msg("ACK", self.peer_short_id, **fields))

    async def close(self) -> None:
        self.closed = True


def _sender_with_session(
    tmp_path: Path,
    *,
    reject_chunk: bool,
) -> tuple[Daemon, Peer, _DynamicAckChannel, State]:
    me = _identity()
    them = _identity()
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint=them.fingerprint,
        short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    peer = Peer(
        short_id=them.short_id,
        hostname="peer",
        address="127.0.0.1",
        port=12345,
        ed_pub_hex=them.public_bytes.hex(),
    )
    channel = _DynamicAckChannel(them, reject_chunk=reject_chunk)
    daemon._outbound_sessions[them.fingerprint] = OutboundSession(
        peer_fp=them.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=time.time(),
        regime="lan",
    )
    return daemon, peer, channel, state


@pytest.mark.asyncio
async def test_webrtc_ack_requires_exact_of(tmp_path: Path) -> None:
    daemon, peer, channel, state = _sender_with_session(
        tmp_path,
        reject_chunk=False,
    )
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    try:
        result = await daemon.send_file(peer, source)
    finally:
        state.close()

    assert result["chunks"] == 1
    # missing-of offer ACK, exact offer ACK, exact chunk ACK
    assert channel.recv_calls == 3


@pytest.mark.asyncio
async def test_webrtc_rejected_chunk_ack_aborts_sender(tmp_path: Path) -> None:
    daemon, peer, _channel, state = _sender_with_session(
        tmp_path,
        reject_chunk=True,
    )
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    try:
        with pytest.raises(RuntimeError, match="receiver_disk_write_failed"):
            await daemon.send_file(peer, source)
    finally:
        state.close()
