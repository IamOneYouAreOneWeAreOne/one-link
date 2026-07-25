"""Tests for the Daemon ↔ CallAPI bridge (flush_call_api_response).

The bridge takes an :class:`ApiResponse` from the CallAPI adapter
and performs the outbound side-effects: building wire dicts,
resolving peer records, and dispatching through ``send_to``.

These tests verify:
  - Outbound ApiMessages get translated to wire dicts via make_msg
  - send_to is called with the resolved Peer struct
  - Tail events get broadcast through _broadcast_tail
  - Unknown peers are logged and dropped (no raise)
  - send_to failures are logged and dropped (no raise)
  - Empty response just returns ()
"""

from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_api import (
    ApiOutboundMessage,
    ApiResponse,
    CallAPI,
)
from one_link.call_signaling import CallPhase
from one_link.call_manager import TailEvent, TailEventKind
from one_link.daemon import Daemon, OutboundSession
from one_link.identity import Identity
from one_link.wire import decode_msg, encode_msg, make_msg


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


class _FakePeerRecord:
    def __init__(self, *, short_id: str, ed_pub_hex: str) -> None:
        self.short_id = short_id
        self.hostname = "test-host"
        self.last_address = "127.0.0.1"
        self.last_port = 5000
        self.pubkey = bytes.fromhex(ed_pub_hex)
        self.rendezvous_urls: list[str] = []
        self.device_kind = ""
        self.trust = "pinned"


class _FakeState:
    def __init__(self, peers: dict[str, _FakePeerRecord]) -> None:
        self._peers = peers

    def get_peer(self, peer_fp: str):
        return self._peers.get(peer_fp)

    def get_peer_capability_policy(self, peer_fp: str):
        return None


@pytest.fixture
def alice() -> Identity:
    return _identity("alice-bridge")


@pytest.fixture
def mom() -> Identity:
    return _identity("mom-bridge")


@pytest.fixture
def alice_daemon(alice: Identity, mom: Identity) -> Daemon:
    d = Daemon(me=alice)
    d.state = _FakeState({
        mom.fingerprint: _FakePeerRecord(
            short_id=mom.short_id, ed_pub_hex=mom.public_bytes.hex(),
        ),
    })
    return d


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_resolve_peer_returns_peer_struct(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    peer = alice_daemon._resolve_peer_for_outbound(mom.fingerprint)
    assert peer is not None
    assert peer.short_id == mom.short_id
    assert peer.ed_pub_hex == mom.public_bytes.hex()


def test_resolve_peer_returns_none_for_unknown(
    alice_daemon: Daemon,
) -> None:
    peer = alice_daemon._resolve_peer_for_outbound("unknown-fp")
    assert peer is None


def test_resolve_peer_handles_no_state(alice: Identity) -> None:
    d = Daemon(me=alice)
    d.state = None
    assert d._resolve_peer_for_outbound("anything") is None


def test_sync_peer_verification_sends_notice(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    captured: list[dict] = []

    async def fake_send_to(peer, msgs):
        captured.extend(msgs)
        return [{"t": "ACK", "ok": True}]

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]
    loop = asyncio.new_event_loop()
    try:
        ok = loop.run_until_complete(
            alice_daemon.sync_peer_verification(
                mom.fingerprint,
                verified=True,
                method="sas-digits",
                note="same room",
            )
        )
    finally:
        loop.close()
    assert ok is True
    assert captured[0]["t"] == "PEER_VERIFY_NOTICE"
    assert captured[0]["action"] == "set"
    assert captured[0]["method"] == "sas-digits"


def test_flush_empty_response_is_noop(alice_daemon: Daemon) -> None:
    resp = ApiResponse(ok=True, call_id="x")
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    assert result == ()


def test_flush_outbound_calls_send_to(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    captured: list[tuple[str, list[dict]]] = []

    async def fake_send_to(peer, msgs):
        captured.append((peer.ed_pub_hex, list(msgs)))
        return msgs

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-1",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE",
                peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-1", "ttl_ms": 30_000},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()

    assert delivered == (mom.fingerprint,)
    assert len(captured) == 1
    sent_peer_pub, sent_msgs = captured[0]
    assert sent_peer_pub == mom.public_bytes.hex()
    assert len(sent_msgs) == 1
    assert sent_msgs[0]["t"] == "CALL_INVITE"
    assert sent_msgs[0]["call_id"] == "call-1"
    assert sent_msgs[0]["from"] == alice_daemon.me.short_id


def test_flush_groups_by_peer(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """Multiple outbound messages to the same peer should hit
    send_to ONCE with a batched list."""
    captured: list[tuple[str, list[dict]]] = []

    async def fake_send_to(peer, msgs):
        captured.append((peer.ed_pub_hex, list(msgs)))
        return msgs

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-1",
        outbound=(
            ApiOutboundMessage(
                type="CALL_END", peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-1"},
            ),
            ApiOutboundMessage(
                type="RECORDING_STOP", peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-1"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()

    assert delivered == (mom.fingerprint,)
    assert len(captured) == 1
    _, sent_msgs = captured[0]
    assert len(sent_msgs) == 2
    assert {m["t"] for m in sent_msgs} == {"CALL_END", "RECORDING_STOP"}


def test_flush_tail_events_broadcast(alice_daemon: Daemon) -> None:
    """Tail events from the response get broadcast through
    _broadcast_tail with a normalised payload."""
    captured: list[dict] = []
    alice_daemon._broadcast_tail = lambda ev: captured.append(ev)  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-1",
        tail_events=(
            TailEvent(
                kind=TailEventKind.SHOW_RING,
                payload={"some_key": "some_value"},
            ),
            TailEvent(
                kind=TailEventKind.RECORDING_STATE_CHANGED,
                payload={"consent_phase": "recording"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()

    assert len(captured) == 2
    assert captured[0]["type"] == "call_event"
    assert captured[0]["tail_kind"] == "show_ring"
    assert captured[0]["call_id"] == "call-1"
    assert captured[0]["some_key"] == "some_value"


def test_flush_unknown_peer_logs_and_drops(
    alice_daemon: Daemon,
) -> None:
    """An outbound message to a peer we have no record for must
    NOT raise — just log and skip."""
    captured: list[tuple] = []

    async def fake_send_to(peer, msgs):
        captured.append((peer, msgs))

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="ghost",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE",
                peer_master_vk_hex="unknown-fp-deadbeef",
                payload={"call_id": "ghost"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    # No delivery + no send_to call.
    assert delivered == ()
    assert captured == []


def test_flush_send_to_failure_logs_and_drops(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """If send_to itself raises, the bridge logs and continues —
    the user_message has already told the user the truth."""

    async def boom(peer, msgs):
        raise RuntimeError("synthetic network failure")

    alice_daemon.send_to = boom  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-x",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE", peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-x"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    # No exception escaped.
    assert delivered == ()


def test_flush_retries_call_signal_once_on_closed_session(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """Call signaling is idempotent by call_id, so a stale reusable
    session should fall back to a fresh encrypted control channel."""

    send_to_attempts: list[list[dict]] = []
    control_attempts: list[dict] = []

    async def flaky(peer, msgs):
        send_to_attempts.append(list(msgs))
        raise ConnectionError("closed session")

    async def fresh_control(peer, msg):
        control_attempts.append(dict(msg))
        return b"transcript"

    alice_daemon.send_to = flaky  # type: ignore[assignment]
    alice_daemon._send_control = fresh_control  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-retry",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE",
                peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-retry"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    assert delivered == (mom.fingerprint,)
    assert len(send_to_attempts) == 1
    assert len(control_attempts) == 1
    assert control_attempts[0]["t"] == "CALL_INVITE"


def test_flush_send_to_timeout_does_not_hang_call_ui(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """A stuck live transport must not hold the /api/v1/calls
    response forever. The UI can show inviting state while the daemon
    logs the delivery timeout."""

    async def stuck(peer, msgs):
        await asyncio.sleep(60)

    alice_daemon.CALL_SIGNAL_SEND_TIMEOUT_S = 0.01
    alice_daemon.send_to = stuck  # type: ignore[assignment]

    resp = ApiResponse(
        ok=True,
        call_id="call-timeout",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE",
                peer_master_vk_hex=mom.fingerprint,
                payload={"call_id": "call-timeout"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    assert delivered == ()


def test_call_signal_fallback_sends_each_media_frame_over_control(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """SDP/ICE batches use the same reliable call channel; if the live
    session is stale, each frame is resent over one-shot encrypted control."""
    controls: list[str] = []

    async def stale(peer, msgs):
        raise TimeoutError("stale session")

    async def control(peer, msg):
        controls.append(msg["t"])
        return b"transcript"

    alice_daemon.send_to = stale  # type: ignore[assignment]
    alice_daemon._send_control = control  # type: ignore[assignment]

    msgs = [
        {"t": "CALL_SDP_OFFER", "id": "1", "from": alice_daemon.me.short_id, "call_id": "c", "sdp_offer": {}},
        {"t": "CALL_ICE", "id": "2", "from": alice_daemon.me.short_id, "call_id": "c", "candidate": {}},
    ]
    peer = alice_daemon._resolve_peer_for_outbound(mom.fingerprint)
    assert peer is not None
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(alice_daemon.send_call_signal(peer, msgs))
    finally:
        loop.close()
    assert controls == ["CALL_SDP_OFFER", "CALL_ICE"]


def test_call_signal_can_reply_over_existing_inbound_channel(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """When Alice dialed us first, our best return path may be that same
    bidirectional encrypted channel. Accept/hangup sends there first, then
    still confirms through fresh control so an idle caller cannot miss it."""

    class InboundChannel:
        def __init__(self) -> None:
            self.sent: list[dict] = []

        async def send(self, payload: bytes) -> None:
            from one_link.wire import decode_msg
            self.sent.append(decode_msg(payload))

    inbound = InboundChannel()
    alice_daemon._inbound_live_channels[mom.fingerprint] = [inbound]  # type: ignore[list-item]

    async def stale(peer, msgs):
        raise ConnectionError("outbound route stale")

    controls: list[dict] = []

    async def control(peer, msg):
        controls.append(msg)
        return b"transcript"

    alice_daemon.send_to = stale  # type: ignore[assignment]
    alice_daemon._send_control = control  # type: ignore[assignment]
    peer = alice_daemon._resolve_peer_for_outbound(mom.fingerprint)
    assert peer is not None
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(alice_daemon.send_call_signal(
            peer,
            [{"t": "CALL_ACCEPT", "id": "accept-1", "from": alice_daemon.me.short_id, "call_id": "c"}],
        ))
    finally:
        loop.close()

    assert inbound.sent == [{
        "t": "CALL_ACCEPT",
        "id": "accept-1",
        "from": alice_daemon.me.short_id,
        "call_id": "c",
    }]
    assert [m["t"] for m in controls] == ["CALL_ACCEPT"]


def test_send_to_dispatches_call_reply_that_arrives_before_ack(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """A peer can accept on the same bidirectional encrypted channel while
    our outbound send_to is still waiting for the ACK to CALL_INVITE. The
    ACK waiter must dispatch that CALL_ACCEPT instead of swallowing it."""

    class DuplexChannel:
        def __init__(self, incoming: list[dict]) -> None:
            self.peer_ed_pub = mom.public_bytes
            self.peer_short_id = mom.short_id
            self.sent: list[dict] = []
            self._incoming = [encode_msg(m) for m in incoming]

        async def send(self, payload: bytes) -> None:
            self.sent.append(decode_msg(payload))

        async def recv(self) -> bytes:
            if not self._incoming:
                raise asyncio.IncompleteReadError(b"", 1)
            return self._incoming.pop(0)

    api = CallAPI(
        registry=alice_daemon._call_registry,
        local_master_vk_hex=alice_daemon.me.fingerprint,
    )
    resp = api.initiate(peer_master_vk_hex=mom.fingerprint)
    assert resp.ok
    mgr = alice_daemon._call_registry.get(resp.call_id)
    assert mgr is not None

    outbound = make_msg(
        "CALL_INVITE", alice_daemon.me.short_id, call_id=resp.call_id,
    )
    inbound_accept = make_msg(
        "CALL_ACCEPT", mom.short_id, call_id=resp.call_id,
    )
    outbound_ack = make_msg(
        "ACK", mom.short_id, of=outbound["id"], ok=True,
    )
    channel = DuplexChannel([inbound_accept, outbound_ack])
    peer = alice_daemon._resolve_peer_for_outbound(mom.fingerprint)
    assert peer is not None
    sess = OutboundSession(
        peer_fp=mom.fingerprint,
        peer=peer,
        channel=channel,  # type: ignore[arg-type]
        lock=asyncio.Lock(),
        last_used=4_102_444_800.0,
        regime="lan",
    )
    alice_daemon._outbound_sessions[mom.fingerprint] = sess
    alice_daemon._persist = lambda **_: {"type": "message"}  # type: ignore[method-assign]
    alice_daemon._broadcast_tail = lambda _event: None  # type: ignore[method-assign]

    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(alice_daemon.send_to(peer, [outbound]))
    finally:
        loop.close()

    assert result == [outbound_ack]
    assert mgr.phase == CallPhase.ACTIVE
    assert any(m.get("t") == "ACK" and m.get("of") == inbound_accept["id"] for m in channel.sent)


def test_flush_skips_malformed_outbound_payload(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """A make_msg construction failure (e.g., unencodable payload)
    must not crash the whole flush — other outbound messages still
    go through."""
    captured: list[tuple[str, list[dict]]] = []

    async def fake_send_to(peer, msgs):
        captured.append((peer.ed_pub_hex, list(msgs)))

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]

    # First message has a payload that conflicts with make_msg's
    # reserved fields (it uses keyword args). Setting t/id/ts/from
    # in payload should be harmless because make_msg overrides them,
    # but a deeply broken value (e.g. non-string keys) raises.
    class _Unstable:
        def __init__(self) -> None:
            self.kwargs = {}
        def __iter__(self):
            raise RuntimeError("explode")

    resp = ApiResponse(
        ok=True,
        call_id="call-y",
        outbound=(
            ApiOutboundMessage(
                type="CALL_INVITE",
                peer_master_vk_hex=mom.fingerprint,
                payload={"good_field": "ok"},
            ),
        ),
    )
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(
            alice_daemon.flush_call_api_response(resp)
        )
    finally:
        loop.close()
    # The good message went through.
    assert len(captured) == 1


# ---------------------------------------------------------------------------
# End-to-end: CallAPI + Daemon flush
# ---------------------------------------------------------------------------

def test_end_to_end_call_api_to_daemon_flush(
    alice_daemon: Daemon, mom: Identity,
) -> None:
    """User taps Call Mom → CallAPI returns response → daemon
    flushes → send_to gets the CALL_INVITE."""
    captured: list[tuple[str, list[dict]]] = []

    async def fake_send_to(peer, msgs):
        captured.append((peer.ed_pub_hex, list(msgs)))

    alice_daemon.send_to = fake_send_to  # type: ignore[assignment]

    api = CallAPI(
        registry=alice_daemon._call_registry,
        local_master_vk_hex=alice_daemon.me.fingerprint,
    )
    api_resp = api.initiate(peer_master_vk_hex=mom.fingerprint)
    assert api_resp.ok

    loop = asyncio.new_event_loop()
    try:
        delivered = loop.run_until_complete(
            alice_daemon.flush_call_api_response(api_resp)
        )
    finally:
        loop.close()
    assert delivered == (mom.fingerprint,)
    assert len(captured) == 1
    _, msgs = captured[0]
    assert msgs[0]["t"] == "CALL_INVITE"
    assert msgs[0]["call_id"] == api_resp.call_id
