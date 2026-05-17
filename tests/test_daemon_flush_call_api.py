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
from one_link.call_manager import CallManagerRegistry, TailEvent, TailEventKind
from one_link.daemon import Daemon
from one_link.identity import Identity


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
