"""Tests for the SDP / ICE media-layer actions on /api/v1/calls.

Three browser → daemon actions that bypass CallManager and emit
standalone wire messages:

  - ``send_sdp_offer`` → CALL_SDP_OFFER
  - ``send_sdp_answer`` → CALL_SDP_ANSWER
  - ``send_ice_candidate`` → CALL_ICE

These don't touch the lifecycle FSM — they're the media-transport
rail. The server.py handler validates the SDP shape + builds the
wire message + dispatches via daemon.send_to.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock

import blake3
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from one_link.daemon import Daemon
from one_link.identity import Identity


# ---------------------------------------------------------------------------
# Scaffolding
# ---------------------------------------------------------------------------

def _make_identity(name: str) -> Identity:
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


class _FakePeer:
    def __init__(self, ed_pub_hex: str) -> None:
        self.ed_pub_hex = ed_pub_hex
        self.trust = "pinned"


class _FakeState:
    def __init__(self, peers: dict[str, str]) -> None:
        self._peers = {fp: _FakePeer(pub) for fp, pub in peers.items()}

    def get_peer(self, fp: str):
        return self._peers.get(fp)


class _FakeRequest:
    def __init__(self, body: dict) -> None:
        self._body = body

    async def json(self) -> dict:
        return self._body


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


SAMPLE_OFFER_SDP = (
    "v=0\r\n"
    "o=- 1 1 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
    "a=mid:0\r\n"
)
SAMPLE_ANSWER_SDP = (
    "v=0\r\n"
    "o=- 2 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
)


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def me() -> Identity:
    return _make_identity("server-me")


@pytest.fixture
def peer() -> Identity:
    return _make_identity("server-peer")


@pytest.fixture
def daemon_with_call(me: Identity, peer: Identity) -> Daemon:
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    # Pre-open a call so the media-layer actions have something to
    # look up.
    d._call_registry.open(
        call_id="srv-call-1",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=me.fingerprint,
        started_at_ms=1_000,
    )
    return d


@pytest.fixture
def server(daemon_with_call: Daemon):
    """Construct a Server with the daemon, capture send_to calls."""
    from one_link.server import UIServer as Server

    s = Server.__new__(Server)
    s.daemon = daemon_with_call
    s._lp_call_api_cached = None
    # Patch send_to to capture outbound payloads.
    s.daemon.send_to = AsyncMock()
    return s


# ---------------------------------------------------------------------------
# send_sdp_offer
# ---------------------------------------------------------------------------

def test_send_sdp_offer_dispatches_wire_message(server, peer) -> None:
    req = _FakeRequest({
        "action": "send_sdp_offer",
        "call_id": "srv-call-1",
        "sdp": SAMPLE_OFFER_SDP,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    assert body["call_id"] == "srv-call-1"
    # send_to was called once.
    assert server.daemon.send_to.await_count == 1
    _peer_arg, msgs_arg = server.daemon.send_to.await_args.args
    assert _peer_arg is server.daemon._resolve_peer_for_outbound(peer.fingerprint)
    assert len(msgs_arg) == 1
    wire = msgs_arg[0]
    assert wire["t"] == "CALL_SDP_OFFER"
    assert wire["call_id"] == "srv-call-1"
    assert "sdp_offer" in wire
    assert wire["sdp_offer"]["sdp"] == SAMPLE_OFFER_SDP
    assert wire["sdp_offer"]["kind"] == "offer"


def test_send_sdp_offer_rejects_invalid_sdp(server) -> None:
    req = _FakeRequest({
        "action": "send_sdp_offer",
        "call_id": "srv-call-1",
        "sdp": "not actually SDP",
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False
    # Doctrine — plain language.
    assert "error" not in body["user_message"].lower()
    assert server.daemon.send_to.await_count == 0


def test_send_sdp_offer_for_unknown_call_is_refused(server) -> None:
    req = _FakeRequest({
        "action": "send_sdp_offer",
        "call_id": "ghost",
        "sdp": SAMPLE_OFFER_SDP,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False
    assert server.daemon.send_to.await_count == 0


# ---------------------------------------------------------------------------
# send_sdp_answer
# ---------------------------------------------------------------------------

def test_send_sdp_answer_dispatches_wire_message(server) -> None:
    req = _FakeRequest({
        "action": "send_sdp_answer",
        "call_id": "srv-call-1",
        "sdp": SAMPLE_ANSWER_SDP,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    wire = server.daemon.send_to.await_args.args[1][0]
    assert wire["t"] == "CALL_SDP_ANSWER"
    assert wire["sdp_answer"]["sdp"] == SAMPLE_ANSWER_SDP
    assert wire["sdp_answer"]["kind"] == "answer"


# ---------------------------------------------------------------------------
# send_ice_candidate
# ---------------------------------------------------------------------------

def test_send_ice_candidate_dispatches_wire_message(server) -> None:
    req = _FakeRequest({
        "action": "send_ice_candidate",
        "call_id": "srv-call-1",
        "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
        "sdp_mid": "0",
        "sdp_m_line_index": 0,
        "end_of_candidates": False,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    wire = server.daemon.send_to.await_args.args[1][0]
    assert wire["t"] == "CALL_ICE"
    assert wire["candidate"]["candidate"].startswith("candidate:")
    assert wire["candidate"]["sdpMid"] == "0"
    assert wire["candidate"]["sdpMLineIndex"] == 0


def test_send_ice_end_of_candidates_sentinel(server) -> None:
    req = _FakeRequest({
        "action": "send_ice_candidate",
        "call_id": "srv-call-1",
        "candidate": "",
        "sdp_mid": None,
        "sdp_m_line_index": None,
        "end_of_candidates": True,
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    wire = server.daemon.send_to.await_args.args[1][0]
    assert wire["t"] == "CALL_ICE"
    assert wire["candidate"]["endOfCandidates"] is True


def test_send_ice_for_unknown_call_is_refused(server) -> None:
    req = _FakeRequest({
        "action": "send_ice_candidate",
        "call_id": "ghost",
        "candidate": "candidate:1 1 udp 1 1.2.3.4 1234 typ host",
    })
    resp = _run(server.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is False
    assert server.daemon.send_to.await_count == 0


# ---------------------------------------------------------------------------
# Existing initiate path still flushes outbound through send_to
# ---------------------------------------------------------------------------

def test_initiate_action_now_flushes_outbound(me: Identity, peer: Identity) -> None:
    """Regression: before this commit, api_call_action returned the
    ApiResponse but never called flush_call_api_response. Now an
    inbound `initiate` action must trigger send_to with a CALL_INVITE."""
    from one_link.server import UIServer as Server
    d = Daemon(me=me)
    d.state = _FakeState({peer.fingerprint: peer.public_bytes.hex()})
    d.send_to = AsyncMock()
    s = Server.__new__(Server)
    s.daemon = d
    s._lp_call_api_cached = None

    req = _FakeRequest({
        "action": "initiate",
        "peer_master_vk_hex": peer.fingerprint,
    })
    resp = _run(s.api_call_action(req))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["ok"] is True
    # send_to was called with a CALL_INVITE wire message.
    assert d.send_to.await_count == 1
    msgs = d.send_to.await_args.args[1]
    assert msgs[0]["t"] == "CALL_INVITE"
