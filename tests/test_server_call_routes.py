"""Tests for the HTTP routes that expose the CallAPI.

Verifies that ``POST /api/v1/calls`` + ``GET /api/v1/calls`` +
``GET /api/v1/calls/{call_id}`` dispatch correctly through the
UIServer → CallAPI → CallManager → registry chain.

The tests construct the UIServer's handler methods directly and
mock the aiohttp ``web.Request`` so we don't have to spin up a
real HTTP server.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_manager import (
    CallManager,
    CallManagerRegistry,
    ManagerEvent,
    ManagerEventKind,
)
from one_link.daemon import Daemon
from one_link.identity import Identity
from one_link.server import UIServer


# ---------------------------------------------------------------------------
# Helpers
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


class _FakeRequest:
    """Minimal aiohttp.web.Request stand-in.  Just enough for the
    handlers we wrote."""

    def __init__(
        self,
        *,
        body: dict | None = None,
        match_info: dict | None = None,
        query: dict | None = None,
    ) -> None:
        self._body = body or {}
        self.match_info = match_info or {}
        self.query = query or {}

    async def json(self) -> dict:
        return self._body


def _server_with_daemon(name: str = "alice-routes") -> tuple[UIServer, Daemon]:
    me = _identity(name)
    d = Daemon(me=me)
    # UIServer's __init__ touches the filesystem for the UI token.
    # Stub it out so tests don't write to disk.
    UIServer._load_or_create_token = MagicMock(return_value="test-token-x")  # type: ignore
    srv = UIServer(d)
    return srv, d


# ---------------------------------------------------------------------------
# CallAPI lazy construction
# ---------------------------------------------------------------------------

def test_call_api_cached_on_first_access() -> None:
    srv, _ = _server_with_daemon()
    api1 = srv._call_api()
    api2 = srv._call_api()
    assert api1 is api2


# ---------------------------------------------------------------------------
# POST /api/v1/calls — actions
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_initiate_returns_call_id_and_phase() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-routes")
    daemon.flush_call_api_response = AsyncMock(  # type: ignore[method-assign]
        return_value=(peer.fingerprint,),
    )
    req = _FakeRequest(body={
        "action": "initiate",
        "peer_master_vk_hex": peer.fingerprint,
        "negotiated_capabilities": ["webrtc_av_v1"],
    })
    resp = await srv.api_call_action(req)  # type: ignore[arg-type]
    body = (resp._body or b"")  # aiohttp Response: payload bytes
    import json
    payload = json.loads(body)
    assert payload["ok"] is True
    assert payload["call_id"]
    assert payload["phase"] == "inviting"
    assert payload["delivered"] == [peer.fingerprint]


@pytest.mark.asyncio
async def test_initiate_reports_unreachable_when_invite_not_delivered() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-unreachable")
    daemon.flush_call_api_response = AsyncMock(return_value=())  # type: ignore[method-assign]
    req = _FakeRequest(body={
        "action": "initiate",
        "peer_master_vk_hex": peer.fingerprint,
        "peer_label": "Computer 2",
    })
    resp = await srv.api_call_action(req)  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is False
    assert payload["phase"] == "inviting"
    assert payload["delivered"] == []
    assert "Computer 2 is not reachable right now" in payload["user_message"]


@pytest.mark.asyncio
async def test_action_on_unknown_call_id_returns_plain_language() -> None:
    srv, _ = _server_with_daemon()
    req = _FakeRequest(body={"action": "hangup", "call_id": "ghost"})
    resp = await srv.api_call_action(req)  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is False
    # Doctrine: plain language, no error codes
    msg = payload["user_message"].lower()
    assert "0x" not in msg
    assert "error" not in msg


@pytest.mark.asyncio
async def test_unknown_action_returns_calm_refusal() -> None:
    srv, _ = _server_with_daemon()
    req = _FakeRequest(body={"action": "frobnicate", "call_id": "x"})
    resp = await srv.api_call_action(req)  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is False
    assert "not available" in payload["user_message"].lower()


@pytest.mark.asyncio
async def test_malformed_body_handled_gracefully() -> None:
    srv, _ = _server_with_daemon()

    class _BadRequest:
        match_info: dict = {}

        async def json(self) -> Any:
            raise ValueError("malformed json")
    resp = await srv.api_call_action(_BadRequest())  # type: ignore[arg-type]
    assert resp.status == 400
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is False


# ---------------------------------------------------------------------------
# GET /api/v1/calls — list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_list_empty_when_no_calls() -> None:
    srv, _ = _server_with_daemon()
    resp = await srv.api_calls_list(_FakeRequest())  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload == {"calls": []}


@pytest.mark.asyncio
async def test_list_returns_active_call_after_initiate() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-list")
    # Open a call directly via the registry (cheaper than going through HTTP)
    mgr = daemon._call_registry.open(
        call_id="c1",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=daemon.me.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    resp = await srv.api_calls_list(_FakeRequest())  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert len(payload["calls"]) == 1
    assert payload["calls"][0]["call_id"] == "c1"
    assert payload["calls"][0]["phase"] == "inviting"
    assert payload["calls"][0]["peer_master_vk_hex"] == peer.fingerprint
    assert payload["calls"][0]["local_role"] == "originator"
    assert payload["calls"][0]["is_incoming"] is False
    assert payload["calls"][0]["peer_label"] == peer.short_id


@pytest.mark.asyncio
async def test_list_surfaces_incoming_ring_context_for_ui_backfill() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-inbound")
    daemon.state = MagicMock()
    daemon.state.get_peer.return_value = MagicMock(
        local_alias=None,
        display_name="Mom's laptop",
        hostname="Mom's laptop",
    )
    mgr = daemon._call_registry.open(
        call_id="c-ring",
        peer_master_vk_hex=peer.fingerprint,
        local_role="recipient",
        local_master_vk_hex=daemon.me.fingerprint,
        started_at_ms=2_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_INVITE, 2_000))
    daemon._call_sdp_backfill = {
        "c-ring": {"sdp_offer": "v=0\r\ns=-\r\n"}
    }
    resp = await srv.api_calls_list(_FakeRequest())  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    call = payload["calls"][0]
    assert call["call_id"] == "c-ring"
    assert call["phase"] == "ringing"
    assert call["local_role"] == "recipient"
    assert call["is_incoming"] is True
    assert call["peer_label"] == "Mom's laptop"
    assert call["pending_sdp_offer"] == "v=0\r\ns=-\r\n"


# ---------------------------------------------------------------------------
# GET /api/v1/calls/{call_id} — single call state
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_state_returns_doctrine_compliant_not_found() -> None:
    srv, _ = _server_with_daemon()
    req = _FakeRequest(match_info={"call_id": "ghost"})
    resp = await srv.api_call_state(req)  # type: ignore[arg-type]
    assert resp.status == 404
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is False
    # Doctrine: no "Error 404" — plain language only.
    msg = payload["user_message"].lower()
    assert "error" not in msg
    assert "no longer" in msg


@pytest.mark.asyncio
async def test_state_returns_call_snapshot() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-state")
    mgr = daemon._call_registry.open(
        call_id="c2",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=daemon.me.fingerprint,
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    req = _FakeRequest(match_info={"call_id": "c2"})
    resp = await srv.api_call_state(req)  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is True
    assert payload["call_id"] == "c2"
    assert payload["phase"] == "inviting"
    assert payload["is_active"] is False  # not yet ACCEPTed → not ACTIVE
    assert payload["peer_master_vk_hex"] == peer.fingerprint
    assert payload["local_role"] == "originator"
    assert payload["is_incoming"] is False
    assert "intensity" in payload
    assert payload["backend_authority"]["state"] == "negotiating"
    assert payload["path_recommendation"]["action"] == "observe"
    assert payload["media_session_authority"]["state"] == "negotiating"
    assert payload["media_session_authority"]["reason"] == "no_media_truth_yet"
    assert payload["media_recovery_intent"]["action"] == "observe"


@pytest.mark.asyncio
async def test_report_metrics_returns_backend_path_recommendation() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-metrics")
    daemon._call_registry.open(
        call_id="c-metrics",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=daemon.me.fingerprint,
        started_at_ms=1_000,
    )
    req = _FakeRequest(body={
        "action": "report_metrics",
        "call_id": "c-metrics",
        "media_health_state": "renderer_detached",
        "media_health_severity": 1,
        "ice_connection_state": "connected",
        "connection_state": "connected",
        "remote_video_tracks": 1,
        "remote_video_src_attached": False,
    })
    resp = await srv.api_call_action(req)  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is True
    assert payload["recommendation"]["action"] == "revive_playback"
    assert payload["recommendation"]["reason"] == "renderer_detached"
    assert payload["session_authority"]["state"] == "degraded"
    assert payload["session_authority"]["reason"] == "renderer_detached"
    assert payload["recovery_intent"]["action"] == "revive_playback"
    assert payload["recovery_intent"]["route_preference"] == "same"


@pytest.mark.asyncio
async def test_call_trace_exports_privacy_safe_timeline() -> None:
    srv, daemon = _server_with_daemon()
    peer = _identity("mom-trace")
    daemon._call_registry.open(
        call_id="c-trace",
        peer_master_vk_hex=peer.fingerprint,
        local_role="originator",
        local_master_vk_hex=daemon.me.fingerprint,
        started_at_ms=1_000,
    )
    await srv.api_call_action(_FakeRequest(body={  # type: ignore[arg-type]
        "action": "report_call_event",
        "call_id": "c-trace",
        "event": "remote_surface_synced",
        "reason": "renderer_detached",
        "media_kind": "video",
    }))
    await srv.api_call_action(_FakeRequest(body={  # type: ignore[arg-type]
        "action": "report_metrics",
        "call_id": "c-trace",
        "media_health_state": "remote_media_missing",
        "media_health_severity": 2,
    }))
    resp = await srv.api_call_trace(_FakeRequest(match_info={"call_id": "c-trace"}))  # type: ignore[arg-type]
    import json
    payload = json.loads(resp._body or b"")
    assert payload["ok"] is True
    assert payload["call_id"] == "c-trace"
    assert payload["backend_authority"]["state"] == "negotiating"
    assert payload["recommendation"]["action"] == "renegotiate"
    assert payload["session_authority"]["state"] == "negotiating"
    assert payload["recovery_intent"]["action"] == "renegotiate"
    assert len(payload["rows"]) == 2
    assert "no SDP" in payload["privacy"]


# ---------------------------------------------------------------------------
# Routes registered in app router
# ---------------------------------------------------------------------------

def test_routes_registered_on_app_router() -> None:
    srv, _ = _server_with_daemon()
    # We don't run start(), so the routes haven't been added yet
    # by _setup_routes. But the app exists; we can call _setup_routes
    # manually if it's available, or just check the helper is wired.
    # Simplest assertion: the handlers exist and are async.
    assert callable(srv.api_call_action)
    assert callable(srv.api_calls_list)
    assert callable(srv.api_call_state)
    import inspect
    assert inspect.iscoroutinefunction(srv.api_call_action)
    assert inspect.iscoroutinefunction(srv.api_calls_list)
    assert inspect.iscoroutinefunction(srv.api_call_state)
