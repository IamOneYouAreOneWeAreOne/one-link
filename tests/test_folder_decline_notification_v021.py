"""v0.21.x folder Decline → sender notification.

When the receiver clicks Decline on a folder offer, the daemon
sends a FOLDER_OFFER_DECLINED frame to the sender. The sender's
handler:
  1. Cancels any in-flight folder-send task for this peer/folder
  2. Revokes the temporary share grant from
     send_folder_one_shot_via_manifest
  3. Broadcasts folder_send_declined_by_peer so the sender's UI
     shows "X declined the folder"

Coverage:
  - daemon.notify_peer_folder_declined: best-effort send, returns
    True on success, False on capability/trust/transport failure
  - daemon._handle_folder_offer_declined: cancels the in-flight task,
    revokes the temp grant, broadcasts the UI event
  - api_decline_folder_offer: calls notify_peer_folder_declined +
    marks offer declined locally, returns sender_notified flag in
    the response
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.capabilities import FOLDER_SYNC
from one_link.daemon import Daemon, decode_msg
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="decline-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


# ── daemon.notify_peer_folder_declined ──────────────────────────


@pytest_asyncio.fixture
async def decline_ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=bytes.fromhex(peer_fp), hostname="recipient",
    )
    state.set_peer_trust(peer_fp, "pinned")
    fake_peer = SimpleNamespace(
        short_id=peer_fp[:8], ed_pub_hex=peer_fp,
    )
    daemon._peer_fp_from_peer = lambda p: peer_fp if p is fake_peer else None
    daemon._check_outbound_trust = lambda peer: None
    daemon._capability_allowed = lambda fp, cap, scope=b"": True
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[fake_peer])
    # Capture frames sent to the peer.
    sent = []
    fake_channel = MagicMock()
    fake_channel.send = AsyncMock(side_effect=lambda payload: sent.append(decode_msg(payload)))
    sess = SimpleNamespace(channel=fake_channel, lock=asyncio.Lock(), peer_fp=peer_fp)
    daemon._get_outbound_session = AsyncMock(return_value=sess)
    server = UIServer(daemon)
    daemon.ui_server = server  # wire so _handle_folder_offer_declined finds it
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "server": server, "token": server.token,
            "peer_fp": peer_fp, "peer": fake_peer,
            "sent_frames": sent,
        }
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_notify_peer_folder_declined_sends_frame(decline_ctx):
    ok = await decline_ctx["daemon"].notify_peer_folder_declined(
        decline_ctx["peer"], "papers",
    )
    assert ok is True
    sent = decline_ctx["sent_frames"]
    assert any(
        f.get("t") == "FOLDER_OFFER_DECLINED" and f.get("folder") == "papers"
        for f in sent
    )


@pytest.mark.asyncio
async def test_notify_folder_responses_use_exact_folder_capability_scope(decline_ctx):
    daemon = decline_ctx["daemon"]
    calls = []

    def _allowed(peer_fp, cap, scope=b""):
        calls.append((peer_fp, cap, scope))
        return True

    daemon._capability_allowed = _allowed
    assert await daemon.notify_peer_folder_declined(
        decline_ctx["peer"], "papers",
    )
    assert await daemon.notify_peer_folder_accepted(
        decline_ctx["peer"], "papers",
    )
    assert calls == [
        (decline_ctx["peer_fp"], FOLDER_SYNC, b"papers"),
        (decline_ctx["peer_fp"], FOLDER_SYNC, b"papers"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wire_type", "handler_name"),
    [
        ("FOLDER_OFFER_DECLINED", "_handle_folder_offer_declined"),
        ("FOLDER_OFFER_ACCEPTED", "_handle_folder_offer_accepted"),
    ],
)
async def test_folder_response_dispatch_cannot_cross_folder_capability_scope(
    decline_ctx,
    wire_type,
    handler_name,
):
    daemon = decline_ctx["daemon"]
    checked_scopes = []

    def _only_papers(peer_fp, cap, scope=b""):
        checked_scopes.append(scope)
        return cap == FOLDER_SYNC and scope == b"papers"

    daemon._capability_allowed = _only_papers
    handler = AsyncMock()
    setattr(daemon, handler_name, handler)
    channel = MagicMock(
        peer_ed_pub=bytes.fromhex(decline_ctx["peer_fp"]),
        peer_short_id=decline_ctx["peer_fp"][:8],
    )
    channel.send = AsyncMock()

    await daemon._on_peer_message(
        channel,
        {
            "t": wire_type,
            "id": "wrong-folder-response",
            "ts": 1,
            "from": decline_ctx["peer_fp"][:8],
            "folder": "secrets",
        },
    )

    assert checked_scopes == [b"secrets"]
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_notify_returns_false_when_capability_denied(decline_ctx):
    decline_ctx["daemon"]._capability_allowed = (
        lambda fp, cap, scope=b"": False
    )
    ok = await decline_ctx["daemon"].notify_peer_folder_declined(
        decline_ctx["peer"], "papers",
    )
    assert ok is False
    assert decline_ctx["sent_frames"] == []


@pytest.mark.asyncio
async def test_notify_returns_false_when_session_fails(decline_ctx):
    decline_ctx["daemon"]._get_outbound_session = AsyncMock(
        side_effect=ConnectionError("no route"),
    )
    ok = await decline_ctx["daemon"].notify_peer_folder_declined(
        decline_ctx["peer"], "papers",
    )
    assert ok is False


# ── daemon._handle_folder_offer_declined ────────────────────────


@pytest.mark.asyncio
async def test_handle_declined_cancels_inflight_folder_task(decline_ctx):
    """Sender receives FOLDER_OFFER_DECLINED → cancels the in-flight
    folder-card task targeting that peer + folder."""
    daemon = decline_ctx["daemon"]
    server = decline_ctx["server"]
    # Register a fake in-flight task in the registry.
    blocker = asyncio.Event()

    async def _blocked():
        await blocker.wait()
    task = asyncio.get_running_loop().create_task(_blocked())
    server._ensure_folder_send_registry()
    server._folder_send_tasks[
        server._folder_send_key("folder", "papers", decline_ctx["peer_fp"])
    ] = task
    msg = {"t": "FOLDER_OFFER_DECLINED", "folder": "papers"}
    await daemon._handle_folder_offer_declined(
        MagicMock(), msg, decline_ctx["peer_fp"],
    )
    # The blocked task is now cancelled.
    await asyncio.sleep(0.02)
    assert task.cancelled() or task.done()
    blocker.set()


@pytest.mark.asyncio
async def test_handle_declined_revokes_temp_share(decline_ctx):
    """Decline must remove the peer from shared_with for the folder
    (cleanup of the temp grant from send_folder_one_shot_via_manifest)."""
    daemon = decline_ctx["daemon"]
    state = decline_ctx["state"]
    peer_fp = decline_ctx["peer_fp"]
    # Setup: folder exists with the peer in shared_with.
    state.add_folder(
        name="papers", local_path=str(decline_ctx["client"].server.app.router._resources[0]) if False else "/tmp/papers",
        shared_with=[peer_fp],
    )
    f_before = state.get_folder("papers")
    assert peer_fp in f_before["shared_with"]
    msg = {"t": "FOLDER_OFFER_DECLINED", "folder": "papers"}
    await daemon._handle_folder_offer_declined(MagicMock(), msg, peer_fp)
    f_after = state.get_folder("papers")
    assert peer_fp not in f_after["shared_with"], (
        "decline must revoke the temp share grant"
    )


@pytest.mark.asyncio
async def test_handle_declined_broadcasts_ui_event(decline_ctx):
    daemon = decline_ctx["daemon"]
    daemon.ui_server = MagicMock()
    daemon.ui_server.broadcast = MagicMock()
    # Server uses _folder_send_tasks attr from ui_server; mimic.
    daemon.ui_server._folder_send_tasks = {}
    daemon.ui_server._cancel_folder_send_task = lambda *a: False
    msg = {"t": "FOLDER_OFFER_DECLINED", "folder": "papers"}
    await daemon._handle_folder_offer_declined(
        MagicMock(), msg, decline_ctx["peer_fp"],
    )
    calls = daemon.ui_server.broadcast.call_args_list
    payloads = [c.args[0] for c in calls if c.args]
    decline_events = [
        p for p in payloads
        if p.get("type") == "folder_send_declined_by_peer"
    ]
    assert len(decline_events) == 1
    assert decline_events[0]["folder_name"] == "papers"
    assert decline_events[0]["peer_fp"] == decline_ctx["peer_fp"]


@pytest.mark.asyncio
async def test_handle_declined_empty_folder_name_no_op(decline_ctx):
    """Defense: a malformed FOLDER_OFFER_DECLINED with empty folder
    field must not crash the dispatcher."""
    daemon = decline_ctx["daemon"]
    daemon.ui_server = MagicMock()
    daemon.ui_server.broadcast = MagicMock()
    daemon.ui_server._folder_send_tasks = {}
    msg = {"t": "FOLDER_OFFER_DECLINED", "folder": ""}
    await daemon._handle_folder_offer_declined(
        MagicMock(), msg, decline_ctx["peer_fp"],
    )
    daemon.ui_server.broadcast.assert_not_called()


# ── api_decline_folder_offer end-to-end ─────────────────────────


@pytest.mark.asyncio
async def test_decline_endpoint_calls_notify(decline_ctx):
    """POST /api/folder-offers/{id}/decline calls
    notify_peer_folder_declined when sender is online."""
    state = decline_ctx["state"]
    peer_fp = decline_ctx["peer_fp"]
    offer = state.upsert_pending_folder_offer(
        peer_fp=peer_fp,
        folder_name="papers",
        merkle_root="abc",
        entries=[],
    )
    decline_ctx["daemon"].notify_peer_folder_declined = AsyncMock(
        return_value=True,
    )
    r = await decline_ctx["client"].post(
        f"/api/folder-offers/{offer['id']}/decline",
        headers=_h(decline_ctx["token"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["sender_notified"] is True
    decline_ctx["daemon"].notify_peer_folder_declined.assert_awaited_once()
    # Offer marked declined.
    assert state.get_folder_offer(offer["id"])["state"] == "declined"


@pytest.mark.asyncio
async def test_decline_endpoint_succeeds_when_sender_offline(decline_ctx):
    """Notification is best-effort: if sender is offline, decline
    still records locally + returns sender_notified=false."""
    state = decline_ctx["state"]
    peer_fp = decline_ctx["peer_fp"]
    offer = state.upsert_pending_folder_offer(
        peer_fp=peer_fp,
        folder_name="papers",
        merkle_root="abc",
        entries=[],
    )
    # Make peer "offline" — _resolve_online_peer returns None.
    decline_ctx["daemon"].discovery.registry.list = MagicMock(return_value=[])
    r = await decline_ctx["client"].post(
        f"/api/folder-offers/{offer['id']}/decline",
        headers=_h(decline_ctx["token"]),
    )
    assert r.status == 200
    body = await r.json()
    assert body["ok"] is True
    assert body["sender_notified"] is False
    assert state.get_folder_offer(offer["id"])["state"] == "declined"
