"""v0.21.x folder-share ceremony — in-process integration test
exercising the receiver-side _handle_manifest_push from a SIMULATED
peer push, all the way through to the pending offer surfacing via
the API + the Accept flow inserting the new folder.

This validates the round-trip without needing two subprocess
daemons (mDNS pairing is flaky on Windows test runners). Mocks the
channel + peer identity but uses REAL state + REAL blob_store +
REAL UIServer + REAL endpoints.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import foldersync
from one_link.blobstore import BlobStore
from one_link.capabilities import FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State
from one_link.wire import make_msg


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="receiver",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


def _folder_channel(*, transcript: str = "c" * 64) -> MagicMock:
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.transcript_hex = transcript
    channel.peer_caps = {
        "features": [FOLDER_SYNC, FOLDER_SYNC_COMMIT_V1],
    }
    return channel


def _manifest_push(
    *,
    sender_fp: str,
    folder: str,
    entries: list[dict] | None = None,
) -> dict:
    manifest_entries = list(entries or [])
    return make_msg(
        "MANIFEST_PUSH",
        sender_fp[:8],
        folder=folder,
        merkle_root=foldersync.manifest_root_for_entries(manifest_entries),
        manifest_digest=Daemon._folder_manifest_digest(manifest_entries),
        entry_count=len(manifest_entries),
        entries=manifest_entries,
    )


@pytest_asyncio.fixture
async def receiver_ctx(tmp_path: Path, monkeypatch):
    """Receiver-side daemon with real state + real blob_store + a
    pinned 'sender' peer in the state DB."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    blob_store = BlobStore(root=tmp_path / "blobs")
    daemon = Daemon(me)
    daemon.state = state
    daemon.blob_store = blob_store
    daemon.discovery = None
    daemon.folder_engine = MagicMock()
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    # Insert + pin a fake sender peer.
    sender_fp = "ff" * 32
    state.upsert_peer(
        fingerprint=sender_fp,
        short_id=sender_fp[:8],
        pubkey=bytes.fromhex(sender_fp),
        hostname="sender-host",
    )
    state.set_peer_trust(sender_fp, "pinned")
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    daemon.ui_server = server  # so broadcast() resolves
    try:
        yield {
            "client": client, "daemon": daemon, "state": state,
            "blob_store": blob_store, "server": server,
            "token": server.token, "sender_fp": sender_fp,
            "tmp_path": tmp_path,
        }
    finally:
        await client.close()
        state.close()


@pytest.mark.asyncio
async def test_unknown_folder_push_creates_pending_offer(receiver_ctx):
    """When _handle_manifest_push receives a MANIFEST_PUSH for a
    folder we don't have, the receiver caches it as a pending offer
    + broadcasts the folder_offer_received WS event."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    sender_fp = receiver_ctx["sender_fp"]
    channel = _folder_channel()
    msg = _manifest_push(
        sender_fp=sender_fp,
        folder="papers",
        entries=[
            {"file_path": "a.txt", "blob_hash": "a" * 64, "size": 100,
             "mtime_ms": 1, "vclock": {sender_fp: 1}},
            {"file_path": "b.txt", "blob_hash": "b" * 64, "size": 200,
             "mtime_ms": 2, "vclock": {sender_fp: 1}},
        ],
    )
    await daemon._handle_manifest_push(channel, msg, sender_fp)
    # Offer was cached.
    offers = state.list_folder_offers()
    assert len(offers) == 1
    o = offers[0]
    assert o["folder_name"] == "papers"
    assert o["peer_fp"] == sender_fp
    assert o["entry_count"] == 2
    assert o["total_bytes"] == 300
    # Receiver replied with pending_offer=True so the sender doesn't
    # hit a 15s timeout.
    channel.send.assert_awaited()
    sent_args = channel.send.await_args[0][0]
    # The reply is encoded — just check it has the right shape.
    from one_link.daemon import decode_msg
    decoded = decode_msg(sent_args)
    assert decoded["t"] == "MANIFEST_WANTS"
    assert decoded["folder"] == "papers"
    assert decoded["of"] == msg["id"]
    assert decoded["sync_id"] == msg["id"]
    assert decoded["wants"] == []
    assert decoded.get("pending_offer") is True


@pytest.mark.asyncio
async def test_unpinned_sender_push_is_silently_ignored(receiver_ctx):
    """A push from an UNPINNED peer must be silently dropped — no
    pending offer, no WS broadcast. Otherwise random network peers
    could spam offers into the UI."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    channel = _folder_channel(transcript="d" * 64)
    msg = _manifest_push(
        sender_fp="99" * 32,
        folder="unwanted",
    )
    await daemon._handle_manifest_push(channel, msg, "99" * 32)
    assert state.list_folder_offers() == []


@pytest.mark.asyncio
async def test_offer_listing_endpoint_surfaces_pending(receiver_ctx):
    """The HTTP GET /api/folder-offers endpoint must surface the
    cached offers the manifest handler stored."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    sender_fp = receiver_ctx["sender_fp"]
    client = receiver_ctx["client"]
    token = receiver_ctx["token"]
    # Simulate an inbound push.
    channel = _folder_channel(transcript="e" * 64)
    await daemon._handle_manifest_push(channel, _manifest_push(
        sender_fp=sender_fp,
        folder="ledger",
        entries=[{"file_path": "f.txt", "blob_hash": "c" * 64,
                  "size": 50, "mtime_ms": 1, "vclock": {sender_fp: 1}}],
    ), sender_fp)
    r = await client.get("/api/folder-offers", headers=_h(token))
    assert r.status == 200
    body = await r.json()
    offers = body["offers"]
    assert len(offers) == 1
    assert offers[0]["folder_name"] == "ledger"
    # Enriched with peer_hostname (we inserted the peer with that field).
    assert offers[0].get("peer_hostname") == "sender-host"


@pytest.mark.asyncio
async def test_accept_endpoint_creates_local_folder(receiver_ctx):
    """Accepting an offer must create the local folder, add the
    sender to shared_with, and grant FOLDER_SYNC caps."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    sender_fp = receiver_ctx["sender_fp"]
    client = receiver_ctx["client"]
    token = receiver_ctx["token"]
    tmp_path = receiver_ctx["tmp_path"]
    # We need a REAL folder_engine for accept (it calls add_folder).
    # Replace the mock with a real instance bound to our state.
    from one_link.foldersync import FolderEngine
    import asyncio
    daemon.folder_engine = FolderEngine(
        state=state, blob_store=receiver_ctx["blob_store"],
        my_fingerprint=daemon.me.fingerprint,
        loop=asyncio.get_running_loop(),
    )
    # Stash an offer the API can act on.
    channel = _folder_channel(transcript="f" * 64)
    await daemon._handle_manifest_push(channel, _manifest_push(
        sender_fp=sender_fp,
        folder="incoming",
        entries=[{"file_path": "data.txt", "blob_hash": "0" * 64,
                  "size": 5, "mtime_ms": 1, "vclock": {sender_fp: 1}}],
    ), sender_fp)
    offer = state.list_folder_offers()[0]
    local_path = tmp_path / "accepted-incoming"
    r = await client.post(
        f"/api/folder-offers/{offer['id']}/accept",
        headers=_h(token),
        json={"local_path": str(local_path)},
    )
    assert r.status == 200, await r.text()
    # Folder now exists locally + sender is in shared_with.
    folder = state.get_folder("incoming")
    assert folder is not None
    assert sender_fp in folder["shared_with"]
    # Local path was created on disk.
    assert local_path.is_dir()
    # Offer is now in 'accepted' state.
    accepted_offer = state.get_folder_offer(offer["id"])
    assert accepted_offer["state"] == "accepted"
    assert accepted_offer["local_path"] == str(local_path)


@pytest.mark.asyncio
async def test_decline_endpoint_does_not_create_folder(receiver_ctx):
    """Declining must NOT create the folder, NOT add to shared_with,
    NOT grant caps. Just marks the offer declined."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    sender_fp = receiver_ctx["sender_fp"]
    client = receiver_ctx["client"]
    token = receiver_ctx["token"]
    channel = _folder_channel(transcript="1" * 64)
    await daemon._handle_manifest_push(channel, _manifest_push(
        sender_fp=sender_fp,
        folder="refused",
    ), sender_fp)
    offer = state.list_folder_offers()[0]
    r = await client.post(
        f"/api/folder-offers/{offer['id']}/decline",
        headers=_h(token),
    )
    assert r.status == 200
    assert state.get_folder("refused") is None
    declined = state.get_folder_offer(offer["id"])
    assert declined["state"] == "declined"


@pytest.mark.asyncio
async def test_re_offer_after_decline_resets_to_pending(receiver_ctx):
    """If the sender re-pushes the manifest after we declined, the
    offer flips back to 'pending' so the user gets a fresh chance."""
    daemon = receiver_ctx["daemon"]
    state = receiver_ctx["state"]
    sender_fp = receiver_ctx["sender_fp"]
    channel = _folder_channel(transcript="2" * 64)
    msg = _manifest_push(
        sender_fp=sender_fp,
        folder="persistent",
    )
    await daemon._handle_manifest_push(channel, msg, sender_fp)
    offer = state.list_folder_offers()[0]
    state.mark_folder_offer_declined(offer["id"])
    # Re-push.
    await daemon._handle_manifest_push(channel, msg, sender_fp)
    refreshed = state.get_folder_offer(offer["id"])
    assert refreshed["state"] == "pending"
