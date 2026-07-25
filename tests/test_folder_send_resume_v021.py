"""v0.21.x folder send: resume on transient disconnect.

push_folder_to_peer is one connection cycle; if the link drops at
80%, the receiver has 80% of the chunks already in their cache.
Wrapping the push in a bounded retry loop with backoff turns this
into transparent resume — the next attempt re-walks the manifest,
gets a SHORTER MANIFEST_WANTS (only the missing 20%), streams those.

Coverage:
  - _is_transient_folder_send_error: classifies known network-y
    error names + dict-result-with-network-error-text as True;
    other errors (ValueError, etc.) as False
  - _send_folder_manifest_push: retries up to MAX_RETRIES on
    transient errors, broadcasts folder_send_retrying between
    attempts, succeeds when a retry succeeds
  - _send_folder_manifest_push: gives up after MAX_RETRIES, broadcasts
    folder_send_complete with failed=1
  - _send_folder_manifest_push: non-transient error short-circuits
    the retry loop (no point retrying capability-denied etc.)
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="resume-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def resume_ctx(tmp_path: Path, monkeypatch):
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
    server = UIServer(daemon)
    daemon.ui_server = server
    # Shorten backoff so tests don't sleep for 21s end-to-end.
    server._FOLDER_SEND_BACKOFF_SECONDS = (0.01, 0.01, 0.01)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    broadcasts: list[dict] = []
    orig_broadcast = server.broadcast
    server.broadcast = lambda msg: (broadcasts.append(msg), orig_broadcast(msg))[1]
    try:
        yield {
            "client": client, "daemon": daemon, "server": server,
            "state": state, "token": server.token,
            "peer_fp": peer_fp, "peer": fake_peer,
            "broadcasts": broadcasts,
        }
    finally:
        await client.close()
        state.close()


# ── _is_transient_folder_send_error classifier ──────────────────


def test_transient_classifier_recognizes_network_exceptions(resume_ctx):
    cls = resume_ctx["server"]._is_transient_folder_send_error
    assert cls(ConnectionError("drop")) is True
    assert cls(ConnectionResetError()) is True
    assert cls(TimeoutError()) is True
    assert cls(BrokenPipeError()) is True
    assert cls(OSError()) is True


def test_transient_classifier_rejects_logical_errors(resume_ctx):
    cls = resume_ctx["server"]._is_transient_folder_send_error
    assert cls(ValueError("folder exists")) is False
    assert cls(KeyError("missing folder")) is False
    assert cls(RuntimeError("capability_denied")) is False


def test_transient_classifier_reads_dict_error_text(resume_ctx):
    cls = resume_ctx["server"]._is_transient_folder_send_error
    assert cls({"ok": False, "error": "timeout waiting for ACK"}) is True
    assert cls({"ok": False, "error": "Connection closed by peer"}) is True
    assert cls({"ok": False, "error": "peer not online"}) is True
    assert cls({"ok": False, "error": "capability_denied"}) is False
    assert cls({"ok": True}) is False
    assert cls({}) is False


# ── retry loop ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retries_on_transient_failure_and_succeeds(resume_ctx):
    """First attempt raises ConnectionResetError; second succeeds.
    Final broadcast is folder_send_complete ok=true."""
    daemon = resume_ctx["daemon"]
    call_count = {"n": 0}

    async def fake_push(*a, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise ConnectionResetError("link dropped")
        return {"ok": True, "blobs_sent": 5}
    daemon.send_folder_one_shot_via_manifest = AsyncMock(side_effect=fake_push)
    await resume_ctx["server"]._send_folder_manifest_push(
        peer=resume_ctx["peer"], peer_fp=resume_ctx["peer_fp"],
        folder_name="papers", scope="folder", ident="papers",
    )
    assert call_count["n"] == 2
    types_seen = [b.get("type") for b in resume_ctx["broadcasts"]]
    assert "folder_send_retrying" in types_seen
    # final completion is ok.
    completions = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_complete"
    ]
    assert len(completions) == 1
    assert completions[0]["ok"] is True


@pytest.mark.asyncio
async def test_retries_up_to_max_then_gives_up(resume_ctx):
    """All retries fail with transient errors → final completion
    has failed=1 + error message."""
    daemon = resume_ctx["daemon"]
    daemon.send_folder_one_shot_via_manifest = AsyncMock(
        side_effect=ConnectionResetError("link dropped"),
    )
    await resume_ctx["server"]._send_folder_manifest_push(
        peer=resume_ctx["peer"], peer_fp=resume_ctx["peer_fp"],
        folder_name="papers", scope="folder", ident="papers",
    )
    # Tried MAX times.
    assert daemon.send_folder_one_shot_via_manifest.await_count == 3
    retries = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_retrying"
    ]
    # 2 retry broadcasts between 3 attempts.
    assert len(retries) == 2
    completions = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_complete"
    ]
    assert len(completions) == 1
    assert completions[0]["ok"] is False
    assert completions[0]["failed"] == 1


@pytest.mark.asyncio
async def test_non_transient_error_short_circuits(resume_ctx):
    """ValueError (folder name conflict, etc.) is not retried — one
    attempt, then completion broadcast with failed=1. The retry loop
    short-circuits because the error class isn't transient."""
    daemon = resume_ctx["daemon"]
    daemon.send_folder_one_shot_via_manifest = AsyncMock(
        side_effect=ValueError("folder named 'x' already exists"),
    )
    await resume_ctx["server"]._send_folder_manifest_push(
        peer=resume_ctx["peer"], peer_fp=resume_ctx["peer_fp"],
        folder_name="papers", scope="folder", ident="papers",
    )
    # Only ONE attempt — no retries for logical errors.
    assert daemon.send_folder_one_shot_via_manifest.await_count == 1
    retries = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_retrying"
    ]
    assert len(retries) == 0
    completions = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_complete"
    ]
    assert len(completions) == 1
    assert completions[0]["failed"] == 1


@pytest.mark.asyncio
async def test_retries_on_transient_dict_result(resume_ctx):
    """Result dict with network-y error text is retried as transient
    (no exception raised)."""
    daemon = resume_ctx["daemon"]
    call_count = {"n": 0}

    async def fake_push(*a, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return {"ok": False, "error": "timeout waiting for ACK"}
        return {"ok": True, "blobs_sent": 2}
    daemon.send_folder_one_shot_via_manifest = AsyncMock(side_effect=fake_push)
    await resume_ctx["server"]._send_folder_manifest_push(
        peer=resume_ctx["peer"], peer_fp=resume_ctx["peer_fp"],
        folder_name="papers", scope="folder", ident="papers",
    )
    assert call_count["n"] == 2
    completions = [
        b for b in resume_ctx["broadcasts"]
        if b.get("type") == "folder_send_complete"
    ]
    assert completions[0]["ok"] is True
