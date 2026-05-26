"""v0.21.x multi-peer folder send.

One Send click fans out to N selected peers. Each peer gets its own
background task in the registry + can be cancelled independently
via the existing /cancel endpoint.

Coverage:
  - Body accepts peer_fps: [list] form
  - Body accepts legacy peer_fp: str form (back-compat)
  - peer_fps=[] returns 400
  - Online peers spawn tasks; offline peers reported in per_peer
    with started=false + error
  - All-offline returns 503 with offline_peer_fps list
  - Each peer's task is keyed independently so they're cancellable
    one-at-a-time
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
        hostname="multi-host",
    )


def _h(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


@pytest_asyncio.fixture
async def multi_ctx(tmp_path: Path, monkeypatch):
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
    # Three peers; we'll mark some online + some offline.
    peer_fps = ["aa" * 32, "bb" * 32, "cc" * 32]
    fake_peers = {}
    for fp in peer_fps:
        state.upsert_peer(
            fingerprint=fp, short_id=fp[:8],
            pubkey=bytes.fromhex(fp), hostname=f"peer-{fp[:4]}",
        )
        state.set_peer_trust(fp, "pinned")
        fake_peers[fp] = SimpleNamespace(short_id=fp[:8], ed_pub_hex=fp)
    daemon._peer_fp_from_peer = lambda p: next(
        (fp for fp, obj in fake_peers.items() if obj is p), None,
    )
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.send_folder_one_shot_via_manifest = AsyncMock(
        return_value={"ok": True, "blobs_sent": 1},
    )
    daemon.query_peer_blob_inventory = AsyncMock(return_value=set())
    # Real folder so the endpoint passes the path check.
    src = tmp_path / "demo"
    src.mkdir()
    (src / "a.txt").write_text("x", encoding="utf-8")
    state.add_folder(name="demo", local_path=str(src), shared_with=[])
    server = UIServer(daemon)
    daemon.ui_server = server
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "daemon": daemon, "server": server,
            "state": state, "token": server.token,
            "peer_fps": peer_fps, "fake_peers": fake_peers,
        }
    finally:
        await client.close()
        state.close()


def _set_online(multi_ctx, online_fps: list[str]) -> None:
    """Make only the given peer_fps appear online via discovery."""
    online_peers = [multi_ctx["fake_peers"][fp] for fp in online_fps]
    multi_ctx["daemon"].discovery.registry.list = MagicMock(
        return_value=online_peers,
    )


# ── body shape ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_legacy_peer_fp_single_still_works(multi_ctx):
    _set_online(multi_ctx, [multi_ctx["peer_fps"][0]])
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fp": multi_ctx["peer_fps"][0]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["ok"] is True
    assert body["fanout_count"] == 1
    assert body["offline_count"] == 0
    assert len(body["per_peer"]) == 1


@pytest.mark.asyncio
async def test_peer_fps_list_fans_out_to_all_online(multi_ctx):
    _set_online(multi_ctx, multi_ctx["peer_fps"])  # all 3 online
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fps": multi_ctx["peer_fps"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["fanout_count"] == 3
    assert body["offline_count"] == 0
    assert all(p["started"] for p in body["per_peer"])
    await asyncio.sleep(0.05)
    # send_folder_one_shot_via_manifest awaited once per peer.
    assert multi_ctx["daemon"].send_folder_one_shot_via_manifest.await_count == 3


@pytest.mark.asyncio
async def test_some_peers_offline_returns_partial_results(multi_ctx):
    # Online: first 2; offline: third.
    _set_online(multi_ctx, multi_ctx["peer_fps"][:2])
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fps": multi_ctx["peer_fps"]},
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["fanout_count"] == 2
    assert body["offline_count"] == 1
    online_results = [p for p in body["per_peer"] if p["started"]]
    offline_results = [p for p in body["per_peer"] if not p["started"]]
    assert len(online_results) == 2
    assert len(offline_results) == 1
    assert offline_results[0]["peer_fp"] == multi_ctx["peer_fps"][2]
    assert "offline" in offline_results[0]["error"].lower()


@pytest.mark.asyncio
async def test_all_peers_offline_returns_503(multi_ctx):
    _set_online(multi_ctx, [])  # nobody online
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fps": multi_ctx["peer_fps"]},
    )
    assert r.status == 503
    body = await r.json()
    assert body.get("code") == "peer_offline"
    assert sorted(body["offline_peer_fps"]) == sorted(multi_ctx["peer_fps"])


@pytest.mark.asyncio
async def test_empty_peer_fps_returns_400(multi_ctx):
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fps": []},
    )
    assert r.status == 400


@pytest.mark.asyncio
async def test_no_peer_field_returns_400(multi_ctx):
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={},
    )
    assert r.status == 400


# ── per-peer task independence ──────────────────────────────────


@pytest.mark.asyncio
async def test_per_peer_tasks_have_independent_registry_keys(multi_ctx):
    """Each fanout peer's task has its own (scope, ident, peer_fp)
    registry key — cancelling one doesn't kill the others."""
    _set_online(multi_ctx, multi_ctx["peer_fps"])
    server = multi_ctx["server"]
    # Make send_folder_one_shot_via_manifest block so the tasks
    # stay alive long enough to observe in the registry.
    blocker = asyncio.Event()

    async def blocking_send(*a, **kw):
        await blocker.wait()
        return {"ok": True, "blobs_sent": 0}
    multi_ctx["daemon"].send_folder_one_shot_via_manifest = AsyncMock(
        side_effect=blocking_send,
    )
    r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to",
        headers=_h(multi_ctx["token"]),
        json={"peer_fps": multi_ctx["peer_fps"]},
    )
    assert r.status == 200
    # Three distinct registry keys exist.
    reg = server._ensure_folder_send_registry()
    keys_for_demo = [k for k in reg.keys() if ":demo:" in k]
    assert len(keys_for_demo) == 3
    fps_in_keys = sorted(k.rsplit(":", 1)[1] for k in keys_for_demo)
    assert fps_in_keys == sorted(multi_ctx["peer_fps"])
    # Cancel just one peer's task.
    cancel_r = await multi_ctx["client"].post(
        "/api/folders/demo/send-to/cancel",
        headers=_h(multi_ctx["token"]),
        json={"peer_fp": multi_ctx["peer_fps"][0]},
    )
    assert cancel_r.status == 200
    # Other two are still in the registry + alive.
    await asyncio.sleep(0.05)
    remaining = [k for k in reg.keys() if ":demo:" in k]
    assert len(remaining) == 2
    blocker.set()
    await asyncio.sleep(0.05)
