"""v0.11.5 — Per-chat tools (Phase 5 of Settings overhaul).

Backend:
  - DELETE /api/peers/{fp}/history hard-deletes local message rows.
  - DELETE /api/groups/{gid}/history same for groups.
  - GET /api/peers/{fp}/export?format=json|md serializes the
    conversation as a downloadable file.
  - GET /api/groups/{gid}/export same for groups.
  - GET /api/peers/{fp}/media lists files exchanged for the
    media gallery view.

Frontend:
  - Device drawer: Wallpaper accent picker + Chat tools (Media
    gallery / Export · MD / Export · JSON / Clear local history).
  - Group settings: Chat tools (Export · MD / JSON / Clear local).
  - Media gallery modal with download links.
  - Per-chat wallpaper applied via inline background on
    #convo-active. localStorage-keyed so each chat has its own
    tint without sending anything to the server.
"""

from __future__ import annotations

import json as jsonlib
import sqlite3
from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity(host: str = "host") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub_obj,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname=host,
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "aa" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="alice",
        pubkey=b"\x00" * 32,
        hostname="alice",
    )
    state.set_peer_trust(peer_fp, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token, peer_fp
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def _seed_messages(state: State, peer_fp: str, n: int = 3) -> None:
    """Insert n simple text messages so the export/clear paths have
    real rows to operate on."""
    for i in range(n):
        state.record_message(
            id=f"msg{i}",
            ts_ms=1_700_000_000_000 + i * 1000,
            direction="out" if i % 2 == 0 else "in",
            peer_fp=peer_fp,
            msg_type="text",
            body=f"hello {i}",
            room_id=None,
        )


# ───────── Clear history ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clear_peer_history_deletes_local_rows(http):
    client, _, state, token, peer_fp = http
    _seed_messages(state, peer_fp, 5)
    assert len(state.recent_messages(peer_fp=peer_fp)) == 5
    resp = await client.delete(
        f"/api/peers/{peer_fp}/history",
        headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["deleted"] == 5
    assert state.recent_messages(peer_fp=peer_fp) == []


@pytest.mark.asyncio
async def test_clear_peer_history_404_unknown_peer(http):
    client, _, _, token, _ = http
    resp = await client.delete(
        f"/api/peers/{'00' * 32}/history",
        headers=_h(token),
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_clear_peer_history_idempotent(http):
    """Running clear twice in a row should both succeed; second
    call returns deleted=0 since nothing's left."""
    client, _, state, token, peer_fp = http
    _seed_messages(state, peer_fp, 2)
    r1 = await (
        await client.delete(
            f"/api/peers/{peer_fp}/history",
            headers=_h(token),
        )
    ).json()
    r2 = await (
        await client.delete(
            f"/api/peers/{peer_fp}/history",
            headers=_h(token),
        )
    ).json()
    assert r1["deleted"] == 2
    assert r2["deleted"] == 0


@pytest.mark.asyncio
async def test_clear_group_history_validates_hex(http):
    client, _, _, token, _ = http
    resp = await client.delete(
        "/api/groups/not-hex/history",
        headers=_h(token),
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_clear_group_history_safe_when_no_messages(http):
    """An empty current-schema group is an idempotent successful clear."""
    client, _, _, token, _ = http
    resp = await client.delete(
        f"/api/groups/{'aa' * 16}/history",
        headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    assert "deleted" in j


@pytest.mark.asyncio
async def test_clear_group_history_deletes_blob_keyed_rows(http):
    client, _, state, token, _ = http
    group_id = bytes.fromhex("ab" * 16)
    state.insert_group_message(
        id="group-secret",
        group_id=group_id,
        sender_pub=b"\x02" * 32,
        epoch=1,
        counter=1,
        direction="in",
        body="delete me",
        ts_ms=1,
    )

    response = await client.delete(
        f"/api/groups/{group_id.hex()}/history",
        headers=_h(token),
    )

    assert response.status == 200
    assert (await response.json())["deleted"] == 1
    assert state.recent_group_messages(group_id=group_id) == []


@pytest.mark.asyncio
async def test_clear_group_history_database_failure_returns_500_and_preserves_rows(http):
    client, _, state, token, _ = http
    group_id = bytes.fromhex("cd" * 16)
    state.insert_group_message(
        id="group-must-survive",
        group_id=group_id,
        sender_pub=b"\x03" * 32,
        epoch=1,
        counter=1,
        direction="in",
        body="must survive",
        ts_ms=1,
    )
    state._conn.execute(
        """
        CREATE TRIGGER inject_group_clear_failure
        BEFORE DELETE ON group_messages
        BEGIN
            SELECT RAISE(ABORT, 'injected group clear failure');
        END
        """
    )

    response = await client.delete(
        f"/api/groups/{group_id.hex()}/history",
        headers=_h(token),
    )

    assert response.status == 500
    assert (await response.json())["error"] == "internal server error"
    rows = state.recent_group_messages(group_id=group_id)
    assert [row["id"] for row in rows] == ["group-must-survive"]
    with pytest.raises(sqlite3.IntegrityError, match="injected group clear failure"):
        state.clear_group_history(group_id.hex())


# ───────── Export ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_peer_json_attachments(http):
    client, _, state, token, peer_fp = http
    _seed_messages(state, peer_fp, 4)
    resp = await client.get(
        f"/api/peers/{peer_fp}/export?format=json",
        headers=_h(token),
    )
    assert resp.status == 200
    cd = resp.headers.get("Content-Disposition", "")
    assert "attachment" in cd
    assert ".json" in cd
    body = await resp.text()
    payload = jsonlib.loads(body)
    assert payload["title"].startswith("Conversation with")
    assert len(payload["messages"]) == 4
    # Each message must carry a who, ts, and body.
    for m in payload["messages"]:
        assert "who" in m
        assert "ts" in m
        assert "body" in m


@pytest.mark.asyncio
async def test_export_peer_markdown(http):
    client, _, state, token, peer_fp = http
    _seed_messages(state, peer_fp, 2)
    resp = await client.get(
        f"/api/peers/{peer_fp}/export?format=md",
        headers=_h(token),
    )
    assert resp.status == 200
    cd = resp.headers.get("Content-Disposition", "")
    assert ".md" in cd
    body = await resp.text()
    assert body.startswith("# Conversation with")
    assert "hello 0" in body
    assert "hello 1" in body


@pytest.mark.asyncio
async def test_export_rejects_bad_format(http):
    client, _, _, token, peer_fp = http
    resp = await client.get(
        f"/api/peers/{peer_fp}/export?format=xml",
        headers=_h(token),
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_export_404_unknown_peer(http):
    client, _, _, token, _ = http
    resp = await client.get(
        f"/api/peers/{'00' * 32}/export?format=md",
        headers=_h(token),
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_export_group_validates_hex(http):
    client, _, _, token, _ = http
    resp = await client.get(
        "/api/groups/zz-not-hex/export?format=md",
        headers=_h(token),
    )
    assert resp.status == 400


# ───────── Media gallery ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_peer_media_lists_file_messages(http):
    client, _, state, token, peer_fp = http
    # Mix text + file rows; only file rows should come back.
    state.record_message(
        id="t1",
        ts_ms=1,
        direction="out",
        peer_fp=peer_fp,
        msg_type="text",
        body="hi",
        room_id=None,
    )
    state.record_message(
        id="f1",
        ts_ms=2,
        direction="out",
        peer_fp=peer_fp,
        msg_type="file",
        body="document.pdf",
        room_id=None,
        metadata={"filename": "document.pdf", "size": 12345},
    )
    state.record_message(
        id="f2",
        ts_ms=3,
        direction="in",
        peer_fp=peer_fp,
        msg_type="file",
        body="photo.jpg",
        room_id=None,
        metadata={"filename": "photo.jpg", "size": 99},
    )
    resp = await client.get(
        f"/api/peers/{peer_fp}/media",
        headers=_h(token),
    )
    assert resp.status == 200
    j = await resp.json()
    items = j["items"]
    assert len(items) == 2
    assert {it["id"] for it in items} == {"f1", "f2"}
    f1 = next(it for it in items if it["id"] == "f1")
    assert f1["name"] == "document.pdf"
    assert f1["size"] == 12345


@pytest.mark.asyncio
async def test_peer_media_404_unknown_peer(http):
    client, _, _, token, _ = http
    resp = await client.get(
        f"/api/peers/{'00' * 32}/media",
        headers=_h(token),
    )
    assert resp.status == 404


# ───────── State helpers ────────────────────────────────────────────


def test_clear_peer_history_helper(tmp_path: Path):
    state = State(db_path=tmp_path / "h.db")
    fp = "bb" * 32
    state.upsert_peer(fingerprint=fp, short_id="x", pubkey=b"\x00" * 32, hostname="x")
    for i in range(3):
        state.record_message(
            id=f"m{i}",
            ts_ms=i,
            direction="out",
            peer_fp=fp,
            msg_type="text",
            body="hi",
            room_id=None,
        )
    assert state.clear_peer_history(fp) == 3
    assert state.recent_messages(peer_fp=fp) == []
    state.close()


def test_list_peer_files_returns_files_only(tmp_path: Path):
    state = State(db_path=tmp_path / "g.db")
    fp = "cc" * 32
    state.upsert_peer(fingerprint=fp, short_id="y", pubkey=b"\x00" * 32, hostname="y")
    state.record_message(
        id="t",
        ts_ms=1,
        direction="out",
        peer_fp=fp,
        msg_type="text",
        body="hi",
        room_id=None,
    )
    state.record_message(
        id="f",
        ts_ms=2,
        direction="out",
        peer_fp=fp,
        msg_type="file",
        body="doc.pdf",
        room_id=None,
        metadata={"filename": "doc.pdf", "size": 100},
    )
    files = state.list_peer_files(fp)
    assert [m.id for m in files] == ["f"]
    state.close()


# ───────── UI markup ────────────────────────────────────────────────


def test_device_drawer_has_chat_tools(index_html: str):
    for marker in [
        'id="dev-clear-history"',
        'id="dev-export-md"',
        'id="dev-export-json"',
        'id="dev-media-gallery"',
        'id="dev-wallpaper-swatches"',
    ]:
        assert marker in index_html, marker


def test_group_settings_has_chat_tools(index_html: str):
    for marker in [
        'id="group-clear-history"',
        'id="group-export-md"',
        'id="group-export-json"',
    ]:
        assert marker in index_html, marker


def test_media_gallery_modal_present(index_html: str):
    assert 'id="media-gallery-backdrop"' in index_html
    assert 'id="media-gallery-list"' in index_html
    assert 'id="media-gallery-title"' in index_html


def test_clear_history_handler_calls_endpoint(index_html: str):
    """Pin both the peer + group clear handlers so a refactor can't
    quietly break the wiring."""
    idx = index_html.find('"#dev-clear-history"')
    assert idx > 0
    snippet = index_html[idx : idx + 1500]
    assert "/api/peers/" in snippet
    assert "/history" in snippet
    assert "api.del(" in snippet


def test_export_handlers_post_to_endpoints(index_html: str):
    """Both formats must be wired and pass format=… correctly."""
    md_idx = index_html.find('"#dev-export-md"')
    json_idx = index_html.find('"#dev-export-json"')
    assert md_idx > 0 and json_idx > 0
    md_snippet = index_html[md_idx : md_idx + 400]
    json_snippet = index_html[json_idx : json_idx + 400]
    assert "format=md" in md_snippet
    assert "format=json" in json_snippet


def test_download_helper_uses_anchor_click(index_html: str):
    """Pin the anchor.click() approach — fetch+blob is harder to
    get right with content-disposition."""
    idx = index_html.find("function _downloadConvoExport(url)")
    snippet = index_html[idx : idx + 600]
    assert 'createElement("a")' in snippet
    assert ".click()" in snippet


def test_media_gallery_function_present(index_html: str):
    assert "async function openMediaGallery(fp)" in index_html


def test_media_gallery_renders_items(index_html: str):
    idx = index_html.find("function _renderMediaGallery(host, items)")
    assert idx > 0
    snippet = index_html[idx : idx + 1500]
    # Both empty + populated paths present.
    assert "items.length === 0" in snippet
    assert "blocked-empty" in snippet
    # Direction-aware download for inbox files.
    assert "/api/files/" in snippet


def test_wallpaper_helpers_present(index_html: str):
    assert "function getChatWallpaper(scope, key)" in index_html
    assert "function setChatWallpaper(scope, key, hex)" in index_html
    assert "function applyActiveChatWallpaper()" in index_html


def test_wallpaper_applied_on_select(index_html: str):
    """selectPeer + selectGroup must call applyActiveChatWallpaper
    so swap-to-this-chat re-applies the saved tint."""
    sp = index_html.find("function selectPeer(shortId)")
    sg = index_html.find("async function selectGroup(gidHex)")
    assert sp > 0 and sg > 0
    sp_block = index_html[sp : sp + 3000]
    sg_block = index_html[sg : sg + 1500]
    assert "applyActiveChatWallpaper()" in sp_block
    assert "applyActiveChatWallpaper()" in sg_block


# ───────── version pin ──────────────────────────────────────────────


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
