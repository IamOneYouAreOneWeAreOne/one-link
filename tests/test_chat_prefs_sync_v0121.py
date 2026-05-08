"""v0.12.1 — server-persisted per-chat cosmetic state.

Closes the "localStorage-only state doesn't sync" gap from v0.11.5.

Group color, chat wallpaper, and archive flag now round-trip through
the daemon (settings table, chatpref:<scope>:<id>:<kind> keys) so
they sync across the user's own devices and survive a browser
cache wipe.

Endpoints:
  GET  /api/chat-prefs        snapshot {peer:{...}, group:{...}}
  POST /api/chat-prefs        body {scope, id, kind, value}

WS broadcasts a "chat_pref" event so other open tabs (and other
devices once they receive their own copy) re-render immediately.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="prefs-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
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
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


_PEER_FP = "aa" * 32
_GID = "ab" * 16


# ───────── GET /api/chat-prefs ──────────────────────────────────────

@pytest.mark.asyncio
async def test_get_empty_when_nothing_set(http):
    client, _, _, token = http
    resp = await client.get("/api/chat-prefs", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert j == {"peer": {}, "group": {}}


@pytest.mark.asyncio
async def test_get_returns_persisted_prefs(http):
    client, _, state, token = http
    state.set_setting(
        f"chatpref:peer:{_PEER_FP}:color", "#7c4dff",
    )
    state.set_setting(
        f"chatpref:group:{_GID}:archived", "true",
    )
    state.set_setting(
        f"chatpref:peer:{_PEER_FP}:wallpaper", "#1a2e3a",
    )
    resp = await client.get("/api/chat-prefs", headers=_h(token))
    j = await resp.json()
    assert j["peer"][_PEER_FP]["color"] == "#7c4dff"
    assert j["peer"][_PEER_FP]["wallpaper"] == "#1a2e3a"
    assert j["group"][_GID]["archived"] is True


# ───────── POST /api/chat-prefs ─────────────────────────────────────

@pytest.mark.asyncio
async def test_set_color_persists(http):
    client, _, state, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "color", "value": "#3b82f6"},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["value"] == "#3b82f6"
    raw = state.get_setting(f"chatpref:peer:{_PEER_FP}:color")
    assert raw == "#3b82f6"


@pytest.mark.asyncio
async def test_set_archived_true_persists(http):
    client, _, state, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "group", "id": _GID,
              "kind": "archived", "value": True},
    )
    assert resp.status == 200
    raw = state.get_setting(f"chatpref:group:{_GID}:archived")
    assert raw == "true"


@pytest.mark.asyncio
async def test_set_archived_false_clears(http):
    client, _, state, token = http
    state.set_setting(f"chatpref:group:{_GID}:archived", "true")
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "group", "id": _GID,
              "kind": "archived", "value": False},
    )
    assert resp.status == 200
    raw = state.get_setting(f"chatpref:group:{_GID}:archived")
    assert raw is None  # cleared


@pytest.mark.asyncio
async def test_set_value_null_clears(http):
    client, _, state, token = http
    state.set_setting(f"chatpref:peer:{_PEER_FP}:color", "#7c4dff")
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "color", "value": None},
    )
    assert resp.status == 200
    raw = state.get_setting(f"chatpref:peer:{_PEER_FP}:color")
    assert raw is None


# ───────── Validation ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rejects_unknown_scope(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "channel", "id": _GID,
              "kind": "color", "value": "#fff"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_rejects_unknown_kind(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "fontsize", "value": "16"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_rejects_bad_peer_fingerprint(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": "not-hex",
              "kind": "color", "value": "#fff"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_rejects_bad_color_format(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "color", "value": "purple"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_accepts_short_hex_color(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "color", "value": "#abc"},
    )
    assert resp.status == 200


@pytest.mark.asyncio
async def test_rejects_archived_with_string_value(http):
    """'archived' must be a literal bool, not 'true' / 'false' as
    a string. Pin to prevent type drift across builds."""
    client, _, _, token = http
    resp = await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "group", "id": _GID,
              "kind": "archived", "value": "true"},
    )
    assert resp.status == 400


# ───────── Roundtrip integration ────────────────────────────────────

@pytest.mark.asyncio
async def test_set_then_get_returns_same_value(http):
    client, _, _, token = http
    await client.post(
        "/api/chat-prefs", headers=_h(token),
        json={"scope": "peer", "id": _PEER_FP,
              "kind": "color", "value": "#10b981"},
    )
    g = await (await client.get("/api/chat-prefs", headers=_h(token))).json()
    assert g["peer"][_PEER_FP]["color"] == "#10b981"


@pytest.mark.asyncio
async def test_does_not_collide_with_other_settings(http):
    """The chatpref: prefix must not bleed into other consumers
    of all_settings()."""
    client, _, state, token = http
    state.set_setting("display_name", "Alex")
    state.set_setting(f"chatpref:peer:{_PEER_FP}:color", "#fff")
    j = await (await client.get("/api/chat-prefs", headers=_h(token))).json()
    assert "display_name" not in j["peer"]
    assert "display_name" not in j["group"]


# ───────── UI rewiring — read/write through cache + server ──────────

def test_read_chat_pref_helper_present(index_html: str):
    assert "function _readChatPref(scope, id, kind)" in index_html


def test_write_chat_pref_posts_to_server(index_html: str):
    """Pin the server roundtrip so a refactor can't quietly drop
    the cross-device sync and leave us localStorage-only again."""
    idx = index_html.find("function _writeChatPref(scope, id, kind, value)")
    assert idx > 0
    snippet = index_html[idx:idx + 2000]
    assert '/api/chat-prefs' in snippet
    assert "api.post" in snippet


def test_load_chat_prefs_runs_on_init(index_html: str):
    assert "async function loadChatPrefs()" in index_html
    # Must be called from init() — pin the order.
    init_idx = index_html.find("async function init()")
    snippet = index_html[init_idx:init_idx + 4000]
    assert "loadChatPrefs()" in snippet


def test_ws_handles_chat_pref_event(index_html: str):
    """Other tabs / other devices must trigger UI re-render via WS."""
    idx = index_html.find('m.type === "chat_pref"')
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "state.chatPrefs" in snippet
    assert "renderGroups()" in snippet
    assert "renderPeers()" in snippet


def test_get_group_color_reads_via_cache(index_html: str):
    idx = index_html.find("function getGroupColor(gid)")
    snippet = index_html[idx:idx + 400]
    assert '_readChatPref("group", gid, "color")' in snippet


def test_set_group_archived_writes_via_cache(index_html: str):
    idx = index_html.find("function setGroupArchived(gid, archived)")
    snippet = index_html[idx:idx + 400]
    assert "_writeChatPref" in snippet


def test_set_chat_wallpaper_writes_via_cache(index_html: str):
    idx = index_html.find("function setChatWallpaper(scope, key, hex)")
    snippet = index_html[idx:idx + 400]
    assert "_writeChatPref" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
