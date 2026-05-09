"""v0.11.6 — Storage & data (Phase 6, final phase of Settings overhaul).

Backend:
  - GET /api/storage/usage returns per-peer + per-group rollups
    (msg_count, file_count, file_bytes) joined with display names.
  - State.storage_usage_by_peer / .storage_usage_by_group provide
    the underlying queries.
  - Settings extended with four storage + data keys:
      default_dm_ttl_ms       — int|null (ms; null/0 = off)
      bandwidth_cap_kbps      — int (0 = unlimited)
      auto_accept_max_size_mb — int (0 = no limit)
      auto_accept_extensions  — list-of-strings (lowercased,
                                deduped, leading dots stripped)
  - State.set_peer_trust auto-applies default_dm_ttl_ms on first
    transition to pinned (the "applies to new pairings" promise).

Frontend:
  - Storage pane redesigned: Downloads (existing) +
    Default disappearing messages + Bandwidth limit +
    Auto-accept rules + Storage by chat (table with totals
    + per-row Clear).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import (
    UIServer,
    _normalize_ext_list,
    _parse_int_or_none,
)
from one_link.state import State


def _identity(host: str = "host") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=host,
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice",
        pubkey=b"\x00" * 32, hostname="alice",
    )
    state.set_peer_trust("aa" * 32, "pinned")
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


# ───────── _normalize_ext_list / _parse_int_or_none ──────────────────

def test_normalize_ext_list_dedupes_lowercases_strips_dots():
    assert _normalize_ext_list("PNG, .jpg,jpeg, png") == ["jpeg", "jpg", "png"]


def test_normalize_ext_list_handles_empty():
    assert _normalize_ext_list("") == []
    assert _normalize_ext_list(None) == []


def test_parse_int_or_none_handles_strings():
    assert _parse_int_or_none(None) is None
    assert _parse_int_or_none("") is None
    assert _parse_int_or_none("not a number") is None
    assert _parse_int_or_none("42") == 42
    assert _parse_int_or_none(42) == 42


# ───────── State helpers ────────────────────────────────────────────

def test_storage_usage_by_peer_aggregates_msg_and_file_bytes(tmp_path: Path):
    state = State(db_path=tmp_path / "u.db")
    fp_a = "aa" * 32
    fp_b = "bb" * 32
    state.upsert_peer(fingerprint=fp_a, short_id="a", pubkey=b"\x00" * 32, hostname="a")
    state.upsert_peer(fingerprint=fp_b, short_id="b", pubkey=b"\x00" * 32, hostname="b")
    # A: 2 text, 1 file (size 1000)
    state.record_message(id="t1", ts_ms=1, direction="out", peer_fp=fp_a,
                         msg_type="text", body="hi", room_id=None)
    state.record_message(id="t2", ts_ms=2, direction="in", peer_fp=fp_a,
                         msg_type="text", body="hi", room_id=None)
    state.record_message(id="f1", ts_ms=3, direction="out", peer_fp=fp_a,
                         msg_type="file", body="x.pdf", room_id=None,
                         metadata={"size": 1000})
    # B: 1 file (size 5000)
    state.record_message(id="f2", ts_ms=4, direction="in", peer_fp=fp_b,
                         msg_type="file", body="y.zip", room_id=None,
                         metadata={"size": 5000})
    rows = state.storage_usage_by_peer()
    by_fp = {r["peer_fp"]: r for r in rows}
    assert by_fp[fp_a]["msg_count"] == 3
    assert by_fp[fp_a]["file_count"] == 1
    assert by_fp[fp_a]["file_bytes"] == 1000
    assert by_fp[fp_b]["file_bytes"] == 5000
    # Largest by file_bytes first.
    assert rows[0]["peer_fp"] == fp_b
    state.close()


def test_storage_usage_by_group_returns_empty_when_no_table(tmp_path: Path):
    """Old schemas may not have group_messages; fall back gracefully."""
    state = State(db_path=tmp_path / "g.db")
    rows = state.storage_usage_by_group()
    assert isinstance(rows, list)
    state.close()


# ───────── /api/storage/usage ────────────────────────────────────────

@pytest.mark.asyncio
async def test_storage_usage_endpoint_shape(http):
    client, _, state, token = http
    state.record_message(id="m", ts_ms=1, direction="out", peer_fp="aa" * 32,
                         msg_type="text", body="hi", room_id=None)
    state.record_message(id="f", ts_ms=2, direction="in", peer_fp="aa" * 32,
                         msg_type="file", body="x", room_id=None,
                         metadata={"size": 4242})
    resp = await client.get("/api/storage/usage", headers=_h(token))
    assert resp.status == 200
    j = await resp.json()
    assert "peers" in j
    assert "groups" in j
    assert "totals" in j
    p = j["peers"][0]
    assert p["fingerprint"] == "aa" * 32
    assert p["msg_count"] == 2
    assert p["file_bytes"] == 4242
    assert "display_name" in p
    assert j["totals"]["msg_count"] == 2
    assert j["totals"]["file_bytes"] == 4242


# ───────── Settings GET defaults ─────────────────────────────────────

@pytest.mark.asyncio
async def test_settings_default_storage_keys(http):
    client, _, _, token = http
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    assert j["default_dm_ttl_ms"] is None
    assert j["bandwidth_cap_kbps"] == 0
    assert j["auto_accept_max_size_mb"] == 0
    assert j["auto_accept_extensions"] == []
    assert j["safety_max_file_tb"] == 16
    assert j["safety_min_free_mb"] == 2048
    assert j["safety_peer_active_transfers"] == 3
    assert j["safety_peer_active_gb"] == 2048


# ───────── Settings POST roundtrips ──────────────────────────────────

@pytest.mark.asyncio
async def test_settings_default_dm_ttl_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"default_dm_ttl_ms": 86400000})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["default_dm_ttl_ms"] == 86400000


@pytest.mark.asyncio
async def test_settings_default_dm_ttl_zero_clears(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"default_dm_ttl_ms": 86400000})
    await client.post("/api/settings", headers=_h(token),
                      json={"default_dm_ttl_ms": 0})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["default_dm_ttl_ms"] is None


@pytest.mark.asyncio
async def test_settings_bandwidth_cap_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"bandwidth_cap_kbps": 5120})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["bandwidth_cap_kbps"] == 5120


@pytest.mark.asyncio
async def test_settings_bandwidth_cap_zero_clears(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"bandwidth_cap_kbps": 5120})
    await client.post("/api/settings", headers=_h(token),
                      json={"bandwidth_cap_kbps": 0})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["bandwidth_cap_kbps"] == 0


@pytest.mark.asyncio
async def test_settings_bandwidth_cap_rejects_negative(http):
    client, _, _, token = http
    resp = await client.post("/api/settings", headers=_h(token),
                              json={"bandwidth_cap_kbps": -1})
    assert resp.status == 400


@pytest.mark.asyncio
async def test_settings_auto_accept_size_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"auto_accept_max_size_mb": 100})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["auto_accept_max_size_mb"] == 100


@pytest.mark.asyncio
async def test_settings_auto_accept_extensions_normalize(http):
    """Extensions are normalized server-side: lowercased, deduped,
    leading dots stripped."""
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"auto_accept_extensions": "PNG, .jpg, png, JPG"})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["auto_accept_extensions"] == ["jpg", "png"]


@pytest.mark.asyncio
async def test_settings_auto_accept_extensions_accept_list_form(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"auto_accept_extensions": ["PDF", ".jpg"]})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["auto_accept_extensions"] == ["jpg", "pdf"]


@pytest.mark.asyncio
async def test_settings_transfer_safety_policy_persists_and_refreshes(http):
    client, daemon, _, token = http
    resp = await client.post(
        "/api/settings",
        headers=_h(token),
        json={
            "safety_max_file_tb": 4,
            "safety_min_free_mb": 1024,
            "safety_peer_active_transfers": 2,
            "safety_peer_active_gb": 512,
        },
    )
    assert resp.status == 200
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["safety_max_file_tb"] == 4
    assert j["safety_min_free_mb"] == 1024
    assert j["safety_peer_active_transfers"] == 2
    assert j["safety_peer_active_gb"] == 512
    assert daemon._transfer_admission_policy.max_declared_bytes == 4 * 1024 ** 4
    assert daemon._transfer_admission_policy.min_free_reserve_bytes == 1024 * 1024 ** 2


@pytest.mark.asyncio
async def test_settings_transfer_safety_rejects_unsafe_minimums(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/settings",
        headers=_h(token),
        json={"safety_min_free_mb": 10},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_settings_auto_accept_extensions_empty_clears(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"auto_accept_extensions": "pdf"})
    await client.post("/api/settings", headers=_h(token),
                      json={"auto_accept_extensions": ""})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["auto_accept_extensions"] == []


# ───────── default_dm_ttl_ms applies on new pairing ──────────────────

def test_default_dm_ttl_applies_on_first_pin(tmp_path: Path):
    """The "applies to new pairings" promise from the Storage pane.
    Setting a default + transitioning a peer from pending → pinned
    should populate that peer's dm_ttl_ms automatically."""
    state = State(db_path=tmp_path / "p.db")
    state.set_setting("default_dm_ttl_ms", "3600000")
    fp = "cc" * 32
    state.upsert_peer(fingerprint=fp, short_id="c",
                      pubkey=b"\x00" * 32, hostname="c")
    # Peer starts as "pending" by default.
    state.set_peer_trust(fp, "pinned")
    rec = state.get_peer(fp)
    assert rec.dm_ttl_ms == 3600000
    state.close()


def test_default_dm_ttl_does_not_overwrite_existing(tmp_path: Path):
    """If the peer ALREADY has a per-chat TTL, the default should
    not stomp on it."""
    state = State(db_path=tmp_path / "p2.db")
    state.set_setting("default_dm_ttl_ms", "3600000")
    fp = "dd" * 32
    state.upsert_peer(fingerprint=fp, short_id="d",
                      pubkey=b"\x00" * 32, hostname="d")
    state.set_peer_dm_ttl(fp, 5000)  # explicit per-chat TTL first
    state.set_peer_trust(fp, "pinned")
    rec = state.get_peer(fp)
    assert rec.dm_ttl_ms == 5000
    state.close()


def test_no_default_means_no_ttl_on_pin(tmp_path: Path):
    """Without the default setting, transitioning to pinned must
    NOT set a TTL."""
    state = State(db_path=tmp_path / "p3.db")
    fp = "ee" * 32
    state.upsert_peer(fingerprint=fp, short_id="e",
                      pubkey=b"\x00" * 32, hostname="e")
    state.set_peer_trust(fp, "pinned")
    rec = state.get_peer(fp)
    assert rec.dm_ttl_ms is None
    state.close()


# ───────── UI markup ────────────────────────────────────────────────

def test_storage_pane_has_default_ttl_select(index_html: str):
    assert 'id="set-default-dm-ttl"' in index_html


def test_storage_pane_has_bandwidth_cap_select(index_html: str):
    assert 'id="set-bandwidth-cap"' in index_html


def test_storage_pane_has_auto_accept_inputs(index_html: str):
    assert 'id="set-auto-accept-size"' in index_html
    assert 'id="set-auto-accept-exts"' in index_html


def test_storage_pane_has_usage_table(index_html: str):
    assert 'id="storage-totals"' in index_html
    assert 'id="storage-table"' in index_html
    assert 'id="storage-refresh"' in index_html


def test_save_handler_includes_storage_keys(index_html: str):
    """The four new keys must ride on the same /api/settings POST
    that the existing Save button fires."""
    idx = index_html.find('"#settings-save").onclick')
    assert idx > 0
    snippet = index_html[idx:idx + 5000]
    assert "default_dm_ttl_ms:" in snippet
    assert "bandwidth_cap_kbps:" in snippet
    assert "auto_accept_max_size_mb:" in snippet
    assert "auto_accept_extensions:" in snippet


def test_storage_pane_lazy_loads_usage(index_html: str):
    """switchSettingsPane must call refreshStorageUsage when the
    user navigates to the Storage pane. Otherwise the table sits
    empty until they hit Refresh."""
    idx = index_html.find("function switchSettingsPane(name)")
    snippet = index_html[idx:idx + 1500]
    assert 'name === "storage"' in snippet
    assert "refreshStorageUsage()" in snippet


def test_refresh_storage_usage_renders_totals_and_rows(index_html: str):
    idx = index_html.find("async function refreshStorageUsage()")
    assert idx > 0
    snippet = index_html[idx:idx + 4000]
    assert "/api/storage/usage" in snippet
    # Renders totals (chat / msg / file) and per-row Clear.
    assert "chats" in snippet
    assert "messages" in snippet
    assert "Clear" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
