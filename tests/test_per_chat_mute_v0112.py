"""v0.11.2 — Per-chat mute with duration + notification toggles.

Per-chat mute:
  - peers.muted_until_ms (schema v14): NULL = unmuted, 0 = forever,
    N > 0 = muted until wall-clock ms N.
  - PeerRecord.is_muted_at(now_ms) auto-expires past deadlines.
  - POST /api/peers/{fp}/mute body {duration_ms} stores the absolute
    deadline so a daemon restart preserves the mute.
  - POST /api/groups/{gid}/mute uses settings keyed
    `group_mute:<gid_hex>` so no schema change is needed.

Global notification toggles:
  - notification_preview: include message body in the desktop
    notification.
  - notify_on_reactions: ping when peers react to my messages.
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
from one_link.state import PeerRecord, State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="mute-host",
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


# ───────── PeerRecord.is_muted_at ────────────────────────────────────

def test_is_muted_at_none_means_unmuted():
    rec = PeerRecord(
        fingerprint="x", short_id="x", pubkey=b"", hostname=None,
        last_address=None, last_port=None, trust="pinned",
        first_seen_ms=0, last_seen_ms=0,
        muted_until_ms=None,
    )
    assert rec.is_muted_at(1_000_000) is False


def test_is_muted_at_zero_means_forever():
    """0 = mute forever — never expires."""
    rec = PeerRecord(
        fingerprint="x", short_id="x", pubkey=b"", hostname=None,
        last_address=None, last_port=None, trust="pinned",
        first_seen_ms=0, last_seen_ms=0,
        muted_until_ms=0,
    )
    assert rec.is_muted_at(1) is True
    assert rec.is_muted_at(10**18) is True


def test_is_muted_at_future_deadline_is_muted():
    rec = PeerRecord(
        fingerprint="x", short_id="x", pubkey=b"", hostname=None,
        last_address=None, last_port=None, trust="pinned",
        first_seen_ms=0, last_seen_ms=0,
        muted_until_ms=1_500,
    )
    assert rec.is_muted_at(1_499) is True


def test_is_muted_at_past_deadline_is_unmuted():
    """The whole point of duration mutes — expired deadlines auto-
    unmute without any explicit action."""
    rec = PeerRecord(
        fingerprint="x", short_id="x", pubkey=b"", hostname=None,
        last_address=None, last_port=None, trust="pinned",
        first_seen_ms=0, last_seen_ms=0,
        muted_until_ms=1_000,
    )
    assert rec.is_muted_at(1_001) is False


def test_is_muted_at_falls_back_to_legacy_bool():
    """v0.7.3 schemas pre-date muted_until_ms; the legacy `muted`
    column still drives is_muted_at for those rows."""
    rec = PeerRecord(
        fingerprint="x", short_id="x", pubkey=b"", hostname=None,
        last_address=None, last_port=None, trust="pinned",
        first_seen_ms=0, last_seen_ms=0,
        muted=True,
        muted_until_ms=None,
    )
    assert rec.is_muted_at(1_000) is True


# ───────── State helpers ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_peer_muted_until_persists(http):
    _, _, state, _ = http
    state.set_peer_muted_until("aa" * 32, 999_999_999_999)
    rec = state.get_peer("aa" * 32)
    assert rec.muted_until_ms == 999_999_999_999
    # Legacy boolean kept in sync for callers that haven't been
    # ported yet.
    assert rec.muted is True


@pytest.mark.asyncio
async def test_set_peer_muted_until_none_clears_legacy_bool(http):
    _, _, state, _ = http
    state.set_peer_muted_until("aa" * 32, 0)
    state.set_peer_muted_until("aa" * 32, None)
    rec = state.get_peer("aa" * 32)
    assert rec.muted_until_ms is None
    assert rec.muted is False


@pytest.mark.asyncio
async def test_set_peer_muted_until_rejects_negative(http):
    _, _, state, _ = http
    with pytest.raises(ValueError):
        state.set_peer_muted_until("aa" * 32, -1)


# ───────── POST /api/peers/{fp}/mute ─────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_mute_with_duration_sets_deadline(http):
    client, _, state, token = http
    resp = await client.post(
        f"/api/peers/{'aa' * 32}/mute", headers=_h(token),
        json={"duration_ms": 60_000},
    )
    assert resp.status == 200
    j = await resp.json()
    rec = state.get_peer("aa" * 32)
    # Deadline should be roughly now + 60s.
    assert j["muted_until_ms"] is not None
    assert j["muted_until_ms"] > 0
    assert rec.muted_until_ms == j["muted_until_ms"]


@pytest.mark.asyncio
async def test_endpoint_mute_zero_means_forever(http):
    client, _, state, token = http
    resp = await client.post(
        f"/api/peers/{'aa' * 32}/mute", headers=_h(token),
        json={"duration_ms": 0},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["muted_until_ms"] == 0
    assert state.get_peer("aa" * 32).muted_until_ms == 0


@pytest.mark.asyncio
async def test_endpoint_mute_null_unmutes(http):
    client, _, state, token = http
    state.set_peer_muted_until("aa" * 32, 0)  # mute forever first
    resp = await client.post(
        f"/api/peers/{'aa' * 32}/mute", headers=_h(token),
        json={"duration_ms": None},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["muted_until_ms"] is None
    assert state.get_peer("aa" * 32).muted_until_ms is None


@pytest.mark.asyncio
async def test_endpoint_mute_rejects_negative(http):
    client, _, _, token = http
    resp = await client.post(
        f"/api/peers/{'aa' * 32}/mute", headers=_h(token),
        json={"duration_ms": -1},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_endpoint_mute_404_for_unknown_peer(http):
    client, _, _, token = http
    resp = await client.post(
        f"/api/peers/{'00' * 32}/mute", headers=_h(token),
        json={"duration_ms": 60_000},
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_api_peers_includes_muted_until_ms(http):
    client, _, state, token = http
    state.set_peer_muted_until("aa" * 32, 12345)
    resp = await client.get("/api/peers", headers=_h(token))
    j = await resp.json()
    rec = next(p for p in j["peers"] if p["fingerprint"] == "aa" * 32)
    assert rec["muted_until_ms"] == 12345


# ───────── POST /api/groups/{gid}/mute ───────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_group_mute_stores_in_settings(http):
    client, _, state, token = http
    gid = "ab" * 16  # 32-char hex ok
    resp = await client.post(
        f"/api/groups/{gid}/mute", headers=_h(token),
        json={"duration_ms": 0},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["muted_until_ms"] == 0
    # Stored in settings under group_mute:<gid>.
    raw = state.get_setting(f"group_mute:{gid}")
    assert raw == "0"


@pytest.mark.asyncio
async def test_endpoint_group_mute_null_clears_settings(http):
    client, _, state, token = http
    gid = "ab" * 16
    await client.post(
        f"/api/groups/{gid}/mute", headers=_h(token),
        json={"duration_ms": 0},
    )
    resp = await client.post(
        f"/api/groups/{gid}/mute", headers=_h(token),
        json={"duration_ms": None},
    )
    assert resp.status == 200
    assert state.get_setting(f"group_mute:{gid}") is None


@pytest.mark.asyncio
async def test_endpoint_group_mute_rejects_bad_hex(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/groups/not-hex/mute", headers=_h(token),
        json={"duration_ms": 0},
    )
    assert resp.status == 400


# ───────── /api/settings — notification toggles ──────────────────────

@pytest.mark.asyncio
async def test_settings_default_notification_toggles(http):
    client, _, _, token = http
    resp = await client.get("/api/settings", headers=_h(token))
    j = await resp.json()
    # Both default ON so users see useful behavior on a fresh install.
    assert j["notification_preview"] is True
    assert j["notify_on_reactions"] is True


@pytest.mark.asyncio
async def test_settings_notification_preview_persists(http):
    client, _, _, token = http
    await client.post(
        "/api/settings", headers=_h(token),
        json={"notification_preview": False},
    )
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["notification_preview"] is False


@pytest.mark.asyncio
async def test_settings_notify_on_reactions_persists(http):
    client, _, _, token = http
    await client.post(
        "/api/settings", headers=_h(token),
        json={"notify_on_reactions": False},
    )
    g = await (await client.get("/api/settings", headers=_h(token))).json()
    assert g["notify_on_reactions"] is False


# ───────── UI surface — duration picker + global toggles ─────────────

def test_drawer_has_mute_duration_picker(index_html: str):
    assert 'id="dev-mute-duration"' in index_html
    assert 'id="dev-mute-apply"' in index_html
    assert 'id="dev-mute-status"' in index_html


def test_duration_picker_options(index_html: str):
    """Pin the standard duration set so a refactor can't accidentally
    drop one. 15min / 1h / 8h / 24h / 1 week / Until I unmute /
    Unmute now is the messaging-app convention."""
    idx = index_html.find('id="dev-mute-duration"')
    snippet = index_html[idx:idx + 1500]
    expected = ["900000", "3600000", "28800000", "86400000", "604800000", "0"]
    for v in expected:
        assert f'value="{v}"' in snippet, f"duration {v} missing"
    assert 'value="null"' in snippet  # explicit unmute option


def test_apply_handler_posts_to_mute_endpoint(index_html: str):
    idx = index_html.find('"#dev-mute-apply"')
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "/mute" in snippet
    assert "duration_ms" in snippet


def test_render_mute_status_helper_present(index_html: str):
    assert "function _renderMuteStatus(target, mutedUntilMs, legacyMuted)" in index_html


def test_open_drawer_renders_mute_status(index_html: str):
    """Whenever the device drawer opens, the mute status text must
    reflect the current deadline. Without this the user would have
    to guess whether their previous mute is still active."""
    idx = index_html.find('async function openDeviceDrawer(shortId)')
    assert idx > 0
    snippet = index_html[idx:idx + 4000]
    assert "_renderMuteStatus(" in snippet
    assert "muted_until_ms" in snippet


def test_global_notif_preview_toggle_present(index_html: str):
    assert 'id="set-notif-preview"' in index_html


def test_global_notif_reactions_toggle_present(index_html: str):
    assert 'id="set-notif-reactions"' in index_html


def test_save_handler_includes_notif_toggles(index_html: str):
    idx = index_html.find('"#settings-save").onclick')
    snippet = index_html[idx:idx + 3000]
    assert "notification_preview:" in snippet
    assert "notify_on_reactions:" in snippet


# ───────── version pin ───────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
