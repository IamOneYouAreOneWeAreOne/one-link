"""v0.10.2 — disappearing messages (per-peer TTL).

A per-peer setting (peers.dm_ttl_ms) attaches a self-destruct
timer to every TEXT message sent to or received from that peer.
Sender stamps `ttl_ms` on the wire frame; both ends compute
expires_at_ms = ts_ms + ttl_ms during _persist; the daemon's
reaper task tombstones expired rows every 30s and broadcasts
msg_delete WS events.

Tests: schema migration, state helpers, daemon wire propagation,
reaper sweep semantics, server endpoint, UI surface.
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
        fingerprint=fp, short_id=fp[:8], hostname="ttl-host",
    )


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ───────── schema migration ──────────────────────────────────────────

def test_migration_v12_adds_columns(state: State):
    peer_cols = {
        r["name"] for r in state._conn.execute(
            "PRAGMA table_info(peers)"
        ).fetchall()
    }
    msg_cols = {
        r["name"] for r in state._conn.execute(
            "PRAGMA table_info(messages)"
        ).fetchall()
    }
    assert "dm_ttl_ms" in peer_cols
    assert "expires_at_ms" in msg_cols
    assert state.schema_version() >= 12


def test_partial_index_on_expires_at_ms(state: State):
    rows = state._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' "
        "AND name='idx_messages_expiry'"
    ).fetchall()
    assert len(rows) == 1
    assert "WHERE expires_at_ms IS NOT NULL" in rows[0]["sql"]


# ───────── state helpers ─────────────────────────────────────────────

def _seed_peer(state: State, fp: str = "aa" * 32) -> None:
    state.upsert_peer(
        fingerprint=fp, short_id=fp[:8], pubkey=b"\x00" * 32, hostname="x",
    )


def test_set_and_get_peer_dm_ttl(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    rec = state.set_peer_dm_ttl(fp, 5 * 60 * 1000)
    assert rec.dm_ttl_ms == 300_000
    assert state.get_peer_dm_ttl(fp) == 300_000


def test_set_peer_dm_ttl_clears_on_none(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.set_peer_dm_ttl(fp, 60_000)
    state.set_peer_dm_ttl(fp, None)
    assert state.get_peer_dm_ttl(fp) is None


def test_set_peer_dm_ttl_validates(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    with pytest.raises(ValueError):
        state.set_peer_dm_ttl(fp, -1)
    with pytest.raises(ValueError):
        state.set_peer_dm_ttl(fp, 0)
    too_long = 30 * 24 * 60 * 60 * 1000 + 1000
    with pytest.raises(ValueError):
        state.set_peer_dm_ttl(fp, too_long)


def test_set_peer_dm_ttl_unknown_peer_returns_none(state: State):
    assert state.set_peer_dm_ttl("ff" * 32, 60_000) is None


# ───────── reaper semantics ──────────────────────────────────────────

def test_expire_due_messages_marks_deleted(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body="poof", expires_at_ms=2000,
    )
    expired = state.expire_due_messages(now_ms=3000)
    assert expired == ["m1"]
    rec = state.get_message("m1")
    assert rec.is_deleted
    assert rec.body is None


def test_expire_due_messages_skips_future(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body="not yet", expires_at_ms=10_000,
    )
    expired = state.expire_due_messages(now_ms=5000)
    assert expired == []
    rec = state.get_message("m1")
    assert not rec.is_deleted


def test_expire_due_messages_skips_already_deleted(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body="x", expires_at_ms=2000,
    )
    state.expire_due_messages(now_ms=3000)
    again = state.expire_due_messages(now_ms=3000)
    assert again == []


def test_expire_due_messages_skips_no_ttl(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body="permanent",
    )
    expired = state.expire_due_messages(now_ms=10**12)
    assert expired == []


def test_record_message_persists_expires(state: State):
    fp = "aa" * 32
    _seed_peer(state, fp)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp=fp,
        msg_type="TEXT", body="x", expires_at_ms=99_999,
    )
    rec = state.get_message("m1")
    assert rec.expires_at_ms == 99_999
    assert rec.is_expiring


# ───────── daemon wire propagation ───────────────────────────────────

def test_persist_attaches_expires_from_ttl_ms(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32,
        hostname="alice",
    )
    msg = {
        "t": "TEXT", "id": "m1", "ts": 1_000,
        "body": "hello", "ttl_ms": 5000,
    }
    daemon._persist(
        msg=msg, direction="in",
        peer_fp="aa" * 32, peer_short_id="alice",
    )
    rec = state.get_message("m1")
    assert rec is not None
    assert rec.expires_at_ms == 6_000
    state.close()


def test_persist_ignores_invalid_ttl_ms(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32,
        hostname="alice",
    )
    for label, bad in (("str", "notanint"), ("neg", -10),
                        ("zero", 0), ("none", None)):
        msg = {
            "t": "TEXT", "id": f"m_{label}", "ts": 1_000,
            "body": "hi", "ttl_ms": bad,
        }
        daemon._persist(
            msg=msg, direction="in",
            peer_fp="aa" * 32, peer_short_id="alice",
        )
        rec = state.get_message(f"m_{label}")
        assert rec is not None
        assert rec.expires_at_ms is None, f"ttl_ms={bad!r}"
    state.close()


def test_persist_strips_ttl_ms_from_metadata(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32,
        hostname="alice",
    )
    msg = {
        "t": "TEXT", "id": "m1", "ts": 1_000,
        "body": "hi", "ttl_ms": 5000,
    }
    daemon._persist(
        msg=msg, direction="in",
        peer_fp="aa" * 32, peer_short_id="alice",
    )
    rec = state.get_message("m1")
    assert "ttl_ms" not in rec.metadata
    state.close()


# ───────── server endpoint ───────────────────────────────────────────

@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    fp = "aa" * 32
    state.upsert_peer(
        fingerprint=fp, short_id=fp[:8], pubkey=b"\x00" * 32, hostname="alice",
    )
    state.set_peer_trust(fp, "pinned")
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
        yield client, daemon, state, server.token, fp
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_endpoint_set_ttl(http):
    client, _, _, token, fp = http
    resp = await client.post(
        f"/api/peers/{fp}/ttl", headers=_h(token),
        json={"ttl_ms": 60_000},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["dm_ttl_ms"] == 60_000


@pytest.mark.asyncio
async def test_endpoint_clear_ttl(http):
    client, _, _, token, fp = http
    await client.post(
        f"/api/peers/{fp}/ttl", headers=_h(token),
        json={"ttl_ms": 60_000},
    )
    resp = await client.post(
        f"/api/peers/{fp}/ttl", headers=_h(token),
        json={"ttl_ms": None},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["dm_ttl_ms"] is None


@pytest.mark.asyncio
async def test_endpoint_rejects_negative(http):
    client, _, _, token, fp = http
    resp = await client.post(
        f"/api/peers/{fp}/ttl", headers=_h(token),
        json={"ttl_ms": -1},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_endpoint_unknown_peer_404(http):
    client, _, _, token, _ = http
    resp = await client.post(
        "/api/peers/" + "ff" * 32 + "/ttl", headers=_h(token),
        json={"ttl_ms": 60_000},
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_api_peers_includes_dm_ttl_ms(http):
    client, _, _, token, fp = http
    await client.post(
        f"/api/peers/{fp}/ttl", headers=_h(token),
        json={"ttl_ms": 300_000},
    )
    resp = await client.get("/api/peers", headers=_h(token))
    j = await resp.json()
    p = next(x for x in j["peers"] if x["fingerprint"] == fp)
    assert p["dm_ttl_ms"] == 300_000


# ───────── UI surface ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_drawer_has_ttl_picker(index_html: str):
    assert 'id="dev-dm-ttl"' in index_html
    for ms in (300_000, 1_800_000, 3_600_000, 86_400_000, 604_800_000):
        assert f'value="{ms}"' in index_html


def test_drawer_ttl_change_posts_to_endpoint(index_html: str):
    # Find the change-event handler (not the value-load site).
    idx = index_html.find('$("#dev-dm-ttl")?.addEventListener("change"')
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "/api/peers/" in snippet
    assert "/ttl`" in snippet


def test_expiry_badge_renderer_present(index_html: str):
    assert "function renderExpiryBadge(" in index_html
    assert "function formatExpiryRemaining(" in index_html


def test_expiry_badge_has_per_second_tick(index_html: str):
    idx = index_html.find('document.querySelectorAll(".expiry-badge")')
    assert idx > 0
    window = index_html[max(0, idx - 200):idx + 800]
    assert "setInterval(" in window


def test_expired_bubble_visually_fades(index_html: str):
    tick_idx = index_html.find('document.querySelectorAll(".expiry-badge")')
    tick_snippet = index_html[tick_idx:tick_idx + 1500]
    assert 'classList.add("expired")' in tick_snippet


def test_conversation_header_pill_rendered(index_html: str):
    assert "dm-ttl-pill" in index_html


def test_message_record_dataclass_has_expires():
    src = Path("src/one_link/state.py").read_text(encoding="utf-8")
    assert "expires_at_ms: Optional[int] = None" in src
    assert "def is_expiring(self)" in src


def test_msg_record_to_event_surfaces_expires():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("def _msg_record_to_event(")
    snippet = src[idx:idx + 2000]
    assert '"expires_at_ms"' in snippet


def test_daemon_reaper_loop_present():
    src = Path("src/one_link/daemon.py").read_text(encoding="utf-8")
    assert "async def _dm_reaper_loop(" in src
    assert "expire_due_messages(" in src


def test_send_text_attaches_ttl_when_set():
    src = Path("src/one_link/daemon.py").read_text(encoding="utf-8")
    idx = src.find("async def send_text(")
    snippet = src[idx:idx + 2500]
    assert "get_peer_dm_ttl(" in snippet
    assert 'kwargs["ttl_ms"]' in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
