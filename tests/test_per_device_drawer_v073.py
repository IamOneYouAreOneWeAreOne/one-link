"""v0.7.3 per-device drawer tests.

Pin the contract:
  - State: peers gain `local_alias` + `muted` columns. Migration
    is idempotent and PRAGMA-introspected so existing v0.7.2 dbs
    upgrade cleanly.
  - PeerRecord exposes display_name = local_alias or hostname or
    short_id (alias wins).
  - set_peer_profile updates fields independently with Ellipsis
    sentinel for "leave alone" semantics.
  - api_set_peer_profile validates types, persists, broadcasts a
    `peer_profile` WS event.
  - api_peers surfaces local_alias / muted / display_name on
    every paired-peer row.
  - The Settings modal's old per-device permissions section is
    gone (HTML structural test).
  - The new Device drawer modal exists with the expected ids.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from one_link.state import PeerRecord, State


# ─── State schema migration ────────────────────────────────────────

def test_peers_table_has_profile_columns(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    rows = state._conn.execute("PRAGMA table_info(peers)").fetchall()
    cols = {r[1] for r in rows}
    assert "local_alias" in cols
    assert "muted" in cols
    state.close()


def test_migration_idempotent_on_reopen(tmp_path: Path):
    """Open, close, re-open — no errors, columns remain."""
    db = tmp_path / "s.db"
    State(db_path=db).close()
    state = State(db_path=db)
    rows = state._conn.execute("PRAGMA table_info(peers)").fetchall()
    cols = {r[1] for r in rows}
    assert "local_alias" in cols
    assert "muted" in cols
    state.close()


# ─── PeerRecord.display_name ───────────────────────────────────────

def test_display_name_prefers_alias():
    p = PeerRecord(
        fingerprint="aa" * 32, short_id="ab",
        pubkey=b"\x00" * 32,
        hostname="real-host", last_address=None, last_port=None,
        trust="pinned", first_seen_ms=0, last_seen_ms=0,
        local_alias="my laptop", muted=False,
    )
    assert p.display_name == "my laptop"


def test_display_name_falls_back_to_hostname():
    p = PeerRecord(
        fingerprint="aa" * 32, short_id="ab",
        pubkey=b"\x00" * 32,
        hostname="real-host", last_address=None, last_port=None,
        trust="pinned", first_seen_ms=0, last_seen_ms=0,
        local_alias=None, muted=False,
    )
    assert p.display_name == "real-host"


def test_display_name_falls_back_to_short_id_if_no_hostname():
    p = PeerRecord(
        fingerprint="aa" * 32, short_id="abc12345",
        pubkey=b"\x00" * 32,
        hostname=None, last_address=None, last_port=None,
        trust="pinned", first_seen_ms=0, last_seen_ms=0,
    )
    assert p.display_name == "abc12345"


# ─── set_peer_profile semantics ────────────────────────────────────

def test_set_peer_profile_updates_alias(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x00" * 32, hostname="laptop",
    )
    rec = state.set_peer_profile("aa" * 32, local_alias="my work laptop")
    assert rec.local_alias == "my work laptop"
    assert rec.display_name == "my work laptop"
    state.close()


def test_set_peer_profile_clears_alias_with_none(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x00" * 32, hostname="laptop",
    )
    state.set_peer_profile("aa" * 32, local_alias="custom")
    rec = state.set_peer_profile("aa" * 32, local_alias=None)
    assert rec.local_alias is None
    assert rec.display_name == "laptop"
    state.close()


def test_set_peer_profile_strips_whitespace_to_none(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x00" * 32, hostname="laptop",
    )
    rec = state.set_peer_profile("aa" * 32, local_alias="   ")
    assert rec.local_alias is None
    state.close()


def test_set_peer_profile_mute_toggle(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa", pubkey=b"\x00" * 32,
    )
    rec = state.set_peer_profile("aa" * 32, muted=True)
    assert rec.muted is True
    rec = state.set_peer_profile("aa" * 32, muted=False)
    assert rec.muted is False
    state.close()


def test_set_peer_profile_ellipsis_leaves_field_alone(tmp_path: Path):
    """Updating only `muted` should not touch `local_alias`, and
    vice versa."""
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa", pubkey=b"\x00" * 32,
    )
    state.set_peer_profile("aa" * 32, local_alias="kept")
    rec = state.set_peer_profile("aa" * 32, muted=True)
    assert rec.local_alias == "kept"
    assert rec.muted is True
    state.close()


def test_set_peer_profile_no_fields_returns_current(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa", pubkey=b"\x00" * 32,
    )
    rec = state.set_peer_profile("aa" * 32)
    assert rec is not None
    assert rec.local_alias is None
    assert rec.muted is False
    state.close()


# ─── api_set_peer_profile endpoint ─────────────────────────────────

@pytest.mark.asyncio
async def test_api_profile_round_trip(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb", pubkey=b"\x00" * 32,
        hostname="phone",
    )
    state.set_peer_trust("bb" * 32, "pinned")

    broadcasts: list[dict] = []
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: broadcasts.append(evt)

    class _Req:
        match_info = {"fp": "bb" * 32}
        async def json(self):
            return {"local_alias": "my phone", "muted": True}

    resp = await server.api_set_peer_profile(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["local_alias"] == "my phone"
    assert body["muted"] is True
    assert body["display_name"] == "my phone"

    # Persisted.
    rec = state.get_peer("bb" * 32)
    assert rec.local_alias == "my phone"
    assert rec.muted is True

    # Broadcast fired.
    assert any(b.get("type") == "peer_profile" for b in broadcasts)
    state.close()


@pytest.mark.asyncio
async def test_api_profile_404_unknown_peer(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": "zz" * 32}
        async def json(self):
            return {"local_alias": "x"}

    resp = await server.api_set_peer_profile(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_profile_rejects_long_alias(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb", pubkey=b"\x00" * 32,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": "bb" * 32}
        async def json(self):
            return {"local_alias": "x" * 100}

    resp = await server.api_set_peer_profile(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_profile_rejects_non_bool_muted(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb", pubkey=b"\x00" * 32,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": "bb" * 32}
        async def json(self):
            return {"muted": "yes please"}

    resp = await server.api_set_peer_profile(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_profile_rejects_empty_body(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb", pubkey=b"\x00" * 32,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": "bb" * 32}
        async def json(self):
            return {}

    resp = await server.api_set_peer_profile(_Req())
    assert resp.status == 400
    state.close()


# ─── api_peers surfaces profile fields ──────────────────────────────

@pytest.mark.asyncio
async def test_api_peers_surfaces_local_alias_and_muted(tmp_path: Path):
    from one_link.server import UIServer
    from one_link.identity import fingerprint_of

    pub_hex = "cc" * 32
    fp = fingerprint_of(bytes.fromhex(pub_hex))
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=fp, short_id="ccccc", pubkey=bytes.fromhex(pub_hex),
        hostname="real-name", trust_default="pinned",
    )
    state.set_peer_profile(fp, local_alias="aliased", muted=True)

    daemon = SimpleNamespace(
        state=state,
        discovery=None,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="me", hostname="me"),
        _outbound_sessions={},
        _inbound_regime={},
        get_pair_health=lambda fp: None,
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_peers(_Req())
    body = json.loads(resp.text)
    peers = {p["fingerprint"]: p for p in body["peers"]}
    p = peers[fp]
    assert p["local_alias"] == "aliased"
    assert p["muted"] is True
    assert p["display_name"] == "aliased"
    state.close()


# ─── HTML structural pins (ensure drawer landed, perm row gone) ────

_REPO_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


def test_index_html_has_device_drawer_modal():
    text = _REPO_INDEX.read_text(encoding="utf-8")
    for needle in [
        'id="device-backdrop"',
        'id="device-drawer-name"',
        'id="dev-alias"',
        'id="dev-mute"',
        'id="dev-cap-row"',
        'id="dev-regime"',
        'id="dev-latency"',
        'id="dev-fp"',
        'id="dev-sas"',
        'id="dev-unpair"',
        'id="dev-block"',
        'id="device-save"',
        'id="device-cancel"',
        "function openDeviceDrawer",
        "function closeDeviceDrawer",
    ]:
        assert needle in text, f"device drawer missing {needle!r}"


def test_index_html_dropped_per_device_perm_section_from_settings():
    """The per-device permissions section that briefly lived in the
    main Settings modal (between v0.7.2 and v0.7.3) is gone — caps
    live in the device drawer now."""
    text = _REPO_INDEX.read_text(encoding="utf-8")
    assert 'id="set-perm-section"' not in text
    assert 'id="set-perm-peer"' not in text


def test_index_html_keeps_app_wide_settings():
    """App-wide settings (display name, auto-pair, rendezvous,
    notifications) must still be in the main Settings modal."""
    text = _REPO_INDEX.read_text(encoding="utf-8")
    assert 'id="set-name"' in text
    assert 'id="set-autoaccept"' in text
    assert 'id="set-rendezvous"' in text
    assert 'id="set-notif"' in text


def test_index_html_peer_row_renders_gear_button():
    text = _REPO_INDEX.read_text(encoding="utf-8")
    assert 'class="gear-btn"' in text or '"gear-btn"' in text
    assert "openDeviceDrawer" in text


def test_index_html_convo_who_clickable_for_drawer():
    """Clicking the conversation header device card opens the
    drawer for that peer."""
    text = _REPO_INDEX.read_text(encoding="utf-8")
    assert 'id="convo-who"' in text
    # Click handler binds the drawer.
    assert "convo-who" in text and "openDeviceDrawer" in text
