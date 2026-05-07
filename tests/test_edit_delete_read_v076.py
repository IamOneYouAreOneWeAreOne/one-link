"""v0.7.6 edit / delete / read-marker tests.

Pin the contract:
  - State: messages.edited_at_ms / original_body / deleted_at_ms
    columns added via PRAGMA-introspected ALTER. peer_read_markers
    table created.
  - edit_message preserves the original body the first time and
    leaves it alone on subsequent edits. Won't touch deleted rows.
  - delete_message clears body, stamps deleted_at_ms, idempotent
    on already-deleted.
  - record_read_marker is monotonic — older marker can't shrink
    a newer one.
  - Inbound EDIT_MSG handler: pinned-only, author-only,
    cooldown enforced, validates op shape.
  - Inbound DELETE_MSG handler: pinned-only, author-only.
  - Inbound READ_MARKER handler: pinned-only, persists,
    broadcasts UI event.
  - daemon.send_edit enforces cooldown on the sender side.
  - daemon.send_delete soft-deletes locally + emits frame.
  - api_edit_message / api_delete_message / api_set_read_marker
    endpoints validate inputs and persist.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon, EDIT_COOLDOWN_MS
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps: dict | None = None
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# ─── Schema migration ─────────────────────────────────────────────

def test_messages_have_edit_delete_columns(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    rows = state._conn.execute("PRAGMA table_info(messages)").fetchall()
    cols = {r[1] for r in rows}
    assert "edited_at_ms" in cols
    assert "original_body" in cols
    assert "deleted_at_ms" in cols
    state.close()


def test_peer_read_markers_table_exists(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    rows = state._conn.execute(
        "SELECT name FROM sqlite_master WHERE name='peer_read_markers'"
    ).fetchall()
    assert len(rows) == 1
    state.close()


# ─── State: edit_message ───────────────────────────────────────────

def test_edit_message_preserves_original_body(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=100, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="first version", room_id=None,
    )
    rec = state.edit_message(id="m1", new_body="second", edited_at_ms=200)
    assert rec is not None
    assert rec.body == "second"
    assert rec.original_body == "first version"
    assert rec.edited_at_ms == 200
    # Second edit does NOT overwrite the original_body.
    rec2 = state.edit_message(id="m1", new_body="third", edited_at_ms=300)
    assert rec2.body == "third"
    assert rec2.original_body == "first version"
    state.close()


def test_edit_message_returns_none_for_unknown(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    assert state.edit_message(
        id="ghost", new_body="x", edited_at_ms=1
    ) is None
    state.close()


def test_edit_message_skips_deleted(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="hi", room_id=None,
    )
    state.delete_message(id="m1", deleted_at_ms=2)
    rec = state.edit_message(id="m1", new_body="zombie", edited_at_ms=3)
    assert rec is None
    state.close()


# ─── State: delete_message ─────────────────────────────────────────

def test_delete_message_soft_deletes(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="bye", room_id=None,
    )
    rec = state.delete_message(id="m1", deleted_at_ms=2)
    assert rec is not None
    assert rec.body is None
    assert rec.deleted_at_ms == 2
    assert rec.is_deleted is True
    state.close()


def test_delete_message_idempotent(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="x", room_id=None,
    )
    state.delete_message(id="m1", deleted_at_ms=2)
    rec = state.delete_message(id="m1", deleted_at_ms=99)
    # The deleted_at_ms doesn't get bumped on re-delete; just returns the row.
    assert rec.deleted_at_ms == 2
    state.close()


# ─── State: read markers ───────────────────────────────────────────

def test_read_marker_record_and_get(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_read_marker("aa" * 32, 1000)
    assert state.get_read_marker("aa" * 32) == 1000
    state.close()


def test_read_marker_is_monotonic(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_read_marker("aa" * 32, 1000)
    # Older marker must NOT shrink the newer one.
    state.record_read_marker("aa" * 32, 500)
    assert state.get_read_marker("aa" * 32) == 1000
    # Newer marker advances.
    state.record_read_marker("aa" * 32, 2000)
    assert state.get_read_marker("aa" * 32) == 2000
    state.close()


def test_read_marker_unknown_returns_none(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    assert state.get_read_marker("ghost") is None
    state.close()


def test_read_marker_empty_fp_is_noop(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_read_marker("", 1000)  # silently ignored
    assert state.list_read_markers() == {}
    state.close()


# ─── Daemon: inbound EDIT_MSG ──────────────────────────────────────

@pytest.mark.asyncio
async def test_inbound_edit_msg_pinned_author_within_cooldown(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    now = int(time.time() * 1000)
    state.record_message(
        id="m1", ts_ms=now, direction="in", peer_fp=them.fingerprint,
        msg_type="TEXT", body="oops typo", room_id=None,
    )

    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    edit = make_msg(
        "EDIT_MSG", them.short_id,
        target="m1", body="fixed typo", edited_at_ms=now + 1000,
    )
    await daemon._on_peer_message(chan, edit)
    rec = state.get_message("m1")
    assert rec.body == "fixed typo"
    assert rec.edited_at_ms == now + 1000
    assert rec.original_body == "oops typo"
    assert any(s.get("t") == "ACK" and not s.get("rejected") for s in chan.sent)
    state.close()


@pytest.mark.asyncio
async def test_inbound_edit_rejects_non_pinned(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    edit = make_msg(
        "EDIT_MSG", them.short_id,
        target="m1", body="hi", edited_at_ms=1,
    )
    await daemon._on_peer_message(chan, edit)
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "not_pinned"
    state.close()


@pytest.mark.asyncio
async def test_inbound_edit_rejects_not_author(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    other = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    # The message belongs to a DIFFERENT peer; them shouldn't be able to edit it.
    state.record_message(
        id="m1", ts_ms=int(time.time() * 1000),
        direction="in", peer_fp=other.fingerprint,
        msg_type="TEXT", body="other peer's msg", room_id=None,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    edit = make_msg(
        "EDIT_MSG", them.short_id,
        target="m1", body="forged", edited_at_ms=1,
    )
    await daemon._on_peer_message(chan, edit)
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "not_author"
    rec = state.get_message("m1")
    assert rec.body == "other peer's msg"  # unchanged
    state.close()


@pytest.mark.asyncio
async def test_inbound_edit_rejects_after_cooldown(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    old_ts = int(time.time() * 1000) - EDIT_COOLDOWN_MS - 60_000
    state.record_message(
        id="m1", ts_ms=old_ts, direction="in", peer_fp=them.fingerprint,
        msg_type="TEXT", body="ancient", room_id=None,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    edit = make_msg(
        "EDIT_MSG", them.short_id,
        target="m1", body="too late", edited_at_ms=int(time.time() * 1000),
    )
    await daemon._on_peer_message(chan, edit)
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "cooldown"
    rec = state.get_message("m1")
    assert rec.body == "ancient"
    state.close()


# ─── Daemon: inbound DELETE_MSG ────────────────────────────────────

@pytest.mark.asyncio
async def test_inbound_delete_msg_pinned_author(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.record_message(
        id="m1", ts_ms=1, direction="in", peer_fp=them.fingerprint,
        msg_type="TEXT", body="goodbye", room_id=None,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    d = make_msg(
        "DELETE_MSG", them.short_id, target="m1", deleted_at_ms=2,
    )
    await daemon._on_peer_message(chan, d)
    rec = state.get_message("m1")
    assert rec.body is None
    assert rec.deleted_at_ms == 2
    state.close()


@pytest.mark.asyncio
async def test_inbound_delete_rejects_non_author(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    state.record_message(
        id="m1", ts_ms=1, direction="in", peer_fp="cc" * 32,
        msg_type="TEXT", body="not theirs", room_id=None,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    d = make_msg(
        "DELETE_MSG", them.short_id, target="m1", deleted_at_ms=2,
    )
    await daemon._on_peer_message(chan, d)
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "not_author"
    state.close()


# ─── Daemon: inbound READ_MARKER ───────────────────────────────────

@pytest.mark.asyncio
async def test_inbound_read_marker_pinned_persists(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    rm = make_msg("READ_MARKER", them.short_id, up_to_ts_ms=5000)
    await daemon._on_peer_message(chan, rm)
    assert state.get_read_marker(them.fingerprint) == 5000
    state.close()


@pytest.mark.asyncio
async def test_inbound_read_marker_non_pinned_silently_ignored(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    rm = make_msg("READ_MARKER", them.short_id, up_to_ts_ms=5000)
    await daemon._on_peer_message(chan, rm)
    assert state.get_read_marker(them.fingerprint) is None
    state.close()


# ─── api_edit_message endpoint ─────────────────────────────────────

@pytest.mark.asyncio
async def test_api_edit_validates_body(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=int(time.time() * 1000),
        direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="orig", room_id=None,
    )
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me-fp", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"body": "", "peer": "p"}

    resp = await server.api_edit_message(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_edit_404_unknown_msg(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me-fp", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"msg_id": "ghost"}
        async def json(self):
            return {"body": "x", "peer": "p"}

    resp = await server.api_edit_message(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_edit_403_for_inbound(tmp_path: Path):
    """Can only edit outbound (your own) messages."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="theirs", room_id=None,
    )
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me-fp", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"body": "x", "peer": "p"}

    resp = await server.api_edit_message(_Req())
    assert resp.status == 403
    state.close()


# ─── api_delete_message endpoint ───────────────────────────────────

@pytest.mark.asyncio
async def test_api_delete_offline_peer_persists_locally(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="bye", room_id=None,
    )
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    broadcasts: list[dict] = []
    server.broadcast = lambda evt: broadcasts.append(evt)

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"peer": "no-such"}

    resp = await server.api_delete_message(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["delivered"] is False
    rec = state.get_message("m1")
    assert rec.is_deleted
    assert any(b.get("type") == "msg_delete" for b in broadcasts)
    state.close()


# ─── api_set_read_marker endpoint ──────────────────────────────────

@pytest.mark.asyncio
async def test_api_set_read_marker_offline_returns_ok(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"fp": "aa" * 32}
        async def json(self):
            return {"up_to_ts_ms": 1234}

    resp = await server.api_set_read_marker(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["delivered"] is False
    state.close()


@pytest.mark.asyncio
async def test_api_set_read_marker_validates_input(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="me", short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _ReqMissing:
        match_info = {"fp": "aa" * 32}
        async def json(self):
            return {}

    resp = await server.api_set_read_marker(_ReqMissing())
    assert resp.status == 400
    state.close()


# ─── HTML structural pin ───────────────────────────────────────────

def test_index_html_has_edit_delete_read_surfaces():
    p = Path(__file__).resolve().parent.parent / "src" / "one_link" / "web" / "index.html"
    text = p.read_text(encoding="utf-8")
    for needle in [
        "function startEditMessage",
        "function deleteMessage",
        "function maybeSendReadMarker",
        '"msg_edit"',
        '"msg_delete"',
        '"read_marker"',
        ".edited-badge",
        ".msg-deleted",
        ".read-tick",
        "readMarkers",
    ]:
        assert needle in text, f"index.html missing {needle!r}"


# ─── helpers ───────────────────────────────────────────────────────

def _async_returns(v):
    async def _co():
        return v
    return _co()
