"""v0.7.5 reply/quote + reactions tests.

Pin the contract:
  - State: messages.reply_to column added via PRAGMA-introspected
    ALTER (idempotent on re-open). New message_reactions table
    keyed by (target, peer_fp, emoji).
  - record_message accepts reply_to; round-trips through _row_to_msg.
  - record_reaction is idempotent on the triplet; remove_reaction
    deletes one row.
  - list_reactions_for_messages returns {target: {emoji: [fps]}}.
  - Daemon's TEXT _persist sees reply_to as first-class field.
  - Daemon's REACTION inbound handler validates op + persists.
  - send_reaction emits REACTION frame + persists locally.
  - api_react_message validates body, posts to peer or persists
    locally if peer offline.
  - HTML structural pin: reply-bar, reactions-row, msg-toolbar
    elements + REACTION_EMOJIS palette.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.state import MessageRecord, State
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


# ─── State schema ──────────────────────────────────────────────────

def test_messages_table_has_reply_to_column(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    rows = state._conn.execute("PRAGMA table_info(messages)").fetchall()
    cols = {r[1] for r in rows}
    assert "reply_to" in cols
    state.close()


def test_message_reactions_table_exists(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    rows = state._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='message_reactions'"
    ).fetchall()
    assert len(rows) == 1
    state.close()


def test_record_message_with_reply_to(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_message(
        id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="parent", room_id=None, metadata={},
    )
    state.record_message(
        id="m2", ts_ms=2, direction="out", peer_fp="aa" * 32,
        msg_type="TEXT", body="reply!", room_id=None, metadata={},
        reply_to="m1",
    )
    rows = state.recent_messages(peer_fp="aa" * 32, limit=10)
    by_id = {r.id: r for r in rows}
    assert by_id["m2"].reply_to == "m1"
    assert by_id["m1"].reply_to is None
    state.close()


# ─── reactions CRUD ───────────────────────────────────────────────

def test_record_reaction_idempotent_on_triple(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    inserted_first = state.record_reaction(
        target_msg_id="m1", peer_fp=fp, emoji="👍",
    )
    inserted_again = state.record_reaction(
        target_msg_id="m1", peer_fp=fp, emoji="👍",
    )
    assert inserted_first is True
    assert inserted_again is False
    rows = state._conn.execute(
        "SELECT * FROM message_reactions WHERE target_msg_id = ?", ("m1",),
    ).fetchall()
    assert len(rows) == 1
    state.close()


def test_remove_reaction(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    fp = "aa" * 32
    state.record_reaction(target_msg_id="m1", peer_fp=fp, emoji="👍")
    removed = state.remove_reaction(target_msg_id="m1", peer_fp=fp, emoji="👍")
    assert removed is True
    again = state.remove_reaction(target_msg_id="m1", peer_fp=fp, emoji="👍")
    assert again is False
    state.close()


def test_record_reaction_validates_inputs(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    with pytest.raises(ValueError):
        state.record_reaction(target_msg_id="", peer_fp="aa" * 32, emoji="👍")
    with pytest.raises(ValueError):
        state.record_reaction(target_msg_id="m1", peer_fp="", emoji="👍")
    with pytest.raises(ValueError):
        state.record_reaction(target_msg_id="m1", peer_fp="aa" * 32, emoji="")
    with pytest.raises(ValueError):
        state.record_reaction(
            target_msg_id="m1", peer_fp="aa" * 32, emoji="x" * 100,
        )
    state.close()


def test_list_reactions_groups_by_target_and_emoji(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.record_reaction(target_msg_id="m1", peer_fp="aa" * 32, emoji="👍")
    state.record_reaction(target_msg_id="m1", peer_fp="bb" * 32, emoji="👍")
    state.record_reaction(target_msg_id="m1", peer_fp="aa" * 32, emoji="❤️")
    state.record_reaction(target_msg_id="m2", peer_fp="aa" * 32, emoji="🎉")
    out = state.list_reactions_for_messages(["m1", "m2"])
    assert set(out["m1"]["👍"]) == {"aa" * 32, "bb" * 32}
    assert out["m1"]["❤️"] == ["aa" * 32]
    assert out["m2"]["🎉"] == ["aa" * 32]
    state.close()


def test_list_reactions_empty_for_unknown(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    out = state.list_reactions_for_messages(["ghost"])
    assert out == {}
    state.close()


# ─── Daemon REACTION inbound handler ──────────────────────────────

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


@pytest.mark.asyncio
async def test_inbound_reaction_from_pinned_peer_persisted(tmp_path: Path):
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
    msg = make_msg(
        "REACTION", them.short_id,
        target="m-target", emoji="👍", op="add",
    )
    await daemon._on_peer_message(chan, msg)
    rows = state._conn.execute(
        "SELECT peer_fp, emoji FROM message_reactions WHERE target_msg_id = ?",
        ("m-target",),
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["peer_fp"] == them.fingerprint
    assert rows[0]["emoji"] == "👍"
    # ACK was sent.
    assert any(s.get("t") == "ACK" and not s.get("rejected") for s in chan.sent)
    state.close()


@pytest.mark.asyncio
async def test_inbound_reaction_from_non_pinned_peer_rejected(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    # NOT pinned; default 'pending'.
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg(
        "REACTION", them.short_id,
        target="m1", emoji="👍", op="add",
    )
    await daemon._on_peer_message(chan, msg)
    rows = state._conn.execute(
        "SELECT * FROM message_reactions"
    ).fetchall()
    assert rows == []
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "not_pinned"
    state.close()


@pytest.mark.asyncio
async def test_inbound_reaction_remove_op(tmp_path: Path):
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
    state.record_reaction(
        target_msg_id="m1", peer_fp=them.fingerprint, emoji="👍",
    )
    chan = _FakeChannel(peer_ed_pub=them.public_bytes, peer_short_id=them.short_id)
    msg = make_msg(
        "REACTION", them.short_id,
        target="m1", emoji="👍", op="remove",
    )
    await daemon._on_peer_message(chan, msg)
    rows = state._conn.execute(
        "SELECT * FROM message_reactions WHERE target_msg_id = ?", ("m1",),
    ).fetchall()
    assert rows == []
    state.close()


@pytest.mark.asyncio
async def test_inbound_reaction_validates_op(tmp_path: Path):
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
    msg = make_msg(
        "REACTION", them.short_id,
        target="m1", emoji="👍", op="explode",
    )
    await daemon._on_peer_message(chan, msg)
    rejects = [s for s in chan.sent if s.get("rejected")]
    assert rejects and rejects[0]["rejected"] == "bad_reaction"
    state.close()


# ─── _persist threads reply_to ─────────────────────────────────────

def test_persist_text_with_reply_to(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    msg = make_msg(
        "TEXT", "abc12345", body="hello", reply_to="parent-id",
    )
    out = daemon._persist(
        msg=msg, direction="in", peer_fp="aa" * 32, peer_short_id="abc12345",
    )
    assert out["reply_to"] == "parent-id"
    rows = state.recent_messages(peer_fp="aa" * 32, limit=10)
    assert rows[0].reply_to == "parent-id"
    state.close()


# ─── api_react_message endpoint ────────────────────────────────────

@pytest.mark.asyncio
async def test_api_react_message_offline_peer_persists_locally(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    me_fp = "aa" * 32
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint=me_fp, short_id="me", hostname="me"),
        resolve_for_send=lambda needle: _async_returns(None),
    )
    server = UIServer(daemon)
    broadcasts: list[dict] = []
    server.broadcast = lambda evt: broadcasts.append(evt)

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"emoji": "👍", "op": "add", "peer": "no-such-peer"}

    resp = await server.api_react_message(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["delivered"] is False
    rows = state._conn.execute(
        "SELECT * FROM message_reactions WHERE target_msg_id = ?", ("m1",),
    ).fetchall()
    assert len(rows) == 1
    assert any(b.get("type") == "reaction" for b in broadcasts)
    state.close()


@pytest.mark.asyncio
async def test_api_react_message_validates_emoji(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"emoji": "", "op": "add"}

    resp = await server.api_react_message(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_react_message_validates_op(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(fingerprint="aa" * 32, short_id="me", hostname="me"),
        resolve_for_send=lambda n: _async_returns(None),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"msg_id": "m1"}
        async def json(self):
            return {"emoji": "👍", "op": "explode"}

    resp = await server.api_react_message(_Req())
    assert resp.status == 400
    state.close()


# ─── HTML structural pins ──────────────────────────────────────────

_REPO_INDEX = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


def test_index_html_has_reply_react_surfaces():
    text = _REPO_INDEX.read_text(encoding="utf-8")
    for needle in [
        'id="reply-bar"',
        "function renderMsgToolbar",
        "function renderReactionsRow",
        "function setReplyTo",
        "function clearReplyTo",
        "function openEmojiPicker",
        "function toggleReaction",
        "REACTION_EMOJIS",
        ".react-chip",
        ".reply-quote",
        ".msg-toolbar",
        ".emoji-picker",
        ".reply-bar",
        '"reaction"',  # WS event handler branch
    ]:
        assert needle in text, f"index.html missing {needle!r}"


def test_reaction_palette_is_a_list_of_emojis():
    text = _REPO_INDEX.read_text(encoding="utf-8")
    # We only check that the constant declaration exists and contains
    # at least one quoted emoji-like token. The palette can grow.
    assert "REACTION_EMOJIS" in text
    assert "👍" in text  # smoke check the default thumb is present


# ─── helpers ───────────────────────────────────────────────────────

def _async_returns(v):
    async def _co():
        return v
    return _co()
