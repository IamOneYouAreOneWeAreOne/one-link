"""Persistence layer (state.py) tests — sqlite + FTS5 + CRUD."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ───────── peers ──────────────────────────────────────────────────────

def test_upsert_new_peer(state: State):
    rec = state.upsert_peer(
        fingerprint="ab" * 32,
        short_id="abababab",
        pubkey=b"\x00" * 32,
        hostname="alice",
    )
    assert rec.fingerprint == "ab" * 32
    assert rec.short_id == "abababab"
    assert rec.hostname == "alice"
    assert rec.trust == "pending"
    assert rec.first_seen_ms == rec.last_seen_ms


def test_upsert_existing_peer_updates_last_seen(state: State):
    fp = "ab" * 32
    a = state.upsert_peer(fingerprint=fp, short_id="abababab", pubkey=b"\x01" * 32)
    time.sleep(0.01)
    b = state.upsert_peer(fingerprint=fp, short_id="abababab", pubkey=b"\x01" * 32)
    assert b.last_seen_ms >= a.last_seen_ms
    assert b.first_seen_ms == a.first_seen_ms


def test_upsert_does_not_clobber_trust(state: State):
    fp = "ab" * 32
    state.upsert_peer(fingerprint=fp, short_id="ab", pubkey=b"\x00" * 32)
    state.set_peer_trust(fp, "pinned")
    state.upsert_peer(fingerprint=fp, short_id="ab", pubkey=b"\x00" * 32)
    assert state.get_peer(fp).trust == "pinned"


def test_set_peer_trust_validates(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="aa", pubkey=b"\x00" * 32)
    with pytest.raises(ValueError):
        state.set_peer_trust("aa" * 32, "yolo")
    state.set_peer_trust("aa" * 32, "rejected")
    assert state.get_peer("aa" * 32).trust == "rejected"


def test_get_peer_by_short_id(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="alice123", pubkey=b"\x00" * 32)
    rec = state.get_peer_by_short_id("alice123")
    assert rec and rec.fingerprint == "aa" * 32


def test_list_peers_orders_by_last_seen(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    time.sleep(0.005)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    out = state.list_peers()
    assert [p.short_id for p in out] == ["b", "a"]


# ───────── messages ───────────────────────────────────────────────────

def test_record_and_fetch_message(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32)
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="aa" * 32,
        msg_type="TEXT", body="hello world", metadata={"short_id": "alice"},
    )
    out = state.recent_messages(limit=10)
    assert len(out) == 1
    assert out[0].id == "m1"
    assert out[0].body == "hello world"
    assert out[0].direction == "in"


def test_recent_messages_filters_by_peer(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="from a")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="bb" * 32,
                         msg_type="TEXT", body="from b")
    only_a = state.recent_messages(peer_fp="aa" * 32, limit=10)
    assert [m.body for m in only_a] == ["from a"]


def test_record_message_idempotent(state: State):
    """Recording the same id twice should not duplicate."""
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hi")
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hi")
    assert len(state.recent_messages(limit=10)) == 1


# ───────── FTS5 search ────────────────────────────────────────────────

def test_search_messages(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="the quick brown fox")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="lazy dog jumps")
    state.record_message(id="m3", ts_ms=3, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="quick bunny")
    out = state.search_messages("quick")
    bodies = sorted(m.body for m in out)
    assert bodies == ["quick bunny", "the quick brown fox"]


def test_search_messages_with_peer_filter(state: State):
    state.upsert_peer(fingerprint="aa" * 32, short_id="a", pubkey=b"\x00" * 32)
    state.upsert_peer(fingerprint="bb" * 32, short_id="b", pubkey=b"\x00" * 32)
    state.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                         msg_type="TEXT", body="hello")
    state.record_message(id="m2", ts_ms=2, direction="in", peer_fp="bb" * 32,
                         msg_type="TEXT", body="hello")
    out = state.search_messages("hello", peer_fp="aa" * 32)
    assert len(out) == 1
    assert out[0].peer_fp == "aa" * 32


# ───────── persistence across restart ─────────────────────────────────

def test_state_persists_across_close_and_reopen(tmp_path: Path):
    db = tmp_path / "state.db"
    s1 = State(db_path=db)
    s1.upsert_peer(fingerprint="aa" * 32, short_id="alice", pubkey=b"\x00" * 32)
    s1.set_peer_trust("aa" * 32, "pinned")
    s1.record_message(id="m1", ts_ms=1, direction="in", peer_fp="aa" * 32,
                      msg_type="TEXT", body="persistent hello")
    s1.close()

    s2 = State(db_path=db)
    try:
        rec = s2.get_peer("aa" * 32)
        assert rec is not None
        assert rec.trust == "pinned"
        msgs = s2.recent_messages(limit=10)
        assert len(msgs) == 1
        assert msgs[0].body == "persistent hello"
    finally:
        s2.close()


# ───────── rooms / folders / blobs (smoke) ────────────────────────────

def test_create_and_get_room(state: State):
    state.create_room(room_id="r1", name="Family", members=["aa" * 32, "bb" * 32])
    r = state.get_room("r1")
    assert r["name"] == "Family"
    assert "aa" * 32 in r["members"]


def test_room_name_uniqueness(state: State):
    state.create_room(room_id="r1", name="A", members=[])
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        state.create_room(room_id="r2", name="A", members=[])


def test_add_remove_folder(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=["aa" * 32])
    f = state.get_folder("docs")
    assert f["local_path"] == "/tmp/docs"
    state.remove_folder("docs")
    assert state.get_folder("docs") is None


def test_share_folder_with(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=[])
    state.share_folder_with("docs", "aa" * 32)
    state.share_folder_with("docs", "aa" * 32)  # idempotent
    state.share_folder_with("docs", "bb" * 32)
    members = state.get_folder("docs")["shared_with"]
    assert sorted(members) == sorted(["aa" * 32, "bb" * 32])


def test_manifest_upsert_and_list(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=[])
    state.upsert_manifest_entry(
        folder_name="docs",
        file_path="hello.txt",
        blob_hash="ab" * 32,
        size=11,
        mtime_ms=12345,
        vclock={"aa" * 32: 1},
    )
    out = state.list_manifest("docs")
    assert len(out) == 1
    assert out[0]["file_path"] == "hello.txt"
    assert out[0]["blob_hash"] == "ab" * 32


def test_blob_record(state: State):
    state.record_blob("ab" * 32, 1024)
    assert state.has_blob("ab" * 32)
    assert not state.has_blob("cd" * 32)


# ───────── settings (kv) ──────────────────────────────────────────────

def test_set_get_setting(state: State):
    assert state.get_setting("foo") is None
    assert state.get_setting("foo", "default") == "default"
    state.set_setting("foo", "bar")
    assert state.get_setting("foo") == "bar"


def test_setting_upsert(state: State):
    state.set_setting("color", "red")
    state.set_setting("color", "blue")
    assert state.get_setting("color") == "blue"


def test_all_settings(state: State):
    state.set_setting("a", "1")
    state.set_setting("b", "2")
    out = state.all_settings()
    assert out == {"a": "1", "b": "2"}


def test_delete_setting(state: State):
    state.set_setting("k", "v")
    state.delete_setting("k")
    assert state.get_setting("k") is None
