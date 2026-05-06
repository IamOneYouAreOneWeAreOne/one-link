"""State-layer tests for v0.6.2 group persistence.

Covers the new tables (groups, group_events, group_sender_chains,
group_messages) and their helpers. The daemon-level integration of
these into the wire protocol is tested in test_groups_wire.py."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ─── group_events ──────────────────────────────────────────────────

def test_group_event_upsert_idempotent(state: State):
    gid = b"\xaa" * 16
    wire = {"v": "OL-GROUP-1", "kind": "create", "name": "Test"}
    inserted_first = state.upsert_group_event(
        group_id=gid, event_id="evt1", timestamp_ms=1, wire_dict=wire,
    )
    inserted_again = state.upsert_group_event(
        group_id=gid, event_id="evt1", timestamp_ms=1, wire_dict=wire,
    )
    assert inserted_first is True
    assert inserted_again is False


def test_group_events_listed_in_order(state: State):
    gid = b"\xaa" * 16
    state.upsert_group_event(
        group_id=gid, event_id="b", timestamp_ms=20, wire_dict={"x": 2},
    )
    state.upsert_group_event(
        group_id=gid, event_id="a", timestamp_ms=10, wire_dict={"x": 1},
    )
    state.upsert_group_event(
        group_id=gid, event_id="c", timestamp_ms=30, wire_dict={"x": 3},
    )
    out = state.list_group_events(gid)
    assert [d["x"] for d in out] == [1, 2, 3]


def test_list_group_events_empty_when_no_group(state: State):
    assert state.list_group_events(b"\xff" * 16) == []


# ─── group meta ────────────────────────────────────────────────────

def test_upsert_group_meta_round_trip(state: State):
    gid = b"\xaa" * 16
    state.upsert_group_meta(
        group_id=gid, name="Family", created_ms=1000, state_hash="hashv1",
    )
    meta = state.get_group_meta(gid)
    assert meta is not None
    assert meta["group_id"] == gid
    assert meta["name"] == "Family"
    assert meta["created_ms"] == 1000
    assert meta["state_hash"] == "hashv1"


def test_upsert_group_meta_overwrites_name_and_hash(state: State):
    gid = b"\xaa" * 16
    state.upsert_group_meta(
        group_id=gid, name="Old", created_ms=1000, state_hash="h1",
    )
    state.upsert_group_meta(
        group_id=gid, name="New", created_ms=1000, state_hash="h2",
    )
    meta = state.get_group_meta(gid)
    assert meta["name"] == "New"
    assert meta["state_hash"] == "h2"


def test_list_group_ids(state: State):
    state.upsert_group_meta(
        group_id=b"\x01" * 16, name="A", created_ms=1, state_hash="",
    )
    state.upsert_group_meta(
        group_id=b"\x02" * 16, name="B", created_ms=2, state_hash="",
    )
    ids = state.list_group_ids()
    assert b"\x01" * 16 in ids
    assert b"\x02" * 16 in ids


# ─── sender chains ─────────────────────────────────────────────────

def test_upsert_sender_chain_round_trip(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    key = b"\xcc" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=1,
        chain_key=key, counter=0,
    )
    got = state.get_sender_chain(group_id=gid, sender_pub=pub, direction="out")
    assert got is not None
    assert got["epoch"] == 1
    assert got["chain_key"] == key
    assert got["counter"] == 0


def test_upsert_sender_chain_advance_overwrites_counter(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=1,
        chain_key=b"\x00" * 32, counter=0,
    )
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=1,
        chain_key=b"\x01" * 32, counter=5,
    )
    got = state.get_sender_chain(group_id=gid, sender_pub=pub, direction="out")
    assert got["counter"] == 5
    assert got["chain_key"] == b"\x01" * 32


def test_get_sender_chain_returns_highest_epoch_when_unspecified(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=1,
        chain_key=b"\x01" * 32, counter=0,
    )
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=3,
        chain_key=b"\x03" * 32, counter=0,
    )
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=2,
        chain_key=b"\x02" * 32, counter=0,
    )
    got = state.get_sender_chain(group_id=gid, sender_pub=pub, direction="out")
    assert got["epoch"] == 3
    assert got["chain_key"] == b"\x03" * 32


def test_get_sender_chain_specific_epoch(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="in", epoch=1,
        chain_key=b"\x01" * 32, counter=0,
    )
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="in", epoch=2,
        chain_key=b"\x02" * 32, counter=0,
    )
    got = state.get_sender_chain(
        group_id=gid, sender_pub=pub, direction="in", epoch=1,
    )
    assert got is not None
    assert got["epoch"] == 1
    assert got["chain_key"] == b"\x01" * 32


def test_sender_chain_in_and_out_are_separate(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="out", epoch=1,
        chain_key=b"\x01" * 32, counter=0,
    )
    state.upsert_sender_chain(
        group_id=gid, sender_pub=pub, direction="in", epoch=1,
        chain_key=b"\x02" * 32, counter=0,
    )
    out = state.get_sender_chain(
        group_id=gid, sender_pub=pub, direction="out",
    )
    inn = state.get_sender_chain(
        group_id=gid, sender_pub=pub, direction="in",
    )
    assert out["chain_key"] == b"\x01" * 32
    assert inn["chain_key"] == b"\x02" * 32


def test_upsert_sender_chain_validates_input(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    with pytest.raises(ValueError, match="direction"):
        state.upsert_sender_chain(
            group_id=gid, sender_pub=pub, direction="weird", epoch=1,
            chain_key=b"\x00" * 32, counter=0,
        )
    with pytest.raises(ValueError, match="chain_key"):
        state.upsert_sender_chain(
            group_id=gid, sender_pub=pub, direction="out", epoch=1,
            chain_key=b"\x00" * 16, counter=0,
        )
    with pytest.raises(ValueError, match="sender_pub"):
        state.upsert_sender_chain(
            group_id=gid, sender_pub=b"\x00" * 16, direction="out", epoch=1,
            chain_key=b"\x00" * 32, counter=0,
        )
    with pytest.raises(ValueError, match="group_id"):
        state.upsert_sender_chain(
            group_id=b"\x00" * 8, sender_pub=pub, direction="out", epoch=1,
            chain_key=b"\x00" * 32, counter=0,
        )


# ─── group messages ────────────────────────────────────────────────

def test_insert_and_recent_group_messages(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    for i in range(5):
        state.insert_group_message(
            id=f"msg{i}", group_id=gid, sender_pub=pub,
            epoch=1, counter=i, direction="in",
            body=f"hello {i}", ts_ms=1000 + i,
        )
    out = state.recent_group_messages(group_id=gid, limit=10)
    # Returned newest-first.
    assert [m["body"] for m in out] == ["hello 4", "hello 3", "hello 2", "hello 1", "hello 0"]


def test_insert_group_message_idempotent_by_id(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.insert_group_message(
        id="msg1", group_id=gid, sender_pub=pub,
        epoch=1, counter=0, direction="in", body="first", ts_ms=1,
    )
    # Same id, different body. INSERT OR IGNORE keeps the first.
    state.insert_group_message(
        id="msg1", group_id=gid, sender_pub=pub,
        epoch=1, counter=0, direction="in", body="should be ignored", ts_ms=2,
    )
    out = state.recent_group_messages(group_id=gid, limit=10)
    assert len(out) == 1
    assert out[0]["body"] == "first"


def test_recent_group_messages_filters_by_group(state: State):
    gid_a = b"\xaa" * 16
    gid_b = b"\xbb" * 16
    pub = b"\xcc" * 32
    state.insert_group_message(
        id="m1", group_id=gid_a, sender_pub=pub,
        epoch=1, counter=0, direction="in", body="A", ts_ms=1,
    )
    state.insert_group_message(
        id="m2", group_id=gid_b, sender_pub=pub,
        epoch=1, counter=0, direction="in", body="B", ts_ms=2,
    )
    a_msgs = state.recent_group_messages(group_id=gid_a)
    b_msgs = state.recent_group_messages(group_id=gid_b)
    assert [m["body"] for m in a_msgs] == ["A"]
    assert [m["body"] for m in b_msgs] == ["B"]
