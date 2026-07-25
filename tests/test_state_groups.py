"""State-layer tests for v0.6.2 group persistence.

Covers the new tables (groups, group_events, group_sender_chains,
group_messages) and their helpers. The daemon-level integration of
these into the wire protocol is tested in test_groups_wire.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from one_link import state as state_module
from one_link.state import MessageIdConflict, MessageQuotaExceeded, State


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


def test_group_event_upsert_rejects_id_collision(state: State):
    gid = b"\xaa" * 16
    state.upsert_group_event(
        group_id=gid, event_id="evt-conflict", timestamp_ms=1,
        wire_dict={"x": 1},
    )
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.upsert_group_event(
            group_id=gid, event_id="evt-conflict", timestamp_ms=1,
            wire_dict={"x": 2},
        )
    with pytest.raises(MessageIdConflict, match="reused for different content"):
        state.upsert_group_event(
            group_id=gid, event_id="evt-conflict", timestamp_ms=2,
            wire_dict={"x": 1},
        )


def test_group_event_quota_allows_exact_replay(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_GROUP_EVENTS_PER_GROUP", 1)
    first = dict(
        group_id=b"\xaa" * 16, event_id="evt-quota-1",
        timestamp_ms=1, wire_dict={"x": 1},
    )
    assert state.upsert_group_event(**first) is True
    assert state.upsert_group_event(**first) is False
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.upsert_group_event(
            **{**first, "event_id": "evt-quota-2", "timestamp_ms": 2},
        )


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


def test_group_message_quota_allows_replay_but_rejects_growth(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_GROUP_MESSAGES_PER_GROUP", 1)
    first = dict(
        id="group-quota-1", group_id=b"\xaa" * 16,
        sender_pub=b"\xbb" * 32, epoch=1, counter=0,
        direction="in", body="first", ts_ms=1,
    )
    assert state.insert_group_message(**first) is True
    assert state.insert_group_message(**first) is False
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.insert_group_message(
            **{**first, "id": "group-quota-2", "counter": 1, "ts_ms": 2},
        )


def test_group_edit_quota_counts_retained_original(
    state: State, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(state_module, "MAX_GROUP_BODY_BYTES_PER_GROUP", 8)
    state.insert_group_message(
        id="group-edit-quota-1", group_id=b"\xaa" * 16,
        sender_pub=b"\xbb" * 32, epoch=1, counter=0,
        direction="in", body="12345", ts_ms=1,
    )
    with pytest.raises(MessageQuotaExceeded, match="quota"):
        state.edit_group_message(
            id="group-edit-quota-1", new_body="6789", edited_at_ms=2,
        )
    rec = state.get_group_message("group-edit-quota-1")
    assert rec is not None and rec["body"] == "12345"
    assert rec["original_body"] is None


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


def test_insert_group_message_rejects_conflicting_id_reuse(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    state.insert_group_message(
        id="msg1", group_id=gid, sender_pub=pub,
        epoch=1, counter=0, direction="in", body="first", ts_ms=1,
    )
    # Idempotency applies only to an exact immutable replay. Silently
    # accepting different content under one id would acknowledge data loss.
    with pytest.raises(ValueError, match="reused for different content"):
        state.insert_group_message(
            id="msg1", group_id=gid, sender_pub=pub,
            epoch=1, counter=0, direction="in", body="should be ignored", ts_ms=2,
        )
    out = state.recent_group_messages(group_id=gid, limit=10)
    assert len(out) == 1
    assert out[0]["body"] == "first"


def test_insert_group_message_exact_replay_is_idempotent(state: State):
    gid = b"\xaa" * 16
    pub = b"\xbb" * 32
    kwargs = dict(
        id="group-replay-1", group_id=gid, sender_pub=pub,
        epoch=1, counter=7, direction="in", body="same", ts_ms=99,
    )
    assert state.insert_group_message(**kwargs) is True
    assert state.insert_group_message(**kwargs) is False


def test_group_ratchet_message_and_fanout_commit_atomically(state: State):
    gid = b"\x11" * 16
    sender = b"\x22" * 32
    old_key = b"\x33" * 32
    new_key = b"\x44" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=sender, direction="out", epoch=1,
        chain_key=old_key, counter=3,
    )
    result = state.commit_group_ratchet_boundary(
        group_id=gid, sender_pub=sender, direction="out", epoch=1,
        expected_chain_key=old_key, expected_counter=3,
        advanced_chain_key=new_key, advanced_counter=4,
        message={
            "id": "group-atomic-1", "counter": 3, "body": "hello",
            "reply_to": None, "ts_ms": 100,
        },
        outbox=[{
            "peer_fp": "aa" * 32,
            "msg_id": "group-atomic-1",
            "msg_body": {"t": "GROUP_MSG", "id": "group-atomic-1"},
            "msg_kind": "GROUP_MSG",
        }],
    )
    assert result["message_inserted"] is True
    assert result["outbox_ids"]["aa" * 32] > 0
    chain = state.get_sender_chain(
        group_id=gid, sender_pub=sender, direction="out", epoch=1,
    )
    assert chain and chain["counter"] == 4 and chain["chain_key"] == new_key
    assert state.get_group_message("group-atomic-1")["body"] == "hello"


def test_group_ratchet_boundary_rolls_back_every_row_on_outbox_failure(state: State):
    gid = b"\x55" * 16
    sender = b"\x66" * 32
    old_key = b"\x77" * 32
    state.upsert_sender_chain(
        group_id=gid, sender_pub=sender, direction="in", epoch=1,
        chain_key=old_key, counter=0,
    )
    with pytest.raises(ValueError):
        state.commit_group_ratchet_boundary(
            group_id=gid, sender_pub=sender, direction="in", epoch=1,
            expected_chain_key=old_key, expected_counter=0,
            advanced_chain_key=b"\x88" * 32, advanced_counter=1,
            message={
                "id": "group-rollback-1", "counter": 0, "body": "hello",
                "reply_to": None, "ts_ms": 100,
            },
            outbox=[{
                "peer_fp": "aa" * 32,
                "msg_id": "group-rollback-1",
                "msg_body": {"not_finite": float("nan")},
            }],
        )
    chain = state.get_sender_chain(
        group_id=gid, sender_pub=sender, direction="in", epoch=1,
    )
    assert chain and chain["counter"] == 0 and chain["chain_key"] == old_key
    assert state.get_group_message("group-rollback-1") is None
    assert state.list_outbox(peer_fp="aa" * 32) == []


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
