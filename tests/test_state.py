"""Persistence layer (state.py) tests — sqlite + FTS5 + CRUD."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import identity_dag as idag
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
    assert state.folder_peer_allows("docs", "aa" * 32, "push")
    assert state.folder_peer_allows("docs", "aa" * 32, "pull")
    state.remove_folder("docs")
    assert state.get_folder("docs") is None


def test_share_folder_with(state: State):
    state.add_folder(name="docs", local_path="/tmp/docs", shared_with=[])
    state.share_folder_with("docs", "aa" * 32)
    state.share_folder_with("docs", "aa" * 32)  # idempotent
    state.share_folder_with("docs", "bb" * 32)
    members = state.get_folder("docs")["shared_with"]
    assert sorted(members) == sorted(["aa" * 32, "bb" * 32])
    state.set_folder_peer_permission("docs", "aa" * 32, "push")
    assert state.folder_peer_allows("docs", "aa" * 32, "push")
    assert not state.folder_peer_allows("docs", "aa" * 32, "pull")
    state.unshare_folder_with("docs", "aa" * 32)
    assert state.get_folder("docs")["shared_with"] == ["bb" * 32]
    assert state.get_folder_peer_permission("docs", "aa" * 32) is None


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


def test_route_memory_roundtrips(state: State):
    state.upsert_route_memory(
        peer_fp="aa" * 32,
        route="lan",
        attempts=5,
        successes=4,
        failures=1,
        score=123.5,
        latency_ms=6.0,
        bandwidth_bps=750_000_000.0,
        metadata={"source": "test"},
    )

    rows = state.list_route_memory("aa" * 32)

    assert rows[0]["route"] == "lan"
    assert rows[0]["attempts"] == 5
    assert rows[0]["successes"] == 4
    assert rows[0]["failures"] == 1
    assert rows[0]["latency_ms"] == 6.0
    assert rows[0]["bandwidth_bps"] == 750_000_000.0
    assert rows[0]["metadata"]["source"] == "test"


def test_route_candidates_roundtrip_rank_and_prune(state: State):
    fp = "ab" * 32
    state.upsert_route_candidate(
        peer_fp=fp,
        route="lan",
        transport="tcp",
        host="10.0.0.8",
        port=17117,
        source="signed_bootstrap",
        verified=False,
        expires_ms=10,
        metadata={"hint": "qr"},
    )
    state.observe_route_candidate(
        peer_fp=fp,
        route="lan",
        transport="tcp",
        host="10.0.0.8",
        port=17117,
        ok=True,
        source="endpoint_verify",
        verified=True,
        latency_ms=4.0,
        bandwidth_bps=900_000_000.0,
        expires_ms=9999999999999,
    )
    state.observe_route_candidate(
        peer_fp=fp,
        route="relay",
        transport="tcp",
        host="relay.example",
        port=443,
        ok=False,
        source="runtime",
        error="timeout",
    )

    rows = state.list_route_candidates(fp, verified_only=True)

    assert rows[0]["host"] == "10.0.0.8"
    assert rows[0]["verified"] is True
    assert rows[0]["successes"] == 1
    assert rows[0]["metadata"]["hint"] == "qr"
    assert state.prune_route_candidates(now_ms=11) == 0
    assert state.prune_route_candidates(now_ms=99999999999999) == 1


def _ed25519_pair():
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def test_self_mesh_device_presence_and_replay_persist(tmp_path: Path):
    db = tmp_path / "state.db"
    root_seed, root_pub = _ed25519_pair()
    _, phone_pub = _ed25519_pair()
    _, laptop_pub = _ed25519_pair()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=phone_pub,
        device_kind="phone-ios",
        added_ms=1000,
    )

    s1 = State(db_path=db)
    try:
        row = s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=phone_pub,
            device_kind="phone-ios",
            cert=cert,
            label="Phone",
            local=True,
            metadata={"source": "test"},
            added_ms=1000,
        )
        assert row["label"] == "Phone"
        assert row["local"] is True
        assert row["metadata"]["source"] == "test"

        s1.upsert_self_mesh_device(
            root_pub=root_pub,
            device_pub=laptop_pub,
            device_kind="laptop-windows",
            label="Laptop",
            revoked=True,
            added_ms=1000,
        )
        active = s1.list_self_mesh_devices(root_pub=root_pub, include_revoked=False)
        assert [d["device_pub"] for d in active] == [phone_pub]

        older = s1.upsert_self_mesh_presence(
            device_pub=phone_pub,
            state="awake",
            sequence=4,
            updated_ms=2000,
            network="wifi",
            battery_pct=90,
            free_bytes=123,
            route="self_wifi",
        )
        assert older["state"] == "awake"
        stale = s1.upsert_self_mesh_presence(
            device_pub=phone_pub,
            state="offline",
            sequence=3,
            updated_ms=9999,
            network="offline",
        )
        assert stale["state"] == "awake"

        assert s1.mark_remote_instruction_seen(
            command_id="cmd1",
            expires_ms=9000,
            action="pull_file_manifest",
            controller_device_pub=phone_pub,
            target_device_pub=laptop_pub,
            now_ms=3000,
        ) is True
        assert s1.mark_remote_instruction_seen(
            command_id="cmd1",
            expires_ms=9000,
            now_ms=3001,
        ) is False
    finally:
        s1.close()

    s2 = State(db_path=db)
    try:
        assert s2.schema_version() >= 18
        devices = s2.list_self_mesh_devices(root_pub=root_pub)
        assert {d["label"] for d in devices} == {"Phone", "Laptop"}
        presence = s2.list_self_mesh_presence()
        assert presence[0]["device_pub"] == phone_pub
        assert presence[0]["state"] == "awake"
    finally:
        s2.close()


def test_delete_setting(state: State):
    state.set_setting("k", "v")
    state.delete_setting("k")
    assert state.get_setting("k") is None
