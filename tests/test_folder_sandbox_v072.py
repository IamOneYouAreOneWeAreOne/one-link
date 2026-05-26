"""v0.7.2 folder sandbox capability tests (audit finding B).

Pin the contract:
  - Each folder gets a stable `root_id` UUID at creation.
  - Sandbox policy fields (max_file_bytes, ignored_patterns,
    conflict_policy) round-trip via add_folder + setters.
  - Path-traversal attempts ('..', absolute paths, 'C:/...') get
    rejected and audited.
  - Pattern-match deny-list rejects `*.env`, `.git/*` etc. with audit.
  - Size cap rejects oversized entries with audit.
  - Accepted writes/deletes also produce audit rows.
  - /api/folders/{name}/policy + /audit endpoints work end-to-end.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


# ─── State: add_folder + policy fields ─────────────────────────────

def test_add_folder_assigns_root_id(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="docs", local_path=str(tmp_path / "docs"), shared_with=[],
    )
    f = state.get_folder("docs")
    assert f["root_id"]
    # Stable UUID hex shape: 32 chars.
    assert len(f["root_id"]) == 32
    assert f["max_file_bytes"] is None
    assert f["ignored_patterns"] == []
    assert f["conflict_policy"] == "latest-wins"
    state.close()


def test_add_folder_with_explicit_policy(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="photos",
        local_path=str(tmp_path / "photos"),
        shared_with=[],
        max_file_bytes=10_000_000,
        ignored_patterns=["*.env", ".git/*", "secrets.json"],
        conflict_policy="local-priority",
    )
    f = state.get_folder("photos")
    assert f["max_file_bytes"] == 10_000_000
    assert f["ignored_patterns"] == ["*.env", ".git/*", "secrets.json"]
    assert f["conflict_policy"] == "local-priority"
    state.close()


def test_add_folder_root_id_is_unique_per_folder(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="a", local_path=str(tmp_path / "a"), shared_with=[])
    state.add_folder(name="b", local_path=str(tmp_path / "b"), shared_with=[])
    fa = state.get_folder("a")
    fb = state.get_folder("b")
    assert fa["root_id"] != fb["root_id"]
    state.close()


def test_add_folder_rejects_invalid_conflict_policy(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    with pytest.raises(ValueError, match="conflict_policy"):
        state.add_folder(
            name="x", local_path=str(tmp_path / "x"), shared_with=[],
            conflict_policy="bogus",
        )
    state.close()


# ─── Policy setters ────────────────────────────────────────────────

def test_set_folder_max_file_bytes_roundtrip(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    state.set_folder_max_file_bytes("x", 5_000)
    assert state.get_folder("x")["max_file_bytes"] == 5_000
    state.set_folder_max_file_bytes("x", None)
    assert state.get_folder("x")["max_file_bytes"] is None
    state.close()


def test_set_folder_ignored_patterns_roundtrip(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    state.set_folder_ignored_patterns("x", ["*.tmp", "node_modules/*"])
    assert state.get_folder("x")["ignored_patterns"] == ["*.tmp", "node_modules/*"]
    state.set_folder_ignored_patterns("x", [])
    assert state.get_folder("x")["ignored_patterns"] == []
    state.close()


def test_set_folder_conflict_policy_validates(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    state.set_folder_conflict_policy("x", "peer-priority")
    assert state.get_folder("x")["conflict_policy"] == "peer-priority"
    with pytest.raises(ValueError):
        state.set_folder_conflict_policy("x", "free-for-all")
    state.close()


def test_policy_setters_404_unknown_folder(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    with pytest.raises(KeyError):
        state.set_folder_max_file_bytes("ghost", 100)
    with pytest.raises(KeyError):
        state.set_folder_ignored_patterns("ghost", [])
    with pytest.raises(KeyError):
        state.set_folder_conflict_policy("ghost", "latest-wins")
    state.close()


# ─── Pattern matcher ───────────────────────────────────────────────

def test_folder_path_matches_ignored_glob():
    assert State.folder_path_matches_ignored("config.env", ["*.env"]) is True
    assert State.folder_path_matches_ignored("nested/secrets.json", ["secrets.json"]) is True
    assert State.folder_path_matches_ignored(".git/HEAD", [".git/*"]) is True
    assert State.folder_path_matches_ignored("notes.txt", ["*.env"]) is False


def test_folder_path_matches_handles_windows_separators():
    assert State.folder_path_matches_ignored(
        r"sub\dir\file.env", ["*.env"]
    ) is True


def test_folder_path_matches_empty_patterns_returns_false():
    assert State.folder_path_matches_ignored("anything", []) is False


# ─── Audit log ─────────────────────────────────────────────────────

def test_record_and_list_folder_audit(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    fp = "aa" * 32
    state.record_folder_audit_event(
        folder_name="x", peer_fp=fp,
        action="write", file_path="hello.txt",
        blob_hash="bb" * 32, size=12,
    )
    state.record_folder_audit_event(
        folder_name="x", peer_fp=fp,
        action="reject_pattern", file_path=".env",
        size=20, note="match: *.env",
    )
    events = state.list_folder_audit(folder_name="x")
    assert len(events) == 2
    # Order: most recent first.
    assert events[0]["action"] == "reject_pattern"
    assert events[1]["action"] == "write"
    assert events[0]["root_id"] == state.get_folder("x")["root_id"]
    state.close()


def test_list_folder_audit_filters_by_action(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    fp = "aa" * 32
    for action, path in [
        ("write", "a.txt"), ("write", "b.txt"),
        ("reject_size", "huge.bin"),
    ]:
        state.record_folder_audit_event(
            folder_name="x", peer_fp=fp, action=action, file_path=path,
        )

    rejects = state.list_folder_audit(folder_name="x", actions=["reject_size"])
    assert len(rejects) == 1
    assert rejects[0]["action"] == "reject_size"

    writes = state.list_folder_audit(folder_name="x", actions=["write"])
    assert len(writes) == 2
    state.close()


def test_list_folder_audit_filters_by_peer(tmp_path: Path):
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    fp_a = "aa" * 32
    fp_b = "bb" * 32
    state.record_folder_audit_event(
        folder_name="x", peer_fp=fp_a, action="write", file_path="a.txt",
    )
    state.record_folder_audit_event(
        folder_name="x", peer_fp=fp_b, action="write", file_path="b.txt",
    )
    only_a = state.list_folder_audit(folder_name="x", peer_fp=fp_a)
    assert len(only_a) == 1
    assert only_a[0]["peer_fp"] == fp_a
    state.close()


# ─── Daemon._sandbox_filter_manifest_entries ───────────────────────

def test_sandbox_filter_passes_clean_entries(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    entries = [
        {"file_path": "a.txt", "blob_hash": "bb" * 32, "size": 100},
        {"file_path": "sub/b.bin", "blob_hash": "cc" * 32, "size": 200},
    ]
    kept = daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=entries,
    )
    assert len(kept) == 2
    audit = state.list_folder_audit(folder_name="x")
    assert {e["action"] for e in audit} == {"write"}
    assert len(audit) == 2
    state.close()


def test_sandbox_filter_rejects_path_traversal(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    bad = [
        {"file_path": "../escape.txt", "blob_hash": "bb" * 32, "size": 1},
        {"file_path": "/etc/passwd", "blob_hash": "bb" * 32, "size": 1},
        {"file_path": "C:/Windows/System32/evil.dll", "blob_hash": "bb" * 32, "size": 1},
        {"file_path": "ok/../hidden", "blob_hash": "bb" * 32, "size": 1},
    ]
    kept = daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=bad,
    )
    assert kept == []
    audit = state.list_folder_audit(folder_name="x")
    assert all(e["action"] == "reject_traversal" for e in audit)
    assert len(audit) == 4
    state.close()


def test_sandbox_filter_rejects_empty_path(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    bad = [{"file_path": "", "blob_hash": "bb" * 32, "size": 1}]
    kept = daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=bad,
    )
    assert kept == []
    state.close()


def test_sandbox_filter_rejects_pattern_matches(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="x", local_path=str(tmp_path / "x"),
        shared_with=[],
        ignored_patterns=["*.env", ".git/*", "secrets.json"],
    )
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    entries = [
        {"file_path": "config.env", "blob_hash": "bb" * 32, "size": 50},
        {"file_path": ".git/HEAD", "blob_hash": "bb" * 32, "size": 50},
        {"file_path": "secrets.json", "blob_hash": "bb" * 32, "size": 50},
        {"file_path": "ok.txt", "blob_hash": "bb" * 32, "size": 50},
    ]
    kept = daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=entries,
    )
    assert [e["file_path"] for e in kept] == ["ok.txt"]
    audit = state.list_folder_audit(folder_name="x")
    rejects = [e for e in audit if e["action"] == "reject_pattern"]
    assert len(rejects) == 3
    state.close()


def test_sandbox_filter_ignores_max_file_bytes_after_v021(tmp_path: Path):
    """v0.21.x product decision: One Link does NOT impose a file
    size limit. Even when a folder row still has max_file_bytes set
    (e.g. left over from an older client), the daemon must accept
    every entry regardless of size — zero ``reject_size`` audit rows."""
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="x", local_path=str(tmp_path / "x"), shared_with=[],
        # Legacy cap still on the row; daemon must ignore it.
        max_file_bytes=1_000,
    )
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    entries = [
        {"file_path": "small.txt", "blob_hash": "bb" * 32, "size": 500},
        {"file_path": "huge.bin", "blob_hash": "bb" * 32, "size": 10_000_000_000},
    ]
    kept = daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=entries,
    )
    # Both kept — no size cap enforced.
    assert [e["file_path"] for e in kept] == ["small.txt", "huge.bin"]
    audit = state.list_folder_audit(folder_name="x")
    rejects = [e for e in audit if e["action"] == "reject_size"]
    assert len(rejects) == 0, (
        f"v0.21.x must not produce reject_size rows; got {rejects}"
    )
    state.close()


def test_sandbox_filter_audits_deletes_separately(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = Daemon(me)
    daemon.state = state

    folder = state.get_folder("x")
    fp = "cc" * 32
    entries = [
        {"file_path": "kept.txt", "blob_hash": "bb" * 32, "size": 10},
        {"file_path": "tomb.txt", "blob_hash": None, "size": 0},
    ]
    daemon._sandbox_filter_manifest_entries(
        folder=folder, peer_fp=fp, entries=entries,
    )
    audit = state.list_folder_audit(folder_name="x")
    actions = {e["action"] for e in audit}
    assert "write" in actions and "delete" in actions
    state.close()


# ─── Server endpoints ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_set_folder_policy_max_file_bytes(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])

    daemon = SimpleNamespace(
        state=state, folder_engine=SimpleNamespace(),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "x"}
        async def json(self):
            return {"max_file_bytes": 5000}

    resp = await server.api_set_folder_policy(_Req())
    body = json.loads(resp.text)
    assert body["ok"] is True
    assert body["folder"]["max_file_bytes"] == 5000
    state.close()


@pytest.mark.asyncio
async def test_api_set_folder_policy_rejects_negative_size(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = SimpleNamespace(
        state=state, folder_engine=SimpleNamespace(),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "x"}
        async def json(self):
            return {"max_file_bytes": -1}

    resp = await server.api_set_folder_policy(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_set_folder_policy_404_unknown_folder(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state, folder_engine=SimpleNamespace(),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "ghost"}
        async def json(self):
            return {"max_file_bytes": 100}

    resp = await server.api_set_folder_policy(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_set_folder_policy_ignored_patterns(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = SimpleNamespace(
        state=state, folder_engine=SimpleNamespace(),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "x"}
        async def json(self):
            return {"ignored_patterns": ["*.env", "node_modules/*"]}

    resp = await server.api_set_folder_policy(_Req())
    body = json.loads(resp.text)
    assert body["folder"]["ignored_patterns"] == ["*.env", "node_modules/*"]
    state.close()


@pytest.mark.asyncio
async def test_api_set_folder_policy_invalid_conflict_policy(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    daemon = SimpleNamespace(
        state=state, folder_engine=SimpleNamespace(),
    )
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "x"}
        async def json(self):
            return {"conflict_policy": "magic"}

    resp = await server.api_set_folder_policy(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_folder_audit_returns_events(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    state.add_folder(name="x", local_path=str(tmp_path / "x"), shared_with=[])
    fp = "cc" * 32
    state.record_folder_audit_event(
        folder_name="x", peer_fp=fp,
        action="write", file_path="ok.txt", size=10,
    )
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "x"}
        query: dict = {}

    resp = await server.api_folder_audit(_Req())
    body = json.loads(resp.text)
    assert body["folder"] == "x"
    assert body["root_id"] == state.get_folder("x")["root_id"]
    assert len(body["events"]) == 1
    state.close()


@pytest.mark.asyncio
async def test_api_folder_audit_404_unknown(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info = {"name": "ghost"}
        query: dict = {}

    resp = await server.api_folder_audit(_Req())
    assert resp.status == 404
    state.close()


# ─── Migration: existing folders get backfilled root_id ────────────

def test_migration_backfills_root_id_for_existing_folders(tmp_path: Path):
    """Open a State, drop a folder row that pre-dates v0.7.2 (no
    root_id), close, re-open. The migration should backfill root_id
    via PRAGMA-introspected ALTER + UPDATE."""
    db_path = tmp_path / "s.db"
    state = State(db_path=db_path)
    # Simulate a pre-v0.7.2 row by clearing root_id back to NULL.
    state.add_folder(name="legacy", local_path=str(tmp_path / "l"), shared_with=[])
    with state._write_lock:
        state._conn.execute("UPDATE folders SET root_id = NULL WHERE name = 'legacy'")
    state.close()

    state2 = State(db_path=db_path)
    f = state2.get_folder("legacy")
    assert f["root_id"]
    assert len(f["root_id"]) == 32
    state2.close()
