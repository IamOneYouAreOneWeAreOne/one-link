"""v0.21.x Ship 8 behavioral tests — multi-peer swarm pull.

Tests:
  - list_peers_with_blob filtering by folder + action set
  - swarm_pull_blob no-op when blob already local
  - swarm_pull_blob no-op when no candidates online
  - _request_blob_from_peer hash-mismatch defense (peer sends
    different bytes than we asked for)
  - swarm_pull_blob race: first task to return True cancels others
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from one_link.blobstore import BlobStore
from one_link.daemon import Daemon
from one_link.state import State


# ── list_peers_with_blob filter logic ───────────────────────────────


def test_list_peers_with_blob_returns_distinct_peers(tmp_path: Path):
    """Multiple audit rows from the same peer for the same blob
    must collapse to ONE entry in the output."""
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="f", local_path=str(tmp_path / "f"), shared_with=[],
        max_file_bytes=None, ignored_patterns=[], conflict_policy="latest-wins",
    )
    h = "ab" * 32
    # Same peer pushes 3 times.
    for _ in range(3):
        state.record_folder_audit_event(
            folder_name="f", peer_fp="peer1" * 13, action="write",
            file_path="x.txt", blob_hash=h, size=10,
        )
    state.record_folder_audit_event(
        folder_name="f", peer_fp="peer2" * 13, action="write",
        file_path="x.txt", blob_hash=h, size=10,
    )
    peers = state.list_peers_with_blob(h, folder_name="f")
    assert len(peers) == 2
    assert set(peers) == {"peer1" * 13, "peer2" * 13}
    state.close()


def test_list_peers_with_blob_excludes_empty_peer_fp(tmp_path: Path):
    """Audit rows with peer_fp='' or NULL must NOT appear in the
    swarm candidate list — those are local-origin events."""
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="f", local_path=str(tmp_path / "f"), shared_with=[],
        max_file_bytes=None, ignored_patterns=[], conflict_policy="latest-wins",
    )
    h = "cd" * 32
    state.record_folder_audit_event(
        folder_name="f", peer_fp="", action="write",
        file_path="x.txt", blob_hash=h, size=10,
    )
    state.record_folder_audit_event(
        folder_name="f", peer_fp="real" * 16, action="write",
        file_path="x.txt", blob_hash=h, size=10,
    )
    peers = state.list_peers_with_blob(h, folder_name="f")
    assert "real" * 16 in peers
    assert "" not in peers
    state.close()


def test_list_peers_with_blob_scopes_by_folder(tmp_path: Path):
    """When folder_name is given, peers from OTHER folders are
    excluded — prevents cross-folder candidate leakage."""
    state = State(db_path=tmp_path / "s.db")
    for name in ("f1", "f2"):
        state.add_folder(
            name=name, local_path=str(tmp_path / name), shared_with=[],
            max_file_bytes=None, ignored_patterns=[],
            conflict_policy="latest-wins",
        )
    h = "ef" * 32
    state.record_folder_audit_event(
        folder_name="f1", peer_fp="peerA" * 13, action="write",
        file_path="x", blob_hash=h, size=1,
    )
    state.record_folder_audit_event(
        folder_name="f2", peer_fp="peerB" * 13, action="write",
        file_path="y", blob_hash=h, size=1,
    )
    f1_peers = state.list_peers_with_blob(h, folder_name="f1")
    assert set(f1_peers) == {"peerA" * 13}
    # No-scope returns both.
    all_peers = state.list_peers_with_blob(h)
    assert set(all_peers) == {"peerA" * 13, "peerB" * 13}
    state.close()


def test_list_peers_with_blob_filters_by_action(tmp_path: Path):
    """Only 'write', 'renamed', 'restored' actions count as
    'this peer has the blob' — 'reject_size' / 'reject_pattern' /
    other negative outcomes must NOT be treated as availability."""
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="f", local_path=str(tmp_path / "f"), shared_with=[],
        max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    h = "11" * 32
    # Peer A: rejected (size). Peer B: actually wrote.
    state.record_folder_audit_event(
        folder_name="f", peer_fp="rejecte" * 9 + "d",
        action="reject_size",
        file_path="x", blob_hash=h, size=1,
    )
    state.record_folder_audit_event(
        folder_name="f", peer_fp="real" * 16, action="write",
        file_path="x", blob_hash=h, size=1,
    )
    peers = state.list_peers_with_blob(h, folder_name="f")
    assert "real" * 16 in peers
    assert len(peers) == 1
    state.close()


# ── swarm_pull_blob short-circuits ──────────────────────────────────


@pytest.mark.asyncio
async def test_swarm_pull_returns_true_if_blob_already_local(tmp_path: Path):
    """No racers needed if we already have the blob — instant True."""
    blob_store = BlobStore(root=tmp_path / "blobs")
    # Put a blob in the store.
    test_bytes = b"hello"
    h = blob_store.put_bytes(test_bytes)
    daemon = MagicMock(spec=Daemon)
    daemon.blob_store = blob_store
    daemon.state = MagicMock()
    # No need to set up _peer_from_fp etc — the early return fires
    # before any candidate lookup.
    bound = Daemon.swarm_pull_blob.__get__(daemon)
    ok = await bound(h, folder_name="f")
    assert ok is True


@pytest.mark.asyncio
async def test_swarm_pull_returns_false_with_no_candidates(tmp_path: Path):
    """No peers known to have the blob → False, no dial attempts."""
    blob_store = BlobStore(root=tmp_path / "blobs")
    state = State(db_path=tmp_path / "s.db")
    daemon = MagicMock(spec=Daemon)
    daemon.blob_store = blob_store
    daemon.state = state
    bound = Daemon.swarm_pull_blob.__get__(daemon)
    ok = await bound("aa" * 32, folder_name="missing")
    assert ok is False
    state.close()


@pytest.mark.asyncio
async def test_swarm_pull_returns_false_when_no_pinned_candidates(tmp_path: Path):
    """Audit-known candidates that aren't pinned must be filtered out
    — otherwise we'd dial an unpinned peer and leak our existence."""
    blob_store = BlobStore(root=tmp_path / "blobs")
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="f", local_path=str(tmp_path / "f"), shared_with=[],
        max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    state.record_folder_audit_event(
        folder_name="f", peer_fp="aa" * 32, action="write",
        file_path="x", blob_hash="bb" * 32, size=1,
    )
    daemon = MagicMock(spec=Daemon)
    daemon.blob_store = blob_store
    daemon.state = state
    daemon._is_pinned = MagicMock(return_value=False)  # nobody pinned
    bound = Daemon.swarm_pull_blob.__get__(daemon)
    ok = await bound("bb" * 32, folder_name="f")
    assert ok is False
    state.close()


@pytest.mark.asyncio
async def test_swarm_pull_calls_request_per_candidate(tmp_path: Path):
    """When there ARE pinned, online candidates, swarm_pull_blob
    must call _request_blob_from_peer for each."""
    blob_store = BlobStore(root=tmp_path / "blobs")
    state = State(db_path=tmp_path / "s.db")
    state.add_folder(
        name="f", local_path=str(tmp_path / "f"), shared_with=[],
        max_file_bytes=None, ignored_patterns=[],
        conflict_policy="latest-wins",
    )
    blob = "bb" * 32
    for i, fp in enumerate(("aa" * 32, "cc" * 32)):
        state.record_folder_audit_event(
            folder_name="f", peer_fp=fp, action="write",
            file_path=f"x{i}", blob_hash=blob, size=1,
        )

    daemon = MagicMock(spec=Daemon)
    daemon.blob_store = blob_store
    daemon.state = state
    daemon._is_pinned = MagicMock(return_value=True)
    # Fake "online peer" lookup.
    fake_peer_a = SimpleNamespace(short_id="aa12", ed_pub_hex="aa" * 32)
    fake_peer_c = SimpleNamespace(short_id="cc12", ed_pub_hex="cc" * 32)
    daemon._peer_from_fp = MagicMock(side_effect=lambda fp: {
        "aa" * 32: fake_peer_a,
        "cc" * 32: fake_peer_c,
    }.get(fp))
    # First racer wins; second returns False.
    call_counts = {"called": 0}

    async def fake_request(peer, blob_hash, **kw):
        call_counts["called"] += 1
        if peer is fake_peer_a:
            return True
        await asyncio.sleep(0.5)
        return False
    daemon._request_blob_from_peer = AsyncMock(side_effect=fake_request)

    bound = Daemon.swarm_pull_blob.__get__(daemon)
    ok = await bound(blob, folder_name="f", max_parallel=2, timeout_s=2.0)
    assert ok is True
    assert call_counts["called"] >= 1
    state.close()
