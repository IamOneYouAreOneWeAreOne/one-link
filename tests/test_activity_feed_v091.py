"""v0.9.1 — cross-peer activity feed.

The trust timeline (v0.8.6) is per-peer. v0.9.1 adds a global
activity feed that merges every audit source into one chronological
list: capability_audit (verify, trust, cap policy), key_change_events,
transfers (terminal states only), manifest_conflicts, peers
first_seen.

These tests cover the merge contract: every source surfaces, every
filter works, ordering is newest-first, the limit is honored.
"""

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


def _seed(state: State, fp: str = "aa" * 32, hostname: str = "alice") -> str:
    state.upsert_peer(
        fingerprint=fp, short_id=fp[:8], pubkey=b"\x01" * 32, hostname=hostname,
    )
    return fp


# ───────── empty / unknown ───────────────────────────────────────────

def test_empty_state_returns_empty(state: State):
    assert state.activity_feed() == []


# ───────── source coverage ───────────────────────────────────────────

def test_first_seen_event_present(state: State):
    fp = _seed(state)
    events = state.activity_feed()
    kinds = [e["kind"] for e in events]
    assert "peer" in kinds
    p = next(e for e in events if e["kind"] == "peer")
    assert p["subkind"] == "first_seen"


def test_verify_set_event_present(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits", note="hallway")
    events = state.activity_feed(kinds=["trust"])
    assert any(e["subkind"] == "verify_set" for e in events)


def test_trust_set_event_present(state: State):
    fp = _seed(state)
    state.set_peer_trust(fp, "pinned")
    events = state.activity_feed(kinds=["trust"])
    assert any(e["subkind"] == "trust_set" for e in events)


def test_key_change_event_present(state: State):
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa", pubkey=b"\x01" * 32,
        hostname="h",
    )
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb", pubkey=b"\x02" * 32,
        hostname="h",
    )
    events = state.activity_feed(kinds=["key_change"])
    assert any(e["kind"] == "key_change" for e in events)


def test_transfer_event_present(state: State):
    fp = _seed(state)
    # Insert a complete transfer directly (skip the broader pipeline).
    state.upsert_transfer(
        id="t1", direction="out", peer_fp=fp, kind="file",
        name="report.pdf", size=12345, status="complete",
        progress_bytes=12345, total_bytes=12345,
        chunks_done=1, chunks_total=1,
        metadata={"path": "/tmp/x"},
    )
    events = state.activity_feed(kinds=["transfer"])
    assert any(e["kind"] == "transfer" for e in events)
    t = next(e for e in events if e["kind"] == "transfer")
    assert "report.pdf" in t["label"]


def test_in_flight_transfers_excluded_from_feed(state: State):
    """Mid-flight transfers are the chat bubble's job — feed only
    surfaces terminal states (complete + failed)."""
    fp = _seed(state)
    state.upsert_transfer(
        id="t1", direction="out", peer_fp=fp, kind="file",
        name="active.bin", size=100, status="active",
        progress_bytes=50, total_bytes=100,
        chunks_done=0, chunks_total=1, metadata={},
    )
    events = state.activity_feed(kinds=["transfer"])
    assert all(e["kind"] != "transfer" or "active.bin" not in e["label"] for e in events)


def test_conflict_event_present(state: State):
    cid = state.record_manifest_conflict(
        folder_name="docs", file_path="r.md", peer_fp="aa" * 32,
        local_blob_hash="11" * 32, local_size=10, local_mtime_ms=100,
        local_vclock={"me": 1},
        remote_blob_hash="22" * 32, remote_size=20, remote_mtime_ms=90,
        remote_vclock={"peer": 1},
        applied_choice="local",
    )
    events = state.activity_feed(kinds=["conflict"])
    assert any(e["kind"] == "conflict" for e in events)


# ───────── filters ───────────────────────────────────────────────────

def test_kinds_filter(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits")
    events = state.activity_feed(kinds=["trust"])
    assert all(e["kind"] == "trust" for e in events)


def test_peer_filter(state: State):
    fp1 = _seed(state, fp="aa" * 32, hostname="alice")
    fp2 = _seed(state, fp="bb" * 32, hostname="bob")
    state.set_peer_verified(fp1, method="sas-digits")
    state.set_peer_verified(fp2, method="manual")
    events = state.activity_feed(peer_fp=fp1)
    fps = [e["peer_fp"] for e in events if e.get("peer_fp")]
    assert all(f == fp1 for f in fps)


def test_since_filter(state: State):
    fp = _seed(state)
    # Sleep so the verify event lands strictly after the seed/first_seen.
    time.sleep(0.02)
    cutoff = int(time.time() * 1000) + 1  # exclude any tied timestamps
    time.sleep(0.02)
    state.set_peer_verified(fp, method="sas-digits")
    # Only the verify event is after cutoff; first_seen is before.
    events = state.activity_feed(since_ms=cutoff)
    assert any(e["subkind"] == "verify_set" for e in events)
    assert not any(e["subkind"] == "first_seen" for e in events)


def test_limit_honored(state: State):
    fp = _seed(state)
    for _ in range(20):
        state.set_peer_capability_policy(fp, ["chat"])
        state.clear_peer_capability_policy(fp)
    events = state.activity_feed(limit=5)
    assert len(events) == 5


def test_limit_clamped_to_max(state: State):
    """limit hard-cap is 2000; passing 99999 must clamp not crash."""
    events = state.activity_feed(limit=99999)
    assert len(events) <= 2000


# ───────── ordering ──────────────────────────────────────────────────

def test_newest_first(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits")
    time.sleep(0.005)
    state.clear_peer_verified(fp)
    events = state.activity_feed()
    timestamps = [e["ts_ms"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


# ───────── peer display name ─────────────────────────────────────────

def test_peer_display_name_resolved(state: State):
    fp = _seed(state, hostname="alice-laptop")
    state.set_peer_profile(fp, local_alias="Alice's Mac")
    state.set_peer_verified(fp, method="sas-digits")
    events = state.activity_feed(kinds=["trust"])
    e = next(ev for ev in events if ev["subkind"] == "verify_set")
    # Local alias wins over hostname (PeerRecord.display_name semantics).
    assert e["peer_display_name"] == "Alice's Mac"


# ───────── server route + UI smoke ───────────────────────────────────

def test_route_registered():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get("/api/activity", '
        'self._guarded(self.api_get_activity_feed))'
    ) in src


def test_handler_present():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert "async def api_get_activity_feed(" in src


def test_ui_has_activity_pane():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="activity-list"' in src
    assert 'id="activity-filters"' in src
    assert "function refreshActivityFeed(" in src
    assert "function renderActivityFeed(" in src
    assert "function activityIcon(" in src
    # Filter chips
    assert 'data-activity-filter="all"' in src
    assert 'data-activity-filter="trust"' in src
    assert 'data-activity-filter="transfer"' in src


def test_ws_handlers_nudge_activity_refresh():
    """Trust + key_change + folder_conflict + transfer events must
    trigger scheduleActivityRefresh so the feed stays live."""
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    # Find each WS branch + verify it references scheduleActivityRefresh.
    for kind in ('"peer_trust"', '"peer_verified"',
                 '"key_change_detected"', '"folder_conflict_detected"'):
        idx = src.find(f"m.type === {kind}")
        assert idx > 0, f"missing handler for {kind}"
        snippet = src[idx:idx + 600]
        assert "scheduleActivityRefresh()" in snippet, f"{kind} doesn't refresh feed"
