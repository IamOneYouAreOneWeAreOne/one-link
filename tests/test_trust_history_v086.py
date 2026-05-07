"""v0.8.6 — merged trust-history timeline.

The capability_audit log + key_change_events table + the peers row
were each surfaced in earlier ships, but never as a single
chronological timeline for one peer. v0.8.6 adds peer_trust_history
which merges all three sources into a single newest-first list,
with severity-tagged entries the UI renders as a left-rail timeline.

These tests pin the merge contract: every recorded source shows up,
labels are humanized, severity is graded, ordering is newest-first.
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
        fingerprint=fp,
        short_id=fp[:8],
        pubkey=b"\x01" * 32,
        hostname=hostname,
    )
    return fp


# ───────── empty / missing peers ─────────────────────────────────────

def test_history_empty_for_unknown_peer(state: State):
    assert state.peer_trust_history("ff" * 32) == []


def test_history_includes_first_seen_for_brand_new_peer(state: State):
    """A freshly-upserted peer with no audit rows still gets a
    synthetic 'Device first seen' event derived from
    peers.first_seen_ms — gives the timeline a sensible anchor."""
    fp = _seed(state)
    events = state.peer_trust_history(fp)
    assert len(events) == 1
    assert events[0]["kind"] == "first_seen"
    assert events[0]["label"] == "Device first seen"


# ───────── audit-log entries surface ─────────────────────────────────

def test_verify_set_event_in_history(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits", note="hallway")
    events = state.peer_trust_history(fp)
    kinds = [e["kind"] for e in events]
    assert "verify_set" in kinds
    verify = next(e for e in events if e["kind"] == "verify_set")
    assert verify["severity"] == "good"
    assert "method: sas-digits" in verify["detail"]


def test_verify_clear_event_in_history(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits")
    state.clear_peer_verified(fp, note="rotated keys")
    events = state.peer_trust_history(fp)
    kinds = [e["kind"] for e in events]
    assert "verify_clear" in kinds
    clear_ev = next(e for e in events if e["kind"] == "verify_clear")
    assert clear_ev["severity"] == "warn"


def test_trust_set_event_in_history(state: State):
    fp = _seed(state)
    state.set_peer_trust(fp, "pinned")
    events = state.peer_trust_history(fp)
    kinds = [e["kind"] for e in events]
    assert "trust_set" in kinds
    trust_ev = next(e for e in events if e["kind"] == "trust_set")
    assert "→ pinned" in trust_ev["label"]


def test_capability_policy_change_event_in_history(state: State):
    fp = _seed(state)
    state.set_peer_capability_policy(fp, ["chat"], note="lockdown")
    events = state.peer_trust_history(fp)
    cap_ev = next(
        (e for e in events if e["kind"] == "cap_policy_set"), None,
    )
    assert cap_ev is not None
    assert "now allow: chat" in cap_ev["detail"]


# ───────── key-change events surface ─────────────────────────────────

def test_key_change_in_event_in_history(state: State):
    """When this peer is the rotated-IN fingerprint, the timeline
    flags 'this device replaces a prior one'."""
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x01" * 32, hostname="h",
    )
    state.set_peer_trust("aa" * 32, "pinned")
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb",
        pubkey=b"\x02" * 32, hostname="h",
    )
    events = state.peer_trust_history("bb" * 32)
    kc = next((e for e in events if e["kind"] == "key_change_in"), None)
    assert kc is not None
    assert kc["severity"] == "bad"  # high (prior was pinned)
    assert "UNACKNOWLEDGED" in kc["detail"]


def test_key_change_out_event_in_history(state: State):
    """When this peer is the rotated-OUT fingerprint, the timeline
    shows 'this device was rotated out'."""
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x01" * 32, hostname="h",
    )
    state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb",
        pubkey=b"\x02" * 32, hostname="h",
    )
    events = state.peer_trust_history("aa" * 32)
    kc = next((e for e in events if e["kind"] == "key_change_out"), None)
    assert kc is not None
    assert "replaced by" in kc["detail"]


# ───────── ordering + dedup ──────────────────────────────────────────

def test_history_is_newest_first(state: State):
    fp = _seed(state)
    state.set_peer_verified(fp, method="sas-digits")
    time.sleep(0.005)
    state.clear_peer_verified(fp)
    time.sleep(0.005)
    state.set_peer_verified(fp, method="manual")
    events = state.peer_trust_history(fp)
    timestamps = [e["ts_ms"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)


def test_history_respects_limit(state: State):
    fp = _seed(state)
    for _ in range(20):
        state.set_peer_capability_policy(fp, ["chat"])
        state.clear_peer_capability_policy(fp)
    events = state.peer_trust_history(fp, limit=5)
    assert len(events) == 5


# ───────── server route + UI smoke ───────────────────────────────────

def test_route_registered():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get(r"/api/peers/{fp}/trust-history", '
        'self._guarded(self.api_get_peer_trust_history))'
    ) in src


def test_drawer_has_trust_timeline_section():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert 'id="dev-trust-history-section"' in src
    assert 'id="dev-trust-timeline"' in src
    assert 'id="dev-trust-history-toggle"' in src
    # Helper present
    assert "function loadDrawerTrustHistory(" in src
    assert "trust-timeline" in src
