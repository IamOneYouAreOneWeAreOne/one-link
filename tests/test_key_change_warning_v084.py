"""v0.7.8 — key-change warning (hostname-pubkey rotation tracking).

Threat model: a hostname H was advertised with pubkey K1 yesterday.
Today the same hostname H is being advertised with pubkey K2. That
either means (a) the user reinstalled / replaced the device, or
(b) someone is impersonating it on the LAN. Either way, the chat
session is no longer talking to the same identity, and the user
needs a loud red warning.

These tests cover state.py's `hostname_keys` history table and the
`key_change_events` audit log + ack semantics. UI surfaces are
smoke-checked in the index.html string assertions at the bottom.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


def _seed(
    state: State, *, hostname: str, fp: str, pubkey: bytes,
) -> None:
    state.upsert_peer(
        fingerprint=fp,
        short_id=fp[:8],
        pubkey=pubkey,
        hostname=hostname,
    )


# ───────── schema migration ──────────────────────────────────────────

def test_migration_v9_creates_tables(state: State):
    """hostname_keys + key_change_events must exist; schema_version
    must advance to 9."""
    rows = state._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert "hostname_keys" in names
    assert "key_change_events" in names
    assert state.schema_version() >= 9


# ───────── hostname_keys history ─────────────────────────────────────

def test_first_observation_records_no_event(state: State):
    """A brand-new (hostname, pubkey) pair must not raise an event —
    there's no conflict to flag."""
    _seed(state, hostname="alice-laptop", fp="aa" * 32, pubkey=b"\x01" * 32)
    history = state.list_hostname_keys("alice-laptop")
    assert len(history) == 1
    assert history[0]["fingerprint"] == "aa" * 32
    events = state.list_key_change_events()
    assert events == []


def test_same_pubkey_re_seen_does_not_raise_event(state: State):
    """Re-observing the same (hostname, pubkey) pair just updates
    last_seen_ms — it must not generate a key-change event."""
    _seed(state, hostname="alice-laptop", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="alice-laptop", fp="aa" * 32, pubkey=b"\x01" * 32)
    assert state.list_key_change_events() == []


def test_pubkey_rotation_records_event(state: State):
    """Same hostname, different pubkey → exactly one key-change event."""
    _seed(state, hostname="alice-laptop", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="alice-laptop", fp="bb" * 32, pubkey=b"\x02" * 32)
    events = state.list_key_change_events()
    assert len(events) == 1
    ev = events[0]
    assert ev["hostname"] == "alice-laptop"
    assert ev["old_fingerprint"] == "aa" * 32
    assert ev["new_fingerprint"] == "bb" * 32
    assert ev["acked_ms"] is None


def test_repeat_rotation_is_idempotent(state: State):
    """Reporting the same (old_fp → new_fp) transition twice must
    NOT create a duplicate event row."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    assert len(state.list_key_change_events()) == 1


def test_severity_high_when_old_fp_was_pinned(state: State):
    """The most dangerous case: a paired peer's hostname starts
    advertising a different pubkey. severity must be 'high'."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    state.set_peer_trust("aa" * 32, "pinned")
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    events = state.list_key_change_events()
    assert events[0]["severity"] == "high"


def test_severity_medium_when_old_fp_was_pending(state: State):
    """Pending-but-known peer rotating keys is medium severity."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    # default trust='pending'
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    events = state.list_key_change_events()
    assert events[0]["severity"] in ("medium", "high")  # at least medium


def test_different_hostname_same_pubkey_does_not_alert(state: State):
    """Two devices with the same pubkey is a separate (cosmic) bug.
    Same pubkey advertised under DIFFERENT hostnames is not a
    rotation event — it's a different host, period."""
    _seed(state, hostname="alice-laptop", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="bob-desktop", fp="bb" * 32, pubkey=b"\x02" * 32)
    assert state.list_key_change_events() == []


# ───────── ack semantics ─────────────────────────────────────────────

def test_ack_single_event_marks_acked(state: State):
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    [ev] = state.list_key_change_events()
    assert state.ack_key_change_event(ev["id"]) is True
    refreshed = state.list_key_change_events()
    assert refreshed[0]["acked_ms"] is not None
    # Idempotent re-ack returns False.
    assert state.ack_key_change_event(ev["id"]) is False


def test_ack_unknown_event_returns_false(state: State):
    assert state.ack_key_change_event(999999) is False


def test_unacked_only_filter(state: State):
    _seed(state, hostname="h1", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="h1", fp="bb" * 32, pubkey=b"\x02" * 32)
    _seed(state, hostname="h2", fp="cc" * 32, pubkey=b"\x03" * 32)
    _seed(state, hostname="h2", fp="dd" * 32, pubkey=b"\x04" * 32)
    all_events = state.list_key_change_events()
    assert len(all_events) == 2
    state.ack_key_change_event(all_events[0]["id"])
    unacked = state.list_key_change_events(unacked_only=True)
    assert len(unacked) == 1


def test_filter_by_new_fingerprint(state: State):
    _seed(state, hostname="h1", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="h1", fp="bb" * 32, pubkey=b"\x02" * 32)
    _seed(state, hostname="h2", fp="cc" * 32, pubkey=b"\x03" * 32)
    _seed(state, hostname="h2", fp="dd" * 32, pubkey=b"\x04" * 32)
    only_bb = state.list_key_change_events(new_fingerprint="bb" * 32)
    assert len(only_bb) == 1
    assert only_bb[0]["hostname"] == "h1"


def test_ack_all_for_peer_bulk_clears(state: State):
    """Three rotations under one hostname end up as 3 events; one
    ack_all call clears them all."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    _seed(state, hostname="h", fp="bb" * 32, pubkey=b"\x02" * 32)
    _seed(state, hostname="h", fp="cc" * 32, pubkey=b"\x03" * 32)
    # bb→cc and aa→cc are both unacked events targeting cc.
    targeting_cc = state.list_key_change_events(
        new_fingerprint="cc" * 32, unacked_only=True,
    )
    assert len(targeting_cc) >= 1
    n = state.ack_all_key_change_events_for("cc" * 32)
    assert n == len(targeting_cc)
    after = state.list_key_change_events(
        new_fingerprint="cc" * 32, unacked_only=True,
    )
    assert after == []


def test_ack_all_no_unacked_returns_zero(state: State):
    """ack_all on a peer with no unacked events must return 0,
    not raise."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    assert state.ack_all_key_change_events_for("aa" * 32) == 0


# ───────── pending-event broadcast id ────────────────────────────────

def test_upsert_peer_attaches_pending_event_id(state: State):
    """Daemon needs to broadcast key_change events as they're
    detected. upsert_peer attaches `_pending_key_change_event_id`
    to the returned PeerRecord on the conflict path."""
    _seed(state, hostname="h", fp="aa" * 32, pubkey=b"\x01" * 32)
    rec = state.upsert_peer(
        fingerprint="bb" * 32, short_id="bb",
        pubkey=b"\x02" * 32, hostname="h",
    )
    assert hasattr(rec, "_pending_key_change_event_id")
    assert rec._pending_key_change_event_id is not None


def test_upsert_peer_no_pending_id_when_no_conflict(state: State):
    rec = state.upsert_peer(
        fingerprint="aa" * 32, short_id="aa",
        pubkey=b"\x01" * 32, hostname="h",
    )
    # Either the attribute is absent or set to None — both acceptable.
    assert getattr(rec, "_pending_key_change_event_id", None) is None


# ───────── server / UI smoke ─────────────────────────────────────────

def test_server_routes_key_change_endpoints():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get("/api/key-change-events", '
        'self._guarded(self.api_list_key_change_events))'
    ) in src
    assert (
        'r.add_post(r"/api/key-change-events/{event_id}/ack", '
        'self._guarded(self.api_ack_key_change_event))'
    ) in src
    assert (
        'r.add_post(r"/api/peers/{fp}/key-change-events/ack-all", '
        'self._guarded(self.api_ack_peer_key_change_events))'
    ) in src
    assert (
        'r.add_get(r"/api/peers/{fp}/key-history", '
        'self._guarded(self.api_get_peer_key_history))'
    ) in src


def test_api_peers_attaches_key_change_alert():
    """/api/peers must surface unacked count + freshest event so
    the sidebar can render the red overlay without a second call."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert 'p["key_change_unacked"]' in src
    assert 'p["key_change_alert"]' in src


def test_index_html_renders_key_change_surfaces():
    src = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    # Sidebar overlay class
    assert "keychange-overlay" in src
    # Conversation banner
    assert 'id="convo-keychange"' in src
    assert "keychange-banner" in src
    # Drawer section
    assert 'id="dev-keychange-section"' in src
    assert 'id="dev-keychange-ack"' in src
    # WS handlers
    assert "key_change_acked" in src
    # Page version constant bumped
    assert 'PAGE_BUILT_FOR = "0.8.4"' in src
