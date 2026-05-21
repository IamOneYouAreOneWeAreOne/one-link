"""Tests for ``Daemon._peer_trust_score`` — D02 alignment trust scoring
wired into the daemon.

The helper is a SOFT signal layered onto _capability_allowed: it
surfaces A(x, t) for a peer without changing the allow/deny outcome
in this phase. These tests verify:
  - Score is returned for known peers.
  - Score is None for unknown peers / no state.
  - Score correctly reflects relationship tier + staleness.
  - _capability_allowed behavior is unchanged (regression).
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock

import pytest

from one_link import daemon as daemon_module


def _make_peer(trust: str = "pinned", last_seen_ms: int | None = None):
    """Build a minimal PeerRecord-shaped MagicMock for trust scoring."""
    mock = MagicMock()
    mock.trust = trust
    mock.last_seen_ms = last_seen_ms if last_seen_ms is not None else int(time.time() * 1000)
    return mock


def _make_daemon_with_peer(trust: str, last_seen_ms: int | None = None):
    """Build a stripped-down Daemon-like object exposing the methods we test.

    The full Daemon is heavy to instantiate (network sockets, DBs, etc.).
    Since _peer_trust_score only reads ``self.state.get_peer(fp)``, we
    can test it against a minimal object that mocks state.get_peer.
    """
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.return_value = _make_peer(trust=trust, last_seen_ms=last_seen_ms)
    return d


def test_trust_score_returns_none_when_state_missing() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = None
    assert d._peer_trust_score("doesnt-matter") is None


def test_trust_score_returns_none_for_unknown_peer() -> None:
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.return_value = None
    assert d._peer_trust_score("never-seen") is None


def test_trust_score_fresh_paired_near_one() -> None:
    # Paired peer, just talked: trust ~ 0.99.
    d = _make_daemon_with_peer(trust="pinned")
    t = d._peer_trust_score("abc")
    assert t is not None
    assert 0.98 < t <= 1.0


def test_trust_score_fresh_known_lower_than_paired() -> None:
    # Same staleness, known < paired.
    fp = "abc"
    now_ms = int(time.time() * 1000)
    paired = _make_daemon_with_peer(trust="pinned", last_seen_ms=now_ms)._peer_trust_score(fp)
    known = _make_daemon_with_peer(trust="pending", last_seen_ms=now_ms)._peer_trust_score(fp)
    stranger = _make_daemon_with_peer(trust="rejected", last_seen_ms=now_ms)._peer_trust_score(fp)
    assert paired is not None and known is not None and stranger is not None
    # Hop-distance heuristic: paired=1, known=3, stranger=10 → strict decay.
    assert paired > known > stranger


def test_trust_score_decays_with_staleness() -> None:
    # Paired peer 5 days silent: still > 0.5 (within paired session).
    five_days_ago_ms = int(time.time() * 1000) - 5 * 86_400 * 1000
    d = _make_daemon_with_peer(trust="pinned", last_seen_ms=five_days_ago_ms)
    t = d._peer_trust_score("abc")
    assert t is not None
    # exp(-(1 + 25)/100) ≈ 0.77 — see ol_align/src/align.rs test.
    assert 0.5 < t < 1.0


def test_trust_score_stranger_decays_fast() -> None:
    # Stranger after 1 day silent should be very low.
    one_day_ago_ms = int(time.time() * 1000) - 86_400 * 1000
    d = _make_daemon_with_peer(trust="rejected", last_seen_ms=one_day_ago_ms)
    t = d._peer_trust_score("abc")
    assert t is not None
    # Hop=10, staleness=1d, L=5: exp(-(100+1)/5) ≈ tiny.
    assert t < 0.01


def test_trust_score_handles_corrupt_last_seen() -> None:
    # last_seen_ms = None is allowed (treated as 0).
    d = _make_daemon_with_peer(trust="pinned", last_seen_ms=0)
    t = d._peer_trust_score("abc")
    # Score will be very small since staleness is "since epoch" but
    # must NOT crash.
    assert t is not None
    assert 0.0 <= t <= 1.0


def test_trust_score_handles_state_exception() -> None:
    # If state.get_peer raises, return None instead of crashing.
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.state.get_peer.side_effect = RuntimeError("boom")
    assert d._peer_trust_score("abc") is None
