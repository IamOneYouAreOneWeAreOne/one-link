"""Attention center: classified things the user should look at.

The UI's notification badge surfaces:
  - incoming files waiting for accept (pending_accept)
  - outbound sends stuck at 0% for too long (stuck_outbound)
  - outbound sends held by the recipient who hasn't decided yet
    (awaiting_remote_ok)
  - real (non-transient) outbound failures (failed_needs_action)

These pin the classifier so the badge stays accurate.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key()
    pb = pub.public_bytes_raw()
    fp = fingerprint_of(pb)
    return Identity(
        private=sk, public=pub, public_bytes=pb,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


def _daemon(tmp_path: Path) -> Daemon:
    d = Daemon(_new_identity())
    d.state = State(db_path=tmp_path / "s.db")
    return d


def _make_outbound(state, *, tid, status, peer="aa" * 32,
                   age_ms=0, metadata=None, progress=0):
    state.upsert_transfer(
        id=tid, direction="out", peer_fp=peer, kind="file",
        name="report.pdf", size=1000, status=status,
        progress_bytes=progress, total_bytes=1000,
        chunks_done=0, chunks_total=1, metadata=metadata or {},
    )
    if age_ms > 0:
        backdated = int(time.time() * 1000) - age_ms
        with state._write_lock:
            state._conn.execute(
                "UPDATE transfers SET updated_ms = ? WHERE id = ?",
                (backdated, tid),
            )


def test_empty_attention_when_nothing_needs_action(tmp_path):
    d = _daemon(tmp_path)
    try:
        assert d.list_attention_items() == []
    finally:
        d.state.close()


def test_pending_accept_surfaced_for_held_inbound(tmp_path):
    d = _daemon(tmp_path)
    try:
        d._pending_file_offers["in:abc"] = {
            "channel": object(), "peer_fp": "aa" * 32,
            "peer_sid": "aaaa", "blob": "ab" * 32, "msg_id": "m",
            "msg": {}, "mode": "stream", "missing": None,
            "name": "photo.png", "size": 1234,
            "created_ms": int(time.time() * 1000) - 5_000,
        }
        items = d.list_attention_items()
        assert len(items) == 1
        item = items[0]
        assert item["kind"] == "pending_accept"
        assert item["transfer_id"] == "in:abc"
        assert item["direction"] == "in"
        assert "accept" in item["actions"]
        assert "decline" in item["actions"]
        assert item["since_ms"] >= 5_000
    finally:
        d.state.close()


def test_stuck_outbound_after_threshold(tmp_path):
    d = _daemon(tmp_path)
    try:
        # Fresh send (10s old, 0%) — NOT surfaced (under 60s threshold).
        _make_outbound(d.state, tid="out:fresh", status="active",
                       age_ms=10_000, progress=0)
        items = d.list_attention_items()
        assert all(i["transfer_id"] != "out:fresh" for i in items)

        # Same send aged past the threshold (90s old, still 0%) → flagged.
        _make_outbound(d.state, tid="out:stuck", status="active",
                       age_ms=90_000, progress=0)
        items = d.list_attention_items()
        stuck = [i for i in items if i["transfer_id"] == "out:stuck"]
        assert len(stuck) == 1
        assert stuck[0]["kind"] == "stuck_outbound"
        assert "cancel" in stuck[0]["actions"]
    finally:
        d.state.close()


def test_outbound_with_progress_not_flagged_even_when_old(tmp_path):
    d = _daemon(tmp_path)
    try:
        # Active send that HAS made progress (not stuck) — never flagged.
        _make_outbound(d.state, tid="out:moving", status="active",
                       age_ms=120_000, progress=500)
        items = d.list_attention_items()
        assert all(i["transfer_id"] != "out:moving" for i in items)
    finally:
        d.state.close()


def test_awaiting_remote_ok_surfaced(tmp_path):
    d = _daemon(tmp_path)
    try:
        _make_outbound(
            d.state, tid="out:held", status="offered", age_ms=45_000,
            metadata={"delivery_state": "awaiting_remote_acceptance"},
        )
        items = d.list_attention_items()
        held = [i for i in items if i["transfer_id"] == "out:held"]
        assert held and held[0]["kind"] == "awaiting_remote_ok"
        assert "cancel" in held[0]["actions"]
    finally:
        d.state.close()


def test_non_transient_failure_surfaced_and_dismissable(tmp_path):
    d = _daemon(tmp_path)
    try:
        _make_outbound(
            d.state, tid="out:dead", status="failed", age_ms=10_000,
            metadata={
                "transient": False,
                "error": "decrypt failed",
                "user_message": "The peer rejected the file.",
            },
        )
        items = d.list_attention_items()
        f = [i for i in items if i["transfer_id"] == "out:dead"]
        assert f and f[0]["kind"] == "failed_needs_action"
        assert "dismiss" in f[0]["actions"]
        assert "retry" in f[0]["actions"]

        # Dismiss removes it from future lists.
        res = d.dismiss_attention("out:dead")
        assert res["ok"] is True
        items2 = d.list_attention_items()
        assert all(i["transfer_id"] != "out:dead" for i in items2)
    finally:
        d.state.close()


def test_transient_failure_NOT_surfaced(tmp_path):
    """Transient failures (peer offline) auto-resume; the badge would
    just nag without giving the user anything to do."""
    d = _daemon(tmp_path)
    try:
        _make_outbound(
            d.state, tid="out:pause", status="failed", age_ms=5_000,
            metadata={"transient": True, "error": "peer offline"},
        )
        assert all(
            i["transfer_id"] != "out:pause"
            for i in d.list_attention_items()
        )
    finally:
        d.state.close()


def test_priority_sort_puts_pending_accept_first(tmp_path):
    """The most-actionable kind sorts to the top: pending_accept
    (someone is waiting on YOU) above failed_needs_action above
    awaiting_remote_ok above stuck_outbound."""
    d = _daemon(tmp_path)
    try:
        _make_outbound(
            d.state, tid="out:dead", status="failed", age_ms=5_000,
            metadata={"transient": False, "error": "x"},
        )
        _make_outbound(
            d.state, tid="out:held", status="offered", age_ms=45_000,
            metadata={"delivery_state": "awaiting_remote_acceptance"},
        )
        _make_outbound(
            d.state, tid="out:stuck", status="active", age_ms=120_000, progress=0,
        )
        d._pending_file_offers["in:new"] = {
            "channel": object(), "peer_fp": "aa" * 32,
            "peer_sid": "aaaa", "blob": "ab" * 32, "msg_id": "m",
            "msg": {}, "mode": "stream", "missing": None,
            "name": "photo.png", "size": 1,
            "created_ms": int(time.time() * 1000),
        }
        kinds = [i["kind"] for i in d.list_attention_items()]
        assert kinds == [
            "pending_accept",
            "failed_needs_action",
            "awaiting_remote_ok",
            "stuck_outbound",
        ]
    finally:
        d.state.close()


def test_overflow_row_when_more_than_max(tmp_path):
    """A runaway can't explode the badge — items beyond the cap are
    summarised in one "+N more" overflow row."""
    d = _daemon(tmp_path)
    try:
        # Seed cap + 5 failed items (each its own pending row).
        n = Daemon.ATTENTION_MAX_ITEMS + 5
        for i in range(n):
            _make_outbound(
                d.state, tid=f"out:f{i:03d}", status="failed", age_ms=1000 + i,
                metadata={"transient": False, "error": "x"},
            )
        items = d.list_attention_items()
        # Capped at MAX + 1 overflow row.
        assert len(items) == Daemon.ATTENTION_MAX_ITEMS + 1
        assert items[-1]["kind"] == "overflow"
        assert "more" in items[-1]["summary"]
    finally:
        d.state.close()


def test_inbound_failures_not_in_attention(tmp_path):
    """Only outbound issues + the inbound accept-prompt belong here.
    A historical inbound failure isn't actionable — don't nag."""
    d = _daemon(tmp_path)
    try:
        d.state.upsert_transfer(
            id="in:fail", direction="in", peer_fp="aa" * 32, kind="file",
            name="x.bin", size=1, status="failed",
            progress_bytes=0, total_bytes=1, chunks_done=0, chunks_total=1,
            metadata={"transient": False},
        )
        items = d.list_attention_items()
        assert all(i["transfer_id"] != "in:fail" for i in items)
    finally:
        d.state.close()
