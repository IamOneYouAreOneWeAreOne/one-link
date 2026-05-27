"""v0.21.x activity-feed completeness: folder_lifecycle_audit table
+ activity_feed() coverage for the new `folder` and `offer` kinds.

The audit table is the source of truth for sender-side folder events
(pre-v26 manifest_push sends produced zero activity rows). Tests here
pin:

  - record_folder_lifecycle_event validation (event name, direction,
    severity must be from the allowed sets — typos can't silently
    land rows the UI then has no label for)
  - list_folder_lifecycle_events filtering by since_ms / peer_fp /
    folder_name / event
  - activity_feed() surfaces audit rows as `folder` + `offer` kinds
    with sensible labels per direction
  - the `folder_send_group` tag rides through from transfers metadata
    so the UI can collapse per-file rows under their parent
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


# ── audit-table mechanics ─────────────────────────────────────────


def test_record_lifecycle_event_rejects_unknown_event(state: State):
    with pytest.raises(ValueError, match="unknown folder lifecycle event"):
        state.record_folder_lifecycle_event(
            event="nonsense", direction="out", folder_name="x",
        )


def test_record_lifecycle_event_rejects_bad_direction(state: State):
    with pytest.raises(ValueError, match="direction"):
        state.record_folder_lifecycle_event(
            event="offer_sent", direction="sideways", folder_name="x",
        )


def test_record_lifecycle_event_rejects_bad_severity(state: State):
    with pytest.raises(ValueError, match="severity"):
        state.record_folder_lifecycle_event(
            event="send_complete", direction="out",
            folder_name="x", severity="catastrophic",
        )


def test_record_lifecycle_event_roundtrips_all_fields(state: State):
    rid = state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="papers", peer_fp="aa" * 32,
        mode="archive", file_count=147, total_bytes=23_000_000,
        sent_bytes=9_000_000, dedup_bytes=200_000, duration_ms=12500,
        severity="good", error_msg=None,
        metadata={"folder_send_group": "folder:papers:aabb"},
    )
    assert rid > 0
    rows = state.list_folder_lifecycle_events()
    assert len(rows) == 1
    r = rows[0]
    assert r["event"] == "send_complete"
    assert r["direction"] == "out"
    assert r["folder_name"] == "papers"
    assert r["peer_fp"] == "aa" * 32
    assert r["mode"] == "archive"
    assert r["file_count"] == 147
    assert r["total_bytes"] == 23_000_000
    assert r["sent_bytes"] == 9_000_000
    assert r["dedup_bytes"] == 200_000
    assert r["duration_ms"] == 12500
    assert r["severity"] == "good"
    assert r["metadata"]["folder_send_group"] == "folder:papers:aabb"


def test_list_filters_by_peer_folder_event(state: State):
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="A", peer_fp="aa" * 32,
    )
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="B", peer_fp="bb" * 32,
    )
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="A", peer_fp="aa" * 32,
    )
    assert len(state.list_folder_lifecycle_events()) == 3
    assert len(state.list_folder_lifecycle_events(peer_fp="aa" * 32)) == 2
    assert len(state.list_folder_lifecycle_events(folder_name="A")) == 2
    assert len(state.list_folder_lifecycle_events(
        events=["offer_sent"])) == 2
    # Combined filter: peer + event narrows.
    rows = state.list_folder_lifecycle_events(
        peer_fp="aa" * 32, events=["send_complete"],
    )
    assert len(rows) == 1 and rows[0]["folder_name"] == "A"


def test_list_filters_invalid_event_names_silently(state: State):
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="A", peer_fp="aa" * 32,
    )
    # Unknown event names in the filter are dropped; returns all
    # rather than crashing.
    rows = state.list_folder_lifecycle_events(events=["junk", "offer_sent"])
    assert len(rows) == 1


# ── activity_feed surfaces folder + offer kinds ───────────────────


def test_activity_feed_includes_folder_send_complete(state: State):
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="papers", peer_fp="aa" * 32,
        mode="archive", file_count=147, total_bytes=23_000_000,
        severity="good",
    )
    rows = state.activity_feed()
    folder_rows = [r for r in rows if r["kind"] == "folder"]
    assert len(folder_rows) == 1
    r = folder_rows[0]
    assert r["subkind"] == "send_complete"
    assert r["severity"] == "good"
    assert r["folder_name"] == "papers"
    assert r["mode"] == "archive"
    # Label tells the user what happened in human terms.
    assert "Sent" in r["label"] and "papers" in r["label"]
    # Detail packs mode + count + size.
    assert "archive" in r["detail"]
    assert "147 files" in r["detail"]
    assert "MB" in r["detail"]


def test_activity_feed_includes_offer_kinds(state: State):
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="papers", peer_fp="aa" * 32,
        file_count=12, total_bytes=4_000_000,
    )
    state.record_folder_lifecycle_event(
        event="offer_received", direction="in",
        folder_name="notes", peer_fp="bb" * 32,
        file_count=3, total_bytes=200_000,
    )
    rows = state.activity_feed()
    offer_rows = [r for r in rows if r["kind"] == "offer"]
    assert len(offer_rows) == 2
    labels = {r["subkind"]: r["label"] for r in offer_rows}
    assert "papers" in labels["offer_sent"]
    assert "notes" in labels["offer_received"]


def test_activity_feed_label_differs_by_direction(state: State):
    """offer_accepted on direction=out (peer accepted ours) reads
    differently than direction=in (we accepted theirs)."""
    state.record_folder_lifecycle_event(
        event="offer_accepted", direction="out",
        folder_name="A", peer_fp="aa" * 32,
    )
    state.record_folder_lifecycle_event(
        event="offer_accepted", direction="in",
        folder_name="B", peer_fp="bb" * 32,
    )
    rows = state.activity_feed(kinds=["offer"])
    by_dir = {r["direction"]: r["label"] for r in rows}
    assert "Peer accepted" in by_dir["out"]
    assert "Accepted offer" in by_dir["in"]


def test_activity_feed_failure_event_has_bad_severity(state: State):
    state.record_folder_lifecycle_event(
        event="send_failed", direction="out",
        folder_name="papers", peer_fp="aa" * 32,
        mode="manifest_push",
        severity="bad", error_msg="peer offline",
    )
    rows = state.activity_feed(kinds=["folder"])
    assert len(rows) == 1
    assert rows[0]["severity"] == "bad"
    assert "peer offline" in rows[0]["detail"]


def test_activity_feed_filter_isolates_offer_vs_folder(state: State):
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="A", peer_fp="aa" * 32,
    )
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="A", peer_fp="aa" * 32, mode="archive",
    )
    assert len(state.activity_feed(kinds=["folder"])) == 1
    assert len(state.activity_feed(kinds=["offer"])) == 1
    assert len(state.activity_feed(kinds=["folder", "offer"])) == 2


def test_activity_feed_carries_folder_send_group(state: State):
    """The folder_send_group tag on a summary row lets the UI link
    the parent to its per-file transfer children."""
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="papers", peer_fp="aa" * 32,
        mode="per_file", file_count=3,
        metadata={"folder_send_group": "folder:papers:aabbccdd11223344"},
    )
    rows = state.activity_feed(kinds=["folder"])
    assert rows[0]["folder_send_group"] == (
        "folder:papers:aabbccdd11223344"
    )


def test_activity_feed_orders_newest_first(state: State):
    now = int(time.time() * 1000)
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="A", peer_fp="aa" * 32, ts_ms=now - 10_000,
    )
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="A", peer_fp="aa" * 32, mode="archive",
        ts_ms=now,
    )
    rows = state.activity_feed()
    assert rows[0]["subkind"] == "send_complete"
    assert rows[1]["subkind"] == "offer_sent"


def test_activity_feed_since_ms_clips_old(state: State):
    now = int(time.time() * 1000)
    state.record_folder_lifecycle_event(
        event="offer_sent", direction="out",
        folder_name="A", peer_fp="aa" * 32, ts_ms=now - 60_000,
    )
    state.record_folder_lifecycle_event(
        event="send_complete", direction="out",
        folder_name="A", peer_fp="aa" * 32, mode="archive",
        ts_ms=now,
    )
    recent = state.activity_feed(since_ms=now - 1000)
    assert len(recent) == 1
    assert recent[0]["subkind"] == "send_complete"


# ── transfers rows expose folder_send_group for client-side grouping ─


def test_transfer_row_exposes_folder_send_group(state: State):
    """When the daemon tags a per-file transfer with
    metadata['folder_send_group'], activity_feed should surface
    that key so the UI can group it under the parent folder row."""
    state.upsert_transfer(
        id="t-1",
        direction="out", peer_fp="aa" * 32, kind="file",
        name="f1.py", size=1024, blob_hash="ab" * 32,
        status="complete",
        progress_bytes=1024, total_bytes=1024,
        chunks_done=1, chunks_total=1,
        raw_bytes=1024, wire_bytes=1024,
        metadata={"folder_send_group": "folder:papers:aabbccdd"},
    )
    rows = state.activity_feed(kinds=["transfer"])
    assert len(rows) == 1
    assert rows[0]["folder_send_group"] == "folder:papers:aabbccdd"


def test_transfer_row_without_folder_send_group_omits_key(state: State):
    state.upsert_transfer(
        id="t-2",
        direction="out", peer_fp="aa" * 32, kind="file",
        name="orphan.txt", size=100, blob_hash="cd" * 32,
        status="complete",
        progress_bytes=100, total_bytes=100,
        chunks_done=1, chunks_total=1,
        raw_bytes=100, wire_bytes=100,
        metadata={},
    )
    rows = state.activity_feed(kinds=["transfer"])
    assert len(rows) == 1
    assert "folder_send_group" not in rows[0]
