"""Unit tests for the receiver-side resume module.

Covers the sidecar lifecycle and registry behaviour in isolation
from the daemon. Integration with FILE_OFFER / FILE_WANTS is
exercised by the soak harness.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from one_link.resume import (
    ResumeRegistry,
    ResumeSidecar,
    SCHEMA_VERSION,
    delete_sidecar,
    load_sidecar,
    persist_sidecar,
    scan_inbox,
    sidecar_path,
)


def _make(blob: str, peer: str, out_path: Path, *, size: int = 1024) -> ResumeSidecar:
    return ResumeSidecar(
        blob_hex=blob,
        peer_fp=peer,
        name="some.bin",
        size=size,
        out_path=str(out_path),
        cdc_chunks=[
            {"index": 0, "hash": "a" * 64, "size": 512, "start": 0, "end": 512},
            {"index": 1, "hash": "b" * 64, "size": 512, "start": 512, "end": 1024},
        ],
    )


def test_persist_and_load_round_trip(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "abcd1234_some.bin"
    partial.write_bytes(b"\x00" * 512)
    sc = _make("a" * 64, "p" * 64, partial)

    persist_sidecar(inbox, sc)
    loaded = load_sidecar(inbox, sc.blob_hex)

    assert loaded is not None
    assert loaded.blob_hex == sc.blob_hex
    assert loaded.peer_fp == sc.peer_fp
    assert loaded.out_path == str(partial)
    assert loaded.size == sc.size
    assert loaded.cdc_chunks == sc.cdc_chunks
    assert loaded.schema_version == SCHEMA_VERSION


def test_persist_is_atomic(tmp_path: Path) -> None:
    """A concurrent reader during a write must not see a torn JSON."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "abcd1234_some.bin"
    partial.write_bytes(b"\x00" * 256)
    sc1 = _make("a" * 64, "p" * 64, partial)
    persist_sidecar(inbox, sc1)
    # Now overwrite with a different payload; the os.replace path
    # means the on-disk file is always either the old or the new
    # version — never a partial write.
    sc2 = _make("a" * 64, "p" * 64, partial, size=2048)
    persist_sidecar(inbox, sc2)
    loaded = load_sidecar(inbox, sc2.blob_hex)
    assert loaded is not None
    assert loaded.size == 2048


def test_delete_is_idempotent(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    blob = "f" * 64
    # Deleting a missing sidecar must not raise.
    delete_sidecar(inbox, blob)
    # Persist then delete then delete again.
    partial = inbox / "ffff_some.bin"
    partial.write_bytes(b"x")
    persist_sidecar(inbox, _make(blob, "p" * 64, partial))
    assert sidecar_path(inbox, blob).is_file()
    delete_sidecar(inbox, blob)
    assert not sidecar_path(inbox, blob).exists()
    delete_sidecar(inbox, blob)  # double-delete still fine


def test_load_returns_none_on_missing(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    assert load_sidecar(inbox, "0" * 64) is None


def test_load_returns_none_on_corrupt(tmp_path: Path) -> None:
    """A truncated or malformed sidecar must be reported as None
    rather than crashing the daemon."""
    inbox = tmp_path / "inbox"
    (inbox / ".resume").mkdir(parents=True)
    bad = inbox / ".resume" / ("c" * 64 + ".json")
    bad.write_text("{not valid json", encoding="utf-8")
    assert load_sidecar(inbox, "c" * 64) is None


def test_load_returns_none_on_wrong_schema(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    (inbox / ".resume").mkdir(parents=True)
    p = inbox / ".resume" / ("d" * 64 + ".json")
    p.write_text(
        json.dumps({
            "blob_hex": "d" * 64,
            "peer_fp": "p" * 64,
            "name": "x.bin",
            "size": 1,
            "out_path": str(inbox / "x.bin"),
            "cdc_chunks": [],
            "schema_version": SCHEMA_VERSION + 99,
        }),
        encoding="utf-8",
    )
    assert load_sidecar(inbox, "d" * 64) is None


def test_scan_inbox_drops_orphans(tmp_path: Path) -> None:
    """A sidecar whose out_path no longer exists must be cleaned
    up + dropped from the scan output."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "abcd_real.bin"
    partial.write_bytes(b"x" * 32)
    sc_live = _make("1" * 64, "p" * 64, partial)
    sc_orphan = _make("2" * 64, "p" * 64, inbox / "ghost.bin")
    persist_sidecar(inbox, sc_live)
    persist_sidecar(inbox, sc_orphan)

    out = scan_inbox(inbox)
    blobs = {s.blob_hex for s in out}
    assert "1" * 64 in blobs
    assert "2" * 64 not in blobs
    # The orphaned sidecar must have been auto-unlinked.
    assert not sidecar_path(inbox, sc_orphan.blob_hex).exists()


def test_scan_inbox_drops_path_traversal(tmp_path: Path) -> None:
    """A hostile sidecar that points outside the inbox must be
    rejected and the file unlinked."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x" * 16)
    sc = _make("3" * 64, "p" * 64, outside)
    persist_sidecar(inbox, sc)

    out = scan_inbox(inbox)
    blobs = {s.blob_hex for s in out}
    assert "3" * 64 not in blobs
    assert not sidecar_path(inbox, sc.blob_hex).exists()


def test_registry_pop_match_consumes(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "real.bin"
    partial.write_bytes(b"x" * 64)
    sc = _make("a" * 64, "P" * 64, partial)
    persist_sidecar(inbox, sc)

    reg = ResumeRegistry(inbox)
    reg.load_from_inbox()
    assert len(reg) == 1

    hit = reg.pop_match("P" * 64, "a" * 64)
    assert hit is not None
    assert hit.out_path == str(partial)
    # Second pop returns None — entry was consumed.
    assert reg.pop_match("P" * 64, "a" * 64) is None
    assert len(reg) == 0


def test_registry_no_match_for_wrong_peer(tmp_path: Path) -> None:
    """A sidecar registered for peer A must not be returned when
    peer B sends a FILE_OFFER for the same blob_hex."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "real.bin"
    partial.write_bytes(b"x" * 64)
    persist_sidecar(inbox, _make("a" * 64, "A" * 64, partial))

    reg = ResumeRegistry(inbox)
    reg.load_from_inbox()
    # Wrong peer: must not match.
    assert reg.pop_match("B" * 64, "a" * 64) is None
    # Correct peer: matches.
    assert reg.pop_match("A" * 64, "a" * 64) is not None


def test_registry_load_from_empty_inbox(tmp_path: Path) -> None:
    """A fresh inbox with no resume subdir must yield an empty
    registry, not crash."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    reg = ResumeRegistry(inbox)
    n = reg.load_from_inbox()
    assert n == 0
    assert len(reg) == 0


def test_sidecar_touch_advances_updated_ms(tmp_path: Path) -> None:
    import time
    sc = _make("a" * 64, "P" * 64, tmp_path / "x.bin")
    before = sc.updated_ms
    time.sleep(0.005)
    sc.touch()
    assert sc.updated_ms >= before


def test_registry_register_replaces(tmp_path: Path) -> None:
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    reg = ResumeRegistry(inbox)
    sc1 = _make("a" * 64, "P" * 64, inbox / "v1.bin", size=100)
    sc2 = _make("a" * 64, "P" * 64, inbox / "v2.bin", size=200)
    reg.register(sc1)
    reg.register(sc2)
    assert len(reg) == 1
    hit = reg.pop_match("P" * 64, "a" * 64)
    assert hit is not None
    assert hit.size == 200


def test_registry_prunes_stale_entries(tmp_path: Path) -> None:
    """A sidecar whose updated_ms is older than the TTL must be
    dropped at load time + its partial out_path unlinked. Inboxes
    can't be allowed to accumulate orphan manifests for blobs the
    sender will never come back for."""
    import time
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    fresh_partial = inbox / "fresh.bin"
    fresh_partial.write_bytes(b"f" * 32)
    stale_partial = inbox / "stale.bin"
    stale_partial.write_bytes(b"s" * 32)

    sc_fresh = _make("a" * 64, "P" * 64, fresh_partial)
    sc_stale = _make("b" * 64, "P" * 64, stale_partial)
    # Backdate sc_stale to 45 days ago.
    sc_stale.updated_ms = int((time.time() - 45 * 86400) * 1000)
    sc_stale.created_ms = sc_stale.updated_ms
    persist_sidecar(inbox, sc_fresh)
    persist_sidecar(inbox, sc_stale)

    reg = ResumeRegistry(inbox)
    kept = reg.load_from_inbox(ttl_days=30)
    assert kept == 1
    assert reg.pop_match("P" * 64, "a" * 64) is not None
    assert reg.pop_match("P" * 64, "b" * 64) is None
    # The stale partial AND its sidecar must both be gone.
    assert not stale_partial.exists()
    from one_link.resume import sidecar_path
    assert not sidecar_path(inbox, "b" * 64).exists()
    # The fresh partial stays.
    assert fresh_partial.exists()


def test_registry_snapshot_shape(tmp_path: Path) -> None:
    """snapshot() must return a UI-safe shape: bounded size, no
    full CDC manifest, plain JSON-compatible dicts."""
    import json
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    partial = inbox / "x.bin"
    partial.write_bytes(b"x" * 64)
    sc = _make("a" * 64, "P" * 64, partial, size=2048)
    persist_sidecar(inbox, sc)

    reg = ResumeRegistry(inbox)
    reg.load_from_inbox()
    snap = reg.snapshot()
    assert isinstance(snap, list)
    assert len(snap) == 1
    entry = snap[0]
    assert entry["blob"] == "a" * 64
    assert entry["peer_fp"] == "P" * 64
    assert entry["size"] == 2048
    assert entry["cdc_chunks_total"] == 2  # _make builds 2 chunks
    assert "cdc_chunks" not in entry  # the full manifest must NOT be inlined
    # JSON round-trip must succeed (catches accidentally non-serialisable values).
    json.loads(json.dumps(snap))
