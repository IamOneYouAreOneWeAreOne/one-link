"""File engine v2 — algebraic-correctness tests for ``one_link.wal_native``.

Per ADR-0007 verification gates: round-trip records through the WAL,
verify rotation produces multiple files, validate replay across rotated
files preserves order, and prove crash-recovery convergence by injecting
tail corruption and asserting truncation.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from one_link import wal_native


pytestmark = pytest.mark.skipif(
    not wal_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


# ─── basic loadability ────────────────────────────────────────────────


def test_native_constants_present():
    assert wal_native.FILE_HEADER_LEN == 64
    assert wal_native.RECORD_HEADER_LEN == 8
    assert wal_native.RECORD_TRAILER_LEN == 4
    assert wal_native.MAX_PAYLOAD_LEN == 1024 * 1024
    assert wal_native.ROTATION_SIZE == 256 * 1024 * 1024


def test_log_kind_magic_canonical():
    assert wal_native.log_kind_magic("chunk") == b"OL-CLOG1"
    assert wal_native.log_kind_magic("manifest") == b"OL-MLOG1"


def test_unknown_log_kind_rejected():
    with pytest.raises(Exception):
        wal_native.log_kind_magic("invalid")


# ─── single-file append + replay ───────────────────────────────────────


def test_create_and_replay_single_record():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            wal.append(wal_native.WalRecord(kind=0x01, flags=0x05, payload=b"hello"))
            wal.flush()
        records = wal_native.replay_log_dir(d, "chunk")
        assert len(records) == 1
        assert records[0].kind == 0x01
        assert records[0].flags == 0x05
        assert records[0].payload == b"hello"


def test_create_and_replay_multiple_records_in_order():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "manifest") as wal:
            for i in range(20):
                wal.append(
                    wal_native.WalRecord(kind=0x10, flags=i & 0xFF, payload=bytes([i]) * 16)
                )
            wal.flush()
        records = wal_native.replay_log_dir(d, "manifest")
        assert len(records) == 20
        for i, r in enumerate(records):
            assert r.flags == i & 0xFF
            assert r.payload == bytes([i]) * 16


def test_empty_dir_replay():
    with tempfile.TemporaryDirectory() as d:
        records = wal_native.replay_log_dir(d, "chunk")
        assert records == []


# ─── rotation across files ─────────────────────────────────────────────


def test_rotation_creates_multiple_files():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            wal.append(wal_native.WalRecord(kind=0x01, flags=0xAA, payload=b"a"))
            wal.flush()
            assert wal.active_file_id() == 1
            wal.rotate()
            assert wal.active_file_id() == 2
            wal.append(wal_native.WalRecord(kind=0x01, flags=0xBB, payload=b"b"))
            wal.flush()
        # Files exist:
        files = sorted(os.listdir(d))
        assert files == ["000001.wal", "000002.wal"]
        # Replay preserves order:
        records = wal_native.replay_log_dir(d, "chunk")
        assert len(records) == 2
        assert records[0].flags == 0xAA
        assert records[1].flags == 0xBB


def test_open_resumes_from_highest_file():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "manifest") as wal:
            wal.append(wal_native.WalRecord(kind=0x10, flags=0x00, payload=b"first"))
            wal.flush()
            wal.rotate()
            wal.append(wal_native.WalRecord(kind=0x10, flags=0x01, payload=b"second"))
            wal.flush()
        # Reopen.
        with wal_native.Wal.open(d, "manifest") as wal2:
            assert wal2.active_file_id() == 2
            wal2.append(wal_native.WalRecord(kind=0x10, flags=0x02, payload=b"third"))
            wal2.flush()
        records = wal_native.replay_log_dir(d, "manifest")
        assert len(records) == 3
        assert [r.flags for r in records] == [0x00, 0x01, 0x02]


# ─── crash recovery / tail truncation ──────────────────────────────────


def test_tail_truncation_on_crc_corruption():
    """Corrupt the last byte (CRC) of the file; recovery drops the last record."""
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            wal.append(wal_native.WalRecord(kind=0x01, flags=0x00, payload=b"first"))
            wal.append(wal_native.WalRecord(kind=0x01, flags=0x00, payload=b"second"))
            wal.flush()
        path = os.path.join(d, "000001.wal")
        with open(path, "rb+") as f:
            f.seek(-1, 2)
            tail = f.read(1)
            f.seek(-1, 2)
            f.write(bytes([(tail[0] ^ 0xFF) & 0xFF]))
        records = wal_native.replay_log_dir(d, "chunk")
        # First record survives; second was tail-truncated.
        assert len(records) == 1
        assert records[0].payload == b"first"


def test_tail_truncation_on_short_payload():
    """Append a torn record header (length field exceeds remaining bytes)."""
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            wal.append(wal_native.WalRecord(kind=0x01, flags=0x00, payload=b"complete"))
            wal.flush()
        path = os.path.join(d, "000001.wal")
        # Append a torn header: kind=0x99, flags=0, reserved=0, length=100, no body.
        with open(path, "ab") as f:
            f.write(bytes([0x99, 0x00, 0x00, 0x00, 100, 0, 0, 0]))
        records = wal_native.replay_log_dir(d, "chunk")
        assert len(records) == 1
        assert records[0].payload == b"complete"


# ─── argument validation ──────────────────────────────────────────────


def test_oversize_payload_rejected():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            big = b"x" * (wal_native.MAX_PAYLOAD_LEN + 1)
            with pytest.raises(Exception):
                wal.append(wal_native.WalRecord(kind=0x01, flags=0x00, payload=big))


def test_unknown_log_kind_rejected_on_create():
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(Exception):
            wal_native.Wal.create(d, "garbage")


def test_kind_mismatch_rejected_on_replay():
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            wal.append(wal_native.WalRecord(kind=0x01, flags=0x00, payload=b"x"))
            wal.flush()
        with pytest.raises(Exception):
            wal_native.replay_log_dir(d, "manifest")


# ─── determinism ──────────────────────────────────────────────────────


def test_replay_determinism_across_runs():
    """Same on-disk state must produce byte-identical recovered records."""
    with tempfile.TemporaryDirectory() as d:
        with wal_native.Wal.create(d, "chunk") as wal:
            for i in range(50):
                wal.append(
                    wal_native.WalRecord(kind=0x01, flags=i & 0xFF, payload=bytes([i]) * 8)
                )
            wal.flush()
        a = wal_native.replay_log_dir(d, "chunk")
        b = wal_native.replay_log_dir(d, "chunk")
        assert a == b
