from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link.blobstore import BlobStore


def test_verify_detects_corrupt_blob(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    h = store.put_bytes(b"truth")
    assert store.verify(h) is True
    store.path(h).write_bytes(b"tampered")
    assert store.verify(h) is False
    audit = store.audit()
    assert audit["ok"] is False
    assert audit["corrupt"][0]["hash"] == h


def test_writer_exception_cleans_temp_and_publishes_nothing(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    with pytest.raises(RuntimeError):
        with store.writer() as (w, tmp):
            w.write(b"partial")
            assert tmp.exists()
            raise RuntimeError("simulated receiver crash")
    assert list(store.iter_blobs()) == []
    assert list((store.root / "_tmp").iterdir()) == []


def test_cleanup_tmp_removes_abandoned_temp_files(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    abandoned = store.root / "_tmp" / "put_abandoned"
    abandoned.write_bytes(b"unfinished")
    removed = store.cleanup_tmp(older_than_ms=0)
    assert removed == 1
    assert not abandoned.exists()


def test_audit_all_clear_after_multiple_valid_blobs(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    for i in range(5):
        store.put_bytes(os.urandom(1024 + i))
    audit = store.audit()
    assert audit["ok"] is True
    assert audit["blobs"] == 5
    assert audit["verified"] == 5
    assert audit["corrupt"] == []
