from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import blake3
import pytest

import one_link.blobstore as blobstore_module
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


def test_existing_corrupt_address_is_repaired_by_put_bytes(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    payload = b"self-healing-cas" * 4096
    h = store.put_bytes(payload)
    store.path(h).write_bytes(b"poison")

    assert store.put_bytes(payload) == h
    assert store.read_bytes(h) == payload
    assert store.verify(h)


def test_failed_has_never_unlinks_concurrent_correct_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stale failed verifier must not delete a newer correct CAS object."""

    store = BlobStore(tmp_path / "blobs")
    payload = b"concurrent-correct-publication" * 4096
    hash_hex = blake3.blake3(payload).hexdigest()
    addressed_path = store.path(hash_hex)
    addressed_path.parent.mkdir(parents=True)
    addressed_path.write_bytes(b"poisoned-address")

    verification_finished = threading.Event()
    allow_has_to_finish = threading.Event()
    original_verify = store._verify_path

    def paused_failed_verify(path: Path, expected_hash: str) -> bool:
        verified = original_verify(path, expected_hash)
        assert verified is False
        verification_finished.set()
        assert allow_has_to_finish.wait(timeout=5)
        return verified

    monkeypatch.setattr(store, "_verify_path", paused_failed_verify)
    replacement = store.root / "_tmp" / "concurrent-correct"
    replacement.write_bytes(payload)

    with ThreadPoolExecutor(max_workers=1) as pool:
        pending_has = pool.submit(store.has, hash_hex)
        assert verification_finished.wait(timeout=5)
        os.replace(replacement, addressed_path)
        allow_has_to_finish.set()
        assert pending_has.result(timeout=5) is False

    # The in-flight lookup remains fail-closed, but its stale result must not
    # remove the correct object that won the atomic publication race.
    monkeypatch.setattr(store, "_verify_path", original_verify)
    assert addressed_path.read_bytes() == payload
    assert store.has(hash_hex) is True


def test_put_path_commits_the_bytes_from_the_hashed_handle(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    src = tmp_path / "source.bin"
    payload = os.urandom(512 * 1024)
    src.write_bytes(payload)

    h = store.put_path(src)
    assert h == __import__("blake3").blake3(payload).hexdigest()
    assert store.read_bytes(h) == payload


def test_put_path_rejects_source_mutation_during_stream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = BlobStore(tmp_path / "blobs")
    source = tmp_path / "source.bin"
    source.write_bytes(b"before" * (1024 * 1024))

    first_fstat_captured = threading.Event()
    allow_streaming = threading.Event()
    original_fstat = blobstore_module.os.fstat
    calls = 0
    calls_lock = threading.Lock()

    def paused_fstat(fd: int) -> os.stat_result:
        nonlocal calls
        result = original_fstat(fd)
        with calls_lock:
            calls += 1
            this_call = calls
        if this_call == 1:
            first_fstat_captured.set()
            assert allow_streaming.wait(timeout=5)
        return result

    monkeypatch.setattr(blobstore_module.os, "fstat", paused_fstat)
    with ThreadPoolExecutor(max_workers=1) as pool:
        ingest = pool.submit(store.put_path, source)
        assert first_fstat_captured.wait(timeout=5)
        with open(source, "ab") as mutated:
            mutated.write(b"concurrent-generation")
            mutated.flush()
            os.fsync(mutated.fileno())
        allow_streaming.set()
        with pytest.raises(OSError, match="changed while hashing"):
            ingest.result(timeout=5)

    assert list(store.iter_blobs()) == []
    assert list((store.root / "_tmp").iterdir()) == []


def test_put_path_rejects_symlink_source(tmp_path: Path):
    store = BlobStore(tmp_path / "blobs")
    target = tmp_path / "outside.bin"
    target.write_bytes(b"outside")
    link = tmp_path / "inside-link.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")

    with pytest.raises(ValueError, match="non-symlink"):
        store.put_path(link)
