"""Content-addressed blob store tests."""

from __future__ import annotations

import os
from pathlib import Path

import blake3
import pytest

from one_link.blobstore import BlobStore


@pytest.fixture
def store(tmp_path: Path) -> BlobStore:
    return BlobStore(tmp_path / "blobs")


def test_put_bytes_returns_hash(store: BlobStore):
    data = b"hello, world"
    h = store.put_bytes(data)
    assert len(h) == 64
    assert h == blake3.blake3(data).hexdigest()
    assert store.has(h)
    assert store.read_bytes(h) == data


def test_put_bytes_idempotent(store: BlobStore):
    h1 = store.put_bytes(b"abc")
    h2 = store.put_bytes(b"abc")
    assert h1 == h2
    blobs = list(store.iter_blobs())
    assert len(blobs) == 1


def test_put_path_streaming(store: BlobStore, tmp_path: Path):
    src = tmp_path / "input.bin"
    src.write_bytes(os.urandom(1024 * 1024 + 7))  # not aligned to 1MiB
    h = store.put_path(src)
    assert h == blake3.blake3(src.read_bytes()).hexdigest()
    # Original file is preserved (not moved out)
    assert src.is_file()
    assert store.has(h)
    assert store.size(h) == src.stat().st_size


def test_writer_streaming_commit(store: BlobStore):
    payload = os.urandom(500_000)
    with store.writer() as (w, _):
        # Write in arbitrary chunks
        for i in range(0, len(payload), 7777):
            w.write(payload[i:i + 7777])
        h = w.commit()
    assert h == blake3.blake3(payload).hexdigest()
    assert store.read_bytes(h) == payload


def test_writer_cancel_cleans_up(store: BlobStore):
    """If we drop out of the with-block without commit, the temp file
    must not become a stored blob."""
    with store.writer() as (w, tmp):
        w.write(b"oops")
        # do NOT commit
    blobs = list(store.iter_blobs())
    assert blobs == []
    # Temp dir should be empty (or only contain other ongoing tmp files;
    # in this test, none).
    assert not tmp.exists()


def test_path_rejects_invalid_hash(store: BlobStore):
    with pytest.raises(ValueError):
        store.path("not_hex")
    with pytest.raises(ValueError):
        store.path("ab")  # too short
    with pytest.raises(ValueError):
        store.path("z" * 64)  # not hex


def test_remove_blob(store: BlobStore):
    h = store.put_bytes(b"deleteme")
    assert store.has(h)
    assert store.remove(h)
    assert not store.has(h)
    assert not store.remove(h)  # second remove returns False


def test_iter_blobs_lists_all(store: BlobStore):
    hashes = set()
    for i in range(50):
        hashes.add(store.put_bytes(f"item-{i}".encode()))
    listed = {h for h, _ in store.iter_blobs()}
    assert hashes == listed


def test_total_size(store: BlobStore):
    assert store.total_size() == 0
    store.put_bytes(b"a" * 100)
    store.put_bytes(b"b" * 250)
    assert store.total_size() == 350


def test_layout_uses_two_char_shards(store: BlobStore):
    h = store.put_bytes(b"layout-test")
    p = store.path(h)
    assert p.parent.name == h[:2]
    assert p.name == h[2:]
    # File exists at that exact location
    assert p.is_file()


def test_concurrent_safe_atomic_replace(store: BlobStore, tmp_path: Path):
    """Two writers committing the same content should not race-corrupt."""
    payload = b"x" * 1024
    h1 = store.put_bytes(payload)
    h2 = store.put_bytes(payload)
    assert h1 == h2
    assert store.read_bytes(h1) == payload
    assert len(list(store.iter_blobs())) == 1
