from __future__ import annotations

import os
import random

import pytest

from one_link.cdc import (
    MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES,
    build_dedup_plan,
    chunk_bytes,
    index_path,
)
from one_link.merkle import build_tree, divergent_leaf_indexes, hash_leaf, manifest_leaf_hashes


def test_native_cdc_matches_python_fallback(monkeypatch, tmp_path):
    data = random.Random(20260508).randbytes(MAX_CHUNK_BYTES * 5 + 777)
    p = tmp_path / "native-check.bin"
    p.write_bytes(data)

    monkeypatch.setenv("ONE_LINK_DISABLE_NATIVE_CDC", "1")
    python_chunks = chunk_bytes(data)
    python_idx = index_path(p, read_size=8192)

    monkeypatch.delenv("ONE_LINK_DISABLE_NATIVE_CDC", raising=False)
    native_chunks = chunk_bytes(data)
    native_idx = index_path(p, read_size=8192)

    assert native_chunks == python_chunks
    assert native_idx == python_idx


def test_cdc_chunk_sizes_are_bounded_for_large_payload():
    chunks = chunk_bytes(os.urandom(MAX_CHUNK_BYTES * 2 + 123))

    assert len(chunks) >= 2
    assert chunks[0].start == 0
    assert chunks[-1].end == MAX_CHUNK_BYTES * 2 + 123
    assert all(c.size <= MAX_CHUNK_BYTES for c in chunks)
    assert all(c.size >= MIN_CHUNK_BYTES for c in chunks[:-1])


def test_cdc_is_deterministic_and_offset_resistant():
    base = random.Random(1234).randbytes(MAX_CHUNK_BYTES * 8)
    changed = b"prefix" + base

    a = chunk_bytes(base)
    b = chunk_bytes(changed)

    assert [c.hash for c in a] == [c.hash for c in chunk_bytes(base)]
    assert len(set(c.hash for c in a) & set(c.hash for c in b)) >= 1


def test_dedup_plan_counts_missing_bytes():
    chunks = chunk_bytes(b"x" * (MAX_CHUNK_BYTES + 1))
    known = {chunks[0].hash}

    plan = build_dedup_plan(chunks, known)

    assert plan.total_chunks == len(chunks)
    assert plan.bytes_to_send == sum(c.size for c in chunks[1:])
    assert plan.byte_savings == chunks[0].size
    assert plan.hit_rate > 0


def test_index_path_streams_whole_file_hash_and_chunks(tmp_path):
    p = tmp_path / "big.bin"
    data = random.Random(88).randbytes(MAX_CHUNK_BYTES * 3 + 99)
    p.write_bytes(data)

    idx = index_path(p, read_size=8192)

    import blake3

    assert idx.blob_hash == blake3.blake3(data).hexdigest()
    assert idx.size == len(data)
    assert idx.chunks == chunk_bytes(data)


def test_merkle_root_changes_when_leaf_changes():
    a = build_tree([hash_leaf("a"), hash_leaf("b"), hash_leaf("c")])
    b = build_tree([hash_leaf("a"), hash_leaf("B"), hash_leaf("c")])

    assert a.root != b.root
    assert divergent_leaf_indexes(a, b) == (1,)


def test_merkle_manifest_hashes_are_sorted_and_validated():
    rows_a = [("b.txt", "bb" * 32, 2), ("a.txt", "aa" * 32, 1)]
    rows_b = list(reversed(rows_a))

    assert manifest_leaf_hashes(rows_a) == manifest_leaf_hashes(rows_b)
    assert build_tree(manifest_leaf_hashes(rows_a)).root

    with pytest.raises(ValueError):
        build_tree(["not-a-hash"])


def test_merkle_reports_added_leaf():
    a = build_tree([hash_leaf("a")])
    b = build_tree([hash_leaf("a"), hash_leaf("b")])

    assert divergent_leaf_indexes(a, b) == (1,)


def test_merkle_walk_prunes_identical_subtrees():
    leaves_a = [hash_leaf(f"item-{i}") for i in range(128)]
    leaves_b = list(leaves_a)
    leaves_b[73] = hash_leaf("changed")

    assert divergent_leaf_indexes(build_tree(leaves_a), build_tree(leaves_b)) == (73,)
