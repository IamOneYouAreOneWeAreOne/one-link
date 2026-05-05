from __future__ import annotations

import os
import random

import pytest

from one_link.cdc import (
    AVG_CHUNK_BYTES,
    MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES,
    build_dedup_plan,
    chunk_bytes,
)
from one_link.merkle import build_tree, divergent_leaf_indexes, hash_leaf, manifest_leaf_hashes


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
