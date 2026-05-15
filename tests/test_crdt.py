"""CRDT VectorClock + manifest merge tests."""

from __future__ import annotations

import pytest

from one_link.crdt import ManifestEntry, VectorClock, merge_manifest_entries


# ────────────────── VectorClock ──────────────────

def test_empty_clock():
    v = VectorClock.empty()
    assert v.entries == ()
    assert v.get("any") == 0


def test_increment():
    v = VectorClock.empty().increment("a").increment("a").increment("b")
    assert v.get("a") == 2
    assert v.get("b") == 1
    assert v.get("c") == 0


def test_from_dict_roundtrip():
    d = {"a": 3, "b": 1, "c": 0}
    v = VectorClock.from_dict(d)
    # zero-counter entries are stripped (empty doesn't carry them)
    assert v.to_dict() == {"a": 3, "b": 1}


def test_merge_pointwise_max():
    a = VectorClock.from_dict({"x": 2, "y": 1})
    b = VectorClock.from_dict({"x": 1, "y": 5, "z": 1})
    m = a.merge(b)
    assert m.to_dict() == {"x": 2, "y": 5, "z": 1}


def test_happens_before_strict():
    a = VectorClock.from_dict({"x": 1})
    b = VectorClock.from_dict({"x": 2})
    assert a.happens_before(b)
    assert not b.happens_before(a)


def test_happens_before_extended_node():
    a = VectorClock.from_dict({"x": 1})
    b = VectorClock.from_dict({"x": 1, "y": 1})
    assert a.happens_before(b)


def test_equal_clocks_not_happens_before():
    a = VectorClock.from_dict({"x": 1, "y": 1})
    b = VectorClock.from_dict({"x": 1, "y": 1})
    assert not a.happens_before(b)
    assert not b.happens_before(a)
    assert a == b


def test_concurrent():
    a = VectorClock.from_dict({"x": 2, "y": 0})
    b = VectorClock.from_dict({"x": 0, "y": 2})
    assert a.concurrent_with(b)
    assert b.concurrent_with(a)
    assert not a.happens_before(b)
    assert not b.happens_before(a)


def test_clock_is_hashable():
    a = VectorClock.from_dict({"x": 1})
    b = VectorClock.from_dict({"x": 1})
    s = {a, b}
    assert len(s) == 1


# ────────────────── Manifest merge ──────────────────

def _entry(path, hash_, size=10, mtime=1000, clock=None):
    return ManifestEntry(
        file_path=path,
        blob_hash=hash_,
        size=size,
        mtime_ms=mtime,
        vclock=clock or VectorClock.empty(),
    )


def test_merge_one_side_missing():
    a = _entry("f.txt", "aa", clock=VectorClock.from_dict({"X": 1}))
    assert merge_manifest_entries(None, a) is a
    assert merge_manifest_entries(a, None) is a
    assert merge_manifest_entries(None, None) is None


def test_merge_strict_dominance_remote_wins():
    a = _entry("f", "aa", clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "bb", clock=VectorClock.from_dict({"X": 2}))
    assert merge_manifest_entries(a, b).blob_hash == "bb"


def test_merge_strict_dominance_local_wins():
    a = _entry("f", "aa", clock=VectorClock.from_dict({"X": 3}))
    b = _entry("f", "bb", clock=VectorClock.from_dict({"X": 1}))
    assert merge_manifest_entries(a, b).blob_hash == "aa"


def test_merge_concurrent_uses_content_hash_tiebreak():
    """Audit H14 May 2026: tie-break is content-hash, NOT wall-clock
    mtime. A peer with a future-skewed clock previously won every
    concurrent edit by virtue of higher mtime_ms; content-hash
    comparison is adversary-immune (preimage-hard to grind a higher
    hash than honest content).

    The merged entry preserves the later mtime for UI display but
    the winner is decided by hash."""
    a = _entry("f", "aa", mtime=2000,
               clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "bb", mtime=1000,
               clock=VectorClock.from_dict({"Y": 1}))
    out = merge_manifest_entries(a, b)
    # "bb" > "aa" lexically — content-hash wins regardless of mtime
    assert out.blob_hash == "bb"
    # Merged clock observed both
    assert out.vclock.get("X") == 1
    assert out.vclock.get("Y") == 1
    # Wall-clock mtime preserved as max for UI display.
    assert out.mtime_ms == 2000


def test_merge_concurrent_clock_skew_adversary_cant_win():
    """Audit H14 May 2026 regression — explicit attacker scenario:
    malicious peer sets future-skewed mtime (year 9999) but ships
    content with LOWER hash. Honest peer wins on content-hash even
    though its mtime is much smaller."""
    honest = _entry("f", "zz", mtime=1_000_000,  # 1970
                    clock=VectorClock.from_dict({"H": 1}))
    attacker = _entry("f", "aa",
                      mtime=999_999_999_999,  # year ~33658
                      clock=VectorClock.from_dict({"A": 1}))
    out = merge_manifest_entries(honest, attacker)
    # Honest "zz" > attacker "aa"; clock skew didn't help the attacker.
    assert out.blob_hash == "zz"


def test_merge_concurrent_same_hash_falls_back_to_mtime():
    """If two concurrent versions happen to have IDENTICAL content
    hash (extremely unlikely under BLAKE3), pick the one with the
    later mtime for stability — choice is arbitrary but must be
    deterministic across replicas."""
    a = _entry("f", "aa", mtime=2000,
               clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "aa", mtime=1000,
               clock=VectorClock.from_dict({"Y": 1}))
    out = merge_manifest_entries(a, b)
    # Same hash either way.
    assert out.blob_hash == "aa"
    # Later mtime preserved.
    assert out.mtime_ms == 2000


def test_merge_concurrent_delete_loses_to_edit():
    """If one side deleted and the other edited concurrently, the edit
    wins (no data loss)."""
    edit = _entry("f", "aa", mtime=2000,
                  clock=VectorClock.from_dict({"X": 1}))
    delete = _entry("f", None, size=None, mtime=1500,
                    clock=VectorClock.from_dict({"Y": 1}))
    out = merge_manifest_entries(edit, delete)
    assert out.blob_hash == "aa"
    assert out.vclock.get("X") == 1 and out.vclock.get("Y") == 1


def test_merge_both_tombstones_stays_tombstone():
    a = _entry("f", None, size=None,
               clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", None, size=None,
               clock=VectorClock.from_dict({"Y": 1}))
    out = merge_manifest_entries(a, b)
    assert out.blob_hash is None


def test_merge_idempotent():
    a = _entry("f", "aa", clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "bb", clock=VectorClock.from_dict({"X": 2}))
    once = merge_manifest_entries(a, b)
    twice = merge_manifest_entries(once, b)
    assert once.blob_hash == twice.blob_hash
    assert once.vclock == twice.vclock


def test_merge_commutative_on_dominance():
    a = _entry("f", "aa", clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "bb", clock=VectorClock.from_dict({"X": 2}))
    ab = merge_manifest_entries(a, b)
    ba = merge_manifest_entries(b, a)
    assert ab.blob_hash == ba.blob_hash
    assert ab.vclock == ba.vclock


def test_merge_associative_three_way():
    a = _entry("f", "aa", clock=VectorClock.from_dict({"X": 1}))
    b = _entry("f", "bb", clock=VectorClock.from_dict({"X": 2}))
    c = _entry("f", "cc", clock=VectorClock.from_dict({"X": 3}))
    abc = merge_manifest_entries(merge_manifest_entries(a, b), c)
    a_bc = merge_manifest_entries(a, merge_manifest_entries(b, c))
    assert abc.blob_hash == a_bc.blob_hash
    assert abc.vclock == a_bc.vclock


def test_entry_dict_roundtrip():
    e = ManifestEntry(
        file_path="x.bin", blob_hash="ab" * 32, size=11, mtime_ms=1234,
        vclock=VectorClock.from_dict({"P": 5}),
    )
    out = ManifestEntry.from_dict(e.to_dict())
    assert out == e
