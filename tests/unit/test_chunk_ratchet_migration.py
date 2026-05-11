"""Phase C-3 daemon migration: chunk_ratchet.ChunkRatchet (per-chunk
forward-secret ratchet, ADR-0020).

Verifies forward-secrecy property + sender/receiver in-order +
out-of-order skipped-key handling.
"""

from __future__ import annotations

import pytest


def _native_available() -> bool:
    try:
        from one_link import ratchet_native

        return ratchet_native.HAS_NATIVE
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.ratchet not installed (build via maturin)",
)


def test_sender_receiver_in_order_round_trip():
    from one_link.chunk_ratchet import ChunkRatchet

    ss = b"\x42" * 32
    sender = ChunkRatchet.from_shared_secret(ss)
    receiver = ChunkRatchet.from_shared_secret(ss)

    # Sender + receiver matched: same shared secret => same keys.
    for expected_idx in range(10):
        sk, sidx = sender.next_key()
        rk, ridx = receiver.next_key()
        assert sk == rk, f"keys diverged at idx {expected_idx}"
        assert sidx == ridx == expected_idx


def test_keys_are_distinct_per_chunk():
    """Forward secrecy property: every chunk-key must be distinct.
    A repeat would mean two chunks share the same AEAD key, which
    is catastrophic with a 96-bit nonce."""
    from one_link.chunk_ratchet import ChunkRatchet

    r = ChunkRatchet.from_shared_secret(b"\x33" * 32)
    seen = set()
    for _ in range(100):
        k, _ = r.next_key()
        assert k not in seen, "chunk-key collision in 100 steps"
        seen.add(k)
    assert len(seen) == 100


def test_distinct_shared_secrets_produce_distinct_chains():
    from one_link.chunk_ratchet import ChunkRatchet

    a = ChunkRatchet.from_shared_secret(b"\x11" * 32)
    b = ChunkRatchet.from_shared_secret(b"\x22" * 32)
    ka, _ = a.next_key()
    kb, _ = b.next_key()
    assert ka != kb


def test_shared_secret_size_validated():
    from one_link.chunk_ratchet import ChunkRatchet

    with pytest.raises(ValueError):
        ChunkRatchet.from_shared_secret(b"too short")


def test_out_of_order_via_skipped_store():
    """Receiver gets chunk #3 before chunks #0..#2: must derive #3 by
    skipping ahead, stash #0..#2 in the skipped store, then satisfy
    later reads from the store."""
    from one_link.chunk_ratchet import ChunkRatchet

    ss = b"\x77" * 32
    sender = ChunkRatchet.from_shared_secret(ss)
    receiver = ChunkRatchet.from_shared_secret(ss)
    skipped = receiver.skipped_store(cap=32)

    # Sender produces 4 keys, ships them out-of-order: ship #3 first.
    sent_keys = []
    for _ in range(4):
        sent_keys.append(sender.next_key()[0])

    # Receiver pulls #3 first. This forces it to derive #0/#1/#2 and
    # stash them; the resulting key for #3 must equal sent[3].
    r3 = receiver.key_at(3, skipped=skipped)
    assert r3 == sent_keys[3]

    # Now backfill #0, #1, #2 from the skipped store.
    for idx in (0, 1, 2):
        rk = receiver.key_at(idx, skipped=skipped)
        assert rk == sent_keys[idx], f"key mismatch at idx {idx}"


def test_derive_chunk_key_convenience():
    """Single-shot derive_chunk_key matches the chain output."""
    from one_link.chunk_ratchet import ChunkRatchet, derive_chunk_key

    ss = b"\x55" * 32
    r = ChunkRatchet.from_shared_secret(ss)
    chain_keys = [r.next_key()[0] for _ in range(5)]
    for i in range(5):
        assert derive_chunk_key(ss, i) == chain_keys[i]


def test_peek_does_not_advance():
    from one_link.chunk_ratchet import ChunkRatchet

    r = ChunkRatchet.from_shared_secret(b"\x99" * 32)
    peek_a = r.peek_at_current()
    peek_b = r.peek_at_current()
    assert peek_a == peek_b
    assert r.current_index == 0
    # After advancing, peek changes.
    _, _ = r.next_key()
    peek_c = r.peek_at_current()
    assert peek_c != peek_a
