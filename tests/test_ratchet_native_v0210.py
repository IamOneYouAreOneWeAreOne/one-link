"""ADR-0020 algebraic-correctness tests for ``one_link.ratchet_native``.

Verifies the Python binding for the per-chunk forward-secret chain.
"""

from __future__ import annotations

import pytest

from one_link import ratchet_native

pytestmark = pytest.mark.skipif(
    not ratchet_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def test_module_metadata() -> None:
    assert ratchet_native.NATIVE_VERSION is not None
    assert ratchet_native.DEFAULT_SKIPPED_CAP == 1024


def test_chain_advances_per_step() -> None:
    chain = ratchet_native.from_shared_secret(b"\x42" * 32)
    assert chain.step == 0
    mk0 = chain.next_message_key()
    assert len(mk0) == 32
    assert chain.step == 1
    mk1 = chain.next_message_key()
    assert mk0 != mk1
    assert chain.step == 2


def test_chain_pinned_determinism() -> None:
    """The first three message keys for a fixed shared secret are
    pinned in the Rust crate's `cross_platform_first_three_message_keys_pinned`
    test. This Python test confirms the binding round-trips them
    byte-exactly.
    """
    chain = ratchet_native.from_shared_secret(b"\x42" * 32)
    mk0 = chain.next_message_key().hex()
    mk1 = chain.next_message_key().hex()
    mk2 = chain.next_message_key().hex()
    assert mk0 == "c8c5d3af981a7377b8ff185f03374594edd10d5cb428744f537bbc31bc781d0e"
    assert mk1 == "e61b19efb755ce38fae328c9ed27f0e95ba7a0b461a196ed77d552f9681b4b76"
    assert mk2 == "177d7568b7354fa5d66560c39b17ba4aeff283dbbe8df3c0c51db04b4e23b601"


def test_distinct_secrets_yield_distinct_keys() -> None:
    a = ratchet_native.from_shared_secret(b"\xAA" * 32)
    b = ratchet_native.from_shared_secret(b"\xBB" * 32)
    assert a.next_message_key() != b.next_message_key()


def test_fast_forward_matches_iteration() -> None:
    a = ratchet_native.from_shared_secret(b"\x77" * 32)
    b = ratchet_native.from_shared_secret(b"\x77" * 32)
    a.fast_forward(5)
    for _ in range(5):
        b.next_message_key()
    assert a.step == 5
    assert b.step == 5
    assert a.next_message_key() == b.next_message_key()


def test_peek_does_not_advance() -> None:
    a = ratchet_native.from_shared_secret(b"\x33" * 32)
    peeked = a.peek_message_key(3)
    assert a.step == 0
    # Iterate to step 3 in a fresh chain and compare.
    b = ratchet_native.from_shared_secret(b"\x33" * 32)
    for _ in range(3):
        b.next_message_key()
    assert peeked == b.next_message_key()


def test_skipped_store_insert_take() -> None:
    store = ratchet_native.skipped_store(cap=8)
    key = b"\xAA" * 32
    store.insert(3, key)
    assert len(store) == 1
    taken = store.take(3)
    assert taken == key
    assert len(store) == 0


def test_skipped_store_take_missing_raises() -> None:
    store = ratchet_native.skipped_store(cap=8)
    with pytest.raises(Exception):
        store.take(42)


def test_skipped_store_eviction_at_capacity() -> None:
    store = ratchet_native.skipped_store(cap=3)
    for i in range(5):
        store.insert(i, bytes([i]) * 32)
    assert len(store) == 3
    # First two evicted; last three retained.
    with pytest.raises(Exception):
        store.take(0)
    assert store.take(4) == b"\x04" * 32


def test_chain_repr_includes_step() -> None:
    chain = ratchet_native.from_shared_secret(b"\x00" * 32)
    assert "step=0" in repr(chain)
