"""ADR-0018 algebraic-correctness tests for ``one_link.erasure_native``."""

from __future__ import annotations

import pytest

from one_link import erasure_native

pytestmark = pytest.mark.skipif(
    not erasure_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def test_module_metadata() -> None:
    assert erasure_native.NATIVE_VERSION is not None
    assert erasure_native.STANDARD.k == 10
    assert erasure_native.STANDARD.m == 4
    assert erasure_native.EPHEMERAL.k == 9
    assert erasure_native.EPHEMERAL.m == 1
    assert erasure_native.ARCHIVAL.k == 6
    assert erasure_native.ARCHIVAL.m == 6


def test_standard_round_trip() -> None:
    plaintext = b"hello world " * 100  # 1200 bytes
    shards = erasure_native.encode(plaintext, erasure_native.STANDARD)
    assert len(shards) == 14
    # Decode with all shards present.
    decoded = erasure_native.decode(erasure_native.STANDARD, list(shards))
    assert decoded == plaintext


def test_standard_recovery_from_4_erasures() -> None:
    plaintext = bytes(range(256)) * 10  # 2560 bytes
    shards = erasure_native.encode(plaintext, erasure_native.STANDARD)
    # Drop shards 0, 4, 11, 13.
    present = list(shards)
    for i in (0, 4, 11, 13):
        present[i] = None
    decoded = erasure_native.decode(erasure_native.STANDARD, present)
    assert decoded == plaintext


def test_stripe_id_deterministic() -> None:
    pt = b"deterministic stripe id input bytes"
    id1 = erasure_native.stripe_id(pt, erasure_native.STANDARD)
    id2 = erasure_native.stripe_id(pt, erasure_native.STANDARD)
    assert id1 == id2
    assert len(id1) == 32

    # Different params → different StripeId.
    id3 = erasure_native.stripe_id(pt, erasure_native.ARCHIVAL)
    assert id3 != id1


def test_stripe_id_pinned_determinism() -> None:
    """Cross-platform: matches the Rust-side determinism vector
    pinned in ol_erasure/tests/determinism.rs."""
    pt = bytes([(i * 31) & 0xFF for i in range(200)])
    id_std = erasure_native.stripe_id(pt, erasure_native.STANDARD)
    expected = "b0471f2170da648b76ffe84f156853ea4b50c93ff2e522878738ee998b291994"
    assert id_std.hex() == expected


def test_shard_metadata() -> None:
    shards = erasure_native.encode(b"x" * 100, erasure_native.STANDARD)
    assert shards[0].role == "data"
    assert shards[0].index == 0
    assert shards[0].plaintext_len == 100
    assert shards[10].role == "parity"
    assert shards[10].index == 0
    # All shards share the same StripeId.
    assert shards[0].stripe_id == shards[13].stripe_id


def test_rejects_wrong_present_count() -> None:
    with pytest.raises(Exception):
        erasure_native.decode(erasure_native.STANDARD, [])


def test_custom_params() -> None:
    custom = erasure_native.params(5, 2)
    assert custom.k == 5
    assert custom.m == 2
    shards = erasure_native.encode(b"hi" * 50, custom)
    assert len(shards) == 7
    decoded = erasure_native.decode(custom, list(shards))
    assert decoded == b"hi" * 50
