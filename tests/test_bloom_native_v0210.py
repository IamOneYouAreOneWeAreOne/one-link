"""ADR-0011 algebraic-correctness tests for ``one_link.bloom_native``.

The Bloom filter is the transfer-init handshake's heart. These tests
exercise:

- module loadability + version exposure
- construction with target FP rate
- insert / contains correctness on inserted ids
- false-positive rate empirically near target (1%)
- encode / decode round trip is byte-identical
- order independence (encoded bytes invariant under insertion order)
- determinism across construction (same inputs → same encoding)
- malformed-input rejection (length mismatch, reserved bits set)
"""

from __future__ import annotations

import pytest

from one_link import bloom_native

pytestmark = pytest.mark.skipif(
    not bloom_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def _id(seed: int) -> bytes:
    """32-byte deterministic chunk_id from a small seed."""
    return seed.to_bytes(4, "little") + b"\xAA" * 28


def test_module_metadata() -> None:
    assert bloom_native.NATIVE_VERSION is not None
    assert bloom_native.BLOOM_HEADER_LEN == 12
    assert bloom_native.MAX_FILTER_BYTES == 1024 * 1024


def test_empty_filter_contains_nothing() -> None:
    f = bloom_native.new(1024)
    for i in range(50):
        assert not f.contains(_id(i))


def test_inserted_ids_definitely_present() -> None:
    f = bloom_native.new(1024)
    ids = [_id(i) for i in range(100)]
    for cid in ids:
        f.insert(cid)
    for cid in ids:
        assert f.contains(cid), f"id {cid.hex()} reported absent"


def test_empirical_fp_rate_under_2pct() -> None:
    f = bloom_native.new(1000)
    for i in range(1000):
        f.insert(_id(i))
    # Query 10000 unrelated ids.
    fps = sum(1 for i in range(10_000, 20_000) if f.contains(_id(i)))
    rate = fps / 10_000.0
    assert rate < 0.02, f"FP rate {rate:.4f} too high"


def test_encode_decode_round_trip() -> None:
    f = bloom_native.new(1024)
    for i in range(80):
        f.insert(_id(i))
    encoded = f.encode()
    assert isinstance(encoded, (bytes, bytearray))
    decoded = bloom_native.decode(encoded)
    # All inserted ids still found.
    for i in range(80):
        assert decoded.contains(_id(i))
    # Re-encode matches the original.
    assert decoded.encode() == encoded


def test_order_independence() -> None:
    f1 = bloom_native.new(256)
    f2 = bloom_native.new(256)
    ids = [_id(i) for i in range(50)]
    for cid in ids:
        f1.insert(cid)
    for cid in reversed(ids):
        f2.insert(cid)
    assert f1.encode() == f2.encode()


def test_construction_determinism() -> None:
    f1 = bloom_native.new(64)
    f2 = bloom_native.new(64)
    for i in range(20):
        f1.insert(_id(i))
        f2.insert(_id(i))
    assert f1.encode() == f2.encode()


def test_sizing_helpers_match_adr0011() -> None:
    # ADR-0011 ships with target_fp = 0.01.
    assert bloom_native.default_target_fp_rate() == pytest.approx(0.01)
    # n=1024 at p=0.01 → m ≈ 9816, k ≈ 7.
    m = bloom_native.optimal_m_bits(1024, 0.01)
    assert 9810 <= m <= 9825
    assert bloom_native.optimal_k(1024, m) == 7


def test_build_from_ids_helper() -> None:
    ids = [_id(i) for i in range(30)]
    f = bloom_native.build_from_ids(ids)
    for cid in ids:
        assert f.contains(cid)


def test_rejects_corrupted_reserved_bytes() -> None:
    f = bloom_native.new(64)
    encoded = bytearray(f.encode())
    encoded[10] = 0xFF  # poison reserved byte
    with pytest.raises(Exception):
        bloom_native.decode(bytes(encoded))


def test_rejects_wrong_chunk_id_length() -> None:
    f = bloom_native.new(1024)
    with pytest.raises(Exception):
        f.insert(b"too short")
    with pytest.raises(Exception):
        f.contains(b"\x00" * 33)
