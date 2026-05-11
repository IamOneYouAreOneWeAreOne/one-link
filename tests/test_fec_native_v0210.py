"""ADR-0016 algebraic-correctness tests for ``one_link.fec_native``.

Verifies that the Python binding for Reed-Solomon over GF(2^8) round-
trips correctly + recovers from any K-of-(K+M) shard subset.
"""

from __future__ import annotations

import pytest

from one_link import fec_native

pytestmark = pytest.mark.skipif(
    not fec_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def _data_shard(i: int, length: int = 64) -> bytes:
    return bytes([(i + j) & 0xFF for j in range(length)])


def test_module_metadata() -> None:
    assert fec_native.NATIVE_VERSION is not None


def test_rs_10_4_round_trip() -> None:
    codec = fec_native.codec(10, 4)
    assert codec.k == 10
    assert codec.m == 4
    assert codec.total_shards == 14

    data = [_data_shard(i) for i in range(10)]
    parity = codec.encode(data)
    assert len(parity) == 4
    for p in parity:
        assert len(p) == 64

    # Decode with all shards present.
    present = list(data) + list(parity)
    decoded = codec.decode(present)
    assert list(decoded) == data


def test_rs_10_4_recovers_from_4_erasures() -> None:
    codec = fec_native.codec(10, 4)
    data = [_data_shard(i, length=128) for i in range(10)]
    parity = codec.encode(data)
    # Drop 0, 4, 9 (data) + 11 (parity 1).
    present = list(data) + list(parity)
    for i in (0, 4, 9, 11):
        present[i] = None
    decoded = codec.decode(present)
    assert list(decoded) == data


def test_rs_pinned_determinism_first_data_shard() -> None:
    """Cross-platform determinism: encode of a fixed input must produce
    the same parity bytes on every architecture.

    The Rust-side `cross_platform_rs_10_4_parity_pinned` test in
    `ol_fec/tests/determinism.rs` pins the canonical vector; this
    Python test confirms the binding round-trips it byte-exactly.
    """
    codec = fec_native.codec(10, 4)
    # Same fixed input as the Rust test: 10 64-byte shards with pattern
    # i + j (mod 256), with j=63 = 0xCD marker.
    data = []
    for i in range(10):
        shard = bytearray(64)
        for j in range(63):
            shard[j] = (i + j) & 0xFF
        shard[63] = 0xCD
        data.append(bytes(shard))
    parity = codec.encode(data)
    # First parity shard's hex matches the pinned vector from
    # ol_fec/tests/determinism.rs::PINNED_P0.
    expected_p0_hex = (
        "8ab54d3e3c040a497dd0dd6aba1e121c86b94132300806ac881ae6c2ad2a225f"
        "92ad5526241c125165c8c572a2060a049ea1592a28101e7d7995908983424213"
    )
    assert parity[0].hex() == expected_p0_hex


def test_rs_rejects_too_few_shards() -> None:
    codec = fec_native.codec(5, 2)
    present: list[bytes | None] = [None] * 7  # all missing
    with pytest.raises(Exception):
        codec.decode(present)


def test_rs_rejects_wrong_count() -> None:
    codec = fec_native.codec(5, 2)
    with pytest.raises(Exception):
        codec.decode([])  # not k+m = 7
