"""Tests for the Phase B Bloom-init handshake helper module.

The protocol-level wiring (channel + transfer offer) lands in a
follow-up; this file gates the helper math + wire encoding that the
daemon path will call into.
"""

from __future__ import annotations

import hashlib

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import bloom  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.bloom not installed",
)


def _make_chunk_ids(n: int, *, seed: int = 0) -> list[bytes]:
    out = []
    for i in range(n):
        h = hashlib.blake3 if hasattr(hashlib, "blake3") else hashlib.sha256
        out.append(
            h(seed.to_bytes(8, "little") + i.to_bytes(8, "little")).digest()[:32]
        )
    return out


def test_has_native_flag_reports_true_when_bloom_installed():
    from one_link import bloom_init

    assert bloom_init.HAS_NATIVE is True


def test_build_receiver_bloom_returns_wire_bytes():
    from one_link import bloom_init

    ids = _make_chunk_ids(100)
    wire = bloom_init.build_receiver_bloom(ids)
    assert isinstance(wire, bytes)
    assert len(wire) > 4  # at least the length prefix + a body
    # Length prefix matches body length.
    import struct

    (declared_len,) = struct.unpack_from("<I", wire, 0)
    assert declared_len == len(wire) - 4


def test_decode_round_trips():
    from one_link import bloom_init

    ids = _make_chunk_ids(50, seed=7)
    wire = bloom_init.build_receiver_bloom(ids)
    bf = bloom_init.decode_receiver_bloom(wire)
    # Every inserted chunk_id must still test positive.
    for cid in ids:
        assert bf.contains(cid)


def test_decode_rejects_short_frame():
    from one_link import bloom_init

    with pytest.raises(ValueError, match="too short"):
        bloom_init.decode_receiver_bloom(b"\x00")


def test_decode_rejects_length_mismatch():
    from one_link import bloom_init

    # Length prefix says 999 bytes, but body is 0.
    bad = b"\xe7\x03\x00\x00"
    with pytest.raises(ValueError, match="length mismatch"):
        bloom_init.decode_receiver_bloom(bad)


def test_filter_manifest_excludes_present_chunks():
    """The core Bloom-init property: filtering a manifest against the
    receiver's Bloom must drop chunks the receiver already has."""
    from one_link import bloom_init

    receiver_ids = _make_chunk_ids(80, seed=1)
    sender_manifest = receiver_ids + _make_chunk_ids(20, seed=2)
    wire = bloom_init.build_receiver_bloom(receiver_ids)
    bf = bloom_init.decode_receiver_bloom(wire)
    missing = bloom_init.filter_manifest_against_bloom(sender_manifest, bf)
    # The 20 new chunks should mostly appear in the missing list,
    # though at the 5% target FP rate ~1 may be incorrectly skipped.
    # The honest gate: ≥ 18/20 (= 90%) new chunks correctly identified
    # as missing.
    new_chunks = set(_make_chunk_ids(20, seed=2))
    missing_set = set(missing)
    correctly_flagged = len(new_chunks & missing_set)
    assert correctly_flagged >= 18, (
        f"Bloom-init dropped only {correctly_flagged}/20 new chunks; "
        f"expected ≥ 18 at 5% target FP"
    )
    # Most of the 80 known chunks should NOT appear (false positives
    # mean a few WILL appear, but at 5% target FP we expect ~4 misses).
    known_set = set(receiver_ids)
    false_positives_skipped = [cid for cid in missing if cid in known_set]
    assert len(false_positives_skipped) <= 12  # generous bound for FP noise


def test_filter_manifest_empty_receiver_means_send_everything():
    """If the receiver has zero chunks, the Bloom queries return False
    for every manifest entry → sender ships all of them."""
    from one_link import bloom_init

    sender_manifest = _make_chunk_ids(50, seed=3)
    wire = bloom_init.build_receiver_bloom([])
    bf = bloom_init.decode_receiver_bloom(wire)
    missing = bloom_init.filter_manifest_against_bloom(sender_manifest, bf)
    # Every manifest entry should be missing (receiver has nothing).
    assert len(missing) == len(sender_manifest)


def test_measure_savings_basic_math():
    from one_link import bloom_init

    # 1000 chunks total, Bloom is 1200 bytes, 200 chunks need to be sent.
    r = bloom_init.measure_savings(
        manifest_size=1000,
        bloom_wire_bytes=1200,
        missing_chunk_count=200,
    )
    # Baseline 1000 * 32 = 32000.
    assert r["baseline_bytes"] == 32000
    # Actual 1200 + 200*32 = 7600.
    assert r["actual_bytes"] == 7600
    # Savings 24400 bytes = 76.25%.
    assert r["savings_bytes"] == 24400
    assert abs(r["savings_fraction"] - 0.7625) < 1e-9


def test_measure_savings_edge_case_zero_manifest():
    from one_link import bloom_init

    r = bloom_init.measure_savings(
        manifest_size=0,
        bloom_wire_bytes=100,
        missing_chunk_count=0,
    )
    assert r["baseline_bytes"] == 0
    assert r["savings_fraction"] == 0.0


def test_bloom_init_capability_advertised():
    """The daemon must advertise BLOOM_INIT_V1 in LOCAL_CAPABILITIES so
    peers know to enter the handshake."""
    from one_link.capabilities import BLOOM_INIT_V1, LOCAL_CAPABILITIES

    assert BLOOM_INIT_V1 == "bloom_init_v1"
    assert BLOOM_INIT_V1 in LOCAL_CAPABILITIES


def test_quic_transport_capability_advertised():
    """The daemon must advertise QUIC_TRANSPORT_V1 once the cutover
    helpers are landed (this commit ships the capability + helpers;
    the full datapath swap is next-phase)."""
    from one_link.capabilities import LOCAL_CAPABILITIES, QUIC_TRANSPORT_V1

    assert QUIC_TRANSPORT_V1 == "quic_transport_v1"
    assert QUIC_TRANSPORT_V1 in LOCAL_CAPABILITIES
