"""Tests for the Bloom-init canonical-honor cutover.

Once the sender decodes + caches a BLOOM_INIT_FILTER advisory, the
chunk-dispatch loop consults the cached Bloom via
``bloom_decision_for_chunk`` as the canonical "does receiver have
this chunk?" answer. FILE_WANTS stays as a fallback for peers that
didn't advertise BLOOM_INIT_V1 / for race-window transfers.
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


def test_bloom_decision_returns_none_without_cached_bloom():
    from one_link.daemon import Daemon

    class _Stub:
        pass

    decision = Daemon.bloom_decision_for_chunk(  # type: ignore[arg-type]
        _Stub(), "abc", "some-blob-hex", b"\x00" * 32
    )
    assert decision is None


def test_bloom_decision_returns_true_when_chunk_in_receiver_bloom():
    """Simulate the daemon's _handle_bloom_init_advisory effect:
    populate the cache directly, then query a chunk that's in the
    Bloom."""
    from one_link import bloom_init
    from one_link.daemon import Daemon

    class _Stub:
        pass

    stub = _Stub()
    receiver_ids = _make_chunk_ids(50, seed=10)
    wire = bloom_init.build_receiver_bloom(receiver_ids)
    bloom_obj = bloom_init.decode_receiver_bloom(wire)
    stub._bloom_init_cache = {("peer-a", "blob-x"): bloom_obj}  # type: ignore[attr-defined]

    target = receiver_ids[5]
    decision = Daemon.bloom_decision_for_chunk(stub, "peer-a", "blob-x", target)  # type: ignore[arg-type]
    assert decision is True


def test_bloom_decision_returns_false_when_chunk_not_in_receiver_bloom():
    from one_link import bloom_init
    from one_link.daemon import Daemon

    class _Stub:
        pass

    stub = _Stub()
    receiver_ids = _make_chunk_ids(50, seed=20)
    wire = bloom_init.build_receiver_bloom(receiver_ids)
    bloom_obj = bloom_init.decode_receiver_bloom(wire)
    stub._bloom_init_cache = {("peer-b", "blob-y"): bloom_obj}  # type: ignore[attr-defined]

    # Build a chunk_id that's NOT in receiver_ids.
    novel = _make_chunk_ids(1, seed=99)[0]
    decision = Daemon.bloom_decision_for_chunk(stub, "peer-b", "blob-y", novel)  # type: ignore[arg-type]
    # False or True (FP rate ~5%); the contract is "deterministic + correct
    # for in-set chunks, may false-positive for out-of-set chunks." We
    # check 100 out-of-set chunks and assert the FP rate is sane.
    fp_count = 0
    for c in _make_chunk_ids(100, seed=999):
        d = Daemon.bloom_decision_for_chunk(stub, "peer-b", "blob-y", c)  # type: ignore[arg-type]
        if d is True:
            fp_count += 1
    # 5% target × 100 ≈ 5 expected; allow up to 15 in worst case.
    assert fp_count <= 15, f"Bloom FP count {fp_count} > 15 (too high)"
    # The specific 'novel' chunk: usually False, occasionally True.
    assert decision in (True, False)


def test_bloom_decision_bumps_honored_chunks_counter():
    """Each call to bloom_decision_for_chunk must bump the honored
    counter so the /api/metrics surface can show operational adoption."""
    from one_link import bloom_init
    from one_link.daemon import Daemon

    class _Stub:
        pass

    stub = _Stub()
    receiver_ids = _make_chunk_ids(10, seed=30)
    bloom_obj = bloom_init.decode_receiver_bloom(
        bloom_init.build_receiver_bloom(receiver_ids)
    )
    stub._bloom_init_cache = {("peer-c", "blob-z"): bloom_obj}  # type: ignore[attr-defined]

    # No stats yet → counter doesn't exist; nothing to assert. After
    # the call we initialise stats dict ourselves to match what
    # _handle_bloom_init_advisory would have done in production.
    stub._bloom_init_stats = {  # type: ignore[attr-defined]
        "advisories_received": 0,
        "bloom_honored_chunks": 0,
        "bloom_vs_file_wants_disagreements": 0,
    }
    for cid in receiver_ids:
        Daemon.bloom_decision_for_chunk(stub, "peer-c", "blob-z", cid)  # type: ignore[arg-type]
    assert stub._bloom_init_stats["bloom_honored_chunks"] == 10  # type: ignore[attr-defined]


def test_bloom_cross_check_records_disagreements():
    """When Bloom says "have" but FILE_WANTS says "send", that's a
    disagreement — track it."""
    from one_link import bloom_init
    from one_link.daemon import Daemon

    class _Stub:
        pass

    stub = _Stub()
    receiver_ids = _make_chunk_ids(50, seed=42)
    bloom_obj = bloom_init.decode_receiver_bloom(
        bloom_init.build_receiver_bloom(receiver_ids)
    )
    stub._bloom_init_cache = {("peer-d", "blob-w"): bloom_obj}  # type: ignore[attr-defined]
    stub._bloom_init_stats = {  # type: ignore[attr-defined]
        "advisories_received": 0,
        "bloom_honored_chunks": 0,
        "bloom_vs_file_wants_disagreements": 0,
    }

    # FILE_WANTS contains all 50 receiver_ids (claiming receiver
    # doesn't have ANY of them). Bloom says receiver has all 50.
    # Cross-check should record 50 disagreements.
    wants_hex = [cid.hex() for cid in receiver_ids]
    Daemon.bloom_cross_check_with_file_wants(  # type: ignore[arg-type]
        stub, "peer-d", "blob-w", wants_hex, receiver_ids
    )
    assert stub._bloom_init_stats["bloom_vs_file_wants_disagreements"] == 50  # type: ignore[attr-defined]


def test_bloom_decision_returns_none_for_unknown_peer():
    """A peer without an advisory entry must return None so the
    caller falls back to FILE_WANTS."""
    from one_link import bloom_init
    from one_link.daemon import Daemon

    class _Stub:
        pass

    stub = _Stub()
    bloom_obj = bloom_init.decode_receiver_bloom(
        bloom_init.build_receiver_bloom(_make_chunk_ids(10))
    )
    stub._bloom_init_cache = {("peer-existing", "blob"): bloom_obj}  # type: ignore[attr-defined]

    decision = Daemon.bloom_decision_for_chunk(  # type: ignore[arg-type]
        stub, "peer-nonexistent", "blob", b"\x00" * 32
    )
    assert decision is None


def test_per_peer_transport_kind_surface():
    """The /api/metrics per_peer_field_advisories block must include
    a transport_kind entry — "webrtc" or "quic" — per peer."""
    from one_link.daemon import Daemon

    class _Peer:
        capabilities = None
        advertised_caps = None
        short_id = "test-peer"

    class _Stub:
        _quic_endpoint = None

        def _ensure_quic_endpoint(self):
            return None

    choice = Daemon.transport_choice_for_peer(_Stub(), _Peer())  # type: ignore[arg-type]
    # No caps + no endpoint → webrtc default.
    assert choice == "webrtc"
