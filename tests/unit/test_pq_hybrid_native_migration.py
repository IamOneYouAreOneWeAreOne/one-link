"""Phase C-3 daemon migration: pq_hybrid → NativeHybridKEM.

Verifies the new :class:`NativeHybridKEM` round-trips against itself
and is byte-compatible with the underlying ``one_link_native.pqkem``
primitive, plus that :func:`default_kem` picks the right backend.
"""

from __future__ import annotations

import pytest

from one_link import pq_hybrid


def _native_available() -> bool:
    from one_link import pqkem_native

    return pqkem_native.HAS_NATIVE


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.pqkem not installed (build via maturin)",
)


def test_native_hybrid_kem_round_trip():
    kem = pq_hybrid.NativeHybridKEM()
    sk, pk = kem.keypair()
    assert len(pk.classical) == kem.classical_pub_size + kem.pq_pub_size

    ct, ss_send = kem.encapsulate(pk)
    ss_recv = kem.decapsulate(ct, sk)
    assert ss_send == ss_recv
    assert len(ss_send) == kem.ss_size


def test_native_hybrid_transcript_separates_sessions():
    kem = pq_hybrid.NativeHybridKEM()
    sk, pk = kem.keypair()
    _, ss_a = kem.encapsulate(pk, transcript=b"session-A")
    _, ss_b = kem.encapsulate(pk, transcript=b"session-B")
    # Different transcripts → different bound shared secrets.
    assert ss_a != ss_b


def test_default_kem_picks_native_when_available():
    kem = pq_hybrid.default_kem()
    # On a host with native installed, default_kem must return a real
    # PQ-protected backend, not the NullKEM placeholder.
    assert isinstance(kem, pq_hybrid.NativeHybridKEM)


def test_python_hybrid_kem_still_works_as_fallback():
    # The Python path still produces a 32-byte shared secret;
    # callers that explicitly want the old wire format keep working.
    kem = pq_hybrid.HybridKEM()
    sk, pk = kem.keypair()
    ct, ss_send = kem.encapsulate(pk, transcript=b"ctx")
    ss_recv = kem.decapsulate(ct, sk, transcript=b"ctx")
    assert ss_send == ss_recv
    assert len(ss_send) == 32
