"""default_kem() must FAIL CLOSED against a silent PQ-strip downgrade.

Regression for the harvest-now-decrypt-later hole: when the native PQ
engine (``one_link_native.pqkem``) is absent, ``default_kem()`` used to
silently return ``HybridKEM`` with the X25519 + NullKEM placeholder (zero
post-quantum entropy) while every audit log still read "PQ hybrid". These
tests pin the fail-closed behaviour and the *explicit* opt-in escape hatch,
and run on ANY host (native present or not) by monkeypatching HAS_NATIVE.
"""

from __future__ import annotations

import pytest

from one_link import pq_hybrid, pqkem_native


def test_default_kem_raises_when_native_absent(monkeypatch):
    # Simulate a host without the native wheel.
    monkeypatch.setattr(pqkem_native, "HAS_NATIVE", False)
    with pytest.raises(pq_hybrid.PQUnavailableError):
        pq_hybrid.default_kem()


def test_default_kem_explicit_downgrade_is_allowed_and_classical(monkeypatch):
    monkeypatch.setattr(pqkem_native, "HAS_NATIVE", False)
    # The conscious, logged escape hatch: caller accepts X25519-only.
    kem = pq_hybrid.default_kem(allow_classical_downgrade=True)
    assert isinstance(kem, pq_hybrid.HybridKEM)
    # And it still produces a working 32-byte classical secret.
    sk, pk = kem.keypair()
    ct, ss_send = kem.encapsulate(pk, transcript=b"ctx")
    ss_recv = kem.decapsulate(ct, sk, transcript=b"ctx")
    assert ss_send == ss_recv and len(ss_send) == 32


def test_explicit_downgrade_emits_warning(monkeypatch, caplog):
    monkeypatch.setattr(pqkem_native, "HAS_NATIVE", False)
    import logging
    with caplog.at_level(logging.WARNING, logger=pq_hybrid.log.name):
        pq_hybrid.default_kem(allow_classical_downgrade=True)
    assert any("DOWNGRADING to" in r.message or "NO post-quantum" in r.message
               for r in caplog.records), "explicit classical downgrade must WARN"
