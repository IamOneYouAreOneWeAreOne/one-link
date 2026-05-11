"""ADR-0017 algebraic-correctness tests for ``one_link.pqkem_native``."""

from __future__ import annotations

import pytest

from one_link import pqkem_native

pytestmark = pytest.mark.skipif(
    not pqkem_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def test_module_metadata() -> None:
    assert pqkem_native.NATIVE_VERSION is not None
    assert pqkem_native.HYBRID_PUBLIC_KEY_LEN == 1216
    assert pqkem_native.HYBRID_SECRET_KEY_LEN == 2432
    assert pqkem_native.HYBRID_CIPHERTEXT_LEN == 1120
    assert pqkem_native.SHARED_SECRET_LEN == 32


def test_full_round_trip() -> None:
    pk, sk = pqkem_native.keypair()
    ct, ss_initiator = pqkem_native.encapsulate(pk)
    ss_responder = pqkem_native.decapsulate(sk, ct)
    assert ss_initiator == ss_responder
    assert len(ss_initiator) == 32


def test_distinct_sessions_distinct_secrets() -> None:
    pk, _sk = pqkem_native.keypair()
    _ct1, ss1 = pqkem_native.encapsulate(pk)
    _ct2, ss2 = pqkem_native.encapsulate(pk)
    assert ss1 != ss2


def test_wire_round_trip_pk_sk_ct() -> None:
    pk, sk = pqkem_native.keypair()
    pk_bytes = pk.to_bytes()
    sk_bytes = sk.to_bytes()
    assert len(pk_bytes) == pqkem_native.HYBRID_PUBLIC_KEY_LEN
    assert len(sk_bytes) == pqkem_native.HYBRID_SECRET_KEY_LEN

    pk2 = pqkem_native.public_key_from_bytes(pk_bytes)
    sk2 = pqkem_native.secret_key_from_bytes(sk_bytes)

    ct, ss_a = pqkem_native.encapsulate(pk2)
    ct_bytes = ct.to_bytes()
    assert len(ct_bytes) == pqkem_native.HYBRID_CIPHERTEXT_LEN
    ct2 = pqkem_native.ciphertext_from_bytes(ct_bytes)
    ss_b = pqkem_native.decapsulate(sk2, ct2)
    assert ss_a == ss_b


def test_rejects_wrong_length_inputs() -> None:
    with pytest.raises(Exception):
        pqkem_native.public_key_from_bytes(b"short")
    with pytest.raises(Exception):
        pqkem_native.secret_key_from_bytes(b"\x00" * 100)
    with pytest.raises(Exception):
        pqkem_native.ciphertext_from_bytes(b"\x00" * 200)
