"""v0.20.7 (audit M5) — reject X25519 small-order pubkeys before
running the ECDH that feeds kdf_root.

A malicious-but-paired peer can craft a ratchet header carrying one of
the 13 known small-order Curve25519 u-coordinates (RFC 7748 §6.1 +
libsodium's blocklist). Every party derives the SAME root step from
the deterministic zero output. The pre-fix code only caught the
all-zero output post-exchange; v0.20.7 also rejects the input pubkey
explicitly, eliminating the one-curve-op-of-attacker-controlled-
material primitive.

These tests pin:
  - each small-order pubkey raises ValueError with a small-order error
  - non-zero-length but wrong-size pubkeys raise without reaching curve
  - a normal X25519 pubkey still works
  - the rejection happens BEFORE priv.exchange is called (so a
    monkeypatched exchange that raises proves we shortcut)
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
)

from one_link import double_ratchet as dr


SMALL_ORDER_POINTS = [
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0100000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
]


@pytest.mark.parametrize("pub_hex", SMALL_ORDER_POINTS)
def test_small_order_pubkey_rejected(pub_hex):
    priv = X25519PrivateKey.generate()
    pub = bytes.fromhex(pub_hex)
    with pytest.raises(ValueError, match="(small-order|zero shared secret)"):
        dr.x25519_dh(priv, pub)


def test_wrong_length_pubkey_rejected():
    priv = X25519PrivateKey.generate()
    with pytest.raises(ValueError, match="32 bytes"):
        dr.x25519_dh(priv, b"\x00" * 31)
    with pytest.raises(ValueError, match="32 bytes"):
        dr.x25519_dh(priv, b"\x00" * 33)
    with pytest.raises(ValueError, match="32 bytes"):
        dr.x25519_dh(priv, b"")


def test_normal_pubkey_works():
    priv1 = X25519PrivateKey.generate()
    priv2 = X25519PrivateKey.generate()
    pub2 = priv2.public_key().public_bytes_raw()
    out = dr.x25519_dh(priv1, pub2)
    assert isinstance(out, bytes)
    assert len(out) == 32
    assert out != b"\x00" * 32


def test_smallorder_check_runs_before_exchange(monkeypatch):
    """Patch X25519PrivateKey.exchange to detonate; a small-order
    pubkey must STILL raise the small-order ValueError because the
    rejection happens before the curve op is reached."""
    priv = X25519PrivateKey.generate()
    boom = RuntimeError("exchange() should not have been called")

    def _boom(self, peer):
        raise boom

    monkeypatch.setattr(X25519PrivateKey, "exchange", _boom, raising=True)
    pub = bytes.fromhex(SMALL_ORDER_POINTS[0])
    with pytest.raises(ValueError, match="small-order"):
        dr.x25519_dh(priv, pub)


def test_blocklist_membership_check():
    """The internal blocklist must contain at least the 7 canonical
    small-order pubkeys + their high-bit-flipped variants. Pin the
    cardinality so a future refactor can't accidentally shrink it."""
    assert len(dr._X25519_SMALL_ORDER_POINTS) >= 13
    for h in SMALL_ORDER_POINTS:
        assert bytes.fromhex(h) in dr._X25519_SMALL_ORDER_POINTS
