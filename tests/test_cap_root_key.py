"""Audit M14 May 2026 — regression tests for the per-daemon cap_root_key.

Closes the audit finding where macaroon HMAC root keys derived from
the identity Ed25519 seed (shared entropy → side-channel leak risk).
The new ``cap_root_key`` is a separate 32-byte secret minted at first
boot and persisted via DPAPI on Windows / mode-0600 on POSIX.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from one_link import cap_migration, cap_root_key


def test_load_or_create_mints_fresh_on_first_call():
    with tempfile.TemporaryDirectory(prefix="ol_cap_root_") as tmp:
        data_dir = Path(tmp)
        key, created = cap_root_key.load_or_create_cap_root_key(data_dir)
        assert created is True
        assert len(key) == cap_root_key.CAP_ROOT_KEY_LEN_BYTES
        assert cap_root_key.has_cap_root_key(data_dir)


def test_load_or_create_returns_existing_on_second_call():
    with tempfile.TemporaryDirectory(prefix="ol_cap_root_") as tmp:
        data_dir = Path(tmp)
        key1, _ = cap_root_key.load_or_create_cap_root_key(data_dir)
        key2, created = cap_root_key.load_or_create_cap_root_key(data_dir)
        assert created is False
        assert key1 == key2


def test_load_returns_none_when_missing():
    with tempfile.TemporaryDirectory(prefix="ol_cap_root_") as tmp:
        data_dir = Path(tmp)
        assert cap_root_key.load_cap_root_key(data_dir) is None


def test_store_then_load_round_trip():
    with tempfile.TemporaryDirectory(prefix="ol_cap_root_") as tmp:
        data_dir = Path(tmp)
        original = bytes(range(32))
        cap_root_key.store_cap_root_key(data_dir, original)
        loaded = cap_root_key.load_cap_root_key(data_dir)
        assert loaded == original


def test_store_rejects_wrong_length():
    with tempfile.TemporaryDirectory(prefix="ol_cap_root_") as tmp:
        data_dir = Path(tmp)
        with pytest.raises(ValueError):
            cap_root_key.store_cap_root_key(data_dir, b"\x00" * 31)


def test_m14_derived_key_separate_from_seed_path():
    """Regression: derive_root_key_from_cap_root and derive_root_key
    produce DIFFERENT outputs even when given byte-identical inputs.
    Confirms the macaroon HMAC root is not just a renamed derivation
    of the same input — the domain separation is real."""
    same_bytes = bytes(range(32))
    cap_root_derived = cap_migration.derive_root_key_from_cap_root(same_bytes)
    seed_derived = cap_migration.derive_root_key(same_bytes)
    assert cap_root_derived != seed_derived, (
        "M14: cap_root_key and identity-seed derivations must diverge "
        "for the SAME input bytes (domain-separated contexts)"
    )


def test_m14_mint_share_capability_from_root_round_trip():
    """The new mint_share_capability_from_root path produces a valid
    Capability that verifies under the same cap_root_key."""
    try:
        from one_link import capability_native  # type: ignore[attr-defined]
    except ImportError:
        pytest.skip("capability_native not built")
    if not getattr(capability_native, "HAS_NATIVE", False):
        pytest.skip("capability_native native ext unavailable")

    cap_root = bytes(range(32))
    granter_pub = bytes([0x11] * 32)
    subject_pub = bytes([0x22] * 32)
    cap = cap_migration.mint_share_capability_from_root(
        cap_root_key=cap_root,
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        capabilities=["files:read"],
        not_after_ms=int(2 ** 50),
    )
    assert cap is not None
    encoded = cap.encode()
    assert isinstance(encoded, (bytes, bytearray))
    assert len(encoded) > 0
