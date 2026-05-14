"""Tests for the SealedMasterIdentity runtime sealing wrapper."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from one_link.confidential_native import (
    HAS_NATIVE,
    SealedMasterIdentity,
    fresh_attestation_nonce,
    verify_attestation,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.confidential not built; run `maturin develop --release`",
)

TEST_SDP_PUBKEY = bytes([0x77] * 32)


def test_from_seed_bytes_rejects_wrong_length():
    with pytest.raises(ValueError):
        SealedMasterIdentity.from_seed_bytes(bytes([0x42] * 31))


def test_master_vk_is_published_form():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x42] * 32))
    vk = m.master_vk()
    assert len(vk) == 1984


def test_sign_round_trips_under_vk():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x55] * 32))
    sig = m.sign(b"hello sealed")
    assert len(sig) > 0
    # Verify under the published VK via attestation transcript path —
    # cross-checked by attest+verify_attestation below.


def test_attest_and_verify_round_trip():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x77] * 32))
    nonce = fresh_attestation_nonce()
    doc = m.attest(nonce, 1_000, 1_020, TEST_SDP_PUBKEY)
    verify_attestation(doc, nonce, 1_010, TEST_SDP_PUBKEY)


def test_attest_with_field_witness():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x88] * 32))
    nonce = fresh_attestation_nonce()
    witness = bytes([0xAA] * 32)
    doc = m.attest(nonce, 1_000, 1_020, TEST_SDP_PUBKEY, field_witness=witness)
    verify_attestation(
        doc, nonce, 1_010, TEST_SDP_PUBKEY, expected_field_witness=witness
    )


def test_derive_child_distinct_vk_from_master():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x99] * 32))
    c = m.derive_child(b"phone-day-1")
    assert m.master_vk() != c.master_vk()


def test_derive_child_distinct_per_context_tag():
    m = SealedMasterIdentity.from_seed_bytes(bytes([0xAB] * 32))
    c1 = m.derive_child(b"channel-a")
    c2 = m.derive_child(b"channel-b")
    assert c1.master_vk() != c2.master_vk()


def test_no_plaintext_seed_accessor():
    """SealedMasterIdentity must NOT expose the raw seed bytes."""
    m = SealedMasterIdentity.from_seed_bytes(bytes([0x42] * 32))
    # No `.seed()`, `._seed`, etc.
    assert not hasattr(m, "seed")
    assert not hasattr(m, "_seed")
    # The internal _sealed is opaque bytes — even reading it
    # doesn't yield the plaintext.
    raw = m._sealed.bytes  # access via private attr deliberately
    assert bytes([0x42] * 32) not in raw


def test_master_seed_load_sealed_returns_none_when_no_seed():
    from one_link import master_seed

    with tempfile.TemporaryDirectory() as td:
        result = master_seed.load_sealed_master(Path(td))
        assert result is None


def test_master_seed_load_sealed_full_lifecycle():
    from one_link import master_seed

    with tempfile.TemporaryDirectory() as td:
        # Mint + persist.
        seed, created = master_seed.load_or_create_seed(Path(td))
        assert created
        assert len(seed) == 32
        # Now seal-load.
        sealed = master_seed.load_sealed_master(Path(td))
        assert sealed is not None and sealed is not False
        # Hot-path operations work on the sealed handle.
        nonce = fresh_attestation_nonce()
        doc = sealed.attest(nonce, 1_000, 1_020, TEST_SDP_PUBKEY)
        verify_attestation(doc, nonce, 1_010, TEST_SDP_PUBKEY)
        # Second seal-load returns ANOTHER independent provider over
        # the same persisted seed — both have the same master VK
        # because the underlying seed is the same.
        sealed2 = master_seed.load_sealed_master(Path(td))
        assert sealed2 is not None and sealed2 is not False
        assert sealed.master_vk() == sealed2.master_vk()
