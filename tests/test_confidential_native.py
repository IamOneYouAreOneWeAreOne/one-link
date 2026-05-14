"""Tests for the daemon-side Row 10 confidential-compute adapter."""

from __future__ import annotations

import os

import pytest

from one_link.confidential_native import (
    HAS_NATIVE,
    PROVIDER_TAG_SOFTWARE,
    AttestationDoc,
    SealedKey,
    SoftwareProvider,
    attestation_freshness_window_secs,
    fresh_attestation_nonce,
    verify_attestation,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.confidential not built; run `maturin develop --release`",
)


# ── SoftwareProvider lifecycle ────────────────────────────────────


def test_fresh_provider_tier_and_tag():
    p = SoftwareProvider.fresh()
    assert p.tier == 0  # TIER_SOFTWARE
    assert p.tag == PROVIDER_TAG_SOFTWARE


def test_seal_master_round_trips_sign_verify():
    p = SoftwareProvider.fresh()
    seed = bytes([0x42] * 32)
    sealed = p.seal_master(seed)
    assert sealed.tag == PROVIDER_TAG_SOFTWARE
    assert sealed.is_software
    assert not sealed.is_hardware_bound
    vk = p.verifying_key(sealed)
    sig = p.sealed_sign(sealed, b"hello row 10")
    # The sig verifies under the published VK via the ol_pqsig path
    # (not exercised here directly — covered by the Rust unit tests).
    assert len(sig) > 0
    assert len(vk) == 1984


def test_seal_master_rejects_wrong_seed_length():
    p = SoftwareProvider.fresh()
    with pytest.raises(ValueError):
        p.seal_master(bytes([0x42] * 31))


def test_derive_child_diverges_from_master():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x55] * 32))
    child = p.derive_child(sealed, b"phone-day-1")
    assert child.tag == PROVIDER_TAG_SOFTWARE
    vk_m = p.verifying_key(sealed)
    vk_c = p.verifying_key(child)
    assert vk_m != vk_c


def test_distinct_context_tags_yield_distinct_children():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x77] * 32))
    c1 = p.derive_child(sealed, b"alpha")
    c2 = p.derive_child(sealed, b"beta")
    assert p.verifying_key(c1) != p.verifying_key(c2)


def test_from_seed_deterministic_across_providers():
    # Two providers from the same seed can open each other's blobs.
    p1 = SoftwareProvider.from_seed(bytes([0x10] * 32))
    p2 = SoftwareProvider.from_seed(bytes([0x10] * 32))
    sealed = p1.seal_master(bytes([0x99] * 32))
    vk1 = p1.verifying_key(sealed)
    vk2 = p2.verifying_key(sealed)
    assert vk1 == vk2


def test_from_seed_rejects_wrong_length():
    with pytest.raises(ValueError):
        SoftwareProvider.from_seed(bytes([0x10] * 31))


# ── Attestation issue + verify ───────────────────────────────────


def test_attestation_round_trip_no_witness():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x44] * 32))
    nonce = fresh_attestation_nonce()
    assert len(nonce) == 32
    doc = p.attest(sealed, nonce, 1_000, 1_020)
    verify_attestation(doc, nonce, now_unix=1_010)


def test_attestation_with_field_witness():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0xAB] * 32))
    nonce = fresh_attestation_nonce()
    witness = bytes([0xCD] * 32)
    doc = p.attest(sealed, nonce, 1_000, 1_020, field_witness=witness)
    verify_attestation(doc, nonce, now_unix=1_010, expected_field_witness=witness)


def test_attestation_wrong_peer_nonce_rejected():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0xEE] * 32))
    nonce_a = fresh_attestation_nonce()
    nonce_b = fresh_attestation_nonce()
    doc = p.attest(sealed, nonce_a, 1_000, 1_020)
    with pytest.raises(ValueError):
        verify_attestation(doc, nonce_b, now_unix=1_010)


def test_attestation_expired_rejected():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x33] * 32))
    nonce = fresh_attestation_nonce()
    doc = p.attest(sealed, nonce, 1_000, 1_020)
    with pytest.raises(ValueError):
        verify_attestation(doc, nonce, now_unix=1_100)


def test_attestation_freshness_window_too_wide_rejected_at_issue():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x21] * 32))
    nonce = fresh_attestation_nonce()
    # ATTESTATION_FRESHNESS_WINDOW_SECS = 30; 31 must reject.
    with pytest.raises(ValueError):
        p.attest(sealed, nonce, 1_000, 1_000 + 31)


def test_attestation_deadline_equal_issue_rejected():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x88] * 32))
    nonce = fresh_attestation_nonce()
    with pytest.raises(ValueError):
        p.attest(sealed, nonce, 1_000, 1_000)


def test_attestation_tampered_master_sig_rejected():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x12] * 32))
    nonce = fresh_attestation_nonce()
    doc = p.attest(sealed, nonce, 1_000, 1_020)
    # Flip a sig byte; build a new doc.
    tampered_sig = bytearray(doc.master_sig)
    tampered_sig[0] ^= 0x01
    tampered = AttestationDoc(
        provider_tag=doc.provider_tag,
        master_vk=doc.master_vk,
        peer_nonce=doc.peer_nonce,
        issued_unix=doc.issued_unix,
        deadline_unix=doc.deadline_unix,
        field_witness_commitment=doc.field_witness_commitment,
        platform_quote=doc.platform_quote,
        master_sig=bytes(tampered_sig),
    )
    with pytest.raises(ValueError):
        verify_attestation(tampered, nonce, now_unix=1_010)


def test_attestation_field_witness_mismatch_rejected():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0xFE] * 32))
    nonce = fresh_attestation_nonce()
    doc = p.attest(sealed, nonce, 1_000, 1_020, field_witness=bytes([0xAA] * 32))
    with pytest.raises(ValueError):
        verify_attestation(
            doc,
            nonce,
            now_unix=1_010,
            expected_field_witness=bytes([0xBB] * 32),
        )


# ── SealedKey opaque round-trip ──────────────────────────────────


def test_sealed_key_serialises_to_bytes_plus_tag():
    p = SoftwareProvider.fresh()
    sealed = p.seal_master(bytes([0x66] * 32))
    # Daemon stores (bytes, tag); reload and verify functionality survives.
    raw_bytes = sealed.bytes
    raw_tag = sealed.tag
    reloaded = SealedKey(bytes=raw_bytes, tag=raw_tag)
    vk_orig = p.verifying_key(sealed)
    vk_reloaded = p.verifying_key(reloaded)
    assert vk_orig == vk_reloaded


# ── Freshness window constant ────────────────────────────────────


def test_freshness_window_is_30_seconds():
    assert attestation_freshness_window_secs() == 30
