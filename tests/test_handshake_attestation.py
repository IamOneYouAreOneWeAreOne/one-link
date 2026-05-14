"""Tests for the Row 10 peer-handshake attestation helper."""

from __future__ import annotations

import base64
import json

import pytest

from one_link.confidential_native import HAS_NATIVE, SealedMasterIdentity
from one_link.handshake_attestation import (
    AttestationWire,
    fresh_challenge_for_peer,
    issue_for_challenge,
    verify_doc,
)

pytestmark = pytest.mark.skipif(
    not HAS_NATIVE,
    reason="one_link_native.confidential not built; run `maturin develop --release`",
)

TEST_SDP_PUBKEY = bytes([0x77] * 32)


def _fresh_master() -> SealedMasterIdentity:
    return SealedMasterIdentity.from_seed_bytes(bytes([0x42] * 32))


def test_fresh_challenge_is_32_bytes():
    c = fresh_challenge_for_peer()
    assert len(c) == 32


def test_distinct_challenges():
    c1 = fresh_challenge_for_peer()
    c2 = fresh_challenge_for_peer()
    assert c1 != c2


def test_issue_and_verify_round_trip():
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    doc = issue_for_challenge(m, c, TEST_SDP_PUBKEY, now_unix=1_000)
    verify_doc(doc, c, TEST_SDP_PUBKEY, now_unix=1_010)


def test_issue_with_field_witness_binds_doc():
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    witness = bytes([0xAB] * 32)
    doc = issue_for_challenge(
        m, c, TEST_SDP_PUBKEY, field_witness=witness, now_unix=1_000
    )
    # Verify with the right witness passes.
    verify_doc(
        doc, c, TEST_SDP_PUBKEY, expected_field_witness=witness, now_unix=1_010
    )
    # Wrong witness rejected.
    with pytest.raises(ValueError):
        verify_doc(
            doc,
            c,
            TEST_SDP_PUBKEY,
            expected_field_witness=bytes([0xCD] * 32),
            now_unix=1_010,
        )


def test_wrong_challenge_rejected():
    m = _fresh_master()
    c1 = fresh_challenge_for_peer()
    c2 = fresh_challenge_for_peer()
    doc = issue_for_challenge(m, c1, TEST_SDP_PUBKEY, now_unix=1_000)
    with pytest.raises(ValueError):
        verify_doc(doc, c2, TEST_SDP_PUBKEY, now_unix=1_010)


def test_expired_doc_rejected():
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    doc = issue_for_challenge(m, c, TEST_SDP_PUBKEY, now_unix=1_000)
    # The doc's deadline is now_unix + 30 = 1_030 by default.
    with pytest.raises(ValueError):
        verify_doc(doc, c, TEST_SDP_PUBKEY, now_unix=1_100)


def test_wrong_issuer_sdp_pubkey_rejected():
    """Regression test for audit C1 (May 14 2026): a doc bound to
    SDP pubkey A must be rejected by a verifier whose channel is
    speaking SDP pubkey B — even though challenge + everything
    else is fine."""
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    sdp_a = bytes([0xAA] * 32)
    sdp_b = bytes([0xBB] * 32)
    doc = issue_for_challenge(m, c, sdp_a, now_unix=1_000)
    with pytest.raises(ValueError):
        verify_doc(doc, c, sdp_b, now_unix=1_010)


def test_wire_dict_round_trip_through_json():
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    doc = issue_for_challenge(m, c, TEST_SDP_PUBKEY, now_unix=1_000)
    wire = AttestationWire.from_doc(doc)
    d = wire.to_wire_dict()
    # Survives JSON encoding.
    js = json.dumps(d)
    d2 = json.loads(js)
    wire2 = AttestationWire.from_wire_dict(d2)
    doc2 = wire2.to_doc()
    # Reconstructed doc verifies the same.
    verify_doc(doc2, c, TEST_SDP_PUBKEY, now_unix=1_010)


def test_wire_version_validation():
    with pytest.raises(ValueError):
        AttestationWire.from_wire_dict(
            {
                "v": 999,  # unknown version
                "provider_tag": 1,
                "master_vk": "",
                "peer_nonce": "",
                "issued_unix": 0,
                "deadline_unix": 1,
                "field_witness_commitment": None,
                "platform_quote": "",
                "issuer_sdp_pubkey": "",
                "master_sig": "",
            }
        )


def test_wire_rejects_legacy_v1():
    """v1 docs from before audit C1 (no issuer_sdp_pubkey field) must
    be rejected against the v2 verifier — the transcript domain bump
    guarantees they can't pass sig verify anyway."""
    with pytest.raises(ValueError):
        AttestationWire.from_wire_dict(
            {
                "v": 1,  # legacy
                "provider_tag": 1,
                "master_vk": "",
                "peer_nonce": "",
                "issued_unix": 0,
                "deadline_unix": 1,
                "field_witness_commitment": None,
                "platform_quote": "",
                "master_sig": "",
            }
        )


def test_wire_with_witness_preserves_commitment():
    m = _fresh_master()
    c = fresh_challenge_for_peer()
    witness = bytes([0xEE] * 32)
    doc = issue_for_challenge(
        m, c, TEST_SDP_PUBKEY, field_witness=witness, now_unix=1_000
    )
    wire = AttestationWire.from_doc(doc)
    d = wire.to_wire_dict()
    # Witness commitment is non-null and base64-decodes to 32 bytes.
    assert d["field_witness_commitment"] is not None
    cmt = base64.b64decode(d["field_witness_commitment"])  # type: ignore[arg-type]
    assert len(cmt) == 32
