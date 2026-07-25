"""Acceptance tests for pair_qr_native (Phase F2 wiring)."""

from __future__ import annotations

import os
import time

import pytest


def _native_available() -> bool:
    try:
        from one_link_native import pair_qr  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="one_link_native.pair_qr not installed",
)


def _seed() -> bytes:
    return os.urandom(32)


def _future_expiry() -> int:
    return int(time.time()) + 300


# ── Module / constants ────────────────────────────────────────────


def test_module_imports():
    from one_link import pair_qr_native as pq

    assert pq.HAS_NATIVE is True
    assert pq.SAS_WORD_COUNT == 5
    assert pq.SAS_BITS == 30
    assert pq.CHAIN_KEY_LEN == 32
    assert pq.INVITE_NONCE_LEN == 32
    assert pq.INVITE_VERSION == 1


# ── Inviter ───────────────────────────────────────────────────────


def test_inviter_constructs_and_produces_qr_bytes():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"contact")
    qr_bytes = inviter.invite_bytes()
    assert isinstance(qr_bytes, bytes)
    assert 0 < len(qr_bytes) <= pq.INVITE_MAX_BYTES


def test_inviter_id_seed_must_be_32_bytes():
    from one_link import pair_qr_native as pq

    with pytest.raises(ValueError, match="32 bytes"):
        pq.Inviter(b"too short", _future_expiry())


def test_inviter_state_string_round_trip():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    assert "AwaitingResponse" in inviter.state()


# ── Scanner ───────────────────────────────────────────────────────


def test_scanner_scan_validates_invite_and_returns_response():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"contact")
    qr_bytes = inviter.invite_bytes()
    scanner, response_bytes = pq.Scanner.scan(
        id_seed=_seed(),
        invite_bytes=qr_bytes,
        now_unix=int(time.time()),
    )
    assert isinstance(response_bytes, bytes)
    assert len(response_bytes) > 0
    # SAS shows immediately
    sas = scanner.sas()
    assert isinstance(sas, str)
    assert len(sas.split(" ")) == pq.SAS_WORD_COUNT


def test_scanner_refuses_expired_invite():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), 100, b"contact")  # past expiry
    qr_bytes = inviter.invite_bytes()
    with pytest.raises(ValueError, match="[Ee]xpired"):
        pq.Scanner.scan(
            id_seed=_seed(),
            invite_bytes=qr_bytes,
            now_unix=200,
        )


def test_scanner_refuses_tampered_invite():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"contact")
    qr_bytes = bytearray(inviter.invite_bytes())
    qr_bytes[len(qr_bytes) - 1] ^= 0x01  # flip last byte of signature
    with pytest.raises(ValueError, match="[Ss]ignature"):
        pq.Scanner.scan(
            id_seed=_seed(),
            invite_bytes=bytes(qr_bytes),
            now_unix=int(time.time()),
        )


# ── Full round-trip ───────────────────────────────────────────────


def test_full_pair_roundtrip_produces_matching_chain_keys():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"contact")
    qr_bytes = inviter.invite_bytes()

    scanner, response_bytes = pq.Scanner.scan(
        id_seed=_seed(),
        invite_bytes=qr_bytes,
        now_unix=int(time.time()),
    )

    sas_inviter = inviter.receive_response(response_bytes)
    sas_scanner = scanner.sas()
    assert sas_inviter == sas_scanner
    assert len(sas_inviter.split(" ")) == pq.SAS_WORD_COUNT

    confirm_bytes, key_inviter = inviter.confirm()
    key_scanner = scanner.receive_confirm(confirm_bytes)

    assert isinstance(key_inviter, bytes)
    assert len(key_inviter) == pq.CHAIN_KEY_LEN
    assert key_inviter == key_scanner


def test_factor2_mix_matches_when_both_supply_same_key():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    qr_bytes = inviter.invite_bytes()
    scanner, response_bytes = pq.Scanner.scan(
        id_seed=_seed(),
        invite_bytes=qr_bytes,
        now_unix=int(time.time()),
    )
    inviter.receive_response(response_bytes)

    f2 = b"\xA5" * 32
    cb = inviter.confirm_with_factor2(f2)
    assert "AwaitingFactor2Ack" in inviter.state()
    ack, k_s = scanner.receive_confirm_with_factor2(cb, f2)
    k_i = inviter.receive_factor2_ack(ack)
    assert k_i == k_s


def test_factor2_mix_rejects_different_keys_without_returning_a_key():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    qr_bytes = inviter.invite_bytes()
    scanner, response_bytes = pq.Scanner.scan(
        id_seed=_seed(),
        invite_bytes=qr_bytes,
        now_unix=int(time.time()),
    )
    inviter.receive_response(response_bytes)

    f2a = b"\xA5" * 32
    f2b = b"\xA6" + b"\xA5" * 31
    cb = inviter.confirm_with_factor2(f2a)
    with pytest.raises(ValueError, match="confirmation"):
        scanner.receive_confirm_with_factor2(cb, f2b)
    assert "AwaitingConfirm" in scanner.state()
    assert "AwaitingFactor2Ack" in inviter.state()


def test_inviter_confirm_with_factor2_validates_key_length():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    with pytest.raises(ValueError, match="32 bytes"):
        inviter.confirm_with_factor2(b"too short")


def test_factor2_tampered_ack_does_not_release_inviter_key():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    scanner, response_bytes = pq.Scanner.scan(
        _seed(), inviter.invite_bytes(), int(time.time())
    )
    inviter.receive_response(response_bytes)
    f2 = b"\xA5" * 32
    cb = inviter.confirm_with_factor2(f2)
    ack, _scanner_key = scanner.receive_confirm_with_factor2(cb, f2)
    tampered = bytes([ack[0] ^ 1]) + ack[1:]
    with pytest.raises(ValueError, match="confirmation"):
        inviter.receive_factor2_ack(tampered)
    assert "AwaitingFactor2Ack" in inviter.state()


def test_factor2_ack_length_validated_before_native_call():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    with pytest.raises(ValueError, match="acknowledgement"):
        inviter.receive_factor2_ack(b"short")


# ── Free functions ────────────────────────────────────────────────


def test_decode_invite_round_trip_fields():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"my-scope")
    qr_bytes = inviter.invite_bytes()
    id_pk, ephem, nonce, expiry, scope = pq.decode_invite(qr_bytes)
    assert id_pk == inviter.id_pubkey()
    assert len(ephem) == 32
    assert len(nonce) == 32
    assert expiry == int(expiry)
    assert scope == b"my-scope"


def test_decode_invite_rejects_tampered_bytes():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"my-scope")
    qr_bytes = bytearray(inviter.invite_bytes())
    qr_bytes[5] ^= 0x80
    with pytest.raises(ValueError):
        pq.decode_invite(bytes(qr_bytes))


def test_sas_from_transcript_deterministic():
    from one_link import pair_qr_native as pq

    t = bytes(range(32))
    s1 = pq.sas_from_transcript(t)
    s2 = pq.sas_from_transcript(t)
    assert s1 == s2
    assert len(s1.split(" ")) == pq.SAS_WORD_COUNT


def test_sas_from_transcript_validates_length():
    from one_link import pair_qr_native as pq

    with pytest.raises(ValueError, match="32 bytes"):
        pq.sas_from_transcript(b"short")


# ── Cross-Python-process two-daemon smoke ─────────────────────────


def test_render_invite_qr_svg_produces_scannable_svg():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry(), b"contact:test")
    qr_bytes = inviter.invite_bytes()
    svg = pq.render_invite_qr_svg(qr_bytes)
    assert isinstance(svg, bytes)
    assert len(svg) > 0
    # Valid SVG header (qrcode lib emits standard SVG 1.1 paths).
    assert svg.startswith(b"<?xml") or svg.startswith(b"<svg")
    assert b"</svg>" in svg


def test_render_invite_qr_svg_rejects_unknown_ec_level():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    qr_bytes = inviter.invite_bytes()
    with pytest.raises(ValueError, match="error_correction"):
        pq.render_invite_qr_svg(qr_bytes, error_correction="Z")


def test_render_invite_qr_svg_rejects_oversize_input():
    from one_link import pair_qr_native as pq

    too_big = b"\x00" * (pq.INVITE_MAX_BYTES + 1)
    with pytest.raises(ValueError, match="oversize"):
        pq.render_invite_qr_svg(too_big)


def test_render_invite_qr_svg_supports_all_ec_levels():
    from one_link import pair_qr_native as pq

    inviter = pq.Inviter(_seed(), _future_expiry())
    qr_bytes = inviter.invite_bytes()
    for ec in ("L", "M", "Q", "H"):
        svg = pq.render_invite_qr_svg(qr_bytes, error_correction=ec)
        assert b"</svg>" in svg


def test_two_independent_inviter_scanner_pairs_dont_collide():
    """Two independent pairs (different identities) running in parallel
    derive different chain keys + their messages don't cross-verify."""
    from one_link import pair_qr_native as pq

    inv_a = pq.Inviter(_seed(), _future_expiry())
    inv_b = pq.Inviter(_seed(), _future_expiry())
    qr_a = inv_a.invite_bytes()
    qr_b = inv_b.invite_bytes()

    scan_a, resp_a = pq.Scanner.scan(_seed(), qr_a, int(time.time()))
    scan_b, resp_b = pq.Scanner.scan(_seed(), qr_b, int(time.time()))

    inv_a.receive_response(resp_a)
    inv_b.receive_response(resp_b)

    cb_a, k_a = inv_a.confirm()
    cb_b, k_b = inv_b.confirm()

    k_scan_a = scan_a.receive_confirm(cb_a)
    k_scan_b = scan_b.receive_confirm(cb_b)

    assert k_a == k_scan_a
    assert k_b == k_scan_b
    assert k_a != k_b

    # Cross-feeding should fail.
    inv_c = pq.Inviter(_seed(), _future_expiry())
    scan_c, _ = pq.Scanner.scan(_seed(), inv_c.invite_bytes(), int(time.time()))
    with pytest.raises(ValueError):
        scan_c.receive_confirm(cb_a)
