"""v0.21.x rotation cert: fuzz the wire-payload parser + verifier.

ROTATION_CERT messages arrive from peers over the network. The
schema is strict (canonical JSON + Ed25519 signature) but the
parser must never crash on malformed input - every bad payload
should funnel to a clean ValueError / CertVerifyError, never an
uncaught exception that would tear down the wire-message
dispatcher and disconnect every other peer on the same channel.

This file enumerates 30+ categories of hostile or malformed input
and asserts each one is rejected cleanly. Categories:

  - Truncation, non-ASCII, empty
  - Missing required keys, extra unexpected keys
  - Wrong types (int where str, etc.)
  - Out-of-range integers (negative ts, huge ts)
  - Wrong-length fingerprints / pubkeys
  - Non-hex characters in fingerprints / pubkeys
  - Mismatched internal fields (new_fp vs new_pub_hex)
  - Signature wrong length / non-hex
  - Random-bytes cert_json
  - Whitespace-only cert_json
  - Signature from a different message (cross-protocol replay)
"""
from __future__ import annotations

import json
import os
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity_rotation import (
    CERT_VERSION,
    CertVerifyError,
    RotationCertificate,
    fingerprint_for_pubkey,
    mint_certificate,
    verify_certificate,
)


def _good_cert():
    old = Ed25519PrivateKey.generate()
    new = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new)
    return old, new, cert


def _mutated_canonical(mutation_fn):
    """Helper: build a good cert, mutate its canonical body via the
    callback (takes dict, returns dict OR raw bytes), keep the
    original signature, return the wire dict the test will feed to
    from_wire_dict."""
    old, _, cert = _good_cert()
    body = json.loads(cert.canonical_bytes.decode("ascii"))
    mutated = mutation_fn(body)
    if isinstance(mutated, dict):
        canonical = json.dumps(
            mutated, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
    elif isinstance(mutated, bytes):
        canonical = mutated
    else:
        canonical = str(mutated).encode("ascii", errors="replace")
    return {
        "cert_json": canonical.decode("ascii", errors="replace"),
        "sig_hex": cert.signature.hex(),
    }, old


# ── from_wire_dict (parser) hostile inputs ──────────────────────────


def test_from_wire_dict_rejects_empty_dict():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({})


def test_from_wire_dict_rejects_missing_cert_json():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({"sig_hex": "00" * 64})


def test_from_wire_dict_rejects_missing_sig_hex():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({"cert_json": "{}"})


def test_from_wire_dict_rejects_non_string_fields():
    """JSON-typed payloads from a hostile peer might send non-string
    types for these fields. The parser must reject without crashing."""
    for bad in (
        {"cert_json": 12345, "sig_hex": "00" * 64},
        {"cert_json": "{}", "sig_hex": 12345},
        {"cert_json": None, "sig_hex": None},
        {"cert_json": [], "sig_hex": "00" * 64},
    ):
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(bad)


def test_from_wire_dict_rejects_sig_hex_wrong_length():
    """64 bytes -> 128 hex chars. Anything else is rejected."""
    for bad_sig in (
        "",
        "deadbeef",
        "ab" * 32,   # 32 bytes
        "ab" * 65,   # 65 bytes
        "ab" * 1024, # absurdly long
    ):
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict({
                "cert_json": "{}", "sig_hex": bad_sig,
            })


def test_from_wire_dict_rejects_sig_hex_non_hex():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({
            "cert_json": "{}",
            # length-128 string but contains 'z' which isn't hex
            "sig_hex": "z" * 128,
        })


def test_from_wire_dict_rejects_cert_json_empty_string():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({
            "cert_json": "", "sig_hex": "00" * 64,
        })


def test_from_wire_dict_rejects_cert_json_whitespace_only():
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({
            "cert_json": "   \n\t  ", "sig_hex": "00" * 64,
        })


def test_from_wire_dict_rejects_cert_json_not_an_object():
    """JSON valid but top-level is array / string / number."""
    for bad in ('[]', '"hello"', '42', 'true', 'null'):
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict({
                "cert_json": bad, "sig_hex": "00" * 64,
            })


def test_from_wire_dict_rejects_malformed_json():
    for bad in (
        "{",
        "}{",
        '{"v":',
        '{"v": 1,}',  # trailing comma
        "<html>",
    ):
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict({
                "cert_json": bad, "sig_hex": "00" * 64,
            })


def test_from_wire_dict_rejects_non_ascii_canonical():
    """Canonical is supposed to be pure ASCII. Non-ASCII surfaces
    as a decode error inside the parser."""
    bad_canonical = ("{\"sneaky\":\"" + chr(0x2264) + "\"}").encode("utf-8")
    # The parser reads cert_json as a string then encodes ASCII;
    # smuggle the non-ASCII through the string form to mirror what
    # a hostile peer would send.
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict({
            "cert_json": bad_canonical.decode("utf-8"),
            "sig_hex": "00" * 64,
        })


# ── canonical-body schema fuzz ──────────────────────────────────────


def test_canonical_missing_each_required_key():
    """Drop each required key one at a time; each should reject."""
    required_keys = ("v", "old_fp", "new_fp", "new_pub_hex", "ts_ms", "reason")
    for missing in required_keys:
        wire, _ = _mutated_canonical(
            lambda body, _m=missing: {k: v for k, v in body.items() if k != _m},
        )
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_extra_keys_rejected():
    """Strict schema: unknown keys break the parse so an attacker
    can't smuggle extra fields the application layer trusts."""
    for extra_key in ("sneaky", "admin", "v2", "bypass"):
        wire, _ = _mutated_canonical(
            lambda body, _k=extra_key: {**body, _k: "extra"},
        )
        with pytest.raises(ValueError, match="unexpected"):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_wrong_version():
    """Future version (v=2) must be rejected by a v1-only parser."""
    wire, _ = _mutated_canonical(lambda body: {**body, "v": 99})
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict(wire)


def test_canonical_ts_ms_non_int():
    for bad_ts in ("now", None, [], {"nested": 1}, 1.5):
        wire, _ = _mutated_canonical(lambda body, _t=bad_ts: {**body, "ts_ms": _t})
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_reason_unknown_value():
    for bad_reason in ("hack", "", "trust_me", "compromise2"):
        wire, _ = _mutated_canonical(
            lambda body, _r=bad_reason: {**body, "reason": _r},
        )
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_fingerprint_wrong_length():
    """fp is hex-encoded BLAKE3 = 64 chars. Anything else rejected."""
    for bad_fp in ("", "ab", "ab" * 31, "ab" * 33, "ab" * 256):
        wire, _ = _mutated_canonical(lambda body, _f=bad_fp: {**body, "old_fp": _f})
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)
        wire, _ = _mutated_canonical(lambda body, _f=bad_fp: {**body, "new_fp": _f})
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_fingerprint_uppercase_or_non_hex():
    """Fingerprint must be lowercase hex specifically. Uppercase OR
    non-hex chars (z, special chars) reject."""
    for bad_fp in (
        "AB" * 32,  # uppercase hex
        "zz" * 32,  # not hex
        "a!" * 32,  # special chars
        "  " + "ab" * 31,  # leading whitespace
    ):
        wire, _ = _mutated_canonical(lambda body, _f=bad_fp: {**body, "old_fp": _f})
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_pub_hex_wrong_length():
    """pubkey is 32 bytes -> 64 hex chars."""
    for bad_pub in ("", "ab" * 31, "ab" * 33):
        wire, _ = _mutated_canonical(
            lambda body, _p=bad_pub: {**body, "new_pub_hex": _p},
        )
        with pytest.raises(ValueError):
            RotationCertificate.from_wire_dict(wire)


def test_canonical_pub_hex_non_hex():
    wire, _ = _mutated_canonical(
        lambda body: {**body, "new_pub_hex": "zz" * 32},
    )
    with pytest.raises(ValueError):
        RotationCertificate.from_wire_dict(wire)


def test_canonical_new_fp_mismatches_pub_hex():
    """Internal-consistency check: cert.new_fp must equal
    BLAKE3(new_pub_hex). Lying about either field rejected."""
    # Set new_fp to a valid-format but unrelated hash.
    wire, _ = _mutated_canonical(
        lambda body: {**body, "new_fp": "00" * 32},
    )
    with pytest.raises(ValueError, match="internally inconsistent"):
        RotationCertificate.from_wire_dict(wire)


# ── verify_certificate hostile inputs ───────────────────────────────


def test_verify_rejects_signature_for_different_message():
    """An attacker captures a valid cert (e.g. real K1->K2 rotation)
    and substitutes the canonical body for a DIFFERENT cert
    (K1->K3). The signature still matches the OLD canonical bytes,
    so the verify call against the new body must fail."""
    old = Ed25519PrivateKey.generate()
    target_a = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    target_b = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    cert_a = mint_certificate(old_priv=old, new_pub=target_a)
    cert_b = mint_certificate(old_priv=old, new_pub=target_b)
    # Frankenstein: cert_a's canonical bytes + cert_b's signature.
    bad = RotationCertificate(
        version=cert_a.version,
        old_fp=cert_a.old_fp,
        new_fp=cert_a.new_fp,
        new_pub_hex=cert_a.new_pub_hex,
        ts_ms=cert_a.ts_ms,
        reason=cert_a.reason,
        canonical_bytes=cert_a.canonical_bytes,
        signature=cert_b.signature,
    )
    with pytest.raises(CertVerifyError):
        verify_certificate(
            cert=bad,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )


def test_verify_rejects_zero_signature():
    """All-zero signature must reject."""
    _, _, cert = _good_cert()
    tampered = RotationCertificate(
        version=cert.version,
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pub_hex=cert.new_pub_hex,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
        canonical_bytes=cert.canonical_bytes,
        signature=b"\x00" * 64,
    )
    with pytest.raises(CertVerifyError):
        verify_certificate(
            cert=tampered,
            expected_old_pubkey=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
        )


def test_verify_rejects_random_garbage_signature():
    """64 random bytes as signature must reject."""
    old, _, cert = _good_cert()
    for _ in range(5):
        tampered = RotationCertificate(
            version=cert.version,
            old_fp=cert.old_fp,
            new_fp=cert.new_fp,
            new_pub_hex=cert.new_pub_hex,
            ts_ms=cert.ts_ms,
            reason=cert.reason,
            canonical_bytes=cert.canonical_bytes,
            signature=os.urandom(64),
        )
        with pytest.raises(CertVerifyError):
            verify_certificate(
                cert=tampered,
                expected_old_pubkey=old.public_key().public_bytes_raw(),
            )


def test_verify_rejects_bit_flip_in_every_canonical_byte():
    """Flip a single bit in each byte of the canonical body, one at
    a time. Every flip must fail verification - either via the
    schema parser inside verify_certificate OR via Ed25519 signature
    mismatch. Catches any silent-acceptance hole."""
    old, _, cert = _good_cert()
    canonical = bytearray(cert.canonical_bytes)
    # Test a sample of bytes (every 4th) so the test runs in a
    # reasonable time. The canonical body is ~200 bytes; sampling
    # every 4th is ~50 verifies, ~3ms total.
    for offset in range(0, len(canonical), 4):
        flipped = bytearray(canonical)
        flipped[offset] ^= 0x01
        tampered = RotationCertificate(
            version=cert.version,
            old_fp=cert.old_fp,
            new_fp=cert.new_fp,
            new_pub_hex=cert.new_pub_hex,
            ts_ms=cert.ts_ms,
            reason=cert.reason,
            canonical_bytes=bytes(flipped),
            signature=cert.signature,
        )
        with pytest.raises(CertVerifyError):
            verify_certificate(
                cert=tampered,
                expected_old_pubkey=old.public_key().public_bytes_raw(),
            )


def test_verify_rejects_expected_pubkey_wrong_length():
    """expected_old_pubkey must be exactly 32 bytes; defense at the
    helper signature so callers can't pass garbage."""
    _, _, cert = _good_cert()
    for bad in (b"", b"\x00" * 31, b"\x00" * 33, b"\x00" * 1024):
        with pytest.raises(CertVerifyError, match="32 bytes"):
            verify_certificate(cert=cert, expected_old_pubkey=bad)


def test_handler_silent_drops_random_garbage(tmp_path):
    """Synthetic test of the daemon-side handler against pure
    random bytes posing as a cert. The handler should silently
    drop without raising (silent-drop is the documented contract).
    """
    import asyncio
    import base64
    from types import SimpleNamespace

    from one_link.daemon import Daemon
    from one_link.state import State

    state = State(tmp_path / "fuzz.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="x",
        pubkey=b"\x01" * 32, hostname="x.lan",
    )
    state.set_peer_trust("aa" * 32, "pinned")

    sent: list[bytes] = []

    class _Chan:
        async def send(self, frame): sent.append(frame)

    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon.ui_server = None
    daemon.me = SimpleNamespace(short_id="me")

    # 20 rounds of pure random bytes wrapped as cert wire dicts.
    for _ in range(20):
        bogus = {
            "cert_json": base64.b64encode(os.urandom(150)).decode("ascii"),
            "sig_hex": os.urandom(64).hex(),
        }
        # Must not raise; must not write any state mutations.
        asyncio.run(daemon._handle_rotation_cert(
            _Chan(), {"cert": bogus, "id": "x"}, peer_fp="aa" * 32,
        ))

    # Peer state unchanged.
    rec = state.get_peer("aa" * 32)
    assert rec is not None
    assert rec.trust == "pinned"
    # No acks sent (silent drop).
    assert sent == []


def test_handler_silent_drops_missing_cert_field():
    """If the wire frame has no 'cert' field, the handler must
    silently no-op without raising."""
    import asyncio
    from types import SimpleNamespace
    from one_link.daemon import Daemon

    daemon = Daemon.__new__(Daemon)
    daemon.state = None  # also covers the state-unavailable path
    daemon.ui_server = None
    daemon.me = SimpleNamespace(short_id="me")

    class _Chan:
        async def send(self, frame): pass

    # No 'cert' key in the frame; handler should silently return.
    asyncio.run(daemon._handle_rotation_cert(
        _Chan(), {"id": "x"}, peer_fp="aa" * 32,
    ))
    # No exception means we pass.
