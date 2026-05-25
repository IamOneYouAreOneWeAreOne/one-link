"""Properties of the v0.21.x rotation-certificate primitive.

This is the load-bearing primitive of the entire identity rotation
feature. If ANY of these invariants ever fail, the rotation feature
is either spoofable (attacker rotates your identity) or unusable
(legitimate rotations are rejected). Hypothesis runs 100s of
random-key examples per test - vastly more coverage than the
example-based tests in tests/test_identity_rotation_v021.py.
"""
from __future__ import annotations

from copy import deepcopy

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import HealthCheck, given, settings, strategies as st

from one_link.identity_rotation import (
    CertVerifyError,
    RotationCertificate,
    RotationReason,
    VALID_REASONS,
    apply_certificate_to_peer,
    fingerprint_for_pubkey,
    mint_certificate,
    verify_certificate,
)


# Hypothesis can't generate Ed25519 keys directly - generate seeds
# and derive the keys inside each test body.
@st.composite
def ed_keypair(draw):
    seed = draw(st.binary(min_size=32, max_size=32))
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    return priv


# ── mint → verify round-trip ──────────────────────────────────────


@given(
    old=ed_keypair(),
    new=ed_keypair(),
    reason=st.sampled_from(sorted(VALID_REASONS)),
    ts_ms=st.integers(min_value=0, max_value=2**62),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_mint_then_verify_round_trips_for_every_keypair(old, new, reason, ts_ms):
    """The load-bearing property: a cert minted with the OLD
    private key verifies under the OLD public key, for any pair
    of Ed25519 keys + any valid reason + any timestamp. If this
    fails for ANY input, legitimate rotations would be silently
    rejected for that user."""
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(
        old_priv=old, new_pub=new_pub, reason=reason, ts_ms=ts_ms,
    )
    # verify_certificate raises CertVerifyError on any failure.
    verify_certificate(
        cert=cert,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
    )


@given(old=ed_keypair(), new=ed_keypair(), attacker=ed_keypair())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_verify_rejects_cert_under_wrong_pubkey(old, new, attacker):
    """Symmetric: a cert minted with old's key MUST NOT verify
    under any other pubkey. If this fails, ANY peer could claim
    the rotation cert was theirs - identity theft. Skip the
    trivially-equal case (attacker == old)."""
    if attacker.public_key().public_bytes_raw() == old.public_key().public_bytes_raw():
        return
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new_pub)
    try:
        verify_certificate(
            cert=cert,
            expected_old_pubkey=attacker.public_key().public_bytes_raw(),
        )
    except CertVerifyError:
        return  # correct: rejected
    assert False, (
        "verify accepted a cert under the WRONG old pubkey; "
        "any peer could now masquerade as the cert author. "
        "Identity-theft-class regression."
    )


# ── signature tampering ──────────────────────────────────────────


@given(
    old=ed_keypair(),
    new=ed_keypair(),
    flip_byte=st.integers(min_value=0, max_value=63),
    flip_bit=st.integers(min_value=0, max_value=7),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_verify_rejects_cert_with_flipped_signature_bit(
    old, new, flip_byte, flip_bit,
):
    """Flipping ANY bit in the signature must cause verification
    to fail. If it succeeds, the signature is malleable + the
    cert is forgeable."""
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new_pub)
    # Tamper signature.
    sig = bytearray(cert.signature)
    sig[flip_byte] ^= (1 << flip_bit)
    tampered = RotationCertificate(
        version=cert.version,
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pub_hex=cert.new_pub_hex,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
        canonical_bytes=cert.canonical_bytes,
        signature=bytes(sig),
    )
    try:
        verify_certificate(
            cert=tampered,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )
    except CertVerifyError:
        return  # correct: rejected
    assert False, (
        f"verify accepted a cert with a flipped bit "
        f"(byte {flip_byte}, bit {flip_bit}) in the signature; "
        "signature is malleable + forgeable."
    )


@given(
    old=ed_keypair(),
    new=ed_keypair(),
    flip_index=st.integers(min_value=0, max_value=1000),
    flip_bit=st.integers(min_value=0, max_value=7),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_verify_rejects_cert_with_tampered_body(
    old, new, flip_index, flip_bit,
):
    """Flipping ANY bit in the canonical body must cause
    verification to fail. (Sign-then-mac-the-body invariant.)"""
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new_pub)
    body = bytearray(cert.canonical_bytes)
    if flip_index >= len(body):
        return  # out of range; skip
    body[flip_index] ^= (1 << flip_bit)
    tampered = RotationCertificate(
        version=cert.version,
        old_fp=cert.old_fp,
        new_fp=cert.new_fp,
        new_pub_hex=cert.new_pub_hex,
        ts_ms=cert.ts_ms,
        reason=cert.reason,
        canonical_bytes=bytes(body),
        signature=cert.signature,
    )
    try:
        verify_certificate(
            cert=tampered,
            expected_old_pubkey=old.public_key().public_bytes_raw(),
        )
    except CertVerifyError:
        return  # correct: rejected
    assert False, (
        f"verify accepted a cert with a flipped body bit "
        f"(byte {flip_index}, bit {flip_bit}); the body→sig "
        "binding is broken."
    )


# ── wire-format round-trip ──────────────────────────────────────


@given(old=ed_keypair(), new=ed_keypair())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_to_wire_dict_then_from_wire_dict_roundtrip(old, new):
    """Cert serializes to a wire dict + deserializes back to a
    cert that verifies under the same pubkey. Catches any drift
    between the in-memory + on-wire formats."""
    new_pub = new.public_key().public_bytes_raw()
    cert = mint_certificate(old_priv=old, new_pub=new_pub)
    wire = cert.to_wire_dict()
    recovered = RotationCertificate.from_wire_dict(wire)
    assert recovered.old_fp == cert.old_fp
    assert recovered.new_fp == cert.new_fp
    assert recovered.signature == cert.signature
    assert recovered.canonical_bytes == cert.canonical_bytes
    # And it still verifies.
    verify_certificate(
        cert=recovered,
        expected_old_pubkey=old.public_key().public_bytes_raw(),
    )


# ── fingerprint determinism ─────────────────────────────────────


@given(pub=st.binary(min_size=32, max_size=32))
@settings(max_examples=200)
def test_fingerprint_is_deterministic(pub):
    """fingerprint_for_pubkey(p) is a pure function. Two calls
    with the same pubkey return the same fingerprint - if not,
    the entire peer-identity system desyncs across runs."""
    fp1 = fingerprint_for_pubkey(pub)
    fp2 = fingerprint_for_pubkey(pub)
    assert fp1 == fp2
    # And it's a 64-hex-char string (BLAKE3-256).
    assert len(fp1) == 64
    assert all(c in "0123456789abcdef" for c in fp1)


@given(
    pub_a=st.binary(min_size=32, max_size=32),
    pub_b=st.binary(min_size=32, max_size=32),
)
@settings(max_examples=100)
def test_fingerprint_is_injective_for_distinct_pubs(pub_a, pub_b):
    """Distinct pubkeys MUST produce distinct fingerprints. A
    collision means two peers with different keys appear to be
    the same peer to the daemon - catastrophic mix-up. (BLAKE3
    collisions are vanishingly unlikely; this just pins the
    contract for the property layer.)"""
    if pub_a == pub_b:
        return
    assert fingerprint_for_pubkey(pub_a) != fingerprint_for_pubkey(pub_b)
