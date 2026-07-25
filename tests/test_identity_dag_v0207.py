"""v0.20.7 — Identity DAG (multi-device identity without shared keys).

Today One Link identity = one Ed25519 keypair = one device. Bundle
45 ships a DAG model: a master root keypair signs device certs,
each device has its own keypair, attestations bind a device to a
specific session via the verifier's challenge + the channel
transcript.

Properties:
  - One device compromise = ONE device revoked. Root key stays
    cold; revoking a phone doesn't touch the laptop's cert.
  - Multi-device discovery: any of the user's N devices can sign
    for the user's identity.
  - Composes with social recovery (Bundle 35): root seed restores
    via 3-of-5 trusted contacts; from there, mint new device
    certs for remaining devices, revoke the lost ones.

These tests pin:
  - Cert encode + parse round-trip preserves all fields
  - Cert signature verifies under root_pub
  - Cert with expires_ms=0 never expires; cert with non-zero
    expires_ms past now_ms is rejected
  - Tampered cert (any field) is rejected
  - Attestation encode + parse + verify round-trip
  - Attestation rejected when challenge doesn't match
  - Attestation rejected when transcript doesn't match
  - Attestation rejected when device_priv doesn't correspond
    to cert.device_pub
  - Replay defense: same attestation against a different challenge
    fails
  - Cert rejection when root_pub == device_pub (degenerate)
  - Length-limit enforcement on device_kind, challenge, transcript
"""
from __future__ import annotations


import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import identity_dag as idag


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


# ── DeviceCert ────────────────────────────────────────────────────


def test_cert_round_trip():
    root_seed, root_pub = _gen_ed25519()
    device_seed, device_pub = _gen_ed25519()
    blob = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="phone-ios",
    )
    parsed = idag.verify_device_cert(blob)
    assert parsed.root_pub == root_pub
    assert parsed.device_pub == device_pub
    assert parsed.device_kind == "phone-ios"
    assert parsed.expires_ms == 0  # never expires by default


def test_cert_signature_under_root_pub():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="laptop",
    )
    other_root_pub = _gen_ed25519()[1]
    with pytest.raises(ValueError, match="root_pub doesn't match"):
        idag.verify_device_cert(blob, expected_root_pub=other_root_pub)


def test_cert_with_expiry():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    base = 1_000_000_000_000
    blob = idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x",
        added_ms=base, expires_ms=base + 60_000,
    )
    # Within window: OK.
    idag.verify_device_cert(blob, now_ms=base + 30_000)
    # Past expiry: rejected.
    with pytest.raises(ValueError, match="expired"):
        idag.verify_device_cert(blob, now_ms=base + 60_001)


def test_cert_zero_expires_never_expires():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x", expires_ms=0,
    )
    # Far in the future — still valid (no expiry).
    idag.verify_device_cert(blob, now_ms=2**62)


def test_cert_not_valid_before_issuance_beyond_clock_skew():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    now_ms = int(time.time() * 1000)
    blob = idag.encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind="phone",
        added_ms=now_ms + idag.MAX_CERT_FUTURE_SKEW_MS + 1,
    )

    with pytest.raises(ValueError, match="issuance is in the future"):
        idag.verify_device_cert(blob, now_ms=now_ms)


@pytest.mark.parametrize("field", ["added_ms", "expires_ms"])
def test_cert_encoder_rejects_boolean_timestamps(field: str):
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    kwargs = {"added_ms": 1, "expires_ms": 0}
    kwargs[field] = True

    with pytest.raises(ValueError, match=f"{field} must be an integer"):
        idag.encode_device_cert(
            root_priv_seed=root_seed,
            root_pub=root_pub,
            device_pub=device_pub,
            device_kind="phone",
            **kwargs,
        )


def test_cert_signature_tamper_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = bytearray(idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x",
    ))
    blob[-1] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        idag.verify_device_cert(bytes(blob))


def test_cert_device_pub_tamper_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = bytearray(idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x",
    ))
    # device_pub starts at offset 7 + 32 = 39.
    blob[40] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        idag.verify_device_cert(bytes(blob))


def test_cert_root_pub_tamper_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = bytearray(idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x",
    ))
    # root_pub starts at offset 7. Flipping a byte makes the
    # signature verify-attempt happen under a wrong key, fails.
    blob[8] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        idag.verify_device_cert(bytes(blob))


def test_root_equal_device_rejected_at_encode():
    seed, pub = _gen_ed25519()
    with pytest.raises(ValueError, match="must differ"):
        idag.encode_device_cert(
            root_priv_seed=seed, root_pub=pub,
            device_pub=pub, device_kind="x",
        )


def test_empty_device_kind_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="must not be empty"):
        idag.encode_device_cert(
            root_priv_seed=root_seed, root_pub=root_pub,
            device_pub=device_pub, device_kind="",
        )


def test_device_kind_too_long_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="too long"):
        idag.encode_device_cert(
            root_priv_seed=root_seed, root_pub=root_pub,
            device_pub=device_pub,
            device_kind="x" * (idag.MAX_DEVICE_KIND_LEN + 1),
        )


def test_invalid_expires_rejected():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    with pytest.raises(ValueError):
        idag.encode_device_cert(
            root_priv_seed=root_seed, root_pub=root_pub,
            device_pub=device_pub, device_kind="x",
            added_ms=2000, expires_ms=1000,
        )


def test_parse_too_short():
    with pytest.raises(ValueError, match="too short"):
        idag.parse_device_cert(b"\x00" * 10)


def test_parse_bad_magic():
    root_seed, root_pub = _gen_ed25519()
    _, device_pub = _gen_ed25519()
    blob = bytearray(idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="x",
    ))
    blob[0:6] = b"NOTOLI"
    with pytest.raises(ValueError, match="bad magic"):
        idag.parse_device_cert(bytes(blob))


# ── SessionAttestation ────────────────────────────────────────────


def _signed_cert_pair():
    """Helper: make a (root, device) pair + signed cert."""
    root_seed, root_pub = _gen_ed25519()
    device_seed, device_pub = _gen_ed25519()
    cert = idag.encode_device_cert(
        root_priv_seed=root_seed, root_pub=root_pub,
        device_pub=device_pub, device_kind="phone-ios",
    )
    return root_pub, device_seed, device_pub, cert


def test_attestation_round_trip():
    root_pub, device_seed, device_pub, cert = _signed_cert_pair()
    challenge = idag.fresh_challenge()
    transcript = b"channel-transcript-hash"
    att = idag.encode_attestation(
        device_priv_seed=device_seed, cert=cert,
        challenge=challenge, transcript=transcript,
    )
    parsed = idag.verify_attestation(
        att,
        expected_root_pub=root_pub,
        expected_challenge=challenge,
        expected_transcript=transcript,
    )
    assert parsed.cert.device_pub == device_pub
    assert parsed.challenge == challenge
    assert parsed.transcript == transcript


def test_attestation_wrong_challenge_rejected():
    """A captured attestation can't be replayed against a different
    verifier challenge — that's the freshness defense."""
    root_pub, device_seed, _, cert = _signed_cert_pair()
    att = idag.encode_attestation(
        device_priv_seed=device_seed, cert=cert,
        challenge=b"original-challenge", transcript=b"x",
    )
    with pytest.raises(ValueError, match="challenge"):
        idag.verify_attestation(
            att, expected_challenge=b"different-challenge",
            expected_transcript=b"x",
        )


def test_attestation_wrong_transcript_rejected():
    root_pub, device_seed, _, cert = _signed_cert_pair()
    att = idag.encode_attestation(
        device_priv_seed=device_seed, cert=cert,
        challenge=b"c", transcript=b"original-transcript",
    )
    with pytest.raises(ValueError, match="transcript"):
        idag.verify_attestation(
            att, expected_challenge=b"c",
            expected_transcript=b"different-transcript",
        )


def test_attestation_wrong_device_priv_rejected():
    """Mallory tries to attest using her own priv but presenting
    Bob's cert. The signature verifies under Bob's device_pub
    (from the cert), not Mallory's, so it fails."""
    root_pub, _, _, cert = _signed_cert_pair()
    mallory_seed, _ = _gen_ed25519()
    att = idag.encode_attestation(
        device_priv_seed=mallory_seed, cert=cert,
        challenge=b"c", transcript=b"t",
    )
    with pytest.raises(ValueError, match="signature invalid"):
        idag.verify_attestation(att)


def test_attestation_wrong_root_pub_rejected():
    """A cert minted under root_A can't pass for identity B."""
    root_pub_a, device_seed, _, cert = _signed_cert_pair()
    _, root_pub_b = _gen_ed25519()
    att = idag.encode_attestation(
        device_priv_seed=device_seed, cert=cert,
        challenge=b"c", transcript=b"t",
    )
    with pytest.raises(ValueError, match="root_pub"):
        idag.verify_attestation(att, expected_root_pub=root_pub_b)


def test_attestation_oversized_challenge_rejected():
    _, device_seed, _, cert = _signed_cert_pair()
    big = b"x" * (idag.MAX_CHALLENGE_LEN + 1)
    with pytest.raises(ValueError, match="challenge"):
        idag.encode_attestation(
            device_priv_seed=device_seed, cert=cert,
            challenge=big, transcript=b"x",
        )


def test_attestation_empty_challenge_rejected():
    _, device_seed, _, cert = _signed_cert_pair()
    with pytest.raises(ValueError):
        idag.encode_attestation(
            device_priv_seed=device_seed, cert=cert,
            challenge=b"", transcript=b"x",
        )


def test_fresh_challenge_is_random():
    a = idag.fresh_challenge()
    b = idag.fresh_challenge()
    assert a != b
    assert len(a) == 32


# ── multi-device scenario ────────────────────────────────────────


def test_multi_device_identity_workflow():
    """Realistic scenario: Alice has a phone + laptop + tablet, all
    sharing one root identity. Each device has its own cert + priv
    key. A peer can verify any of them as a member of Alice's
    identity."""
    root_seed, root_pub = _gen_ed25519()
    devices = []
    for kind in ("phone-ios", "laptop-macos", "tablet-android"):
        seed, pub = _gen_ed25519()
        cert = idag.encode_device_cert(
            root_priv_seed=root_seed, root_pub=root_pub,
            device_pub=pub, device_kind=kind,
        )
        devices.append((kind, seed, pub, cert))

    # Bob (the peer) issues a challenge per session and wants any
    # of Alice's devices to attest. All three should work.
    challenge = idag.fresh_challenge()
    transcript = b"alice-bob-transcript"
    for kind, seed, pub, cert in devices:
        att = idag.encode_attestation(
            device_priv_seed=seed, cert=cert,
            challenge=challenge, transcript=transcript,
        )
        parsed = idag.verify_attestation(
            att, expected_root_pub=root_pub,
            expected_challenge=challenge,
            expected_transcript=transcript,
        )
        assert parsed.cert.device_kind == kind

    # If Alice loses the phone, she can revoke just THAT cert
    # without invalidating the laptop or tablet — by adding the
    # phone's device_pub to a revocation list (out of scope here;
    # the property pinned is that revoking-by-pub only affects
    # one branch of the DAG). The laptop's attestation still
    # passes:
    _, laptop_seed, laptop_pub, laptop_cert = devices[1]
    att = idag.encode_attestation(
        device_priv_seed=laptop_seed, cert=laptop_cert,
        challenge=challenge, transcript=transcript,
    )
    parsed = idag.verify_attestation(att, expected_root_pub=root_pub)
    assert parsed.cert.device_pub == laptop_pub
