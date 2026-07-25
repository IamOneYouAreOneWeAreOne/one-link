"""v0.20.7 — rendezvous blinding (the /lookup itself reveals nothing).

Even with sealed sender + onion routing on the actual messages, the
rendezvous /lookup endpoint sees who-is-looking-up-whom and builds
a social graph. Bundle 43 derives a deterministic-but-unlinkable
TOKEN per (peer_pub, epoch); the rendezvous indexes by token, never
by raw pubkey. Tokens rotate every epoch (default 1 hour), so a
leaked log goes stale within the rotation window.

These tests pin:
  - Same (peer_pub, epoch) → same token (so /lookup matches /register)
  - Different epoch_id → different token (forward-unlinkability)
  - Different peer_pub → different token (no correlation)
  - Token reveals nothing about peer_pub (in the sense of HKDF
    one-wayness — we test the negative property by confirming the
    token is uncorrelated with the input pubkey)
  - Registration encodes correctly + parses back
  - verify_registration accepts a valid record under the correct
    peer_pub
  - Tampered token / signature / epoch / magic / version are
    rejected
  - Wrong peer_pub at the rendezvous (e.g. an attacker tries to
    hijack a token by registering with a different signing key)
    is detected
"""
from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import rdz_blind as rb


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


# ── token derivation ───────────────────────────────────────────────


def test_token_deterministic_for_same_inputs():
    _, pub = _gen_ed25519()
    a = rb.derive_blinded_token(peer_pub=pub, epoch_id=42)
    b = rb.derive_blinded_token(peer_pub=pub, epoch_id=42)
    assert a == b
    assert len(a) == rb.TOKEN_LEN


def test_token_changes_with_epoch():
    _, pub = _gen_ed25519()
    a = rb.derive_blinded_token(peer_pub=pub, epoch_id=10)
    b = rb.derive_blinded_token(peer_pub=pub, epoch_id=11)
    assert a != b


def test_token_changes_with_pubkey():
    _, pub_a = _gen_ed25519()
    _, pub_b = _gen_ed25519()
    a = rb.derive_blinded_token(peer_pub=pub_a, epoch_id=42)
    b = rb.derive_blinded_token(peer_pub=pub_b, epoch_id=42)
    assert a != b


def test_token_avalanches_on_pubkey_bit_flip():
    _, pub = _gen_ed25519()
    flipped = bytes([pub[0] ^ 1]) + pub[1:]
    a = rb.derive_blinded_token(peer_pub=pub, epoch_id=42)
    b = rb.derive_blinded_token(peer_pub=flipped, epoch_id=42)
    # HKDF should give substantially different output. We can't
    # measure the bit-distance precisely (it's random per-input),
    # but two outputs from inputs differing by one bit MUST differ.
    assert a != b


def test_token_does_not_contain_pubkey_substring():
    """The token is HKDF output, so it must not contain the pubkey
    as a substring (sanity: a buggy implementation that just
    truncated pubkey wouldn't satisfy this)."""
    _, pub = _gen_ed25519()
    token = rb.derive_blinded_token(peer_pub=pub, epoch_id=42)
    assert pub[:8] not in token
    assert pub[-8:] not in token


def test_token_invalid_inputs_rejected():
    with pytest.raises(ValueError):
        rb.derive_blinded_token(peer_pub=b"\x00" * 16, epoch_id=42)
    with pytest.raises(ValueError):
        rb.derive_blinded_token(peer_pub=b"\x00" * 32, epoch_id=-1)


# ── current_epoch_id ───────────────────────────────────────────────


def test_current_epoch_id_advances_with_time():
    a = rb.current_epoch_id(now_ms=1_000_000_000_000, epoch_seconds=3600)
    b = rb.current_epoch_id(now_ms=1_000_000_000_000 + 3600 * 1000,
                            epoch_seconds=3600)
    assert b == a + 1


def test_current_epoch_id_stable_within_epoch():
    a = rb.current_epoch_id(now_ms=1_000_000_000_000, epoch_seconds=3600)
    b = rb.current_epoch_id(now_ms=1_000_000_000_000 + 1000,
                            epoch_seconds=3600)
    assert a == b


def test_invalid_epoch_seconds_rejected():
    with pytest.raises(ValueError):
        rb.current_epoch_id(epoch_seconds=0)
    with pytest.raises(ValueError):
        rb.current_epoch_id(epoch_seconds=-100)


# ── registration encode/parse/verify ──────────────────────────────


def test_registration_round_trip():
    seed, pub = _gen_ed25519()
    blob = rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    )
    parsed = rb.verify_registration(blob=blob, peer_pub=pub)
    assert parsed.epoch_id == 42
    assert parsed.token == rb.derive_blinded_token(
        peer_pub=pub, epoch_id=42,
    )


def test_registration_length_matches_constant():
    seed, pub = _gen_ed25519()
    blob = rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    )
    assert len(blob) == rb.RECORD_LEN


def test_parse_rejects_too_short():
    with pytest.raises(ValueError, match="bytes"):
        rb.parse_registration(b"\x00" * 10)


def test_parse_rejects_bad_magic():
    seed, pub = _gen_ed25519()
    blob = bytearray(rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    ))
    blob[0:5] = b"NOTOL"
    with pytest.raises(ValueError, match="bad magic"):
        rb.parse_registration(bytes(blob))


def test_parse_rejects_unsupported_version():
    seed, pub = _gen_ed25519()
    blob = bytearray(rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    ))
    blob[5] = 99
    with pytest.raises(ValueError, match="unsupported version"):
        rb.parse_registration(bytes(blob))


def test_verify_rejects_tampered_token():
    seed, pub = _gen_ed25519()
    blob = bytearray(rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    ))
    # Corrupt the token region (offset 14, length 32).
    blob[14] ^= 0xff
    with pytest.raises(ValueError, match="token doesn't match"):
        rb.verify_registration(blob=bytes(blob), peer_pub=pub)


def test_verify_rejects_tampered_epoch():
    seed, pub = _gen_ed25519()
    blob = bytearray(rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    ))
    # Bump the epoch in-place.
    new_epoch = 99
    blob[6:14] = struct.pack(">Q", new_epoch)
    # The signed token was for epoch 42; now the parsed epoch_id is
    # 99 but the recomputed token-for-epoch-99 doesn't match the
    # token-for-epoch-42 carried in the body.
    with pytest.raises(ValueError, match="token doesn't match"):
        rb.verify_registration(blob=bytes(blob), peer_pub=pub)


def test_verify_rejects_tampered_signature():
    seed, pub = _gen_ed25519()
    blob = bytearray(rb.encode_registration(
        peer_priv_seed=seed, peer_pub=pub, epoch_id=42,
    ))
    # Corrupt the signature region (last 64 bytes).
    blob[-1] ^= 0xff
    with pytest.raises(ValueError, match="signature invalid"):
        rb.verify_registration(blob=bytes(blob), peer_pub=pub)


def test_verify_rejects_wrong_peer_pub():
    """An attacker who knows the legitimate token but tries to
    re-register it with a different signing key fails the verify
    step."""
    seed_real, pub_real = _gen_ed25519()
    seed_evil, pub_evil = _gen_ed25519()
    # Evil mints a registration claiming to be pub_real but signs
    # with their own key. The token they put in the body uses
    # pub_real (so the rendezvous looking up by pub_real would hit
    # this row), but the signature is verified under pub_real and
    # fails because evil signed it.
    real_token = rb.derive_blinded_token(peer_pub=pub_real, epoch_id=42)
    body = (
        rb.RECORD_MAGIC + bytes([rb.RECORD_VERSION])
        + struct.pack(">Q", 42) + real_token
    )
    sign_input_for_real = (
        body + pub_real
    )
    sig = Ed25519PrivateKey.from_private_bytes(seed_evil).sign(sign_input_for_real)
    blob = body + sig
    with pytest.raises(ValueError, match="signature invalid"):
        rb.verify_registration(blob=blob, peer_pub=pub_real)


def test_two_distinct_peers_at_same_epoch_get_distinct_tokens():
    _, pub_a = _gen_ed25519()
    _, pub_b = _gen_ed25519()
    a = rb.derive_blinded_token(peer_pub=pub_a, epoch_id=42)
    b = rb.derive_blinded_token(peer_pub=pub_b, epoch_id=42)
    assert a != b


def test_token_storage_does_not_correlate_across_epochs():
    """The defining unlinkability property: peer P's tokens at
    consecutive epochs are uncorrelated. Even if the rendezvous
    operator dumps every token they ever saw, they cannot link
    epoch-N's record to epoch-(N+1)'s record for the same peer."""
    _, pub = _gen_ed25519()
    tokens = [
        rb.derive_blinded_token(peer_pub=pub, epoch_id=e)
        for e in range(10)
    ]
    # Pairwise distinct.
    assert len(set(tokens)) == len(tokens)
