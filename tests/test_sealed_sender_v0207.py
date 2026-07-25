"""v0.20.7 — Sealed Sender (Signal-style sender-identity hiding).

The legacy relay route exposed its destination identity; the live v2 route
uses a rotating pairwise tag. These tests isolate the sealed envelope that
hides the sender identity inside recipient-only ciphertext. Socket, timing,
size, and rotating-tag metadata remain outside this primitive's scope.

These tests pin:
  - Ed25519 ↔ X25519 conversion is correct for sealed-sender ECDH
  - seal + unseal round-trip restores the original body + sender
    identity + timestamp
  - The wire blob carries NO plaintext sender pubkey (the whole
    point: relay can't read it)
  - Wrong recipient cannot decrypt
  - Tamper on the ciphertext / ephemeral pubkey is rejected
  - A fake signature (someone NOT the claimed sender) is rejected
  - Untrusted-sender (not in paired set) is rejected
  - Stale-timestamp (outside freshness window) is rejected
  - Future-timestamp is rejected
"""
from __future__ import annotations

import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import sealed_sender as ss


def _gen_ed25519():
    """Return (priv_seed_bytes, pub_bytes)."""
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


# ── basic round-trip ───────────────────────────────────────────────


def test_seal_unseal_round_trip():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    body = b"hello bob, signal here, this never reaches the relay's social graph"
    blob = ss.seal(
        body=body,
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
    )
    msg = ss.unseal(
        blob=blob,
        my_ed_priv_seed=recipient_seed,
        paired_ed_pubs=[sender_pub],
    )
    assert msg.body == body
    assert msg.sender_ed_pub == sender_pub
    # Timestamp is recent (within last 5s).
    assert abs(msg.timestamp_ms - int(time.time() * 1000)) < 5000


def test_blob_does_not_contain_sender_pub():
    """The defining property: the wire blob carries NO sender
    pubkey in plaintext. Greppable verification."""
    sender_seed, sender_pub = _gen_ed25519()
    _, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"no metadata for you",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
    )
    assert sender_pub not in blob


def test_blob_changes_per_call():
    """Two calls with the same inputs must produce DIFFERENT blobs
    (fresh ephemeral pubkey per send)."""
    sender_seed, sender_pub = _gen_ed25519()
    _, recipient_pub = _gen_ed25519()
    a = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    b = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    assert a != b


def test_embedding_context_is_cryptographically_domain_separated():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"identity-bearing first flight",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        aad_context=b"OL/relay-handshake/initiator/v1",
    )
    opened = ss.unseal(
        blob=blob,
        my_ed_priv_seed=recipient_seed,
        paired_ed_pubs=[sender_pub],
        aad_context=b"OL/relay-handshake/initiator/v1",
    )
    assert opened.body == b"identity-bearing first flight"

    with pytest.raises(ValueError, match="decrypt failed"):
        ss.unseal(
            blob=blob,
            my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[sender_pub],
            aad_context=b"OL/relay-handshake/responder/v1",
        )


# ── failure modes ──────────────────────────────────────────────────


def test_wrong_recipient_cannot_decrypt():
    sender_seed, sender_pub = _gen_ed25519()
    _, recipient_pub = _gen_ed25519()
    other_seed, _ = _gen_ed25519()
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    with pytest.raises(ValueError, match="decrypt failed"):
        ss.unseal(
            blob=blob, my_ed_priv_seed=other_seed,
            paired_ed_pubs=[sender_pub],
        )


def test_tampered_ciphertext_rejected():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = bytearray(ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    ))
    # Flip a byte deep in the ciphertext.
    blob[-10] ^= 0xff
    with pytest.raises(ValueError):
        ss.unseal(
            blob=bytes(blob), my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[sender_pub],
        )


def test_tampered_ephemeral_pubkey_rejected():
    """The eph_pub is bound into the AAD, so flipping a byte
    invalidates the tag even though the AEAD ciphertext itself
    is untouched."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = bytearray(ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    ))
    blob[5] ^= 0xff  # within the eph_pub region
    with pytest.raises(ValueError):
        ss.unseal(
            blob=bytes(blob), my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[sender_pub],
        )


def test_unpaired_sender_rejected():
    """If the sender pubkey isn't in the recipient's paired set,
    refuse — even if the AEAD + signature are valid. Stops a
    paired-with-Bob attacker from impersonating Alice to Bob's
    contact Charlie."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    other_paired_pub = _gen_ed25519()[1]  # someone ELSE
    with pytest.raises(ValueError, match="not in paired set"):
        ss.unseal(
            blob=blob, my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[other_paired_pub],
        )


def test_no_paired_set_accepts_any_sender():
    """When ``paired_ed_pubs=None``, unseal skips the trust check.
    Useful for explicitly-anonymous flows (public bulletin); the
    caller is responsible for being deliberate about it."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    # No paired_ed_pubs supplied → no trust check.
    msg = ss.unseal(
        blob=blob, my_ed_priv_seed=recipient_seed,
    )
    assert msg.sender_ed_pub == sender_pub


def test_stale_timestamp_rejected():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    # Mint a sealed envelope dated 1 hour in the past.
    past = int(time.time() * 1000) - 60 * 60 * 1000
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
        timestamp_ms=past,
    )
    with pytest.raises(ValueError, match="freshness"):
        ss.unseal(
            blob=blob, my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[sender_pub],
            freshness_window_ms=5 * 60 * 1000,
        )


def test_future_timestamp_rejected():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    # Date 1 hour in the future.
    future = int(time.time() * 1000) + 60 * 60 * 1000
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
        timestamp_ms=future,
    )
    with pytest.raises(ValueError, match="freshness"):
        ss.unseal(
            blob=blob, my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[sender_pub],
        )


def test_freshness_check_disabled_with_none():
    """Setting ``freshness_window_ms=None`` skips the timestamp
    check (e.g. for archival messages where time is irrelevant)."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    past = 1_000_000_000  # year 1970-ish
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
        timestamp_ms=past,
    )
    msg = ss.unseal(
        blob=blob, my_ed_priv_seed=recipient_seed,
        paired_ed_pubs=[sender_pub],
        freshness_window_ms=None,
    )
    assert msg.body == b"x"
    assert msg.timestamp_ms == past


def test_blob_too_short():
    _, recipient_seed_pub = _gen_ed25519()
    with pytest.raises(ValueError, match="too short"):
        ss.unseal(
            blob=b"\x00" * 10, my_ed_priv_seed=os.urandom(32),
        )


def test_signature_forgery_rejected():
    """A malicious sender who knows the recipient's pub but NOT a
    given sender's priv seed cannot forge a sealed envelope claiming
    to come from that sender. This is the impersonation defense."""
    real_sender_seed, real_sender_pub = _gen_ed25519()
    # Mallory has her own keys, but tries to claim to be the real
    # sender. She constructs a sealed envelope with real_sender_pub
    # in the inner header, but signed with HER OWN priv. The signature
    # then fails to verify under real_sender_pub.
    mallory_seed, _ = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"hi from 'real sender'",
        sender_ed_priv_seed=mallory_seed,
        sender_ed_pub=real_sender_pub,  # claim to be them
        recipient_ed_pub=recipient_pub,
    )
    with pytest.raises(ValueError, match="signature does not verify"):
        ss.unseal(
            blob=blob, my_ed_priv_seed=recipient_seed,
            paired_ed_pubs=[real_sender_pub],
        )


# ── interop with paired-set list types ────────────────────────────


def test_paired_set_accepts_iterable():
    """The paired set parameter is Iterable[bytes]; it works with
    list, tuple, set, generator."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    blob = ss.seal(
        body=b"x", sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub, recipient_ed_pub=recipient_pub,
    )
    # Generator
    msg = ss.unseal(
        blob=blob, my_ed_priv_seed=recipient_seed,
        paired_ed_pubs=(p for p in [sender_pub, b"x" * 32]),
    )
    assert msg.body == b"x"
    # Set
    msg2 = ss.unseal(
        blob=blob, my_ed_priv_seed=recipient_seed,
        paired_ed_pubs={sender_pub},
    )
    assert msg2.body == b"x"
