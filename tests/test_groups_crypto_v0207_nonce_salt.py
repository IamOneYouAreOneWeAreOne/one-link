"""Nonce-reuse defence and rolling compatibility for group AEAD.

Pre-v0.20.7 the group AEAD nonce was deterministic ``(epoch, counter)``.
A daemon that crashed mid-send and restarted with a stale persisted
chain_key would re-emit a frame at the same ``(key, nonce)`` —
catastrophic ChaCha20 keystream reuse.

v2 added a four-byte random suffix. v3 replaces that 32-bit collision
ceiling with a full 96-bit random ChaCha20 nonce. These tests pin:

  - new-sender frames are v3 with a full random nonce per send,
  - v1 frames are still accepted on receive (rolling-upgrade safety),
  - the nonce_salt is part of the AAD (flipped salt → AEAD fail),
  - the nonce_salt is part of the signed input (a relay can't
    substitute a salt to force a collision),
  - mixing v1/v3 across the same chain works (legacy peer + new peer
    both hit the same ReceivingChain).
"""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import groups_crypto as gc


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _make_party():
    """Return (private_key, sender_chain, receiver_chain) at epoch 1."""
    priv = Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    group_id = b"\x10" * 16
    chain_key = gc.new_chain_key()
    sender = gc.SenderChain(
        group_id=group_id,
        sender_pubkey=pub_bytes,
        epoch=1,
        chain_key=chain_key,
    )
    receiver = gc.ReceivingChain(
        group_id=group_id,
        sender_pubkey=pub_bytes,
        epoch=1,
        chain_key=chain_key,
    )
    return priv, sender, receiver


def test_new_frames_emit_v3_with_full_entropy_nonce():
    priv, sender, _ = _make_party()
    wire1, sender = gc.encrypt_message(
        plaintext=b"hello", chain=sender, private_key=priv,
    )
    wire2, sender = gc.encrypt_message(
        plaintext=b"world", chain=sender, private_key=priv,
    )
    assert wire1["v"] == "OL-GROUP-MSG-3"
    assert wire2["v"] == "OL-GROUP-MSG-3"
    assert "nonce_salt_b64" in wire1
    salt1 = _b64d(wire1["nonce_salt_b64"])
    salt2 = _b64d(wire2["nonce_salt_b64"])
    assert len(salt1) == gc.NONCE_SALT_BYTES == 12
    # v3 uses the full 96-bit ChaCha20 nonce for fresh entropy rather than
    # v2's 32-bit suffix, making stale-state crash replay collision-safe.
    assert salt1 != salt2


def test_v3_round_trip():
    priv, sender, receiver = _make_party()
    plaintext = b"some group chat body bytes"
    wire, sender_after = gc.encrypt_message(
        plaintext=plaintext, chain=sender, private_key=priv,
    )
    out, _ = gc.decrypt_message(wire=wire, chain=receiver)
    assert out == plaintext
    # Sender chain advanced.
    assert sender_after.counter == 1
    assert sender_after.chain_key != sender.chain_key


def test_v3_salt_tamper_rejected():
    priv, sender, receiver = _make_party()
    wire, _ = gc.encrypt_message(
        plaintext=b"x", chain=sender, private_key=priv,
    )
    # Flip one bit in the nonce_salt — AAD mismatch should fail the
    # signature first (since we sign the salt) and AEAD second.
    salt = bytearray(_b64d(wire["nonce_salt_b64"]))
    salt[0] ^= 0xff
    wire["nonce_salt_b64"] = base64.urlsafe_b64encode(
        bytes(salt)
    ).rstrip(b"=").decode("ascii")
    import pytest
    with pytest.raises(ValueError):
        gc.decrypt_message(wire=wire, chain=receiver)


def test_v3_ciphertext_tamper_rejected():
    priv, sender, receiver = _make_party()
    wire, _ = gc.encrypt_message(
        plaintext=b"y", chain=sender, private_key=priv,
    )
    ct = bytearray(_b64d(wire["ciphertext_b64"]))
    ct[0] ^= 0xff
    wire["ciphertext_b64"] = base64.urlsafe_b64encode(
        bytes(ct)
    ).rstrip(b"=").decode("ascii")
    import pytest
    with pytest.raises(ValueError):
        gc.decrypt_message(wire=wire, chain=receiver)


def test_legacy_v1_frame_still_accepts_on_receive():
    """A daemon that hasn't upgraded yet emits v1 frames; receivers
    must still accept them, decrypt under deterministic-nonce rules,
    and advance the chain. This is the rolling-upgrade safety net."""
    import struct
    priv, sender, receiver = _make_party()
    # Synthesize a v1 frame by hand using the legacy AAD/nonce shape.
    msg_key = gc.derive_message_key(sender.chain_key)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    plaintext = b"legacy traveler"
    nonce = struct.pack(">II", sender.epoch, sender.counter) + b"\x00\x00\x00\x00"
    aad = (
        b"OL-GROUP-MSG-1"
        + sender.group_id
        + sender.sender_pubkey
        + struct.pack(">II", sender.epoch, sender.counter)
    )
    ct = ChaCha20Poly1305(msg_key).encrypt(nonce, plaintext, aad)
    sig_input = (
        sender.group_id
        + sender.sender_pubkey
        + struct.pack(">II", sender.epoch, sender.counter)
        + ct
    )
    sig = priv.sign(sig_input)
    wire = {
        "v": "OL-GROUP-MSG-1",
        "group_id_b64": base64.urlsafe_b64encode(sender.group_id).rstrip(b"=").decode(),
        "sender_pubkey_b64": base64.urlsafe_b64encode(sender.sender_pubkey).rstrip(b"=").decode(),
        "epoch": sender.epoch,
        "counter": sender.counter,
        "ciphertext_b64": base64.urlsafe_b64encode(ct).rstrip(b"=").decode(),
        "signature_b64": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
    }
    out, advanced = gc.decrypt_message(wire=wire, chain=receiver)
    assert out == plaintext
    assert advanced.counter == 1


def test_v3_missing_salt_rejected():
    priv, sender, receiver = _make_party()
    wire, _ = gc.encrypt_message(
        plaintext=b"z", chain=sender, private_key=priv,
    )
    # Drop the salt field — a v3 frame without it is malformed.
    wire.pop("nonce_salt_b64")
    import pytest
    with pytest.raises(ValueError):
        gc.decrypt_message(wire=wire, chain=receiver)


def test_unsupported_version_rejected():
    priv, sender, receiver = _make_party()
    wire, _ = gc.encrypt_message(
        plaintext=b"q", chain=sender, private_key=priv,
    )
    wire["v"] = "OL-GROUP-MSG-99"  # not a supported version
    import pytest
    with pytest.raises(ValueError, match="unsupported version"):
        gc.decrypt_message(wire=wire, chain=receiver)


def test_v1_to_v3_mixed_chain_works():
    """A receiver state can serve both an old v1 frame at counter=0
    AND a v3 frame at counter=1 from the same sender across an
    upgrade. The chain advances normally across the mix."""
    import struct
    priv, sender, receiver = _make_party()
    # Counter 0: v1 frame.
    msg_key = gc.derive_message_key(sender.chain_key)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    nonce = struct.pack(">II", 1, 0) + b"\x00\x00\x00\x00"
    aad = (
        b"OL-GROUP-MSG-1"
        + sender.group_id
        + sender.sender_pubkey
        + struct.pack(">II", 1, 0)
    )
    ct = ChaCha20Poly1305(msg_key).encrypt(nonce, b"first", aad)
    sig = priv.sign(
        sender.group_id + sender.sender_pubkey
        + struct.pack(">II", 1, 0) + ct
    )
    wire_v1 = {
        "v": "OL-GROUP-MSG-1",
        "group_id_b64": base64.urlsafe_b64encode(sender.group_id).rstrip(b"=").decode(),
        "sender_pubkey_b64": base64.urlsafe_b64encode(sender.sender_pubkey).rstrip(b"=").decode(),
        "epoch": 1,
        "counter": 0,
        "ciphertext_b64": base64.urlsafe_b64encode(ct).rstrip(b"=").decode(),
        "signature_b64": base64.urlsafe_b64encode(sig).rstrip(b"=").decode(),
    }
    out, receiver = gc.decrypt_message(wire=wire_v1, chain=receiver)
    assert out == b"first"
    # Counter 1: v3 frame from the upgraded sender. (Use the SenderChain
    # API: it has already advanced past 0 because the v1 emit was
    # synthesized; bump sender to match.)
    sender = gc.SenderChain(
        group_id=sender.group_id,
        sender_pubkey=sender.sender_pubkey,
        epoch=1,
        chain_key=gc.advance_chain_key(sender.chain_key),
        counter=1,
    )
    wire_v3, _ = gc.encrypt_message(
        plaintext=b"second", chain=sender, private_key=priv,
    )
    assert wire_v3["v"] == "OL-GROUP-MSG-3"
    out, receiver = gc.decrypt_message(wire=wire_v3, chain=receiver)
    assert out == b"second"
    assert receiver.counter == 2
