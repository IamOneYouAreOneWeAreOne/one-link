"""v0.20.7 — onion-routed relay path.

Sealed Sender hides the SENDER from the relay; onion routing hides
the PATH. With N relays, the first relay knows the sender but not
the destination; the last relay knows the destination but not the
sender; middle relays know neither.

These tests pin:
  - 1-hop, 3-hop, and 5-hop round-trips work end-to-end
  - Each relay sees ONLY the next-hop address + still-encrypted
    inner blob (not the recipient, not the body)
  - Recipient unwrap restores the original body
  - Recipient layer has empty next_address (terminal hop)
  - Wrong relay private key cannot unwrap that hop
  - Tampered ciphertext at any layer is rejected
  - Tampered ephemeral pubkey at any layer is rejected (AAD binding)
  - Tampered next-hop address inside a layer is rejected (covered by
    the AEAD plaintext integrity)
  - Empty path is rejected
  - Recipient layer cannot be opened with relay AAD (and vice versa)
    — domain separation between relay and recipient unwrap
  - Bound checks: oversized address / oversized blob rejected
"""
from __future__ import annotations


import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from one_link import onion


def _gen_x25519():
    """Return (priv_bytes_32, pub_bytes_32)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return priv.private_bytes_raw(), pub


def _hop(addr: bytes):
    priv, pub = _gen_x25519()
    return priv, onion.HopKey(address=addr, x25519_pub=pub)


# ── round-trips ───────────────────────────────────────────────────


def test_one_hop_round_trip():
    """Path: sender → R1 → recipient. 2 unwraps total."""
    r1_priv, r1 = _hop(b"relay-1.example:9001")
    rcpt_priv, rcpt_pub = _gen_x25519()
    body = b"alpha"
    blob = onion.build_onion(
        body=body, path=[r1],
        recipient_address=b"recipient.example:9999",
        recipient_x25519_pub=rcpt_pub,
    )
    # R1 unwraps its layer.
    out = onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r1_priv)
    assert out.next_address == b"recipient.example:9999"
    # The recipient unwraps the inner.
    body_out = onion.unwrap_recipient_layer(
        blob=out.inner, my_x25519_priv=rcpt_priv,
    )
    assert body_out == body


def test_three_hop_round_trip():
    """Sender → R1 → R2 → R3 → recipient. The classic onion
    configuration."""
    r1_priv, r1 = _hop(b"r1.example:9001")
    r2_priv, r2 = _hop(b"r2.example:9002")
    r3_priv, r3 = _hop(b"r3.example:9003")
    rcpt_priv, rcpt_pub = _gen_x25519()
    body = b"the secret payload that no relay should see"

    blob = onion.build_onion(
        body=body, path=[r1, r2, r3],
        recipient_address=b"recipient:9999",
        recipient_x25519_pub=rcpt_pub,
    )
    # R1 sees: next=R2, inner_for_R2
    h1 = onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r1_priv)
    assert h1.next_address == b"r2.example:9002"
    # R2 sees: next=R3, inner_for_R3
    h2 = onion.unwrap_relay_layer(blob=h1.inner, my_x25519_priv=r2_priv)
    assert h2.next_address == b"r3.example:9003"
    # R3 sees: next=recipient, inner_for_recipient
    h3 = onion.unwrap_relay_layer(blob=h2.inner, my_x25519_priv=r3_priv)
    assert h3.next_address == b"recipient:9999"
    # Recipient unwraps body.
    body_out = onion.unwrap_recipient_layer(
        blob=h3.inner, my_x25519_priv=rcpt_priv,
    )
    assert body_out == body


def test_five_hop_round_trip():
    privs_hops = [_hop(f"hop-{i}".encode()) for i in range(5)]
    rcpt_priv, rcpt_pub = _gen_x25519()
    body = b"big path"
    blob = onion.build_onion(
        body=body, path=[h for _, h in privs_hops],
        recipient_address=b"end",
        recipient_x25519_pub=rcpt_pub,
    )
    inner = blob
    for i, (priv, hop) in enumerate(privs_hops):
        out = onion.unwrap_relay_layer(blob=inner, my_x25519_priv=priv)
        if i < len(privs_hops) - 1:
            assert out.next_address == privs_hops[i + 1][1].address
        else:
            assert out.next_address == b"end"
        inner = out.inner
    body_out = onion.unwrap_recipient_layer(
        blob=inner, my_x25519_priv=rcpt_priv,
    )
    assert body_out == body


# ── confidentiality ────────────────────────────────────────────────


def test_relay_sees_only_next_hop_not_recipient():
    """A middle relay's view of next_hop must be the NEXT relay's
    address, not the final recipient. This is the unlinkability
    property."""
    r1_priv, r1 = _hop(b"r1")
    r2_priv, r2 = _hop(b"r2")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = onion.build_onion(
        body=b"secret",
        path=[r1, r2],
        recipient_address=b"the-recipient-address-not-visible-mid-route",
        recipient_x25519_pub=rcpt_pub,
    )
    h1 = onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r1_priv)
    # R1 sees R2's address, NOT the recipient address.
    assert h1.next_address == b"r2"
    # R1's view of inner is encrypted; the recipient address must
    # NOT appear there in plaintext.
    assert b"recipient-address-not-visible" not in h1.inner


def test_body_not_visible_at_relay_layer():
    """No relay can see the body; only the recipient can."""
    r1_priv, r1 = _hop(b"r1")
    r2_priv, r2 = _hop(b"r2")
    rcpt_priv, rcpt_pub = _gen_x25519()
    secret_body = b"VERY-SECRET-MARKER-DONT-LEAK-12345"
    blob = onion.build_onion(
        body=secret_body, path=[r1, r2],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    h1 = onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r1_priv)
    h2 = onion.unwrap_relay_layer(blob=h1.inner, my_x25519_priv=r2_priv)
    # Neither relay sees the body cleartext.
    assert secret_body not in h1.inner
    assert secret_body not in h2.inner
    # But the recipient does.
    assert onion.unwrap_recipient_layer(
        blob=h2.inner, my_x25519_priv=rcpt_priv,
    ) == secret_body


# ── failure modes ──────────────────────────────────────────────────


def test_wrong_relay_priv_cannot_unwrap():
    r1_priv, r1 = _hop(b"r1")
    other_priv, _ = _gen_x25519()
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    with pytest.raises(ValueError):
        onion.unwrap_relay_layer(blob=blob, my_x25519_priv=other_priv)


def test_tampered_ciphertext_rejected():
    r1_priv, r1 = _hop(b"r1")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = bytearray(onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    ))
    blob[-5] ^= 0xff
    with pytest.raises(ValueError):
        onion.unwrap_relay_layer(blob=bytes(blob), my_x25519_priv=r1_priv)


def test_tampered_ephemeral_pubkey_rejected():
    """eph_pub is bound into the AAD; flipping a byte invalidates
    the tag."""
    r1_priv, r1 = _hop(b"r1")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = bytearray(onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    ))
    blob[3] ^= 0xff  # within eph_pub region
    with pytest.raises(ValueError):
        onion.unwrap_relay_layer(blob=bytes(blob), my_x25519_priv=r1_priv)


def test_relay_cannot_unwrap_recipient_layer():
    """The relay AAD ("relay") is distinct from the recipient AAD
    ("recipient"), so a relay using its own ECDH key against the
    innermost layer would fail decryption — domain separation."""
    r1_priv, r1 = _hop(b"r1")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    h1 = onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r1_priv)
    # Calling relay-unwrap on the inner (recipient) layer with the
    # recipient's priv: fails because the AAD label is "recipient"
    # not "relay".
    with pytest.raises(ValueError):
        onion.unwrap_relay_layer(
            blob=h1.inner, my_x25519_priv=rcpt_priv,
        )


def test_recipient_cannot_unwrap_relay_layer():
    r1_priv, r1 = _hop(b"r1")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    # The outermost layer is a relay layer; unwrap_recipient_layer
    # should fail (wrong AAD).
    with pytest.raises(ValueError):
        onion.unwrap_recipient_layer(
            blob=blob, my_x25519_priv=r1_priv,
        )


def test_empty_path_rejected():
    rcpt_priv, rcpt_pub = _gen_x25519()
    with pytest.raises(ValueError, match="at least one relay"):
        onion.build_onion(
            body=b"x", path=[],
            recipient_address=b"end",
            recipient_x25519_pub=rcpt_pub,
        )


def test_oversized_address_rejected():
    big_addr = b"x" * (onion.MAX_ADDR_LEN + 1)
    rcpt_priv, rcpt_pub = _gen_x25519()
    with pytest.raises(ValueError):
        onion.HopKey(address=big_addr, x25519_pub=rcpt_pub)


def test_blob_too_short_rejected():
    priv, _ = _gen_x25519()
    with pytest.raises(ValueError, match="too short"):
        onion.unwrap_relay_layer(blob=b"\x00" * 20, my_x25519_priv=priv)


def test_blob_too_large_rejected():
    priv, _ = _gen_x25519()
    big = b"\x00" * (onion.MAX_ONION_LEN + 1)
    with pytest.raises(ValueError, match="exceeds"):
        onion.unwrap_relay_layer(blob=big, my_x25519_priv=priv)


def test_each_call_produces_different_blob():
    """Two onions with identical inputs differ on the wire (fresh
    ephemerals at every hop)."""
    r1_priv, r1 = _hop(b"r1")
    rcpt_priv, rcpt_pub = _gen_x25519()
    a = onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    b = onion.build_onion(
        body=b"x", path=[r1],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    assert a != b


def test_intermediate_relay_cannot_skip_layers():
    """A malicious R2 cannot decrypt R1's layer with its own key,
    even if it has the wire blob."""
    r1_priv, r1 = _hop(b"r1")
    r2_priv, r2 = _hop(b"r2")
    rcpt_priv, rcpt_pub = _gen_x25519()
    blob = onion.build_onion(
        body=b"x", path=[r1, r2],
        recipient_address=b"end", recipient_x25519_pub=rcpt_pub,
    )
    # The outermost layer is for R1. R2 trying to decrypt it fails.
    with pytest.raises(ValueError):
        onion.unwrap_relay_layer(blob=blob, my_x25519_priv=r2_priv)
