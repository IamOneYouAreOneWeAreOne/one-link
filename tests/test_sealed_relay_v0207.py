"""v0.20.7 (Bundle 52) — sealed-sender + capability grant on the relay path.

Combines Bundle 39 (sealed sender) with Bundle 44 (signed capability
grants). The relay sees an opaque envelope; the recipient unseals,
verifies the (optionally attached) grant, and learns the sender +
the authorized capabilities atomically.

These tests pin:
  - Round-trip with no grant
  - Round-trip with grant + matching capabilities + scope
  - Sender pubkey not on the wire (greppable)
  - Grant nonce binding: a relay that strips the grant or swaps in
    a different one is detected
  - Grant with wrong subject (not the sealed sender) rejected
  - Expected_capabilities enforcement
  - Expected_scope enforcement
  - Replay defense via seen_grant_nonces
  - Wrong-recipient rejected (sealed_sender envelope can't decrypt)
  - Tampered envelope / grant rejected
"""
from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import caps_grants, sealed_relay


def _gen_ed25519():
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    return seed, pub


def _now_ms():
    return int(time.time() * 1000)


# ── basic round-trips ─────────────────────────────────────────────


def test_round_trip_no_grant():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    payload = b"hello via the relay"
    blob = sealed_relay.seal_for_relay(
        payload=payload,
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
    )
    frame = sealed_relay.unseal_from_relay(
        blob=blob, my_ed_priv_seed=recipient_seed,
    )
    assert frame.payload == payload
    assert frame.sender_ed_pub == sender_pub
    assert frame.grant is None


def test_round_trip_with_grant():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    granter_seed, granter_pub = sender_seed, sender_pub  # sender grants to self
    now = _now_ms()
    grant = caps_grants.encode_grant(
        granter_priv_seed=granter_seed,
        granter_pub=granter_pub,
        subject_pub=sender_pub,
        capabilities=["files:read"],
        not_before_ms=now, not_after_ms=now + 60_000,
        scope=b"folder-X",
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"want a chunk",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    frame = sealed_relay.unseal_from_relay(
        blob=blob, my_ed_priv_seed=recipient_seed,
        expected_capabilities={"files:read"},
        expected_scope=b"folder-X",
    )
    assert frame.payload == b"want a chunk"
    assert frame.grant is not None
    assert "files:read" in frame.grant.capabilities


def test_sender_pub_not_on_the_wire():
    """Defining property: greppable confirmation that the wire blob
    contains no plaintext sender pubkey."""
    sender_seed, sender_pub = _gen_ed25519()
    _, recipient_pub = _gen_ed25519()
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
    )
    assert sender_pub not in blob


# ── grant binding ─────────────────────────────────────────────────


def test_grant_strip_detected():
    """A relay that strips the grant from the wire (sets grant_len=0)
    while leaving the sealed envelope intact must be detected: the
    envelope's bound nonce isn't NULL_NONCE."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    grant = caps_grants.encode_grant(
        granter_priv_seed=sender_seed,
        granter_pub=sender_pub,
        subject_pub=sender_pub,
        capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    # Strip the grant by manually rewriting the wire format —
    # grant_len = 0, envelope kept intact.
    import struct as _s
    # Layout: [u16 grant_len][grant][u32 env_len][env]. Find env.
    grant_len = _s.unpack(">H", blob[:2])[0]
    env_off = 2 + grant_len
    env_len = _s.unpack(">I", blob[env_off:env_off + 4])[0]
    envelope = blob[env_off + 4:env_off + 4 + env_len]
    stripped = (
        _s.pack(">H", 0) + _s.pack(">I", env_len) + envelope
    )
    with pytest.raises(ValueError, match="stripped"):
        sealed_relay.unseal_from_relay(
            blob=stripped, my_ed_priv_seed=recipient_seed,
        )


def test_grant_swap_detected():
    """A relay that swaps in a DIFFERENT (still-valid) grant must be
    detected: the swapped grant's nonce won't match the bound nonce
    inside the sealed envelope."""
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    grant_a = caps_grants.encode_grant(
        granter_priv_seed=sender_seed, granter_pub=sender_pub,
        subject_pub=sender_pub, capabilities=["a"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    grant_b = caps_grants.encode_grant(
        granter_priv_seed=sender_seed, granter_pub=sender_pub,
        subject_pub=sender_pub, capabilities=["b"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    blob_with_a = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant_a,
    )
    # Swap A for B in the outer grant slot. The inner sealed
    # envelope still binds A's nonce.
    import struct as _s
    grant_a_len = _s.unpack(">H", blob_with_a[:2])[0]
    rest = blob_with_a[2 + grant_a_len:]
    swapped = _s.pack(">H", len(grant_b)) + grant_b + rest
    with pytest.raises(ValueError, match="doesn't match"):
        sealed_relay.unseal_from_relay(
            blob=swapped, my_ed_priv_seed=recipient_seed,
        )


def test_grant_subject_must_match_sealed_sender():
    """Granter signs a grant for SUBJECT X; sender (pretending to
    be X) seals + relays. If the seal sender_pub != grant
    subject_pub, the verifier rejects."""
    sender_seed, sender_pub = _gen_ed25519()
    other_seed, other_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    # Grant says SUBJECT = other_pub, but the sealed sender_pub is
    # sender_pub.
    grant = caps_grants.encode_grant(
        granter_priv_seed=other_seed, granter_pub=other_pub,
        subject_pub=other_pub,  # different from sender_pub
        capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    with pytest.raises(ValueError, match="subject_pub"):
        sealed_relay.unseal_from_relay(
            blob=blob, my_ed_priv_seed=recipient_seed,
        )


# ── capability + scope enforcement ────────────────────────────────


def test_required_capability_enforced():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    grant = caps_grants.encode_grant(
        granter_priv_seed=sender_seed, granter_pub=sender_pub,
        subject_pub=sender_pub, capabilities=["files:read"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    # Request requires files:write — grant only has files:read.
    with pytest.raises(ValueError, match="lacks required"):
        sealed_relay.unseal_from_relay(
            blob=blob, my_ed_priv_seed=recipient_seed,
            expected_capabilities={"files:write"},
        )


def test_required_scope_enforced():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    grant = caps_grants.encode_grant(
        granter_priv_seed=sender_seed, granter_pub=sender_pub,
        subject_pub=sender_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 60_000,
        scope=b"folder-X",
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    with pytest.raises(ValueError, match="scope"):
        sealed_relay.unseal_from_relay(
            blob=blob, my_ed_priv_seed=recipient_seed,
            expected_scope=b"folder-Y",
        )


def test_replay_via_grant_nonce():
    sender_seed, sender_pub = _gen_ed25519()
    recipient_seed, recipient_pub = _gen_ed25519()
    now = _now_ms()
    grant = caps_grants.encode_grant(
        granter_priv_seed=sender_seed, granter_pub=sender_pub,
        subject_pub=sender_pub, capabilities=["x"],
        not_before_ms=now, not_after_ms=now + 60_000,
    )
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
        grant_blob=grant,
    )
    seen: set[bytes] = set()
    sealed_relay.unseal_from_relay(
        blob=blob, my_ed_priv_seed=recipient_seed,
        seen_grant_nonces=seen,
    )
    with pytest.raises(ValueError, match="replayed"):
        sealed_relay.unseal_from_relay(
            blob=blob, my_ed_priv_seed=recipient_seed,
            seen_grant_nonces=seen,
        )


# ── failure modes ────────────────────────────────────────────────


def test_wrong_recipient_cannot_decrypt():
    sender_seed, sender_pub = _gen_ed25519()
    _, recipient_pub = _gen_ed25519()
    other_seed, _ = _gen_ed25519()
    blob = sealed_relay.seal_for_relay(
        payload=b"x",
        sender_ed_priv_seed=sender_seed,
        sender_ed_pub=sender_pub,
        recipient_ed_pub=recipient_pub,
    )
    with pytest.raises(ValueError):
        sealed_relay.unseal_from_relay(
            blob=blob, my_ed_priv_seed=other_seed,
        )


def test_truncated_blob_rejected():
    with pytest.raises(ValueError, match="too short"):
        sealed_relay.unseal_from_relay(
            blob=b"\x00" * 5, my_ed_priv_seed=b"\x00" * 32,
        )
