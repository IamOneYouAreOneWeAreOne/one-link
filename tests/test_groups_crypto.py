"""Comprehensive tests for v0.6.1 sender-keys group encryption.

Sections:
  1. Chain primitives — derive, advance, deterministic, well-typed
  2. AEAD round-trip — encrypt then decrypt yields plaintext
  3. Forward secrecy bound — old chain key cannot decrypt new messages
  4. Sender authentication — Ed25519 signature catches forgery by a
     malicious group member who has the chain key
  5. Tampering rejection — ciphertext, AAD, fields all bound by the tag
  6. Replay defence — same (counter) twice rejected
  7. Order constraints — strict in-order in v0.6.1
  8. Epoch rotation — fresh epoch invalidates old chain keys
  9. Wire format — version mismatch, wrong group, wrong sender,
     malformed fields
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.groups_crypto import (
    CHAIN_KEY_BYTES,
    MAX_MESSAGE_PLAINTEXT_BYTES,
    PROTOCOL_VERSION,
    ReceivingChain,
    SenderChain,
    advance_chain_key,
    begin_new_epoch,
    decrypt_message,
    derive_message_key,
    encrypt_message,
    new_chain_key,
    receive_new_epoch,
)


# ─── helpers ────────────────────────────────────────────────────────

def _new_keypair() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


def _new_group_id() -> bytes:
    import os
    return os.urandom(16)


def _make_sender(
    sk: Ed25519PrivateKey, pk: bytes, group_id: bytes, *, epoch: int = 1
) -> SenderChain:
    return SenderChain(
        group_id=group_id,
        sender_pubkey=pk,
        epoch=epoch,
        chain_key=new_chain_key(),
    )


def _make_receiver_for(sender: SenderChain) -> ReceivingChain:
    return ReceivingChain(
        group_id=sender.group_id,
        sender_pubkey=sender.sender_pubkey,
        epoch=sender.epoch,
        chain_key=sender.chain_key,
    )


# ─── 1. Chain primitives ────────────────────────────────────────────

def test_new_chain_key_correct_length():
    assert len(new_chain_key()) == CHAIN_KEY_BYTES


def test_new_chain_key_is_unique_per_call():
    """RNG entropy: 1000 fresh keys, all distinct."""
    keys = {new_chain_key() for _ in range(1000)}
    assert len(keys) == 1000


def test_derive_message_key_is_deterministic():
    k = new_chain_key()
    assert derive_message_key(k) == derive_message_key(k)


def test_advance_chain_key_is_deterministic():
    k = new_chain_key()
    assert advance_chain_key(k) == advance_chain_key(k)


def test_advance_changes_the_key():
    """The whole point of advance: subsequent key differs from the
    previous one. Probability of accidental collision is 2^-256."""
    k = new_chain_key()
    assert advance_chain_key(k) != k


def test_message_key_differs_from_next_chain_key():
    """msg_key and next_key are derived with different `info` strings.
    Mixing them up would be a critical-class bug."""
    k = new_chain_key()
    assert derive_message_key(k) != advance_chain_key(k)


def test_derive_message_key_rejects_wrong_length():
    with pytest.raises(ValueError, match="chain_key"):
        derive_message_key(b"\x00" * 16)
    with pytest.raises(ValueError, match="chain_key"):
        derive_message_key(b"\x00" * 64)


def test_advance_chain_key_rejects_wrong_length():
    with pytest.raises(ValueError, match="chain_key"):
        advance_chain_key(b"\x00" * 16)


# ─── 2. AEAD round-trip ─────────────────────────────────────────────

def test_encrypt_then_decrypt_round_trip():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    plaintext = b"hello group"
    wire, sender_after = encrypt_message(
        plaintext=plaintext, chain=sender, private_key=sk,
    )
    decoded, receiver_after = decrypt_message(wire=wire, chain=receiver)
    assert decoded == plaintext
    # Both sides advanced one step.
    assert sender_after.counter == 1
    assert receiver_after.counter == 1
    assert sender_after.chain_key != sender.chain_key
    assert receiver_after.chain_key != receiver.chain_key


def test_round_trip_for_long_message():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    plaintext = b"X" * 100_000
    wire, _ = encrypt_message(
        plaintext=plaintext, chain=sender, private_key=sk,
    )
    decoded, _ = decrypt_message(wire=wire, chain=receiver)
    assert decoded == plaintext


def test_round_trip_for_unicode_message():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    plaintext = "hello 世界 🌍".encode("utf-8")
    wire, _ = encrypt_message(
        plaintext=plaintext, chain=sender, private_key=sk,
    )
    decoded, _ = decrypt_message(wire=wire, chain=receiver)
    assert decoded == plaintext


def test_encrypt_rejects_empty_plaintext():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    with pytest.raises(ValueError, match="empty plaintext"):
        encrypt_message(plaintext=b"", chain=sender, private_key=sk)


def test_encrypt_rejects_oversized_plaintext():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    with pytest.raises(ValueError, match="too large"):
        encrypt_message(
            plaintext=b"\x00" * (MAX_MESSAGE_PLAINTEXT_BYTES + 1),
            chain=sender, private_key=sk,
        )


def test_round_trip_many_messages_in_sequence():
    """100 sequential messages. Both sides walk the chain in lockstep."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    for i in range(100):
        wire, sender = encrypt_message(
            plaintext=f"msg {i}".encode(), chain=sender, private_key=sk,
        )
        decoded, receiver = decrypt_message(wire=wire, chain=receiver)
        assert decoded == f"msg {i}".encode()
    assert sender.counter == 100
    assert receiver.counter == 100


# ─── 3. Forward secrecy bound ───────────────────────────────────────

def test_forward_secrecy_after_epoch_rotation():
    """v0.20.7: forward secrecy is delivered by epoch rotation, not
    by the within-epoch chain advancement (chain advancement is
    one-way HMAC; any holder of chain_key[N] can derive chain_key[N+k]
    for arbitrary k, which is the GROUP-MEMBER property of a sender
    chain — every member already has the chain key). The sharper
    cryptographic guarantee is that ``begin_new_epoch`` mints a
    fresh chain_key from os.urandom; an attacker who held the
    PRIOR-EPOCH chain_key cannot decrypt next-epoch messages without
    membership in the next-epoch chain distribution."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender_e1 = _make_sender(sk, pk, gid, epoch=1)
    captured_e1_chain_key = sender_e1.chain_key

    # Membership rotation: epoch advances, chain_key is fresh.
    sender_e2 = begin_new_epoch(group_id=gid, sender_pubkey=pk, new_epoch=2)
    assert sender_e2.chain_key != captured_e1_chain_key

    # Send a message at the new epoch.
    wire, _ = encrypt_message(
        plaintext=b"after rotation", chain=sender_e2, private_key=sk,
    )
    # Attacker holding the prior-epoch chain_key tries to decrypt by
    # constructing a receiver pinned at the new epoch with the OLD
    # chain_key — fails on AEAD tag (chain_keys differ) or on epoch
    # mismatch if attacker pins the wrong epoch.
    attacker_with_old_key = ReceivingChain(
        group_id=gid, sender_pubkey=pk,
        epoch=sender_e2.epoch,
        chain_key=captured_e1_chain_key,
        counter=0,
    )
    with pytest.raises(ValueError):
        decrypt_message(wire=wire, chain=attacker_with_old_key)


def test_chain_advance_within_epoch_is_member_property_not_secrecy():
    """Documents that within an epoch, chain advancement is one-way
    HMAC and ANY chain_key holder can derive future chain_keys. The
    "forward secrecy" claim properly applies at epoch boundaries
    via begin_new_epoch (see test above) — within an epoch the chain
    is shared among current members by design."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    captured = sender.chain_key
    # Advance 5 manually; the captured key plus advance_chain_key is
    # enough to reach any future state. This is intentional.
    cur = captured
    for _ in range(5):
        cur = advance_chain_key(cur)
    # And the legitimate sender's chain matches after 5 sends.
    for _ in range(5):
        _, sender = encrypt_message(
            plaintext=b"x", chain=sender, private_key=sk,
        )
    assert sender.chain_key == cur


def test_advancing_chain_destroys_previous_key():
    """Strict cryptographic check: the chain advance is one-way.
    Given chain_key[N], you cannot derive chain_key[N-1]. We can
    test this empirically by checking the advance is just
    HMAC-SHA256, which is preimage-resistant by definition. So the
    test is: chain[N] does not equal chain[N-1] and there's no
    'reverse' helper exposed."""
    k0 = new_chain_key()
    k1 = advance_chain_key(k0)
    # The module exposes no inverse. Documenting the API surface:
    import one_link.groups_crypto as gc
    assert not hasattr(gc, "rewind_chain_key")
    assert k0 != k1


# ─── 4. Sender authentication ───────────────────────────────────────

def test_signature_catches_forgery_from_chain_holder():
    """Eve is a member of the group, so she has Alice's chain key
    (Alice distributed it on add). Eve tries to forge a message
    *as Alice*: she encrypts under Alice's chain key, AAD-binds
    Alice's pubkey... but she can't produce a valid Ed25519
    signature without Alice's signing key. Decryption verifies the
    signature first and rejects."""
    sk_alice, pk_alice = _new_keypair()
    sk_eve, _ = _new_keypair()
    gid = _new_group_id()

    # Alice's chain — Eve has the chain key (group member).
    alice_chain = _make_sender(sk_alice, pk_alice, gid)
    receiver = _make_receiver_for(alice_chain)

    # Eve forges a message claiming to be Alice. She has
    # alice_chain.chain_key. She uses Eve's signing key to sign.
    wire, _ = encrypt_message(
        plaintext=b"forged",
        chain=alice_chain,
        private_key=sk_eve,  # ← wrong signer
    )
    with pytest.raises(ValueError, match="signature"):
        decrypt_message(wire=wire, chain=receiver)


def test_signature_tampering_rejects():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(
        plaintext=b"hi", chain=sender, private_key=sk,
    )
    # Flip a bit in the signature.
    bad_sig = bytearray(base64.urlsafe_b64decode(
        wire["signature_b64"] + "=" * (4 - len(wire["signature_b64"]) % 4)
    ))
    bad_sig[0] ^= 0x80
    wire["signature_b64"] = base64.urlsafe_b64encode(bytes(bad_sig)).rstrip(b"=").decode()
    with pytest.raises(ValueError, match="signature"):
        decrypt_message(wire=wire, chain=receiver)


# ─── 5. Tampering rejection ─────────────────────────────────────────

def test_ciphertext_tampering_rejects():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(
        plaintext=b"original", chain=sender, private_key=sk,
    )
    # Decode the b64, flip a bit, re-encode.
    raw = bytearray(base64.urlsafe_b64decode(
        wire["ciphertext_b64"] + "=" * (4 - len(wire["ciphertext_b64"]) % 4)
    ))
    raw[3] ^= 0x40
    wire["ciphertext_b64"] = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()
    # Signature catches this OR AEAD does — either way decrypt fails.
    with pytest.raises(ValueError):
        decrypt_message(wire=wire, chain=receiver)


def test_aad_tampering_via_counter_rejects():
    """Counter is part of AAD. Lying about it on the wire
    invalidates the AEAD tag (and the signature)."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(
        plaintext=b"x", chain=sender, private_key=sk,
    )
    wire["counter"] = wire["counter"] + 1  # claim it was msg 1, not 0
    with pytest.raises(ValueError):
        decrypt_message(wire=wire, chain=receiver)


def test_aad_tampering_via_epoch_rejects():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid, epoch=1)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(
        plaintext=b"x", chain=sender, private_key=sk,
    )
    wire["epoch"] = 99
    with pytest.raises(ValueError):
        decrypt_message(wire=wire, chain=receiver)


# ─── 6. Replay defence ──────────────────────────────────────────────

def test_same_message_replayed_rejects():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(
        plaintext=b"once", chain=sender, private_key=sk,
    )
    pt, receiver = decrypt_message(wire=wire, chain=receiver)
    assert pt == b"once"
    # Replay the same wire dict — must reject.
    with pytest.raises(ValueError):
        decrypt_message(wire=wire, chain=receiver)


# ─── 7. Order constraints ───────────────────────────────────────────

def test_out_of_order_within_window_now_accepted():
    """v0.20.7 (audit M4): out-of-order delivery within the sliding
    window is now ACCEPTED. A message with counter=2 arriving before
    counter=1 decrypts cleanly; later, when counter=1 arrives, it
    decrypts via the stashed key cache."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)

    # Sender emits counter=0, 1, 2.
    wire0, sender = encrypt_message(plaintext=b"zero", chain=sender, private_key=sk)
    wire1, sender = encrypt_message(plaintext=b"one", chain=sender, private_key=sk)
    wire2, sender = encrypt_message(plaintext=b"two", chain=sender, private_key=sk)

    # Receiver consumes them out of order: 0, 2, 1.
    pt, receiver = decrypt_message(wire=wire0, chain=receiver)
    assert pt == b"zero"
    pt, receiver = decrypt_message(wire=wire2, chain=receiver)
    assert pt == b"two"
    pt, receiver = decrypt_message(wire=wire1, chain=receiver)
    assert pt == b"one"


def test_out_of_window_ooo_is_rejected():
    """A frame whose counter is below chain.counter AND not in the
    skipped cache is rejected with 'out-of-window'."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)

    # Sender emits 0, 1, 2. Receiver consumes 0, 1, 2 in order.
    wires = []
    for body in (b"a", b"b", b"c"):
        w, sender = encrypt_message(plaintext=body, chain=sender, private_key=sk)
        wires.append(w)
    for w in wires:
        _, receiver = decrypt_message(wire=w, chain=receiver)

    # Now a frame appears claiming counter=0 (replay-of-old). The
    # receiver has already consumed it; seen_counters catches it.
    with pytest.raises(ValueError, match="replay"):
        decrypt_message(wire=wires[0], chain=receiver)


def test_forward_jump_beyond_window_is_rejected():
    """A counter that's farther ahead than MAX_SKIP_KEYS_GROUP is
    refused — the receiver won't derive an unbounded number of
    intermediate keys for an attacker-claimed jump."""
    from one_link.groups_crypto import MAX_SKIP_KEYS_GROUP
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)

    # Walk the SENDER forward past the window so we have a legitimately
    # signed wire frame for a far-future counter.
    for _ in range(MAX_SKIP_KEYS_GROUP + 5):
        _, sender = encrypt_message(plaintext=b"x", chain=sender, private_key=sk)
    far_wire, _ = encrypt_message(
        plaintext=b"far away", chain=sender, private_key=sk,
    )
    with pytest.raises(ValueError, match="too many skipped messages"):
        decrypt_message(wire=far_wire, chain=receiver)


# ─── 8. Epoch rotation ──────────────────────────────────────────────

def test_begin_new_epoch_yields_fresh_chain():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    chain1 = _make_sender(sk, pk, gid, epoch=1)
    # Send a couple of messages.
    _, chain1 = encrypt_message(plaintext=b"a", chain=chain1, private_key=sk)
    _, chain1 = encrypt_message(plaintext=b"b", chain=chain1, private_key=sk)

    chain2 = begin_new_epoch(group_id=gid, sender_pubkey=pk, new_epoch=2)
    assert chain2.epoch == 2
    assert chain2.counter == 0
    assert chain2.chain_key != chain1.chain_key  # genuinely fresh


def test_old_epoch_chain_cannot_decrypt_new_epoch_messages():
    """The whole point of rotation: a removed member who has the old
    epoch's chain_key cannot read new-epoch messages."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    old_sender = _make_sender(sk, pk, gid, epoch=1)
    old_receiver = _make_receiver_for(old_sender)

    # Send a message at epoch 1.
    wire1, old_sender = encrypt_message(
        plaintext=b"epoch1", chain=old_sender, private_key=sk,
    )
    # Confirm the old receiver can read it.
    pt, _ = decrypt_message(wire=wire1, chain=old_receiver)
    assert pt == b"epoch1"

    # Rotate to epoch 2 (post-membership-change).
    new_sender = begin_new_epoch(group_id=gid, sender_pubkey=pk, new_epoch=2)
    wire2, _ = encrypt_message(
        plaintext=b"epoch2", chain=new_sender, private_key=sk,
    )

    # Removed member only has the OLD epoch=1 chain. Reject.
    stale_attacker = ReceivingChain(
        group_id=gid, sender_pubkey=pk, epoch=1,
        chain_key=old_sender.chain_key, counter=old_sender.counter,
    )
    with pytest.raises(ValueError, match="epoch"):
        decrypt_message(wire=wire2, chain=stale_attacker)


def test_receive_new_epoch_constructs_proper_chain():
    pk = b"\xaa" * 32
    gid = _new_group_id()
    chain_key = b"\x11" * CHAIN_KEY_BYTES
    rcv = receive_new_epoch(
        group_id=gid, sender_pubkey=pk, epoch=3, chain_key=chain_key,
    )
    assert rcv.group_id == gid
    assert rcv.sender_pubkey == pk
    assert rcv.epoch == 3
    assert rcv.chain_key == chain_key
    assert rcv.counter == 0


def test_receive_new_epoch_rejects_wrong_chain_key_length():
    pk = b"\xaa" * 32
    gid = _new_group_id()
    with pytest.raises(ValueError, match="chain_key"):
        receive_new_epoch(group_id=gid, sender_pubkey=pk, epoch=1, chain_key=b"\x00" * 16)


def test_begin_new_epoch_rejects_zero_or_negative():
    pk = b"\xaa" * 32
    gid = _new_group_id()
    with pytest.raises(ValueError, match="epoch"):
        begin_new_epoch(group_id=gid, sender_pubkey=pk, new_epoch=0)
    with pytest.raises(ValueError, match="epoch"):
        begin_new_epoch(group_id=gid, sender_pubkey=pk, new_epoch=-1)


# ─── 9. Wire format ─────────────────────────────────────────────────

def test_decrypt_rejects_wrong_protocol_version():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(plaintext=b"x", chain=sender, private_key=sk)
    wire["v"] = "OL-GROUP-MSG-99"
    with pytest.raises(ValueError, match="version"):
        decrypt_message(wire=wire, chain=receiver)


def test_decrypt_rejects_wrong_group_id():
    sk, pk = _new_keypair()
    gid_a = _new_group_id()
    gid_b = _new_group_id()
    sender = _make_sender(sk, pk, gid_a)
    receiver_for_b = ReceivingChain(
        group_id=gid_b,
        sender_pubkey=pk,
        epoch=sender.epoch,
        chain_key=sender.chain_key,
    )
    wire, _ = encrypt_message(plaintext=b"x", chain=sender, private_key=sk)
    with pytest.raises(ValueError, match="group_id"):
        decrypt_message(wire=wire, chain=receiver_for_b)


def test_decrypt_rejects_wrong_sender_pubkey():
    sk, pk = _new_keypair()
    _, other_pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    # Receiver is configured for a DIFFERENT sender.
    receiver_for_other = ReceivingChain(
        group_id=gid,
        sender_pubkey=other_pk,
        epoch=sender.epoch,
        chain_key=sender.chain_key,
    )
    wire, _ = encrypt_message(plaintext=b"x", chain=sender, private_key=sk)
    with pytest.raises(ValueError, match="sender"):
        decrypt_message(wire=wire, chain=receiver_for_other)


def test_decrypt_rejects_non_dict_wire():
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    with pytest.raises(ValueError, match="dict"):
        decrypt_message(wire="not a dict", chain=receiver)  # type: ignore


def test_wire_round_trips_through_json():
    """Sanity: the wire format is JSON-serializable (no bytes
    objects in the dict)."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    receiver = _make_receiver_for(sender)
    wire, _ = encrypt_message(plaintext=b"json me", chain=sender, private_key=sk)
    encoded = json.dumps(wire)
    decoded = json.loads(encoded)
    pt, _ = decrypt_message(wire=decoded, chain=receiver)
    assert pt == b"json me"


# ─── multi-recipient simulation ─────────────────────────────────────

def test_three_recipients_all_decrypt_in_lockstep():
    """One sender, three recipients all holding the same chain.
    Each independently advances and reads. This is the multi-member
    group case."""
    sk, pk = _new_keypair()
    gid = _new_group_id()
    sender = _make_sender(sk, pk, gid)
    rcv1 = _make_receiver_for(sender)
    rcv2 = _make_receiver_for(sender)
    rcv3 = _make_receiver_for(sender)

    for i in range(10):
        wire, sender = encrypt_message(
            plaintext=f"#{i}".encode(), chain=sender, private_key=sk,
        )
        pt1, rcv1 = decrypt_message(wire=wire, chain=rcv1)
        pt2, rcv2 = decrypt_message(wire=wire, chain=rcv2)
        pt3, rcv3 = decrypt_message(wire=wire, chain=rcv3)
        assert pt1 == pt2 == pt3 == f"#{i}".encode()
    # All three converged to the same chain state.
    assert rcv1.chain_key == rcv2.chain_key == rcv3.chain_key
    assert rcv1.counter == rcv2.counter == rcv3.counter == 10
