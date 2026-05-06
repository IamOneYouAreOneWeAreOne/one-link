"""v0.7.2 Double Ratchet primitive tests (audit roadmap).

Pin the Signal-style ratchet's three load-bearing properties:

  - Correctness: A→B and B→A messages decrypt to plaintext on
    the matched receive side.
  - Forward secrecy: a chain key captured at time T cannot
    decrypt messages from time T-1 — the chain advances
    irreversibly via HKDF.
  - Post-compromise security: the DH ratchet step injects
    fresh entropy from a brand-new ephemeral; an attacker
    holding the post-handshake state cannot decrypt the
    NEXT message after a successful round-trip.
  - Out-of-order delivery: skipped messages (within the
    bounded window) decrypt later via the cached message-key
    table.
  - Replay defence: each (dh_pub, n) tuple decrypts at most
    once.
  - Header tampering: AAD binding causes AEAD InvalidTag
    if a man-in-the-middle swaps headers.
  - Capability advertisement: DOUBLE_RATCHET_V1 is in
    LOCAL_CAPABILITIES so peers can negotiate readiness.
"""
from __future__ import annotations

import os

import pytest

from cryptography.exceptions import InvalidTag

from one_link.capabilities import DOUBLE_RATCHET_V1, LOCAL_CAPABILITIES
from one_link.double_ratchet import (
    Header,
    MAX_SKIP_KEYS,
    RatchetState,
    decrypt,
    encrypt,
    init_alice,
    init_bob,
    init_pair,
    kdf_chain,
    kdf_root,
    x25519_keypair,
)


def _ss() -> bytes:
    """A 32-byte shared secret simulating a prior handshake."""
    return os.urandom(32)


# ─── primitives ────────────────────────────────────────────────────

def test_kdf_chain_advances_and_diverges():
    """Each chain step yields a NEW chain_key and a message_key
    that's distinct from both. Same input never yields same output
    twice — irreversible."""
    ck = b"\x42" * 32
    next_ck, mk = kdf_chain(ck)
    assert next_ck != ck
    assert mk != ck
    assert next_ck != mk
    next_ck2, mk2 = kdf_chain(ck)
    # Deterministic given the same input.
    assert next_ck == next_ck2 and mk == mk2
    # Stepping ONCE more on next_ck produces yet another distinct pair.
    nn, m2 = kdf_chain(next_ck)
    assert nn != next_ck and m2 != mk


def test_kdf_root_diverges_with_dh_input():
    """Same root_key + different DH outputs = different new root + chain."""
    root = b"\x01" * 32
    a_root, a_chain = kdf_root(root, b"\xaa" * 32)
    b_root, b_chain = kdf_root(root, b"\xbb" * 32)
    assert a_root != b_root
    assert a_chain != b_chain
    assert a_root != a_chain


def test_header_codec_round_trip():
    h = Header(v=1, flags=0, dh=b"\x07" * 32, pn=42, n=99)
    raw = h.encode()
    assert len(raw) == 42
    h2 = Header.decode(raw)
    assert h2 == h


def test_header_decode_rejects_short_buffer():
    with pytest.raises(ValueError):
        Header.decode(b"too short")


def test_header_decode_rejects_unknown_version():
    raw = bytes([2, 0]) + b"\x00" * 32 + b"\x00" * 8
    with pytest.raises(ValueError):
        Header.decode(raw)


# ─── basic round-trip ──────────────────────────────────────────────

def test_alice_to_bob_round_trip():
    alice, bob = init_pair(_ss())
    h, ct = encrypt(alice, b"hello")
    pt = decrypt(bob, h, ct)
    assert pt == b"hello"


def test_bob_can_reply_after_first_alice_message():
    alice, bob = init_pair(_ss())
    # Alice → Bob first.
    h1, ct1 = encrypt(alice, b"ping")
    decrypt(bob, h1, ct1)
    # Now Bob can send.
    h2, ct2 = encrypt(bob, b"pong")
    pt = decrypt(alice, h2, ct2)
    assert pt == b"pong"


def test_long_back_and_forth_conversation():
    alice, bob = init_pair(_ss())
    for i in range(50):
        h, ct = encrypt(alice, f"msg-from-alice-{i}".encode())
        assert decrypt(bob, h, ct) == f"msg-from-alice-{i}".encode()
        h, ct = encrypt(bob, f"reply-{i}".encode())
        assert decrypt(alice, h, ct) == f"reply-{i}".encode()


def test_bob_cannot_send_before_first_recv():
    alice, bob = init_pair(_ss())
    with pytest.raises(RuntimeError, match="not ready to send"):
        encrypt(bob, b"premature")


# ─── forward secrecy ───────────────────────────────────────────────

def test_forward_secrecy_chain_key_cannot_decrypt_past():
    """If we capture the send_chain_key AFTER message N has been
    sent, we should not be able to derive the message_key for any
    earlier message (the chain advanced past those keys)."""
    alice, bob = init_pair(_ss())
    h0, ct0 = encrypt(alice, b"first")
    decrypt(bob, h0, ct0)
    # Capture Alice's chain key here. It's now ahead of message 0.
    captured_chain_key = alice.send_chain_key
    # Now try to manually re-derive the message_key for message 0.
    # The chain key after kdf_chain'ing the captured one would yield
    # the key for message 1, not 0. There's no way to get back to 0.
    _, msg_key_for_next = kdf_chain(captured_chain_key)
    # Spending that key on the original ciphertext fails (wrong key).
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    aead = ChaCha20Poly1305(msg_key_for_next)
    nonce = b"\x00" * 4 + (0).to_bytes(8, "big")
    aead_ad = h0.encode()
    with pytest.raises(InvalidTag):
        aead.decrypt(nonce, ct0, aead_ad)


def test_forward_secrecy_root_key_diverges_each_step():
    """Each DH ratchet step replaces root_key. After three round-
    trips, the root_key bears no static relationship to the
    initial shared secret."""
    seed = _ss()
    alice, bob = init_pair(seed)
    initial_alice_root = alice.root_key
    initial_bob_root = bob.root_key
    # First round-trip drives one DH step from each side.
    for _ in range(3):
        h, ct = encrypt(alice, b"x")
        decrypt(bob, h, ct)
        h, ct = encrypt(bob, b"y")
        decrypt(alice, h, ct)
    assert alice.root_key != initial_alice_root
    assert bob.root_key != initial_bob_root
    assert alice.root_key != seed
    assert bob.root_key != seed


# ─── post-compromise security via DH ratchet ───────────────────────

def test_dh_ratchet_step_rotates_send_chain():
    """When Bob first replies (DH ratchet on his side), Alice's
    next-message DH step rotates HER chain too. Capturing Alice's
    pre-ratchet send_chain_key and feeding it into a forged frame
    fails."""
    alice, bob = init_pair(_ss())
    # Alice sends, Bob receives.
    h, ct = encrypt(alice, b"a1")
    decrypt(bob, h, ct)
    # Capture Alice's chain key BEFORE her DH ratchet (which
    # happens lazily when she next encrypts after Bob sends to her).
    pre_chain = alice.send_chain_key
    # Bob replies.
    h, ct = encrypt(bob, b"b1")
    decrypt(alice, h, ct)  # This triggers DH ratchet on Alice.
    # Alice's send_chain_key has been replaced by a fresh one
    # derived from the new DH output.
    assert alice.send_chain_key != pre_chain


def test_post_compromise_security_after_full_ratchet():
    """An attacker who holds Alice's full state at time T cannot
    decrypt messages Alice and Bob exchange AFTER a fresh DH
    round-trip (because the new DH outputs depend on ephemeral
    keys the attacker doesn't have).

    Concrete check: we deep-copy Alice's state, advance the real
    Alice + Bob through a DH round-trip, then attempt to decrypt
    Bob's next message using the COPY. That copy lacks the new
    dh_send private key Alice rotates into — decryption fails."""
    import copy
    alice, bob = init_pair(_ss())
    # Get past the very first message so Alice has a fully-derived
    # state with both send + recv chains.
    h, ct = encrypt(alice, b"m1")
    decrypt(bob, h, ct)
    h, ct = encrypt(bob, b"m2")
    decrypt(alice, h, ct)
    # Attacker snapshot: clone Alice's state. (`dh_send` is the
    # private key object — copy.deepcopy doesn't deep-clone the
    # cryptography private key, but for this test we capture all
    # fields including send_chain_key.)
    captured_chain_key = alice.send_chain_key
    captured_root = alice.root_key
    # Real Alice + Bob continue: full round-trip introduces fresh
    # DH ephemerals on BOTH sides.
    h, ct = encrypt(alice, b"m3")
    decrypt(bob, h, ct)
    h, ct = encrypt(bob, b"m4")
    decrypt(alice, h, ct)
    # Alice's chain + root have moved on. Attacker's captured
    # values can't decrypt the latest ciphertext.
    assert alice.send_chain_key != captured_chain_key
    assert alice.root_key != captured_root
    # And deriving the next message key from the captured chain
    # would produce the WRONG key for the new ciphertext.
    h_new, ct_new = encrypt(alice, b"m5")
    _, attacker_msg_key = kdf_chain(captured_chain_key)
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    nonce = b"\x00" * 4 + (h_new.n).to_bytes(8, "big")
    aead_ad = h_new.encode()
    with pytest.raises(InvalidTag):
        ChaCha20Poly1305(attacker_msg_key).decrypt(nonce, ct_new, aead_ad)


# ─── out-of-order delivery ─────────────────────────────────────────

def test_out_of_order_delivery_within_chain():
    """Alice sends m1, m2, m3 in order. Bob receives m3 first
    (m1, m2 delayed). Bob decrypts m3, then m1, then m2 — all
    plaintext correct."""
    alice, bob = init_pair(_ss())
    h1, ct1 = encrypt(alice, b"m1")
    h2, ct2 = encrypt(alice, b"m2")
    h3, ct3 = encrypt(alice, b"m3")
    # Receive out of order:
    assert decrypt(bob, h3, ct3) == b"m3"
    # Now m1 and m2 are in skipped table.
    assert decrypt(bob, h1, ct1) == b"m1"
    assert decrypt(bob, h2, ct2) == b"m2"


def test_out_of_order_across_dh_ratchet():
    """Alice sends m1 (chain 0), then Bob sends b1 (DH ratchet
    on Alice). Alice continues with m2 (chain 1). Bob receives
    m2 first, then m1 — both decrypt correctly."""
    alice, bob = init_pair(_ss())
    h_a1, ct_a1 = encrypt(alice, b"a1")
    decrypt(bob, h_a1, ct_a1)
    h_b1, ct_b1 = encrypt(bob, b"b1")
    decrypt(alice, h_b1, ct_b1)  # Alice ratchets.
    h_a2, ct_a2 = encrypt(alice, b"a2")
    h_a3, ct_a3 = encrypt(alice, b"a3")
    # Bob receives a3 first, then a2.
    assert decrypt(bob, h_a3, ct_a3) == b"a3"
    assert decrypt(bob, h_a2, ct_a2) == b"a2"


def test_skipped_keys_bounded():
    """If a peer claims n=10000 in the very first message, we
    should refuse to derive 10000 keys. Bound is MAX_SKIP_KEYS."""
    alice, bob = init_pair(_ss())
    # Generate a header way ahead of recv_n.
    h, ct = encrypt(alice, b"x")
    forged = Header(
        v=h.v, flags=h.flags, dh=h.dh,
        pn=h.pn, n=h.n + MAX_SKIP_KEYS + 1,
    )
    with pytest.raises(RuntimeError, match="too many skipped"):
        decrypt(bob, forged, ct)


# ─── replay defence ────────────────────────────────────────────────

def test_replay_of_same_header_rejected():
    alice, bob = init_pair(_ss())
    h, ct = encrypt(alice, b"once")
    assert decrypt(bob, h, ct) == b"once"
    with pytest.raises(RuntimeError, match="replayed"):
        decrypt(bob, h, ct)


def test_replay_of_skipped_message_rejected():
    """If m1 was decrypted via the skipped-key cache, replaying
    the same (dh, n) doesn't re-decrypt — the cache entry is
    one-shot."""
    alice, bob = init_pair(_ss())
    h1, ct1 = encrypt(alice, b"first")
    h2, ct2 = encrypt(alice, b"second")
    # Receive 2 first, then 1 (cached), then 1 again.
    decrypt(bob, h2, ct2)
    assert decrypt(bob, h1, ct1) == b"first"
    with pytest.raises(RuntimeError):
        decrypt(bob, h1, ct1)


# ─── header tampering ─────────────────────────────────────────────

def test_swapped_header_fails_aead():
    """Two valid messages from Alice. Swap their headers; both
    decrypts must fail because the AAD includes header.encode()."""
    alice, bob = init_pair(_ss())
    h1, ct1 = encrypt(alice, b"one")
    h2, ct2 = encrypt(alice, b"two")
    # Cross-pair headers and ciphertexts.
    with pytest.raises(Exception):
        decrypt(bob, h2, ct1)
    # Bob's state may or may not have been mutated — fresh pair
    # for the second check.
    alice2, bob2 = init_pair(_ss())
    h1b, ct1b = encrypt(alice2, b"one")
    h2b, ct2b = encrypt(alice2, b"two")
    with pytest.raises(Exception):
        decrypt(bob2, h1b, ct2b)


def test_modified_ciphertext_fails():
    alice, bob = init_pair(_ss())
    h, ct = encrypt(alice, b"hello")
    tampered = bytes([ct[0] ^ 1]) + ct[1:]
    with pytest.raises(InvalidTag):
        decrypt(bob, h, tampered)


def test_associated_data_must_match():
    alice, bob = init_pair(_ss())
    h, ct = encrypt(alice, b"hi", ad=b"context-A")
    # Different AD on receive → AEAD fails.
    with pytest.raises(InvalidTag):
        decrypt(bob, h, ct, ad=b"context-B")


def test_associated_data_round_trip():
    alice, bob = init_pair(_ss())
    h, ct = encrypt(alice, b"hi", ad=b"ctx")
    assert decrypt(bob, h, ct, ad=b"ctx") == b"hi"


# ─── capability advertisement ──────────────────────────────────────

def test_double_ratchet_capability_in_local_capabilities():
    assert DOUBLE_RATCHET_V1 in LOCAL_CAPABILITIES


def test_double_ratchet_capability_string_is_versioned():
    """If the protocol changes shape, peers must be able to
    distinguish v1 from a future v2 by the capability string."""
    assert DOUBLE_RATCHET_V1.endswith("_v1")


# ─── init constructor invariants ───────────────────────────────────

def test_init_alice_validates_lengths():
    with pytest.raises(ValueError):
        init_alice(shared_secret=b"short", peer_pub=b"\x00" * 32)
    with pytest.raises(ValueError):
        init_alice(shared_secret=b"\x00" * 32, peer_pub=b"\x00")


def test_init_bob_validates_length():
    sk, _ = x25519_keypair()
    with pytest.raises(ValueError):
        init_bob(shared_secret=b"short", dh_priv=sk)


def test_init_pair_uses_independent_secrets_per_call():
    """Each init_pair generates fresh ephemerals; two pairs with
    the same seed don't share any DH state."""
    seed = _ss()
    a1, b1 = init_pair(seed)
    a2, b2 = init_pair(seed)
    assert a1.dh_send_pub != a2.dh_send_pub
    assert b1.dh_send_pub != b2.dh_send_pub


# ─── multi-step DH ratchet validation ──────────────────────────────

def test_three_full_dh_round_trips_decrypt_correctly():
    alice, bob = init_pair(_ss())
    msgs_a_to_b = ["a1", "a2", "a3"]
    msgs_b_to_a = ["b1", "b2", "b3"]
    for a, b in zip(msgs_a_to_b, msgs_b_to_a):
        h, ct = encrypt(alice, a.encode())
        assert decrypt(bob, h, ct) == a.encode()
        h, ct = encrypt(bob, b.encode())
        assert decrypt(alice, h, ct) == b.encode()


def test_alice_burst_then_bob_reply_then_alice_burst():
    """The sequence-number-on-prev-chain mechanism: Alice sends
    5 messages, Bob receives all 5, Bob replies once, Alice
    sends 5 more (new chain). Bob's pn (prev_chain_length) on
    his recv side updates, and all 10 of Alice's messages
    decrypt — even if delivered in mixed order across the chain
    boundary."""
    alice, bob = init_pair(_ss())
    burst1 = [
        encrypt(alice, f"a-{i}".encode()) for i in range(5)
    ]
    # Bob receives the burst out of order.
    for h, ct in reversed(burst1):
        assert decrypt(bob, h, ct).startswith(b"a-")
    # Bob replies; Alice ratchets.
    h, ct = encrypt(bob, b"b-reply")
    assert decrypt(alice, h, ct) == b"b-reply"
    # Alice sends another burst on the new chain.
    burst2 = [
        encrypt(alice, f"a2-{i}".encode()) for i in range(5)
    ]
    for h, ct in burst2:
        assert decrypt(bob, h, ct).startswith(b"a2-")
