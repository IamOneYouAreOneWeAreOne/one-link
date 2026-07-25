"""v0.20.7 — Private Set Intersection via DH-OPRF.

Friend-finder: Alice + Bob compute the intersection of their contact
lists without revealing the non-intersection items. OPRF construction
on Curve25519: blind, eval, unblind, compare-to-published-set.

These tests pin:
  - server_keypair returns 32-byte priv + 32-byte pub
  - server_evaluate_image is deterministic per (priv, contact)
  - client_blind + server_evaluate_query + client_unblind round-trip
    yields the same value as server_evaluate_image (the OPRF
    correctness property)
  - PSI: items in BOTH sets appear in the intersection; items in
    only one don't
  - Bob can't tell Alice's contact from her blinded query (the
    "blind" is uniform random over the curve)
  - Two different blinds of the same contact produce different
    blinded queries (no leakage of repeated lookups)
"""
from __future__ import annotations


import pytest

from one_link import psi


def test_server_keypair_shape():
    priv, pub = psi.server_keypair()
    assert isinstance(priv, bytes) and len(priv) == 32
    assert isinstance(pub, bytes) and len(pub) == 32


def test_server_evaluate_image_deterministic():
    priv, _ = psi.server_keypair()
    a = psi.server_evaluate_image(server_priv=priv, contact=b"alice@example")
    b = psi.server_evaluate_image(server_priv=priv, contact=b"alice@example")
    assert a == b
    assert len(a) == 32


def test_server_image_changes_with_contact():
    priv, _ = psi.server_keypair()
    a = psi.server_evaluate_image(server_priv=priv, contact=b"alice@example")
    b = psi.server_evaluate_image(server_priv=priv, contact=b"bob@example")
    assert a != b


def test_server_image_changes_with_priv():
    priv1, _ = psi.server_keypair()
    priv2, _ = psi.server_keypair()
    a = psi.server_evaluate_image(server_priv=priv1, contact=b"x@y")
    b = psi.server_evaluate_image(server_priv=priv2, contact=b"x@y")
    assert a != b


def test_oprf_correctness():
    """The defining OPRF property: client_unblind(server_evaluate_
    query(client_blind(c))) == server_evaluate_image(c). Alice's
    OPRF-protocol output equals the value Bob would have computed
    locally on the same input under the same key."""
    priv, _ = psi.server_keypair()
    contact = b"common-contact@example"
    direct = psi.server_evaluate_image(server_priv=priv, contact=contact)
    blind_s, T = psi.client_blind(contact=contact)
    T_prime = psi.server_evaluate_query(
        server_priv=priv, blinded_query=T,
    )
    Y = psi.client_unblind(
        blind_scalar=blind_s, server_response=T_prime,
    )
    assert Y == direct


def test_blind_uses_fresh_randomness():
    """Two blinds of the same contact produce different blinded
    queries — Bob can't link repeated lookups."""
    blind1, T1 = psi.client_blind(contact=b"x")
    blind2, T2 = psi.client_blind(contact=b"x")
    assert T1 != T2
    assert blind1 != blind2


def test_psi_intersection_full():
    priv, _ = psi.server_keypair()
    alice = [b"a@x", b"shared@x", b"b@x", b"another-shared@x", b"c@x"]
    bob = [b"shared@x", b"d@x", b"another-shared@x", b"e@x"]
    intersection = psi.psi_intersection(
        alice_contacts=alice, bob_contacts=bob, server_priv=priv,
    )
    assert intersection == {b"shared@x", b"another-shared@x"}


def test_psi_empty_intersection():
    priv, _ = psi.server_keypair()
    alice = [b"a", b"b", b"c"]
    bob = [b"d", b"e", b"f"]
    intersection = psi.psi_intersection(
        alice_contacts=alice, bob_contacts=bob, server_priv=priv,
    )
    assert intersection == set()


def test_psi_alice_subset_of_bob():
    priv, _ = psi.server_keypair()
    alice = [b"a", b"b"]
    bob = [b"a", b"b", b"c", b"d"]
    intersection = psi.psi_intersection(
        alice_contacts=alice, bob_contacts=bob, server_priv=priv,
    )
    assert intersection == {b"a", b"b"}


def test_psi_full_overlap():
    priv, _ = psi.server_keypair()
    contacts = [b"x", b"y", b"z"]
    intersection = psi.psi_intersection(
        alice_contacts=contacts, bob_contacts=contacts, server_priv=priv,
    )
    assert intersection == set(contacts)


def test_invalid_inputs_rejected():
    with pytest.raises(ValueError):
        psi.server_evaluate_image(
            server_priv=b"\x00" * 16, contact=b"x",
        )
    with pytest.raises(ValueError):
        psi.server_evaluate_query(
            server_priv=b"\x00" * 32, blinded_query=b"\x00" * 16,
        )
    with pytest.raises(ValueError):
        psi.client_unblind(
            blind_scalar=b"\x00" * 32, server_response=b"\x00" * 16,
        )
    # All-zero blinded_query is the curve identity which decompress
    # treats as a valid point — but multiplied by K it stays
    # identity, so OPRF gives a degenerate output. Not a security
    # bug per se but worth flagging.


def test_unblind_with_wrong_blind_scalar():
    """If Alice loses track of which blind goes with which response,
    the unblind produces garbage (not the right OPRF output)."""
    priv, _ = psi.server_keypair()
    blind1, T1 = psi.client_blind(contact=b"contact1")
    blind2, T2 = psi.client_blind(contact=b"contact2")
    T1_prime = psi.server_evaluate_query(
        server_priv=priv, blinded_query=T1,
    )
    # Use blind2 with T1's response — should NOT yield F_K(contact1).
    Y_wrong = psi.client_unblind(
        blind_scalar=blind2, server_response=T1_prime,
    )
    Y_right = psi.client_unblind(
        blind_scalar=blind1, server_response=T1_prime,
    )
    direct = psi.server_evaluate_image(
        server_priv=priv, contact=b"contact1",
    )
    assert Y_right == direct
    assert Y_wrong != direct
