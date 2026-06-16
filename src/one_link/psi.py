"""Private Set Intersection — find common contacts without revealing either set.

The classic friend-finder problem: Alice has 500 phone-number /
email contacts; Bob has 800. They want to learn the intersection
("which of my contacts are also Bob's contacts") WITHOUT either
party learning the contacts the other has but they don't share.

Standard solutions involve oblivious transfer + circuit-style
privacy that's too heavy for a chat-app context. This module
ships a pragmatic OPRF-based PSI: simple, fast, audited
construction. The primitives:

  - **OPRF (Oblivious PRF)**: Bob holds a secret key K; Alice has
    a contact x. Alice wants Bob to compute F_K(x) without Bob
    learning x and without Alice learning K. Construction (DH-OPRF
    on Curve25519):

      1. Alice picks random scalar r, sends T = r * H(x) to Bob.
      2. Bob computes T' = K * T = r * K * H(x), sends back.
      3. Alice computes Y = (1/r) * T' = K * H(x) = F_K(x).

    Alice now has F_K(x) for her input x. She can compute this
    for every contact in her list. Bob never learns x; Alice
    never learns K.

  - **PSI from OPRF**: Bob also publishes the set
    ``{F_K(b) : b ∈ Bob's contacts}``. Alice computes F_K(a) for
    each a ∈ her contacts using the OPRF protocol, then checks
    which of her F_K(a) values appear in Bob's published set.
    The intersection is exactly Alice's contacts that match Bob's.

  - **Bob doesn't learn Alice's NON-shared contacts** (only the
    OPRF-blinded points, which look uniform random).

  - **Alice doesn't learn Bob's NON-shared contacts** (Bob's
    set is published as F_K-images; without K, Alice can't reverse
    them).

  - **Bob CAN learn the count of Alice's queries** (one OPRF call
    per Alice contact). Mitigation: pad Alice's queries with
    decoys. Out of scope for this primitive.

Threat caveat
-------------

OPRF-based PSI assumes Bob runs the protocol honestly. A malicious
Bob who picks K to be 0 makes every F_K(x) = identity, so all of
Alice's contacts "match" — false positives. Mitigation: Alice
verifies Bob's public key (= K * BASE_POINT) is non-trivial and
the OPRF responses are consistent. A future bundle can add the
verifiable-OPRF (RFC 9497) variant with a Schnorr-style proof.

Wire format
-----------

  - Alice's blinded query: 32-byte compressed point T
  - Bob's response: 32-byte compressed point T'
  - Bob's published set entries: 32-byte F_K(b) values (the
    output of Y = K * H(b), compressed)
"""
from __future__ import annotations

import secrets

from one_link import vrf as _vrf  # share the curve arithmetic


_L = _vrf._L
_BASE = _vrf._BASE
_point_add = _vrf._point_add
_point_mul = _vrf._point_mul
_point_mul_ct = _vrf._point_mul_ct  # v0.20.7+ Bundle 57: secret-scalar mult
_point_compress = _vrf._point_compress
_point_decompress = _vrf._point_decompress
_hash_to_point = _vrf._hash_to_point


def server_keypair() -> tuple[bytes, bytes]:
    """Bob's side: generate a fresh OPRF key + the public commitment.

    Returns ``(private_scalar_bytes, public_commitment_bytes)``.
    The public commitment ``K * BASE`` lets a verifier check that
    Bob's PSI responses are consistent with a single fixed K (a
    future bundle can add the proof-of-correct-K via Schnorr ZKP).
    """
    k_int = int.from_bytes(secrets.token_bytes(32), "little") % _L
    if k_int == 0:
        k_int = 1  # vanishingly unlikely; defense
    # Bundle 57: k_int is the OPRF private key — constant-time mult.
    pub = _point_compress(_point_mul_ct(k_int, _BASE))
    return k_int.to_bytes(32, "little"), pub


def server_evaluate_image(*, server_priv: bytes, contact: bytes) -> bytes:
    """Bob computes F_K(b) = K * H(b) for one of his own contacts b.
    Use this to populate Bob's published set: every entry is one
    F_K(b) value. Bob ships the full set to Alice once, then
    Alice OPRF-queries her contacts and checks which fall in the
    set."""
    if len(server_priv) != 32:
        raise ValueError("server_priv must be 32 bytes")
    k = int.from_bytes(server_priv, "little") % _L
    h_pt = _hash_to_point(contact)
    # Bundle 57: secret OPRF key — constant-time mult.
    return _point_compress(_point_mul_ct(k, h_pt))


def client_blind(*, contact: bytes) -> tuple[bytes, bytes]:
    """Alice's side: blind one of her contacts before sending to
    Bob. Returns ``(blind_scalar_bytes, blinded_query_bytes)``.

    Alice keeps blind_scalar private and ships blinded_query to
    Bob over the OPRF channel. After receiving Bob's response,
    she calls ``client_unblind`` with both."""
    h_pt = _hash_to_point(contact)
    while True:
        r = int.from_bytes(secrets.token_bytes(32), "little") % _L
        if r != 0:
            break
    # Bundle 57: r is the client's blind scalar — constant-time mult.
    T = _point_mul_ct(r, h_pt)
    return r.to_bytes(32, "little"), _point_compress(T)


def server_evaluate_query(
    *, server_priv: bytes, blinded_query: bytes,
) -> bytes:
    """Bob: evaluate the OPRF on Alice's blinded query.
    Returns ``T' = K * T``."""
    if len(server_priv) != 32 or len(blinded_query) != 32:
        raise ValueError("server_priv and blinded_query must be 32 bytes")
    k = int.from_bytes(server_priv, "little") % _L
    T = _point_decompress(blinded_query)
    if T is None:
        raise ValueError("blinded_query is not a valid curve point")
    # Bundle 57: secret OPRF key — constant-time mult.
    return _point_compress(_point_mul_ct(k, T))


def client_unblind(
    *, blind_scalar: bytes, server_response: bytes,
) -> bytes:
    """Alice: remove the blind to recover F_K(x). Returns the
    32-byte compressed point Y. Alice compares Y against Bob's
    published set entries to find matches."""
    if len(blind_scalar) != 32 or len(server_response) != 32:
        raise ValueError("blind_scalar and server_response must be 32 bytes")
    r = int.from_bytes(blind_scalar, "little") % _L
    if r == 0:
        raise ValueError("blind_scalar is zero (should never happen)")
    r_inv = pow(r, -1, _L)
    T_prime = _point_decompress(server_response)
    if T_prime is None:
        raise ValueError("server_response is not a valid curve point")
    # Bundle 57: r_inv is derived from the secret blind scalar — CT.
    Y = _point_mul_ct(r_inv, T_prime)
    return _point_compress(Y)


# ── high-level convenience flow ────────────────────────────────────


def psi_intersection(
    *,
    alice_contacts: list[bytes],
    bob_contacts: list[bytes],
    server_priv: bytes,
) -> set[bytes]:
    """One-shot end-to-end intersection (test harness). Alice
    blinds each of her contacts, Bob evaluates, Alice unblinds,
    Alice checks against Bob's published-set images. Returns the
    set of Alice's contacts that are also in Bob's set.

    In a real deployment, server_priv stays on Bob's side; the
    blind/eval/unblind exchange happens over the network. This
    helper just demonstrates the math; tests pin both pieces."""
    bob_set = {
        server_evaluate_image(server_priv=server_priv, contact=b)
        for b in bob_contacts
    }
    matches: set[bytes] = set()
    for a in alice_contacts:
        blind_s, T = client_blind(contact=a)
        T_prime = server_evaluate_query(
            server_priv=server_priv, blinded_query=T,
        )
        Y = client_unblind(blind_scalar=blind_s, server_response=T_prime)
        if Y in bob_set:
            matches.add(a)
    return matches
