"""Ring signatures — prove "I'm in {pubkey set}" without revealing which.

A ring signature lets a signer prove "one of these N pubkeys signed
this" without revealing which specific pubkey did. The signer must
hold the private key for at least ONE pubkey in the ring; the
verifier learns nothing about which one. There's no group setup
ceremony; any signer who knows the ring can produce a signature
without coordination with the other members.

Use cases in One Link:

  - **Anonymous group credentials**: prove "I'm in group G" without
    revealing your identity within the group. Each group member
    publishes their pubkey to the group's pubkey set; an anonymous
    "I'm a member" signature comes from any member with their priv.
    Useful for whistleblower / journalist-source flows where the
    receiver wants verifiable provenance ("definitely a member") but
    not identification ("which one specifically").

  - **Anonymous abuse reports / appeals**: a paired peer can submit
    a signed report "I have evidence X" without revealing their
    identity to the daemon's audit log. The daemon verifies the
    signer is paired (member of the paired-pubkey ring) but doesn't
    log who.

  - **Anonymous voting / consent in groups**: each member casts a
    ring-signed vote; the tally counts only DISTINCT-via-key-image
    votes (Section "linkable" below) but doesn't reveal who voted
    which way.

Variants
--------

This module ships **AOS** ring signatures (Abe-Ohkubo-Suzuki, 2002 —
the classic discrete-log ring signature, also used as a building
block in CryptoNote / Monero). Pure Ed25519 / Curve25519, no
pairings. Signing: O(N); verifying: O(N).

The implementation is the **non-linkable** AOS variant: two
signatures from the same signer are unlinkable to a verifier, and
the signer can sign multiple times without external state. A future
"linkable AOS" variant adds a key image (Borromean / CryptoNote-
style) so the verifier can tell when two signatures came from the
same signer (without revealing who); useful for double-spend
prevention in voting flows.

Signature format
----------------

For a ring of N pubkeys ``[P_0, P_1, ..., P_{N-1}]``, the signature
is::

  c_0 || s_0 || s_1 || ... || s_{N-1}

where ``c_0`` is a 32-byte challenge and each ``s_i`` is a 32-byte
scalar response. Total length = 32 * (N+1) bytes.

Verification recomputes ``c_1, c_2, ..., c_{N-1}, c_N`` walking
the ring; the signature is valid iff ``c_N == c_0`` (the ring
"closes"). The signer's actual position is hidden because every
non-signer position emits a uniformly-random ``s_i``, and the
signer's position is the one where the random ``s_i`` is computed
from the secret to make the ring close.
"""
from __future__ import annotations

import hashlib
import secrets

from one_link import vrf as _vrf  # reuse Ed25519 point arithmetic


# Re-export curve constants from vrf.py so the implementations stay
# in lockstep on edge cases (e.g. point-decompress sign handling).
_P = _vrf._P
_L = _vrf._L
_BASE = _vrf._BASE
_point_add = _vrf._point_add
_point_mul = _vrf._point_mul
_point_mul_ct = _vrf._point_mul_ct  # v0.20.7+ Bundle 57: secret-scalar mult
_point_compress = _vrf._point_compress
_point_decompress = _vrf._point_decompress


def _scalar_from_priv_seed(priv_seed: bytes) -> int:
    """Derive a discrete-log scalar from an Ed25519 private seed
    using the same clamp construction as vrf.py / RFC 8032."""
    if len(priv_seed) != 32:
        raise ValueError("priv_seed must be 32 bytes")
    h = bytearray(hashlib.sha512(priv_seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(bytes(h), "little") % _L


def public_key_from_priv_seed(priv_seed: bytes) -> bytes:
    """Derive the matching ring-signature public key. Like vrf.py,
    this is the raw ``scalar * BASE`` encoding — NOT bit-compatible
    with Ed25519 signing pubkeys (which fold in additional
    derivation steps). For ring signatures, use this function on
    every member's priv_seed to produce the ring."""
    s = _scalar_from_priv_seed(priv_seed)
    # Bundle 57: secret scalar — constant-time path.
    return _point_compress(_point_mul_ct(s, _BASE))


def _hash_to_scalar(*chunks: bytes) -> int:
    h = hashlib.sha512(b"OL/ring-sig/c|v1|" + b"".join(chunks)).digest()
    return int.from_bytes(h[:32], "little") % _L


def _serialize_ring(ring: list[bytes]) -> bytes:
    return b"".join(ring)


def sign(
    *,
    priv_seed: bytes,
    ring: list[bytes],
    message: bytes,
) -> bytes:
    """Produce a ring signature over ``message`` such that any
    verifier learns "one of the pubkeys in ``ring`` signed this"
    without learning which one.

    The caller's pubkey MUST be in ``ring``; the signer's position
    in the ring is found internally.

    Returns the signature bytes (32 * (N+1) where N = len(ring))."""
    if not isinstance(ring, list) or len(ring) < 2:
        raise ValueError("ring must contain at least 2 pubkeys")
    if any(len(p) != 32 for p in ring):
        raise ValueError("every ring pubkey must be 32 bytes")
    my_pub = public_key_from_priv_seed(priv_seed)
    try:
        signer_idx = ring.index(my_pub)
    except ValueError:
        raise ValueError(
            "signer's pubkey is not in the ring — caller must "
            "include their own pubkey"
        ) from None
    n = len(ring)
    secret_scalar = _scalar_from_priv_seed(priv_seed)
    ring_bytes = _serialize_ring(ring)

    # Decompress every ring pubkey once.
    ring_points = []
    for p in ring:
        pt = _point_decompress(p)
        if pt is None:
            raise ValueError(f"ring pubkey {p.hex()[:16]}… invalid")
        ring_points.append(pt)

    # Random nonce + s_i for every non-signer position. The signer's
    # s is computed last to close the ring.
    s = [0] * n
    c = [0] * n
    # Pick the nonce alpha (signer's secret) — used to start the ring
    # at position (signer_idx + 1).
    alpha = int.from_bytes(secrets.token_bytes(32), "little") % _L
    # Bundle 57: alpha is the signer's secret nonce — constant-time mult.
    R = _point_mul_ct(alpha, _BASE)
    next_idx = (signer_idx + 1) % n
    c[next_idx] = _hash_to_scalar(
        ring_bytes, message, _point_compress(R),
    )

    # Walk the ring forward from (signer_idx + 1), computing each
    # subsequent c_i from a fresh random s_i and the previous c.
    i = next_idx
    while i != signer_idx:
        s[i] = int.from_bytes(secrets.token_bytes(32), "little") % _L
        # R_i = s_i * B + c_i * P_i
        # Bundle 57: s[i] is fresh secret randomness; constant-time
        # mult prevents the per-position timing from leaking the
        # signer's index. c[i] is derived from the public ring +
        # message + previous R, so the c[i]*P_i mult can stay
        # variable-time.
        R_i = _point_add(
            _point_mul_ct(s[i], _BASE),
            _point_mul(c[i], ring_points[i]),
        )
        next_i = (i + 1) % n
        c[next_i] = _hash_to_scalar(
            ring_bytes, message, _point_compress(R_i),
        )
        i = next_i

    # Close the ring at the signer's position:
    #   alpha = s_signer + c_signer * secret_scalar
    #   ⇒ s_signer = alpha - c_signer * secret_scalar mod L
    s[signer_idx] = (alpha - c[signer_idx] * secret_scalar) % _L

    # Signature = c[0] || s[0] || s[1] || ... || s[n-1]
    sig = c[0].to_bytes(32, "little")
    for si in s:
        sig += si.to_bytes(32, "little")
    return sig


def verify(
    *,
    ring: list[bytes],
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify a ring signature. Returns True iff the signature
    closes the ring under the message + ring pubkeys."""
    try:
        if not isinstance(ring, list) or len(ring) < 2:
            return False
        n = len(ring)
        expected_len = 32 * (n + 1)
        if len(signature) != expected_len:
            return False
        if any(len(p) != 32 for p in ring):
            return False
        ring_points = []
        for p in ring:
            pt = _point_decompress(p)
            if pt is None:
                return False
            ring_points.append(pt)
        c0 = int.from_bytes(signature[:32], "little") % _L
        s = [
            int.from_bytes(signature[32 + 32 * i: 32 + 32 * (i + 1)], "little")
            % _L
            for i in range(n)
        ]
        ring_bytes = _serialize_ring(ring)
        c_i = c0
        for i in range(n):
            R_i = _point_add(
                _point_mul(s[i], _BASE),
                _point_mul(c_i, ring_points[i]),
            )
            c_i = _hash_to_scalar(
                ring_bytes, message, _point_compress(R_i),
            )
        return c_i == c0
    except Exception:
        return False
