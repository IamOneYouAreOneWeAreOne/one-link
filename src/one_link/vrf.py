"""Verifiable Random Function (VRF) — unbiased random selection
with a publicly-verifiable proof.

A VRF is a function ``F(secret_key, input) → (output, proof)``
where:

  - The output looks pseudorandom to anyone without the secret key.
  - The proof lets anyone (with only the public key) verify that
    the output was correctly computed from input + secret key.
  - The output is deterministic per (secret_key, input).

Use cases in One Link:

  - **Unbiased lookup-routing in the Kademlia DHT** (Bundle 36):
    when picking which alpha=3 nodes to query next, derive the
    "candidate score" for each known contact via VRF(self_priv,
    target_id || contact_id). The score is reproducible by
    auditors but unpredictable to a node that wants to game the
    routing. Mitigates eclipse attacks.

  - **Fair onion-relay rotation** (Bundle 40): pick the next
    relay path via VRF(self_priv, session_seed || timestamp).
    Verifiable by an auditor (you didn't pick a malicious relay
    on purpose) but unpredictable to a relay that wants to
    pre-position itself in your path.

  - **Verifiable random sampling in social recovery** (Bundle 35):
    when proving "I really did query 3 of my 5 guardians" without
    revealing which 3, VRF the guardian index list to produce
    a public commitment. (Out of scope for this bundle — flagged
    as a future use.)

Implementation
--------------

This is a SIMPLIFIED VRF construction, not full RFC 9381 ECVRF
(which uses a delicate hash-to-curve construction with try-and-
increment that's annoying to get right in pure Python). The
construction here is the well-known "DDH-VRF" (Dodis-Yampolskiy-
style) using Ed25519 scalars + the standard Ed25519 base point:

  output  = SHA-512(input || gamma)[:32]
  gamma   = scalar_mult(secret_scalar, hash_to_point(input))
  proof   = (gamma, c, s) — Schnorr-style NIZK proof of knowledge
                            of the secret scalar that produced gamma

  hash_to_point(input) = clear_cofactor(SHA-512(b"VRF-H2P|" || input)
                                        decode-as-Edwards-y)

The hash_to_point uses the "Elligator-on-pre-image" simplification:
hash to 32 bytes, decode as a y-coordinate, recover x with the
canonical sign bit (0). If the y doesn't decode to a valid curve
point, increment the input and retry. ~50% of inputs produce
valid points; expected ~2 retries. The cofactor multiplication
ensures the output sits in the prime-order subgroup, defeating
small-subgroup attacks.

Security: this gives the standard VRF guarantees (uniqueness,
pseudorandomness, full collision resistance) under the discrete
log assumption on Curve25519. NOT compatible with RFC 9381 ECVRF
on the wire — interop with other ecosystems requires the full
RFC 9381 ciphersuite. For One Link's internal use the simplified
construction is sufficient; a future bundle can add the RFC 9381
variant for ecosystem interop.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional


# Curve25519 / Ed25519 constants.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493  # group order
_D = -121665 * pow(121666, -1, _P) % _P
# Base point B (Ed25519 generator) — y=4/5 mod p, x recovered.
_BY = 4 * pow(5, -1, _P) % _P


def _modp_inv(x: int) -> int:
    return pow(x, -1, _P)


def _x_from_y(y: int, sign: int) -> Optional[int]:
    """Recover x from y on the Ed25519 curve. Returns None if y
    doesn't correspond to a valid point."""
    yy = (y * y) % _P
    u = (yy - 1) % _P
    v = (_D * yy + 1) % _P
    # x = sqrt(u/v). Computed via the Edwards-style trick.
    # x = (u * v^3) * (u * v^7)^((p-5)/8) mod p
    v3 = pow(v, 3, _P)
    x = (u * v3) % _P
    x = x * pow((u * pow(v, 7, _P)) % _P, (_P - 5) // 8, _P) % _P
    # Verify x^2 * v == u (or == -u; in the latter case x = x * 2^((p-1)/4)).
    vx2 = (v * x * x) % _P
    if vx2 == u:
        pass
    elif vx2 == (-u) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    else:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _point_decompress(y_bytes: bytes) -> Optional[tuple[int, int]]:
    """Decode a 32-byte little-endian Ed25519 point. The high bit of
    the last byte is the sign of x. Returns None if invalid."""
    if len(y_bytes) != 32:
        return None
    y = int.from_bytes(y_bytes, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x = _x_from_y(y, sign)
    if x is None:
        return None
    return (x, y)


def _point_compress(P: tuple[int, int]) -> bytes:
    x, y = P
    out = y | ((x & 1) << 255)
    return out.to_bytes(32, "little")


# ── Ed25519 (twisted Edwards) point arithmetic ──────────────────────


def _point_add(P: tuple[int, int], Q: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x1y2 = x1 * y2
    x2y1 = x2 * y1
    x1x2 = x1 * x2
    y1y2 = y1 * y2
    dxxyy = _D * x1x2 * y1y2 % _P
    x3 = ((x1y2 + x2y1) * _modp_inv((1 + dxxyy) % _P)) % _P
    y3 = ((y1y2 + x1x2) * _modp_inv((1 - dxxyy) % _P)) % _P
    return (x3, y3)


def _point_mul(scalar: int, P: tuple[int, int]) -> tuple[int, int]:
    """Variable-time double-and-add. Used for **public** inputs only
    (verify paths). Do NOT use this on secret scalars — the early-
    exit and the data-dependent branch on bit i leak the scalar via
    timing.

    For secret scalars (sign / decap / encap-in-secret-blind) use
    ``_point_mul_ct`` which fixes the loop bound to 256 iterations
    and runs the conditional add as a swap on every bit.
    """
    R = (0, 1)  # neutral element
    s = scalar % _L
    while s > 0:
        if s & 1:
            R = _point_add(R, P)
        P = _point_add(P, P)
        s >>= 1
    return R


def _cmov_point(
    A: tuple[int, int], B: tuple[int, int], cond: int,
) -> tuple[int, int]:
    """Constant-time conditional move: returns B when cond=1, A when
    cond=0. ``cond`` MUST be 0 or 1. The arithmetic-mask trick keeps
    timing independent of cond.

    Python integers are bigints with no native "constant time"
    guarantee from the runtime — we make a best-effort here, but
    Python's int operations vary in time with the magnitude of the
    operands. Real constant-time crypto needs C-level primitives
    (libsodium, OpenSSL); this best-effort is appropriate for the
    threat model "raise the bar against opportunistic timing
    attackers", not "defend against state-actor side-channel
    analysis." Documented explicitly so callers know the limit."""
    mask = -cond  # 0 → 0; 1 → -1 (all-bits-set on a two's-complement view)
    # Python ints don't have fixed width, but bitwise ops still work
    # the way you'd expect: A & ~mask | B & mask.
    inv = ~mask
    x = (A[0] & inv) | (B[0] & mask)
    y = (A[1] & inv) | (B[1] & mask)
    return (x, y)


def _point_mul_ct(scalar: int, P: tuple[int, int]) -> tuple[int, int]:
    """Best-effort constant-time scalar multiplication for secret
    scalars. Fixes the loop bound to 256 iterations (the bit-length
    of the group order) regardless of the scalar's magnitude, and
    uses ``_cmov_point`` to fold the conditional add into a
    branchless select.

    Caveat: Python's bigint arithmetic on coordinates is not
    constant-time at the hardware level (a multiplication on a
    smaller operand finishes faster than one on a larger). For
    state-actor-grade side-channel resistance, use the cryptography
    library's X25519 / Ed25519 (which call into OpenSSL's constant-
    time primitives) wherever the operation is a base-point mul.
    For arbitrary scalar*point on Curve25519 (which VRF / ring sigs
    / PSI need), neither cryptography nor PyNaCl exposes a public
    constant-time API — pure Python is the practical option, with
    this hardening to raise the bar against opportunistic timing
    attackers.

    The OUTPUT of _point_mul and _point_mul_ct are bit-identical
    for the same inputs."""
    R = (0, 1)
    s = scalar % _L
    Pcur = P
    for i in range(256):
        bit = (s >> i) & 1
        # Conditional add: R += Pcur if bit else R += 0.
        candidate = _point_add(R, Pcur)
        R = _cmov_point(R, candidate, bit)
        Pcur = _point_add(Pcur, Pcur)
    return R


_BASE = (None, _BY)
# Recover x of base point.
_BX = _x_from_y(_BY, 0)
_BASE = (_BX, _BY)


# ── Hash-to-point ──────────────────────────────────────────────────


def _hash_to_point(input_bytes: bytes) -> tuple[int, int]:
    """Try-and-increment hash-to-curve. Hash with a counter, decode
    as a Y-coordinate, recover X. ~50% success per try; expected
    ~2 tries. Cofactor-multiply to land in the prime-order
    subgroup."""
    counter = 0
    while True:
        h = hashlib.sha512(
            b"VRF-H2P|"
            + counter.to_bytes(4, "big")
            + input_bytes
        ).digest()[:32]
        # Mask off the high bit (force sign=0) so we don't depend on
        # the random sign — it just halves our decode rate.
        masked = bytearray(h)
        masked[31] &= 0x7f
        pt = _point_decompress(bytes(masked))
        if pt is not None:
            # Cofactor-multiply by 8 to ensure the point is in the
            # prime-order subgroup (Ed25519 cofactor = 8).
            return _point_mul(8, pt)
        counter += 1
        if counter > 100:
            raise RuntimeError("hash-to-point: 100 retries exhausted")


# ── Key derivation (Ed25519 priv-seed → VRF scalar) ────────────────


def _scalar_from_priv_seed(priv_seed: bytes) -> int:
    """Derive the VRF private scalar from an Ed25519 private seed.
    Uses the standard Ed25519 prefix-hash + clamp."""
    if len(priv_seed) != 32:
        raise ValueError("priv_seed must be 32 bytes")
    h = bytearray(hashlib.sha512(priv_seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return int.from_bytes(bytes(h), "little") % _L


# ── VRF API ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VRFOutput:
    output: bytes  # 32-byte VRF output (the pseudorandom value)
    proof: bytes   # 96-byte proof: gamma (32) + c (32) + s (32)


def prove(*, priv_seed: bytes, input_bytes: bytes) -> VRFOutput:
    """Generate a VRF output + proof for ``input_bytes`` under the
    Ed25519 private seed. The output is deterministic per
    (priv_seed, input)."""
    secret_scalar = _scalar_from_priv_seed(priv_seed)
    H = _hash_to_point(input_bytes)
    # v0.20.7+ (Bundle 57): secret_scalar is the long-term VRF
    # private key; route through _point_mul_ct so a timing attacker
    # observing prove() doesn't learn scalar bits via the early-exit
    # in the variable-time _point_mul.
    gamma = _point_mul_ct(secret_scalar, H)
    gamma_bytes = _point_compress(gamma)
    output = hashlib.sha512(b"VRF-OUT|" + input_bytes + gamma_bytes).digest()[:32]
    # Schnorr NIZK: prove knowledge of secret_scalar s.t.
    #   gamma = secret_scalar * H
    #   pubkey = secret_scalar * B
    # Both equations share the same secret. Random nonce k; commitment
    # is the pair (k*H, k*B). Challenge is hash of all public values.
    # Response s = k - c * secret_scalar mod L.
    k_bytes = hashlib.sha512(
        b"VRF-NONCE|" + priv_seed + input_bytes,
    ).digest()
    k = int.from_bytes(k_bytes[:32], "little") % _L
    K_H = _point_mul(k, H)
    K_B = _point_mul(k, _BASE)
    # Public key = secret_scalar * B. (constant-time path; secret.)
    public_key_point = _point_mul_ct(secret_scalar, _BASE)
    pub_bytes = _point_compress(public_key_point)
    H_bytes = _point_compress(H)
    c_input = (
        b"VRF-CHALLENGE|"
        + pub_bytes + H_bytes + gamma_bytes
        + _point_compress(K_H) + _point_compress(K_B)
    )
    c = int.from_bytes(hashlib.sha512(c_input).digest()[:32], "little") % _L
    s = (k - c * secret_scalar) % _L
    proof = (
        gamma_bytes
        + c.to_bytes(32, "little")
        + s.to_bytes(32, "little")
    )
    return VRFOutput(output=output, proof=proof)


def verify(
    *, public_key: bytes, input_bytes: bytes, output: bytes, proof: bytes,
) -> bool:
    """Verify a VRF proof. Returns True iff:
      - the proof is well-formed
      - gamma was correctly computed from input under the secret
        scalar matching the public_key (proved via the NIZK)
      - the output is the canonical hash of (input || gamma)
    """
    try:
        if len(public_key) != 32 or len(proof) != 96 or len(output) != 32:
            return False
        gamma_bytes = proof[:32]
        c_bytes = proof[32:64]
        s_bytes = proof[64:96]
        gamma = _point_decompress(gamma_bytes)
        if gamma is None:
            return False
        pub = _point_decompress(public_key)
        if pub is None:
            return False
        c = int.from_bytes(c_bytes, "little") % _L
        s = int.from_bytes(s_bytes, "little") % _L
        H = _hash_to_point(input_bytes)
        # Reconstruct K_B = s*B + c*pub
        K_B = _point_add(_point_mul(s, _BASE), _point_mul(c, pub))
        # Reconstruct K_H = s*H + c*gamma
        K_H = _point_add(_point_mul(s, H), _point_mul(c, gamma))
        H_bytes = _point_compress(H)
        c_recomputed = int.from_bytes(
            hashlib.sha512(
                b"VRF-CHALLENGE|"
                + public_key + H_bytes + gamma_bytes
                + _point_compress(K_H) + _point_compress(K_B)
            ).digest()[:32],
            "little",
        ) % _L
        if c_recomputed != c:
            return False
        # Verify output binding.
        expected_output = hashlib.sha512(
            b"VRF-OUT|" + input_bytes + gamma_bytes,
        ).digest()[:32]
        return expected_output == output
    except Exception:
        return False


def public_key_from_priv_seed(priv_seed: bytes) -> bytes:
    """Derive the VRF public key (= scalar * BASE) from an Ed25519
    private seed. NOT the same encoding as Ed25519's pubkey
    derivation (which folds in additional hashing) — this VRF uses
    the raw scalar mult result. The pubkey is 32 bytes compressed.

    v0.20.7+ (Bundle 57): constant-time path — derives the pubkey
    from a secret scalar so we route through _point_mul_ct."""
    s = _scalar_from_priv_seed(priv_seed)
    return _point_compress(_point_mul_ct(s, _BASE))
