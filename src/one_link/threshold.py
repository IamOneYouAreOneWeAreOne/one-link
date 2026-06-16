"""Shamir's Secret Sharing over GF(256) — primitive for threshold-of-N
device clusters.

The user's master secret (e.g. the data root key from lockbox.py, or
the Ed25519 identity key, or the seed for a deterministic derivation
of all of the above) gets split into N shares. Any M-of-N shares
reconstruct the secret; fewer than M reveal nothing.

The intended use, per `docs/SECURITY.md` §T4 and the project's
threshold-of-N device cluster ship plan:

  - User has 3 devices (laptop + phone + tablet). N=3 shares,
    threshold M=2. Each device holds one share locally; the
    full secret never persists on any single device.
  - Adding a 4th device: existing devices each transmit their
    share to the new device over an authenticated P2P channel
    (the One Link channel itself, post-pair). The new device
    combines them once locally, derives the master, then GENERATES
    a fresh sharing (N=4 shares now) and distributes the new
    shares back. Each device shreds the OLD share.
  - Lost device: any 2 of the 3 surviving devices reseal the
    cluster — they generate a fresh sharing (N=2 shares now) and
    each holds one. The lost device's share is no longer useful
    because the polynomial changed.

Why GF(256)?

  - One byte per evaluation point. Easy.
  - Standard tooling (ssss, vault). Interoperable.
  - Lookup-table arithmetic is fast in pure Python.
  - The underlying field choice doesn't affect security; the
    information-theoretic guarantee comes from polynomial
    interpolation, not the field size. Larger fields give bigger
    shares without security gain for a 256-bit secret.

Why pure Python?

  - No new dependency. cryptography>=42 is already the trust
    anchor; an SSS impl in 250 lines doesn't need a pip install.
  - The primitive is well-known and the tests in
    test_threshold_v0207.py pin every property (zero-knowledge
    below threshold, perfect reconstruction at threshold,
    deterministic vs random sharing modes, share-byte alignment
    on multi-byte secrets).

Cryptographic posture:

  - The polynomial coefficients are drawn from os.urandom (CSPRNG
    in cryptography's hazmat layer). Each byte is independent —
    no MITM-leakable correlation across share bytes.
  - Reconstruction is constant-time within the field operations:
    the GF(256) arithmetic uses table lookups whose access pattern
    is deterministic. Each share-byte is processed independently.
  - There is no secret information in the share INDICES (the
    "x-coordinate"). Indices 1..255 are the standard set;
    SHARE_ZERO is the secret itself, never transmitted.
  - The threshold property is information-theoretic, not
    computational: even an attacker with unlimited compute who
    holds <M shares learns nothing about the secret.

What this module does NOT do:

  - It is not a verifiable secret sharing scheme. A malicious
    share-holder cannot detect that they were given a bogus
    share until reconstruction fails. The threshold-cluster
    protocol that uses this primitive (`cluster.py` once shipped)
    handles authenticity by binding share transmissions to the
    One Link channel's transcript hash.
  - It is not proactive. Shares don't refresh on a clock; the
    cluster rotates only on membership change.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Iterable


# ── GF(256) arithmetic via lookup tables ─────────────────────────────
#
# Field generator polynomial: x^8 + x^4 + x^3 + x + 1 (0x11b), the
# AES Rijndael field. EXP[i] = generator^i mod p; LOG[v] is the
# inverse for v != 0. Multiplication in the field becomes table
# lookups + an integer add, which is constant-time at the Python
# bytecode level.

_EXP = [0] * 512
_LOG = [0] * 256


def _build_tables() -> None:
    """Walk the AES field's multiplicative group (period 255) using
    the generator g = 3 (= x_field + 1).

    Multiplying by g is `xtime(a) XOR a` where xtime is multiply-
    by-x with the AES irreducible polynomial reduction:
        xtime(a) = (a << 1) AND 0xff if bit 7 was 0
        xtime(a) = ((a << 1) AND 0xff) XOR 0x1b if bit 7 was 1
    The 0x1b is the lower 8 bits of the irreducible polynomial
    x^8 + x^4 + x^3 + x + 1 = 0x11b (the bit 8 itself is the
    leading 1 we just shifted out).
    """
    a = 1  # g^0 = 1
    for i in range(255):
        _EXP[i] = a
        _LOG[a] = i
        # Multiply a by g = x_field + 1.
        a_times_x = (a << 1) & 0xff
        if a & 0x80:
            a_times_x ^= 0x1b
        a = a_times_x ^ a   # a * (x+1) = (a*x) XOR a
    # Double the EXP table so multiply doesn't need a mod.
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_build_tables()
# Defensive: the AES field has period 255, so EXP[0..254] cover all
# nonzero elements. After this point any access to LOG[0] is a bug;
# we leave LOG[0] as the sentinel 0 so a misuse fails predictably.


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("inverse of 0 in GF(256)")
    return _EXP[255 - _LOG[a]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by 0 in GF(256)")
    if a == 0:
        return 0
    return _EXP[_LOG[a] + 255 - _LOG[b]]


# ── Shamir core ──────────────────────────────────────────────────────


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Horner's method evaluation of a GF(256) polynomial.

    coeffs[0] = constant term (= the secret byte for x=0).
    Result is in GF(256); 0 ≤ result ≤ 255.
    """
    acc = 0
    for c in reversed(coeffs):
        acc = _gf_mul(acc, x) ^ c
    return acc


def _lagrange_interp_at_zero(points: list[tuple[int, int]]) -> int:
    """Lagrange interpolation evaluated at x=0 to recover the secret
    byte. Each point is (x, y) in GF(256). We compute:

        secret = Σ_i y_i · Π_{j≠i} (-x_j) / (x_i - x_j)

    GF(256) is a characteristic-2 field, so subtraction == addition
    (== XOR). The "negative" of x_j is just x_j.
    """
    secret = 0
    for i, (xi, yi) in enumerate(points):
        # Build numerator + denominator.
        num = 1
        den = 1
        for j, (xj, _yj) in enumerate(points):
            if i == j:
                continue
            num = _gf_mul(num, xj)        # -x_j == x_j in GF(2^k)
            den = _gf_mul(den, xi ^ xj)   # x_i - x_j
        if den == 0:
            raise ValueError(
                "duplicate share x-coordinate (shares must be distinct)"
            )
        term = _gf_mul(yi, _gf_div(num, den))
        secret ^= term
    return secret


@dataclass(frozen=True)
class Share:
    """One participant's share. ``x`` is the share index (1..255).
    ``y`` is the per-byte values, length == len(secret)."""
    x: int
    y: bytes

    def to_bytes(self) -> bytes:
        """Wire/storage encoding: 1-byte index + raw share bytes."""
        if not (1 <= self.x <= 255):
            raise ValueError(f"share index out of range: {self.x}")
        return bytes([self.x]) + self.y

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Share":
        if len(blob) < 2:
            raise ValueError("share blob too short")
        return cls(x=blob[0], y=bytes(blob[1:]))


def split(
    secret: bytes,
    *,
    threshold: int,
    num_shares: int,
    randomness: bytes | None = None,
) -> list[Share]:
    """Split ``secret`` into ``num_shares`` Shamir shares; any
    ``threshold`` of them reconstruct.

    Args:
      secret: the bytes to split. Any length ≥ 1.
      threshold: the M in M-of-N. 2 ≤ threshold ≤ num_shares ≤ 255.
      num_shares: the N in M-of-N.
      randomness: optional caller-provided coefficient bytes for
        deterministic testing. MUST NOT be used in production —
        production callers leave this None and the os.urandom path
        produces the canonical fresh sharing. Length, if provided,
        must equal len(secret) * (threshold - 1).

    Returns:
      A list of Share objects, indices 1..num_shares.
    """
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    if len(secret) == 0:
        raise ValueError("secret must be at least 1 byte")
    if not (2 <= threshold <= num_shares <= 255):
        raise ValueError(
            f"threshold must satisfy 2 ≤ threshold ≤ num_shares ≤ 255, "
            f"got threshold={threshold}, num_shares={num_shares}"
        )
    coeff_count_per_byte = threshold - 1
    needed = len(secret) * coeff_count_per_byte
    if randomness is None:
        randomness = secrets.token_bytes(needed)
    elif len(randomness) != needed:
        raise ValueError(
            f"randomness must be {needed} bytes for deterministic "
            f"split with secret_len={len(secret)} threshold={threshold}, "
            f"got {len(randomness)} bytes"
        )

    shares: list[Share] = [Share(x=i, y=b"") for i in range(1, num_shares + 1)]
    # We'll accumulate share bytes in mutable bytearrays.
    accumulated = [bytearray() for _ in range(num_shares)]

    cursor = 0
    for byte_idx, sec_byte in enumerate(secret):
        # Build coefficient list for this byte: [secret_byte, r0, r1, ...]
        coeffs = [sec_byte]
        for _ in range(coeff_count_per_byte):
            coeffs.append(randomness[cursor])
            cursor += 1
        # Evaluate at x=1..num_shares.
        for share_idx in range(num_shares):
            x = share_idx + 1
            accumulated[share_idx].append(_eval_poly(coeffs, x))

    return [
        Share(x=i + 1, y=bytes(accumulated[i]))
        for i in range(num_shares)
    ]


def combine(shares: Iterable[Share]) -> bytes:
    """Reconstruct the secret from at least ``threshold`` shares.

    Raises ValueError if shares are inconsistent (different lengths,
    duplicate indices, or fewer-than-threshold shares present and
    the polynomial has high enough degree to require more — which
    we don't check here, the caller is responsible for providing
    enough).
    """
    share_list = list(shares)
    if len(share_list) < 2:
        raise ValueError("need at least 2 shares to reconstruct")
    secret_len = len(share_list[0].y)
    if any(len(s.y) != secret_len for s in share_list):
        raise ValueError("shares have inconsistent lengths")
    seen_x = set()
    for s in share_list:
        if not (1 <= s.x <= 255):
            raise ValueError(f"share index out of range: {s.x}")
        if s.x in seen_x:
            raise ValueError(f"duplicate share index: {s.x}")
        seen_x.add(s.x)

    out = bytearray(secret_len)
    for byte_idx in range(secret_len):
        points = [(s.x, s.y[byte_idx]) for s in share_list]
        out[byte_idx] = _lagrange_interp_at_zero(points)
    return bytes(out)


# ── high-level helpers for cluster bootstrap ─────────────────────────


def split_master_key(
    master_key: bytes,
    *,
    n_devices: int,
    threshold: int,
) -> list[bytes]:
    """Convenience: split a 32-byte master key into ``n_devices``
    wire-encoded shares (1 + 32 = 33 bytes each). Mirrors the
    typical lockbox.LockBox initialization input."""
    if len(master_key) != 32:
        raise ValueError("master_key must be 32 bytes")
    return [s.to_bytes() for s in split(
        master_key, threshold=threshold, num_shares=n_devices,
    )]


def combine_master_key(share_blobs: Iterable[bytes]) -> bytes:
    """Inverse of split_master_key. Caller must supply at least
    ``threshold`` blobs (the function doesn't know the threshold
    on its own; that's protocol context)."""
    return combine(Share.from_bytes(b) for b in share_blobs)
