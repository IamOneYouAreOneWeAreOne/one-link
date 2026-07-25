"""Sealed Sender — strip the sender identity off the wire.

Historically, relay framing exposed the sender identity and the legacy route
exposed the destination public key. The live v2 transport now addresses an
already-paired recipient with a rotating secret tag, while this envelope keeps
the sender identity inside recipient-only ciphertext. A relay still observes
socket, timing, byte-count, and tag-activity metadata.

Sealed Sender (Signal, 2018) hides the sender identity from the
relay payload. The wire frame is encrypted to the recipient's identity;
the *sender* identity is encrypted INSIDE that envelope. The
relay sees an opaque envelope carried under a blinded tag. B decrypts, learns
the sender identity + verifies the
sender is in B's paired-peer set.

Embedding protocols pass a bounded ``aad_context``. Its hash is bound into
both HKDF info and AEAD associated data, so a valid envelope minted for one
protocol role cannot be replayed into another.

This envelope does not itself address the recipient. The live relay's v2
transport now uses a rotating pairwise route tag, so neither identity public
key is present on that relay protocol wire. The relay still observes socket,
timing, size, and per-tag metadata; this primitive does not claim anonymity.
Because the recipient side uses a long-term identity-derived X25519 key, a
later compromise of that recipient identity seed can open previously recorded
envelopes. This envelope provides sender-identity confidentiality in transit,
not metadata forward secrecy against endpoint-key compromise.

Wire format
-----------

  [ephemeral_x25519_pub: 32 bytes]
  [nonce: 12 bytes]
  [AES-GCM ciphertext + 16-byte tag]

The plaintext inside the AEAD is::

  [version: 1 byte]                         # 1 today
  [sender_ed_pub: 32 bytes]
  [timestamp_ms: 8 bytes BE]
  [signature: 64 bytes]                     # Ed25519
  [body: variable]

Where ``signature`` covers ``(version || sender_ed_pub ||
timestamp_ms || body)`` and binds the sender identity to the
specific body + timestamp. The recipient verifies:

  1. AEAD decrypts (proves the sender knew an ephemeral that ECDH'd
     to their long-term pub)
  2. signature verifies under sender_ed_pub
  3. sender_ed_pub is in the recipient's paired-peer set (caller's
     responsibility to enforce — sealed_sender only PROVIDES the
     identity, doesn't decide trust)
  4. timestamp_ms is within an acceptable freshness window
     (prevents replay of stale frames)

Why ECIES + Ed25519 sig (not just AEAD)?

The AEAD alone proves "someone with the recipient's address knew
how to do an X25519 ECDH" — that's anyone who has a valid pub
key, not authenticated. The Ed25519 sig inside the envelope binds
the sender's *long-term identity* to the message; without it, an
attacker could craft a valid envelope claiming to come from
anyone.
"""
from __future__ import annotations

import hashlib
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Iterable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SEALED_VERSION = 1
EPH_PUB_LEN = 32
NONCE_LEN = 12
SIG_LEN = 64
ED_PUB_LEN = 32
TIMESTAMP_LEN = 8
INNER_HEADER_LEN = 1 + ED_PUB_LEN + TIMESTAMP_LEN + SIG_LEN  # = 105
HKDF_INFO = b"OL/sealed-sender/v1|"

# Default freshness window for the embedded timestamp. 5 minutes
# matches Signal's; tighter = more time-sync sensitivity, looser =
# wider replay window. Adjustable per-call.
DEFAULT_FRESHNESS_MS = 5 * 60 * 1000
MAX_AAD_CONTEXT_BYTES = 1024


@dataclass(frozen=True)
class UnsealedMessage:
    sender_ed_pub: bytes
    timestamp_ms: int
    body: bytes


# ── helpers ────────────────────────────────────────────────────────


def _ed25519_pub_to_x25519(ed_pub: bytes) -> bytes:
    """Convert an Ed25519 public key to its X25519 equivalent.

    Mirror of social_recovery.ed25519_pub_to_x25519 — kept local so
    sealed_sender doesn't take a circular dep on that module.

    The map: ``u = (1 + y) / (1 - y) mod p`` on Curve25519, where
    ``y`` is the Edwards y-coordinate encoded in the low 255 bits
    of ed_pub."""
    if len(ed_pub) != 32:
        raise ValueError("ed_pub must be 32 bytes")
    p = 2**255 - 19
    y = int.from_bytes(ed_pub, "little") & ((1 << 255) - 1)
    u = ((1 + y) * pow((1 - y) % p, -1, p)) % p
    return u.to_bytes(32, "little")


def _ed25519_priv_seed_to_x25519(ed_priv_seed: bytes) -> bytes:
    """Derive the X25519 private key from an Ed25519 private SEED
    (the 32-byte value passed to Ed25519PrivateKey.from_private_bytes).
    Same construction as social_recovery."""
    if len(ed_priv_seed) != 32:
        raise ValueError("ed_priv_seed must be 32 bytes")
    h = bytearray(hashlib.sha512(ed_priv_seed).digest()[:32])
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return bytes(h)


def _derive_aead_key(shared: bytes, *, info_extra: bytes = b"") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO + info_extra,
    ).derive(shared)


def _context_binding(aad_context: bytes) -> bytes:
    if not isinstance(aad_context, bytes):
        raise ValueError("aad_context must be bytes")
    if len(aad_context) > MAX_AAD_CONTEXT_BYTES:
        raise ValueError(
            f"aad_context exceeds {MAX_AAD_CONTEXT_BYTES}-byte bound"
        )
    if not aad_context:
        return b""
    return b"context-sha256|" + hashlib.sha256(aad_context).digest()


def _sig_input(version: int, sender_ed_pub: bytes, timestamp_ms: int, body: bytes) -> bytes:
    return (
        bytes([version]) + sender_ed_pub
        + struct.pack(">Q", timestamp_ms) + body
    )


# ── seal / unseal ───────────────────────────────────────────────────


def seal(
    *,
    body: bytes,
    sender_ed_priv_seed: bytes,
    sender_ed_pub: bytes,
    recipient_ed_pub: bytes,
    timestamp_ms: Optional[int] = None,
    aad_context: bytes = b"",
) -> bytes:
    """Encrypt + sign a message such that only the recipient can
    learn the sender identity. Returns the wire blob: ephemeral
    pubkey || nonce || AEAD ciphertext.

    The wire blob carries no sender identity. A relay routing this
    blob to ``recipient_ed_pub`` learns nothing about the sender
    beyond "a peer with a valid X25519 ephemeral". ``aad_context`` is
    domain separation supplied by the embedding protocol; both sides must use
    the exact same value.
    """
    if len(sender_ed_priv_seed) != 32:
        raise ValueError("sender_ed_priv_seed must be 32 bytes")
    if len(sender_ed_pub) != ED_PUB_LEN:
        raise ValueError(f"sender_ed_pub must be {ED_PUB_LEN} bytes")
    if len(recipient_ed_pub) != ED_PUB_LEN:
        raise ValueError(f"recipient_ed_pub must be {ED_PUB_LEN} bytes")
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)

    # Ed25519 → X25519 conversion for both sides.
    recipient_x_pub = _ed25519_pub_to_x25519(recipient_ed_pub)
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    try:
        shared = eph_priv.exchange(
            X25519PublicKey.from_public_bytes(recipient_x_pub),
        )
    except Exception as e:
        raise ValueError(f"recipient pubkey not Ed25519→X25519 valid: {e}") from None
    if shared == b"\x00" * 32:
        raise ValueError("recipient pub yielded zero shared secret")
    context_binding = _context_binding(aad_context)
    key = _derive_aead_key(shared, info_extra=context_binding)

    # Ed25519 sign over (version || sender_pub || ts || body).
    sender_priv = Ed25519PrivateKey.from_private_bytes(sender_ed_priv_seed)
    si = _sig_input(SEALED_VERSION, sender_ed_pub, timestamp_ms, body)
    signature = sender_priv.sign(si)

    inner = (
        bytes([SEALED_VERSION])
        + sender_ed_pub
        + struct.pack(">Q", timestamp_ms)
        + signature
        + body
    )
    nonce = secrets.token_bytes(NONCE_LEN)
    # Bind the ephemeral pubkey into the AAD so a relay can't swap
    # it without invalidating the tag.
    aad = b"OL/sealed-sender/aad/v1|" + eph_pub + context_binding
    ct = AESGCM(key).encrypt(nonce, inner, aad)
    return eph_pub + nonce + ct


def unseal(
    *,
    blob: bytes,
    my_ed_priv_seed: bytes,
    paired_ed_pubs: Optional[Iterable[bytes]] = None,
    freshness_window_ms: int = DEFAULT_FRESHNESS_MS,
    now_ms: Optional[int] = None,
    aad_context: bytes = b"",
) -> UnsealedMessage:
    """Decrypt + verify a sealed-sender blob. Returns the
    ``UnsealedMessage`` with sender identity, timestamp, and body.

    Raises ValueError on:
      - too-short blob
      - AEAD decrypt failure (wrong recipient or tamper)
      - signature verification failure (forged sender claim)
      - sender pub not in ``paired_ed_pubs`` (when supplied)
      - timestamp older / newer than ``freshness_window_ms`` either
        side of ``now_ms``
      - a wrong embedding ``aad_context`` (reported as AEAD failure)
    """
    if len(my_ed_priv_seed) != 32:
        raise ValueError("my_ed_priv_seed must be 32 bytes")
    if len(blob) < EPH_PUB_LEN + NONCE_LEN + INNER_HEADER_LEN + 16:
        raise ValueError("sealed blob too short")
    eph_pub = blob[:EPH_PUB_LEN]
    nonce = blob[EPH_PUB_LEN:EPH_PUB_LEN + NONCE_LEN]
    ct = blob[EPH_PUB_LEN + NONCE_LEN:]

    my_x_priv_bytes = _ed25519_priv_seed_to_x25519(my_ed_priv_seed)
    my_x_priv = X25519PrivateKey.from_private_bytes(my_x_priv_bytes)
    try:
        shared = my_x_priv.exchange(
            X25519PublicKey.from_public_bytes(eph_pub),
        )
    except Exception as e:
        raise ValueError(f"shared-secret derive failed: {e}") from None
    if shared == b"\x00" * 32:
        raise ValueError("ECDH yielded zero shared secret")
    context_binding = _context_binding(aad_context)
    key = _derive_aead_key(shared, info_extra=context_binding)
    aad = b"OL/sealed-sender/aad/v1|" + eph_pub + context_binding
    try:
        inner = AESGCM(key).decrypt(nonce, ct, aad)
    except Exception as e:
        raise ValueError(
            f"sealed envelope decrypt failed (wrong recipient or tamper): {e}"
        ) from None
    if len(inner) < INNER_HEADER_LEN:
        raise ValueError("inner payload truncated")
    version = inner[0]
    if version != SEALED_VERSION:
        raise ValueError(f"unsupported sealed-sender version: {version}")
    sender_ed_pub = inner[1:1 + ED_PUB_LEN]
    timestamp_ms = struct.unpack(
        ">Q", inner[1 + ED_PUB_LEN:1 + ED_PUB_LEN + TIMESTAMP_LEN],
    )[0]
    sig_off = 1 + ED_PUB_LEN + TIMESTAMP_LEN
    signature = inner[sig_off:sig_off + SIG_LEN]
    body = inner[sig_off + SIG_LEN:]

    # Verify Ed25519 signature.
    si = _sig_input(version, sender_ed_pub, timestamp_ms, body)
    try:
        Ed25519PublicKey.from_public_bytes(sender_ed_pub).verify(signature, si)
    except InvalidSignature:
        raise ValueError("sealed-sender signature does not verify") from None

    # Check trust: sender must be in the paired set, if a set is
    # supplied. Caller skips this only for explicitly-anonymous
    # flows (e.g. a public bulletin board); for normal peer chat
    # we always pass the paired set.
    if paired_ed_pubs is not None:
        paired_set = {bytes(p) for p in paired_ed_pubs}
        if sender_ed_pub not in paired_set:
            raise ValueError(
                f"sealed sender pubkey not in paired set "
                f"(possible impersonation): {sender_ed_pub.hex()[:16]}"
            )

    # Check freshness.
    if freshness_window_ms is not None:
        if now_ms is None:
            now_ms = int(time.time() * 1000)
        delta = abs(now_ms - timestamp_ms)
        if delta > freshness_window_ms:
            raise ValueError(
                f"sealed-sender timestamp {delta}ms outside freshness "
                f"window of {freshness_window_ms}ms"
            )

    return UnsealedMessage(
        sender_ed_pub=sender_ed_pub,
        timestamp_ms=timestamp_ms,
        body=body,
    )
