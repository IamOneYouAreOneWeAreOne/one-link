"""Onion-routed relay path — no single relay sees both endpoints.

Sealed Sender (Bundle 39) hid the SENDER identity from the relay.
Onion routing hides the PATH: a packet flows through 3+ relays,
each unwrapping only its own layer to learn "forward to the next
hop". The first relay knows the sender but not the destination;
the last relay knows the destination but not the sender; the
middle relays know neither.

Inspired by Sphinx (Danezis & Goldberg, 2009 — the format used by
Tor's hidden services + Lightning Network). This is a SIMPLIFIED
variant: not constant-size, no header MAC chain that hides hop
count, no replay tag. Those are real Sphinx requirements for
strong unlinkability against a global adversary; for the One Link
threat model (a curious or compromised single relay, not a global
passive adversary), the simpler layered ECIES gives the user-
visible property "no relay sees both endpoints" while keeping the
implementation small + auditable.

A future bundle can swap this for a full Sphinx (constant-size +
unlinkable + replay-protected) when the threat model upgrades to
the global-adversary tier.

Wire format
-----------

For an N-hop path [R1, R2, ..., RN, recipient], the sender
constructs::

    Layer N (innermost):
      [eph_pub_N: 32] [nonce: 12] [AES-GCM(payload, recipient_pub)]
        plaintext = (recipient_addr, body)

    Layer N-1:
      [eph_pub_{N-1}: 32] [nonce: 12] [AES-GCM(layer_N, R_N_pub)]
        plaintext = (next_hop = R_N_addr, layer_N)

    ...

    Layer 1 (outermost):
      [eph_pub_1: 32] [nonce: 12] [AES-GCM(layer_2, R_1_pub)]
        plaintext = (next_hop = R_2_addr, layer_2)

The sender ships the outermost wrapper to R1. R1 ECDHs its priv
with eph_pub_1, derives the AES-GCM key, decrypts to get
``(next_hop, layer_2)``, forwards layer_2 to R2. Each hop sees
ONLY its own ephemeral, the next-hop address, and the still-
encrypted remainder.

Hop addresses are opaque ``bytes`` to this module: the transport
layer (UDP, WebRTC DataChannel, Tor) interprets them.

Public keys are X25519 (32 bytes raw). Each relay must publish
its X25519 pub via the directory; the sender includes
that pub in the per-hop ECDH key derivation.
"""
from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass
from typing import Iterable, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


EPH_PUB_LEN = 32
NONCE_LEN = 12
HKDF_INFO = b"OL/onion/hop|v1"
# Cap each hop's "next address" length so a malicious sender
# can't craft a header that consumes unbounded recipient memory.
MAX_ADDR_LEN = 256
# Max total onion size — same threat as above. 64 KiB is plenty
# for a 5-hop path with a moderate body; larger payloads should
# use a chunked-onion construction (out of scope here).
MAX_ONION_LEN = 64 * 1024


@dataclass(frozen=True)
class HopKey:
    """One relay's directory entry: opaque transport address + the
    relay's X25519 public key. The sender enumerates a path of
    HopKeys + a final recipient address."""
    address: bytes
    x25519_pub: bytes

    def __post_init__(self):
        if len(self.x25519_pub) != EPH_PUB_LEN:
            raise ValueError(
                f"x25519_pub must be {EPH_PUB_LEN} bytes, "
                f"got {len(self.x25519_pub)}"
            )
        if len(self.address) == 0 or len(self.address) > MAX_ADDR_LEN:
            raise ValueError(
                f"address must be 1..{MAX_ADDR_LEN} bytes, "
                f"got {len(self.address)}"
            )


def _derive_hop_key(shared: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HKDF_INFO,
    ).derive(shared)


def _encode_layer(next_addr: bytes, inner: bytes) -> bytes:
    """A layer's plaintext is ``[u16 addr_len][addr][inner]``."""
    if len(next_addr) > MAX_ADDR_LEN:
        raise ValueError(f"next_addr too large: {len(next_addr)}")
    return struct.pack(">H", len(next_addr)) + next_addr + inner


def _decode_layer(raw: bytes) -> tuple[bytes, bytes]:
    if len(raw) < 2:
        raise ValueError("layer truncated at addr length")
    addr_len = struct.unpack(">H", raw[:2])[0]
    if addr_len > MAX_ADDR_LEN:
        raise ValueError(f"addr_len {addr_len} exceeds cap")
    if len(raw) < 2 + addr_len:
        raise ValueError("layer truncated at addr body")
    addr = raw[2:2 + addr_len]
    inner = raw[2 + addr_len:]
    return addr, inner


def _wrap_one_hop(
    *, plaintext: bytes, hop_pub: bytes, aad: bytes,
) -> bytes:
    """Encrypt ``plaintext`` to ``hop_pub`` via X25519+AES-GCM.
    Returns the on-wire blob ``[eph_pub | nonce | ct+tag]``."""
    if len(hop_pub) != EPH_PUB_LEN:
        raise ValueError(f"hop_pub must be {EPH_PUB_LEN} bytes")
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes_raw()
    try:
        shared = eph_priv.exchange(X25519PublicKey.from_public_bytes(hop_pub))
    except Exception as e:
        raise ValueError(f"hop_pub ECDH failed: {e}") from None
    if shared == b"\x00" * 32:
        raise ValueError("hop_pub yielded zero shared secret")
    key = _derive_hop_key(shared)
    nonce = secrets.token_bytes(NONCE_LEN)
    full_aad = b"OL/onion/aad/v1|" + eph_pub + b"|" + aad
    ct = AESGCM(key).encrypt(nonce, plaintext, full_aad)
    return eph_pub + nonce + ct


def _unwrap_one_hop(
    *, blob: bytes, my_x25519_priv: bytes, aad: bytes,
) -> bytes:
    if len(blob) < EPH_PUB_LEN + NONCE_LEN + 16:
        raise ValueError("hop blob too short")
    if len(blob) > MAX_ONION_LEN:
        raise ValueError(f"hop blob exceeds {MAX_ONION_LEN}")
    if len(my_x25519_priv) != 32:
        raise ValueError("my_x25519_priv must be 32 bytes")
    eph_pub = blob[:EPH_PUB_LEN]
    nonce = blob[EPH_PUB_LEN:EPH_PUB_LEN + NONCE_LEN]
    ct = blob[EPH_PUB_LEN + NONCE_LEN:]
    priv_obj = X25519PrivateKey.from_private_bytes(my_x25519_priv)
    try:
        shared = priv_obj.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    except Exception as e:
        raise ValueError(f"hop ECDH failed: {e}") from None
    if shared == b"\x00" * 32:
        raise ValueError("hop ECDH yielded zero shared secret")
    key = _derive_hop_key(shared)
    full_aad = b"OL/onion/aad/v1|" + eph_pub + b"|" + aad
    try:
        return AESGCM(key).decrypt(nonce, ct, full_aad)
    except Exception as e:
        raise ValueError(f"hop AEAD decrypt failed: {e}") from None


# ── public API ──────────────────────────────────────────────────────


def build_onion(
    *,
    body: bytes,
    path: list[HopKey],
    recipient_address: bytes,
    recipient_x25519_pub: bytes,
) -> bytes:
    """Wrap a payload in N+1 layers (N relays + 1 recipient).

    The sender hands the returned blob to ``path[0].address``. That
    relay decrypts its layer and forwards the inner blob to
    ``path[1].address``. Repeat until the last relay forwards to
    ``recipient_address``, which decrypts the innermost layer
    revealing ``body``.

    Raises ValueError if the path is empty, the recipient pub is
    malformed, or any wrapped layer would exceed ``MAX_ONION_LEN``.
    """
    if not path:
        raise ValueError(
            "path must contain at least one relay (use sealed_sender "
            "directly for zero-relay flows)"
        )
    if len(recipient_x25519_pub) != EPH_PUB_LEN:
        raise ValueError(
            f"recipient_x25519_pub must be {EPH_PUB_LEN} bytes"
        )
    if len(recipient_address) == 0 or len(recipient_address) > MAX_ADDR_LEN:
        raise ValueError(
            f"recipient_address must be 1..{MAX_ADDR_LEN} bytes"
        )

    # Innermost layer: body wrapped to recipient. The "next_addr"
    # at the recipient layer is empty (it's the terminal hop).
    layer = _wrap_one_hop(
        plaintext=_encode_layer(b"", body),
        hop_pub=recipient_x25519_pub,
        aad=b"recipient",
    )
    if len(layer) > MAX_ONION_LEN:
        raise ValueError(f"recipient layer exceeds {MAX_ONION_LEN}")

    # Wrap from the LAST relay (closest to recipient) outward to
    # the FIRST relay (closest to sender). Each layer's plaintext
    # is "the next-hop address + the inner already-encrypted blob".
    next_address = recipient_address
    for hop in reversed(path):
        layer = _wrap_one_hop(
            plaintext=_encode_layer(next_address, layer),
            hop_pub=hop.x25519_pub,
            aad=b"relay",
        )
        if len(layer) > MAX_ONION_LEN:
            raise ValueError(
                f"onion exceeds {MAX_ONION_LEN} bytes at hop {hop.address!r}"
            )
        next_address = hop.address
    return layer


@dataclass(frozen=True)
class HopUnwrap:
    next_address: bytes
    inner: bytes
    is_terminal: bool


def unwrap_relay_layer(
    *, blob: bytes, my_x25519_priv: bytes,
) -> HopUnwrap:
    """A relay calls this on a received onion blob. Returns the
    next-hop address + the still-encrypted inner blob to forward.

    If ``next_address`` is empty AND ``is_terminal`` is True, this
    relay is actually the recipient — call ``unwrap_recipient_layer``
    instead with the same blob. (We don't auto-detect because a
    relay normally can't tell if it's also the recipient; the
    caller decides based on its own role.)"""
    plaintext = _unwrap_one_hop(
        blob=blob, my_x25519_priv=my_x25519_priv, aad=b"relay",
    )
    next_addr, inner = _decode_layer(plaintext)
    return HopUnwrap(
        next_address=next_addr,
        inner=inner,
        is_terminal=False,
    )


def unwrap_recipient_layer(
    *, blob: bytes, my_x25519_priv: bytes,
) -> bytes:
    """The recipient unwraps the innermost layer to recover the
    body. The ``next_address`` at the recipient layer is always
    empty (the path stops here)."""
    plaintext = _unwrap_one_hop(
        blob=blob, my_x25519_priv=my_x25519_priv, aad=b"recipient",
    )
    next_addr, body = _decode_layer(plaintext)
    if next_addr != b"":
        raise ValueError(
            "recipient layer has non-empty next_address — not the "
            "innermost layer (caller may have routed prematurely)"
        )
    return body
