"""Adapter for the Coherence Mesh F3 onion-packet primitive
(``ol_onion`` via ``one_link_native``).

This module exposes construction and one-layer peeling for bounded packets.
Each layer is ChaCha20-Poly1305 AEAD-sealed under a per-layer key derived from
one X25519 ECDH exchange. No active One Link daemon message or file route
imports this adapter, no relay-circuit control plane or mix network is deployed,
and repository presence is not evidence of sender anonymity or
traffic-analysis resistance. The static relay-key construction also is not
forward secret against later compromise of that relay key.

Primitive sender example (not current daemon wiring):

.. code-block:: python

    from one_link import onion_native as on

    # Each hop is (32-byte hop_id, 32-byte X25519 pubkey) tuple.
    circuit = [
        (peer_a_id, peer_a_pubkey),  # first relay
        (peer_b_id, peer_b_pubkey),  # middle relay
        (dest_id, dest_pubkey),       # destination
    ]
    packet_bytes = on.build_onion(circuit, payload=b"hello")
    # Send packet_bytes to peer_a over the existing transport.

Primitive relay example (not current daemon wiring):

.. code-block:: python

    outcome, next_hop_id, inner = on.peel_one_layer(
        relay_static_sk=my_x25519_secret,
        packet_bytes=received_bytes,
    )
    if outcome == "forward":
        # Forward inner to next_hop_id via the transport layer.
        forward_to(next_hop_id, inner)
    elif outcome == "deliver":
        # We're the destination; inner is the user payload.
        deliver(inner)
"""

from __future__ import annotations

import logging
from typing import List, Tuple

log = logging.getLogger(__name__)

try:
    from one_link_native import onion as _native_onion  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    MAX_HOPS: int = _native_onion.MAX_HOPS
    MAX_USER_PAYLOAD: int = _native_onion.MAX_USER_PAYLOAD
    HOP_ID_LEN: int = _native_onion.HOP_ID_LEN
    TRANSPORT_PAD_HINT: int = _native_onion.TRANSPORT_PAD_HINT
except ImportError as exc:
    HAS_NATIVE = False
    _native_onion = None  # type: ignore[assignment]
    MAX_HOPS = 5
    MAX_USER_PAYLOAD = 1024
    HOP_ID_LEN = 32
    TRANSPORT_PAD_HINT = 1280
    log.info(
        "one_link_native.onion not installed (%s); onion-circuit "
        "routing unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


class NativeMissingError(RuntimeError):
    """Raised when the native onion surface is not available."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise NativeMissingError(
            "one_link_native.onion unavailable; rebuild native crate "
            "via `cd native && maturin develop --release`"
        )


def build_onion(
    circuit: List[Tuple[bytes, bytes]], payload: bytes
) -> bytes:
    """Construct an onion packet for delivery along `circuit`.

    `circuit` is a list of `(hop_id_32_bytes, hop_pubkey_32_bytes)`
    tuples ordered from first relay to destination. The first hop in
    the list is the entry relay; the last is the destination.

    Returns the wire bytes of the outermost packet. The caller sends
    this to `circuit[0]` over the existing transport.
    """
    _require_native()
    if not circuit:
        raise ValueError("circuit must have at least one hop")
    if len(circuit) > MAX_HOPS:
        raise ValueError(
            f"circuit has {len(circuit)} hops, max {MAX_HOPS}"
        )
    if len(payload) > MAX_USER_PAYLOAD:
        raise ValueError(
            f"payload is {len(payload)} bytes, max {MAX_USER_PAYLOAD}"
        )
    return bytes(_native_onion.build_onion(circuit, payload))


def peel_one_layer(
    relay_static_sk: bytes, packet_bytes: bytes
) -> Tuple[str, bytes, bytes]:
    """Peel one layer of an onion packet at this relay.

    Returns `(outcome, next_hop_id_or_empty, inner_or_payload)`.

    - If `outcome == "forward"`: forward `inner_or_payload` to
      `next_hop_id_or_empty` via the transport.
    - If `outcome == "deliver"`: this relay is the destination;
      `inner_or_payload` is the user payload. `next_hop_id_or_empty`
      is `b""`.
    """
    _require_native()
    if len(relay_static_sk) != 32:
        raise ValueError(
            f"relay_static_sk must be 32 bytes, got {len(relay_static_sk)}"
        )
    outcome, next_hop, inner = _native_onion.peel_one_layer(
        relay_static_sk, packet_bytes
    )
    return str(outcome), bytes(next_hop), bytes(inner)


def pad_to_transport(packet_bytes: bytes, pad_seed: bytes) -> bytes:
    """Pad an onion packet to exactly TRANSPORT_PAD_HINT bytes.

    Trailing pad bytes are BLAKE3-derived from `pad_seed` (must be
    32 bytes; pass a fresh value per packet, e.g.,
    BLAKE3(circuit_id || packet_counter)).

    A future transport could send the padded bytes and let a receiving relay
    call `unpad_from_transport` before peeling. This establishes one encoded
    length for accepted packets only. It does not hide endpoints, route
    topology, direction, timing, counts, connection linkage, retransmission,
    or the fact that traffic exists, and it is not wired into a product route.
    """
    _require_native()
    if len(pad_seed) != 32:
        raise ValueError(
            f"pad_seed must be 32 bytes, got {len(pad_seed)}"
        )
    return bytes(_native_onion.pad_to_transport(packet_bytes, pad_seed))


def unpad_from_transport(padded_bytes: bytes) -> bytes:
    """Strip transport padding, returning the original onion packet
    wire bytes. Refuses non-padded-size input."""
    _require_native()
    if len(padded_bytes) != TRANSPORT_PAD_HINT:
        raise ValueError(
            f"padded_bytes must be {TRANSPORT_PAD_HINT} bytes, got "
            f"{len(padded_bytes)}"
        )
    return bytes(_native_onion.unpad_from_transport(padded_bytes))


def derive_pubkey(static_sk: bytes) -> bytes:
    """Compute the X25519 pubkey for a 32-byte static secret. Helper
    for daemons that need to publish their relay pubkey alongside
    their hop_id."""
    _require_native()
    if len(static_sk) != 32:
        raise ValueError(
            f"static_sk must be 32 bytes, got {len(static_sk)}"
        )
    return bytes(_native_onion.derive_pubkey(static_sk))


__all__ = [
    "HAS_NATIVE",
    "NativeMissingError",
    "build_onion",
    "peel_one_layer",
    "derive_pubkey",
    "pad_to_transport",
    "unpad_from_transport",
    "MAX_HOPS",
    "MAX_USER_PAYLOAD",
    "HOP_ID_LEN",
    "TRANSPORT_PAD_HINT",
]
