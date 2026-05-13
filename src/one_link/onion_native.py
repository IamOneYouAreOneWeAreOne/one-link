"""Adapter for the Coherence Mesh F3 onion-circuit primitive
(``ol_onion`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md row 5 — multi-hop onion routing where
each relay only knows its predecessor and successor. Each layer is
ChaCha20-Poly1305 AEAD-sealed under a per-layer key derived from
one X25519 ECDH exchange.

Typical daemon usage as sender:

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

Typical daemon usage as relay:

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
except ImportError as exc:
    HAS_NATIVE = False
    _native_onion = None  # type: ignore[assignment]
    MAX_HOPS = 5
    MAX_USER_PAYLOAD = 1024
    HOP_ID_LEN = 32
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
    "MAX_HOPS",
    "MAX_USER_PAYLOAD",
    "HOP_ID_LEN",
]
