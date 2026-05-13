"""Adapter for the Sphinx Coherence onion-routing primitive
(`ol_onion::sphinx` via `one_link_native.sphinx`).

Per `One_link/native/ol_onion/SPHINX_COHERENCE_DESIGN.md`. Three
layers:

1. **Standard Sphinx (T1.1)**: Ristretto255 alpha blinding + filler-
   byte construction. Single packet-level ephemeral pubkey BLINDED
   at each hop so a global passive observer sees uncorrelated random
   group elements at every relay. ~165 us 3-hop build.

2. **PQ-hybrid (T1.2)**: ML-KEM-768 ciphertext addressed to the
   entry hop. The PQ-binding propagates downstream via the
   cumulative blinding chain, so a quantum adversary recording
   today cannot decrypt the alpha chain tomorrow.

3. **Field-bound (T1.3)**: derive_hop_keys_with_witness mixes the
   relay's coherence-field PDE state into the blinding factor.
   Daemon-side responsibility to source witnesses from
   `ol_coherence_field` (not exposed at this Python layer yet).

Sphinx packets are FIXED SIZE at every hop (~1305 bytes standard,
~2393 bytes PQ-hybrid) so a network observer cannot infer hop count
from packet length.

Typical daemon usage as sender:

.. code-block:: python

    from one_link import sphinx_native as sph

    eph_sk, _ = sph.generate_keypair()
    circuit = [
        (peer_a_id, peer_a_pubkey),  # first relay
        (peer_b_id, peer_b_pubkey),  # middle relay
        (dest_id, dest_pubkey),       # destination
    ]
    packet = sph.build_sphinx(eph_sk, circuit, payload=b"hello")
    # Send packet to peer_a over the transport.

As a relay:

.. code-block:: python

    outcome, next_hop_id, inner = sph.peel_sphinx(
        relay_sk=my_static_sk,
        packet=received_bytes,
    )
    if outcome == "forward":
        forward_to(next_hop_id, inner)
    elif outcome == "deliver":
        deliver(inner)
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple

log = logging.getLogger(__name__)

try:
    from one_link_native import sphinx as _native_sphinx  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    HOP_ID_LEN: int = _native_sphinx.HOP_ID_LEN
    MAX_HOPS: int = _native_sphinx.MAX_HOPS
    SPHINX_MAX_USER_PAYLOAD: int = _native_sphinx.SPHINX_MAX_USER_PAYLOAD
    SPHINX_PACKET_LEN: int = _native_sphinx.SPHINX_PACKET_LEN
    PQ_SPHINX_PACKET_LEN: int = _native_sphinx.PQ_SPHINX_PACKET_LEN
    ML_KEM_CT_LEN: int = _native_sphinx.ML_KEM_CT_LEN
    ML_KEM_EK_LEN: int = _native_sphinx.ML_KEM_EK_LEN
except ImportError as exc:
    HAS_NATIVE = False
    _native_sphinx = None  # type: ignore[assignment]
    HOP_ID_LEN = 32
    MAX_HOPS = 5
    SPHINX_MAX_USER_PAYLOAD = 1022
    SPHINX_PACKET_LEN = 1305
    PQ_SPHINX_PACKET_LEN = 2393
    ML_KEM_CT_LEN = 1088
    ML_KEM_EK_LEN = 1184
    log.info(
        "one_link_native.sphinx not installed (%s); Sphinx Coherence "
        "routing unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


class NativeMissingError(RuntimeError):
    """Raised when the native sphinx surface is not available."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise NativeMissingError(
            "one_link_native.sphinx unavailable; rebuild via "
            "`cd native && maturin develop --release`"
        )


# ── Standard Sphinx ─────────────────────────────────────────────


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Ristretto255 keypair. Returns (sk, pk) both 32 bytes."""
    _require_native()
    sk, pk = _native_sphinx.generate_keypair()
    return bytes(sk), bytes(pk)


def derive_pubkey_from_scalar(sk: bytes) -> bytes:
    """Derive the public Ristretto255 point from a 32-byte scalar."""
    _require_native()
    if len(sk) != 32:
        raise ValueError(f"sk must be 32 bytes, got {len(sk)}")
    return bytes(_native_sphinx.derive_pubkey_from_scalar(sk))


def build_sphinx(
    eph_sk: bytes, circuit: List[Tuple[bytes, bytes]], payload: bytes
) -> bytes:
    """Construct a standard Sphinx packet.

    `eph_sk`: 32-byte ephemeral Ristretto255 scalar (one per circuit).
    `circuit`: list of (hop_id_32, pubkey_32) tuples in circuit order.
    `payload`: up to `SPHINX_MAX_USER_PAYLOAD` bytes.

    Returns the fixed-size `SPHINX_PACKET_LEN` wire bytes the sender
    hands to `circuit[0]`.
    """
    _require_native()
    if len(eph_sk) != 32:
        raise ValueError(f"eph_sk must be 32 bytes, got {len(eph_sk)}")
    if not circuit:
        raise ValueError("circuit must have at least one hop")
    if len(circuit) > MAX_HOPS:
        raise ValueError(f"circuit has {len(circuit)} hops, max {MAX_HOPS}")
    if len(payload) > SPHINX_MAX_USER_PAYLOAD:
        raise ValueError(
            f"payload is {len(payload)} bytes, max {SPHINX_MAX_USER_PAYLOAD}"
        )
    return bytes(_native_sphinx.build_sphinx(eph_sk, circuit, payload))


def peel_sphinx(
    relay_sk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]:
    """Peel one Sphinx layer at this relay.

    Returns `(outcome, next_hop_id_or_empty, inner_or_payload)`:
    - "forward": forward `inner_or_payload` to `next_hop_id_or_empty`.
    - "deliver": this relay is the destination; `inner_or_payload`
      is the user payload.
    """
    _require_native()
    if len(relay_sk) != 32:
        raise ValueError(f"relay_sk must be 32 bytes, got {len(relay_sk)}")
    outcome, next_hop, inner = _native_sphinx.peel_sphinx(relay_sk, packet)
    return str(outcome), bytes(next_hop), bytes(inner)


# ── PQ-hybrid Sphinx ────────────────────────────────────────────


def generate_pq_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh ML-KEM-768 keypair. Returns (dk_2400, ek_1184)."""
    _require_native()
    dk, ek = _native_sphinx.generate_pq_keypair()
    return bytes(dk), bytes(ek)


def build_pq_sphinx(
    eph_sk: bytes,
    circuit: List[Tuple[bytes, bytes, Optional[bytes]]],
    payload: bytes,
) -> bytes:
    """Construct a PQ-hybrid Sphinx packet.

    `circuit`: list of (hop_id_32, x25519_pk_32, pq_pk_1184_or_None).
    The FIRST hop MUST supply a PQ pubkey; downstream hops MAY pass None.
    """
    _require_native()
    if len(eph_sk) != 32:
        raise ValueError(f"eph_sk must be 32 bytes, got {len(eph_sk)}")
    if not circuit:
        raise ValueError("circuit must have at least one hop")
    if len(circuit) > MAX_HOPS:
        raise ValueError(f"circuit has {len(circuit)} hops, max {MAX_HOPS}")
    if circuit[0][2] is None:
        raise ValueError("first hop must have a PQ pubkey")
    if len(payload) > SPHINX_MAX_USER_PAYLOAD:
        raise ValueError(
            f"payload is {len(payload)} bytes, max {SPHINX_MAX_USER_PAYLOAD}"
        )
    return bytes(_native_sphinx.build_pq_sphinx(eph_sk, circuit, payload))


def peel_pq_sphinx_entry(
    relay_x_sk: bytes, relay_pq_dk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]:
    """Peel a PQ-hybrid Sphinx packet at the ENTRY relay (decapsulates
    the carried ML-KEM ciphertext into the hybrid shared secret)."""
    _require_native()
    if len(relay_x_sk) != 32:
        raise ValueError(f"relay_x_sk must be 32 bytes, got {len(relay_x_sk)}")
    outcome, next_hop, inner = _native_sphinx.peel_pq_sphinx_entry(
        relay_x_sk, relay_pq_dk, packet
    )
    return str(outcome), bytes(next_hop), bytes(inner)


def peel_pq_sphinx_intermediate(
    relay_x_sk: bytes, packet: bytes
) -> Tuple[str, bytes, bytes]:
    """Peel a PQ-hybrid Sphinx packet at a downstream/intermediate
    relay (classical-only; ignores the carried PQ ciphertext)."""
    _require_native()
    if len(relay_x_sk) != 32:
        raise ValueError(f"relay_x_sk must be 32 bytes, got {len(relay_x_sk)}")
    outcome, next_hop, inner = _native_sphinx.peel_pq_sphinx_intermediate(
        relay_x_sk, packet
    )
    return str(outcome), bytes(next_hop), bytes(inner)


__all__ = [
    "HAS_NATIVE",
    "NativeMissingError",
    "generate_keypair",
    "derive_pubkey_from_scalar",
    "build_sphinx",
    "peel_sphinx",
    "generate_pq_keypair",
    "build_pq_sphinx",
    "peel_pq_sphinx_entry",
    "peel_pq_sphinx_intermediate",
    "HOP_ID_LEN",
    "MAX_HOPS",
    "SPHINX_MAX_USER_PAYLOAD",
    "SPHINX_PACKET_LEN",
    "PQ_SPHINX_PACKET_LEN",
    "ML_KEM_CT_LEN",
    "ML_KEM_EK_LEN",
]
