"""Adapter for the row 7 pluggable-transport obfuscation primitive
(``ol_onion::transport_obfs`` via ``one_link_native``).

Per COHERENCE_MESH_PLAN.md row 7 — hardware-attested transport with
pluggable DPI-resistance. This module ships the FOUNDATION: a
ChaCha20 stream-cipher wrapper that makes wire bytes statistically
indistinguishable from random when the observer doesn't hold the
pre-shared key.

## What this is

- Length-preserving byte-wise XOR. Output length == input length.
- Symmetric: same op for obfuscate + deobfuscate.
- IND-CPA secure under ChaCha20.

## What this is NOT

- Not a full pluggable transport (obfs4 / Cloak / Snowflake).
  Those need a TLS-shaped handshake + protocol mimicry on top.
- Not authenticated. Apply BENEATH a layer that has its own MAC
  (Sphinx header_mac, AEAD, QUIC's TLS handshake) so a censor flipping
  bytes causes the upper layer to drop the packet.

## Usage

.. code-block:: python

    from one_link import obfs_native as obfs

    # Pre-shared key arrives via F2 pair-by-QR or out-of-band.
    key = derive_key_from_pair_chain(...)  # 32 bytes

    # Sender side: wrap every outbound packet.
    nonce = obfs.derive_nonce(conn_id=0xCAFE, packet_counter=seq)
    wire_bytes = obfs.obfuscate(key, nonce, packet_bytes)
    send(wire_bytes)

    # Receiver side: unwrap before handing to the upper layer.
    nonce = obfs.derive_nonce(conn_id=0xCAFE, packet_counter=seq)
    packet_bytes = obfs.deobfuscate(key, nonce, wire_bytes)
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from one_link_native import obfs as _native_obfs  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    OBFS_KEY_LEN: int = _native_obfs.OBFS_KEY_LEN
    OBFS_NONCE_LEN: int = _native_obfs.OBFS_NONCE_LEN
except ImportError as exc:
    HAS_NATIVE = False
    _native_obfs = None  # type: ignore[assignment]
    OBFS_KEY_LEN = 32
    OBFS_NONCE_LEN = 12
    log.info(
        "one_link_native.obfs not installed (%s); pluggable transport "
        "obfuscation unavailable. Build via "
        "`cd native && maturin develop --release`.",
        exc,
    )


class NativeMissingError(RuntimeError):
    """Raised when the native obfs surface is not available."""


def _require_native() -> None:
    if not HAS_NATIVE:
        raise NativeMissingError(
            "one_link_native.obfs unavailable; rebuild via "
            "`cd native && maturin develop --release`"
        )


def obfuscate(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Obfuscate `data` (length-preserving). Symmetric with `deobfuscate`."""
    _require_native()
    if len(key) != OBFS_KEY_LEN:
        raise ValueError(f"key must be {OBFS_KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != OBFS_NONCE_LEN:
        raise ValueError(
            f"nonce must be {OBFS_NONCE_LEN} bytes, got {len(nonce)}"
        )
    return bytes(_native_obfs.obfuscate(key, nonce, data))


def deobfuscate(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Deobfuscate `data`. Returns the original bytes."""
    _require_native()
    if len(key) != OBFS_KEY_LEN:
        raise ValueError(f"key must be {OBFS_KEY_LEN} bytes, got {len(key)}")
    if len(nonce) != OBFS_NONCE_LEN:
        raise ValueError(
            f"nonce must be {OBFS_NONCE_LEN} bytes, got {len(nonce)}"
        )
    return bytes(_native_obfs.deobfuscate(key, nonce, data))


def derive_nonce(conn_id: int, packet_counter: int) -> bytes:
    """Derive a 12-byte nonce from (conn_id, packet_counter). Use this
    rather than rolling your own to avoid (key, nonce) reuse."""
    _require_native()
    if not (0 <= conn_id < 2**32):
        raise ValueError("conn_id must fit in u32")
    if not (0 <= packet_counter < 2**64):
        raise ValueError("packet_counter must fit in u64")
    return bytes(_native_obfs.derive_nonce(conn_id, packet_counter))


__all__ = [
    "HAS_NATIVE",
    "NativeMissingError",
    "obfuscate",
    "deobfuscate",
    "derive_nonce",
    "OBFS_KEY_LEN",
    "OBFS_NONCE_LEN",
]
