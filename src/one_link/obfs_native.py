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


try:
    BRIDGE_PUBKEY_LEN: int = _native_obfs.BRIDGE_PUBKEY_LEN
    BRIDGE_SECRET_LEN: int = _native_obfs.BRIDGE_SECRET_LEN
    BRIDGE_ID_LEN: int = _native_obfs.BRIDGE_ID_LEN
    HANDSHAKE_LEN: int = _native_obfs.HANDSHAKE_LEN
    HANDSHAKE_MAC_LEN: int = _native_obfs.HANDSHAKE_MAC_LEN
    HANDSHAKE_EPOCH_SECS: int = _native_obfs.HANDSHAKE_EPOCH_SECS
    SESSION_KEY_LEN: int = _native_obfs.SESSION_KEY_LEN
except AttributeError:
    BRIDGE_PUBKEY_LEN = 32
    BRIDGE_SECRET_LEN = 32
    BRIDGE_ID_LEN = 32
    HANDSHAKE_LEN = 48
    HANDSHAKE_MAC_LEN = 16
    HANDSHAKE_EPOCH_SECS = 3600
    SESSION_KEY_LEN = 32


def generate_bridge_keypair() -> tuple[bytes, bytes, bytes]:
    """Generate a fresh bridge keypair.

    Returns ``(secret_32, public_32, id_32)``:
    - secret: store encrypted at rest (loss = bridge identity lost).
    - public: distribute to clients out-of-band (paper, QR, F2 pair).
    - id: distribute to clients out-of-band; bound into HMAC so probe
      attackers without it can't forge a handshake.
    """
    _require_native()
    sk, pk, bid = _native_obfs.generate_bridge_keypair()
    return bytes(sk), bytes(pk), bytes(bid)


class ClientHandshake:
    """Client side of the obfs4-style handshake.

    Typical flow:

    .. code-block:: python

        import time
        hs = ClientHandshake(bridge_public, bridge_id, now_unix=int(time.time()))
        # Send hs.first_message() to bridge over transport.
        # Receive reply.
        session = hs.finish(reply_bytes)
        # Now use session.seal_outbound / session.open_inbound for data.
    """

    def __init__(self, bridge_public: bytes, bridge_id: bytes, now_unix: int) -> None:
        _require_native()
        if len(bridge_public) != BRIDGE_PUBKEY_LEN:
            raise ValueError(
                f"bridge_public must be {BRIDGE_PUBKEY_LEN} bytes, got {len(bridge_public)}"
            )
        if len(bridge_id) != BRIDGE_ID_LEN:
            raise ValueError(
                f"bridge_id must be {BRIDGE_ID_LEN} bytes, got {len(bridge_id)}"
            )
        self._native = _native_obfs.ClientHandshake(
            bridge_public, bridge_id, int(now_unix)
        )

    def first_message(self) -> bytes:
        """The bytes the daemon transmits to the bridge."""
        return bytes(self._native.first_message())

    def finish(self, server_reply: bytes) -> "Session":
        """Complete the handshake using the bridge's reply.

        Raises ValueError if the MAC doesn't verify (wrong bridge_id,
        too-skewed epoch, tampered bytes, etc.).
        """
        native_session = self._native.finish(server_reply)
        return Session.__from_native__(native_session)


class Session:
    """Bidirectional obfuscation session derived from the handshake.

    Each direction (outbound / inbound) gets a distinct ChaCha20 key.
    The caller owns the per-direction packet counter and must ensure
    (key, nonce) pairs never repeat — counters MUST be strictly
    monotonic per direction.
    """

    def __init__(self) -> None:
        raise TypeError(
            "Session is constructed via ClientHandshake.finish() or "
            "server_accept(); do not instantiate directly"
        )

    @classmethod
    def __from_native__(cls, native_session: object) -> "Session":
        obj = object.__new__(cls)
        obj._native = native_session  # type: ignore[attr-defined]
        return obj

    def seal_outbound(self, plaintext: bytes, counter: int) -> bytes:
        return bytes(self._native.seal_outbound(plaintext, int(counter)))  # type: ignore[attr-defined]

    def open_inbound(self, ciphertext: bytes, counter: int) -> bytes:
        return bytes(self._native.open_inbound(ciphertext, int(counter)))  # type: ignore[attr-defined]

    def close(self) -> None:
        self._native.close()  # type: ignore[attr-defined]

    def is_open(self) -> bool:
        return bool(self._native.is_open())  # type: ignore[attr-defined]


def server_accept(
    bridge_secret: bytes,
    bridge_id: bytes,
    client_first_message: bytes,
    now_unix: int,
) -> tuple[bytes, Session]:
    """Server side of the obfs4-style handshake.

    The bridge calls this on every incoming first message. Returns
    ``(reply_bytes, session)``: ship reply_bytes back over the
    transport, then use `session` for all subsequent traffic.

    Raises ValueError if the client's MAC doesn't verify (wrong
    bridge_id, time skew > 2 epochs, tampered bytes).
    """
    _require_native()
    if len(bridge_secret) != BRIDGE_SECRET_LEN:
        raise ValueError(
            f"bridge_secret must be {BRIDGE_SECRET_LEN} bytes, got {len(bridge_secret)}"
        )
    if len(bridge_id) != BRIDGE_ID_LEN:
        raise ValueError(
            f"bridge_id must be {BRIDGE_ID_LEN} bytes, got {len(bridge_id)}"
        )
    reply, native_session = _native_obfs.server_accept(
        bridge_secret, bridge_id, client_first_message, int(now_unix)
    )
    return bytes(reply), Session.__from_native__(native_session)


__all__ = [
    "HAS_NATIVE",
    "NativeMissingError",
    "obfuscate",
    "deobfuscate",
    "derive_nonce",
    "generate_bridge_keypair",
    "ClientHandshake",
    "Session",
    "server_accept",
    "OBFS_KEY_LEN",
    "OBFS_NONCE_LEN",
    "BRIDGE_PUBKEY_LEN",
    "BRIDGE_SECRET_LEN",
    "BRIDGE_ID_LEN",
    "HANDSHAKE_LEN",
    "HANDSHAKE_MAC_LEN",
    "HANDSHAKE_EPOCH_SECS",
    "SESSION_KEY_LEN",
]
