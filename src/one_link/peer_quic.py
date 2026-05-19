"""QUIC transport adapter — Phase A2 cutover.

Wraps ``one_link_native.quic`` (the ``ol_quic`` crate built on
``quinn``) with the same outbound/inbound shape as ``peer_rtc.py``,
so the daemon's transport-selection layer can route via either
WebRTC or QUIC without the call sites caring which.

Per [PHASE_A2_QUIC_CUTOVER_PLAN.md](../../docs/PHASE_A2_QUIC_CUTOVER_PLAN.md),
the cutover is **dual-stack**:

- WebRTC stays the always-working default.
- QUIC activates per-peer when both peers advertise ``QUIC_TRANSPORT_V1``.
- Browser-as-peer paths stay on WebRTC (browsers don't speak QUIC
  datagrams without WebTransport).
- v0.20.x daemons (no cap advertised) keep using WebRTC.

This module ships the **adapter** that the daemon's send/recv paths
will call when a peer is on the QUIC track. The transport-selection
logic itself lives in `daemon.py`'s `_choose_transport_for_peer`.

Threading model:
- Endpoint lives on the asyncio loop; the underlying ``quinn``
  runtime is wrapped via blocking calls (`*_blocking` suffix) that
  release the GIL during I/O.
- Per-peer ``Connection`` objects are owned by the daemon's peer
  table; the adapter does not retain global state.

Sovereignty: ``quinn`` is MIT/Apache, pure-Rust, no Microsoft. See
the sovereignty table in `FILE_ENGINE_V2_PLAN.md`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Protocol

log = logging.getLogger(__name__)


try:
    from one_link_native import quic as _native_quic  # type: ignore[import-not-found,attr-defined]

    HAS_NATIVE: bool = True
    NATIVE_VERSION: str | None = getattr(_native_quic, "__version__", None)
except ImportError as exc:
    HAS_NATIVE = False
    NATIVE_VERSION = None
    _native_quic = None  # type: ignore[assignment]
    log.info(
        "one_link_native.quic not installed (%s); QUIC transport unavailable. "
        "Daemon falls back to WebRTC for all peers.",
        exc,
    )


# Frame type constants — re-exported from the native module so the
# daemon's send/recv code paths don't have to import _native_quic
# directly (cleaner adapter boundary).
FRAME_CHUNK_REQUEST = getattr(_native_quic, "FRAME_CHUNK_REQUEST", None)
FRAME_CHUNK_RESPONSE = getattr(_native_quic, "FRAME_CHUNK_RESPONSE", None)
FRAME_CHUNK_NOT_FOUND = getattr(_native_quic, "FRAME_CHUNK_NOT_FOUND", None)
FRAME_BLOOM_FILTER = getattr(_native_quic, "FRAME_BLOOM_FILTER", None)
FRAME_MANIFEST_SYNC = getattr(_native_quic, "FRAME_MANIFEST_SYNC", None)
FRAME_MANIFEST_SYNC_END = getattr(_native_quic, "FRAME_MANIFEST_SYNC_END", None)
FRAME_MISSING_CHUNKS = getattr(_native_quic, "FRAME_MISSING_CHUNKS", None)
FRAME_PING = getattr(_native_quic, "FRAME_PING", None)
FRAME_PONG = getattr(_native_quic, "FRAME_PONG", None)
FRAME_CLOSE = getattr(_native_quic, "FRAME_CLOSE", None)


class PeerTransport(Protocol):
    """Common shape that both WebRTC and QUIC transport adapters
    implement. The daemon's send/recv paths target this protocol so
    they don't care which underlying transport carries a peer."""

    def is_connected(self) -> bool: ...

    def rtt_ms(self) -> Optional[float]: ...

    def send_frame(self, frame_type: int, payload: bytes) -> None: ...

    def close(self) -> None: ...


@dataclass
class QuicEndpointConfig:
    """Local QUIC endpoint configuration. Mirrors the subset of
    ``ol_quic::EndpointConfig`` the daemon actually drives at runtime."""

    bind_addr: str = "0.0.0.0:0"
    """Bind address. ``0.0.0.0:0`` picks an OS-assigned port; the
    daemon publishes the resulting port via mDNS / rendezvous."""

    keep_alive_interval_ms: int = 5_000
    """How often the endpoint sends a PING to detect dead peers.
    5s matches the field-snapshot tick so the per-peer state stays
    fresh."""

    max_idle_timeout_ms: int = 30_000
    """How long without traffic before the connection is considered
    dead. 30s is conservative enough to survive a cellular handoff."""


def _build_native_identity_from_pem(identity_pem: str):
    """Wave 2c: bridge from the daemon's Ed25519 Identity to the
    native ``ol_quic::Identity`` via PKCS#8 PEM. Returns the
    native Identity or raises if the native crate isn't usable.

    The PEM is loaded fresh on the native side; the daemon's
    in-memory Ed25519PrivateKey is never shared across the FFI
    boundary directly.
    """
    if not HAS_NATIVE or _native_quic is None:
        raise RuntimeError("one_link_native.quic not installed")
    return _native_quic.Identity.from_pkcs8_pem(identity_pem)


def _native_endpoint_config(cfg: QuicEndpointConfig):
    """Build a native ``ol_quic::EndpointConfig`` from our local
    dataclass. Keeps the daemon-facing API in pure Python while
    the native side keeps its own struct shape."""
    if not HAS_NATIVE or _native_quic is None:
        raise RuntimeError("one_link_native.quic not installed")
    return _native_quic.EndpointConfig(
        bind=cfg.bind_addr,
        keepalive_interval_ms=cfg.keep_alive_interval_ms,
        idle_timeout_ms=cfg.max_idle_timeout_ms,
    )


def make_server_endpoint(
    identity_pem: str,
    is_paired_callback,
    config: Optional[QuicEndpointConfig] = None,
):
    """Build a local QUIC server endpoint. Wave 2c — the Identity
    bridge that lit up the QUIC stack.

    Args:
        identity_pem: The daemon's Ed25519 private key encoded as
            PKCS#8 PEM. Same key that signs the WebRTC handshake.
        is_paired_callback: A function ``(fingerprint_bytes) -> bool``
            that the native endpoint calls during TLS to decide
            whether to admit an inbound connection. The daemon
            wires this to its PeerStore: pinned == accept.
        config: Optional ``QuicEndpointConfig``; defaults pick an
            OS-assigned port on ``0.0.0.0``.

    Returns:
        The native ``Endpoint`` instance (exposes
        ``accept_blocking``, ``local_addr``, ``close``, etc.), or
        ``None`` when the native crate isn't installed and the
        daemon should fall back to WebRTC.
    """
    if not HAS_NATIVE:
        return None
    cfg = config or QuicEndpointConfig()
    try:
        identity = _build_native_identity_from_pem(identity_pem)
        nat_cfg = _native_endpoint_config(cfg)
        return _native_quic.Endpoint.server(identity, is_paired_callback, nat_cfg)
    except Exception as e:
        log.warning(
            "QUIC server endpoint bring-up failed (%s); falling back to WebRTC",
            e,
        )
        return None


def make_client_endpoint(
    identity_pem: str,
    config: Optional[QuicEndpointConfig] = None,
):
    """Build a local QUIC client endpoint for outbound dials.
    Wave 2c counterpart to :func:`make_server_endpoint`.

    Unlike the server, a client endpoint doesn't need an
    is_paired callback — the daemon checks the peer's fingerprint
    against its own store before calling ``connect_blocking``.
    """
    if not HAS_NATIVE:
        return None
    cfg = config or QuicEndpointConfig()
    try:
        identity = _build_native_identity_from_pem(identity_pem)
        nat_cfg = _native_endpoint_config(cfg)
        return _native_quic.Endpoint.client(identity, nat_cfg)
    except Exception as e:
        log.warning(
            "QUIC client endpoint bring-up failed (%s); falling back to WebRTC",
            e,
        )
        return None


def make_endpoint(
    config: Optional[QuicEndpointConfig] = None,
) -> Optional[object]:
    """Legacy alias kept for backward-compat with existing
    call sites that don't yet pass an identity. Returns ``None`` —
    real endpoint construction goes through
    :func:`make_server_endpoint` / :func:`make_client_endpoint`,
    which Wave 2c added.
    """
    _ = config
    return None


class QuicPeerSession:
    """Per-peer QUIC transport state.

    Holds a single ``Connection`` (one QUIC stream multiplexes all
    frames per peer; multiplexing across multiple streams is a
    follow-up). Mirrors the API surface that the daemon's
    `_outbound_sessions` table expects.

    Thread-safe in the same sense as the underlying Connection:
    `send_frame` is single-writer; `recv_frame` is single-reader.
    The daemon's existing per-peer locking is sufficient.
    """

    def __init__(self, connection) -> None:
        self._conn = connection
        self._closed = False

    def is_connected(self) -> bool:
        return not self._closed and self._conn is not None

    def rtt_ms(self) -> Optional[float]:
        if not self.is_connected():
            return None
        try:
            return float(self._conn.rtt_ms())
        except Exception:
            return None

    def remote_address(self) -> Optional[str]:
        if not self.is_connected():
            return None
        try:
            return str(self._conn.remote_address())
        except Exception:
            return None

    def send_frame(self, frame_type: int, payload: bytes) -> bytes:
        """Send a frame + read the response. The QUIC stream is
        request/response per the existing ``ol_quic`` wire spec; for
        fire-and-forget frames (PING, CLOSE) the response is the
        canonical ACK.

        Returns the response payload. Raises if the connection is
        closed or the peer rejects the frame.
        """
        if not self.is_connected():
            raise RuntimeError("QuicPeerSession is closed")
        return bytes(self._conn.send_frame_round_trip(frame_type, payload))

    def recv_frame(self, timeout_ms: int = 5_000) -> tuple[int, bytes]:
        """Read one incoming frame from the peer-initiated direction.
        Returns ``(frame_type, payload)``.

        Raises ``one_link_native.OlQuicError`` on timeout / peer close.
        """
        if not self.is_connected():
            raise RuntimeError("QuicPeerSession is closed")
        # The native API returns a (frame_type: int, payload: bytes) tuple.
        return self._conn.recv_frame_blocking(timeout_ms)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._conn.close()
        except Exception:
            pass


def open_outbound(endpoint, remote_addr: str) -> Optional[QuicPeerSession]:
    """Dial a remote peer over QUIC. Returns ``None`` when the
    endpoint isn't initialised (no native crate) or the connection
    attempt fails — callers fall back to WebRTC."""
    if endpoint is None:
        return None
    try:
        conn = endpoint.connect_blocking(remote_addr)
        return QuicPeerSession(conn)
    except Exception as e:
        log.info("QUIC dial to %s failed (%s); caller should fall back", remote_addr, e)
        return None


def should_prefer_quic_for_peer(local_caps: tuple[str, ...], peer_caps: tuple[str, ...]) -> bool:
    """Transport-selection predicate. Both peers must advertise
    ``QUIC_TRANSPORT_V1`` for the daemon to choose QUIC over WebRTC.

    This is the single decision point — every other path that asks
    "which transport for peer P?" goes through here so the policy
    stays consistent.
    """
    from one_link.capabilities import QUIC_TRANSPORT_V1

    return QUIC_TRANSPORT_V1 in local_caps and QUIC_TRANSPORT_V1 in peer_caps


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "QUIC transport requires one_link_native.quic; not installed"
        )
