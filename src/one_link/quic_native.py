"""Adapter for the file-engine v2 native QUIC transport (ol_quic via one_link_native).

Per ADR-0009 + ADR-0010. Replaces the WebRTC/DTLS-SRTP daemon-to-daemon
transport with QUIC + identity-bound TLS. WebRTC stays for browser-as-peer.

Synchronous Python API; the underlying tokio runtime + async machinery
is hidden in the native crate. The runtime is single-instance per
process and lazy-initialized on first endpoint construction.

Usage:

    from one_link import quic_native

    if not quic_native.HAS_NATIVE:
        # Fall back to WebRTC for daemon-to-daemon during the migration.
        ...

    identity = quic_native.Identity.generate()
    config = quic_native.EndpointConfig(bind="127.0.0.1:0")

    # Server
    def is_paired(fingerprint: bytes) -> bool:
        return fingerprint in known_peers
    server = quic_native.Endpoint.server(identity, is_paired, config)
    conn = server.accept_blocking(timeout_ms=30_000)
    if conn is not None:
        stream_id, kind, payload = conn.recv_frame_blocking(timeout_ms=30_000)
        if kind == quic_native.FRAME_CHUNK_REQUEST:
            chunk_bytes = read_chunk(payload)
            conn.send_response_on(stream_id, quic_native.FRAME_CHUNK_RESPONSE, chunk_bytes)

    # Client
    client = quic_native.Endpoint.client(identity, config)
    conn = client.connect_blocking(addr, peer_fingerprint, timeout_ms=10_000)
    kind, payload = conn.send_frame_round_trip(quic_native.FRAME_PING, b"hello")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger(__name__)

try:
    from one_link_native import quic as _native_quic  # type: ignore[import-not-found]

    HAS_NATIVE: bool = True
except ImportError as exc:
    HAS_NATIVE = False
    _native_quic = None  # type: ignore[assignment]
    log.info(
        "one_link_native.quic unavailable (%s); daemon-to-daemon transport "
        "falls back to WebRTC. Build via "
        "`cd native && maturin develop --release` for Phase A2 QUIC.",
        exc,
    )


# Frame kind constants — surfaced from native at module-load time so
# downstream callers don't import directly from the pyo3 module.
if HAS_NATIVE:
    ALPN: bytes = _native_quic.ALPN
    MAX_BULK_FRAME_BYTES: int = _native_quic.MAX_BULK_FRAME_BYTES
    MAX_CONTROL_FRAME_BYTES: int = _native_quic.MAX_CONTROL_FRAME_BYTES
    FRAME_CHUNK_REQUEST: int = _native_quic.FRAME_CHUNK_REQUEST
    FRAME_CHUNK_RESPONSE: int = _native_quic.FRAME_CHUNK_RESPONSE
    FRAME_CHUNK_NOT_FOUND: int = _native_quic.FRAME_CHUNK_NOT_FOUND
    FRAME_MANIFEST_SYNC: int = _native_quic.FRAME_MANIFEST_SYNC
    FRAME_MANIFEST_RECORD: int = _native_quic.FRAME_MANIFEST_RECORD
    FRAME_MANIFEST_SYNC_END: int = _native_quic.FRAME_MANIFEST_SYNC_END
    FRAME_BLOOM_FILTER: int = _native_quic.FRAME_BLOOM_FILTER
    FRAME_MISSING_CHUNKS: int = _native_quic.FRAME_MISSING_CHUNKS
    FRAME_CAPABILITY_CHECK: int = _native_quic.FRAME_CAPABILITY_CHECK
    FRAME_CAPABILITY_ACK: int = _native_quic.FRAME_CAPABILITY_ACK
    FRAME_PING: int = _native_quic.FRAME_PING
    FRAME_PONG: int = _native_quic.FRAME_PONG
    FRAME_PROTO_ERROR: int = _native_quic.FRAME_PROTO_ERROR
    FRAME_CLOSE: int = _native_quic.FRAME_CLOSE
else:
    ALPN = b""
    MAX_BULK_FRAME_BYTES = 0
    MAX_CONTROL_FRAME_BYTES = 0
    FRAME_CHUNK_REQUEST = 0x01
    FRAME_CHUNK_RESPONSE = 0x02
    FRAME_CHUNK_NOT_FOUND = 0x03
    FRAME_MANIFEST_SYNC = 0x10
    FRAME_MANIFEST_RECORD = 0x11
    FRAME_MANIFEST_SYNC_END = 0x12
    FRAME_BLOOM_FILTER = 0x20
    FRAME_MISSING_CHUNKS = 0x21
    FRAME_CAPABILITY_CHECK = 0x30
    FRAME_CAPABILITY_ACK = 0x31
    FRAME_PING = 0xF0
    FRAME_PONG = 0xF1
    FRAME_PROTO_ERROR = 0xFE
    FRAME_CLOSE = 0xFF


@dataclass(frozen=True)
class QuicDiagnostics:
    """Snapshot of the QUIC subsystem state for /api/diagnostics surfaces."""

    native_available: bool
    alpn: Optional[bytes]
    max_bulk_frame_bytes: Optional[int]
    max_control_frame_bytes: Optional[int]


def diagnostics() -> QuicDiagnostics:
    return QuicDiagnostics(
        native_available=HAS_NATIVE,
        alpn=ALPN if HAS_NATIVE else None,
        max_bulk_frame_bytes=MAX_BULK_FRAME_BYTES if HAS_NATIVE else None,
        max_control_frame_bytes=MAX_CONTROL_FRAME_BYTES if HAS_NATIVE else None,
    )


# ─── Public API surfaces (passthroughs to native) ─────────────────────


def _require_native() -> None:
    if not HAS_NATIVE:
        raise RuntimeError(
            "one_link_native.quic is not installed; build via "
            "`cd native && maturin develop --release`"
        )


class Identity:
    """Ed25519 peer identity + self-signed cert per ADR-0010."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def generate(cls) -> "Identity":
        _require_native()
        return cls(_native_quic.Identity.generate())

    @classmethod
    def from_pkcs8_pem(cls, pem: str) -> "Identity":
        _require_native()
        return cls(_native_quic.Identity.from_pkcs8_pem(pem))

    @property
    def fingerprint(self) -> bytes:
        return self._inner.fingerprint

    @property
    def fingerprint_hex(self) -> str:
        return self._inner.fingerprint_hex

    @property
    def public_key_bytes(self) -> bytes:
        return self._inner.public_key_bytes

    def to_pkcs8_pem(self) -> str:
        return self._inner.to_pkcs8_pem()

    def __repr__(self) -> str:
        return repr(self._inner)


class EndpointConfig:
    """QUIC endpoint configuration."""

    __slots__ = ("_inner",)

    def __init__(
        self,
        *,
        bind: Optional[str] = None,
        idle_timeout_ms: Optional[int] = None,
        keepalive_interval_ms: Optional[int] = None,
        max_concurrent_bidi_streams: Optional[int] = None,
    ) -> None:
        _require_native()
        self._inner = _native_quic.EndpointConfig(
            bind=bind,
            idle_timeout_ms=idle_timeout_ms,
            keepalive_interval_ms=keepalive_interval_ms,
            max_concurrent_bidi_streams=max_concurrent_bidi_streams,
        )

    @property
    def bind(self) -> str:
        return self._inner.bind

    @property
    def idle_timeout_ms(self) -> int:
        return self._inner.idle_timeout_ms

    @property
    def keepalive_interval_ms(self) -> int:
        return self._inner.keepalive_interval_ms

    @property
    def max_concurrent_bidi_streams(self) -> int:
        return self._inner.max_concurrent_bidi_streams

    def __repr__(self) -> str:
        return repr(self._inner)


class Connection:
    """Active QUIC connection to a peer.

    Wrap, don't construct directly. Issued by [`Endpoint.connect_blocking`]
    or [`Endpoint.accept_blocking`].
    """

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @property
    def remote_address(self) -> str:
        return self._inner.remote_address

    @property
    def rtt_ms(self) -> int:
        return self._inner.rtt_ms

    def send_frame_round_trip(
        self, frame_kind: int, payload: bytes
    ) -> tuple[int, bytes]:
        """Open a stream, send a request frame, read the response frame.

        Returns ``(response_kind, response_payload)``.
        """
        return self._inner.send_frame_round_trip(frame_kind, payload)

    def recv_frame_blocking(
        self, timeout_ms: int
    ) -> Optional[tuple[int, int, bytes]]:
        """Server-side: accept the next inbound stream and read its first frame.

        Returns ``(stream_id, kind, payload)`` or ``None`` on timeout.
        Pass ``stream_id`` to :meth:`send_response_on` to reply.
        """
        return self._inner.recv_frame_blocking(timeout_ms)

    def send_response_on(
        self, stream_id: int, frame_kind: int, payload: bytes
    ) -> None:
        """Send the response frame on a stream returned by :meth:`recv_frame_blocking`."""
        self._inner.send_response_on(stream_id, frame_kind, payload)

    def close(self, error_code: int = 0, reason: bytes = b"") -> None:
        self._inner.close(error_code, reason)


class Endpoint:
    """Combined QUIC listener / dialer."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:
        self._inner = inner

    @classmethod
    def server(
        cls,
        identity: Identity,
        is_paired: Callable[[bytes], bool],
        config: Optional[EndpointConfig] = None,
    ) -> "Endpoint":
        _require_native()
        cfg = config if config is not None else EndpointConfig()
        return cls(_native_quic.Endpoint.server(identity._inner, is_paired, cfg._inner))

    @classmethod
    def client(
        cls,
        identity: Identity,
        config: Optional[EndpointConfig] = None,
    ) -> "Endpoint":
        _require_native()
        cfg = config if config is not None else EndpointConfig()
        return cls(_native_quic.Endpoint.client(identity._inner, cfg._inner))

    @property
    def local_addr(self) -> str:
        return self._inner.local_addr

    @property
    def fingerprint(self) -> bytes:
        return self._inner.fingerprint

    def connect_blocking(
        self,
        addr: str,
        expected_fingerprint: bytes,
        timeout_ms: int = 10_000,
    ) -> Connection:
        return Connection(
            self._inner.connect_blocking(addr, expected_fingerprint, timeout_ms)
        )

    def accept_blocking(self, timeout_ms: int = 30_000) -> Optional[Connection]:
        result = self._inner.accept_blocking(timeout_ms)
        if result is None:
            return None
        return Connection(result)

    def close(self, error_code: int = 0, reason: bytes = b"") -> None:
        self._inner.close(error_code, reason)
