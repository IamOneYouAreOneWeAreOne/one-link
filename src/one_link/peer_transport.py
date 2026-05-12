"""Peer-transport facade — unified interface for WebRTC and QUIC.

The daemon owns one ``PeerTransport`` per peer. The facade exposes a
single ``send(payload: bytes)`` / ``recv(timeout_ms: int)`` surface;
the underlying transport (WebRTC datachannel via ``peer_rtc`` or QUIC
session via ``peer_quic``) is selected once at session-creation time
based on capability negotiation, then never changes for the lifetime
of the peer connection.

Why a facade rather than swap-in:

- The existing channel-layer code (``channel.send``,
  ``channel.recv``) treats the underlying transport as a bag of bytes.
  Adding QUIC alongside WebRTC means either (a) duplicating the
  channel layer per transport or (b) putting a thin facade between
  the channel and the wire. (b) is what this module is.
- The facade preserves ALL existing behaviour. WebRTC stays the
  default; v0.20.x peers never hit the QUIC code path; existing
  tests pass unchanged.
- Per-message routing is O(1): the facade caches the chosen transport
  on construction.

When the QUIC datapath eventually fully replaces WebRTC for
daemon↔daemon (per ``PHASE_A2_QUIC_CUTOVER_PLAN.md``), the facade's
WebRTC implementation is what we delete — every call site already
talks to the facade, so the migration is local.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional, Protocol

log = logging.getLogger(__name__)


class TransportSendError(RuntimeError):
    """Raised when the underlying transport cannot complete a send.
    Callers translate to higher-level retry / reconnect / drop-peer
    decisions."""


class TransportRecvError(RuntimeError):
    """Raised when recv() times out or the transport is closed by
    the remote."""


class PeerTransport(Protocol):
    """Common shape every transport implementation honours.

    Implementations:
    - ``WebRTCTransport`` wraps the existing peer_rtc datachannel.
    - ``QuicTransport`` wraps a ``QuicPeerSession`` from peer_quic.

    Methods are NOT required to be thread-safe in absolute terms;
    callers serialise per-peer at the daemon layer via existing
    per-peer locks."""

    @property
    def kind(self) -> str:
        """Either ``"webrtc"`` or ``"quic"``. Reported in telemetry."""
        ...

    def is_open(self) -> bool: ...

    def send_bytes(self, payload: bytes) -> None: ...

    def rtt_ms(self) -> Optional[float]: ...

    def close(self) -> None: ...


@dataclass
class TransportStats:
    """Per-transport telemetry. Bumped by the facade as bytes flow;
    surfaced via ``/api/metrics``."""

    bytes_sent: int = 0
    sends: int = 0
    send_failures: int = 0
    last_send_ns: int = 0
    transport_kind: str = "webrtc"


@dataclass
class WebRTCTransport:
    """Wraps the existing ``peer_rtc`` channel as a PeerTransport.

    The actual datachannel is owned by the daemon's existing channel
    object; this adapter forwards bytes through it.
    """

    channel: object
    """The peer's :class:`one_link.channel.Channel` instance."""

    stats: TransportStats = field(default_factory=TransportStats)

    def __post_init__(self) -> None:
        self.stats.transport_kind = "webrtc"

    @property
    def kind(self) -> str:
        return "webrtc"

    def is_open(self) -> bool:
        if self.channel is None:
            return False
        # Channel objects expose `is_closed` semantics differently
        # depending on transport state; treat absence of error as open.
        closed = getattr(self.channel, "_closed", False)
        return not closed

    def send_bytes(self, payload: bytes) -> None:
        if not self.is_open():
            self.stats.send_failures += 1
            raise TransportSendError("WebRTC channel closed")
        try:
            # Existing channel.send accepts pre-encoded bytes. The
            # facade does NOT re-encode; encoding happens upstream.
            import asyncio

            send_fn = getattr(self.channel, "send", None)
            if send_fn is None:
                raise TransportSendError("WebRTC channel has no send()")
            coro_or_none = send_fn(payload)
            # `send` may be sync or async. Tolerate both for stub
            # usage in tests; production uses awaitable returns.
            if asyncio.iscoroutine(coro_or_none):
                # Daemon hot path is async; if a caller invokes the
                # facade outside an event loop, this raises clearly.
                raise TransportSendError(
                    "channel.send() returned a coroutine; await it at "
                    "the daemon call site"
                )
        except TransportSendError:
            self.stats.send_failures += 1
            raise
        except Exception as e:
            self.stats.send_failures += 1
            raise TransportSendError(str(e)) from e
        self.stats.bytes_sent += len(payload)
        self.stats.sends += 1
        import time

        self.stats.last_send_ns = time.perf_counter_ns()

    def rtt_ms(self) -> Optional[float]:
        # WebRTC ICE candidates expose RTT via stats; the channel
        # surface doesn't currently propagate it. Returning None is
        # the safe default — callers that need RTT fall back to
        # daemon-level relay-metrics tracking.
        rtt = getattr(self.channel, "rtt_ms", None)
        if callable(rtt):
            try:
                v = rtt()
                return float(v) if v is not None else None
            except Exception:
                return None
        if isinstance(rtt, (int, float)):
            return float(rtt)
        return None

    def close(self) -> None:
        # WebRTC channels are owned by the daemon's session-tracker,
        # not the facade. Closing the facade is a no-op; the daemon
        # tears the channel down via its own lifecycle hooks.
        pass


@dataclass
class QuicTransport:
    """Wraps a :class:`one_link.peer_quic.QuicPeerSession`."""

    session: object
    """A QuicPeerSession from peer_quic.open_outbound()."""

    stats: TransportStats = field(default_factory=TransportStats)

    def __post_init__(self) -> None:
        self.stats.transport_kind = "quic"

    @property
    def kind(self) -> str:
        return "quic"

    def is_open(self) -> bool:
        if self.session is None:
            return False
        is_conn = getattr(self.session, "is_connected", None)
        return bool(is_conn()) if callable(is_conn) else False

    def send_bytes(self, payload: bytes) -> None:
        if not self.is_open():
            self.stats.send_failures += 1
            raise TransportSendError("QUIC session closed")
        # The ol_quic frame type used for generic message-layer bytes
        # — we encode an existing channel-layer message into a single
        # QUIC frame so the channel's message format stays intact.
        # FRAME_CHUNK_REQUEST is a generic carrier in the current
        # ol_quic wire spec; if a dedicated FRAME_MESSAGE lands, swap
        # the import here. The receiver dispatches by frame type, so
        # the choice of carrier matters only for cross-version compat.
        try:
            from one_link import peer_quic

            frame_type = peer_quic.FRAME_CHUNK_REQUEST  # generic carrier
            send_fn = getattr(self.session, "send_frame", None)
            if send_fn is None:
                raise TransportSendError("QUIC session has no send_frame()")
            send_fn(frame_type, payload)
        except TransportSendError:
            self.stats.send_failures += 1
            raise
        except Exception as e:
            self.stats.send_failures += 1
            raise TransportSendError(str(e)) from e
        self.stats.bytes_sent += len(payload)
        self.stats.sends += 1
        import time

        self.stats.last_send_ns = time.perf_counter_ns()

    def rtt_ms(self) -> Optional[float]:
        if not self.is_open():
            return None
        try:
            rtt = self.session.rtt_ms()  # type: ignore[attr-defined]
            return float(rtt) if rtt is not None else None
        except Exception:
            return None

    def close(self) -> None:
        if self.session is None:
            return
        try:
            close_fn = getattr(self.session, "close", None)
            if callable(close_fn):
                close_fn()
        except Exception:
            pass


def make_transport_for_peer(
    transport_kind: str,
    *,
    channel: Optional[object] = None,
    quic_session: Optional[object] = None,
) -> PeerTransport:
    """Build the facade for a given (kind, underlying) pair. Raises
    ``ValueError`` if the required underlying is missing for the
    requested kind."""
    if transport_kind == "webrtc":
        if channel is None:
            raise ValueError(
                "WebRTC transport requires a channel object"
            )
        return WebRTCTransport(channel=channel)
    if transport_kind == "quic":
        if quic_session is None:
            raise ValueError(
                "QUIC transport requires a QuicPeerSession"
            )
        return QuicTransport(session=quic_session)
    raise ValueError(
        f"unknown transport kind: {transport_kind!r} "
        "(expected 'webrtc' or 'quic')"
    )
