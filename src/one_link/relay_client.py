"""Daemon-side encrypted-relay client.

Two roles, both wrapping aiohttp WebSockets:

  RelayListenerClient  — destination side. Persistently subscribed
                         to /api/v2/relay/listen. Demultiplexes
                         incoming connector sessions onto a callback,
                         each surfaced as a (StreamReader, StreamWriter)
                         pair so the existing One Link channel can
                         run on top of the relay-tunneled bytes
                         unchanged.

  open_relay_outbound  — source side. Returns a (StreamReader,
                         StreamWriter) pair that runs over a
                         WebSocket session against the destination's
                         registered listener. Caller hands those to
                         `channel.initiate(...)` and chats normally.

Design points
=============

  - The production relay wire carries a rotating pairwise routing tag,
    not either identity public key. Both sides authenticate with an
    epoch key derived from their already-paired identity agreement.
  - The identity-bearing channel HELLO and REPLY are each carried inside a
    bounded, versioned sealed-sender envelope. After that first flight, the
    channel's own AEAD protects every application frame.
  - Legacy public-key destination routes exist only behind an explicit
    mixed-version migration override; that path also retains the historical
    plaintext channel identity first flight and is reported as exposed.
  - All payload bytes are encrypted by the One Link channel above
    this transport. The relay forwards opaque bytes.
  - The "stream" abstraction is implemented via byte-bounded,
    ordered bridges.  Slow or failed WebSockets therefore apply real
    backpressure instead of accumulating an unbounded file in RAM.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections import deque
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Optional

import aiohttp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.relay_proto import (
    DATA_FRAME_MAX_BYTES,
    FRAME_CLOSE,
    FRAME_DATA,
    bounded_json_loads,
    decode_frame,
    encode_close_frame,
    encode_data_frame,
    parse_session_id_from_msg,
    sign_listen_auth,
)

log = logging.getLogger("one_link.relay_client")

DEFAULT_REQUEST_TIMEOUT_S = 10.0
RELAY_RECEIVE_DEADLINE_S = 5.0
RELAY_SEND_DEADLINE_S = 30.0

# A relay frame is at most 1 MiB.  Four frames in each inbound stage keeps
# enough work in flight to fill normal WAN paths while placing a hard ceiling
# on a stalled consumer.  Outbound channel queueing can produce multi-MiB
# encrypted records, so its ceiling is larger; Channel.queue_send uses the
# optional ``wait_writable`` hook below before each queued record.
RELAY_READER_BUFFER_LIMIT_BYTES = 4 * DATA_FRAME_MAX_BYTES
RELAY_INBOUND_QUEUE_LIMIT_BYTES = 4 * DATA_FRAME_MAX_BYTES
RELAY_INBOUND_QUEUE_MAX_ITEMS = 64
RELAY_OUTBOUND_BUFFER_LIMIT_BYTES = 32 * DATA_FRAME_MAX_BYTES
RELAY_OUTBOUND_QUEUE_MAX_ITEMS = 1024
RELAY_CONTROL_QUEUE_LIMIT_BYTES = 64 * 1024
RELAY_CONTROL_QUEUE_MAX_ITEMS = 64
RELAY_ROUTE_REFRESH_POLL_S = 5.0
# One listener can multiplex 32 sessions. Per-session ceilings alone would
# permit over 1 GiB of queued DATA. This shared ceiling accounts every byte in
# listener-side relay writer queues, inbound work queues, and reader buffers.
# During queue->reader ownership transfer there can be one transient copy per
# active session (at most 1 MiB each); steady-state adapter storage remains at
# or below this exact 64 MiB budget.
RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES = 64 * DATA_FRAME_MAX_BYTES
# Inbound DATA may use at most 44 MiB of that aggregate, leaving enough room
# for one maximum 16 MiB channel frame plus relay framing and ACK/control
# traffic. Otherwise full inbound buffers could prevent the ACK required to
# make the sender drain, creating a cross-direction deadlock.
RELAY_LISTENER_OUTBOUND_HEADROOM_BYTES = 20 * DATA_FRAME_MAX_BYTES
RELAY_LISTENER_MAX_ACTIVE_SESSIONS = 32

# The authenticated channel handshake contains each endpoint's Ed25519 public
# key before its ordinary channel AEAD exists.  Pairwise-blinded routing alone
# therefore is not enough to keep identities off the relay wire.  V2 relay
# streams seal exactly the first framed channel flight in each direction to
# the already-paired recipient.  Subsequent channel frames are already AEAD
# protected by channel.py and pass through unchanged.
SEALED_RELAY_HANDSHAKE_MAGIC = b"OLRH1"
_SEALED_RELAY_INIT_CONTEXT = b"OL/relay-handshake/initiator/v1\x00"
_SEALED_RELAY_RESPONSE_CONTEXT = b"OL/relay-handshake/responder/v1\x00"
SEALED_RELAY_HANDSHAKE_MAX_PLAINTEXT = 64 * 1024
# sealed_sender wire overhead: ephemeral X25519 key + nonce + inner version,
# sender key, timestamp, signature, and AES-GCM tag.
_SEALED_SENDER_WIRE_OVERHEAD = 32 + 12 + 1 + 32 + 8 + 64 + 16


class _SharedByteBudget:
    """Event-loop-local byte semaphore with synchronous release/reserve."""

    def __init__(self, limit_bytes: int):
        if limit_bytes < DATA_FRAME_MAX_BYTES + 9:
            raise ValueError("relay shared budget must hold at least one maximum DATA frame")
        self.limit_bytes = int(limit_bytes)
        self.used_bytes = 0
        self.peak_bytes = 0
        self._used_by_owner: dict[object | None, int] = {}
        self._changed = asyncio.Event()

    def try_reserve(
        self,
        size: int,
        *,
        headroom_bytes: int = 0,
        owner: object | None = None,
    ) -> bool:
        usable_limit = self.limit_bytes - int(headroom_bytes)
        if size < 0 or size > usable_limit:
            return False
        if self.used_bytes + size > usable_limit:
            return False
        self.used_bytes += size
        self._used_by_owner[owner] = self._used_by_owner.get(owner, 0) + size
        self.peak_bytes = max(self.peak_bytes, self.used_bytes)
        return True

    async def reserve(
        self,
        size: int,
        *,
        headroom_bytes: int = 0,
        owner: object | None = None,
    ) -> None:
        usable_limit = self.limit_bytes - int(headroom_bytes)
        if size < 0 or size > usable_limit:
            raise BufferError(f"relay item exceeds shared byte budget: {size} > {usable_limit}")
        while not self.try_reserve(
            size,
            headroom_bytes=headroom_bytes,
            owner=owner,
        ):
            # No await can interleave between the failed reservation and
            # clear(), so a release notification cannot be lost here.
            self._changed.clear()
            await self._changed.wait()

    def release_nowait(self, size: int, *, owner: object | None = None) -> None:
        if size < 0 or size > self.used_bytes:
            raise RuntimeError(
                "relay shared byte-budget accounting underflow: "
                f"release={size} used={self.used_bytes}"
            )
        owner_used = self._used_by_owner.get(owner, 0)
        if size > owner_used:
            raise RuntimeError(
                "relay shared byte-budget owner accounting underflow: "
                f"release={size} owner_used={owner_used}"
            )
        self.used_bytes -= size
        remaining = owner_used - size
        if remaining:
            self._used_by_owner[owner] = remaining
        else:
            self._used_by_owner.pop(owner, None)
        self._changed.set()

    def used_by(self, owner: object | None) -> int:
        """Return exact currently-reserved bytes for one session owner."""
        return self._used_by_owner.get(owner, 0)


# ─── stream bridge over WebSocket ──────────────────────────────────


class _RelayStreamReader:
    """Adapter that lets ch.initiate / ch.respond's StreamReader
    interface read bytes that the WebSocket sends us via push.

    asyncio.StreamReader-compatible: implements `read(n)`,
    `readexactly(n)`, and the IncompleteReadError on EOF."""

    def __init__(
        self,
        *,
        buffer_limit_bytes: int = RELAY_READER_BUFFER_LIMIT_BYTES,
        shared_budget: _SharedByteBudget | None = None,
        shared_budget_headroom_bytes: int = 0,
        shared_budget_owner: object | None = None,
    ):
        if buffer_limit_bytes < DATA_FRAME_MAX_BYTES:
            raise ValueError("relay reader buffer must hold at least one maximum DATA frame")
        self._buf = bytearray()
        self._eof = False
        self._buffer_limit_bytes = int(buffer_limit_bytes)
        self._shared_budget = shared_budget
        self._shared_budget_headroom_bytes = int(shared_budget_headroom_bytes)
        self._shared_budget_owner = shared_budget_owner
        self._cond = asyncio.Condition()

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        async with self._cond:
            while not self._buf and not self._eof:
                await self._cond.wait()
            if n == -1 or n >= len(self._buf):
                out = bytes(self._buf)
                self._buf.clear()
                self._cond.notify_all()
                if self._shared_budget is not None:
                    self._shared_budget.release_nowait(
                        len(out),
                        owner=self._shared_budget_owner,
                    )
                return out
            out = bytes(self._buf[:n])
            del self._buf[:n]
            self._cond.notify_all()
            if self._shared_budget is not None:
                self._shared_budget.release_nowait(
                    len(out),
                    owner=self._shared_budget_owner,
                )
            return out

    async def readexactly(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            async with self._cond:
                while not self._buf and not self._eof:
                    await self._cond.wait()
                if self._eof and not self._buf:
                    raise asyncio.IncompleteReadError(bytes(out), n)
                take = min(n - len(out), len(self._buf))
                out.extend(self._buf[:take])
                del self._buf[:take]
                self._cond.notify_all()
                if self._shared_budget is not None:
                    self._shared_budget.release_nowait(
                        take,
                        owner=self._shared_budget_owner,
                    )
        return bytes(out)

    async def feed(
        self,
        data: bytes,
        *,
        budget_reserved: bool = False,
    ) -> None:
        if not data:
            return
        if len(data) > self._buffer_limit_bytes:
            raise ValueError(
                f"relay reader item exceeds byte limit: {len(data)} > {self._buffer_limit_bytes}"
            )
        if budget_reserved and self._shared_budget is None:
            raise RuntimeError("reserved reader feed requires a shared budget")
        acquired_here = False
        token_held = budget_reserved
        try:
            while True:
                async with self._cond:
                    while not self._eof and len(self._buf) + len(data) > self._buffer_limit_bytes:
                        await self._cond.wait()
                    if self._eof:
                        raise ConnectionError("cannot feed a closed relay reader")
                    if token_held or self._shared_budget is None:
                        self._buf.extend(data)
                        self._cond.notify_all()
                        return
                # Never await the aggregate budget while holding _cond: a
                # reader must remain able to consume existing bytes that may
                # be the only way this reservation becomes available.
                shared_budget = self._shared_budget
                if shared_budget is None:
                    raise RuntimeError("relay reader shared-budget invariant failed")
                await shared_budget.reserve(
                    len(data),
                    headroom_bytes=self._shared_budget_headroom_bytes,
                    owner=self._shared_budget_owner,
                )
                token_held = True
                acquired_here = True
        except BaseException:
            if acquired_here and self._shared_budget is not None:
                self._shared_budget.release_nowait(
                    len(data),
                    owner=self._shared_budget_owner,
                )
            raise

    async def feed_eof(self) -> None:
        async with self._cond:
            self._eof = True
            self._cond.notify_all()

    async def abort(self) -> None:
        """Discard buffered bytes and wake readers during session teardown."""
        async with self._cond:
            discarded = len(self._buf)
            self._buf.clear()
            self._eof = True
            self._cond.notify_all()
        if discarded and self._shared_budget is not None:
            self._shared_budget.release_nowait(
                discarded,
                owner=self._shared_budget_owner,
            )

    def at_eof(self) -> bool:
        return self._eof and not self._buf

    @property
    def buffered_bytes(self) -> int:
        return len(self._buf)


@dataclass(frozen=True)
class _OutboundItem:
    sequence: int
    frame: bytes
    accounted_bytes: int
    close_after: bool = False


class RelayTransportError(ConnectionError):
    """Sticky terminal failure in a relay-backed stream."""


class _RelayStreamWriter:
    """Adapter that emits StreamWriter.write+drain semantics by
    sending DATA frames over a shared WebSocket. close() emits a
    CLOSE frame and stops the session.

    Ordering: writes go through a single asyncio.Queue drained by
    one background task, so frames hit the wire in the same order
    as the .write() calls. Without this, multiple write() calls
    would race via independently-scheduled tasks and the encrypted
    channel above would see corrupted bytes.
    """

    def __init__(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        session_id: bytes,
        on_close: Optional[Callable[[], Awaitable[None]]] = None,
        *,
        buffer_limit_bytes: int = RELAY_OUTBOUND_BUFFER_LIMIT_BYTES,
        send_deadline_s: float = RELAY_SEND_DEADLINE_S,
        queue_max_items: int = RELAY_OUTBOUND_QUEUE_MAX_ITEMS,
        shared_budget: _SharedByteBudget | None = None,
        shared_budget_owner: object | None = None,
    ):
        if buffer_limit_bytes < DATA_FRAME_MAX_BYTES + 9:
            raise ValueError("relay outbound buffer must hold at least one maximum DATA frame")
        if send_deadline_s <= 0:
            raise ValueError("relay send deadline must be positive")
        if queue_max_items < 2:
            raise ValueError("relay outbound queue must have at least two slots")
        self._ws = ws
        self._session_id = session_id
        self._on_close = on_close
        self._buffer_limit_bytes = int(buffer_limit_bytes)
        self._send_deadline_s = float(send_deadline_s)
        self._queue_max_items = int(queue_max_items)
        self._shared_budget = shared_budget
        self._shared_budget_owner = shared_budget_owner
        # Reserve one queue slot for CLOSE so close() is deterministic even
        # when data has filled every permitted data slot.
        self._data_queue_max_items = self._queue_max_items - 1
        self._pending_bytes = 0
        self._reserved_bytes = 0
        self._reserved_items = 0
        self._write_reservations: deque[tuple[int, int]] = deque()
        self._enqueued_sequence = 0
        self._completed_sequence = 0
        self._terminal_exc: BaseException | None = None
        self._closing = False
        self._closed = False
        self._close_callback_ran = False
        self._state_changed = asyncio.Condition()
        self._send_queue: asyncio.Queue[_OutboundItem] = asyncio.Queue(
            maxsize=self._queue_max_items
        )
        self._sender_task: asyncio.Task = asyncio.create_task(self._sender_loop())

    async def _sender_loop(self) -> None:
        current: _OutboundItem | None = None
        try:
            while True:
                current = await self._send_queue.get()
                try:
                    await asyncio.wait_for(
                        self._ws.send_bytes(current.frame),
                        timeout=self._send_deadline_s,
                    )
                except Exception as exc:
                    self._remember_terminal(
                        RelayTransportError(
                            "relay WebSocket send failed at outbound item "
                            f"{current.sequence}: {type(exc).__name__}: {exc}"
                        ),
                        cause=exc,
                    )
                    break

                async with self._state_changed:
                    self._pending_bytes -= current.accounted_bytes
                    self._completed_sequence = current.sequence
                    self._state_changed.notify_all()
                self._release_shared_item(current.accounted_bytes)
                self._send_queue.task_done()
                close_after = current.close_after
                current = None
                if close_after:
                    break
        except asyncio.CancelledError as exc:
            if self._terminal_exc is None:
                self._remember_terminal(
                    RelayTransportError("relay outbound sender was cancelled"),
                    cause=exc,
                )
        finally:
            # The current item and all queued items remain included in
            # _pending_bytes until this terminal cleanup.  Drop references
            # promptly so a failed 385 MiB transfer cannot linger in memory.
            if current is not None:
                self._pending_bytes -= current.accounted_bytes
                self._release_shared_item(current.accounted_bytes)
                self._send_queue.task_done()
            while True:
                try:
                    abandoned = self._send_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._pending_bytes -= abandoned.accounted_bytes
                self._release_shared_item(abandoned.accounted_bytes)
                self._send_queue.task_done()
            self._release_unused_reservations()
            self._pending_bytes = max(0, self._pending_bytes)
            self._closed = True
            async with self._state_changed:
                self._state_changed.notify_all()
            await self._run_close_callback_once()

    def _remember_terminal(
        self,
        exc: BaseException,
        *,
        cause: BaseException | None = None,
    ) -> None:
        if self._terminal_exc is not None:
            return
        if cause is not None:
            exc.__cause__ = cause
        self._terminal_exc = exc
        self._closing = True

    def _release_shared_item(self, size: int) -> None:
        if size and self._shared_budget is not None:
            self._shared_budget.release_nowait(
                size,
                owner=self._shared_budget_owner,
            )

    def _release_unused_reservations(self) -> None:
        if self._shared_budget is not None and self._reserved_bytes:
            self._shared_budget.release_nowait(
                self._reserved_bytes,
                owner=self._shared_budget_owner,
            )
        self._write_reservations.clear()
        self._reserved_bytes = 0
        self._reserved_items = 0

    async def _run_close_callback_once(self) -> None:
        if self._close_callback_ran:
            return
        self._close_callback_ran = True
        if self._on_close is None:
            return
        try:
            await asyncio.wait_for(self._on_close(), timeout=self._send_deadline_s)
        except Exception as exc:
            log.debug("relay close callback failed: %s", exc, exc_info=True)

    @staticmethod
    def _encoded_size_for_stream_bytes(size: int) -> tuple[int, int]:
        if size < 0:
            raise ValueError("relay write size cannot be negative")
        if size == 0:
            return 0, 0
        frames = (size + DATA_FRAME_MAX_BYTES - 1) // DATA_FRAME_MAX_BYTES
        return size + frames * 9, frames

    def _raise_if_terminal(self) -> None:
        if self._terminal_exc is not None:
            raise self._terminal_exc

    async def wait_writable(self, size: int) -> None:
        """Wait until a subsequent ``write(size bytes)`` fits exactly.

        This optional, duck-typed hook is used by Channel.queue_send before
        its synchronous StreamWriter.write call.  Ordinary StreamWriter
        implementations do not expose it and continue unchanged.
        """
        accounted, frame_count = self._encoded_size_for_stream_bytes(size)
        if accounted > self._buffer_limit_bytes:
            raise BufferError(
                "single relay write exceeds outbound byte limit: "
                f"{accounted} > {self._buffer_limit_bytes}"
            )
        if frame_count > self._data_queue_max_items:
            raise BufferError(
                "single relay write exceeds outbound item limit: "
                f"{frame_count} > {self._data_queue_max_items}"
            )
        while True:
            async with self._state_changed:
                self._raise_if_terminal()
                if self._closing:
                    raise ConnectionError("relay stream is closing")
                if (
                    self._pending_bytes + self._reserved_bytes + accounted
                    > self._buffer_limit_bytes
                    or self._send_queue.qsize() + self._reserved_items + frame_count
                    > self._data_queue_max_items
                ):
                    await self._state_changed.wait()
                    continue
                if self._shared_budget is None:
                    self._write_reservations.append((accounted, frame_count))
                    self._reserved_bytes += accounted
                    self._reserved_items += frame_count
                    return
            await self._shared_budget.reserve(
                accounted,
                owner=self._shared_budget_owner,
            )
            shared_token_held = True
            try:
                async with self._state_changed:
                    self._raise_if_terminal()
                    if self._closing:
                        raise ConnectionError("relay stream is closing")
                    # Another task on this same writer may have consumed local
                    # capacity while we waited for the listener-wide budget.
                    # Release and retry instead of exposing BufferError to a
                    # caller that correctly awaited wait_writable().
                    if (
                        self._pending_bytes + self._reserved_bytes + accounted
                        > self._buffer_limit_bytes
                        or self._send_queue.qsize() + self._reserved_items + frame_count
                        > self._data_queue_max_items
                    ):
                        self._shared_budget.release_nowait(
                            accounted,
                            owner=self._shared_budget_owner,
                        )
                        shared_token_held = False
                        continue
                    self._write_reservations.append((accounted, frame_count))
                    self._reserved_bytes += accounted
                    self._reserved_items += frame_count
                    shared_token_held = False  # reservation owns it now
                    return
            except BaseException:
                if shared_token_held:
                    self._shared_budget.release_nowait(
                        accounted,
                        owner=self._shared_budget_owner,
                    )
                raise

    def write(self, data: bytes) -> None:
        self._raise_if_terminal()
        if self._closing or self._closed:
            raise ConnectionError("cannot write to a closed relay stream")
        if not data:
            return
        # Chunk to DATA_FRAME_MAX_BYTES so a >1 MB write doesn't blow
        # the WS frame budget. Each chunk is enqueued in order.
        view = memoryview(data)
        frames = [
            encode_data_frame(
                self._session_id,
                bytes(view[i : i + DATA_FRAME_MAX_BYTES]),
            )
            for i in range(0, len(view), DATA_FRAME_MAX_BYTES)
        ]
        accounted = sum(len(frame) for frame in frames)
        reserved = bool(
            self._write_reservations and self._write_reservations[0] == (accounted, len(frames))
        )
        if self._write_reservations and not reserved:
            raise RuntimeError("relay write does not match the preceding wait_writable size")
        if reserved:
            self._write_reservations.popleft()
            self._reserved_bytes -= accounted
            self._reserved_items -= len(frames)
        elif (
            self._pending_bytes + self._reserved_bytes + accounted > self._buffer_limit_bytes
            or self._send_queue.qsize() + self._reserved_items + len(frames)
            > self._data_queue_max_items
        ):
            raise BufferError(
                "relay outbound buffer full; await wait_writable()/drain() before writing more"
            )
        elif self._shared_budget is not None and not self._shared_budget.try_reserve(
            accounted,
            owner=self._shared_budget_owner,
        ):
            raise BufferError(
                "relay listener aggregate buffer full; await "
                "wait_writable()/drain() before writing more"
            )
        # No await occurs between the capacity check and these put_nowait
        # calls, so the reservation is atomic on the event-loop thread.
        self._pending_bytes += accounted
        for frame in frames:
            self._enqueued_sequence += 1
            self._send_queue.put_nowait(
                _OutboundItem(
                    sequence=self._enqueued_sequence,
                    frame=frame,
                    accounted_bytes=len(frame),
                )
            )

    async def drain(self) -> None:
        # Sequence capture is a real barrier: success means every item that
        # preceded this call completed ws.send_bytes, not merely that the
        # sender task got a scheduling turn.
        target = self._enqueued_sequence
        async with self._state_changed:
            while self._completed_sequence < target and self._terminal_exc is None:
                await self._state_changed.wait()
            self._raise_if_terminal()

    def close(self) -> None:
        self._raise_if_terminal()
        if self._closing or self._closed:
            return
        self._closing = True
        self._release_unused_reservations()
        self._enqueued_sequence += 1
        # One queue slot is reserved exclusively for this close item.
        self._send_queue.put_nowait(
            _OutboundItem(
                sequence=self._enqueued_sequence,
                frame=encode_close_frame(self._session_id),
                accounted_bytes=0,
                close_after=True,
            )
        )

    async def abort(self, exc: BaseException | None = None) -> None:
        """Fail the stream now and wake every blocked writer/drain."""
        if not self._closed and self._terminal_exc is None:
            terminal = exc or RelayTransportError("relay stream aborted")
            if not isinstance(terminal, RelayTransportError):
                wrapped = RelayTransportError(
                    f"relay stream aborted: {type(terminal).__name__}: {terminal}"
                )
                self._remember_terminal(wrapped, cause=terminal)
            else:
                self._remember_terminal(terminal)
        async with self._state_changed:
            self._state_changed.notify_all()
        if not self._sender_task.done():
            self._sender_task.cancel()
            with contextlib.suppress(BaseException):
                await self._sender_task

    async def wait_closed(self) -> None:
        # Deterministic: CLOSE is transmitted after all prior DATA and the
        # cleanup callback finishes before this returns.
        await self._sender_task
        self._raise_if_terminal()

    def is_closing(self) -> bool:
        return self._closing or self._closed

    @property
    def pending_bytes(self) -> int:
        return self._pending_bytes

    def get_extra_info(self, name: str, default=None):
        # ch.respond reads "peername" for diagnostics — return a
        # synthetic shape so it doesn't blow up.
        if name == "peername":
            return ("relay", 0)
        return default


@dataclass
class _SealedHandshakeState:
    """Peer authority learned before the responder emits its first flight."""

    peer_public_key: bytes | None = None


def _validate_complete_channel_frame(data: bytes, *, name: str) -> None:
    if not isinstance(data, bytes):
        raise ValueError(f"{name} must be bytes")
    if len(data) < 4:
        raise ValueError(f"{name} is missing its channel length prefix")
    payload_size = int.from_bytes(data[:4], "big")
    if payload_size > SEALED_RELAY_HANDSHAKE_MAX_PLAINTEXT - 4:
        raise ValueError(
            f"{name} exceeds the {SEALED_RELAY_HANDSHAKE_MAX_PLAINTEXT}-byte "
            "sealed relay handshake bound"
        )
    if payload_size + 4 != len(data):
        raise ValueError(f"{name} must contain exactly one complete channel frame")


def _sealed_handshake_framed_size(plaintext_size: int, context_size: int) -> int:
    if plaintext_size < 0:
        raise ValueError("sealed relay handshake size cannot be negative")
    return (
        4
        + len(SEALED_RELAY_HANDSHAKE_MAGIC)
        + _SEALED_SENDER_WIRE_OVERHEAD
        + context_size
        + plaintext_size
    )


class _SealedRelayHandshakeReader:
    """Unseal exactly one identity-bearing channel flight, then pass through.

    The relay-facing stream contains a version marker and a sealed-sender
    envelope.  The channel-facing stream receives the original length-prefixed
    HELLO/REPLY bytes, so channel.py retains its existing transcript and
    authentication semantics.  The sender identity is accepted only from the
    live paired-peer authority supplied by the daemon.
    """

    def __init__(
        self,
        underlying: _RelayStreamReader,
        *,
        local_private_key: Ed25519PrivateKey,
        paired_peer_pubkeys_provider: Callable[[], Iterable[bytes]],
        state: _SealedHandshakeState,
        expected_context: bytes,
    ) -> None:
        if not isinstance(local_private_key, Ed25519PrivateKey):
            raise ValueError("sealed relay reader requires an Ed25519 private key")
        if not expected_context:
            raise ValueError("sealed relay handshake context must not be empty")
        self._underlying = underlying
        self._local_private_seed = local_private_key.private_bytes_raw()
        self._paired_peer_pubkeys_provider = paired_peer_pubkeys_provider
        self._state = state
        self._expected_context = bytes(expected_context)
        self._first_plaintext = bytearray()
        self._first_loaded = False
        self._first_load_lock = asyncio.Lock()

    def _paired_peer_pubkeys(self) -> tuple[bytes, ...]:
        peers: list[bytes] = []
        seen: set[bytes] = set()
        for value in self._paired_peer_pubkeys_provider():
            if not isinstance(value, bytes) or len(value) != 32:
                raise ValueError("sealed relay paired authority must contain 32-byte keys")
            if value in seen:
                continue
            seen.add(value)
            peers.append(value)
        if not peers:
            raise ValueError("sealed relay handshake has no paired peer authority")
        # Match relay_routing.MAX_PAIRED_ROUTE_PEERS without importing that
        # module on every stream read.
        if len(peers) > 256:
            raise ValueError("sealed relay paired authority exceeds 256 peers")
        return tuple(peers)

    async def _load_first(self) -> None:
        if self._first_loaded:
            return
        async with self._first_load_lock:
            if self._first_loaded:
                return
            header = await self._underlying.readexactly(4)
            outer_size = int.from_bytes(header, "big")
            max_outer = _sealed_handshake_framed_size(
                SEALED_RELAY_HANDSHAKE_MAX_PLAINTEXT,
                len(self._expected_context),
            ) - 4
            min_outer = len(SEALED_RELAY_HANDSHAKE_MAGIC) + _SEALED_SENDER_WIRE_OVERHEAD
            if not min_outer <= outer_size <= max_outer:
                raise ValueError("sealed relay handshake envelope has an invalid size")
            outer = await self._underlying.readexactly(outer_size)
            if not outer.startswith(SEALED_RELAY_HANDSHAKE_MAGIC):
                raise ValueError(
                    "v2 relay channel requires a versioned sealed handshake first flight"
                )

            from one_link import sealed_sender

            peers = self._paired_peer_pubkeys()
            message = sealed_sender.unseal(
                blob=outer[len(SEALED_RELAY_HANDSHAKE_MAGIC) :],
                my_ed_priv_seed=self._local_private_seed,
                paired_ed_pubs=peers,
                aad_context=self._expected_context,
            )
            prior_peer = self._state.peer_public_key
            if prior_peer is not None and not secrets.compare_digest(
                prior_peer, message.sender_ed_pub
            ):
                raise ValueError("sealed relay response came from an unexpected paired peer")
            if not message.body.startswith(self._expected_context):
                raise ValueError("sealed relay handshake direction/context mismatch")
            framed = message.body[len(self._expected_context) :]
            _validate_complete_channel_frame(framed, name="unsealed relay handshake")
            self._state.peer_public_key = message.sender_ed_pub
            self._first_plaintext.extend(framed)
            self._first_loaded = True

    async def read(self, n: int = -1) -> bytes:
        if n == 0:
            return b""
        await self._load_first()
        if self._first_plaintext:
            if n < 0 or n >= len(self._first_plaintext):
                out = bytes(self._first_plaintext)
                self._first_plaintext.clear()
                return out
            out = bytes(self._first_plaintext[:n])
            del self._first_plaintext[:n]
            return out
        return await self._underlying.read(n)

    async def readexactly(self, n: int) -> bytes:
        if n < 0:
            raise ValueError("readexactly size must not be negative")
        if n == 0:
            return b""
        await self._load_first()
        prefix = bytes(self._first_plaintext[:n])
        del self._first_plaintext[: len(prefix)]
        if len(prefix) == n:
            return prefix
        try:
            suffix = await self._underlying.readexactly(n - len(prefix))
        except asyncio.IncompleteReadError as exc:
            raise asyncio.IncompleteReadError(prefix + exc.partial, n) from exc
        return prefix + suffix

    def at_eof(self) -> bool:
        return self._first_loaded and not self._first_plaintext and self._underlying.at_eof()

    @property
    def buffered_bytes(self) -> int:
        return len(self._first_plaintext) + self._underlying.buffered_bytes


class _SealedRelayHandshakeWriter:
    """Seal exactly one channel flight before it reaches a v2 relay."""

    def __init__(
        self,
        underlying: _RelayStreamWriter,
        *,
        local_private_key: Ed25519PrivateKey,
        local_public_key: bytes,
        state: _SealedHandshakeState,
        outbound_context: bytes,
    ) -> None:
        if not isinstance(local_private_key, Ed25519PrivateKey):
            raise ValueError("sealed relay writer requires an Ed25519 private key")
        if not isinstance(local_public_key, bytes) or len(local_public_key) != 32:
            raise ValueError("sealed relay writer identity must be a 32-byte key")
        actual_public = local_private_key.public_key().public_bytes_raw()
        if not secrets.compare_digest(actual_public, local_public_key):
            raise ValueError("sealed relay writer public key does not match private key")
        if not outbound_context:
            raise ValueError("sealed relay handshake context must not be empty")
        self._underlying = underlying
        self._local_private_seed = local_private_key.private_bytes_raw()
        self._local_public_key = local_public_key
        self._state = state
        self._outbound_context = bytes(outbound_context)
        self._first_written = False

    def write(self, data: bytes) -> None:
        if self._first_written:
            self._underlying.write(data)
            return
        _validate_complete_channel_frame(data, name="outbound relay handshake")
        recipient = self._state.peer_public_key
        if not isinstance(recipient, bytes) or len(recipient) != 32:
            raise ValueError("sealed relay responder has not authenticated its peer")

        from one_link import sealed_sender

        envelope = sealed_sender.seal(
            body=self._outbound_context + data,
            sender_ed_priv_seed=self._local_private_seed,
            sender_ed_pub=self._local_public_key,
            recipient_ed_pub=recipient,
            aad_context=self._outbound_context,
        )
        outer = SEALED_RELAY_HANDSHAKE_MAGIC + envelope
        framed = len(outer).to_bytes(4, "big") + outer
        expected_size = _sealed_handshake_framed_size(
            len(data), len(self._outbound_context)
        )
        if len(framed) != expected_size:
            raise RuntimeError("sealed relay handshake size invariant failed")
        self._underlying.write(framed)
        self._first_written = True

    async def wait_writable(self, framed_size: int) -> None:
        effective_size = framed_size
        if not self._first_written:
            effective_size = _sealed_handshake_framed_size(
                framed_size, len(self._outbound_context)
            )
        await self._underlying.wait_writable(effective_size)

    async def drain(self) -> None:
        await self._underlying.drain()

    def close(self) -> None:
        self._underlying.close()

    async def abort(self, exc: BaseException | None = None) -> None:
        await self._underlying.abort(exc)

    async def wait_closed(self) -> None:
        await self._underlying.wait_closed()

    def is_closing(self) -> bool:
        return self._underlying.is_closing()

    @property
    def pending_bytes(self) -> int:
        return self._underlying.pending_bytes

    def get_extra_info(self, name: str, default=None):
        return self._underlying.get_extra_info(name, default)


class _OrderedInboundFlow:
    """Per-session DATA/EOF serializer with byte and item backpressure."""

    def __init__(
        self,
        reader: _RelayStreamReader,
        *,
        queue_limit_bytes: int = RELAY_INBOUND_QUEUE_LIMIT_BYTES,
        queue_max_items: int = RELAY_INBOUND_QUEUE_MAX_ITEMS,
        shared_budget: _SharedByteBudget | None = None,
        shared_budget_headroom_bytes: int = 0,
        shared_budget_owner: object | None = None,
    ):
        if queue_limit_bytes < DATA_FRAME_MAX_BYTES:
            raise ValueError("relay inbound queue must hold at least one maximum DATA frame")
        if queue_max_items < 1:
            raise ValueError("relay inbound queue item limit must be positive")
        self._reader = reader
        self._queue_limit_bytes = int(queue_limit_bytes)
        self._queue_max_items = int(queue_max_items)
        self._shared_budget = shared_budget
        self._shared_budget_headroom_bytes = int(shared_budget_headroom_bytes)
        self._shared_budget_owner = shared_budget_owner
        # Capacity is enforced under _state_changed rather than by
        # asyncio.Queue(maxsize). That lets abort() wake a producer waiting
        # for capacity even if the worker has failed or been cancelled.
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._queued_bytes = 0
        self._queued_items = 0
        self._accepting = True
        self._terminal_exc: BaseException | None = None
        self._last_admission_failure: str | None = None
        self._abort_requested = False
        self._state_changed = asyncio.Condition()
        self._worker_task = asyncio.create_task(self._worker())

    def try_feed(self, data: bytes) -> bool:
        """Admit one DATA frame without waiting for capacity.

        The listener multiplexes every relay session on one WebSocket receive
        loop.  Waiting for a single session's queue (or for the shared byte
        budget) would let one peer stop delivery for every other session.
        This method performs the complete reservation and enqueue operation
        synchronously on the event-loop thread.  ``False`` means that the
        caller must terminate only this overloaded session.
        """
        if not data:
            return True
        if len(data) > self._queue_limit_bytes:
            raise ValueError(
                f"relay inbound item exceeds byte limit: {len(data)} > {self._queue_limit_bytes}"
            )
        self._last_admission_failure = None
        self._raise_if_terminal()
        if not self._accepting:
            raise ConnectionError("relay inbound flow is closed")
        if (
            self._queued_bytes + len(data) > self._queue_limit_bytes
            or self._queued_items >= self._queue_max_items
        ):
            self._last_admission_failure = "session"
            return False

        shared_reserved = False
        if self._shared_budget is not None:
            shared_reserved = self._shared_budget.try_reserve(
                len(data),
                headroom_bytes=self._shared_budget_headroom_bytes,
                owner=self._shared_budget_owner,
            )
            if not shared_reserved:
                self._last_admission_failure = "aggregate"
                return False
        try:
            # There is no await between the checks, accounting, and queue
            # insertion, so another event-loop task cannot steal capacity.
            self._queued_bytes += len(data)
            self._queued_items += 1
            self._queue.put_nowait(bytes(data))
            self._last_admission_failure = None
        except BaseException:
            self._queued_bytes -= len(data)
            self._queued_items -= 1
            if shared_reserved and self._shared_budget is not None:
                self._shared_budget.release_nowait(
                    len(data),
                    owner=self._shared_budget_owner,
                )
            raise
        return True

    async def feed(self, data: bytes) -> None:
        if not data:
            return
        if len(data) > self._queue_limit_bytes:
            raise ValueError(
                f"relay inbound item exceeds byte limit: {len(data)} > {self._queue_limit_bytes}"
            )
        while True:
            async with self._state_changed:
                self._raise_if_terminal()
                while self._accepting and (
                    self._queued_bytes + len(data) > self._queue_limit_bytes
                    or self._queued_items >= self._queue_max_items
                ):
                    await self._state_changed.wait()
                    self._raise_if_terminal()
                if not self._accepting:
                    raise ConnectionError("relay inbound flow is closed")
                if self._shared_budget is None:
                    self._queued_bytes += len(data)
                    self._queued_items += 1
                    self._queue.put_nowait(bytes(data))
                    return
            await self._shared_budget.reserve(
                len(data),
                headroom_bytes=self._shared_budget_headroom_bytes,
                owner=self._shared_budget_owner,
            )
            shared_token_held = True
            try:
                async with self._state_changed:
                    self._raise_if_terminal()
                    if not self._accepting:
                        raise ConnectionError("relay inbound flow is closed")
                    if (
                        self._queued_bytes + len(data) > self._queue_limit_bytes
                        or self._queued_items >= self._queue_max_items
                    ):
                        self._shared_budget.release_nowait(
                            len(data),
                            owner=self._shared_budget_owner,
                        )
                        shared_token_held = False
                        continue
                    self._queued_bytes += len(data)
                    self._queued_items += 1
                    # No await between reservation and insertion: capacity
                    # accounting is atomic on the event-loop thread.
                    self._queue.put_nowait(bytes(data))
                    shared_token_held = False  # flow owns it now
                    return
            except BaseException:
                if shared_token_held:
                    self._shared_budget.release_nowait(
                        len(data),
                        owner=self._shared_budget_owner,
                    )
                raise

    async def feed_eof(self) -> None:
        async with self._state_changed:
            if not self._accepting:
                return
            self._accepting = False
            self._state_changed.notify_all()
        # A single producer (the listener receive loop) calls feed/feed_eof,
        # so putting EOF after DATA preserves exact WebSocket frame order.
        self._queue.put_nowait(None)

    async def _worker(self) -> None:
        try:
            while True:
                item = await self._queue.get()
                try:
                    if item is None:
                        await self._reader.feed_eof()
                        return
                    await self._reader.feed(
                        item,
                        budget_reserved=self._shared_budget is not None,
                    )
                    # The shared-budget token moved with the bytes into the
                    # reader. Update queue ownership synchronously before the
                    # next cancellation point so abort cannot double-release.
                    self._queued_bytes -= len(item)
                    self._queued_items -= 1
                    async with self._state_changed:
                        self._state_changed.notify_all()
                finally:
                    self._queue.task_done()
        except asyncio.CancelledError as exc:
            if self._abort_requested:
                async with self._state_changed:
                    self._accepting = False
                    self._state_changed.notify_all()
                await self._discard_owned_bytes()
                await self._reader.abort()
                return
            terminal = RelayTransportError("relay inbound worker was cancelled")
            terminal.__cause__ = exc
            await self._fail(terminal)
        except Exception as exc:
            terminal = RelayTransportError(
                f"relay inbound worker failed: {type(exc).__name__}: {exc}"
            )
            terminal.__cause__ = exc
            await self._fail(terminal)

    def _raise_if_terminal(self) -> None:
        if self._terminal_exc is not None:
            raise self._terminal_exc

    async def _discard_owned_bytes(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            self._queue.task_done()
        async with self._state_changed:
            owned_bytes = self._queued_bytes
            self._queued_bytes = 0
            self._queued_items = 0
            self._state_changed.notify_all()
        if self._shared_budget is not None and owned_bytes:
            self._shared_budget.release_nowait(
                owned_bytes,
                owner=self._shared_budget_owner,
            )

    async def _fail(self, exc: BaseException) -> None:
        async with self._state_changed:
            if self._terminal_exc is None:
                self._terminal_exc = exc
            self._accepting = False
            self._state_changed.notify_all()
        await self._discard_owned_bytes()
        await self._reader.abort()

    async def abort(self) -> None:
        async with self._state_changed:
            self._accepting = False
            self._abort_requested = True
            self._state_changed.notify_all()
        if not self._worker_task.done():
            self._worker_task.cancel()
        with contextlib.suppress(BaseException):
            await self._worker_task
        await self._discard_owned_bytes()
        await self._reader.abort()

    async def wait_closed(self) -> None:
        await self._worker_task
        self._raise_if_terminal()

    @property
    def queued_bytes(self) -> int:
        return self._queued_bytes

    @property
    def last_admission_failure(self) -> str | None:
        return self._last_admission_failure


class _RelayControlOutbox:
    """One bounded, ordered sender for listener-side control frames.

    The relay listener's WebSocket receive loop must never await a CLOSE
    written for an over-cap or overloaded session.  A slow TCP peer would
    otherwise stop admission and DATA demultiplexing for every healthy
    session.  This outbox has one long-lived worker (never one task per
    refusal), reserves a queue slot for shutdown, and fails the listener
    connection closed if its strict byte/item ceiling is exceeded.
    """

    def __init__(
        self,
        ws: aiohttp.ClientWebSocketResponse,
        *,
        send_deadline_s: float = RELAY_SEND_DEADLINE_S,
        buffer_limit_bytes: int = RELAY_CONTROL_QUEUE_LIMIT_BYTES,
        queue_max_items: int = RELAY_CONTROL_QUEUE_MAX_ITEMS,
    ) -> None:
        if send_deadline_s <= 0:
            raise ValueError("relay control send deadline must be positive")
        if buffer_limit_bytes < 9:
            raise ValueError("relay control outbox must hold one CLOSE frame")
        if queue_max_items < 2:
            raise ValueError("relay control outbox needs a reserved shutdown slot")
        self._ws = ws
        self._send_deadline_s = float(send_deadline_s)
        self._buffer_limit_bytes = int(buffer_limit_bytes)
        self._data_queue_max_items = int(queue_max_items) - 1
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=queue_max_items)
        self._pending_bytes = 0
        self._pending_items = 0
        self._closing = False
        self._terminal_exc: BaseException | None = None
        self._state_changed = asyncio.Condition()
        self._worker_task = asyncio.create_task(self._worker())

    def try_send(self, frame: bytes) -> bool:
        """Atomically enqueue a control frame; never await network I/O."""
        if not frame:
            raise ValueError("relay control frame cannot be empty")
        if self._terminal_exc is not None or self._closing:
            return False
        if (
            len(frame) > self._buffer_limit_bytes
            or self._pending_bytes + len(frame) > self._buffer_limit_bytes
            or self._pending_items >= self._data_queue_max_items
        ):
            self._terminal_exc = RelayTransportError(
                "relay control outbox exceeded its bounded admission capacity"
            )
            self._closing = True
            self._worker_task.cancel()
            return False
        self._pending_bytes += len(frame)
        self._pending_items += 1
        self._queue.put_nowait(bytes(frame))
        return True

    async def _worker(self) -> None:
        current: bytes | None = None
        current_is_item = False
        try:
            while True:
                current = await self._queue.get()
                current_is_item = True
                if current is None:
                    self._queue.task_done()
                    current_is_item = False
                    return
                try:
                    await asyncio.wait_for(
                        self._ws.send_bytes(current),
                        timeout=self._send_deadline_s,
                    )
                except Exception as exc:
                    terminal = RelayTransportError(
                        "relay control WebSocket send failed: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    terminal.__cause__ = exc
                    self._terminal_exc = terminal
                    self._closing = True
                    return
                self._pending_bytes -= len(current)
                self._pending_items -= 1
                self._queue.task_done()
                current_is_item = False
                current = None
                async with self._state_changed:
                    self._state_changed.notify_all()
        except asyncio.CancelledError:
            return
        finally:
            if current_is_item:
                if current is None:
                    raise RuntimeError("relay control outbox item invariant failed")
                self._pending_bytes -= len(current)
                self._pending_items -= 1
                self._queue.task_done()
            while True:
                try:
                    abandoned = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                if abandoned is not None:
                    self._pending_bytes -= len(abandoned)
                    self._pending_items -= 1
                self._queue.task_done()
            self._pending_bytes = 0
            self._pending_items = 0
            async with self._state_changed:
                self._state_changed.notify_all()
            if self._terminal_exc is not None:
                close = getattr(self._ws, "close", None)
                if close is not None:
                    with contextlib.suppress(Exception):
                        await asyncio.wait_for(close(), timeout=self._send_deadline_s)

    async def wait_idle(self) -> None:
        async with self._state_changed:
            while self._pending_items and self._terminal_exc is None:
                await self._state_changed.wait()
        if self._terminal_exc is not None:
            raise self._terminal_exc

    async def abort(self) -> None:
        self._closing = True
        if not self._worker_task.done():
            self._worker_task.cancel()
        with contextlib.suppress(BaseException):
            await self._worker_task

    @property
    def pending_items(self) -> int:
        return self._pending_items

    @property
    def pending_bytes(self) -> int:
        return self._pending_bytes


# ─── outbound: source → destination via relay ──────────────────────


async def open_relay_outbound(
    rendezvous_url: str,
    dst_pubkey: bytes,
    *,
    source_private_key: Ed25519PrivateKey | None = None,
    source_pubkey: bytes | None = None,
    allow_legacy_identity_route: bool = False,
    session: aiohttp.ClientSession | None = None,
    timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
) -> tuple[
    _RelayStreamReader | _SealedRelayHandshakeReader,
    _RelayStreamWriter | _SealedRelayHandshakeWriter,
    asyncio.Task,
]:
    """Open a relay session to an already-paired destination.

    The production path derives rotating pairwise routing tags and sends a
    signed, replay-resistant connector proof.  Neither identity public key is
    present in the v2 URL or connector control frame.  The public-key-addressed
    v1 route remains available only when ``allow_legacy_identity_route`` is
    explicitly true, for controlled mixed-version migrations.

    Returns a stream pair plus a background task that pumps inbound frames
    into the reader.

    Raises:
      RuntimeError if the destination is not currently listening or
      the relay is unavailable.
    """
    if len(dst_pubkey) != 32:
        raise ValueError("dst_pubkey must be 32 bytes")
    from one_link.relay_routing import (
        DerivedRoute,
        derive_dial_routes,
        sign_route_connect_auth,
    )
    from one_link.rendezvous_proto import _b64  # type: ignore

    base = rendezvous_url.rstrip("/")
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")

    attempts: list[tuple[str, DerivedRoute | None, str]] = []
    if source_private_key is not None or source_pubkey is not None:
        if source_private_key is None or source_pubkey is None:
            raise ValueError(
                "source_private_key and source_pubkey must be supplied together"
            )
        for derived_route in derive_dial_routes(
            local_private_key=source_private_key,
            local_public_key=source_pubkey,
            recipient_public_key=dst_pubkey,
        ):
            attempts.append(
                (
                    f"{ws_base}/api/v2/relay/connect/{_b64(derived_route.route_tag)}",
                    derived_route,
                    "pairwise_blinded_v1",
                )
            )
    if allow_legacy_identity_route:
        attempts.append(
            (
                f"{ws_base}/api/v1/relay/connect/{_b64(dst_pubkey)}",
                None,
                "legacy_public_destination_v1",
            )
        )
    if not attempts:
        raise RuntimeError(
            "blinded relay routing requires paired source identity authority; "
            "legacy public-key routing was not explicitly enabled"
        )

    own_session = session is None
    sess = session or aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout))
    ws: aiohttp.ClientWebSocketResponse | None = None
    session_id: bytes | None = None
    routing_mode = "unavailable"
    last_error: BaseException | None = None
    for url, route, candidate_mode in attempts:
        candidate_ws: aiohttp.ClientWebSocketResponse | None = None
        try:
            candidate_ws = await sess.ws_connect(
                url, max_msg_size=DATA_FRAME_MAX_BYTES + 64
            )
            if route is not None:
                connector_auth = sign_route_connect_auth(route)
                await candidate_ws.send_json(connector_auth.to_wire())
            first = await asyncio.wait_for(
                candidate_ws.receive(), timeout=RELAY_RECEIVE_DEADLINE_S
            )
            if first.type != aiohttp.WSMsgType.TEXT:
                raise RuntimeError(
                    f"unexpected first message from relay: {first.type}"
                )
            ready = bounded_json_loads(first.data)
            if not isinstance(ready, dict):
                raise ValueError("relay ready control frame must be an object")
            if ready.get("t") != "ready":
                raise ValueError("relay did not return a ready control frame")
            session_id = parse_session_id_from_msg(ready)
            ws = candidate_ws
            routing_mode = candidate_mode
            break
        except asyncio.CancelledError:
            if candidate_ws is not None:
                with contextlib.suppress(Exception):
                    await candidate_ws.close()
            if own_session:
                with contextlib.suppress(Exception):
                    await sess.close()
            raise
        except BaseException as exc:
            last_error = exc
            if candidate_ws is not None:
                with contextlib.suppress(Exception):
                    await candidate_ws.close()
    if ws is None or session_id is None:
        if own_session:
            with contextlib.suppress(Exception):
                await sess.close()
        if isinstance(last_error, asyncio.TimeoutError):
            raise RuntimeError(
                f"relay handshake timed out after {RELAY_RECEIVE_DEADLINE_S:.1f}s"
            ) from last_error
        raise RuntimeError("no authenticated relay route accepted the connection") from last_error

    raw_reader = _RelayStreamReader()

    async def _on_close():
        with contextlib.suppress(Exception):
            await ws.close()
        if own_session:
            with contextlib.suppress(Exception):
                await sess.close()

    raw_writer = _RelayStreamWriter(ws, session_id, on_close=_on_close)
    if routing_mode == "pairwise_blinded_v1":
        if source_private_key is None or source_pubkey is None:
            raise RuntimeError(
                "blinded relay route selected without source identity authority"
            )
        handshake_state = _SealedHandshakeState(peer_public_key=dst_pubkey)
        reader: _RelayStreamReader | _SealedRelayHandshakeReader = (
            _SealedRelayHandshakeReader(
                raw_reader,
                local_private_key=source_private_key,
                paired_peer_pubkeys_provider=lambda: (dst_pubkey,),
                state=handshake_state,
                expected_context=_SEALED_RELAY_RESPONSE_CONTEXT,
            )
        )
        writer: _RelayStreamWriter | _SealedRelayHandshakeWriter = (
            _SealedRelayHandshakeWriter(
                raw_writer,
                local_private_key=source_private_key,
                local_public_key=source_pubkey,
                state=handshake_state,
                outbound_context=_SEALED_RELAY_INIT_CONTEXT,
            )
        )
    else:
        # The explicit v1 migration route retains its historical raw channel
        # first flight. Runtime truth marks that route as identity-exposing.
        reader = raw_reader
        writer = raw_writer
    setattr(writer, "_one_link_relay_routing_mode", routing_mode)

    async def _pump():
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        frame = decode_frame(msg.data)
                    except ValueError:
                        continue
                    if frame.session_id != session_id:
                        continue  # not for us
                    if frame.type == FRAME_DATA:
                        await raw_reader.feed(frame.payload)
                    elif frame.type == FRAME_CLOSE:
                        break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            await raw_reader.feed_eof()
            # aiohttp's WebSocket async iterator stops *before* yielding
            # CLOSE/CLOSED, so natural loop termination itself is a remote
            # close signal. Only a writer-initiated close should finish the
            # pump without installing a sticky terminal error.
            if not writer.is_closing():
                await writer.abort(ConnectionResetError("relay peer closed the session"))
            with contextlib.suppress(Exception):
                await ws.close()
            if own_session:
                with contextlib.suppress(Exception):
                    await sess.close()

    pump_task = asyncio.create_task(_pump())
    return reader, writer, pump_task


# ─── inbound: destination listener ─────────────────────────────────


@dataclass
class _ActiveSession:
    session_id: bytes
    reader: _RelayStreamReader
    writer: _RelayStreamWriter
    inbound: _OrderedInboundFlow
    budget_owner: object
    opened_sequence: int
    drive_task: asyncio.Task | None = None
    teardown_task: asyncio.Task[None] | None = None
    remote_closed: bool = False
    admission_paused: bool = False


class RelayListenerClient:
    """Persistently registered listener at the destination side.

    Constructed with a callback that receives (reader, writer) for
    each new incoming session. The daemon's `_handle_peer` is the
    natural callback — it already knows how to drive a fresh
    encrypted handshake on a stream pair."""

    def __init__(
        self,
        *,
        rendezvous_url: str,
        private_key: Ed25519PrivateKey,
        pubkey: bytes,
        on_session: Callable[[_RelayStreamReader, _RelayStreamWriter], Awaitable[None]],
        paired_peer_pubkeys_provider: Callable[[], Iterable[bytes]] | None = None,
        allow_legacy_identity_route: bool = False,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        aggregate_buffer_limit_bytes: int = RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES,
        max_active_sessions: int = RELAY_LISTENER_MAX_ACTIVE_SESSIONS,
    ):
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        self._rendezvous_url = rendezvous_url.rstrip("/")
        self._private_key = private_key
        self._pubkey = pubkey
        self._on_session = on_session
        self._paired_peer_pubkeys_provider = paired_peer_pubkeys_provider
        self._allow_legacy_identity_route = bool(allow_legacy_identity_route)
        self._routing_mode = "waiting_for_pairwise_routes"
        self._request_timeout_s = request_timeout_s
        if max_active_sessions < 1:
            raise ValueError("relay listener session limit must be positive")
        self._max_active_sessions = int(max_active_sessions)
        if aggregate_buffer_limit_bytes < 2 * DATA_FRAME_MAX_BYTES + 9:
            raise ValueError(
                "relay listener aggregate budget must leave room for "
                "simultaneous inbound and outbound DATA frames"
            )
        self._memory_budget = _SharedByteBudget(aggregate_buffer_limit_bytes)
        self._outbound_headroom_bytes = min(
            RELAY_LISTENER_OUTBOUND_HEADROOM_BYTES,
            aggregate_buffer_limit_bytes - DATA_FRAME_MAX_BYTES,
        )

        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._loop_task: asyncio.Task | None = None
        self._active: dict[bytes, _ActiveSession] = {}
        self._session_teardown_tasks: set[asyncio.Task[None]] = set()
        self._control_outbox: _RelayControlOutbox | None = None
        self._opened_sequence = 0
        self._stop = asyncio.Event()

    @property
    def is_running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

    @property
    def aggregate_buffered_bytes(self) -> int:
        return self._memory_budget.used_bytes

    @property
    def aggregate_peak_buffered_bytes(self) -> int:
        return self._memory_budget.peak_bytes

    @property
    def routing_mode(self) -> str:
        """Truthful relay metadata mode for runtime/audit surfaces."""

        return self._routing_mode

    @property
    def destination_identity_exposure(self) -> str:
        if self._routing_mode == "legacy_public_destination_v1":
            return "destination_public_key_in_relay_auth_and_url"
        if self._routing_mode == "pairwise_blinded_v1":
            return "no_identity_public_key_on_relay_wire"
        return "not_registered"

    @property
    def channel_first_flight_identity_protection(self) -> str:
        """Truth surface for the identity-bearing channel HELLO/REPLY."""

        if self._routing_mode == "pairwise_blinded_v1":
            return "sealed_recipient_only_v1"
        if self._routing_mode == "legacy_public_destination_v1":
            return "plaintext_channel_identity_keys"
        return "not_registered"

    @property
    def admission_occupancy(self) -> int:
        """Sessions plus still-running teardown work holding resources."""
        active_tasks = {
            sess.teardown_task
            for sess in self._active.values()
            if sess.teardown_task is not None
        }
        return len(self._active) + len(self._session_teardown_tasks - active_tasks)

    async def start(self) -> None:
        if self.is_running:
            return
        self._stop.clear()
        self._session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self._request_timeout_s)
        )
        self._loop_task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._ws is not None:
            with contextlib.suppress(Exception):
                await self._ws.close()
            self._ws = None
        if self._loop_task is not None:
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(self._loop_task, timeout=2.0)
            self._loop_task = None
        await self._shutdown_active_sessions(ConnectionResetError("relay listener stopped"))
        await self._wait_for_session_teardowns()
        if self._control_outbox is not None:
            await self._control_outbox.abort()
            self._control_outbox = None
        if self._session is not None:
            with contextlib.suppress(Exception):
                await self._session.close()
            self._session = None

    # ─── internals ─────────────────────────────────────────────

    async def _run_loop(self) -> None:
        """Reconnect-with-backoff loop. Re-registers on disconnect."""
        backoff = 1.0
        while not self._stop.is_set():
            try:
                await self._connect_once()
                backoff = 1.0  # successful connect → reset backoff
            except asyncio.CancelledError:
                return
            except Exception as e:
                log.warning("relay listener (%s) errored: %s", self._rendezvous_url, e)
            if self._stop.is_set():
                return
            await asyncio.sleep(min(backoff, 30.0))
            backoff = min(backoff * 2, 30.0)

    async def _connect_once(self) -> None:
        from one_link.relay_routing import (
            build_route_listen_auth,
            listener_route_epochs,
            route_listen_wire,
        )

        ws_base = self._rendezvous_url.replace("https://", "wss://").replace("http://", "ws://")
        route_auth = None
        if self._paired_peer_pubkeys_provider is not None:
            peers = tuple(self._paired_peer_pubkeys_provider())
            if peers:
                route_auth = build_route_listen_auth(
                    local_private_key=self._private_key,
                    local_public_key=self._pubkey,
                    paired_peer_public_keys=peers,
                )
        if route_auth is not None:
            url = f"{ws_base}/api/v2/relay/listen"
            routing_mode = "pairwise_blinded_v1"
        elif self._allow_legacy_identity_route:
            url = f"{ws_base}/api/v1/relay/listen"
            routing_mode = "legacy_public_destination_v1"
        else:
            self._routing_mode = "waiting_for_pairwise_routes"
            raise RuntimeError("no paired peers are eligible for blinded relay routing")

        session = self._session
        if session is None:
            raise RuntimeError("relay listener session is not initialized")
        ws = await session.ws_connect(url, max_msg_size=DATA_FRAME_MAX_BYTES + 64)
        self._ws = ws
        outbox = _RelayControlOutbox(ws)
        self._control_outbox = outbox
        refresh_task: asyncio.Task[None] | None = None
        try:
            # Auth.
            if route_auth is not None:
                peer_provider = self._paired_peer_pubkeys_provider
                if peer_provider is None:
                    raise RuntimeError(
                        "blinded relay listener lost paired-peer authority"
                    )
                await ws.send_json(route_listen_wire(route_auth))
                self._routing_mode = routing_mode
                log.info(
                    "blinded relay listener registered at %s with %d rotating routes",
                    self._rendezvous_url,
                    len(route_auth.routes),
                )

                async def _refresh_pairwise_routes() -> None:
                    # The old loop rebuilt and re-signed every pair/epoch route
                    # every five seconds merely to discover that its digest
                    # had not changed. With 256 peers that meant hundreds of
                    # needless X25519/HKDF/Ed25519 operations per poll. Compare
                    # the cheap provider+epoch basis first and only build when
                    # membership or the canonical rotation window changes.
                    route_basis = (
                        peers,
                        tuple(sorted({route.epoch for route in route_auth.routes})),
                    )
                    try:
                        while not self._stop.is_set() and not ws.closed:
                            await asyncio.sleep(RELAY_ROUTE_REFRESH_POLL_S)
                            current_peers = tuple(peer_provider())
                            if not current_peers:
                                await ws.close(
                                    code=4000,
                                    message=b"no paired relay routes remain",
                                )
                                return
                            candidate_basis = (
                                current_peers,
                                tuple(sorted(listener_route_epochs())),
                            )
                            if candidate_basis == route_basis:
                                continue
                            refreshed = build_route_listen_auth(
                                local_private_key=self._private_key,
                                local_public_key=self._pubkey,
                                paired_peer_public_keys=current_peers,
                            )
                            await ws.send_json(route_listen_wire(refreshed, refresh=True))
                            route_basis = (
                                current_peers,
                                tuple(
                                    sorted({route.epoch for route in refreshed.routes})
                                ),
                            )
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        log.warning(
                            "blinded relay route refresh at %s failed: %s",
                            self._rendezvous_url,
                            exc,
                        )
                        with contextlib.suppress(Exception):
                            await ws.close(
                                code=4000,
                                message=b"blinded route refresh failed",
                            )

                refresh_task = asyncio.create_task(_refresh_pairwise_routes())
            else:
                auth = sign_listen_auth(private_key=self._private_key, pubkey=self._pubkey)
                await ws.send_json(auth.to_wire())
                self._routing_mode = routing_mode
                log.warning(
                    "legacy relay listener registered at %s; destination public key "
                    "is exposed to that relay",
                    self._rendezvous_url,
                )

            # Pump.
            async for msg in ws:
                if self._stop.is_set():
                    break
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_control(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    await self._handle_data(msg.data)
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            if refresh_task is not None:
                refresh_task.cancel()
                with contextlib.suppress(BaseException):
                    await refresh_task
            self._ws = None
            self._routing_mode = "waiting_for_pairwise_routes"
            await self._shutdown_active_sessions(
                ConnectionResetError("relay listener WebSocket disconnected")
            )
            if self._control_outbox is outbox:
                self._control_outbox = None
            await outbox.abort()
            with contextlib.suppress(Exception):
                await ws.close()

    async def _handle_control(self, payload: str) -> None:
        try:
            doc = bounded_json_loads(payload)
        except ValueError as e:
            raise RelayTransportError(f"relay listener rejected control JSON: {e}") from e
        if not isinstance(doc, dict):
            raise RelayTransportError("relay listener control message must be an object")
        kind = doc.get("t")
        if kind == "incoming":
            try:
                sid = parse_session_id_from_msg(doc)
            except ValueError as e:
                raise RelayTransportError(
                    f"relay listener rejected incoming control: {e}"
                ) from e
            await self._open_inbound_session(sid)
        elif kind == "session_closed":
            try:
                sid = parse_session_id_from_msg(doc)
            except ValueError as e:
                raise RelayTransportError(
                    f"relay listener rejected close control: {e}"
                ) from e
            sess = self._active.get(sid)
            if sess is not None:
                self._schedule_remote_session_close(
                    sess,
                    ConnectionResetError("relay server closed the session"),
                )
        else:
            raise RelayTransportError(
                f"relay listener rejected unknown control type: {kind!r}"
            )

    def _ensure_control_outbox(self) -> _RelayControlOutbox | None:
        if self._ws is None:
            return None
        if self._control_outbox is None:
            # Unit-level stream tests inject a WebSocket without running the
            # reconnect loop. Production connections create this eagerly.
            self._control_outbox = _RelayControlOutbox(self._ws)
        return self._control_outbox

    def _queue_session_close(self, sid: bytes) -> bool:
        outbox = self._ensure_control_outbox()
        return outbox is not None and outbox.try_send(encode_close_frame(sid))

    async def _open_inbound_session(self, sid: bytes) -> None:
        if self._ws is None:
            return
        prior = self._active.get(sid)
        if prior is not None:
            # A duplicate identifier is a relay protocol violation. Do not
            # wait for its old handler or silently reuse memory/accounting.
            self._schedule_overloaded_session_teardown(
                prior,
                reason="duplicate relay session identifier",
            )
            return
        if self.admission_occupancy >= self._max_active_sessions:
            log.warning(
                "relay listener at local session cap (%d); refusing %s",
                self._max_active_sessions,
                sid.hex(),
            )
            # Refusals share one bounded sender. No per-refusal task and no
            # network await can stall the multiplexed control receive loop.
            if not self._queue_session_close(sid):
                raise RelayTransportError("relay control refusal outbox is overloaded")
            return
        budget_owner = object()
        reader = _RelayStreamReader(
            shared_budget=self._memory_budget,
            shared_budget_headroom_bytes=self._outbound_headroom_bytes,
            shared_budget_owner=budget_owner,
        )
        writer = _RelayStreamWriter(
            self._ws,
            sid,
            shared_budget=self._memory_budget,
            shared_budget_owner=budget_owner,
        )
        inbound = _OrderedInboundFlow(
            reader,
            shared_budget=self._memory_budget,
            shared_budget_headroom_bytes=self._outbound_headroom_bytes,
            shared_budget_owner=budget_owner,
        )
        self._opened_sequence += 1
        active = _ActiveSession(
            session_id=sid,
            reader=reader,
            writer=writer,
            inbound=inbound,
            budget_owner=budget_owner,
            opened_sequence=self._opened_sequence,
        )
        self._active[sid] = active

        callback_reader: _RelayStreamReader | _SealedRelayHandshakeReader = reader
        callback_writer: _RelayStreamWriter | _SealedRelayHandshakeWriter = writer
        if self._routing_mode == "pairwise_blinded_v1":
            if self._paired_peer_pubkeys_provider is None:
                # A v2 listener without pair authority is an internal policy
                # violation. Refuse the session rather than exposing the raw
                # identity-bearing channel handshake to the relay.
                raise RelayTransportError(
                    "blinded relay session has no sealed-handshake peer authority"
                )
            handshake_state = _SealedHandshakeState()
            callback_reader = _SealedRelayHandshakeReader(
                reader,
                local_private_key=self._private_key,
                paired_peer_pubkeys_provider=self._paired_peer_pubkeys_provider,
                state=handshake_state,
                expected_context=_SEALED_RELAY_INIT_CONTEXT,
            )
            callback_writer = _SealedRelayHandshakeWriter(
                writer,
                local_private_key=self._private_key,
                local_public_key=self._pubkey,
                state=handshake_state,
                outbound_context=_SEALED_RELAY_RESPONSE_CONTEXT,
            )

        # Hand off to the user-provided callback. They run independently;
        # we just make sure errors don't kill the listener loop.
        async def _drive():
            try:
                await self._on_session(callback_reader, callback_writer)  # type: ignore[arg-type]
            except Exception as e:
                log.warning("relay session handler errored: %s", e)
            finally:
                active.remote_closed = True
                await inbound.abort()
                # CLOSE is queued after all preceding session DATA.  Waiting
                # here prevents the listener WebSocket from being torn down
                # before the close frame actually reaches the server.
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
                if self._active.get(sid) is active:
                    self._active.pop(sid, None)

        active.drive_task = asyncio.create_task(_drive())

    async def _handle_data(self, raw: bytes) -> None:
        try:
            frame = decode_frame(raw)
        except ValueError as e:
            log.warning("relay listener: bad data frame: %s", e)
            return
        sess = self._active.get(frame.session_id)
        if sess is None:
            return  # unknown session — server may be closing
        if frame.type == FRAME_DATA:
            if sess.remote_closed:
                return
            if sess.admission_paused:
                # One DATA frame (at most 1 MiB) may be retained while a
                # larger aggregate borrower is reclaimed. A second frame is
                # a session-local overload; terminating it preserves order
                # and caps transient retry memory at one frame per session.
                self._schedule_overloaded_session_teardown(
                    sess,
                    reason="relay DATA arrived while aggregate retry was pending",
                )
                return
            # Never await per-session capacity in the multiplexed receive
            # loop.  A peer that stops consuming after a few MiB must not
            # head-of-line block unrelated sessions.  Queue admission is
            # atomic; overload terminates only the responsible session.
            try:
                admitted = sess.inbound.try_feed(frame.payload)
            except ConnectionError:
                admitted = False
            if not admitted:
                if sess.inbound.last_admission_failure == "aggregate":
                    victim = self._largest_buffer_borrower()
                    if victim is not None and victim is not sess:
                        sess.admission_paused = True
                        self._schedule_fair_eviction_and_retry(
                            victim=victim,
                            retry_session=sess,
                            payload=bytes(frame.payload),
                        )
                        return
                self._schedule_overloaded_session_teardown(
                    sess,
                    reason="relay inbound session exceeded its bounded allocation",
                )
        elif frame.type == FRAME_CLOSE:
            self._schedule_remote_session_close(
                sess,
                ConnectionResetError("relay peer sent CLOSE"),
            )

    def _largest_buffer_borrower(self) -> _ActiveSession | None:
        candidates = [
            sess
            for sess in self._active.values()
            if not sess.remote_closed and self._memory_budget.used_by(sess.budget_owner) > 0
        ]
        if not candidates:
            return None
        # Bytes dominate. On exact ties evict the oldest borrower, a stable
        # server-chosen order that an attacker cannot influence with a SID.
        return max(
            candidates,
            key=lambda candidate: (
                self._memory_budget.used_by(candidate.budget_owner),
                -candidate.opened_sequence,
            ),
        )

    def _detach_for_teardown(self, sess: _ActiveSession) -> bool:
        if self._active.get(sess.session_id) is not sess:
            return False
        self._active.pop(sess.session_id, None)
        sess.remote_closed = True
        sess.admission_paused = False
        return True

    def _track_teardown_task(
        self,
        task: asyncio.Task[None],
        *,
        primary_session: _ActiveSession,
    ) -> None:
        primary_session.teardown_task = task
        self._session_teardown_tasks.add(task)

        def _done(completed: asyncio.Task[None]) -> None:
            self._session_teardown_tasks.discard(completed)
            if primary_session.teardown_task is completed:
                primary_session.teardown_task = None
            if completed.cancelled():
                return
            exc = completed.exception()
            if exc is not None:
                log.warning(
                    "relay session teardown failed for %s: %s",
                    primary_session.session_id.hex(),
                    exc,
                )

        task.add_done_callback(_done)

    def _schedule_overloaded_session_teardown(
        self,
        sess: _ActiveSession,
        *,
        reason: str = "relay inbound session exceeded its bounded buffer allocation",
    ) -> None:
        if not self._detach_for_teardown(sess):
            return
        task = asyncio.create_task(
            self._teardown_detached_session(sess, RelayTransportError(reason))
        )
        self._track_teardown_task(task, primary_session=sess)

    def _schedule_remote_session_close(
        self,
        sess: _ActiveSession,
        terminal: BaseException,
    ) -> None:
        if self._active.get(sess.session_id) is not sess or sess.remote_closed:
            return
        sess.remote_closed = True

        async def _finish_remote() -> None:
            # DATA preceding CLOSE is already ordered in inbound. Preserve it
            # for the handler, then fail the reverse direction promptly.
            await sess.inbound.feed_eof()
            await sess.writer.abort(terminal)

        task = asyncio.create_task(_finish_remote())
        self._track_teardown_task(task, primary_session=sess)

    async def _teardown_detached_session(
        self,
        sess: _ActiveSession,
        terminal: BaseException,
    ) -> None:
        # Reclaim all memory before queueing best-effort network control. The
        # control outbox is separately bounded and never delays this path.
        await sess.inbound.abort()
        await sess.writer.abort(terminal)
        if sess.drive_task is not None and not sess.drive_task.done():
            sess.drive_task.cancel()
            with contextlib.suppress(BaseException):
                await sess.drive_task
        if not self._queue_session_close(sess.session_id):
            log.warning("relay control outbox could not enqueue CLOSE for %s", sess.session_id.hex())

    def _schedule_fair_eviction_and_retry(
        self,
        *,
        victim: _ActiveSession,
        retry_session: _ActiveSession,
        payload: bytes,
    ) -> None:
        if not self._detach_for_teardown(victim):
            retry_session.admission_paused = False
            self._schedule_overloaded_session_teardown(
                retry_session,
                reason="relay aggregate admission race could not be resolved",
            )
            return

        async def _evict_and_retry() -> None:
            current_victim = victim
            try:
                while True:
                    await self._teardown_detached_session(
                        current_victim,
                        RelayTransportError(
                            "relay session was the deterministic largest "
                            "aggregate-buffer borrower"
                        ),
                    )
                    if (
                        self._active.get(retry_session.session_id) is not retry_session
                        or retry_session.remote_closed
                        or not retry_session.admission_paused
                    ):
                        return
                    try:
                        admitted = retry_session.inbound.try_feed(payload)
                    except ConnectionError:
                        admitted = False
                    if admitted:
                        retry_session.admission_paused = False
                        return
                    next_victim = self._largest_buffer_borrower()
                    if (
                        retry_session.inbound.last_admission_failure != "aggregate"
                        or next_victim is None
                        or next_victim is retry_session
                        or not self._detach_for_teardown(next_victim)
                    ):
                        self._detach_for_teardown(retry_session)
                        await self._teardown_detached_session(
                            retry_session,
                            RelayTransportError(
                                "relay aggregate retry could not obtain bounded capacity"
                            ),
                        )
                        return
                    next_victim.teardown_task = asyncio.current_task()
                    current_victim = next_victim
            finally:
                # Any unexpected teardown/accounting failure must not leave a
                # paused session permanently occupying admission with one
                # retained retry frame.
                if (
                    self._active.get(retry_session.session_id) is retry_session
                    and retry_session.admission_paused
                    and self._detach_for_teardown(retry_session)
                ):
                    with contextlib.suppress(BaseException):
                        await self._teardown_detached_session(
                            retry_session,
                            RelayTransportError("relay aggregate retry aborted"),
                        )

        task = asyncio.create_task(_evict_and_retry())
        self._track_teardown_task(task, primary_session=victim)

    async def _wait_for_session_teardowns(self) -> None:
        while self._session_teardown_tasks:
            await asyncio.gather(*list(self._session_teardown_tasks), return_exceptions=True)

    async def _wait_for_control_outbox_idle(self) -> None:
        if self._control_outbox is not None:
            await self._control_outbox.wait_idle()

    async def _shutdown_active_sessions(self, exc: BaseException) -> None:
        sessions = list(self._active.values())
        self._active.clear()
        # Graceful remote-close tasks intentionally leave the session handler
        # alive to consume ordered EOF. A listener shutdown is different: it
        # must cancel those tasks and force every handler/queue closed before
        # returning, otherwise their resources outlive reconnection.
        active_tasks = {
            sess.teardown_task
            for sess in sessions
            if sess.teardown_task is not None and not sess.teardown_task.done()
        }
        for task in active_tasks:
            task.cancel()
        if active_tasks:
            await asyncio.gather(*active_tasks, return_exceptions=True)
        for sess in sessions:
            sess.teardown_task = None
        teardown = [self._teardown_detached_session(sess, exc) for sess in sessions]
        if teardown:
            await asyncio.gather(*teardown, return_exceptions=True)
        await self._wait_for_session_teardowns()
        if self._control_outbox is not None:
            await self._control_outbox.abort()
            self._control_outbox = None
