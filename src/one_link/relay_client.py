"""Daemon-side encrypted-relay client.

Two roles, both wrapping aiohttp WebSockets:

  RelayListenerClient  — destination side. Persistently subscribed
                         to /api/v1/relay/listen. Demultiplexes
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

  - The relay sees only `dst_pubkey`. Source side does NOT
    authenticate to the relay (sealed sender — relay must not learn
    who's connecting).
  - All payload bytes are encrypted by the One Link channel above
    this transport. The relay forwards opaque bytes.
  - The "stream" abstraction is implemented via a small in-memory
    bridge (asyncio.Queue) so the existing channel.py code works
    without modification.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

import aiohttp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.relay_proto import (
    DATA_FRAME_MAX_BYTES,
    FRAME_CLOSE,
    FRAME_DATA,
    SESSION_ID_BYTES,
    decode_frame,
    encode_close_frame,
    encode_data_frame,
    parse_session_id_from_msg,
    sign_listen_auth,
)

log = logging.getLogger("one_link.relay_client")

DEFAULT_REQUEST_TIMEOUT_S = 10.0
RELAY_RECEIVE_DEADLINE_S = 5.0


# ─── stream bridge over WebSocket ──────────────────────────────────

class _RelayStreamReader:
    """Adapter that lets ch.initiate / ch.respond's StreamReader
    interface read bytes that the WebSocket sends us via push.

    asyncio.StreamReader-compatible: implements `read(n)`,
    `readexactly(n)`, and the IncompleteReadError on EOF."""

    def __init__(self):
        self._buf = bytearray()
        self._eof = False
        self._cond = asyncio.Condition()

    async def read(self, n: int = -1) -> bytes:
        async with self._cond:
            while not self._buf and not self._eof:
                await self._cond.wait()
            if n == -1 or n >= len(self._buf):
                out = bytes(self._buf)
                self._buf.clear()
                return out
            out = bytes(self._buf[:n])
            del self._buf[:n]
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
        return bytes(out)

    async def feed(self, data: bytes) -> None:
        async with self._cond:
            self._buf.extend(data)
            self._cond.notify_all()

    async def feed_eof(self) -> None:
        async with self._cond:
            self._eof = True
            self._cond.notify_all()


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
    ):
        self._ws = ws
        self._session_id = session_id
        self._on_close = on_close
        self._closed = False
        self._send_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._sender_task: asyncio.Task = asyncio.create_task(self._sender_loop())

    async def _sender_loop(self) -> None:
        try:
            while True:
                item = await self._send_queue.get()
                if item is None:
                    break  # close sentinel
                with contextlib.suppress(Exception):
                    await self._ws.send_bytes(item)
        except asyncio.CancelledError:
            return

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        # Chunk to DATA_FRAME_MAX_BYTES so a >1 MB write doesn't blow
        # the WS frame budget. Each chunk is enqueued in order.
        view = memoryview(data)
        i = 0
        while i < len(view):
            chunk = bytes(view[i:i + DATA_FRAME_MAX_BYTES])
            i += DATA_FRAME_MAX_BYTES
            self._send_queue.put_nowait(
                encode_data_frame(self._session_id, chunk)
            )

    async def drain(self) -> None:
        # Wait until everything queued so far has been sent.
        # asyncio.Queue.join() requires task_done — we don't track per
        # message, so use a sentinel: enqueue a no-op marker that we
        # await once consumed. Simpler: just yield a couple of loop
        # ticks so the sender_loop drains. WebSocket has its own
        # backpressure inside send_bytes.
        for _ in range(2):
            await asyncio.sleep(0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Enqueue a CLOSE frame, then a sentinel to terminate the loop.
        with contextlib.suppress(Exception):
            self._send_queue.put_nowait(encode_close_frame(self._session_id))
            self._send_queue.put_nowait(None)
        if self._on_close is not None:
            with contextlib.suppress(Exception):
                loop = asyncio.get_event_loop()
                loop.create_task(self._on_close())

    async def wait_closed(self) -> None:
        # Wait for sender_loop to flush + exit.
        if self._sender_task is not None and not self._sender_task.done():
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(self._sender_task, timeout=2.0)

    def get_extra_info(self, name: str, default=None):
        # ch.respond reads "peername" for diagnostics — return a
        # synthetic shape so it doesn't blow up.
        if name == "peername":
            return ("relay", 0)
        return default


# ─── outbound: source → destination via relay ──────────────────────

async def open_relay_outbound(
    rendezvous_url: str,
    dst_pubkey: bytes,
    *,
    session: aiohttp.ClientSession | None = None,
    timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
) -> tuple[_RelayStreamReader, _RelayStreamWriter, asyncio.Task]:
    """Open a relay session targeting `dst_pubkey` via the given
    rendezvous URL. Returns a stream pair plus a background task that
    pumps inbound frames into the reader.

    Raises:
      RuntimeError if the destination is not currently listening or
      the relay is unavailable.
    """
    if len(dst_pubkey) != 32:
        raise ValueError("dst_pubkey must be 32 bytes")
    from one_link.rendezvous_proto import _b64  # type: ignore

    base = rendezvous_url.rstrip("/")
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    url = f"{ws_base}/api/v1/relay/connect/{_b64(dst_pubkey)}"

    own_session = session is None
    sess = session or aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=timeout)
    )
    try:
        ws = await sess.ws_connect(url, max_msg_size=DATA_FRAME_MAX_BYTES + 64)
    except Exception:
        if own_session:
            await sess.close()
        raise

    # First message must be a "ready" text frame with our session_id.
    first = await asyncio.wait_for(ws.receive(), timeout=RELAY_RECEIVE_DEADLINE_S)
    if first.type != aiohttp.WSMsgType.TEXT:
        await ws.close()
        if own_session:
            await sess.close()
        raise RuntimeError(
            f"unexpected first message from relay: {first.type}"
        )
    try:
        ready = json.loads(first.data)
        if ready.get("t") != "ready":
            raise ValueError(f"expected ready, got {ready!r}")
        session_id = parse_session_id_from_msg(ready)
    except (json.JSONDecodeError, ValueError) as e:
        await ws.close()
        if own_session:
            await sess.close()
        raise RuntimeError(f"relay handshake malformed: {e}")

    reader = _RelayStreamReader()

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
                        await reader.feed(frame.payload)
                    elif frame.type == FRAME_CLOSE:
                        break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            await reader.feed_eof()
            with contextlib.suppress(Exception):
                await ws.close()
            if own_session:
                with contextlib.suppress(Exception):
                    await sess.close()

    pump_task = asyncio.create_task(_pump())

    async def _on_close():
        with contextlib.suppress(Exception):
            await ws.close()
        if own_session:
            with contextlib.suppress(Exception):
                await sess.close()

    writer = _RelayStreamWriter(ws, session_id, on_close=_on_close)
    return reader, writer, pump_task


# ─── inbound: destination listener ─────────────────────────────────

@dataclass
class _ActiveSession:
    session_id: bytes
    reader: _RelayStreamReader
    writer: _RelayStreamWriter


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
        on_session: Callable[
            [_RelayStreamReader, _RelayStreamWriter], Awaitable[None]
        ],
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
    ):
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        self._rendezvous_url = rendezvous_url.rstrip("/")
        self._private_key = private_key
        self._pubkey = pubkey
        self._on_session = on_session
        self._request_timeout_s = request_timeout_s

        self._session: aiohttp.ClientSession | None = None
        self._ws: aiohttp.ClientWebSocketResponse | None = None
        self._loop_task: asyncio.Task | None = None
        self._active: dict[bytes, _ActiveSession] = {}
        self._stop = asyncio.Event()

    @property
    def is_running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

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
        # Close any active sessions.
        for sess in list(self._active.values()):
            with contextlib.suppress(Exception):
                await sess.reader.feed_eof()
        self._active.clear()
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
                log.warning(
                    "relay listener (%s) errored: %s", self._rendezvous_url, e
                )
            if self._stop.is_set():
                return
            await asyncio.sleep(min(backoff, 30.0))
            backoff = min(backoff * 2, 30.0)

    async def _connect_once(self) -> None:
        from one_link.rendezvous_proto import _b64  # type: ignore

        ws_base = self._rendezvous_url.replace(
            "https://", "wss://"
        ).replace("http://", "ws://")
        url = f"{ws_base}/api/v1/relay/listen"

        assert self._session is not None
        ws = await self._session.ws_connect(
            url, max_msg_size=DATA_FRAME_MAX_BYTES + 64
        )
        self._ws = ws
        try:
            # Auth.
            auth = sign_listen_auth(
                private_key=self._private_key, pubkey=self._pubkey
            )
            await ws.send_json(auth.to_wire())
            log.info(
                "relay listener registered at %s for %s",
                self._rendezvous_url, self._pubkey.hex()[:8],
            )

            # Pump.
            async for msg in ws:
                if self._stop.is_set():
                    break
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_control(msg.data)
                elif msg.type == aiohttp.WSMsgType.BINARY:
                    self._handle_data(msg.data)
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            self._ws = None
            with contextlib.suppress(Exception):
                await ws.close()

    async def _handle_control(self, payload: str) -> None:
        try:
            doc = json.loads(payload)
        except json.JSONDecodeError as e:
            log.warning("relay listener: bad control msg: %s", e)
            return
        kind = doc.get("t")
        if kind == "incoming":
            try:
                sid = parse_session_id_from_msg(doc)
            except ValueError as e:
                log.warning("relay listener: bad incoming sid: %s", e)
                return
            await self._open_inbound_session(sid)
        elif kind == "session_closed":
            try:
                sid = parse_session_id_from_msg(doc)
            except ValueError:
                return
            sess = self._active.pop(sid, None)
            if sess is not None:
                with contextlib.suppress(Exception):
                    await sess.reader.feed_eof()

    async def _open_inbound_session(self, sid: bytes) -> None:
        if self._ws is None:
            return
        reader = _RelayStreamReader()
        writer = _RelayStreamWriter(self._ws, sid)
        self._active[sid] = _ActiveSession(
            session_id=sid, reader=reader, writer=writer
        )
        # Hand off to the user-provided callback. They run independently;
        # we just make sure errors don't kill the listener loop.
        async def _drive():
            try:
                await self._on_session(reader, writer)
            except Exception as e:
                log.warning("relay session handler errored: %s", e)
            finally:
                self._active.pop(sid, None)
                # Make sure we send a CLOSE so the connector drops too.
                with contextlib.suppress(Exception):
                    if self._ws is not None:
                        await self._ws.send_bytes(encode_close_frame(sid))

        asyncio.create_task(_drive())

    def _handle_data(self, raw: bytes) -> None:
        try:
            frame = decode_frame(raw)
        except ValueError as e:
            log.warning("relay listener: bad data frame: %s", e)
            return
        sess = self._active.get(frame.session_id)
        if sess is None:
            return  # unknown session — server may be closing
        if frame.type == FRAME_DATA:
            # Schedule the feed instead of awaiting (we're in the
            # outer pump; can't block).
            asyncio.create_task(sess.reader.feed(frame.payload))
        elif frame.type == FRAME_CLOSE:
            asyncio.create_task(sess.reader.feed_eof())
            self._active.pop(frame.session_id, None)
