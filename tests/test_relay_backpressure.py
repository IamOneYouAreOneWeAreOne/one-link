"""Relay flow-control, failure-propagation, and session-liveness proofs."""

from __future__ import annotations

import asyncio
import json
import struct
from collections.abc import AsyncIterator, Callable

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import double_ratchet
from one_link.channel import Channel, DR_HEADER_LEN
from one_link.relay_client import (
    RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES,
    RELAY_LISTENER_OUTBOUND_HEADROOM_BYTES,
    RelayListenerClient,
    RelayTransportError,
    _OrderedInboundFlow,
    _RelayControlOutbox,
    _RelayStreamReader,
    _RelayStreamWriter,
    _SharedByteBudget,
    open_relay_outbound,
)
from one_link.relay_proto import (
    DATA_FRAME_MAX_BYTES,
    FRAME_CLOSE,
    FRAME_DATA,
    decode_frame,
    encode_close_frame,
    encode_data_frame,
    parse_session_id_from_msg,
    sign_listen_auth,
)
from one_link.rendezvous_proto import _b64  # type: ignore[attr-defined]
from one_link.rendezvous_server import (
    RendezvousApp,
    ServerConfig,
    _parse_args,
    _RelayForwardBudget,
    _RelayForwardQueue,
)


@pytest_asyncio.fixture(autouse=True)
async def _close_owned_client_websockets(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[None]:
    """Close every WebSocket opened by a test, including failure paths.

    Closing an ``aiohttp.ClientSession`` closes its connector, but it does
    not run ``ClientWebSocketResponse.close()`` for application-owned
    WebSocket response objects.  Those response wrappers otherwise retain an
    unreleased ``Connection`` cycle until a later garbage collection, which
    is both a real test resource leak and a source of cross-test failures on
    the Windows proactor loop.
    """

    opened: list[aiohttp.ClientWebSocketResponse] = []
    original = aiohttp.ClientSession.ws_connect

    async def _tracked_ws_connect(self, *args, **kwargs):
        websocket = await original(self, *args, **kwargs)
        opened.append(websocket)
        return websocket

    monkeypatch.setattr(aiohttp.ClientSession, "ws_connect", _tracked_ws_connect)
    try:
        yield
    finally:
        await asyncio.gather(
            *(websocket.close() for websocket in reversed(opened)),
            return_exceptions=True,
        )
        # Let non-TLS transport close callbacks run before pytest closes the
        # owning event loop.
        await asyncio.sleep(0)


class _GateWebSocket:
    def __init__(
        self,
        *,
        gate: asyncio.Event | None = None,
        fail_at: int | None = None,
        on_send: Callable[[bytes], None] | None = None,
    ):
        self.gate = gate
        self.fail_at = fail_at
        self.on_send = on_send
        self.calls = 0
        self.entered = asyncio.Event()

    async def send_bytes(self, data: bytes) -> None:
        self.calls += 1
        self.entered.set()
        if self.gate is not None:
            await self.gate.wait()
        if self.fail_at is not None and self.calls == self.fail_at:
            raise ConnectionResetError(f"injected send failure #{self.calls}")
        if self.on_send is not None:
            self.on_send(data)


class _PacedWebSocket:
    """A WebSocket whose peer must explicitly consume every attempted send."""

    def __init__(self) -> None:
        self.attempted: asyncio.Queue[bytes] = asyncio.Queue()
        self._permits = asyncio.Semaphore(0)
        self.completed: list[bytes] = []

    async def send_bytes(self, data: bytes) -> None:
        await self.attempted.put(data)
        await self._permits.acquire()
        self.completed.append(data)

    def consume_one(self) -> None:
        self._permits.release()


@pytest.mark.asyncio
async def test_nth_send_failure_is_sticky_and_drain_is_a_real_barrier() -> None:
    ws = _GateWebSocket(fail_at=2)
    callback_calls = 0

    async def _closed() -> None:
        nonlocal callback_calls
        callback_calls += 1

    writer = _RelayStreamWriter(  # type: ignore[arg-type]
        ws,
        b"12345678",
        on_close=_closed,
        buffer_limit_bytes=2 * DATA_FRAME_MAX_BYTES + 32,
    )
    writer.write(b"first")
    writer.write(b"second")

    with pytest.raises(RelayTransportError, match="outbound item 2"):
        await writer.drain()
    assert ws.calls == 2
    assert writer.pending_bytes == 0
    assert callback_calls == 1

    # The same terminal condition is visible to all future stream methods;
    # no bytes can be silently accepted after an uncertain send outcome.
    with pytest.raises(RelayTransportError, match="outbound item 2"):
        writer.write(b"must-not-be-accepted")
    with pytest.raises(RelayTransportError, match="outbound item 2"):
        await writer.drain()
    with pytest.raises(RelayTransportError, match="outbound item 2"):
        await writer.wait_closed()
    assert ws.calls == 2
    assert callback_calls == 1


@pytest.mark.asyncio
async def test_slow_websocket_applies_hard_byte_backpressure() -> None:
    gate = asyncio.Event()
    ws = _GateWebSocket(gate=gate)
    limit = DATA_FRAME_MAX_BYTES + 9
    writer = _RelayStreamWriter(  # type: ignore[arg-type]
        ws,
        b"abcdefgh",
        buffer_limit_bytes=limit,
    )
    payload = b"x" * (700 * 1024)

    await writer.wait_writable(len(payload))
    writer.write(payload)
    await ws.entered.wait()
    assert 0 < writer.pending_bytes <= limit

    blocked = asyncio.create_task(writer.wait_writable(len(payload)))
    await asyncio.sleep(0.02)
    assert not blocked.done(), "capacity waiter bypassed a stalled send"
    with pytest.raises(BufferError, match="buffer full"):
        writer.write(payload)

    gate.set()
    await asyncio.wait_for(blocked, timeout=1.0)
    writer.write(payload)
    await writer.drain()
    assert writer.pending_bytes == 0
    writer.close()
    await writer.wait_closed()
    assert ws.calls == 3  # two DATA frames followed by CLOSE


@pytest.mark.asyncio
async def test_sustained_slow_consumer_bounds_transfer_well_beyond_capacity() -> None:
    """A 24 MiB producer stays bounded by a ~1 MiB relay queue."""

    ws = _PacedWebSocket()
    limit = DATA_FRAME_MAX_BYTES + 9
    writer = _RelayStreamWriter(  # type: ignore[arg-type]
        ws,
        b"paceflow",
        buffer_limit_bytes=limit,
    )
    chunk_size = 256 * 1024
    chunk_count = 96
    peak_pending = 0

    async def _produce() -> None:
        nonlocal peak_pending
        for sequence in range(chunk_count):
            payload = struct.pack("!I", sequence) + bytes([sequence % 251]) * (chunk_size - 4)
            await writer.wait_writable(len(payload))
            writer.write(payload)
            peak_pending = max(peak_pending, writer.pending_bytes)
            assert writer.pending_bytes <= limit
        await writer.drain()

    producer = asyncio.create_task(_produce())
    first = await asyncio.wait_for(ws.attempted.get(), timeout=1.0)
    assert decode_frame(first).payload[:4] == struct.pack("!I", 0)
    await asyncio.sleep(0.02)
    assert not producer.done(), "24 MiB producer bypassed the stalled ~1 MiB consumer"
    assert 0 < writer.pending_bytes <= limit

    ws.consume_one()
    for sequence in range(1, chunk_count):
        attempted = await asyncio.wait_for(ws.attempted.get(), timeout=1.0)
        frame = decode_frame(attempted)
        assert frame.type == FRAME_DATA
        assert frame.payload[:4] == struct.pack("!I", sequence)
        # Model a persistently slower peer, not merely a one-shot stall.
        await asyncio.sleep(0.001)
        assert not producer.done()
        assert writer.pending_bytes <= limit
        ws.consume_one()

    await asyncio.wait_for(producer, timeout=1.0)
    assert peak_pending <= limit
    assert writer.pending_bytes == 0
    assert len(ws.completed) == chunk_count

    writer.close()
    close = await asyncio.wait_for(ws.attempted.get(), timeout=1.0)
    assert decode_frame(close).type == FRAME_CLOSE
    ws.consume_one()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_close_flushes_data_then_close_before_callback_and_wait_returns() -> None:
    events: list[str] = []

    def _sent(data: bytes) -> None:
        frame = decode_frame(data)
        events.append("data" if frame.type == FRAME_DATA else "close-frame")

    async def _closed() -> None:
        events.append("close-callback")

    ws = _GateWebSocket(on_send=_sent)
    writer = _RelayStreamWriter(  # type: ignore[arg-type]
        ws,
        b"close123",
        on_close=_closed,
    )
    writer.write(b"one")
    writer.write(b"two")
    writer.close()
    await writer.wait_closed()

    assert events == ["data", "data", "close-frame", "close-callback"]


@pytest.mark.asyncio
async def test_write_after_ordered_close_is_rejected_not_silently_dropped() -> None:
    ws = _GateWebSocket()
    writer = _RelayStreamWriter(ws, b"closed01")  # type: ignore[arg-type]
    writer.close()

    with pytest.raises(ConnectionError, match="closed relay stream"):
        writer.write(b"must never disappear")

    await writer.wait_closed()
    with pytest.raises(ConnectionError, match="closed relay stream"):
        writer.write(b"still closed")
    assert ws.calls == 1


class _CapacityWriter:
    def __init__(self) -> None:
        self.events: list[tuple[str, int]] = []

    async def wait_writable(self, size: int) -> None:
        self.events.append(("wait", size))

    def write(self, data: bytes) -> None:
        assert self.events and self.events[-1][0] == "wait"
        self.events.append(("write", len(data)))

    async def drain(self) -> None:
        return


class _RejectingCapacityWriter(_CapacityWriter):
    async def wait_writable(self, size: int) -> None:
        self.events.append(("wait", size))
        raise BufferError("injected full relay budget")


def _capacity_test_channel(writer: _CapacityWriter) -> Channel:
    return Channel(
        reader=asyncio.StreamReader(),
        writer=writer,  # type: ignore[arg-type]
        peer_ed_pub=b"p" * 32,
        peer_short_id="peer",
        tx_aead=ChaCha20Poly1305(b"t" * 32),
        rx_aead=ChaCha20Poly1305(b"r" * 32),
        transcript_hash=b"h" * 32,
    )


@pytest.mark.asyncio
async def test_channel_legacy_queue_send_uses_optional_capacity_hook() -> None:
    writer = _CapacityWriter()
    channel = _capacity_test_channel(writer)
    plaintext = b"legacy queued payload"

    await channel.queue_send(plaintext)

    assert writer.events == [
        ("wait", len(plaintext) + 16 + 4),
        ("write", len(plaintext) + 16 + 4),
    ]


@pytest.mark.asyncio
async def test_channel_legacy_send_uses_capacity_hook_before_nonce_advance() -> None:
    writer = _CapacityWriter()
    channel = _capacity_test_channel(writer)
    plaintext = b"ordinary control payload"

    await channel.send(plaintext)

    assert channel.tx_seq == 1
    assert writer.events == [
        ("wait", len(plaintext) + 16 + 4),
        ("write", len(plaintext) + 16 + 4),
    ]


@pytest.mark.asyncio
async def test_channel_legacy_send_does_not_advance_nonce_when_capacity_fails() -> None:
    writer = _RejectingCapacityWriter()
    channel = _capacity_test_channel(writer)

    with pytest.raises(BufferError, match="full relay budget"):
        await channel.send(b"blocked")

    assert channel.tx_seq == 0
    assert writer.events == [("wait", len(b"blocked") + 16 + 4)]


@pytest.mark.asyncio
async def test_control_send_backpressures_behind_full_file_queue() -> None:
    gate = asyncio.Event()
    ws = _GateWebSocket(gate=gate)
    relay_writer = _RelayStreamWriter(  # type: ignore[arg-type]
        ws,
        b"control1",
        buffer_limit_bytes=DATA_FRAME_MAX_BYTES + 9,
    )
    channel = _capacity_test_channel(relay_writer)  # type: ignore[arg-type]
    queued_file_payload = b"q" * (DATA_FRAME_MAX_BYTES - 64)

    await channel.queue_send(queued_file_payload)
    await ws.entered.wait()
    assert channel.tx_seq == 1

    control = asyncio.create_task(channel.send(b"p" * 256))
    await asyncio.sleep(0.02)
    assert not control.done()
    # Capacity is awaited before nonce selection/encryption, so a blocked
    # concurrent control frame cannot consume a sequence number.
    assert channel.tx_seq == 1

    gate.set()
    await asyncio.wait_for(control, timeout=1.0)
    assert channel.tx_seq == 2
    relay_writer.close()
    await relay_writer.wait_closed()


@pytest.mark.asyncio
async def test_channel_ratchet_queue_send_uses_optional_capacity_hook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _CapacityWriter()
    channel = _capacity_test_channel(writer)

    class _RatchetState:
        send_chain_key = b"ready"

    class _Header:
        def encode(self) -> bytes:
            return b"h" * DR_HEADER_LEN

    def _encrypt(_state, plaintext: bytes, *, ad: bytes):
        assert ad == b"h" * 32
        return _Header(), plaintext + b"t" * 16

    monkeypatch.setattr(double_ratchet, "encrypt", _encrypt)
    channel._dr_state = _RatchetState()  # type: ignore[assignment]
    plaintext = b"ratcheted queued payload"

    await channel.queue_send(plaintext)

    framed = len(plaintext) + DR_HEADER_LEN + 16 + 4
    assert writer.events == [("wait", framed), ("write", framed)]


@pytest.mark.asyncio
async def test_channel_ratchet_send_uses_capacity_hook_before_ratchet_advance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _CapacityWriter()
    channel = _capacity_test_channel(writer)

    class _RatchetState:
        send_chain_key = b"ready"

    class _Header:
        def encode(self) -> bytes:
            return b"h" * DR_HEADER_LEN

    encrypt_calls = 0

    def _encrypt(_state, plaintext: bytes, *, ad: bytes):
        nonlocal encrypt_calls
        encrypt_calls += 1
        assert ad == b"h" * 32
        return _Header(), plaintext + b"t" * 16

    monkeypatch.setattr(double_ratchet, "encrypt", _encrypt)
    channel._dr_state = _RatchetState()  # type: ignore[assignment]
    plaintext = b"ordinary ratcheted control payload"

    await channel.send(plaintext)

    framed = len(plaintext) + DR_HEADER_LEN + 16 + 4
    assert encrypt_calls == 1
    assert writer.events == [("wait", framed), ("write", framed)]


@pytest.mark.asyncio
async def test_channel_ratchet_send_does_not_advance_when_capacity_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _RejectingCapacityWriter()
    channel = _capacity_test_channel(writer)

    class _RatchetState:
        send_chain_key = b"ready"

    encrypt_calls = 0

    def _encrypt(*_args, **_kwargs):
        nonlocal encrypt_calls
        encrypt_calls += 1
        raise AssertionError("ratchet advanced before capacity was available")

    monkeypatch.setattr(double_ratchet, "encrypt", _encrypt)
    channel._dr_state = _RatchetState()  # type: ignore[assignment]

    with pytest.raises(BufferError, match="full relay budget"):
        await channel.send(b"blocked ratchet")

    assert encrypt_calls == 0


class _ListenerClientWebSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send_bytes(self, data: bytes) -> None:
        self.sent.append(data)


class _GatedListenerClientWebSocket:
    def __init__(self) -> None:
        self.attempted: asyncio.Queue[bytes] = asyncio.Queue()
        self.permits = asyncio.Semaphore(0)
        self.sent: list[bytes] = []
        self.closed = False

    async def send_bytes(self, data: bytes) -> None:
        await self.attempted.put(data)
        await self.permits.acquire()
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_listener_adversarial_feed_delay_preserves_data_then_eof() -> None:
    delivered: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def _on_session(reader, _writer) -> None:
        out = await reader.readexactly(6)
        assert await reader.read(1) == b""
        delivered.set_result(out)

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
    )
    listener._ws = _ListenerClientWebSocket()  # type: ignore[assignment]
    sid = b"order123"
    await listener._open_inbound_session(sid)
    active = listener._active[sid]
    original_feed = active.reader.feed

    async def _delayed_first(
        data: bytes,
        *,
        budget_reserved: bool = False,
    ) -> None:
        if data == b"abc":
            await asyncio.sleep(0.05)
        await original_feed(data, budget_reserved=budget_reserved)

    active.reader.feed = _delayed_first  # type: ignore[method-assign]

    # The old implementation created three independent tasks here.  Under
    # this delay, EOF or "def" could overtake "abc".  The per-session worker
    # now serializes the exact WebSocket arrival order.
    await listener._handle_data(encode_data_frame(sid, b"abc"))
    await listener._handle_data(encode_data_frame(sid, b"def"))
    await listener._handle_data(encode_close_frame(sid))
    assert await asyncio.wait_for(delivered, timeout=1.0) == b"abcdef"
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))
    assert listener.aggregate_buffered_bytes == 0
    assert listener.aggregate_peak_buffered_bytes <= RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES


@pytest.mark.asyncio
async def test_listener_enforces_local_active_session_cap() -> None:
    hold = asyncio.Event()

    async def _on_session(_reader, _writer) -> None:
        await hold.wait()

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
        max_active_sessions=2,
    )
    ws = _ListenerClientWebSocket()
    listener._ws = ws  # type: ignore[assignment]
    await listener._open_inbound_session(b"session1")
    await listener._open_inbound_session(b"session2")
    await listener._open_inbound_session(b"session3")
    await listener._wait_for_control_outbox_idle()

    assert set(listener._active) == {b"session1", b"session2"}
    assert len(ws.sent) == 1
    refused = decode_frame(ws.sent[0])
    assert refused.type == FRAME_CLOSE
    assert refused.session_id == b"session3"
    hold.set()
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))


@pytest.mark.asyncio
async def test_cap_refusals_use_one_bounded_ordered_off_loop_control_sender() -> None:
    hold = asyncio.Event()

    async def _on_session(_reader, _writer) -> None:
        await hold.wait()

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
        max_active_sessions=1,
    )
    ws = _GatedListenerClientWebSocket()
    listener._ws = ws  # type: ignore[assignment]
    outbox = _RelayControlOutbox(  # type: ignore[arg-type]
        ws,
        buffer_limit_bytes=128,
        queue_max_items=5,
    )
    listener._control_outbox = outbox
    await listener._open_inbound_session(b"active01")

    refused = [b"refuse01", b"refuse02", b"refuse03"]
    for sid in refused:
        await asyncio.wait_for(listener._open_inbound_session(sid), timeout=0.05)
    assert listener.admission_occupancy == 1
    assert not listener._session_teardown_tasks
    assert outbox.pending_items == len(refused)
    assert outbox.pending_bytes == 9 * len(refused)

    # Only the single outbox worker touches the socket, and the slow first
    # refusal did not block parsing/admission of the next two controls.
    for expected_sid in refused:
        attempted = await asyncio.wait_for(ws.attempted.get(), timeout=1.0)
        assert decode_frame(attempted).session_id == expected_sid
        ws.permits.release()
    await outbox.wait_idle()
    assert [decode_frame(frame).session_id for frame in ws.sent] == refused

    hold.set()
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))


@pytest.mark.asyncio
async def test_control_outbox_overload_is_bounded_and_fails_listener_closed() -> None:
    ws = _GatedListenerClientWebSocket()
    outbox = _RelayControlOutbox(  # type: ignore[arg-type]
        ws,
        buffer_limit_bytes=9,
        queue_max_items=2,
    )
    assert outbox.try_send(encode_close_frame(b"refuse01"))
    await asyncio.wait_for(ws.attempted.get(), timeout=1.0)
    assert outbox.pending_items == 1

    assert not outbox.try_send(encode_close_frame(b"refuse02"))
    await asyncio.sleep(0)
    assert outbox.pending_items == 0
    assert outbox.pending_bytes == 0
    assert ws.closed
    await outbox.abort()


@pytest.mark.asyncio
async def test_teardown_work_counts_against_listener_session_admission_cap() -> None:
    hold_handler = asyncio.Event()

    async def _on_session(_reader, _writer) -> None:
        await hold_handler.wait()

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
        max_active_sessions=1,
    )
    ws = _ListenerClientWebSocket()
    listener._ws = ws  # type: ignore[assignment]
    first_sid = b"teardown"
    await listener._open_inbound_session(first_sid)
    active = listener._active[first_sid]
    entered = asyncio.Event()
    release = asyncio.Event()
    original_abort = active.writer.abort

    async def _slow_abort(exc=None) -> None:
        entered.set()
        await release.wait()
        await original_abort(exc)

    active.writer.abort = _slow_abort  # type: ignore[method-assign]
    listener._schedule_overloaded_session_teardown(active, reason="injected teardown")
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    assert not listener._active
    assert listener.admission_occupancy == 1

    await listener._open_inbound_session(b"newslot1")
    await listener._wait_for_control_outbox_idle()
    assert b"newslot1" not in listener._active
    assert decode_frame(ws.sent[-1]).session_id == b"newslot1"

    release.set()
    await listener._wait_for_session_teardowns()
    assert listener.admission_occupancy == 0
    hold_handler.set()
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))


@pytest.mark.asyncio
async def test_overloaded_session_cannot_head_of_line_block_healthy_session() -> None:
    """One non-reader is evicted while another multiplexed session advances."""
    malicious_reader = None
    healthy_reader = None
    malicious_handler = asyncio.Event()
    healthy_payload: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    async def _on_session(reader, _writer) -> None:
        if reader is malicious_reader:
            await malicious_handler.wait()
            return
        if reader is healthy_reader:
            healthy_payload.set_result(await reader.readexactly(7))

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
    )
    ws = _ListenerClientWebSocket()
    listener._ws = ws  # type: ignore[assignment]
    malicious_sid = b"stalled1"
    healthy_sid = b"healthy1"
    await listener._open_inbound_session(malicious_sid)
    malicious_reader = listener._active[malicious_sid].reader
    await listener._open_inbound_session(healthy_sid)
    healthy_reader = listener._active[healthy_sid].reader

    # Hold the malicious session's worker inside reader.feed.  Its bounded
    # inbound queue can fill, but listener._handle_data must never wait for it.
    stalled_feed_entered = asyncio.Event()
    never_release = asyncio.Event()

    async def _stalled_feed(
        _data: bytes,
        *,
        budget_reserved: bool = False,
    ) -> None:
        assert budget_reserved
        stalled_feed_entered.set()
        await never_release.wait()

    malicious_reader.feed = _stalled_feed  # type: ignore[method-assign]
    full_frame = b"x" * DATA_FRAME_MAX_BYTES
    await listener._handle_data(encode_data_frame(malicious_sid, full_frame))
    await asyncio.wait_for(stalled_feed_entered.wait(), timeout=1.0)
    # The in-flight frame remains accounted until reader.feed completes. Add
    # three more to reach the 4 MiB session ceiling, then one to trigger the
    # non-blocking overload path.
    for _ in range(3):
        await listener._handle_data(encode_data_frame(malicious_sid, full_frame))
    await asyncio.wait_for(
        listener._handle_data(encode_data_frame(malicious_sid, b"overflow")),
        timeout=0.1,
    )
    assert malicious_sid not in listener._active

    # A frame for a separate session is admitted and consumed immediately;
    # the malicious session's asynchronous teardown is not on this path.
    await asyncio.wait_for(
        listener._handle_data(encode_data_frame(healthy_sid, b"healthy")),
        timeout=0.1,
    )
    assert await asyncio.wait_for(healthy_payload, timeout=1.0) == b"healthy"

    await listener._wait_for_session_teardowns()
    overload_closes = [
        decode_frame(raw) for raw in ws.sent if decode_frame(raw).session_id == malicious_sid
    ]
    assert [frame.type for frame in overload_closes] == [FRAME_CLOSE]
    assert listener.aggregate_buffered_bytes == 0
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))


@pytest.mark.asyncio
async def test_listener_shared_budget_evicts_largest_borrower_not_zero_byte_arrival() -> None:
    hold = asyncio.Event()

    async def _on_session(_reader, _writer) -> None:
        await hold.wait()

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    # The listener requires room for simultaneous directions, but inbound
    # headroom leaves exactly one maximum DATA frame available here.
    aggregate_limit = 2 * DATA_FRAME_MAX_BYTES + 9
    listener = RelayListenerClient(
        rendezvous_url="http://unused.invalid",
        private_key=key,
        pubkey=pub,
        on_session=_on_session,
        aggregate_buffer_limit_bytes=aggregate_limit,
    )
    listener._ws = _ListenerClientWebSocket()  # type: ignore[assignment]
    first_sid = b"budget01"
    second_sid = b"budget02"
    await listener._open_inbound_session(first_sid)
    await listener._open_inbound_session(second_sid)

    payload = b"b" * DATA_FRAME_MAX_BYTES
    await listener._handle_data(encode_data_frame(first_sid, payload))
    # No reader consumption is required before the second session is handled.
    # Its reservation cannot fit. The first session is the deterministic
    # 1 MiB borrower; the zero-byte arriving session must not be sacrificed.
    await asyncio.wait_for(
        listener._handle_data(encode_data_frame(second_sid, payload)),
        timeout=0.1,
    )
    await listener._wait_for_session_teardowns()
    assert first_sid not in listener._active
    assert second_sid in listener._active
    assert not listener._active[second_sid].admission_paused
    assert listener._memory_budget.used_by(listener._active[second_sid].budget_owner) == len(
        payload
    )
    assert listener.aggregate_peak_buffered_bytes <= aggregate_limit

    hold.set()
    await listener._shutdown_active_sessions(ConnectionResetError("test cleanup"))
    assert listener.aggregate_buffered_bytes == 0


@pytest.mark.asyncio
async def test_inbound_flow_backpressures_at_combined_byte_ceiling() -> None:
    reader = _RelayStreamReader()
    flow = _OrderedInboundFlow(
        reader,
        queue_limit_bytes=DATA_FRAME_MAX_BYTES,
        queue_max_items=4,
    )
    payload = b"z" * DATA_FRAME_MAX_BYTES

    # Four frames fill the reader.  The fifth is held by the ordered worker,
    # so the queue's one-frame byte budget is full as well.
    for _ in range(5):
        await flow.feed(payload)
    for _ in range(100):
        if flow.queued_bytes == DATA_FRAME_MAX_BYTES:
            break
        await asyncio.sleep(0)
    assert flow.queued_bytes == DATA_FRAME_MAX_BYTES

    sixth = asyncio.create_task(flow.feed(payload))
    await asyncio.sleep(0.02)
    assert not sixth.done(), "inbound producer bypassed its byte ceiling"

    # Reading one frame lets the worker publish frame five and admits frame
    # six.  DATA order and EOF remain serialized by the same worker.
    assert await reader.readexactly(DATA_FRAME_MAX_BYTES) == payload
    await asyncio.wait_for(sixth, timeout=1.0)
    await flow.feed_eof()
    assert await reader.readexactly(5 * DATA_FRAME_MAX_BYTES) == payload * 5
    assert await reader.read(1) == b""
    await flow.wait_closed()


@pytest.mark.asyncio
async def test_listener_shared_budget_bounds_writers_across_sessions() -> None:
    gate = asyncio.Event()
    budget_limit = 2 * DATA_FRAME_MAX_BYTES + 64
    budget = _SharedByteBudget(budget_limit)
    first_ws = _GateWebSocket(gate=gate)
    second_ws = _GateWebSocket(gate=gate)
    first = _RelayStreamWriter(  # type: ignore[arg-type]
        first_ws,
        b"budget01",
        shared_budget=budget,
    )
    second = _RelayStreamWriter(  # type: ignore[arg-type]
        second_ws,
        b"budget02",
        shared_budget=budget,
    )
    payload = b"b" * (DATA_FRAME_MAX_BYTES + DATA_FRAME_MAX_BYTES // 2)

    await first.wait_writable(len(payload))
    first.write(payload)
    await first_ws.entered.wait()
    second_capacity = asyncio.create_task(second.wait_writable(len(payload)))
    await asyncio.sleep(0.02)
    assert not second_capacity.done()
    assert budget.used_bytes <= budget_limit
    assert budget.peak_bytes <= budget_limit

    gate.set()
    await asyncio.wait_for(second_capacity, timeout=1.0)
    second.write(payload)
    await asyncio.gather(first.drain(), second.drain())
    first.close()
    second.close()
    await asyncio.gather(first.wait_closed(), second.wait_closed())
    assert budget.used_bytes == 0
    assert RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES == 64 * 1024 * 1024


@pytest.mark.asyncio
async def test_listener_budget_reserves_outbound_ack_headroom() -> None:
    total = RELAY_LISTENER_AGGREGATE_BUFFER_LIMIT_BYTES
    headroom = RELAY_LISTENER_OUTBOUND_HEADROOM_BYTES
    budget = _SharedByteBudget(total)
    inbound_limit = total - headroom
    await budget.reserve(inbound_limit, headroom_bytes=headroom)

    more_inbound = asyncio.create_task(budget.reserve(1, headroom_bytes=headroom))
    await asyncio.sleep(0)
    assert not more_inbound.done()
    # ACK/control/file-response writers do not apply inbound headroom and can
    # therefore make progress that eventually drains the inbound sender.
    assert budget.try_reserve(headroom)
    assert budget.used_bytes == total
    budget.release_nowait(headroom)
    budget.release_nowait(inbound_limit)
    await asyncio.wait_for(more_inbound, timeout=1.0)
    budget.release_nowait(1)
    assert budget.used_bytes == 0


@pytest.mark.asyncio
async def test_listener_shared_budget_bounds_inbound_queues_and_readers() -> None:
    budget_limit = 2 * DATA_FRAME_MAX_BYTES + 32
    budget = _SharedByteBudget(budget_limit)
    reader_a = _RelayStreamReader(shared_budget=budget)
    reader_b = _RelayStreamReader(shared_budget=budget)
    flow_a = _OrderedInboundFlow(reader_a, shared_budget=budget)
    flow_b = _OrderedInboundFlow(reader_b, shared_budget=budget)
    payload = b"i" * DATA_FRAME_MAX_BYTES

    await flow_a.feed(payload)
    await flow_b.feed(payload)
    for _ in range(100):
        if budget.used_bytes == 2 * DATA_FRAME_MAX_BYTES:
            break
        await asyncio.sleep(0)
    assert budget.used_bytes == 2 * DATA_FRAME_MAX_BYTES

    blocked = asyncio.create_task(flow_a.feed(payload))
    await asyncio.sleep(0.02)
    assert not blocked.done()
    assert budget.peak_bytes <= budget_limit
    assert await reader_a.readexactly(DATA_FRAME_MAX_BYTES) == payload
    await asyncio.wait_for(blocked, timeout=1.0)

    await flow_a.feed_eof()
    await flow_b.feed_eof()
    assert await reader_a.readexactly(DATA_FRAME_MAX_BYTES) == payload
    assert await reader_b.readexactly(DATA_FRAME_MAX_BYTES) == payload
    assert await reader_a.read(1) == b""
    assert await reader_b.read(1) == b""
    await asyncio.gather(flow_a.wait_closed(), flow_b.wait_closed())
    assert budget.used_bytes == 0


@pytest.mark.asyncio
async def test_inbound_worker_failure_is_sticky_and_wakes_capacity_waiters() -> None:
    budget = _SharedByteBudget(DATA_FRAME_MAX_BYTES + 9)
    reader = _RelayStreamReader(shared_budget=budget)
    flow = _OrderedInboundFlow(
        reader,
        queue_limit_bytes=2 * DATA_FRAME_MAX_BYTES,
        shared_budget=budget,
    )
    entered = asyncio.Event()
    fail_now = asyncio.Event()

    async def _failing_feed(
        _data: bytes,
        *,
        budget_reserved: bool = False,
    ) -> None:
        assert budget_reserved
        entered.set()
        await fail_now.wait()
        raise OSError("injected reader failure")

    reader.feed = _failing_feed  # type: ignore[method-assign]
    payload = b"f" * DATA_FRAME_MAX_BYTES
    await flow.feed(payload)
    await entered.wait()
    capacity_waiter = asyncio.create_task(flow.feed(payload))
    await asyncio.sleep(0.02)
    assert not capacity_waiter.done()

    fail_now.set()
    with pytest.raises(RelayTransportError, match="injected reader failure"):
        await asyncio.wait_for(capacity_waiter, timeout=1.0)
    with pytest.raises(RelayTransportError, match="injected reader failure"):
        await flow.wait_closed()
    with pytest.raises(RelayTransportError, match="injected reader failure"):
        await flow.feed(b"later")
    assert reader.at_eof()
    assert flow.queued_bytes == 0
    assert budget.used_bytes == 0


@pytest.mark.asyncio
async def test_unexpected_inbound_worker_cancellation_releases_every_budget_token() -> None:
    budget = _SharedByteBudget(2 * DATA_FRAME_MAX_BYTES + 9)
    owner = object()
    reader = _RelayStreamReader(shared_budget=budget, shared_budget_owner=owner)
    flow = _OrderedInboundFlow(
        reader,
        shared_budget=budget,
        shared_budget_owner=owner,
    )
    entered = asyncio.Event()
    never = asyncio.Event()

    async def _stalled_feed(
        _data: bytes,
        *,
        budget_reserved: bool = False,
    ) -> None:
        assert budget_reserved
        entered.set()
        await never.wait()

    reader.feed = _stalled_feed  # type: ignore[method-assign]
    payload = b"c" * DATA_FRAME_MAX_BYTES
    assert flow.try_feed(payload)
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    assert budget.used_by(owner) == len(payload)

    flow._worker_task.cancel()
    with pytest.raises(RelayTransportError, match="worker was cancelled"):
        await flow.wait_closed()
    assert flow.queued_bytes == 0
    assert budget.used_by(owner) == 0
    assert budget.used_bytes == 0
    assert reader.at_eof()


@pytest.mark.asyncio
async def test_server_process_budget_tracks_queue_current_control_and_cancellation() -> None:
    gate = asyncio.Event()
    entered = asyncio.Event()

    async def _send(_frame: bytes) -> None:
        entered.set()
        await gate.wait()

    owner = object()
    budget = _RelayForwardBudget(limit_bytes=1024, control_reserve_bytes=128)
    queue = _RelayForwardQueue(
        _send,
        timeout_s=1.0,
        buffer_limit_bytes=512,
        queue_max_items=4,
        on_sent=lambda _payload_bytes: None,
        process_budget=budget,
        budget_owner=owner,
    )
    first = b"a" * 100
    second = b"b" * 120
    first_lease = budget.try_acquire(len(first), owner=owner, category="current")
    second_lease = budget.try_acquire(len(second), owner=owner, category="current")
    assert first_lease is not None
    assert second_lease is not None
    assert queue.try_enqueue(first, payload_bytes=91, current_lease=first_lease) == "accepted"
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    assert queue.try_enqueue(second, payload_bytes=111, current_lease=second_lease) == "accepted"

    control = budget.try_acquire(7, owner=owner, category="control")
    teardown = budget.try_acquire(9, owner=owner, category="teardown")
    assert control is not None
    assert teardown is not None
    snapshot = budget.snapshot()
    assert snapshot["used_bytes"] == 236
    assert snapshot["current_bytes"] == 100
    assert snapshot["queued_bytes"] == 120
    assert snapshot["control_bytes"] == 7
    assert snapshot["teardown_bytes"] == 9
    assert snapshot["active_leases"] == 4
    assert snapshot["active_owners"] == 1
    assert snapshot["largest_owner_bytes"] == 236

    assert control.release()
    assert not control.release(), "lease release must be idempotent"
    assert teardown.release()
    # Cancellation owns both the currently sending frame and queued frame;
    # abort must release both exact leases without waiting for the socket.
    await queue.abort()
    assert first_lease.released
    assert second_lease.released
    drained = budget.snapshot()
    assert drained["used_bytes"] == 0
    assert drained["active_leases"] == 0
    assert drained["current_bytes"] == 0
    assert drained["queued_bytes"] == 0
    assert drained["control_bytes"] == 0
    assert drained["teardown_bytes"] == 0
    assert drained["peak_bytes"] == 236


@pytest.mark.asyncio
async def test_server_control_payload_has_one_exact_process_budget_lease() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()
    sent: list[str] = []

    class _TextGate:
        async def send_str(self, text: str) -> None:
            sent.append(text)
            entered.set()
            await release.wait()

    rdz = RendezvousApp(ServerConfig())
    owner = object()
    message: dict[str, object] = {"t": "ready", "session_id": "0102030405060708"}
    task = asyncio.create_task(
        rdz._send_relay_json(  # type: ignore[arg-type]
            _TextGate(),
            message,
            owner=owner,
            category="control",
            operation="test gated control",
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    assert len(sent) == 1
    snapshot = rdz._relay_forward_budget.snapshot()
    assert snapshot["used_bytes"] == len(sent[0])
    assert snapshot["control_bytes"] == len(sent[0])
    assert snapshot["active_leases"] == 1
    assert snapshot["active_owners"] == 1
    assert snapshot["queued_bytes"] == 0
    assert snapshot["current_bytes"] == 0
    assert snapshot["teardown_bytes"] == 0

    release.set()
    await asyncio.wait_for(task, timeout=1.0)
    assert rdz._relay_forward_budget.used_bytes == 0
    assert rdz._relay_forward_budget.active_leases == 0


def test_server_process_budget_preserves_teardown_tail_at_data_saturation() -> None:
    owner = object()
    budget = _RelayForwardBudget(limit_bytes=100, control_reserve_bytes=20)
    with pytest.raises(ValueError, match="owner must be hashable"):
        budget.try_acquire(1, owner=[], category="current")
    assert budget.used_bytes == 0
    assert budget.active_leases == 0
    data = budget.try_acquire(80, owner=owner, category="queued")
    assert data is not None
    assert budget.try_acquire(1, owner=owner, category="current") is None

    # DATA saturation cannot consume the control tail. Teardown can use all
    # of it, but never one byte beyond the hard process ceiling.
    teardown = budget.try_acquire(20, owner=owner, category="teardown")
    assert teardown is not None
    assert budget.used_bytes == budget.limit_bytes == 100
    assert budget.try_acquire(1, owner=owner, category="control") is None
    snapshot = budget.snapshot()
    assert snapshot["data_denials_total"] == 1
    assert snapshot["control_denials_total"] == 1
    assert snapshot["peak_bytes"] == snapshot["limit_bytes"]

    assert teardown.release()
    assert data.release()
    assert budget.used_bytes == 0
    assert budget.active_leases == 0


@pytest.mark.asyncio
async def test_server_control_budget_overload_is_fail_fast_and_observable() -> None:
    class _MustNotSend:
        async def send_str(self, _text: str) -> None:
            raise AssertionError("control write started without a budget lease")

    rdz = RendezvousApp(ServerConfig())
    rdz._relay_forward_budget = _RelayForwardBudget(
        limit_bytes=100,
        control_reserve_bytes=20,
    )
    owner = object()
    data = rdz._relay_forward_budget.try_acquire(
        80,
        owner=owner,
        category="queued",
    )
    reserved_control = rdz._relay_forward_budget.try_acquire(
        20,
        owner=owner,
        category="control",
    )
    assert data is not None
    assert reserved_control is not None

    with pytest.raises(BufferError, match="process-wide relay forwarding"):
        await rdz._send_relay_json(  # type: ignore[arg-type]
            _MustNotSend(),
            {"t": "ready"},
            owner=object(),
            category="control",
            operation="must not start",
        )
    assert rdz.metrics.relay_forward_overloads_total == 1
    assert rdz.metrics.relay_forward_global_overloads_total == 1
    assert rdz.metrics.relay_forward_global_control_overloads_total == 1
    assert rdz._relay_forward_budget.control_denials_total == 1
    assert reserved_control.release()
    assert data.release()
    assert rdz._relay_forward_budget.used_bytes == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["--relay-max-sessions-per-listener", "0"],
        ["--relay-max-route-keys", "0"],
        ["--relay-forward-timeout-s", "nan"],
        ["--relay-session-idle-s", "inf"],
        ["--relay-forward-queue-max-items", "1"],
        ["--relay-forward-global-budget-bytes", "0"],
        ["--relay-forward-control-reserve-bytes", "4095"],
        [
            "--relay-forward-global-budget-bytes",
            str(8 * 1024 * 1024),
            "--relay-forward-control-reserve-bytes",
            str(8 * 1024 * 1024),
        ],
        [
            "--relay-forward-global-budget-bytes",
            str(6 * 1024 * 1024),
            "--relay-forward-control-reserve-bytes",
            str(4 * 1024 * 1024),
        ],
    ],
)
def test_server_relay_budget_cli_rejects_unsafe_config(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as rejected:
        _parse_args(argv)
    assert rejected.value.code == 2


async def _start_server(
    *,
    idle_s: float = 300.0,
    max_sessions: int = 32,
    forward_queue_limit_bytes: int = 4 * (DATA_FRAME_MAX_BYTES + 9),
    forward_timeout_s: float = 0.5,
    forward_global_budget_bytes: int = 128 * 1024 * 1024,
    forward_control_reserve_bytes: int = 4 * 1024 * 1024,
) -> tuple[str, RendezvousApp, web.AppRunner]:
    rdz = RendezvousApp(
        ServerConfig(
            host="127.0.0.1",
            port=0,
            enable_relay=True,
            rate_per_ip_per_min=10_000,
            relay_connect_per_ip_per_min=10_000,
            relay_max_sessions_per_listener=max_sessions,
            relay_session_idle_s=idle_s,
            relay_forward_timeout_s=forward_timeout_s,
            relay_forward_queue_limit_bytes=forward_queue_limit_bytes,
            relay_forward_global_budget_bytes=forward_global_budget_bytes,
            relay_forward_control_reserve_bytes=forward_control_reserve_bytes,
            eviction_interval_s=0.05,
        )
    )
    runner = web.AppRunner(rdz.make_app())
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", rdz, runner


async def _cleanup_server(runner: web.AppRunner) -> None:
    """Close the server and let aiohttp's plain-TCP callbacks drain."""
    await runner.cleanup()
    # aiohttp releases non-TLS transports through callbacks scheduled by
    # cleanup.  Returning directly lets pytest collect Connection wrappers
    # before those callbacks run, misattributing ResourceWarning to a later
    # test on Windows' proactor loop.
    await asyncio.sleep(0)


@pytest_asyncio.fixture
async def relay_server() -> AsyncIterator[tuple[str, RendezvousApp]]:
    base, rdz, runner = await _start_server()
    try:
        yield base, rdz
    finally:
        await _cleanup_server(runner)


async def _open_server_session(
    base: str,
    session: aiohttp.ClientSession,
) -> tuple[
    bytes,
    aiohttp.ClientWebSocketResponse,
    aiohttp.ClientWebSocketResponse,
    bytes,
]:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    listener = await session.ws_connect(f"{base}/api/v1/relay/listen")
    await listener.send_json(sign_listen_auth(private_key=key, pubkey=pub).to_wire())
    connector = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
    incoming = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
    ready = await asyncio.wait_for(connector.receive_json(), timeout=1.0)
    sid = parse_session_id_from_msg(incoming)
    assert parse_session_id_from_msg(ready) == sid
    return pub, listener, connector, sid


@pytest.mark.asyncio
async def test_server_shutdown_closes_live_relay_transports_and_registry() -> None:
    """Runner cleanup must not leave active WebSockets to finalizers."""

    base, rdz, runner = await _start_server()
    session = aiohttp.ClientSession()
    listener: aiohttp.ClientWebSocketResponse | None = None
    connector: aiohttp.ClientWebSocketResponse | None = None
    try:
        pub, listener, connector, sid = await _open_server_session(base, session)
        assert sid in rdz._relay_listeners[pub].sessions

        await runner.cleanup()

        assert not rdz._relay_listeners
        assert not rdz._relay_teardown_tasks
        assert rdz._relay_forward_budget.used_bytes == 0
    finally:
        if connector is not None:
            await connector.close()
        if listener is not None:
            await listener.close()
        await session.close()


@pytest.mark.asyncio
async def test_server_slow_connector_cannot_block_other_listener_sessions(
    relay_server: tuple[str, RendezvousApp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz = relay_server
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    async with aiohttp.ClientSession() as session:
        listener = await session.ws_connect(f"{base}/api/v1/relay/listen")
        await listener.send_json(sign_listen_auth(private_key=key, pubkey=pub).to_wire())
        slow_connector = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
        slow_incoming = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
        slow_ready = await asyncio.wait_for(slow_connector.receive_json(), timeout=1.0)
        slow_sid = parse_session_id_from_msg(slow_incoming)
        assert parse_session_id_from_msg(slow_ready) == slow_sid

        fast_connector = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
        fast_incoming = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
        fast_ready = await asyncio.wait_for(fast_connector.receive_json(), timeout=1.0)
        fast_sid = parse_session_id_from_msg(fast_incoming)
        assert parse_session_id_from_msg(fast_ready) == fast_sid

        slow_server_ws = rdz._relay_listeners[pub].sessions[slow_sid].connector_ws
        original = web.WebSocketResponse.send_bytes
        slow_send_entered = asyncio.Event()
        release_slow_send = asyncio.Event()

        async def _gate_one_connector(self, data, *args, **kwargs):
            if self is slow_server_ws and decode_frame(data).type == FRAME_DATA:
                slow_send_entered.set()
                await release_slow_send.wait()
            return await original(self, data, *args, **kwargs)

        monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _gate_one_connector)
        await listener.send_bytes(encode_data_frame(slow_sid, b"stalled"))
        await asyncio.wait_for(slow_send_entered.wait(), timeout=1.0)

        # This frame arrives on the same multiplexed listener WebSocket. It
        # must reach its independent connector while the first send is stuck.
        await listener.send_bytes(encode_data_frame(fast_sid, b"healthy"))
        healthy = await asyncio.wait_for(fast_connector.receive(), timeout=0.2)
        assert healthy.type == aiohttp.WSMsgType.BINARY
        assert decode_frame(healthy.data).payload == b"healthy"

        release_slow_send.set()
        stalled = await asyncio.wait_for(slow_connector.receive(), timeout=1.0)
        assert decode_frame(stalled.data).payload == b"stalled"
        assert set(rdz._relay_listeners[pub].sessions) == {slow_sid, fast_sid}


@pytest.mark.asyncio
async def test_server_connector_forward_accounts_received_and_rewritten_copies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server()
    release_send = asyncio.Event()
    try:
        async with aiohttp.ClientSession() as session:
            pub, listener, connector, sid = await _open_server_session(base, session)
            server_listener_ws = rdz._relay_listeners[pub].ws
            original = web.WebSocketResponse.send_bytes
            entered = asyncio.Event()

            async def _hold_listener_data(self, data, *args, **kwargs):
                if self is server_listener_ws and decode_frame(data).type == FRAME_DATA:
                    entered.set()
                    await release_send.wait()
                return await original(self, data, *args, **kwargs)

            monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _hold_listener_data)
            payload = b"d" * DATA_FRAME_MAX_BYTES
            await connector.send_bytes(encode_data_frame(sid, payload))
            await asyncio.wait_for(entered.wait(), timeout=1.0)

            wire_bytes = DATA_FRAME_MAX_BYTES + 9
            snapshot = rdz._relay_forward_budget.snapshot()
            assert snapshot["used_bytes"] == 2 * wire_bytes
            assert snapshot["current_bytes"] == 2 * wire_bytes
            assert snapshot["queued_bytes"] == 0
            assert snapshot["active_leases"] == 2
            assert snapshot["active_owners"] == 1
            assert snapshot["largest_owner_bytes"] == 2 * wire_bytes
            assert snapshot["peak_bytes"] <= snapshot["limit_bytes"]

            release_send.set()
            delivered = await asyncio.wait_for(listener.receive(), timeout=1.0)
            assert delivered.type == aiohttp.WSMsgType.BINARY
            assert decode_frame(delivered.data).payload == payload
            for _ in range(100):
                if rdz._relay_forward_budget.used_bytes == 0:
                    break
                await asyncio.sleep(0)
            assert rdz._relay_forward_budget.used_bytes == 0
    finally:
        release_send.set()
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_global_budget_is_shared_across_distinct_listeners(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wire_bytes = DATA_FRAME_MAX_BYTES + 9
    control_reserve = 4 * 1024
    base, rdz, runner = await _start_server(
        forward_queue_limit_bytes=wire_bytes,
        forward_global_budget_bytes=3 * wire_bytes + control_reserve,
        forward_control_reserve_bytes=control_reserve,
    )
    release_sends = asyncio.Event()
    try:
        async with aiohttp.ClientSession() as session:
            established = [await _open_server_session(base, session) for _ in range(3)]
            server_connectors = {
                rdz._relay_listeners[pub].sessions[sid].connector_ws
                for pub, _listener, _connector, sid in established
            }
            original = web.WebSocketResponse.send_bytes
            entered_count = 0
            all_entered = asyncio.Event()

            async def _hold_three_connectors(self, data, *args, **kwargs):
                nonlocal entered_count
                if self in server_connectors and decode_frame(data).type == FRAME_DATA:
                    entered_count += 1
                    if entered_count == 3:
                        all_entered.set()
                    await release_sends.wait()
                return await original(self, data, *args, **kwargs)

            monkeypatch.setattr(
                web.WebSocketResponse,
                "send_bytes",
                _hold_three_connectors,
            )
            maximum = b"m" * DATA_FRAME_MAX_BYTES
            await asyncio.gather(
                *(
                    listener.send_bytes(encode_data_frame(sid, maximum))
                    for _pub, listener, _connector, sid in established
                )
            )
            await asyncio.wait_for(all_entered.wait(), timeout=1.0)
            full = rdz._relay_forward_budget.snapshot()
            assert full["used_bytes"] == full["data_limit_bytes"] == 3 * wire_bytes
            assert full["current_bytes"] == 3 * wire_bytes
            assert full["active_owners"] == 3
            assert full["largest_owner_bytes"] == wire_bytes

            # A fourth, unrelated listener can still complete control-plane
            # pairing from the reserved tail. Its DATA is refused fail-fast,
            # and only that responsible session is closed.
            fourth = await _open_server_session(base, session)
            fourth_pub, fourth_listener, fourth_connector, fourth_sid = fourth
            await fourth_listener.send_bytes(encode_data_frame(fourth_sid, b"over-cap"))
            notice = await asyncio.wait_for(fourth_listener.receive_json(), timeout=1.0)
            assert notice["t"] == "session_closed"
            assert parse_session_id_from_msg(notice) == fourth_sid
            fourth_close = await asyncio.wait_for(fourth_connector.receive(), timeout=1.0)
            assert fourth_close.type in {
                aiohttp.WSMsgType.BINARY,
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
            }
            assert fourth_sid not in rdz._relay_listeners[fourth_pub].sessions
            assert rdz.metrics.relay_forward_global_overloads_total == 1
            assert rdz.metrics.relay_forward_overloads_total == 1

            async with session.get(f"{base}/metrics") as response:
                assert response.status == 200
                status = await response.json()
            budget_status = status["relay_forward_budget"]
            assert budget_status["limit_bytes"] == 3 * wire_bytes + control_reserve
            assert budget_status["used_bytes"] == 3 * wire_bytes
            assert budget_status["peak_bytes"] <= budget_status["limit_bytes"]
            assert budget_status["data_denials_total"] == 1
            assert status["relay_forward_global_overloads_total"] == 1

            # Releasing the three stalled sends drains the process budget and
            # proves their sessions were isolated from the fourth overload.
            release_sends.set()
            for _pub, _listener, connector, _sid in established:
                delivered = await asyncio.wait_for(connector.receive(), timeout=1.0)
                assert decode_frame(delivered.data).payload == maximum
            first_pub, first_listener, first_connector, first_sid = established[0]
            await first_listener.send_bytes(encode_data_frame(first_sid, b"healthy"))
            healthy = await asyncio.wait_for(first_connector.receive(), timeout=1.0)
            assert decode_frame(healthy.data).payload == b"healthy"
            assert first_sid in rdz._relay_listeners[first_pub].sessions
            for pub, _listener, _connector, sid in established[1:]:
                assert sid in rdz._relay_listeners[pub].sessions
            assert rdz._relay_forward_budget.used_bytes == 0
    finally:
        release_sends.set()
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_forward_queue_overload_terminates_only_responsible_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server(
        forward_queue_limit_bytes=DATA_FRAME_MAX_BYTES + 9,
    )
    release_slow_send = asyncio.Event()
    try:
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        async with aiohttp.ClientSession() as session:
            listener = await session.ws_connect(f"{base}/api/v1/relay/listen")
            await listener.send_json(sign_listen_auth(private_key=key, pubkey=pub).to_wire())
            slow = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
            slow_sid = parse_session_id_from_msg(
                await asyncio.wait_for(listener.receive_json(), timeout=1.0)
            )
            assert parse_session_id_from_msg(await slow.receive_json()) == slow_sid
            healthy = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
            healthy_sid = parse_session_id_from_msg(
                await asyncio.wait_for(listener.receive_json(), timeout=1.0)
            )
            assert parse_session_id_from_msg(await healthy.receive_json()) == healthy_sid

            slow_server_ws = rdz._relay_listeners[pub].sessions[slow_sid].connector_ws
            original = web.WebSocketResponse.send_bytes
            entered = asyncio.Event()

            async def _stall_slow_data(self, data, *args, **kwargs):
                if self is slow_server_ws and decode_frame(data).type == FRAME_DATA:
                    entered.set()
                    await release_slow_send.wait()
                return await original(self, data, *args, **kwargs)

            monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _stall_slow_data)
            await listener.send_bytes(encode_data_frame(slow_sid, b"x" * DATA_FRAME_MAX_BYTES))
            await asyncio.wait_for(entered.wait(), timeout=1.0)
            # The in-flight maximum frame owns the entire session queue.
            await listener.send_bytes(encode_data_frame(slow_sid, b"overflow"))
            await listener.send_bytes(encode_data_frame(healthy_sid, b"still-good"))

            healthy_frame = await asyncio.wait_for(healthy.receive(), timeout=0.2)
            assert decode_frame(healthy_frame.data).payload == b"still-good"
            notice = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
            assert parse_session_id_from_msg(notice) == slow_sid
            assert healthy_sid in rdz._relay_listeners[pub].sessions
            assert slow_sid not in rdz._relay_listeners[pub].sessions
            assert rdz.metrics.relay_forward_overloads_total == 1
    finally:
        release_slow_send.set()
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_forward_deadline_is_session_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server(forward_timeout_s=0.05)
    never = asyncio.Event()
    try:
        async with aiohttp.ClientSession() as session:
            pub, listener, connector, sid = await _open_server_session(base, session)
            server_connector_ws = rdz._relay_listeners[pub].sessions[sid].connector_ws
            original = web.WebSocketResponse.send_bytes

            async def _never_send_data(self, data, *args, **kwargs):
                if self is server_connector_ws and decode_frame(data).type == FRAME_DATA:
                    await never.wait()
                return await original(self, data, *args, **kwargs)

            monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _never_send_data)
            await listener.send_bytes(encode_data_frame(sid, b"deadline"))
            notice = await asyncio.wait_for(listener.receive_json(), timeout=0.5)
            assert parse_session_id_from_msg(notice) == sid
            assert sid not in rdz._relay_listeners[pub].sessions
            assert rdz.metrics.relay_forward_failures_total == 1
            close = await asyncio.wait_for(connector.receive(), timeout=0.5)
            assert close.type in {
                aiohttp.WSMsgType.BINARY,
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
            }
    finally:
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_session_cap_reserves_before_websocket_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server(max_sessions=1)
    release_first_upgrade = asyncio.Event()
    try:
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        async with aiohttp.ClientSession() as session:
            listener_client = await session.ws_connect(f"{base}/api/v1/relay/listen")
            first_open: asyncio.Task[aiohttp.ClientWebSocketResponse] | None = None
            first_connector: aiohttp.ClientWebSocketResponse | None = None
            try:
                await listener_client.send_json(
                    sign_listen_auth(private_key=key, pubkey=pub).to_wire()
                )
                original_prepare = web.WebSocketResponse.prepare
                first_upgrade_entered = asyncio.Event()
                gated_once = False

                async def _gate_first_connector_upgrade(self, request):
                    nonlocal gated_once
                    if request.path.startswith("/api/v1/relay/connect/") and not gated_once:
                        gated_once = True
                        first_upgrade_entered.set()
                        await release_first_upgrade.wait()
                    return await original_prepare(self, request)

                monkeypatch.setattr(
                    web.WebSocketResponse,
                    "prepare",
                    _gate_first_connector_upgrade,
                )
                url = f"{base}/api/v1/relay/connect/{_b64(pub)}"
                first_open = asyncio.create_task(session.ws_connect(url))
                await asyncio.wait_for(first_upgrade_entered.wait(), timeout=1.0)
                server_listener = rdz._relay_listeners[pub]
                assert server_listener.reserved_sessions == 1
                assert not server_listener.sessions

                # Admission is rejected before WebSocket upgrade. Consume it
                # as HTTP so aiohttp can deterministically release the failed
                # attempt's Connection instead of waiting for finalization.
                async with session.get(url) as rejected:
                    assert rejected.status == 503
                    await rejected.read()
                assert server_listener.reserved_sessions == 1
                assert not server_listener.sessions

                release_first_upgrade.set()
                first_connector = await asyncio.wait_for(first_open, timeout=1.0)
                incoming = await asyncio.wait_for(
                    listener_client.receive_json(),
                    timeout=1.0,
                )
                ready = await asyncio.wait_for(
                    first_connector.receive_json(),
                    timeout=1.0,
                )
                assert parse_session_id_from_msg(incoming) == parse_session_id_from_msg(ready)
                assert server_listener.reserved_sessions == 0
                assert len(server_listener.sessions) == 1
            finally:
                release_first_upgrade.set()
                if first_open is not None and not first_open.done():
                    first_open.cancel()
                if first_open is not None:
                    await asyncio.gather(first_open, return_exceptions=True)
                if first_connector is not None:
                    await first_connector.close()
                await listener_client.close()
    finally:
        release_first_upgrade.set()
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_teardown_resources_remain_charged_to_session_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server(max_sessions=1, forward_timeout_s=0.5)
    release_close = asyncio.Event()
    try:
        async with aiohttp.ClientSession() as session:
            pub, listener_client, connector, sid = await _open_server_session(base, session)
            try:
                server_listener = rdz._relay_listeners[pub]
                server_connector_ws = server_listener.sessions[sid].connector_ws
                original = web.WebSocketResponse.send_bytes
                close_entered = asyncio.Event()

                async def _hold_connector_close(self, data, *args, **kwargs):
                    if self is server_connector_ws and decode_frame(data).type == FRAME_CLOSE:
                        close_entered.set()
                        await release_close.wait()
                    return await original(self, data, *args, **kwargs)

                monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _hold_connector_close)
                close_task = rdz._schedule_relay_session_close(server_listener, sid)
                assert close_task is not None
                await asyncio.wait_for(close_entered.wait(), timeout=1.0)
                assert not server_listener.sessions
                assert server_listener.teardown_count == 1
                teardown_snapshot = rdz._relay_forward_budget.snapshot()
                assert teardown_snapshot["teardown_bytes"] >= 9
                assert teardown_snapshot["used_bytes"] == teardown_snapshot["teardown_bytes"]
                assert teardown_snapshot["peak_bytes"] <= teardown_snapshot["limit_bytes"]

                url = f"{base}/api/v1/relay/connect/{_b64(pub)}"
                # This endpoint rejects before WebSocket upgrade. Exercise it
                # as ordinary HTTP so the 503 response body/connection are
                # deterministically consumed instead of relying on aiohttp's
                # failed-upgrade object finalizer.
                async with session.get(url) as rejected:
                    assert rejected.status == 503
                    await rejected.read()
                assert server_listener.teardown_count == 1

                release_close.set()
                await asyncio.wait_for(close_task, timeout=1.0)
                assert server_listener.teardown_count == 0
                assert rdz._relay_forward_budget.used_bytes == 0
                notice = await asyncio.wait_for(listener_client.receive_json(), timeout=1.0)
                assert parse_session_id_from_msg(notice) == sid
            finally:
                await connector.close()
                await listener_client.close()
    finally:
        release_close.set()
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_ready_control_precedes_listener_immediate_data(
    relay_server: tuple[str, RendezvousApp],
) -> None:
    base, _rdz = relay_server
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    async with aiohttp.ClientSession() as session:
        listener = await session.ws_connect(f"{base}/api/v1/relay/listen")
        await listener.send_json(sign_listen_auth(private_key=key, pubkey=pub).to_wire())
        connector = await session.ws_connect(f"{base}/api/v1/relay/connect/{_b64(pub)}")
        incoming = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
        sid = parse_session_id_from_msg(incoming)
        # Act as an adversarially fast listener: emit DATA in the same turn
        # that INCOMING is observed.
        await listener.send_bytes(encode_data_frame(sid, b"immediate"))

        first = await asyncio.wait_for(connector.receive(), timeout=1.0)
        assert first.type == aiohttp.WSMsgType.TEXT
        assert parse_session_id_from_msg(json.loads(first.data)) == sid
        second = await asyncio.wait_for(connector.receive(), timeout=1.0)
        assert second.type == aiohttp.WSMsgType.BINARY
        assert decode_frame(second.data).payload == b"immediate"


@pytest.mark.asyncio
async def test_server_failed_upgrade_rolls_back_session_cap_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz, runner = await _start_server(max_sessions=1)
    try:
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        async with aiohttp.ClientSession() as session:
            listener_client = await session.ws_connect(f"{base}/api/v1/relay/listen")
            connector: aiohttp.ClientWebSocketResponse | None = None
            try:
                await listener_client.send_json(
                    sign_listen_auth(private_key=key, pubkey=pub).to_wire()
                )
                original_prepare = web.WebSocketResponse.prepare
                fail_once = True

                async def _fail_first_connector_upgrade(self, request):
                    nonlocal fail_once
                    if request.path.startswith("/api/v1/relay/connect/") and fail_once:
                        fail_once = False
                        raise ConnectionResetError("injected upgrade failure")
                    return await original_prepare(self, request)

                monkeypatch.setattr(
                    web.WebSocketResponse,
                    "prepare",
                    _fail_first_connector_upgrade,
                )
                url = f"{base}/api/v1/relay/connect/{_b64(pub)}"
                with pytest.raises((aiohttp.ClientError, ConnectionResetError)):
                    await session.ws_connect(url)
                server_listener = rdz._relay_listeners[pub]
                assert server_listener.reserved_sessions == 0
                assert not server_listener.sessions

                connector = await session.ws_connect(url)
                incoming = await asyncio.wait_for(listener_client.receive_json(), timeout=1.0)
                ready = await asyncio.wait_for(connector.receive_json(), timeout=1.0)
                assert parse_session_id_from_msg(incoming) == parse_session_id_from_msg(ready)
                assert server_listener.reserved_sessions == 0
                assert len(server_listener.sessions) == 1
            finally:
                if connector is not None:
                    await connector.close()
                await listener_client.close()
    finally:
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_forward_failure_closes_both_session_sides(
    relay_server: tuple[str, RendezvousApp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz = relay_server
    async with aiohttp.ClientSession() as session:
        pub, listener_client, connector_client, sid = await _open_server_session(base, session)
        server_listener = rdz._relay_listeners[pub]
        server_listener_ws = server_listener.ws
        original = web.WebSocketResponse.send_bytes

        async def _fail_listener_forward(self, data, *args, **kwargs):
            if self is server_listener_ws:
                raise ConnectionResetError("injected listener send failure")
            return await original(self, data, *args, **kwargs)

        monkeypatch.setattr(web.WebSocketResponse, "send_bytes", _fail_listener_forward)
        await connector_client.send_bytes(encode_data_frame(sid, b"payload"))

        connector_close = await asyncio.wait_for(connector_client.receive(), timeout=1.0)
        assert connector_close.type == aiohttp.WSMsgType.BINARY
        assert decode_frame(connector_close.data).type == FRAME_CLOSE
        closed_notice = await asyncio.wait_for(listener_client.receive_json(), timeout=1.0)
        assert closed_notice["t"] == "session_closed"
        assert parse_session_id_from_msg(closed_notice) == sid
        assert sid not in server_listener.sessions
        assert rdz.metrics.relay_forward_failures_total == 1


@pytest.mark.asyncio
async def test_server_reverse_forward_failure_closes_both_session_sides(
    relay_server: tuple[str, RendezvousApp],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    base, rdz = relay_server
    async with aiohttp.ClientSession() as session:
        pub, listener_client, connector_client, sid = await _open_server_session(base, session)
        relay_session = rdz._relay_listeners[pub].sessions[sid]
        server_connector_ws = relay_session.connector_ws
        original = web.WebSocketResponse.send_bytes

        async def _fail_connector_forward(self, data, *args, **kwargs):
            if self is server_connector_ws:
                raise ConnectionResetError("injected connector send failure")
            return await original(self, data, *args, **kwargs)

        monkeypatch.setattr(
            web.WebSocketResponse,
            "send_bytes",
            _fail_connector_forward,
        )
        await listener_client.send_bytes(encode_data_frame(sid, b"reply"))

        notice = await asyncio.wait_for(listener_client.receive_json(), timeout=1.0)
        assert notice["t"] == "session_closed"
        connector_close = await asyncio.wait_for(connector_client.receive(), timeout=1.0)
        assert connector_close.type in {
            aiohttp.WSMsgType.CLOSE,
            aiohttp.WSMsgType.CLOSED,
            aiohttp.WSMsgType.ERROR,
        }
        assert sid not in rdz._relay_listeners[pub].sessions
        assert rdz.metrics.relay_forward_failures_total == 1


@pytest.mark.asyncio
async def test_server_idle_deadline_expires_and_notifies_both_sides() -> None:
    base, rdz, runner = await _start_server(idle_s=0.08)
    try:
        async with aiohttp.ClientSession() as session:
            pub, listener, connector, sid = await _open_server_session(base, session)
            connector_close = await asyncio.wait_for(connector.receive(), timeout=1.0)
            assert connector_close.type == aiohttp.WSMsgType.BINARY
            parsed = decode_frame(connector_close.data)
            assert parsed.type == FRAME_CLOSE
            assert parsed.session_id == sid
            notice = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
            assert notice["t"] == "session_closed"
            assert sid not in rdz._relay_listeners[pub].sessions
            assert rdz.metrics.relay_idle_expirations_total == 1
    finally:
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_server_idle_deadline_is_refreshed_by_one_way_listener_traffic() -> None:
    # Keep a wide scheduling margin for loaded Windows CI while making the
    # aggregate one-way activity period exceed the original idle deadline.
    # The session would expire before the fourth frame unless each successful
    # listener-to-connector forward refreshes ``last_activity_at``.
    base, rdz, runner = await _start_server(idle_s=0.5)
    try:
        async with aiohttp.ClientSession() as session:
            pub, listener, connector, sid = await _open_server_session(base, session)
            for sequence in range(4):
                await asyncio.sleep(0.14)
                await listener.send_bytes(encode_data_frame(sid, bytes([sequence])))
                forwarded = await asyncio.wait_for(connector.receive(), timeout=0.5)
                assert forwarded.type == aiohttp.WSMsgType.BINARY
                parsed = decode_frame(forwarded.data)
                assert parsed.payload == bytes([sequence])
                assert sid in rdz._relay_listeners[pub].sessions

            # Expiry starts only after the last successful one-way frame.
            connector_close = await asyncio.wait_for(connector.receive(), timeout=1.0)
            assert connector_close.type == aiohttp.WSMsgType.BINARY
            assert decode_frame(connector_close.data).type == FRAME_CLOSE
            assert rdz.metrics.relay_idle_expirations_total == 1
    finally:
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_outbound_pump_natural_ws_end_installs_sticky_writer_failure() -> None:
    base, _rdz, runner = await _start_server(idle_s=0.06)
    try:
        key = Ed25519PrivateKey.generate()
        pub = key.public_key().public_bytes_raw()
        async with aiohttp.ClientSession() as session:
            listener = await session.ws_connect(f"{base}/api/v1/relay/listen")
            await listener.send_json(sign_listen_auth(private_key=key, pubkey=pub).to_wire())
            reader, writer, pump = await open_relay_outbound(
                base,
                pub,
                allow_legacy_identity_route=True,
                session=session,
            )
            incoming = await asyncio.wait_for(listener.receive_json(), timeout=0.5)
            assert incoming["t"] == "incoming"

            assert await asyncio.wait_for(reader.read(1), timeout=0.5) == b""
            await asyncio.wait_for(pump, timeout=0.5)
            with pytest.raises(RelayTransportError, match="peer closed"):
                writer.write(b"must-not-disappear")
    finally:
        await _cleanup_server(runner)


@pytest.mark.asyncio
async def test_sparse_385_mib_transfer_resumes_after_81_mib_without_duplicate_commit() -> None:
    """Model the reported boundary without retaining 385 MiB in memory.

    Each 64 KiB DATA payload represents one sparse 1 MiB file extent.  The
    first WebSocket fails before extent 81 is committed; a fresh relay stream
    resumes at the receiver-confirmed extent.  The resulting logical file is
    385 MiB and its terminal delivery commit is applied exactly once.
    """

    total_extents = 385
    fail_after_committed = 81
    logical_extent_bytes = 1024 * 1024
    wire_extent_bytes = 64 * 1024
    committed: set[int] = set()
    duplicate_extents = 0
    terminal_commits = 0

    def _record(data: bytes) -> None:
        nonlocal duplicate_extents
        frame = decode_frame(data)
        if frame.type == FRAME_CLOSE:
            return
        index, logical_size = struct.unpack(">II", frame.payload[:8])
        assert logical_size == logical_extent_bytes
        if index in committed:
            duplicate_extents += 1
        committed.add(index)

    async def _send_extent(writer: _RelayStreamWriter, index: int) -> None:
        payload = struct.pack(">II", index, logical_extent_bytes) + bytes([index % 251]) * (
            wire_extent_bytes - 8
        )
        await writer.wait_writable(len(payload))
        writer.write(payload)
        await writer.drain()

    first_ws = _GateWebSocket(
        fail_at=fail_after_committed + 1,
        on_send=_record,
    )
    first = _RelayStreamWriter(first_ws, b"sparse01")  # type: ignore[arg-type]
    with pytest.raises(RelayTransportError):
        for index in range(total_extents):
            await _send_extent(first, index)
    assert len(committed) == fail_after_committed
    assert first.pending_bytes == 0

    resumed_ws = _GateWebSocket(on_send=_record)
    resumed = _RelayStreamWriter(resumed_ws, b"sparse02")  # type: ignore[arg-type]
    for index in range(len(committed), total_extents):
        await _send_extent(resumed, index)
    resumed.close()
    await resumed.wait_closed()

    if len(committed) == total_extents:
        terminal_commits += 1
    # A retry observes the already committed delivery and sends no extents.
    if len(committed) != total_extents:  # pragma: no cover - proof invariant
        terminal_commits += 1

    assert len(committed) * logical_extent_bytes == 385 * 1024 * 1024
    assert duplicate_extents == 0
    assert terminal_commits == 1
    assert resumed.pending_bytes == 0
