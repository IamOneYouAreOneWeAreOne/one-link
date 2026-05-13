"""Native QUIC Python bridge batch helpers."""

from __future__ import annotations

import threading
import time

import pytest

from one_link import quic_native


pytestmark = pytest.mark.skipif(
    not quic_native.HAS_NATIVE,
    reason="one_link_native.quic not installed",
)


def _round_trip(payloads: list[bytes], *, parallel: bool) -> list[tuple[int, bytes]]:
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp == bob.fingerprint,
        quic_native.EndpointConfig(bind="127.0.0.1:0"),
    )
    addr = server.local_addr
    ready = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn = server.accept_blocking(timeout_ms=10_000)
            assert conn is not None
            ready.set()
            for _ in payloads:
                req = conn.recv_frame_blocking(timeout_ms=10_000)
                assert req is not None
                sid, _kind, payload = req
                conn.send_response_on(
                    sid,
                    quic_native.FRAME_CHUNK_RESPONSE,
                    payload + b"-ok",
                )
            time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = quic_native.Endpoint.client(
        bob, quic_native.EndpointConfig(bind="127.0.0.1:0")
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    assert ready.wait(timeout=5)
    if parallel:
        replies = conn.send_frame_round_trips_parallel(
            quic_native.FRAME_CHUNK_REQUEST,
            payloads,
            max_in_flight=4,
        )
    else:
        replies = conn.send_frame_round_trips(
            quic_native.FRAME_CHUNK_REQUEST,
            payloads,
        )
    thread.join(timeout=5)
    conn.close(0, b"ok")
    client.close(0, b"ok")
    server.close(0, b"ok")
    if errors:
        raise errors[0]
    return replies


def _round_trip_server_batch(payloads: list[bytes]) -> list[tuple[int, bytes]]:
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp == bob.fingerprint,
        quic_native.EndpointConfig(bind="127.0.0.1:0"),
    )
    addr = server.local_addr
    ready = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn = server.accept_blocking(timeout_ms=10_000)
            assert conn is not None
            ready.set()
            served = 0
            while served < len(payloads):
                batch = conn.recv_frames_blocking(8, timeout_ms=10_000)
                assert batch
                conn.send_responses_on(
                    [
                        (
                            sid,
                            quic_native.FRAME_CHUNK_RESPONSE,
                            payload + b"-batch-ok",
                        )
                        for sid, _kind, payload in batch
                    ],
                    max_in_flight=4,
                )
                served += len(batch)
            time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = quic_native.Endpoint.client(
        bob, quic_native.EndpointConfig(bind="127.0.0.1:0")
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    assert ready.wait(timeout=5)
    replies = conn.send_frame_round_trips_parallel(
        quic_native.FRAME_CHUNK_REQUEST,
        payloads,
        max_in_flight=4,
    )
    thread.join(timeout=5)
    conn.close(0, b"ok")
    client.close(0, b"ok")
    server.close(0, b"ok")
    if errors:
        raise errors[0]
    return replies


def test_quic_sequential_batch_preserves_order():
    replies = _round_trip([b"a", b"b", b"c"], parallel=False)
    assert replies == [
        (quic_native.FRAME_CHUNK_RESPONSE, b"a-ok"),
        (quic_native.FRAME_CHUNK_RESPONSE, b"b-ok"),
        (quic_native.FRAME_CHUNK_RESPONSE, b"c-ok"),
    ]


def test_quic_parallel_batch_preserves_order():
    payloads = [f"chunk-{i}".encode() for i in range(12)]
    replies = _round_trip(payloads, parallel=True)
    assert replies == [
        (quic_native.FRAME_CHUNK_RESPONSE, p + b"-ok")
        for p in payloads
    ]


def test_quic_server_batch_receive_and_response_preserves_payloads():
    payloads = [f"server-batch-{i}".encode() for i in range(16)]
    replies = _round_trip_server_batch(payloads)
    assert sorted(replies) == sorted(
        (quic_native.FRAME_CHUNK_RESPONSE, p + b"-batch-ok")
        for p in payloads
    )


def test_quic_native_fixed_response_server_hot_path():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp == bob.fingerprint,
        quic_native.EndpointConfig(bind="127.0.0.1:0"),
    )
    addr = server.local_addr
    ready = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn = server.accept_blocking(timeout_ms=10_000)
            assert conn is not None
            ready.set()
            served = conn.serve_fixed_responses_blocking(
                10,
                quic_native.FRAME_CHUNK_RESPONSE,
                b"native-hot",
                max_in_flight=4,
            )
            assert served == 10
            time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = quic_native.Endpoint.client(
        bob, quic_native.EndpointConfig(bind="127.0.0.1:0")
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    assert ready.wait(timeout=5)
    replies = conn.send_frame_round_trips_parallel(
        quic_native.FRAME_CHUNK_REQUEST,
        [f"fixed-{i}".encode() for i in range(10)],
        max_in_flight=4,
    )
    thread.join(timeout=5)
    conn.close(0, b"ok")
    client.close(0, b"ok")
    server.close(0, b"ok")
    if errors:
        raise errors[0]
    assert replies == [(quic_native.FRAME_CHUNK_RESPONSE, b"native-hot")] * 10


def test_quic_native_bulk_stream_hot_path_preserves_order():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp == bob.fingerprint,
        quic_native.EndpointConfig(bind="127.0.0.1:0"),
    )
    addr = server.local_addr
    ready = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn = server.accept_blocking(timeout_ms=10_000)
            assert conn is not None
            ready.set()
            served = conn.serve_fixed_stream_responses_blocking(
                3,
                4,
                quic_native.FRAME_CHUNK_RESPONSE,
                b"stream-hot",
                max_in_flight=3,
            )
            assert served == 12
            time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = quic_native.Endpoint.client(
        bob, quic_native.EndpointConfig(bind="127.0.0.1:0")
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    assert ready.wait(timeout=5)
    replies = conn.send_frame_stream_round_trips_parallel(
        quic_native.FRAME_CHUNK_REQUEST,
        [f"stream-{i}".encode() for i in range(12)],
        lanes=3,
    )
    thread.join(timeout=5)
    conn.close(0, b"ok")
    client.close(0, b"ok")
    server.close(0, b"ok")
    if errors:
        raise errors[0]
    assert replies == [(quic_native.FRAME_CHUNK_RESPONSE, b"stream-hot")] * 12


def test_quic_native_bulk_stream_count_hot_path():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice,
        lambda fp: fp == bob.fingerprint,
        quic_native.EndpointConfig(bind="127.0.0.1:0"),
    )
    addr = server.local_addr
    ready = threading.Event()
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            conn = server.accept_blocking(timeout_ms=10_000)
            assert conn is not None
            ready.set()
            served = conn.serve_fixed_stream_responses_blocking(
                2,
                5,
                quic_native.FRAME_CHUNK_RESPONSE,
                b"native-count",
                max_in_flight=2,
            )
            assert served == 10
            time.sleep(0.05)
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = quic_native.Endpoint.client(
        bob, quic_native.EndpointConfig(bind="127.0.0.1:0")
    )
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=10_000)
    assert ready.wait(timeout=5)
    received = conn.send_frame_stream_round_trips_count_parallel(
        quic_native.FRAME_CHUNK_REQUEST,
        [f"count-{i}".encode() for i in range(10)],
        quic_native.FRAME_CHUNK_RESPONSE,
        lanes=2,
    )
    thread.join(timeout=5)
    conn.close(0, b"ok")
    client.close(0, b"ok")
    server.close(0, b"ok")
    if errors:
        raise errors[0]
    assert received == 10 * len(b"native-count")
