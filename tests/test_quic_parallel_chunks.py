"""Unit tests for the Wave 2f multi-stream parallel sender.

Validates that ``Connection.send_frame_stream_round_trips_count_parallel``
ships ``N`` frame payloads across ``lanes`` bi-streams and that
the response-byte count matches the expected serve-back. Two
in-process endpoints; the server uses the native
``serve_fixed_stream_responses_blocking`` to mirror what the
daemon's frame loop will do in production.

Skipped when the native crate isn't installed.
"""

from __future__ import annotations

import threading
import time

import pytest

peer_quic = pytest.importorskip("one_link.peer_quic")
if not peer_quic.HAS_NATIVE:  # pragma: no cover
    pytest.skip("one_link_native.quic not installed", allow_module_level=True)

from one_link_native import quic as native_quic  # type: ignore[import-not-found]


def _build_pair():
    """Spin up matched server + client endpoints for a one-shot
    test. Returns (server_ep, server_id, client_ep, client_id,
    accept_thread_starter)."""
    server_pem = native_quic.Identity.generate().to_pkcs8_pem()
    server_id = native_quic.Identity.from_pkcs8_pem(server_pem)
    client_pem = native_quic.Identity.generate().to_pkcs8_pem()
    client_id = native_quic.Identity.from_pkcs8_pem(client_pem)

    def is_paired(_fp: bytes) -> bool:
        return True

    s = peer_quic.make_server_endpoint(
        server_pem, is_paired,
        peer_quic.QuicEndpointConfig(bind_addr="127.0.0.1:0"),
    )
    c = peer_quic.make_client_endpoint(
        client_pem,
        peer_quic.QuicEndpointConfig(bind_addr="127.0.0.1:0"),
    )
    return s, server_id, c, client_id


def test_parallel_stream_round_trips_count_matches_payload_bytes() -> None:
    """``send_frame_stream_round_trips_count_parallel`` returns
    the total response bytes from all lanes — must equal
    ``frames * response_payload_len`` when the server uses a
    fixed response."""
    server_ep, server_id, client_ep, _client_id = _build_pair()
    try:
        server_addr = server_ep.local_addr

        N_FRAMES = 12
        N_LANES = 3
        RESPONSE_BODY = b"chunk-ack" * 4  # 36 bytes per response

        # Server: accept + serve N_FRAMES responses across N_LANES
        # streams (the native crate's stream-batch server fixture).
        server_conn_holder: list[object] = []
        server_err: list[BaseException] = []

        def serve() -> None:
            try:
                conn = server_ep.accept_blocking(timeout_ms=10_000)
                if conn is not None:
                    server_conn_holder.append(conn)
                    conn.serve_fixed_stream_responses_blocking(
                        N_LANES,
                        N_FRAMES // N_LANES,
                        native_quic.FRAME_CHUNK_RESPONSE,
                        RESPONSE_BODY,
                        max_in_flight=N_LANES,
                    )
            except BaseException as e:  # pragma: no cover - surfaced
                server_err.append(e)

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        time.sleep(0.1)

        client_conn = client_ep.connect_blocking(
            server_addr, server_id.fingerprint, timeout_ms=10_000,
        )

        # Build payload list (N_FRAMES request bodies); use
        # arbitrary bytes — server ignores them in this fixture.
        payloads = [f"chunk-{i}".encode("utf-8") * 16 for i in range(N_FRAMES)]

        total_response_bytes = client_conn.send_frame_stream_round_trips_count_parallel(
            native_quic.FRAME_CHUNK_REQUEST,
            payloads,
            native_quic.FRAME_CHUNK_RESPONSE,
            N_LANES,
        )

        t.join(timeout=10.0)
        if server_err:
            raise server_err[0]

        assert total_response_bytes == N_FRAMES * len(RESPONSE_BODY), (
            f"expected {N_FRAMES * len(RESPONSE_BODY)} response bytes, "
            f"got {total_response_bytes}"
        )

        client_conn.close(0, b"done")
        for conn in server_conn_holder:
            conn.close(0, b"done")
    finally:
        server_ep.close(0, b"done")
        client_ep.close(0, b"done")


def test_parallel_stream_empty_payload_list_is_noop() -> None:
    """Empty payload list returns zero bytes, no streams opened
    — important because the Wave 2f helper short-circuits on
    empty input."""
    server_ep, server_id, client_ep, _client_id = _build_pair()
    try:
        server_addr = server_ep.local_addr

        def accept_quietly() -> None:
            try:
                server_ep.accept_blocking(timeout_ms=3_000)
            except Exception:
                pass

        t = threading.Thread(target=accept_quietly, daemon=True)
        t.start()
        time.sleep(0.1)

        client_conn = client_ep.connect_blocking(
            server_addr, server_id.fingerprint, timeout_ms=5_000,
        )

        # Actually exercise the thing this test is named for. The wrapper
        # short-circuits on an empty list, so it must return zero bytes WITHOUT
        # opening a stream -- previously this test never passed an empty list
        # at all and only confirmed the connection survived a close, which is
        # a different property entirely.
        sent = client_conn.send_frame_stream_round_trips_count_parallel(
            native_quic.FRAME_CHUNK_REQUEST,
            [],
            native_quic.FRAME_CHUNK_RESPONSE,
        )
        assert sent == 0, f"empty payload list returned {sent} bytes"

        client_conn.close(0, b"done")
        t.join(timeout=5.0)
    finally:
        server_ep.close(0, b"done")
        client_ep.close(0, b"done")
