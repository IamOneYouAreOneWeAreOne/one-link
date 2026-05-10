"""File engine v2 — algebraic-correctness tests for ``one_link.quic_native``.

Per ADR-0009 + ADR-0010 verification gates: identity round-trip, cert
fingerprint binding, frame round-trip, server registry rejection,
client fingerprint mismatch rejection, multi-stream, large bulk
transfer.

Tests skip when the native module isn't available. When green, these
are the canonical correctness contract for any future QUIC binding
reimplementation.
"""

from __future__ import annotations

import threading
import time

import pytest

from one_link import quic_native


pytestmark = pytest.mark.skipif(
    not quic_native.HAS_NATIVE,
    reason="one_link_native not installed; run `cd native && maturin develop --release`",
)


def _client_loopback_config() -> "quic_native.EndpointConfig":
    return quic_native.EndpointConfig(
        bind="127.0.0.1:0",
        idle_timeout_ms=10_000,
        keepalive_interval_ms=2_000,
    )


def _start_pong_server(
    identity, is_paired, ready_evt: threading.Event
) -> tuple["quic_native.Endpoint", threading.Thread]:
    """Helper: start a server endpoint that echoes Ping → Pong on every stream."""
    server = quic_native.Endpoint.server(
        identity, is_paired, _client_loopback_config()
    )
    ready_evt.set()

    def loop():
        # Single connection; up to 64 streams.
        conn = server.accept_blocking(timeout_ms=10_000)
        if conn is None:
            return
        for _ in range(64):
            result = conn.recv_frame_blocking(timeout_ms=5_000)
            if result is None:
                return
            stream_id, kind, payload = result
            if kind == quic_native.FRAME_CLOSE:
                break
            conn.send_response_on(
                stream_id,
                _pong_kind_for(kind),
                payload,
            )

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return server, t


def _pong_kind_for(kind: int) -> int:
    if kind == quic_native.FRAME_PING:
        return quic_native.FRAME_PONG
    if kind == quic_native.FRAME_CHUNK_REQUEST:
        return quic_native.FRAME_CHUNK_RESPONSE
    return quic_native.FRAME_PONG


# ─── module surface ────────────────────────────────────────────────────


def test_module_constants_present():
    assert quic_native.ALPN == b"ol/1"
    assert quic_native.MAX_BULK_FRAME_BYTES == 1024 * 1024
    assert quic_native.MAX_CONTROL_FRAME_BYTES == 64 * 1024
    assert quic_native.FRAME_CHUNK_REQUEST == 0x01
    assert quic_native.FRAME_CHUNK_RESPONSE == 0x02
    assert quic_native.FRAME_PING == 0xF0
    assert quic_native.FRAME_PONG == 0xF1
    assert quic_native.FRAME_CLOSE == 0xFF


def test_phase_b2_frame_kinds_exposed():
    """Phase B-2 wire-protocol frame kinds (ADR-0015 fountain + ADR-0011 v2 scoped bloom)."""
    assert quic_native.FRAME_BLOOM_FILTER == 0x20
    assert quic_native.FRAME_MISSING_CHUNKS == 0x21
    assert quic_native.FRAME_FOUNTAIN_BURST == 0x22
    assert quic_native.FRAME_FOUNTAIN_ACK == 0x23
    assert quic_native.FRAME_FOUNTAIN_REQUEST == 0x24
    assert quic_native.FRAME_SCOPED_BLOOM_FILTER == 0x25


def test_diagnostics_when_native_available():
    diag = quic_native.diagnostics()
    assert diag.native_available is True
    assert diag.alpn == b"ol/1"
    assert diag.max_bulk_frame_bytes == 1024 * 1024
    assert diag.max_control_frame_bytes == 64 * 1024


# ─── identity ──────────────────────────────────────────────────────────


def test_identity_generate_yields_distinct():
    a = quic_native.Identity.generate()
    b = quic_native.Identity.generate()
    assert a.fingerprint != b.fingerprint
    assert a.public_key_bytes != b.public_key_bytes
    assert len(a.fingerprint) == 32
    assert len(a.public_key_bytes) == 32


def test_identity_pkcs8_pem_round_trip():
    original = quic_native.Identity.generate()
    pem = original.to_pkcs8_pem()
    assert "BEGIN PRIVATE KEY" in pem or "BEGIN ED25519 PRIVATE KEY" in pem
    restored = quic_native.Identity.from_pkcs8_pem(pem)
    assert restored.fingerprint == original.fingerprint
    assert restored.public_key_bytes == original.public_key_bytes


def test_identity_fingerprint_hex_matches_bytes():
    id_ = quic_native.Identity.generate()
    fp = id_.fingerprint
    fp_hex = id_.fingerprint_hex
    assert fp_hex == fp.hex()


def test_identity_repr_does_not_leak_private_key():
    id_ = quic_native.Identity.generate()
    s = repr(id_)
    assert "Identity" in s
    # Hex prefix is fine; full PKCS8 wouldn't be.
    assert "BEGIN" not in s
    assert "PRIVATE" not in s


def test_identity_from_pkcs8_pem_rejects_garbage():
    with pytest.raises(Exception):
        quic_native.Identity.from_pkcs8_pem("not a real PEM")


# ─── endpoint config ───────────────────────────────────────────────────


def test_endpoint_config_defaults():
    cfg = quic_native.EndpointConfig()
    assert cfg.idle_timeout_ms == 30_000
    assert cfg.keepalive_interval_ms == 10_000
    assert cfg.max_concurrent_bidi_streams == 256


def test_endpoint_config_overrides():
    cfg = quic_native.EndpointConfig(
        bind="127.0.0.1:0",
        idle_timeout_ms=5_000,
        keepalive_interval_ms=1_000,
        max_concurrent_bidi_streams=32,
    )
    assert cfg.bind == "127.0.0.1:0"
    assert cfg.idle_timeout_ms == 5_000
    assert cfg.keepalive_interval_ms == 1_000
    assert cfg.max_concurrent_bidi_streams == 32


def test_endpoint_config_rejects_bad_bind():
    with pytest.raises(Exception):
        quic_native.EndpointConfig(bind="not a socket addr")


# ─── endpoint construction ─────────────────────────────────────────────


def test_client_endpoint_constructs():
    id_ = quic_native.Identity.generate()
    ep = quic_native.Endpoint.client(id_, _client_loopback_config())
    assert ep.fingerprint == id_.fingerprint
    addr = ep.local_addr
    assert ":" in addr  # has a port
    ep.close()


def test_server_endpoint_constructs():
    id_ = quic_native.Identity.generate()
    ep = quic_native.Endpoint.server(id_, lambda fp: True, _client_loopback_config())
    assert ep.fingerprint == id_.fingerprint
    addr = ep.local_addr
    assert ":" in addr
    ep.close()


# ─── handshake + round-trip ────────────────────────────────────────────


def test_handshake_and_ping_pong():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    permitted = {bob.fingerprint}

    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp in permitted, ready
    )
    ready.wait(5)
    addr = server.local_addr

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=5_000)
    kind, payload = conn.send_frame_round_trip(quic_native.FRAME_PING, b"hello")
    assert kind == quic_native.FRAME_PONG
    assert payload == b"hello"
    conn.close()
    server.close()
    server_thread.join(timeout=2)


def test_chunk_request_response_round_trip():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    permitted = {bob.fingerprint}

    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp in permitted, ready
    )
    ready.wait(5)
    addr = server.local_addr

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=5_000)
    chunk_id = b"\x42" * 32
    kind, payload = conn.send_frame_round_trip(quic_native.FRAME_CHUNK_REQUEST, chunk_id)
    assert kind == quic_native.FRAME_CHUNK_RESPONSE
    assert payload == chunk_id  # echo server returns the input
    conn.close()
    server.close()
    server_thread.join(timeout=2)


def test_rtt_is_positive_after_round_trip():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp == bob.fingerprint, ready
    )
    ready.wait(5)

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(server.local_addr, alice.fingerprint, 5_000)
    conn.send_frame_round_trip(quic_native.FRAME_PING, b"x")
    rtt = conn.rtt_ms
    assert rtt >= 0
    conn.close()
    server.close()
    server_thread.join(timeout=2)


# ─── identity-bound rejection ──────────────────────────────────────────


def test_rejects_when_client_not_in_server_registry():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    # Server registry says no.
    server = quic_native.Endpoint.server(
        alice, lambda fp: False, _client_loopback_config()
    )
    addr = server.local_addr

    def server_loop():
        # Won't accept; just drain.
        server.accept_blocking(timeout_ms=2_000)

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    # Connect may succeed (initial CRYPTO exchange OK) but using the
    # connection must fail when the server's reject verdict propagates.
    try:
        conn = client.connect_blocking(addr, alice.fingerprint, timeout_ms=3_000)
    except Exception:
        # Hard reject at handshake — pass.
        server.close()
        t.join(timeout=2)
        return
    with pytest.raises(Exception):
        conn.send_frame_round_trip(quic_native.FRAME_PING, b"x")
    server.close()
    t.join(timeout=2)


def test_rejects_on_fingerprint_mismatch():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    mallory_fp = quic_native.Identity.generate().fingerprint
    # Server is happy to accept Bob, but Bob expects Mallory's fingerprint.
    server = quic_native.Endpoint.server(
        alice, lambda fp: fp == bob.fingerprint, _client_loopback_config()
    )
    addr = server.local_addr

    def server_loop():
        server.accept_blocking(timeout_ms=2_000)

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    with pytest.raises(Exception):
        client.connect_blocking(addr, mallory_fp, timeout_ms=3_000)
    server.close()
    t.join(timeout=2)


# ─── argument validation ──────────────────────────────────────────────


def test_connect_rejects_bad_addr():
    bob = quic_native.Identity.generate()
    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    with pytest.raises(Exception):
        client.connect_blocking("not an addr", b"\x00" * 32, 1_000)


def test_connect_rejects_bad_fingerprint_length():
    bob = quic_native.Identity.generate()
    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    with pytest.raises(Exception):
        client.connect_blocking("127.0.0.1:1", b"\x00" * 31, 1_000)


def test_send_frame_rejects_unknown_kind():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp == bob.fingerprint, ready
    )
    ready.wait(5)
    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(server.local_addr, alice.fingerprint, 5_000)
    with pytest.raises(Exception):
        conn.send_frame_round_trip(0x99, b"x")  # 0x99 not registered
    conn.close()
    server.close()
    server_thread.join(timeout=2)


def test_send_frame_rejects_oversized_payload():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp == bob.fingerprint, ready
    )
    ready.wait(5)
    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(server.local_addr, alice.fingerprint, 5_000)
    too_big = b"\x00" * (quic_native.MAX_CONTROL_FRAME_BYTES + 1)
    with pytest.raises(Exception):
        conn.send_frame_round_trip(quic_native.FRAME_PING, too_big)
    conn.close()
    server.close()
    server_thread.join(timeout=2)


# ─── parallel streams ──────────────────────────────────────────────────


def test_parallel_streams_no_serialization():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    ready = threading.Event()
    server, server_thread = _start_pong_server(
        alice, lambda fp: fp == bob.fingerprint, ready
    )
    ready.wait(5)

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(server.local_addr, alice.fingerprint, 5_000)

    results: list[tuple[int, bytes]] = []
    threads: list[threading.Thread] = []
    lock = threading.Lock()

    def issue(i: int):
        kind, payload = conn.send_frame_round_trip(
            quic_native.FRAME_PING, bytes([i & 0xFF] * 64)
        )
        with lock:
            results.append((kind, payload))

    for i in range(16):
        t = threading.Thread(target=issue, args=(i,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert len(results) == 16
    for kind, payload in results:
        assert kind == quic_native.FRAME_PONG
        assert len(payload) == 64

    conn.close()
    server.close()
    server_thread.join(timeout=2)


# ─── bulk transfer ────────────────────────────────────────────────────


def test_bulk_chunk_response_matches():
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()
    permitted = {bob.fingerprint}

    bulk_payload = b"\xCD" * (256 * 1024)  # 256 KiB

    server = quic_native.Endpoint.server(
        alice, lambda fp: fp in permitted, _client_loopback_config()
    )
    addr = server.local_addr

    # Hold the server-side PyConnection in a list so the main thread can
    # keep a reference and prevent the connection from dropping when the
    # server thread exits its loop. In production the daemon's peer
    # registry holds connections long-lived; the test mirrors that.
    server_conn_holder: list = []
    done_evt = threading.Event()

    def server_loop():
        conn = server.accept_blocking(timeout_ms=5_000)
        server_conn_holder.append(conn)
        if conn is None:
            done_evt.set()
            return
        for _ in range(8):
            result = conn.recv_frame_blocking(timeout_ms=5_000)
            if result is None:
                break
            stream_id, kind, _payload = result
            assert kind == quic_native.FRAME_CHUNK_REQUEST
            conn.send_response_on(stream_id, quic_native.FRAME_CHUNK_RESPONSE, bulk_payload)
        done_evt.set()

    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(addr, alice.fingerprint, 5_000)
    for i in range(8):
        cid = bytes([i] * 32)
        kind, payload = conn.send_frame_round_trip(quic_native.FRAME_CHUNK_REQUEST, cid)
        assert kind == quic_native.FRAME_CHUNK_RESPONSE
        assert payload == bulk_payload
    # All client iterations succeeded before either side closes.
    done_evt.wait(timeout=5)
    conn.close()
    if server_conn_holder and server_conn_holder[0] is not None:
        server_conn_holder[0].close()
    server.close()
    t.join(timeout=2)


def test_max_bulk_frame_round_trip():
    """The 1 MiB bulk-frame cap round-trips successfully."""
    alice = quic_native.Identity.generate()
    bob = quic_native.Identity.generate()

    payload = bytes(range(256)) * 4096  # exactly 1 MiB

    server = quic_native.Endpoint.server(
        alice, lambda fp: fp == bob.fingerprint, _client_loopback_config()
    )
    addr = server.local_addr

    server_conn_holder: list = []
    done_evt = threading.Event()

    def loop():
        conn = server.accept_blocking(timeout_ms=5_000)
        server_conn_holder.append(conn)
        if conn is None:
            done_evt.set()
            return
        result = conn.recv_frame_blocking(timeout_ms=5_000)
        if result is None:
            done_evt.set()
            return
        stream_id, _kind, _payload = result
        conn.send_response_on(stream_id, quic_native.FRAME_CHUNK_RESPONSE, payload)
        done_evt.set()

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    conn = client.connect_blocking(addr, alice.fingerprint, 5_000)
    kind, recv = conn.send_frame_round_trip(quic_native.FRAME_CHUNK_REQUEST, b"\x00" * 32)
    assert kind == quic_native.FRAME_CHUNK_RESPONSE
    assert len(recv) == quic_native.MAX_BULK_FRAME_BYTES
    assert recv == payload
    done_evt.wait(timeout=5)
    conn.close()
    if server_conn_holder and server_conn_holder[0] is not None:
        server_conn_holder[0].close()
    server.close()
    t.join(timeout=2)


# ─── close + lifecycle ────────────────────────────────────────────────


def test_endpoint_close_idempotent():
    bob = quic_native.Identity.generate()
    client = quic_native.Endpoint.client(bob, _client_loopback_config())
    client.close()
    # Second close should not panic.
    client.close()


def test_accept_timeout_returns_none():
    alice = quic_native.Identity.generate()
    server = quic_native.Endpoint.server(
        alice, lambda fp: True, _client_loopback_config()
    )
    # No client connecting; accept must timeout cleanly.
    start = time.time()
    result = server.accept_blocking(timeout_ms=300)
    elapsed = time.time() - start
    assert result is None
    assert elapsed < 1.0
    server.close()
