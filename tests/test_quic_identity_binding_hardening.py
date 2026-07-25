"""QUIC accepts are authorized only by their authenticated TLS identity."""

from __future__ import annotations

from collections import deque
from types import SimpleNamespace

import pytest

from one_link.daemon import Daemon


class _Connection:
    def __init__(self, fingerprint: bytes | None, *, method: bool = True) -> None:
        self.remote_address = "127.0.0.1:4433"
        self.closed: list[tuple[int, bytes]] = []
        if method:
            self.peer_fingerprint = lambda: fingerprint  # type: ignore[attr-defined]

    def close(self, code: int, reason: bytes) -> None:
        self.closed.append((code, reason))


class _OneShotEndpoint:
    def __init__(self, daemon: Daemon, connection: _Connection) -> None:
        self._daemon = daemon
        self._connection = connection

    def accept_blocking(self, timeout_ms: int) -> _Connection:
        assert timeout_ms == 5000
        # Make the captured endpoint stale so the loop exits after processing
        # this one connection.
        self._daemon._quic_server_endpoint = object()
        return self._connection


def _daemon_for_accept(
    connection: _Connection,
    *,
    pinned: set[str],
    callback_order: list[bytes],
) -> Daemon:
    daemon = object.__new__(Daemon)
    daemon._quic_inbound = {}
    daemon._quic_inbound_tasks = set()
    daemon._degradation_events = []
    daemon._quic_recent_paired = deque(
        (1_000_000_000_000, fingerprint) for fingerprint in callback_order
    )
    daemon.state = SimpleNamespace(
        get_peer=lambda fingerprint: (
            SimpleNamespace(trust="pinned") if fingerprint in pinned else None
        )
    )
    endpoint = _OneShotEndpoint(daemon, connection)
    daemon._quic_server_endpoint = endpoint
    return daemon


@pytest.mark.asyncio
async def test_missing_connection_identity_closes_instead_of_using_fifo() -> None:
    queued = bytes.fromhex("11" * 32)
    conn = _Connection(None, method=False)
    daemon = _daemon_for_accept(
        conn,
        pinned={queued.hex()},
        callback_order=[queued],
    )
    await daemon._quic_accept_loop()
    assert daemon._quic_inbound == {}
    assert conn.closed == [(0x100, b"identity binding required")]
    assert daemon._degradation_events[-1]["kind"] == (
        "quic_accept_identity_binding_rejected"
    )


@pytest.mark.asyncio
async def test_failed_a_then_accepted_b_cannot_cross_bind_fifo_order() -> None:
    fp_a = bytes.fromhex("22" * 32)
    fp_b = bytes.fromhex("33" * 32)
    conn_b = _Connection(fp_b)
    daemon = _daemon_for_accept(
        conn_b,
        pinned={fp_a.hex(), fp_b.hex()},
        callback_order=[fp_a, fp_b],
    )
    dispatched: list[str] = []

    async def _sink(_conn, _remote: str, peer_fp: str = "") -> None:
        dispatched.append(peer_fp)

    daemon._quic_inbound_frame_loop = _sink  # type: ignore[method-assign]
    await daemon._quic_accept_loop()
    if daemon._quic_inbound_tasks:
        await next(iter(daemon._quic_inbound_tasks))
    assert set(daemon._quic_inbound) == {fp_b.hex()}
    assert dispatched == [fp_b.hex()]
    assert fp_a.hex() not in daemon._quic_inbound
    assert conn_b.closed == []


@pytest.mark.asyncio
async def test_peer_revoked_after_tls_callback_is_rejected_at_accept() -> None:
    fp = bytes.fromhex("44" * 32)
    conn = _Connection(fp)
    daemon = _daemon_for_accept(conn, pinned=set(), callback_order=[fp])
    await daemon._quic_accept_loop()
    assert daemon._quic_inbound == {}
    assert conn.closed
    assert daemon._degradation_events[-1]["reason"] == "peer_no_longer_pinned"


def test_legacy_fifo_authorization_path_is_absent() -> None:
    source = (
        __import__("pathlib").Path(__file__).resolve().parents[1]
        / "src/one_link/daemon.py"
    ).read_text(encoding="utf-8")
    loop = source[source.index("async def _quic_accept_loop"):]
    loop = loop[: loop.index("async def _quic_inbound_frame_loop")]
    assert "_quic_recent_paired.popleft()\n                    peer_fp" not in loop
    assert "quic_accept_fifo_race_window" not in loop
    assert "quic_accept_identity_binding_rejected" in loop

