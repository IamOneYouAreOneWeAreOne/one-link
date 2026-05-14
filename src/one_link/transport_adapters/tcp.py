"""TCP transport sessions for concrete fabric routes.

The fabric adapter contract sits below One Link's identity, capability,
channel crypto, and chunk verification. This module therefore only opens a
byte pipe and preserves frame boundaries with the existing wire framing.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

from one_link.wire import read_frame, write_frame

from .base import PreparedRoute, RepairResult, SessionStats


@dataclass
class TcpStreamSession:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    route: PreparedRoute
    mtu: int = 16 * 1024 * 1024
    ordered: bool = True
    reliable: bool = True
    bulk_capable: bool = True
    control_capable: bool = True
    _bytes_sent: int = 0
    _bytes_received: int = 0
    _frames_sent: int = 0
    _frames_received: int = 0
    _opened_ns: int = field(default_factory=time.perf_counter_ns)

    async def send_frame(self, frame: bytes) -> None:
        await write_frame(self.writer, bytes(frame))
        self._bytes_sent += len(frame)
        self._frames_sent += 1

    async def recv_frame(self) -> bytes:
        frame = await read_frame(self.reader)
        self._bytes_received += len(frame)
        self._frames_received += 1
        return frame

    async def stats(self) -> SessionStats:
        elapsed_s = max(1e-9, (time.perf_counter_ns() - self._opened_ns) / 1_000_000_000)
        measured_bps = float((self._bytes_sent + self._bytes_received) * 8) / elapsed_s
        return SessionStats(
            bytes_sent=self._bytes_sent,
            bytes_received=self._bytes_received,
            frames_sent=self._frames_sent,
            frames_received=self._frames_received,
            measured_bps=measured_bps,
        )

    async def repair(self, reason: str) -> RepairResult:
        return RepairResult(
            repaired=False,
            action="reopen_route",
            retry_after_s=0.0,
            reason=str(reason or "tcp session must be reopened"),
        )

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


async def open_tcp_route(route: PreparedRoute, *, timeout_s: float = 5.0) -> TcpStreamSession:
    host, port = _endpoint_host_port(route.endpoint)
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=max(0.1, float(timeout_s)),
    )
    return TcpStreamSession(reader=reader, writer=writer, route=route)


def _endpoint_host_port(endpoint: str | None) -> tuple[str, int]:
    if not endpoint:
        raise ValueError("tcp route is missing endpoint")
    if endpoint.startswith("["):
        host, _, rest = endpoint[1:].partition("]")
        if not host or not rest.startswith(":"):
            raise ValueError("invalid bracketed IPv6 endpoint")
        port_s = rest[1:]
    else:
        host, sep, port_s = endpoint.rpartition(":")
        if not sep or not host:
            raise ValueError("invalid tcp endpoint")
    port = int(port_s)
    if port <= 0 or port > 65535:
        raise ValueError("tcp endpoint port must be 1..65535")
    return host, port
