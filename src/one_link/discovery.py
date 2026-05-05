"""mDNS peer discovery using zeroconf (async).

Each daemon advertises a `_onelink._tcp.local.` service whose name is the
device's short_id. TXT record carries the full Ed25519 public-key hex so
peers can pin identity at first contact.

Browsing returns a live registry of known peers keyed by short_id.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Callable

from zeroconf import IPVersion, ServiceListener
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

SERVICE_TYPE = "_onelink._tcp.local."


@dataclass
class Peer:
    short_id: str
    hostname: str
    address: str
    port: int
    ed_pub_hex: str


@dataclass
class Registry:
    peers: dict[str, Peer] = field(default_factory=dict)
    on_change: Callable[[], None] | None = None

    def upsert(self, peer: Peer) -> None:
        self.peers[peer.short_id] = peer
        if self.on_change:
            self.on_change()

    def remove(self, short_id: str) -> None:
        if self.peers.pop(short_id, None) is not None and self.on_change:
            self.on_change()

    def find(self, needle: str) -> Peer | None:
        if needle in self.peers:
            return self.peers[needle]
        for p in self.peers.values():
            if p.hostname.lower() == needle.lower():
                return p
            if p.short_id.startswith(needle):
                return p
        return None

    def list(self) -> list[Peer]:
        return sorted(self.peers.values(), key=lambda p: p.hostname)


def _info_to_peer(info: AsyncServiceInfo, self_short_id: str) -> Peer | None:
    if not info.addresses:
        return None
    addr = socket.inet_ntoa(info.addresses[0])
    props = {
        (k.decode() if isinstance(k, bytes) else k): (
            v.decode() if isinstance(v, bytes) else v
        )
        for k, v in (info.properties or {}).items()
    }
    short_id = props.get("sid") or info.name.split(".", 1)[0]
    if short_id == self_short_id:
        return None
    server = info.server.rstrip(".") if info.server else "?"
    return Peer(
        short_id=short_id,
        hostname=props.get("host", server),
        address=addr,
        port=info.port or 0,
        ed_pub_hex=props.get("pub", ""),
    )


class _AsyncListener(ServiceListener):
    """Sync ServiceListener that schedules async work on the daemon loop."""

    def __init__(
        self,
        registry: Registry,
        self_short_id: str,
        zc: AsyncZeroconf,
        loop: asyncio.AbstractEventLoop,
    ):
        self.registry = registry
        self.self_short_id = self_short_id
        self.zc = zc
        self.loop = loop

    def _schedule_resolve(self, type_: str, name: str) -> None:
        asyncio.run_coroutine_threadsafe(self._resolve(type_, name), self.loop)

    async def _resolve(self, type_: str, name: str) -> None:
        info = AsyncServiceInfo(type_, name)
        ok = await info.async_request(self.zc.zeroconf, timeout=2000)
        if not ok:
            return
        peer = _info_to_peer(info, self.self_short_id)
        if peer:
            self.registry.upsert(peer)

    def add_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def update_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def remove_service(self, _zc, _type, name: str) -> None:
        sid = name.split(".", 1)[0]
        self.registry.remove(sid)


class Discovery:
    def __init__(
        self,
        short_id: str,
        hostname: str,
        port: int,
        ed_pub_hex: str,
    ):
        self.short_id = short_id
        self.hostname = hostname
        self.port = port
        self.ed_pub_hex = ed_pub_hex
        self.registry = Registry()
        self._zc: AsyncZeroconf | None = None
        self._info: AsyncServiceInfo | None = None
        self._browser: AsyncServiceBrowser | None = None

    async def start(self) -> None:
        if self._zc is not None:
            return
        loop = asyncio.get_running_loop()
        self._zc = AsyncZeroconf(ip_version=IPVersion.V4Only)
        local_ip = _best_local_ipv4()
        self._info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties={
                "sid": self.short_id,
                "host": self.hostname,
                "pub": self.ed_pub_hex,
                "v": "0.0.1",
            },
            server=f"{self.short_id}.local.",
        )
        await self._zc.async_register_service(self._info, allow_name_change=True)
        self._browser = AsyncServiceBrowser(
            self._zc.zeroconf,
            SERVICE_TYPE,
            listener=_AsyncListener(self.registry, self.short_id, self._zc, loop),
        )

    async def stop(self) -> None:
        try:
            if self._browser:
                await self._browser.async_cancel()
        except Exception:
            pass
        try:
            if self._info and self._zc:
                await self._zc.async_unregister_service(self._info)
        except Exception:
            pass
        try:
            if self._zc:
                await self._zc.async_close()
        except Exception:
            pass
        self._zc = None
        self._info = None
        self._browser = None


def _best_local_ipv4() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()
