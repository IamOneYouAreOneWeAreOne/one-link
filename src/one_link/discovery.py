"""mDNS peer discovery using zeroconf (async).

Each daemon advertises a `_onelink._tcp.local.` service whose name is the
device's short_id. TXT record carries the full Ed25519 public-key hex so
peers can pin identity at first contact.

Browsing returns a live registry of known peers keyed by short_id.
"""

from __future__ import annotations

import asyncio
import contextlib
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
    # v0.5.4: rendezvous URLs the peer is advertising via mDNS TXT.
    # Other daemons on the same Wi-Fi pick this up so a household
    # only needs ONE device to know about a rendezvous — the rest
    # auto-discover. Stored as a list of strings; never None
    # (empty list when the peer didn't advertise any).
    rendezvous_urls: list[str] = field(default_factory=list)


@dataclass
class Registry:
    peers: dict[str, Peer] = field(default_factory=dict)
    on_change: Callable[[], None] | None = None

    def upsert(self, peer: Peer) -> None:
        # mDNS can briefly surface multiple service names for the same device
        # after restarts. The public key is the durable identity; keep the
        # newest advertisement and remove older aliases so the UI does not
        # fill with duplicates.
        if peer.ed_pub_hex:
            for sid, existing in list(self.peers.items()):
                if sid != peer.short_id and existing.ed_pub_hex == peer.ed_pub_hex:
                    self.peers.pop(sid, None)
        self.peers[peer.short_id] = peer
        if self.on_change:
            self.on_change()

    def remove(self, short_id: str) -> None:
        if self.peers.pop(short_id, None) is not None and self.on_change:
            self.on_change()

    def find(self, needle: str) -> Peer | None:
        matches = self.candidates(needle)
        return matches[0] if matches else None

    def candidates(self, needle: str) -> list[Peer]:
        """Return peer matches in safest order.

        Short IDs are stable and unambiguous, so exact/prefix identity matches
        beat hostname matches. Hostnames are human-friendly but many devices on
        one test machine share the same name, and stale mDNS records can linger.
        """
        if needle in self.peers:
            return [self.peers[needle]]

        lowered = needle.lower()
        seen: set[str] = set()
        out: list[Peer] = []
        for p in self.peers.values():
            if p.short_id.startswith(needle):
                out.append(p)
                seen.add(p.short_id)
        for p in self.peers.values():
            if p.short_id in seen:
                continue
            if p.hostname.lower() == lowered:
                out.append(p)
                seen.add(p.short_id)
        return out

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
    # v0.5.4: parse "rdz" TXT field — comma-separated rendezvous URLs.
    # Limit to a small count to keep TXT records bounded and resist
    # malicious peers spamming junk URLs into the mDNS scope.
    rdz_raw = props.get("rdz") or ""
    rdz_urls: list[str] = []
    if rdz_raw:
        for u in rdz_raw.split(","):
            u = u.strip().rstrip("/")
            if u and (u.startswith("http://") or u.startswith("https://")):
                rdz_urls.append(u)
                if len(rdz_urls) >= 8:
                    break
    return Peer(
        short_id=short_id,
        hostname=props.get("host", server),
        address=addr,
        port=info.port or 0,
        ed_pub_hex=props.get("pub", ""),
        rendezvous_urls=rdz_urls,
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
        self.service_to_short_id: dict[str, str] = {}

    def _schedule_resolve(self, type_: str, name: str) -> None:
        asyncio.run_coroutine_threadsafe(self._resolve(type_, name), self.loop)

    async def _resolve(self, type_: str, name: str) -> None:
        info = AsyncServiceInfo(type_, name)
        ok = await info.async_request(self.zc.zeroconf, timeout=2000)
        if not ok:
            return
        peer = _info_to_peer(info, self.self_short_id)
        if peer:
            self.service_to_short_id[name] = peer.short_id
            self.registry.upsert(peer)

    def add_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def update_service(self, _zc, type_: str, name: str) -> None:
        self._schedule_resolve(type_, name)

    def remove_service(self, _zc, _type, name: str) -> None:
        sid = self.service_to_short_id.pop(name, None) or name.split(".", 1)[0]
        self.registry.remove(sid)


class Discovery:
    def __init__(
        self,
        short_id: str,
        hostname: str,
        port: int,
        ed_pub_hex: str,
        rendezvous_urls: list[str] | None = None,
    ):
        self.short_id = short_id
        self.hostname = hostname
        self.port = port
        self.ed_pub_hex = ed_pub_hex
        # v0.5.4: rendezvous URLs we advertise in our mDNS TXT record
        # so other daemons on this LAN auto-discover them.
        self.rendezvous_urls: list[str] = list(rendezvous_urls or [])
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
        # mDNS TXT properties. Cap rdz length: an oversized record can
        # be silently dropped by routers, defeating the whole point.
        # 8 URLs × ~64 chars = 512 bytes, well under typical limits.
        rdz_value = ",".join(self.rendezvous_urls[:8])
        properties: dict[str, str] = {
            "sid": self.short_id,
            "host": self.hostname,
            "pub": self.ed_pub_hex,
            "v": "0.0.1",
        }
        if rdz_value:
            properties["rdz"] = rdz_value
        self._info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=properties,
            server=f"{self.short_id}.local.",
        )
        await self._zc.async_register_service(self._info, allow_name_change=True)
        self._browser = AsyncServiceBrowser(
            self._zc.zeroconf,
            SERVICE_TYPE,
            listener=_AsyncListener(self.registry, self.short_id, self._zc, loop),
        )

    async def update_rendezvous_urls(self, urls: list[str]) -> None:
        """v0.5.4: live-update the advertised rendezvous URLs in the
        mDNS TXT record without re-registering the service. Called
        whenever the daemon's rendezvous_urls setting changes."""
        self.rendezvous_urls = list(urls or [])
        if self._zc is None or self._info is None:
            return
        rdz_value = ",".join(self.rendezvous_urls[:8])
        # AsyncServiceInfo.properties is a dict; building a new one
        # and re-registering is the supported path.
        new_props: dict[str, str] = {
            "sid": self.short_id,
            "host": self.hostname,
            "pub": self.ed_pub_hex,
            "v": "0.0.1",
        }
        if rdz_value:
            new_props["rdz"] = rdz_value
        # `update_service` re-broadcasts the TXT record without
        # cycling the service registration (which would briefly remove
        # us from peers' registries and surface as a flap).
        from zeroconf import AsyncServiceInfo  # type: ignore[no-redef]
        local_ip = _best_local_ipv4()
        self._info = AsyncServiceInfo(
            type_=SERVICE_TYPE,
            name=f"{self.short_id}.{SERVICE_TYPE}",
            addresses=[socket.inet_aton(local_ip)],
            port=self.port,
            properties=new_props,
            server=f"{self.short_id}.local.",
        )
        with contextlib.suppress(Exception):
            await self._zc.async_update_service(self._info)

    async def prune_unreachable(self, *, timeout: float = 0.6) -> int:
        """TCP-probe every peer in the registry; remove any that don't accept
        a connection within `timeout` seconds. Returns count removed.

        Catches the "ghost peer" case where mDNS broadcasts (cached by the
        OS or a network device) outlive the daemon that announced them.
        """
        peers = list(self.registry.peers.values())
        if not peers:
            return 0

        async def _probe(p: Peer) -> tuple[Peer, bool]:
            try:
                fut = asyncio.open_connection(p.address, p.port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return p, True
            except (asyncio.TimeoutError, OSError):
                return p, False

        results = await asyncio.gather(*(_probe(p) for p in peers), return_exceptions=False)
        removed = 0
        for peer, ok in results:
            if not ok:
                self.registry.remove(peer.short_id)
                removed += 1
        return removed

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
