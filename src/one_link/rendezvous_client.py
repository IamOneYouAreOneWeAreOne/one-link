"""Daemon-side rendezvous client.

Wraps an aiohttp.ClientSession to talk to a configured rendezvous URL
(e.g. https://rendezvous.example.com). Registers the local device's
presence on a refresh schedule, looks up other peers' current
endpoints when asked, and revokes on graceful shutdown.

Designed for partial-failure tolerance: if the rendezvous is offline,
LAN/mDNS discovery still works; only cross-internet pairing is
affected. The daemon never blocks on rendezvous I/O — all calls have
explicit timeouts.

Multiple rendezvous URLs can be configured; register propagates to
all of them in parallel, lookup races them and returns the first
non-404. This gives operators a free-fault-tolerance and a path to
federation without changing the protocol.

v0.20.7 (sovereignty pack): when ``ONE_LINK_TOR_PROXY`` is set in
the environment (e.g. ``socks5://127.0.0.1:9050`` for a local Tor
SOCKS port), all outbound rendezvous traffic routes through the
SOCKS proxy. The rendezvous server then sees Tor exit / hidden
service traffic only — never the user's real IP. Requires the
optional ``[tor]`` install extra (``pip install one_link[tor]``)
which pulls in ``aiohttp-socks``.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
from dataclasses import dataclass
from typing import Optional

import aiohttp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# v0.20.7 (sovereignty pack): SOCKS proxy support for outbound
# rendezvous traffic. The aiohttp_socks dep is optional — the import
# is lazy + guarded so the daemon runs identically without it.
TOR_PROXY_ENV = "ONE_LINK_TOR_PROXY"


def _build_proxy_connector() -> aiohttp.BaseConnector | None:
    """Return a configured ProxyConnector if ONE_LINK_TOR_PROXY is
    set and aiohttp_socks is importable; None otherwise.

    Sovereignty note: Tor's SOCKS port is the canonical entry point
    for routing traffic over the Tor network. A user who runs the
    daemon with ``ONE_LINK_TOR_PROXY=socks5://127.0.0.1:9050``
    achieves rendezvous-without-corporate-IP-visibility — the
    rendezvous operator sees Tor exit traffic only. Pair this with
    a rendezvous URL whose host is a ``.onion`` to get full
    end-to-end-onion sovereignty (no exit node ever sees the
    plaintext rendezvous request, because the request never leaves
    the Tor network).
    """
    proxy_url = os.environ.get(TOR_PROXY_ENV, "").strip()
    if not proxy_url:
        return None
    try:
        from aiohttp_socks import ProxyConnector  # type: ignore[import-not-found]
    except ImportError:
        log.warning(
            "%s is set but aiohttp-socks is not installed; "
            "outbound rendezvous traffic will use the direct "
            "network. Install with: pip install one_link[tor]",
            TOR_PROXY_ENV,
        )
        return None
    try:
        return ProxyConnector.from_url(proxy_url)
    except Exception as e:
        log.warning(
            "%s=%r could not be parsed as a SOCKS proxy URL (%s); "
            "outbound rendezvous traffic will use the direct network",
            TOR_PROXY_ENV, proxy_url, e,
        )
        return None

from one_link.rendezvous_proto import (
    Endpoint,
    LookupAck,
    PROTOCOL_VERSION,
    RegisterAck,
    sign_register,
    sign_revoke,
    _b64,  # noqa: F401 — private helper, used for lookup URL building
)

log = logging.getLogger("one_link.rendezvous_client")

DEFAULT_REQUEST_TIMEOUT_S = 5.0
DEFAULT_REGISTER_TTL_S = 300       # 5 min
DEFAULT_REFRESH_FRACTION = 0.5     # refresh halfway through TTL

# v0.5.4: Baked-in default rendezvous URLs. EMPTY by default — the
# upstream OSS distribution doesn't operate a default rendezvous on
# behalf of users.
#
# Three ways an operator can pre-populate this for their distribution:
#   1. Patch this constant before building the binary / wheel.
#   2. Ship a `seeds.toml` in the user's data dir with `[rendezvous]
#      urls = ["https://..."]`.
#   3. Set env var `ONE_LINK_RDZ_DEFAULTS=https://a,https://b` at start.
#
# All three feed into Daemon._harvest_default_rendezvous_seeds(); user
# edits in Settings always override the defaults afterwards. See
# docs/RENDEZVOUS_DEPLOY.md for the recommended posture.
DEFAULT_RENDEZVOUS_URLS: list[str] = []


@dataclass
class RendezvousObservedSelf:
    """What the rendezvous saw of this device — its public IP:port as
    visible from the rendezvous's vantage point. Useful for the
    daemon's own NAT-type detection in v0.5.1."""
    rendezvous_url: str
    observed_host: str
    observed_port: int
    expires_at_ms: int
    server_time_ms: int


class RendezvousError(RuntimeError):
    """Raised on any rendezvous-side failure (4xx, 5xx, network)."""


class RendezvousClient:
    """One client per (private_key, set of rendezvous URLs).

    Lifecycle:
      1. `await start()` — opens HTTP session, kicks off the refresh
         loop. Initial register is awaited so callers know whether
         registration succeeded.
      2. Daemon calls `await lookup(target_pubkey)` whenever it needs
         to find a peer not visible on mDNS.
      3. `await stop()` — sends revoke (best-effort, short timeout)
         and closes the HTTP session.
    """

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        pubkey: bytes,
        rendezvous_urls: list[str],
        advertise_endpoints: list[Endpoint] | None = None,
        capabilities: list[str] | None = None,
        ttl_s: int = DEFAULT_REGISTER_TTL_S,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        refresh_fraction: float = DEFAULT_REFRESH_FRACTION,
    ):
        if not rendezvous_urls:
            raise ValueError("at least one rendezvous URL is required")
        self._private_key = private_key
        self._pubkey = pubkey
        self._urls = [u.rstrip("/") for u in rendezvous_urls]
        self._advertise = list(advertise_endpoints or [])
        self._capabilities = list(capabilities or [])
        self._ttl_s = ttl_s
        self._timeout = aiohttp.ClientTimeout(total=request_timeout_s)
        self._refresh_fraction = max(0.1, min(0.9, refresh_fraction))

        self._session: aiohttp.ClientSession | None = None
        self._refresh_task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self._last_observed: dict[str, RendezvousObservedSelf] = {}

    # ─── lifecycle ──────────────────────────────────────────────────

    async def start(self) -> None:
        if self._session is not None:
            return
        # v0.20.7 (sovereignty pack): route through Tor SOCKS proxy
        # when ONE_LINK_TOR_PROXY is set + aiohttp-socks is available.
        proxy_connector = _build_proxy_connector()
        if proxy_connector is not None:
            log.info(
                "rendezvous: outbound traffic routed via %s",
                os.environ.get(TOR_PROXY_ENV, "<env unset>"),
            )
            self._session = aiohttp.ClientSession(
                timeout=self._timeout,
                connector=proxy_connector,
            )
        else:
            self._session = aiohttp.ClientSession(timeout=self._timeout)
        # Initial register to all URLs — race them but don't fail if some
        # are down.
        await self._register_all()
        self._refresh_task = asyncio.create_task(self._refresh_loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._refresh_task is not None:
            self._refresh_task.cancel()
            with contextlib.suppress(BaseException):
                await self._refresh_task
            self._refresh_task = None
        # Best-effort revoke.
        if self._session is not None and not self._session.closed:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._revoke_all(), timeout=3.0)
            await self._session.close()
        self._session = None

    # ─── public API ─────────────────────────────────────────────────

    async def lookup(self, target_pubkey: bytes) -> Optional[LookupAck]:
        """Look up a peer's current presence. Races configured
        rendezvous URLs and returns the first non-404 hit. None if
        no rendezvous knows the peer or all are unreachable."""
        if self._session is None:
            raise RendezvousError("client not started")
        if len(target_pubkey) != 32:
            raise ValueError("target_pubkey must be 32 bytes")
        path = f"/api/v1/lookup/{_b64(target_pubkey)}"

        assert self._session is not None, "RendezvousClient.start() must be called first"
        session = self._session

        async def _try_one(url: str) -> Optional[LookupAck]:
            try:
                async with session.get(url + path) as r:
                    if r.status == 404:
                        return None
                    if r.status != 200:
                        log.warning(
                            "rendezvous %s lookup status=%d", url, r.status
                        )
                        return None
                    body = await r.json()
                return LookupAck.from_wire(body)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("rendezvous %s lookup failed: %s", url, e)
                return None

        # Race the URLs in parallel; return the first non-None.
        tasks = [asyncio.create_task(_try_one(u)) for u in self._urls]
        try:
            for finished in asyncio.as_completed(tasks):
                result = await finished
                if result is not None:
                    return result
            return None
        finally:
            for t in tasks:
                if not t.done():
                    t.cancel()

    @property
    def observed_self(self) -> dict[str, RendezvousObservedSelf]:
        """Last-seen self-observation per rendezvous URL.
        Populated after a successful register."""
        return dict(self._last_observed)

    @property
    def session(self) -> aiohttp.ClientSession | None:
        """v0.6.2 audit: expose the daemon-lifetime aiohttp session
        so other components (the relay outbound dial, in particular)
        can route through it instead of creating their own per-call
        session that's prone to leaking under cancellation races."""
        return self._session

    def update_advertised_endpoints(self, endpoints: list[Endpoint]) -> None:
        """Called when the daemon learns its own LAN IPs / NAT-mapped
        addresses change. Next refresh will pick this up."""
        self._advertise = list(endpoints)

    # ─── internals ──────────────────────────────────────────────────

    async def _register_all(self) -> None:
        """Register against all rendezvous URLs in parallel. Logs but
        does not raise on per-URL failure."""
        if self._session is None:
            return

        async def _try_one(url: str) -> None:
            req = sign_register(
                private_key=self._private_key,
                pubkey=self._pubkey,
                ttl_s=self._ttl_s,
                advertised_endpoints=self._advertise,
                nat_type="unknown",
                capabilities=self._capabilities,
            )
            assert self._session is not None
            try:
                async with self._session.post(
                    url + "/api/v1/register", json=req.to_wire()
                ) as r:
                    if r.status != 200:
                        log.warning(
                            "rendezvous %s register status=%d body=%s",
                            url, r.status, (await r.text())[:200],
                        )
                        return
                    body = await r.json()
                ack = RegisterAck.from_wire(body)
                self._last_observed[url] = RendezvousObservedSelf(
                    rendezvous_url=url,
                    observed_host=ack.observed_host,
                    observed_port=ack.observed_port,
                    expires_at_ms=ack.expires_at_ms,
                    server_time_ms=ack.server_time_ms,
                )
                log.info(
                    "rendezvous %s registered; observed self at %s:%d",
                    url, ack.observed_host, ack.observed_port,
                )
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                log.warning("rendezvous %s register failed: %s", url, e)

        await asyncio.gather(*[_try_one(u) for u in self._urls], return_exceptions=False)

    async def _revoke_all(self) -> None:
        if self._session is None:
            return
        session = self._session
        rev = sign_revoke(private_key=self._private_key, pubkey=self._pubkey)

        async def _try_one(url: str) -> None:
            try:
                async with session.post(
                    url + "/api/v1/revoke", json=rev.to_wire()
                ) as r:
                    log.debug("rendezvous %s revoke status=%d", url, r.status)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                log.debug("rendezvous %s revoke failed: %s", url, e)

        await asyncio.gather(*[_try_one(u) for u in self._urls], return_exceptions=False)

    async def _refresh_loop(self) -> None:
        try:
            while not self._stop.is_set():
                # Sleep for refresh_fraction of TTL, then re-register.
                interval = max(15.0, self._ttl_s * self._refresh_fraction)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=interval)
                    return  # stop fired
                except asyncio.TimeoutError:
                    pass
                if self._stop.is_set():
                    return
                await self._register_all()
        except asyncio.CancelledError:
            return


# ─── helper: enumerate local advertise-able endpoints ───────────────

def discover_local_endpoints(
    *,
    peer_port: int,
    include_loopback: bool = False,
) -> list[Endpoint]:
    """Best-effort enumeration of local IPv4 addresses we can advertise.

    Skips 169.254.x.x link-local, 127.0.0.0/8 (unless `include_loopback`),
    and 0.0.0.0. The result is what we publish to the rendezvous as our
    `advertised_endpoints` — peers on the same NAT might be able to use
    these directly without needing the rendezvous-observed public IP.
    """
    # If we don't have a real peer-listener port (e.g., outbound-only
    # daemon during tests, or pre-bind state), there's nothing to
    # advertise — return an empty list rather than producing port-0
    # entries that the rendezvous would reject.
    if not peer_port or int(peer_port) <= 0:
        return []
    out: list[Endpoint] = []
    seen: set[str] = set()
    try:
        host = socket.gethostname()
        for info in socket.getaddrinfo(host, None, family=socket.AF_INET):
            # info[4] for AF_INET is (host, port); host is always str.
            addr_raw = info[4][0]
            if not isinstance(addr_raw, str):
                continue
            addr: str = addr_raw
            if not addr or addr in seen:
                continue
            seen.add(addr)
            if addr.startswith("169.254."):
                continue
            if addr == "0.0.0.0":
                continue
            if addr.startswith("127.") and not include_loopback:
                continue
            out.append(Endpoint(host=addr, port=int(peer_port)))
    except OSError as e:
        log.debug("getaddrinfo failed: %s", e)
    # Also try the "what IP do I use to reach the public internet"
    # trick — opens a UDP socket and inspects the chosen source IP.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 53))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and ip not in seen and not ip.startswith("169.254."):
            out.append(Endpoint(host=ip, port=int(peer_port)))
    except OSError:
        pass
    return out
