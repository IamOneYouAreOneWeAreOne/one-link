"""One Link Rendezvous Server — production aiohttp app.

Runs as a small standalone service that holds, in memory, signed
presence beacons from One Link daemons. Devices on different networks
look each other up here so they can attempt direct connection
(NAT hole-punch in v0.5.1, encrypted relay fallback in v0.5.2).

Deploy as a single Python process behind nginx / Cloudflare / similar
TLS-terminating reverse proxy. The protocol payloads are signed; the
HTTP transport need only be reasonably honest about delivery.

Run with:

    python -m one_link.rendezvous_server --host 0.0.0.0 --port 7118

Or via the convenience entrypoint script in `scripts/rendezvous.py`.

Threats this hardens against:

  - **Spoofed registration**: every register/revoke is Ed25519-signed
    by the device's own key. A third party can replay an unmodified
    register, but only inside the 60s replay window, and the registry
    overwrites idempotently.
  - **Resource exhaustion**: per-IP rate limit + per-pubkey rate limit
    + hard cap on total registrations + bounded TTL.
  - **Censoring lookups**: the protocol is symmetric; anyone can run
    their own. There is no authoritative rendezvous.
  - **Plaintext exposure**: this server never sees chat or file
    payloads. It records `(pubkey, observed_endpoint, advertised_endpoints)`
    only.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from aiohttp import web

from one_link.rendezvous_proto import (
    MAX_REQUEST_BYTES,
    LookupAck,
    RegisterAck,
    RegisterReq,
    RevokeReq,
    Endpoint,
    now_ms,
    timestamp_within_replay_window,
)

log = logging.getLogger("one_link.rendezvous_server")


# ─── config ─────────────────────────────────────────────────────────

@dataclass
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 7118
    # Hard cap on total registrations the server will hold. Keeps
    # memory bounded even under abuse. Each entry is ~1 KB.
    max_registrations: int = 200_000
    # Per-IP rate limits. Tokens reset on a sliding 60s window.
    rate_per_ip_per_min: int = 120
    # Per-pubkey rate limit on register specifically. A single device
    # legitimately re-registers every TTL/2 (so for ttl=300, every 150s
    # = 0.4/min). 30/min absorbs reasonable churn.
    rate_register_per_pubkey_per_min: int = 30
    # How often to scan for expired entries. Sub-second granularity not
    # needed; the scan is O(N) where N = registrations.
    eviction_interval_s: float = 5.0
    # Maximum trust we place in client-supplied advertised endpoints.
    # Above this count we reject the registration outright (the proto
    # already enforces a smaller cap; this is double-defense).
    max_advertised_endpoints: int = 8


# ─── in-memory store ────────────────────────────────────────────────

@dataclass
class Registration:
    pubkey: bytes
    observed_endpoint: Endpoint
    advertised_endpoints: list[Endpoint]
    nat_type: str
    capabilities: list[str]
    registered_at_ms: int
    expires_at_ms: int


class Registry:
    """Pubkey -> Registration. Bounded; evicts on insert when full."""

    def __init__(self, max_entries: int):
        self.max_entries = max_entries
        self._entries: dict[bytes, Registration] = {}
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, pubkey: bytes) -> Optional[Registration]:
        return self._entries.get(pubkey)

    def upsert(self, reg: Registration) -> None:
        # If we'd exceed capacity, evict the oldest-expiring entry.
        if reg.pubkey not in self._entries and len(self._entries) >= self.max_entries:
            victim = min(self._entries.values(), key=lambda r: r.expires_at_ms)
            self._entries.pop(victim.pubkey, None)
            self.evictions += 1
        self._entries[reg.pubkey] = reg

    def remove(self, pubkey: bytes) -> bool:
        return self._entries.pop(pubkey, None) is not None

    def evict_expired(self, now_ms_value: int) -> int:
        dead = [k for k, v in self._entries.items() if v.expires_at_ms <= now_ms_value]
        for k in dead:
            self._entries.pop(k, None)
        return len(dead)


# ─── token-bucket rate limiter ──────────────────────────────────────

class _RateLimiter:
    """Sliding-window per-key counter. Bounded — keys with no activity
    in the last `window_s` are dropped during sweeps."""

    def __init__(self, rate_per_min: int, window_s: float = 60.0):
        self.rate = int(rate_per_min)
        self.window_s = float(window_s)
        self._hits: dict[str, deque[float]] = {}

    def admit(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_s
        dq = self._hits.setdefault(key, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.rate:
            return False
        dq.append(now)
        return True

    def sweep(self) -> int:
        """Drop keys with no live tokens. Returns dropped count."""
        now = time.monotonic()
        cutoff = now - self.window_s
        dead = []
        for k, dq in self._hits.items():
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(k)
        for k in dead:
            self._hits.pop(k, None)
        return len(dead)


# ─── metrics ────────────────────────────────────────────────────────

@dataclass
class Metrics:
    started_at_ms: int = field(default_factory=now_ms)
    registers_total: int = 0
    register_rejects_total: int = 0
    lookups_total: int = 0
    lookup_misses_total: int = 0
    revokes_total: int = 0
    rate_limit_rejects_total: int = 0


# ─── server app ─────────────────────────────────────────────────────

class RendezvousApp:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.registry = Registry(max_entries=config.max_registrations)
        self.rate_per_ip = _RateLimiter(rate_per_min=config.rate_per_ip_per_min)
        self.rate_register_per_pubkey = _RateLimiter(
            rate_per_min=config.rate_register_per_pubkey_per_min
        )
        self.metrics = Metrics()
        self._eviction_task: asyncio.Task | None = None

    def make_app(self) -> web.Application:
        app = web.Application(client_max_size=MAX_REQUEST_BYTES)
        app.router.add_post("/api/v1/register", self._handle_register)
        app.router.add_get("/api/v1/lookup/{pubkey_b64}", self._handle_lookup)
        app.router.add_post("/api/v1/revoke", self._handle_revoke)
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)
        return app

    async def _on_startup(self, _app: web.Application) -> None:
        self._eviction_task = asyncio.create_task(self._eviction_loop())

    async def _on_cleanup(self, _app: web.Application) -> None:
        if self._eviction_task:
            self._eviction_task.cancel()
            with contextlib.suppress(BaseException):
                await self._eviction_task
            self._eviction_task = None

    async def _eviction_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self.config.eviction_interval_s)
                evicted = self.registry.evict_expired(now_ms())
                self.rate_per_ip.sweep()
                self.rate_register_per_pubkey.sweep()
                if evicted:
                    log.debug("evicted %d expired registrations", evicted)
        except asyncio.CancelledError:
            return

    # ─── request helpers ────────────────────────────────────────────

    def _client_ip(self, request: web.Request) -> str:
        """Best-effort remote IP. If a reverse proxy set
        X-Forwarded-For, trust the leftmost entry; otherwise fall back
        to the socket peer. Operators deploying without a known proxy
        can disable XFF trust by stripping the header upstream."""
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer:
            return peer[0]
        return "unknown"

    def _client_port(self, request: web.Request) -> int:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if peer:
            return int(peer[1])
        return 0

    def _rate_check_ip(self, request: web.Request) -> bool:
        ip = self._client_ip(request)
        ok = self.rate_per_ip.admit(ip)
        if not ok:
            self.metrics.rate_limit_rejects_total += 1
            log.info("rate-limited IP=%s on %s", ip, request.path)
        return ok

    async def _read_json(self, request: web.Request) -> dict:
        body = await request.read()
        if len(body) > MAX_REQUEST_BYTES:
            raise web.HTTPRequestEntityTooLarge(
                max_size=MAX_REQUEST_BYTES, actual_size=len(body)
            )
        try:
            d = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise web.HTTPBadRequest(text=f"invalid json: {e}")
        if not isinstance(d, dict):
            raise web.HTTPBadRequest(text="body must be a JSON object")
        return d

    # ─── handlers ───────────────────────────────────────────────────

    async def _handle_register(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        try:
            payload = await self._read_json(request)
            req = RegisterReq.from_wire(payload)
        except web.HTTPException:
            self.metrics.register_rejects_total += 1
            raise
        except ValueError as e:
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text=f"bad request: {e}")

        if not timestamp_within_replay_window(req.timestamp_ms):
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text="timestamp out of replay window")

        try:
            req.verify()
        except ValueError:
            self.metrics.register_rejects_total += 1
            return web.Response(status=401, text="signature does not verify")

        # Per-pubkey rate limit kicks in only AFTER signature verifies,
        # so an attacker without the key can't burn through a victim's
        # quota with garbage signatures.
        pubkey_b64_for_rate = req.pubkey.hex()
        if not self.rate_register_per_pubkey.admit(pubkey_b64_for_rate):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="too many registrations for this pubkey")

        # Cap advertised endpoints (defense-in-depth; proto already caps).
        if len(req.advertised_endpoints) > self.config.max_advertised_endpoints:
            self.metrics.register_rejects_total += 1
            return web.Response(status=400, text="too many advertised endpoints")

        observed = Endpoint(host=self._client_ip(request), port=self._client_port(request))
        now = now_ms()
        expires_at = now + req.ttl_s * 1000

        reg = Registration(
            pubkey=req.pubkey,
            observed_endpoint=observed,
            advertised_endpoints=list(req.advertised_endpoints),
            nat_type=req.nat_type,
            capabilities=list(req.capabilities),
            registered_at_ms=now,
            expires_at_ms=expires_at,
        )
        self.registry.upsert(reg)
        self.metrics.registers_total += 1

        ack = RegisterAck(
            observed_host=observed.host,
            observed_port=observed.port,
            server_time_ms=now,
            expires_at_ms=expires_at,
        )
        return web.json_response(ack.to_wire())

    async def _handle_lookup(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        from one_link.rendezvous_proto import _b64d  # type: ignore

        try:
            pubkey = _b64d(request.match_info["pubkey_b64"])
        except Exception:
            return web.Response(status=400, text="invalid pubkey_b64")
        if len(pubkey) != 32:
            return web.Response(status=400, text="pubkey must be 32 bytes")

        reg = self.registry.get(pubkey)
        now = now_ms()
        if reg is None or reg.expires_at_ms <= now:
            if reg is not None:
                self.registry.remove(pubkey)
            self.metrics.lookups_total += 1
            self.metrics.lookup_misses_total += 1
            return web.Response(status=404, text="not registered")

        ack = LookupAck(
            pubkey=reg.pubkey,
            observed_endpoint=reg.observed_endpoint,
            advertised_endpoints=list(reg.advertised_endpoints),
            nat_type=reg.nat_type,
            capabilities=list(reg.capabilities),
            expires_at_ms=reg.expires_at_ms,
            server_time_ms=now,
        )
        self.metrics.lookups_total += 1
        return web.json_response(ack.to_wire())

    async def _handle_revoke(self, request: web.Request) -> web.Response:
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        try:
            payload = await self._read_json(request)
            req = RevokeReq.from_wire(payload)
        except web.HTTPException:
            raise
        except ValueError as e:
            return web.Response(status=400, text=f"bad request: {e}")

        if not timestamp_within_replay_window(req.timestamp_ms):
            return web.Response(status=400, text="timestamp out of replay window")
        try:
            req.verify()
        except ValueError:
            return web.Response(status=401, text="signature does not verify")

        removed = self.registry.remove(req.pubkey)
        self.metrics.revokes_total += 1
        return web.Response(
            status=200 if removed else 404,
            text="revoked" if removed else "not registered",
        )

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response({
            "ok": True,
            "uptime_ms": now_ms() - self.metrics.started_at_ms,
            "registrations": len(self.registry),
        })

    async def _handle_metrics(self, _request: web.Request) -> web.Response:
        return web.json_response({
            "started_at_ms": self.metrics.started_at_ms,
            "uptime_ms": now_ms() - self.metrics.started_at_ms,
            "registrations": len(self.registry),
            "registry_evictions_total": self.registry.evictions,
            "registers_total": self.metrics.registers_total,
            "register_rejects_total": self.metrics.register_rejects_total,
            "lookups_total": self.metrics.lookups_total,
            "lookup_misses_total": self.metrics.lookup_misses_total,
            "revokes_total": self.metrics.revokes_total,
            "rate_limit_rejects_total": self.metrics.rate_limit_rejects_total,
        })


# ─── CLI entrypoint ─────────────────────────────────────────────────

def _parse_args(argv: Optional[list[str]] = None) -> ServerConfig:
    p = argparse.ArgumentParser(description="One Link rendezvous server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=7118)
    p.add_argument("--max-registrations", type=int, default=200_000)
    p.add_argument("--rate-per-ip-per-min", type=int, default=120)
    p.add_argument("--rate-register-per-pubkey-per-min", type=int, default=30)
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    args = p.parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return ServerConfig(
        host=args.host,
        port=args.port,
        max_registrations=args.max_registrations,
        rate_per_ip_per_min=args.rate_per_ip_per_min,
        rate_register_per_pubkey_per_min=args.rate_register_per_pubkey_per_min,
    )


async def _serve_forever(config: ServerConfig) -> None:
    rdz = RendezvousApp(config)
    app = rdz.make_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host=config.host, port=config.port)
    await site.start()
    log.info("rendezvous listening on %s:%d", config.host, config.port)

    stop = asyncio.Event()

    def _stop_handler():
        log.info("shutdown signal received")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if sig is not None:
            try:
                loop.add_signal_handler(sig, _stop_handler)
            except NotImplementedError:
                # Windows: signal handlers via add_signal_handler aren't
                # supported. Fall back to default handlers; KeyboardInterrupt
                # will propagate via asyncio.run.
                pass

    try:
        await stop.wait()
    finally:
        await runner.cleanup()


def main(argv: Optional[list[str]] = None) -> int:
    config = _parse_args(argv)
    try:
        asyncio.run(_serve_forever(config))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
