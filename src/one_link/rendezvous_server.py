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
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
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

# v0.20.7 (security audit Bundle 2):
#  - H25: every map keyed on attacker-controllable input (IPs, pubkeys,
#    nonces) caps at this size. On insert when full, the oldest entry
#    by first-timestamp is evicted. Without this an IPv6 spray (2^64
#    distinct sources) can OOM the box. 256k entries × ~100 bytes ≈
#    25 MB worst case across 5 maps; comfortably bounded.
_MAX_RATE_LIMITER_KEYS = 256_000
#  - H25: chunk sweeps so a single eviction tick doesn't stall the
#    event loop. After every batch of this many keys we yield with
#    asyncio.sleep(0).
_SWEEP_CHUNK = 2_000
#  - M32: per-request body-read deadline. Without this aiohttp's
#    request.read() will happily wait forever for a slowloris client.
_REQUEST_READ_TIMEOUT_S = 10.0


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
    # v0.5.5: encrypted relay support. Off by default — operators have
    # to explicitly enable, since the relay forwards bytes (still
    # opaque to us) and so consumes more bandwidth than register/lookup.
    enable_relay: bool = False
    # Per-listener concurrent session cap. The relay multiplexes
    # multiple connector→listener sessions over one listener
    # WebSocket. This cap prevents a malicious listener (or runaway
    # client) from exhausting server memory.
    relay_max_sessions_per_listener: int = 32
    # Per-IP rate limit on connect attempts. Independent from the
    # main rate_per_ip_per_min so relay-heavy operators can tune
    # separately.
    relay_connect_per_ip_per_min: int = 60
    # Idle timeout for an established session. Both sides quiet for
    # this long → relay closes. Senders re-establish for the next msg.
    relay_session_idle_s: float = 300.0  # 5 min
    # Trust reverse-proxy client IP headers. Disabled by default
    # because a directly exposed server would otherwise let clients
    # spoof X-Forwarded-For and bypass per-IP rate limits.
    trust_proxy_headers: bool = False
    # v0.20.7 (security audit H24): /lookup is unauthenticated and the
    # response is meaningfully larger than the request (15-30x). Lower
    # the lookup-specific cap so a botnet can't use the rendezvous as
    # a reflector. Independent from rate_per_ip_per_min so register
    # / revoke aren't dragged down with it.
    rate_lookup_per_ip_per_min: int = 30
    # v0.20.7 (security audit H26): per-IP NEW-pubkey registration
    # limit, separate from per-pubkey. Defeats fresh-pubkey churn
    # against the registry by forcing a per-source ceiling on how
    # often a single IP can mint a brand-new device beacon.
    rate_new_pubkey_register_per_ip_per_min: int = 10
    # v0.20.7 (security audit M31): per-pubkey listener-slot
    # replacement rate. Without this, a leaked listener key + repeated
    # ping-pong reconnect = perma-kick the legitimate owner.
    rate_listener_replace_per_pubkey_per_min: int = 2
    # v0.20.7 (security audit M33): global cap on concurrent in-flight
    # connections. Defends against fd / asyncio-task exhaustion under
    # fan-out attack from many source IPs. 0 = unlimited (legacy).
    max_concurrent_connections: int = 50_000
    # v0.20.7 (security audit M36): when set, /metrics requires a
    # Bearer token. Loopback callers (127.0.0.1, ::1) are still
    # admitted unauthenticated for ops convenience. When unset, the
    # endpoint is loopback-only and refuses non-loopback callers
    # outright.
    metrics_token: Optional[str] = None


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
    """Pubkey -> Registration. Bounded; evicts on insert when full.

    v0.20.7 (Bundle 51): also maintains a *blinded-token alias map*
    so the rendezvous can answer /api/v2/lookup_token queries
    without ever seeing a raw pubkey on the lookup wire. The alias
    is derived from (pubkey, current epoch) via HKDF and rotates
    per epoch — an attacker logging tokens gets nothing usable
    once the rotation window passes."""

    def __init__(self, max_entries: int):
        self.max_entries = max_entries
        self._entries: dict[bytes, Registration] = {}
        # Bundle 43/51: token (32 bytes) → pubkey (32 bytes). Same
        # entry can have multiple tokens active at once across epoch
        # boundaries; we keep ALL of them indexed so a query at the
        # epoch boundary doesn't miss.
        self._token_index: dict[bytes, bytes] = {}
        # Reverse map: pubkey → set of tokens we've ever indexed for
        # them, so removal cleans up the alias map too.
        self._tokens_for_pubkey: dict[bytes, set[bytes]] = {}
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, pubkey: bytes) -> Optional[Registration]:
        return self._entries.get(pubkey)

    def get_by_token(self, token: bytes) -> Optional[Registration]:
        """v0.20.7 (Bundle 51): blinded-token lookup. Returns the
        Registration whose pubkey was previously aliased to this
        token, or None if no such alias exists / the alias is
        stale."""
        pub = self._token_index.get(token)
        if pub is None:
            return None
        return self._entries.get(pub)

    def upsert(self, reg: Registration) -> None:
        # If we'd exceed capacity, evict the oldest-expiring entry.
        if reg.pubkey not in self._entries and len(self._entries) >= self.max_entries:
            victim = min(self._entries.values(), key=lambda r: r.expires_at_ms)
            self._entries.pop(victim.pubkey, None)
            self._cleanup_token_aliases(victim.pubkey)
            self.evictions += 1
        self._entries[reg.pubkey] = reg
        # v0.20.7 (Bundle 51): compute blinded tokens for the
        # current + previous + next epochs so a query at any time
        # within the rotation window finds the entry. 1-hour
        # default epoch (rdz_blind.DEFAULT_EPOCH_SECONDS); 3 epochs
        # = 3 hours of token coverage. New aliases on each upsert
        # so rotated tokens supersede old ones in the index.
        from one_link import rdz_blind as _rb
        current = _rb.current_epoch_id()
        for delta in (-1, 0, 1):
            token = _rb.derive_blinded_token(
                peer_pub=reg.pubkey, epoch_id=max(0, current + delta),
            )
            self._token_index[token] = reg.pubkey
            self._tokens_for_pubkey.setdefault(
                reg.pubkey, set()
            ).add(token)

    def remove(self, pubkey: bytes) -> bool:
        present = self._entries.pop(pubkey, None) is not None
        if present:
            self._cleanup_token_aliases(pubkey)
        return present

    def _cleanup_token_aliases(self, pubkey: bytes) -> None:
        tokens = self._tokens_for_pubkey.pop(pubkey, set())
        for t in tokens:
            self._token_index.pop(t, None)

    def evict_expired(self, now_ms_value: int) -> int:
        dead = [k for k, v in self._entries.items() if v.expires_at_ms <= now_ms_value]
        for k in dead:
            self._entries.pop(k, None)
            self._cleanup_token_aliases(k)
        return len(dead)


# ─── token-bucket rate limiter ──────────────────────────────────────

class _RateLimiter:
    """Sliding-window per-key counter. Bounded — keys with no activity
    in the last `window_s` are dropped during sweeps. v0.20.7
    (security audit H25): hard-capped at _MAX_RATE_LIMITER_KEYS so an
    IPv6 spray cannot grow this dict without bound."""

    def __init__(
        self,
        rate_per_min: int,
        window_s: float = 60.0,
        max_keys: int = _MAX_RATE_LIMITER_KEYS,
    ):
        self.rate = int(rate_per_min)
        self.window_s = float(window_s)
        self.max_keys = int(max_keys)
        self._hits: dict[str, deque[float]] = {}

    def admit(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_s
        dq = self._hits.get(key)
        if dq is None:
            # Insert path: enforce hard cap by evicting the oldest-by-
            # first-hit entry. Cheap because dict iteration order is
            # insertion order in CPython 3.7+.
            if len(self._hits) >= self.max_keys:
                try:
                    oldest_key = next(iter(self._hits))
                    self._hits.pop(oldest_key, None)
                except StopIteration:
                    pass
            dq = deque()
            self._hits[key] = dq
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= self.rate:
            return False
        dq.append(now)
        return True

    async def sweep(self) -> int:
        """Drop keys with no live tokens. Returns dropped count.

        v0.20.7 (H25): chunked + async-yielding so a sweep over a
        large dict doesn't stall the event loop. Walks at most
        _SWEEP_CHUNK keys before yielding."""
        cutoff = time.monotonic() - self.window_s
        dead: list[str] = []
        seen = 0
        # Snapshot keys so iteration is stable while we mutate.
        for k in list(self._hits.keys()):
            dq = self._hits.get(k)
            if dq is None:
                continue
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(k)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
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
    # v0.5.5
    relay_listeners_total: int = 0
    relay_listener_rejects_total: int = 0
    relay_sessions_total: int = 0
    relay_session_rejects_total: int = 0
    relay_bytes_forwarded: int = 0


# ─── relay session state ───────────────────────────────────────────

@dataclass
class _RelayListener:
    """A destination peer that has authenticated and is now waiting
    for incoming connector sessions."""
    pubkey: bytes
    ws: object  # aiohttp.web.WebSocketResponse
    sessions: dict[bytes, "_RelaySession"] = field(default_factory=dict)


@dataclass
class _RelaySession:
    """A paired connector↔listener session multiplexed over the
    listener's single WebSocket. Each gets a unique session_id; both
    sides see only that id, never the other side's pubkey."""
    session_id: bytes
    listener_pubkey: bytes
    connector_ws: object
    listener_ws: object  # the listener's WS — server forwards to it tagged
    last_activity_at: float = field(default_factory=time.monotonic)


# ─── server app ─────────────────────────────────────────────────────

class RendezvousApp:
    def __init__(self, config: ServerConfig):
        self.config = config
        self.registry = Registry(max_entries=config.max_registrations)
        self.rate_per_ip = _RateLimiter(rate_per_min=config.rate_per_ip_per_min)
        self.rate_register_per_pubkey = _RateLimiter(
            rate_per_min=config.rate_register_per_pubkey_per_min
        )
        # v0.20.7 (security audit H24): /lookup-specific per-IP cap.
        self.rate_lookup_per_ip = _RateLimiter(
            rate_per_min=config.rate_lookup_per_ip_per_min
        )
        # v0.20.7 (security audit H26): per-IP NEW-pubkey register cap.
        self.rate_new_pubkey_per_ip = _RateLimiter(
            rate_per_min=config.rate_new_pubkey_register_per_ip_per_min
        )
        # v0.20.7 (security audit M31): per-pubkey listener-slot
        # replacement cap.
        self.rate_listener_replace_per_pubkey = _RateLimiter(
            rate_per_min=config.rate_listener_replace_per_pubkey_per_min
        )
        # v0.5.5: relay-side rate limit + state.
        self.rate_relay_connect_per_ip = _RateLimiter(
            rate_per_min=config.relay_connect_per_ip_per_min
        )
        self._relay_listeners: dict[bytes, _RelayListener] = {}
        self._relay_listen_nonces: dict[bytes, deque[tuple[int, bytes]]] = {}
        self._signed_replay_cache: dict[tuple[str, bytes], deque[tuple[int, bytes]]] = {}
        self.metrics = Metrics()
        self._eviction_task: asyncio.Task | None = None
        # v0.20.7 (security audit M33): global concurrent-connection
        # gate. Uses a plain counter (asyncio is single-threaded so
        # check-then-increment without an await is atomic) instead of
        # asyncio.Semaphore so we can fail-fast at the cap rather than
        # block the request task. 0 / negative => unlimited (legacy).
        self._max_concurrent: int = max(0, int(config.max_concurrent_connections))
        self._concurrent: int = 0
        # v0.20.7 (security audit M35): HMAC key for IP-in-logs. The
        # raw IP shows up at DEBUG; INFO and above use the HMAC tag so
        # log-pipeline operators don't hold raw client IPs by accident.
        # Re-seeded every process restart — log correlation across
        # restarts is intentionally not preserved.
        self._log_ip_secret: bytes = secrets.token_bytes(32)

    @web.middleware
    async def _concurrency_middleware(self, request: web.Request, handler):
        """v0.20.7 (security audit M33): global concurrent-connection
        cap. Refuses fast at the ceiling so fan-out attacks from many
        source IPs can't exhaust fds / asyncio task state. WebSocket
        handlers count toward the cap for the lifetime of the WS,
        which is exactly the period that holds the resources we care
        about."""
        if self._max_concurrent > 0 and self._concurrent >= self._max_concurrent:
            return web.json_response(
                {"error": "server at capacity"}, status=503
            )
        self._concurrent += 1
        try:
            return await handler(request)
        finally:
            self._concurrent -= 1

    def make_app(self) -> web.Application:
        app = web.Application(
            client_max_size=max(MAX_REQUEST_BYTES, 2 * 1024 * 1024),
            middlewares=[self._concurrency_middleware],
        )
        app.router.add_post("/api/v1/register", self._handle_register)
        app.router.add_get("/api/v1/lookup/{pubkey_b64}", self._handle_lookup)
        # v0.20.7 (Bundle 51): blinded-token lookup. The rendezvous
        # never sees the raw pubkey on this path — it uses an
        # HKDF-derived per-epoch token. Daemons compute the same
        # token from (peer_pub, epoch) and look up by it.
        app.router.add_get(
            "/api/v2/lookup_token/{token_b64}", self._handle_lookup_token,
        )
        app.router.add_post("/api/v1/revoke", self._handle_revoke)
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/metrics", self._handle_metrics)
        # v0.5.5: relay endpoints. Off unless config.enable_relay.
        if self.config.enable_relay:
            app.router.add_get(
                "/api/v1/relay/listen", self._handle_relay_listen
            )
            app.router.add_get(
                "/api/v1/relay/connect/{dst_pubkey_b64}",
                self._handle_relay_connect,
            )
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
                # v0.20.7 (security audit H25): all sweeps are now
                # async + chunked so the eviction tick yields the
                # event loop frequently even with millions of keys.
                await self.rate_per_ip.sweep()
                await self.rate_register_per_pubkey.sweep()
                await self.rate_lookup_per_ip.sweep()
                await self.rate_new_pubkey_per_ip.sweep()
                await self.rate_listener_replace_per_pubkey.sweep()
                await self.rate_relay_connect_per_ip.sweep()
                await self._sweep_relay_listen_nonces()
                await self._sweep_signed_replay_cache()
                if evicted:
                    log.debug("evicted %d expired registrations", evicted)
        except asyncio.CancelledError:
            return

    # ─── request helpers ────────────────────────────────────────────

    def _client_ip(self, request: web.Request) -> str:
        """Best-effort remote IP.

        X-Forwarded-For is trusted only when the operator explicitly
        enables trust_proxy_headers. Directly exposed servers must use
        the socket peer address so clients cannot spoof rate-limit
        identities.

        v0.20.7 (security audit M34): when trust_proxy_headers is
        enabled, take the LAST entry in XFF (the next-hop attested by
        the proxy), not the first (the client-supplied value when
        nginx uses the default `proxy_add_x_forwarded_for`). Validate
        the result via ipaddress; on parse failure fall back to the
        socket peer rather than trusting an attacker-shaped string.
        """
        peer = (
            request.transport.get_extra_info("peername")
            if request.transport
            else None
        )
        peer_ip = peer[0] if peer else "unknown"
        xff = request.headers.get("X-Forwarded-For")
        if self.config.trust_proxy_headers and xff:
            # Last comma-token = proxy-attested next hop.
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                candidate = parts[-1]
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    return peer_ip
        return peer_ip

    def _ip_log_id(self, ip: str) -> str:
        """v0.20.7 (security audit M35): HMAC tag for IP-in-logs.

        Returns first 12 hex chars of HMAC-SHA256(secret, ip). The
        secret is per-process so cross-restart correlation is broken,
        but a single instance can still match same-IP behavior across
        log lines for incident response. Operators who want the raw
        IP can flip log-level to DEBUG.
        """
        try:
            mac = hmac.new(
                self._log_ip_secret, ip.encode("utf-8"), hashlib.sha256
            ).digest()
            return mac[:6].hex()
        except Exception:
            return "?"

    def _admit_relay_listen_nonce(
        self, pubkey: bytes, timestamp_ms: int, nonce: bytes
    ) -> bool:
        """Single-use relay listen nonce per pubkey within replay window."""
        from one_link.relay_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        dq = self._relay_listen_nonces.get(pubkey)
        if dq is None:
            # v0.20.7 (security audit H25): hard-cap the map. Attacker
            # minting fresh pubkeys can otherwise grow it without
            # bound. Evict the oldest pubkey (insertion order).
            if len(self._relay_listen_nonces) >= _MAX_RATE_LIMITER_KEYS:
                with contextlib.suppress(StopIteration):
                    oldest = next(iter(self._relay_listen_nonces))
                    self._relay_listen_nonces.pop(oldest, None)
            dq = deque()
            self._relay_listen_nonces[pubkey] = dq
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if any(seen_nonce == nonce for _seen_ts, seen_nonce in dq):
            return False
        dq.append((int(timestamp_ms), bytes(nonce)))
        return True

    async def _sweep_relay_listen_nonces(self) -> int:
        from one_link.relay_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        dead: list[bytes] = []
        seen = 0
        for pubkey in list(self._relay_listen_nonces.keys()):
            dq = self._relay_listen_nonces.get(pubkey)
            if dq is None:
                continue
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(pubkey)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
        for pubkey in dead:
            self._relay_listen_nonces.pop(pubkey, None)
        return len(dead)

    def _admit_signed_message_once(
        self, kind: str, pubkey: bytes, timestamp_ms: int, signature: bytes
    ) -> bool:
        """Reject exact signed request replays inside the replay window."""
        from one_link.rendezvous_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        key = (kind, pubkey)
        dq = self._signed_replay_cache.get(key)
        if dq is None:
            # v0.20.7 (security audit H25): same cap as
            # _relay_listen_nonces.
            if len(self._signed_replay_cache) >= _MAX_RATE_LIMITER_KEYS:
                with contextlib.suppress(StopIteration):
                    oldest = next(iter(self._signed_replay_cache))
                    self._signed_replay_cache.pop(oldest, None)
            dq = deque()
            self._signed_replay_cache[key] = dq
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if any(seen_sig == signature for _seen_ts, seen_sig in dq):
            return False
        dq.append((int(timestamp_ms), bytes(signature)))
        return True

    async def _sweep_signed_replay_cache(self) -> int:
        from one_link.rendezvous_proto import REPLAY_WINDOW_MS

        cutoff = now_ms() - REPLAY_WINDOW_MS
        dead: list[tuple[str, bytes]] = []
        seen = 0
        for key in list(self._signed_replay_cache.keys()):
            dq = self._signed_replay_cache.get(key)
            if dq is None:
                continue
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            if not dq:
                dead.append(key)
            seen += 1
            if seen % _SWEEP_CHUNK == 0:
                await asyncio.sleep(0)
        for key in dead:
            self._signed_replay_cache.pop(key, None)
        return len(dead)

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
            # v0.20.7 (security audit M35): HMAC tag at INFO; raw IP
            # only at DEBUG. log-pipeline operators stop accidentally
            # retaining raw client IPs.
            log.info(
                "rate-limited iphash=%s on %s",
                self._ip_log_id(ip), request.path,
            )
            log.debug("rate-limited raw-ip=%s on %s", ip, request.path)
        return ok

    async def _read_json(self, request: web.Request) -> dict:
        # v0.20.7 (security audit M32): wrap the body read in
        # asyncio.wait_for so a slowloris client (1 byte / 30s) can't
        # hold a connection open for hours. aiohttp does not enforce
        # a per-request body deadline by default; this is the missing
        # ceiling.
        try:
            body = await asyncio.wait_for(
                request.read(), timeout=_REQUEST_READ_TIMEOUT_S
            )
        except asyncio.TimeoutError:
            raise web.HTTPRequestTimeout(text="body read timed out")
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
        if not self._admit_signed_message_once(
            "register", req.pubkey, req.timestamp_ms, req.signature
        ):
            self.metrics.register_rejects_total += 1
            return web.Response(status=409, text="replayed register")

        # Per-pubkey rate limit kicks in only AFTER signature verifies,
        # so an attacker without the key can't burn through a victim's
        # quota with garbage signatures.
        pubkey_b64_for_rate = req.pubkey.hex()
        if not self.rate_register_per_pubkey.admit(pubkey_b64_for_rate):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="too many registrations for this pubkey")

        # v0.20.7 (security audit H26): per-IP NEW-pubkey limit.
        # Per-pubkey rate alone doesn't catch an attacker minting fresh
        # keys (Ed25519 keypair generation is microseconds). A single
        # IP can therefore churn the bounded registry — 200k slots in
        # ~28 hours from one box. Cap per-IP NEW-pubkey insertions at
        # 10/min so an attacker can't sustain registry-flush.
        is_new = self.registry.get(req.pubkey) is None
        if is_new:
            ip = self._client_ip(request)
            if not self.rate_new_pubkey_per_ip.admit(ip):
                self.metrics.rate_limit_rejects_total += 1
                self.metrics.register_rejects_total += 1
                return web.Response(
                    status=429,
                    text="too many new-pubkey registrations from this IP",
                )

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
        # v0.20.7 (security audit H24): /lookup-specific cap on top of
        # the global per-IP limit. Lookup is unauthenticated and the
        # response is 15-30x the request, so it's a reflection-friendly
        # endpoint without this stricter ceiling.
        ip = self._client_ip(request)
        if not self.rate_lookup_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            log.info(
                "lookup rate-limited iphash=%s", self._ip_log_id(ip),
            )
            return web.Response(status=429, text="lookup rate limited")
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

    async def _handle_lookup_token(self, request: web.Request) -> web.Response:
        """v0.20.7 (Bundle 51): blinded-token lookup. Same rate-limit
        story as v1; the wire never carries a raw pubkey."""
        if not self._rate_check_ip(request):
            return web.Response(status=429, text="rate limited")
        ip = self._client_ip(request)
        if not self.rate_lookup_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            log.info(
                "lookup_token rate-limited iphash=%s",
                self._ip_log_id(ip),
            )
            return web.Response(status=429, text="lookup rate limited")
        from one_link.rendezvous_proto import _b64d  # type: ignore

        try:
            token = _b64d(request.match_info["token_b64"])
        except Exception:
            return web.Response(status=400, text="invalid token_b64")
        if len(token) != 32:
            return web.Response(status=400, text="token must be 32 bytes")
        reg = self.registry.get_by_token(token)
        now = now_ms()
        if reg is None or reg.expires_at_ms <= now:
            self.metrics.lookups_total += 1
            self.metrics.lookup_misses_total += 1
            return web.Response(status=404, text="not registered")
        ack = LookupAck(
            pubkey=reg.pubkey,  # the recipient learns the pubkey;
                                # the rendezvous never sent it on
                                # the *lookup* wire (only the alias)
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
        if not self._admit_signed_message_once(
            "revoke", req.pubkey, req.timestamp_ms, req.signature
        ):
            return web.Response(status=409, text="replayed revoke")

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

    async def _handle_metrics(self, request: web.Request) -> web.Response:
        # v0.20.7 (security audit M36): /metrics is operational
        # telemetry. Exposing it to attackers gives them a feedback
        # signal while they tune an attack (registry_evictions_total,
        # rate_limit_rejects_total, relay_listeners_active). Gate it.
        peer_host = ""
        if request.transport is not None:
            peer = request.transport.get_extra_info("peername")
            if peer:
                peer_host = peer[0]
        is_loopback = peer_host in ("127.0.0.1", "::1", "localhost")
        if not is_loopback:
            token = self.config.metrics_token
            if not token:
                return web.Response(
                    status=403,
                    text="metrics endpoint is loopback-only; set "
                         "--metrics-token to expose externally",
                )
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or not hmac.compare_digest(
                auth[7:], token
            ):
                return web.Response(status=401, text="unauthorized")
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
            "relay_enabled": self.config.enable_relay,
            "relay_listeners_active": len(self._relay_listeners),
            "relay_listeners_total": self.metrics.relay_listeners_total,
            "relay_listener_rejects_total": self.metrics.relay_listener_rejects_total,
            "relay_sessions_total": self.metrics.relay_sessions_total,
            "relay_session_rejects_total": self.metrics.relay_session_rejects_total,
            "relay_bytes_forwarded": self.metrics.relay_bytes_forwarded,
        })

    # ─── relay (v0.5.5) ───────────────────────────────────────────

    async def _handle_relay_listen(self, request: web.Request) -> web.WebSocketResponse:
        """Destination side of the relay.

        Flow:
          1. Open WebSocket.
          2. First message MUST be a JSON ListenAuth signed by the
             pubkey the listener wants to claim. Verified inline.
             Bad auth → close with 4001.
          3. Slot keyed by `auth.pubkey` is taken (kicking any
             existing listener for that pubkey — most-recent wins).
          4. Server now demuxes incoming connector sessions onto
             this WebSocket.

        Frames received from the listener:
          - binary: `[type][session_id][payload]`. type=DATA → forward
            payload to the connector for that session_id. type=CLOSE →
            terminate the session.
          - text: ignored (reserved for future control).

        Frames sent to the listener:
          - binary DATA frames from connectors (server prepends
            session_id so listener can demux).
          - text JSON: `{"t":"incoming","session_id":...}` when a new
            connector arrives.
          - text JSON: `{"t":"session_closed","session_id":...}` when
            a connector disconnects.
        """
        from one_link.relay_proto import (
            CONTROL_FRAME_MAX_BYTES,
            DATA_FRAME_MAX_BYTES,
            FRAME_CLOSE,
            FRAME_DATA,
            ListenAuth,
            decode_frame,
            encode_close_frame,
            make_session_closed_msg,
            timestamp_within_replay_window,
        )

        ip = self._client_ip(request)
        if not self.rate_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="rate limited")

        ws = web.WebSocketResponse(
            max_msg_size=max(DATA_FRAME_MAX_BYTES + 64, CONTROL_FRAME_MAX_BYTES),
        )
        await ws.prepare(request)

        # Step 2: read the auth blob with a strict deadline.
        try:
            first = await asyncio.wait_for(ws.receive(), timeout=10.0)
        except asyncio.TimeoutError:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4002, message=b"auth timeout")
            return ws
        if first.type != aiohttp.WSMsgType.TEXT:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"expected text auth")
            return ws
        try:
            auth_doc = json.loads(first.data)
            auth = ListenAuth.from_wire(auth_doc)
        except (json.JSONDecodeError, ValueError) as e:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=f"bad auth: {e}".encode("utf-8")[:120])
            return ws
        if not timestamp_within_replay_window(auth.timestamp_ms):
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"timestamp out of window")
            return ws
        try:
            auth.verify()
        except ValueError:
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"signature did not verify")
            return ws
        if not self._admit_relay_listen_nonce(
            auth.pubkey, auth.timestamp_ms, auth.nonce
        ):
            self.metrics.relay_listener_rejects_total += 1
            await ws.close(code=4001, message=b"replayed listen auth nonce")
            return ws

        # Step 3: claim listener slot, kicking any prior one.
        prior = self._relay_listeners.get(auth.pubkey)
        if prior is not None and prior.ws is not ws:
            # v0.20.7 (security audit M31): rate-limit listener-slot
            # replacement per pubkey. Without this, a leaked listener
            # key + ping-pong reconnect = perma-kick the legitimate
            # owner. 2/min is comfortable for genuine roaming /
            # network-flap reconnects but kills the abuse path.
            if not self.rate_listener_replace_per_pubkey.admit(
                auth.pubkey.hex()
            ):
                self.metrics.relay_listener_rejects_total += 1
                await ws.close(
                    code=4003,
                    message=b"listener slot replacement rate-limited",
                )
                return ws
            with contextlib.suppress(Exception):
                await prior.ws.close(code=4003, message=b"replaced by newer listener")
            # Drain prior sessions so a new connector frame doesn't
            # land on the about-to-be-replaced listener mid-swap.
            for sid in list(prior.sessions):
                await self._close_relay_session(prior, sid)
        listener = _RelayListener(pubkey=auth.pubkey, ws=ws)
        self._relay_listeners[auth.pubkey] = listener
        self.metrics.relay_listeners_total += 1
        # v0.20.7 (security audit M35): pubkey hex prefix is public
        # (it's an Ed25519 fingerprint), so logging 8 hex chars is
        # acceptable. Belt-and-braces keep it short.
        log.info("relay: listener registered for %s", auth.pubkey.hex()[:8])

        # Step 4: forward demuxed traffic.
        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        frame = decode_frame(msg.data)
                    except ValueError as e:
                        log.warning("relay: bad listener frame: %s", e)
                        continue
                    sess = listener.sessions.get(frame.session_id)
                    if sess is None:
                        # Session unknown — listener lagging behind; drop.
                        continue
                    sess.last_activity_at = time.monotonic()
                    if frame.type == FRAME_DATA:
                        with contextlib.suppress(Exception):
                            await sess.connector_ws.send_bytes(
                                # Connector side strips its own type+sid
                                # tag — we rebuild so the wire format
                                # is uniform.
                                bytes([FRAME_DATA])
                                + frame.session_id
                                + frame.payload
                            )
                            self.metrics.relay_bytes_forwarded += len(frame.payload)
                    elif frame.type == FRAME_CLOSE:
                        await self._close_relay_session(listener, frame.session_id)
                elif msg.type == aiohttp.WSMsgType.TEXT:
                    # Reserved for future listener-initiated control.
                    pass
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            # Tear down all sessions tied to this listener.
            for sid in list(listener.sessions):
                await self._close_relay_session(listener, sid)
            # Unhook only if we're still the registered listener
            # (a newer listener may have replaced us).
            if self._relay_listeners.get(auth.pubkey) is listener:
                self._relay_listeners.pop(auth.pubkey, None)
        return ws

    async def _handle_relay_connect(
        self, request: web.Request
    ) -> web.WebSocketResponse:
        """Source side of the relay.

        Flow:
          1. URL specifies dst_pubkey_b64. No source-side auth (sealed
             sender — the relay must NOT know who's connecting).
          2. Look up the listener slot for dst_pubkey. If absent →
             close with 4040.
          3. Allocate a new session_id and notify the listener with
             a text JSON `{"t":"incoming","session_id":...}`.
          4. Forward connector binary frames (already prefixed with
             type+session_id by the connector) to the listener
             verbatim.
          5. On connector close → send CLOSE frame to listener and
             clean up.
        """
        from one_link.relay_proto import (
            DATA_FRAME_MAX_BYTES,
            FRAME_CLOSE,
            FRAME_DATA,
            decode_frame,
            encode_close_frame,
            make_incoming_msg,
            make_ready_msg,
            make_session_closed_msg,
            new_session_id,
        )
        from one_link.rendezvous_proto import _b64d  # type: ignore

        ip = self._client_ip(request)
        # Two limiters: the global per-IP, and a connect-specific one.
        if not self.rate_per_ip.admit(ip) or not self.rate_relay_connect_per_ip.admit(ip):
            self.metrics.rate_limit_rejects_total += 1
            return web.Response(status=429, text="rate limited")

        try:
            dst_pubkey = _b64d(request.match_info["dst_pubkey_b64"])
        except Exception:
            return web.Response(status=400, text="invalid dst_pubkey_b64")
        if len(dst_pubkey) != 32:
            return web.Response(status=400, text="dst_pubkey must be 32 bytes")

        listener = self._relay_listeners.get(dst_pubkey)
        if listener is None:
            self.metrics.relay_session_rejects_total += 1
            return web.Response(status=404, text="destination not listening")
        if len(listener.sessions) >= self.config.relay_max_sessions_per_listener:
            self.metrics.relay_session_rejects_total += 1
            return web.Response(status=503, text="listener at session cap")

        ws = web.WebSocketResponse(
            max_msg_size=DATA_FRAME_MAX_BYTES + 64,
        )
        await ws.prepare(request)

        sid = new_session_id()
        sess = _RelaySession(
            session_id=sid,
            listener_pubkey=dst_pubkey,
            connector_ws=ws,
            listener_ws=listener.ws,
        )
        listener.sessions[sid] = sess
        self.metrics.relay_sessions_total += 1

        # Tell both sides the session is open.
        try:
            await listener.ws.send_json(make_incoming_msg(sid))
            await ws.send_json(make_ready_msg(sid))
        except Exception:
            await self._close_relay_session(listener, sid)
            with contextlib.suppress(Exception):
                await ws.close(code=4500, message=b"could not signal both sides")
            return ws

        try:
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        frame = decode_frame(msg.data)
                    except ValueError as e:
                        log.warning("relay: bad connector frame: %s", e)
                        continue
                    # Force every connector→listener frame to use the
                    # session_id we allocated — connector can't
                    # arbitrarily address other sessions.
                    forwarded = (
                        bytes([frame.type])
                        + sid
                        + (frame.payload if frame.type == FRAME_DATA else b"")
                    )
                    sess.last_activity_at = time.monotonic()
                    with contextlib.suppress(Exception):
                        await listener.ws.send_bytes(forwarded)
                        if frame.type == FRAME_DATA:
                            self.metrics.relay_bytes_forwarded += len(frame.payload)
                    if frame.type == FRAME_CLOSE:
                        break
                elif msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.ERROR,
                    aiohttp.WSMsgType.CLOSED,
                ):
                    break
        finally:
            await self._close_relay_session(listener, sid)
        return ws

    async def _close_relay_session(
        self, listener: _RelayListener, session_id: bytes
    ) -> None:
        """Tear down a session: notify both sides, drop state."""
        sess = listener.sessions.pop(session_id, None)
        if sess is None:
            return
        from one_link.relay_proto import (
            encode_close_frame,
            make_session_closed_msg,
        )
        # Tell the listener (text JSON, never bytes — keeps demux simple).
        with contextlib.suppress(Exception):
            await listener.ws.send_json(make_session_closed_msg(session_id))
        # Tell the connector via a CLOSE binary frame, then close WS.
        with contextlib.suppress(Exception):
            await sess.connector_ws.send_bytes(encode_close_frame(session_id))
        with contextlib.suppress(Exception):
            await sess.connector_ws.close(code=1000, message=b"session closed")


# ─── CLI entrypoint ─────────────────────────────────────────────────

def _parse_args(argv: Optional[list[str]] = None) -> ServerConfig:
    p = argparse.ArgumentParser(description="One Link rendezvous server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=7118)
    p.add_argument("--max-registrations", type=int, default=200_000)
    p.add_argument("--rate-per-ip-per-min", type=int, default=120)
    p.add_argument("--rate-register-per-pubkey-per-min", type=int, default=30)
    p.add_argument(
        "--enable-relay",
        action="store_true",
        help="enable encrypted relay endpoints (uses more bandwidth)",
    )
    p.add_argument(
        "--relay-connect-per-ip-per-min", type=int, default=60,
        help="rate limit on relay connect attempts per source IP",
    )
    p.add_argument(
        "--relay-max-sessions-per-listener", type=int, default=32,
        help="max concurrent sessions one listener can multiplex",
    )
    p.add_argument(
        "--trust-proxy-headers",
        action="store_true",
        help="trust X-Forwarded-For from a controlled reverse proxy",
    )
    # v0.20.7 (security audit Bundle 2):
    p.add_argument(
        "--rate-lookup-per-ip-per-min", type=int, default=30,
        help="lookup-specific per-IP rate (separate from global)",
    )
    p.add_argument(
        "--rate-new-pubkey-register-per-ip-per-min", type=int, default=10,
        help="per-IP cap on NEW-pubkey registrations (anti registry-flush)",
    )
    p.add_argument(
        "--rate-listener-replace-per-pubkey-per-min", type=int, default=2,
        help="per-pubkey cap on relay listener slot replacements",
    )
    p.add_argument(
        "--max-concurrent-connections", type=int, default=50_000,
        help="global cap on in-flight connections (0 = unlimited)",
    )
    p.add_argument(
        "--metrics-token", type=str, default=None,
        help="if set, /metrics requires Bearer auth from non-loopback "
             "callers (loopback always allowed unauthenticated)",
    )
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
        enable_relay=args.enable_relay,
        relay_connect_per_ip_per_min=args.relay_connect_per_ip_per_min,
        relay_max_sessions_per_listener=args.relay_max_sessions_per_listener,
        trust_proxy_headers=args.trust_proxy_headers,
        rate_lookup_per_ip_per_min=args.rate_lookup_per_ip_per_min,
        rate_new_pubkey_register_per_ip_per_min=args.rate_new_pubkey_register_per_ip_per_min,
        rate_listener_replace_per_pubkey_per_min=args.rate_listener_replace_per_pubkey_per_min,
        max_concurrent_connections=args.max_concurrent_connections,
        metrics_token=args.metrics_token,
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
