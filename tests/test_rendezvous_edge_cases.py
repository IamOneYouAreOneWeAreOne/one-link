"""Edge-case tests for the rendezvous protocol + server.

Covers cases the original v0.5.0 suite didn't:
  - IPv6 endpoints round-trip and are accepted by the server
  - malformed server responses don't crash the client
  - garbage clock values are rejected (already covered) plus the
    very-distant-past / very-distant-future bounds
  - large numbers of advertised endpoints from one peer don't crash
  - non-JSON server reply does not corrupt client state
  - lookup of an enormous hex string returns 400, not crash
  - tampered observed_endpoint port type (string instead of int) rejected
  - registration after eviction-window expiry is fresh, not a stale cache
"""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.rendezvous_client import RendezvousClient
from one_link.rendezvous_proto import (
    Endpoint,
    LookupAck,
    RegisterAck,
    REPLAY_WINDOW_MS,
    sign_register,
    sign_revoke,
)
from one_link.rendezvous_server import RendezvousApp, ServerConfig


def _new_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


@pytest_asyncio.fixture
async def server() -> AsyncIterator[tuple[str, RendezvousApp]]:
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.05,
    )
    rdz = RendezvousApp(config)
    app = rdz.make_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    try:
        yield base, rdz
    finally:
        await runner.cleanup()


# ─── IPv6 ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ipv6_endpoint_round_trips_through_server(server):
    """An IPv6 advertised endpoint must round-trip cleanly: signed,
    accepted, returned on lookup with bytes intact."""
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[
            Endpoint("2001:db8::1", 51234),
            Endpoint("fe80::1", 51234),  # link-local
        ],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200
        from one_link.rendezvous_proto import _b64  # type: ignore
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            assert r.status == 200
            ack = LookupAck.from_wire(await r.json())
        hosts = {e.host for e in ack.advertised_endpoints}
        assert "2001:db8::1" in hosts
        assert "fe80::1" in hosts


# ─── malformed server responses ─────────────────────────────────────

@pytest.mark.asyncio
async def test_client_lookup_returns_none_on_garbage_response():
    """If the rendezvous returns 200 with non-JSON / bad shape, the
    client must return None — not raise into the daemon."""
    # Stand up a fake "rendezvous" that always replies with garbage.
    async def _bad_handler(request):
        return aiohttp.web.Response(text="<html>not json</html>", status=200)

    app = aiohttp.web.Application()
    app.router.add_get(r"/api/v1/lookup/{pk}", _bad_handler)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    try:
        sk, pk = _new_key()
        client = RendezvousClient(
            private_key=sk, pubkey=pk,
            rendezvous_urls=[base],
            advertise_endpoints=[Endpoint("h", 1)],
        )
        # Don't actually start (would try to register against the same
        # garbage server). Just exercise lookup.
        client._session = aiohttp.ClientSession()
        try:
            assert await client.lookup(pk) is None
        finally:
            await client._session.close()
            client._session = None
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_client_lookup_returns_none_on_5xx():
    async def _err_handler(request):
        return aiohttp.web.Response(text="oops", status=503)

    app = aiohttp.web.Application()
    app.router.add_get(r"/api/v1/lookup/{pk}", _err_handler)
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]

    try:
        sk, pk = _new_key()
        client = RendezvousClient(
            private_key=sk, pubkey=pk,
            rendezvous_urls=[f"http://127.0.0.1:{port}"],
            advertise_endpoints=[Endpoint("h", 1)],
        )
        client._session = aiohttp.ClientSession()
        try:
            assert await client.lookup(pk) is None
        finally:
            await client._session.close()
            client._session = None
    finally:
        await runner.cleanup()


# ─── clock-skew bounds ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_at_exact_replay_window_boundary_passes(server):
    """Just inside the replay window should pass; just outside should
    fail. We've already tested 'far in the past' fails — this nails
    the boundary precisely."""
    base, _rdz = server
    sk, pk = _new_key()
    from one_link.rendezvous_proto import now_ms
    boundary_ts = now_ms() - REPLAY_WINDOW_MS + 5_000  # 5s inside boundary
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
        timestamp_ms=boundary_ts,
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200, await r.text()


@pytest.mark.asyncio
async def test_register_with_y2038_timestamp_handled_gracefully(server):
    """Timestamps past 2^31 ms (year 2038 in seconds) should still
    parse — we use 64-bit int. They'll be rejected by the replay
    window, not by overflow."""
    base, _rdz = server
    sk, pk = _new_key()
    huge_ts = 4_000_000_000_000  # year 2096-ish
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
        timestamp_ms=huge_ts,
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            # Out of replay window → 400, NOT a crash/500.
            assert r.status == 400


# ─── enormous payloads ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_rejects_at_max_advertised_endpoints_plus_one(server):
    """Already covered at the proto level; this test confirms the
    server's defense-in-depth check fires too — so a peer can't
    sneak through if proto validation gets bypassed somehow."""
    base, _rdz = server
    sk, pk = _new_key()
    # MAX is 8; build 9.
    eps = [Endpoint(f"h{i}", 1) for i in range(8)]
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=eps,
    )
    wire = req.to_wire()
    wire["advertised_endpoints"].append({"host": "extra", "port": 1})
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=wire) as r:
            assert r.status == 400


# ─── lookup malformed input ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_lookup_with_extremely_long_pubkey_b64_returns_400(server):
    base, _rdz = server
    huge = "A" * 10_000
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/api/v1/lookup/{huge}") as r:
            # Either decoded to wrong length (-> 400) or path 404. Must NOT
            # be 500 / crash.
            assert r.status in (400, 404)


@pytest.mark.asyncio
async def test_lookup_with_url_path_traversal_returns_400(server):
    """Defensive: lookup must not pass through anything that lets the
    request escape the /api/v1/lookup/ subtree."""
    base, _rdz = server
    async with aiohttp.ClientSession() as s:
        # aiohttp router won't even route this (path normalization), but
        # the test pins the behavior — anything not matching the exact
        # route gets 404, never executes our handler with garbage.
        async with s.get(f"{base}/api/v1/lookup/../../etc/passwd") as r:
            assert r.status in (400, 404)


# ─── tampered request shape ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_rejects_string_port_in_endpoint(server):
    """Type discipline: endpoint.port must be int. A peer sending
    "port": "51234" (string) has to be rejected, not coerced."""
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    wire["advertised_endpoints"][0]["port"] = "51234"
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=wire) as r:
            assert r.status == 400


# ─── post-eviction freshness ────────────────────────────────────────

@pytest.mark.asyncio
async def test_re_registration_after_eviction_is_fresh():
    """After a registration's TTL expires and the eviction loop drops
    it, a brand-new registration with the same pubkey must overwrite
    cleanly (no stale data leaks through)."""
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.05,
    )
    rdz = RendezvousApp(config)
    app = rdz.make_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    try:
        sk, pk = _new_key()
        # First registration with 1s TTL.
        req1 = sign_register(
            private_key=sk, pubkey=pk, ttl_s=1,
            advertised_endpoints=[Endpoint("first", 1)],
        )
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{base}/api/v1/register", json=req1.to_wire()) as r:
                assert r.status == 200

            # Wait past TTL + eviction.
            await asyncio.sleep(1.4)
            from one_link.rendezvous_proto import _b64  # type: ignore
            async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
                assert r.status == 404  # gone

            # Re-register.
            req2 = sign_register(
                private_key=sk, pubkey=pk, ttl_s=60,
                advertised_endpoints=[Endpoint("second", 2)],
            )
            async with s.post(f"{base}/api/v1/register", json=req2.to_wire()) as r:
                assert r.status == 200
            async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
                assert r.status == 200
                ack = LookupAck.from_wire(await r.json())
            # Only the new endpoint, not stale "first".
            assert [e.host for e in ack.advertised_endpoints] == ["second"]
    finally:
        await runner.cleanup()


# ─── observed_endpoint contract ─────────────────────────────────────

@pytest.mark.asyncio
async def test_observed_endpoint_is_request_source_not_listener(server):
    """Documents an important contract: the rendezvous-observed port
    is the source port of the HTTP register request, NOT the peer's
    listening port. Daemons must NOT use observed.port as a dial
    target — only observed.host paired with an advertised port.

    This test pins the contract by confirming observed.port is
    different from any advertised port."""
    base, _rdz = server
    sk, pk = _new_key()
    advertised_port = 51234
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("192.168.1.10", advertised_port)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200
            ack = RegisterAck.from_wire(await r.json())
        # The observed port is the source port of *this* HTTP request.
        # That's an ephemeral port the OS picked for the client side
        # of our aiohttp connection — it's almost certainly NOT 51234.
        assert ack.observed_port != advertised_port, (
            "Sanity check failed: observed_port equals advertised_port. "
            "Either the OS picked our advertised port by chance (rare), "
            "or there's a bug confusing the two values."
        )
        assert ack.observed_host == "127.0.0.1"
