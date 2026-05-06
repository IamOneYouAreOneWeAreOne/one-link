"""End-to-end tests for the rendezvous server (`one_link.rendezvous_server`).

These spin up a real aiohttp app on a localhost port, hit the actual
HTTP endpoints, and verify behaviour against the wire protocol.
Concurrency, rate limits, replay rejection, signature failure paths
are all covered."""
from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.rendezvous_proto import (
    Endpoint,
    LookupAck,
    REPLAY_WINDOW_MS,
    RegisterAck,
    RegisterReq,
    RevokeReq,
    sign_register,
    sign_revoke,
)
from one_link.rendezvous_server import RendezvousApp, ServerConfig


pytestmark = pytest.mark.asyncio


# ─── fixtures ────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def server() -> AsyncIterator[tuple[str, RendezvousApp]]:
    """Start a rendezvous on a random localhost port. Yield (base_url, app)."""
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        rate_per_ip_per_min=10_000,        # generous — let tests run
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.2,
    )
    rdz = RendezvousApp(config)
    app = rdz.make_app()

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    sockets = list(site._server.sockets)
    actual_port = sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{actual_port}"

    try:
        yield base, rdz
    finally:
        await runner.cleanup()


def _new_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


# ─── happy paths ─────────────────────────────────────────────────────

async def test_register_then_lookup_returns_advertised_endpoints(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("192.168.1.10", 51234)],
        nat_type="restricted",
        capabilities=["chat", "files"],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200, await r.text()
            ack = RegisterAck.from_wire(await r.json())
        assert ack.observed_host == "127.0.0.1"
        assert ack.observed_port > 0
        assert ack.expires_at_ms > ack.server_time_ms

        from one_link.rendezvous_proto import _b64  # type: ignore
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            assert r.status == 200, await r.text()
            lookup = LookupAck.from_wire(await r.json())
        assert lookup.pubkey == pk
        assert lookup.observed_endpoint is not None
        assert lookup.observed_endpoint.host == "127.0.0.1"
        assert [e.host for e in lookup.advertised_endpoints] == ["192.168.1.10"]
        assert lookup.nat_type == "restricted"
        assert sorted(lookup.capabilities) == ["chat", "files"]


async def test_register_does_not_trust_x_forwarded_for_by_default(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk,
        pubkey=pk,
        ttl_s=300,
        advertised_endpoints=[Endpoint("192.168.1.10", 51234)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{base}/api/v1/register",
            json=req.to_wire(),
            headers={"X-Forwarded-For": "203.0.113.66"},
        ) as r:
            assert r.status == 200, await r.text()
            ack = RegisterAck.from_wire(await r.json())
        assert ack.observed_host == "127.0.0.1"


async def test_revoke_removes_registration(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200

        rev = sign_revoke(private_key=sk, pubkey=pk)
        async with s.post(f"{base}/api/v1/revoke", json=rev.to_wire()) as r:
            assert r.status == 200, await r.text()

        from one_link.rendezvous_proto import _b64  # type: ignore
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            assert r.status == 404


async def test_lookup_unknown_returns_404(server):
    base, _rdz = server
    _, pk = _new_key()
    from one_link.rendezvous_proto import _b64  # type: ignore
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            assert r.status == 404


async def test_register_overwrites_previous_for_same_pubkey(server):
    base, rdz = server
    sk, pk = _new_key()
    async with aiohttp.ClientSession() as s:
        for endpoint in (Endpoint("a", 1), Endpoint("b", 2), Endpoint("c", 3)):
            req = sign_register(
                private_key=sk, pubkey=pk, ttl_s=300,
                advertised_endpoints=[endpoint],
            )
            async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
                assert r.status == 200
        assert len(rdz.registry) == 1
        from one_link.rendezvous_proto import _b64  # type: ignore
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            lookup = LookupAck.from_wire(await r.json())
        assert [e.host for e in lookup.advertised_endpoints] == ["c"]


# ─── security: replay window ────────────────────────────────────────

async def test_register_rejects_stale_timestamp(server):
    base, _rdz = server
    sk, pk = _new_key()
    # Sign with a timestamp well outside the replay window.
    stale_ts = 1
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
        timestamp_ms=stale_ts,
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 400
            text = await r.text()
            assert "replay" in text.lower()


async def test_register_rejects_future_timestamp(server):
    base, _rdz = server
    sk, pk = _new_key()
    from one_link.rendezvous_proto import now_ms
    future_ts = now_ms() + REPLAY_WINDOW_MS + 5_000
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
        timestamp_ms=future_ts,
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 400


# ─── security: signature ────────────────────────────────────────────

async def test_register_rejects_exact_signed_replay(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk,
        pubkey=pk,
        ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=wire) as r:
            assert r.status == 200, await r.text()
        async with s.post(f"{base}/api/v1/register", json=wire) as r:
            assert r.status == 409
            assert "replayed" in (await r.text()).lower()


async def test_revoke_rejects_exact_signed_replay(server):
    base, _rdz = server
    sk, pk = _new_key()
    reg = sign_register(
        private_key=sk,
        pubkey=pk,
        ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    rev = sign_revoke(private_key=sk, pubkey=pk)
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=reg.to_wire()) as r:
            assert r.status == 200
        async with s.post(f"{base}/api/v1/revoke", json=rev.to_wire()) as r:
            assert r.status == 200, await r.text()
        async with s.post(f"{base}/api/v1/revoke", json=rev.to_wire()) as r:
            assert r.status == 409
            assert "replayed" in (await r.text()).lower()


async def test_register_rejects_bad_signature(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    wire = req.to_wire()
    # Tamper after signing — flip a bit in the endpoint list.
    wire["advertised_endpoints"][0]["host"] = "evil"
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=wire) as r:
            assert r.status == 401, await r.text()


async def test_register_rejects_wrong_pubkey_signing(server):
    base, _rdz = server
    sk1, _pk1 = _new_key()
    _,  pk2  = _new_key()
    # sk1 signs on behalf of pk2 — must fail.
    req = sign_register(
        private_key=sk1, pubkey=pk2, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 401, await r.text()


async def test_revoke_rejects_bad_signature(server):
    base, _rdz = server
    sk, pk = _new_key()
    # Register first.
    reg = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=reg.to_wire()) as r:
            assert r.status == 200

        # Forge revoke with someone else's key.
        sk_evil, _ = _new_key()
        rev = sign_revoke(private_key=sk_evil, pubkey=pk)  # wrong signer for pk
        async with s.post(f"{base}/api/v1/revoke", json=rev.to_wire()) as r:
            assert r.status == 401


# ─── security: malformed input ──────────────────────────────────────

async def test_register_rejects_non_json_body(server):
    base, _rdz = server
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", data=b"not json") as r:
            assert r.status == 400


async def test_register_rejects_oversize_body(server):
    base, _rdz = server
    junk = json.dumps({"junk": "x" * (16 * 1024)})
    async with aiohttp.ClientSession() as s:
        async with s.post(
            f"{base}/api/v1/register",
            data=junk.encode("utf-8"),
            headers={"Content-Type": "application/json"},
        ) as r:
            assert r.status in (400, 413)


async def test_lookup_rejects_invalid_pubkey_b64(server):
    base, _rdz = server
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/api/v1/lookup/!!!not_base64!!!") as r:
            assert r.status == 400


async def test_lookup_rejects_pubkey_wrong_length(server):
    base, _rdz = server
    short = "AAAA"  # decodes to 3 bytes
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/api/v1/lookup/{short}") as r:
            assert r.status == 400


# ─── security: rate limiting ────────────────────────────────────────

async def test_per_ip_rate_limit_kicks_in():
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=5,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=10.0,
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
        async with aiohttp.ClientSession() as s:
            statuses = []
            for _ in range(8):
                # Lookup-of-unknown is the cheapest endpoint that still
                # counts against the IP rate limit.
                async with s.get(f"{base}/api/v1/lookup/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") as r:
                    statuses.append(r.status)
            # First 5 within the window should pass (404 since no such key);
            # the rest should hit 429.
            assert statuses.count(429) >= 1, f"no rate-limit hit: {statuses!r}"
    finally:
        await runner.cleanup()


# ─── eviction loop ──────────────────────────────────────────────────

async def test_expired_registrations_are_evicted_by_loop():
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.05,  # fast for the test
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
        req = sign_register(
            private_key=sk, pubkey=pk, ttl_s=1,
            advertised_endpoints=[Endpoint("h", 1)],
        )
        async with aiohttp.ClientSession() as s:
            async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
                assert r.status == 200

            # Wait past TTL + eviction interval.
            await asyncio.sleep(1.4)

            from one_link.rendezvous_proto import _b64  # type: ignore
            async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
                assert r.status == 404
        assert len(rdz.registry) == 0
    finally:
        await runner.cleanup()


# ─── health + metrics ───────────────────────────────────────────────

async def test_health_endpoint(server):
    base, _rdz = server
    async with aiohttp.ClientSession() as s:
        async with s.get(f"{base}/health") as r:
            assert r.status == 200
            j = await r.json()
        assert j["ok"] is True
        assert "uptime_ms" in j
        assert j["registrations"] == 0


async def test_metrics_increments(server):
    base, _rdz = server
    sk, pk = _new_key()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=60,
        advertised_endpoints=[Endpoint("h", 1)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200
        from one_link.rendezvous_proto import _b64  # type: ignore
        async with s.get(f"{base}/api/v1/lookup/{_b64(pk)}") as r:
            assert r.status == 200
        async with s.get(f"{base}/metrics") as r:
            m = await r.json()
        assert m["registers_total"] == 1
        assert m["lookups_total"] == 1
        assert m["lookup_misses_total"] == 0
