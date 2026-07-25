"""v0.20.7 (Bundle 51) — end-to-end HTTP tests for /api/v2/lookup_token.

Spins up the actual aiohttp rendezvous app on a localhost port,
registers a peer via /api/v1/register (which auto-populates the
blinded-token alias map), then looks up via the new
/api/v2/lookup_token/{token_b64} and confirms the result matches
the v1 lookup. The wire never carries a raw pubkey on the v2
lookup path."""
from __future__ import annotations

import base64
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import rdz_blind
from one_link.rendezvous_proto import (
    Endpoint, LookupAck, RegisterAck, sign_register,
)
from one_link.rendezvous_server import RendezvousApp, ServerConfig


pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def server() -> AsyncIterator[str]:
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
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
        yield base
    finally:
        await runner.cleanup()


def _b64url_strip(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


async def test_v2_lookup_token_returns_registration(server: str):
    base = server
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("10.0.0.5", 51234)],
        nat_type="restricted", capabilities=["chat"],
    )
    async with aiohttp.ClientSession() as s:
        # Register via v1 (existing flow). The server auto-populates
        # the blinded-token alias internally.
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200, await r.text()
            RegisterAck.from_wire(await r.json())

        # Looker computes the blinded token from the peer's pubkey
        # + current epoch and looks up via v2.
        epoch = rdz_blind.current_epoch_id()
        token = rdz_blind.derive_blinded_token(peer_pub=pk, epoch_id=epoch)
        token_b64 = _b64url_strip(token)
        async with s.get(
            f"{base}/api/v2/lookup_token/{token_b64}",
        ) as r:
            assert r.status == 200, await r.text()
            ack = LookupAck.from_wire(await r.json())
        assert ack.pubkey == pk
        assert ack.advertised_endpoints[0].host == "10.0.0.5"
        assert ack.nat_type == "restricted"


async def test_v2_lookup_token_404_for_unknown_token(server: str):
    base = server
    fake_token = b"\x00" * 32
    token_b64 = _b64url_strip(fake_token)
    async with aiohttp.ClientSession() as s:
        async with s.get(
            f"{base}/api/v2/lookup_token/{token_b64}",
        ) as r:
            assert r.status == 404


async def test_v2_lookup_token_400_for_wrong_size(server: str):
    base = server
    short_token = b"\x00" * 16  # half the expected size
    token_b64 = _b64url_strip(short_token)
    async with aiohttp.ClientSession() as s:
        async with s.get(
            f"{base}/api/v2/lookup_token/{token_b64}",
        ) as r:
            assert r.status == 400


async def test_v2_lookup_token_400_for_bad_b64(server: str):
    base = server
    async with aiohttp.ClientSession() as s:
        async with s.get(
            f"{base}/api/v2/lookup_token/!!!not-base64!!!",
        ) as r:
            assert r.status == 400


async def test_v2_lookup_after_revoke_404(server: str):
    """Revoking via v1 also tears down the v2 alias map."""
    from one_link.rendezvous_proto import sign_revoke
    base = server
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    req = sign_register(
        private_key=sk, pubkey=pk, ttl_s=300,
        advertised_endpoints=[Endpoint("10.0.0.5", 51234)],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(f"{base}/api/v1/register", json=req.to_wire()) as r:
            assert r.status == 200
        # Lookup via v2 succeeds.
        epoch = rdz_blind.current_epoch_id()
        token = rdz_blind.derive_blinded_token(peer_pub=pk, epoch_id=epoch)
        async with s.get(
            f"{base}/api/v2/lookup_token/{_b64url_strip(token)}",
        ) as r:
            assert r.status == 200
        # Revoke.
        rev = sign_revoke(private_key=sk, pubkey=pk)
        async with s.post(f"{base}/api/v1/revoke", json=rev.to_wire()) as r:
            assert r.status == 200
        # v2 lookup now 404s.
        async with s.get(
            f"{base}/api/v2/lookup_token/{_b64url_strip(token)}",
        ) as r:
            assert r.status == 404
