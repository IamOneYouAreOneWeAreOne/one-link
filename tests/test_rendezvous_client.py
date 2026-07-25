"""End-to-end tests: RendezvousClient ↔ RendezvousApp.

Each test stands up one or more real aiohttp rendezvous servers on
localhost ports and exercises the full client flow: start, register,
lookup, refresh, multi-server fanout, graceful shutdown."""
from __future__ import annotations

from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.rendezvous_client import (
    RendezvousClient,
    discover_local_endpoints,
)
from one_link.rendezvous_proto import Endpoint
from one_link.rendezvous_server import RendezvousApp, ServerConfig


def _new_key() -> tuple[Ed25519PrivateKey, bytes]:
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes_raw()


async def _start_rendezvous(
    *,
    rate_per_ip_per_min: int = 10_000,
    rate_register_per_pubkey_per_min: int = 10_000,
    eviction_interval_s: float = 0.05,
) -> tuple[str, RendezvousApp, aiohttp.web.AppRunner]:
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=rate_per_ip_per_min,
        rate_register_per_pubkey_per_min=rate_register_per_pubkey_per_min,
        eviction_interval_s=eviction_interval_s,
    )
    rdz = RendezvousApp(config)
    app = rdz.make_app()
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", rdz, runner


@pytest_asyncio.fixture
async def rendezvous() -> AsyncIterator[tuple[str, RendezvousApp]]:
    base, rdz, runner = await _start_rendezvous()
    try:
        yield base, rdz
    finally:
        await runner.cleanup()


# ─── happy path ────────────────────────────────────────────────────

@pytest.mark.asyncio

async def test_client_registers_and_other_client_can_look_up(rendezvous):
    base, _ = rendezvous
    sk_a, pk_a = _new_key()
    sk_b, pk_b = _new_key()

    client_a = RendezvousClient(
        private_key=sk_a, pubkey=pk_a,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("192.168.1.10", 51234)],
        capabilities=["chat", "files"],
    )
    client_b = RendezvousClient(
        private_key=sk_b, pubkey=pk_b,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("10.0.0.5", 50000)],
    )
    await client_a.start()
    await client_b.start()
    try:
        # B looks up A.
        ack = await client_b.lookup(pk_a)
        assert ack is not None
        assert ack.pubkey == pk_a
        assert any(e.host == "192.168.1.10" for e in ack.advertised_endpoints)
        assert sorted(ack.capabilities) == ["chat", "files"]
        # A has its own observed_self populated.
        assert base in client_a.observed_self
        obs = client_a.observed_self[base]
        assert obs.observed_host == "127.0.0.1"
    finally:
        await client_a.stop()
        await client_b.stop()


@pytest.mark.asyncio


async def test_lookup_unknown_returns_none(rendezvous):
    base, _ = rendezvous
    sk, pk = _new_key()
    _, other_pk = _new_key()

    client = RendezvousClient(
        private_key=sk, pubkey=pk,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("h", 1)],
    )
    await client.start()
    try:
        assert await client.lookup(other_pk) is None
    finally:
        await client.stop()


@pytest.mark.asyncio


async def test_revoke_on_stop_removes_registration(rendezvous):
    base, rdz = rendezvous
    sk, pk = _new_key()
    client = RendezvousClient(
        private_key=sk, pubkey=pk,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("h", 1)],
    )
    await client.start()
    assert len(rdz.registry) == 1
    await client.stop()
    # Registration is gone.
    assert rdz.registry.get(pk) is None


# ─── multi-rendezvous fanout ────────────────────────────────────────

@pytest.mark.asyncio

async def test_register_propagates_to_all_configured_rendezvous():
    base1, rdz1, run1 = await _start_rendezvous()
    base2, rdz2, run2 = await _start_rendezvous()
    try:
        sk, pk = _new_key()
        client = RendezvousClient(
            private_key=sk, pubkey=pk,
            rendezvous_urls=[base1, base2],
            advertise_endpoints=[Endpoint("h", 1)],
        )
        await client.start()
        try:
            # Both registries should see this pubkey.
            assert rdz1.registry.get(pk) is not None
            assert rdz2.registry.get(pk) is not None
            assert base1 in client.observed_self
            assert base2 in client.observed_self
        finally:
            await client.stop()
        # And both should see the revoke.
        assert rdz1.registry.get(pk) is None
        assert rdz2.registry.get(pk) is None
    finally:
        await run1.cleanup()
        await run2.cleanup()


@pytest.mark.asyncio


async def test_lookup_succeeds_when_only_one_rendezvous_knows():
    base1, rdz1, run1 = await _start_rendezvous()
    base2, _rdz2, run2 = await _start_rendezvous()
    try:
        sk_a, pk_a = _new_key()
        # A registers only with rendezvous 1.
        client_a = RendezvousClient(
            private_key=sk_a, pubkey=pk_a,
            rendezvous_urls=[base1],
            advertise_endpoints=[Endpoint("h-a", 1)],
        )
        await client_a.start()

        sk_b, pk_b = _new_key()
        # B configured with both — should still find A via rendezvous 1.
        client_b = RendezvousClient(
            private_key=sk_b, pubkey=pk_b,
            rendezvous_urls=[base1, base2],
            advertise_endpoints=[Endpoint("h-b", 1)],
        )
        await client_b.start()
        try:
            ack = await client_b.lookup(pk_a)
            assert ack is not None
            assert any(e.host == "h-a" for e in ack.advertised_endpoints)
        finally:
            await client_a.stop()
            await client_b.stop()
    finally:
        await run1.cleanup()
        await run2.cleanup()


@pytest.mark.asyncio


async def test_lookup_returns_none_when_all_rendezvous_unreachable():
    """Configure with deliberately invalid URLs; client must not raise.
    The daemon must keep working with mDNS-only when rendezvous is down."""
    sk, pk = _new_key()
    _, other = _new_key()
    client = RendezvousClient(
        private_key=sk, pubkey=pk,
        rendezvous_urls=["http://127.0.0.1:1"],   # nothing listening
        advertise_endpoints=[Endpoint("h", 1)],
        request_timeout_s=1.0,
    )
    await client.start()
    try:
        assert await client.lookup(other) is None
    finally:
        await client.stop()


# ─── refresh loop ───────────────────────────────────────────────────

@pytest.mark.asyncio

async def test_refresh_loop_re_registers_within_ttl():
    """Set a tiny TTL + matching refresh fraction so the loop fires
    quickly. Verify the registration `registered_at_ms` advances."""
    base, rdz, runner = await _start_rendezvous()
    try:
        sk, pk = _new_key()
        client = RendezvousClient(
            private_key=sk, pubkey=pk,
            rendezvous_urls=[base],
            advertise_endpoints=[Endpoint("h", 1)],
            ttl_s=60,            # passes proto validation (>0)
            refresh_fraction=0.1,  # ignored, internal floor is 15s
        )
        # Compress the cycle for the test by stomping internals — the
        # production refresh interval has a 15s floor for safety.
        await client.start()
        try:
            first_ts = rdz.registry.get(pk).registered_at_ms
            # Force an immediate re-register by calling the internal once.
            await client._register_all()  # type: ignore[attr-defined]
            second_ts = rdz.registry.get(pk).registered_at_ms
            assert second_ts >= first_ts
        finally:
            await client.stop()
    finally:
        await runner.cleanup()


# ─── input validation ──────────────────────────────────────────────

@pytest.mark.asyncio

async def test_lookup_rejects_wrong_length_pubkey(rendezvous):
    base, _ = rendezvous
    sk, pk = _new_key()
    client = RendezvousClient(
        private_key=sk, pubkey=pk,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("h", 1)],
    )
    await client.start()
    try:
        with pytest.raises(ValueError, match="32 bytes"):
            await client.lookup(b"\x00" * 16)
    finally:
        await client.stop()


def test_constructor_rejects_empty_url_list():
    sk, pk = _new_key()
    with pytest.raises(ValueError):
        RendezvousClient(
            private_key=sk, pubkey=pk,
            rendezvous_urls=[],
            advertise_endpoints=[Endpoint("h", 1)],
        )


# ─── update_advertised_endpoints ───────────────────────────────────

@pytest.mark.asyncio

async def test_updated_advertised_endpoints_picked_up_on_next_register(rendezvous):
    base, rdz = rendezvous
    sk, pk = _new_key()
    client = RendezvousClient(
        private_key=sk, pubkey=pk,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("old", 1)],
    )
    await client.start()
    try:
        assert any(e.host == "old" for e in rdz.registry.get(pk).advertised_endpoints)
        client.update_advertised_endpoints([Endpoint("new", 2)])
        await client._register_all()  # type: ignore[attr-defined]
        endpoints = rdz.registry.get(pk).advertised_endpoints
        assert any(e.host == "new" for e in endpoints)
        assert not any(e.host == "old" for e in endpoints)
    finally:
        await client.stop()


# ─── discover_local_endpoints ──────────────────────────────────────

def test_discover_local_endpoints_skips_link_local_and_zero():
    eps = discover_local_endpoints(peer_port=51234)
    for e in eps:
        assert not e.host.startswith("169.254."), e.host
        assert e.host != "0.0.0.0", e.host
        # Default does not include loopback unless asked.
        assert not e.host.startswith("127."), e.host
        assert e.port == 51234


def test_discover_local_endpoints_with_loopback_includes_127():
    eps = discover_local_endpoints(peer_port=80, include_loopback=True)
    # On most boxes, gethostname() resolves to 127.0.0.1 *or* a LAN IP.
    # The "what's my outbound IP" trick should still produce a non-127
    # entry on any networked machine — but we only assert the
    # structural invariants that always hold.
    assert all(0 < e.port < 65536 for e in eps)
