"""Tests for v0.5.2 — happy-eyeballs multi-endpoint dial.

`Daemon._collect_dial_candidates(peer)` and `Daemon._dial_first_responsive(...)`
together let the daemon try multiple advertised + rendezvous-observed
endpoints in parallel and use whichever connects first. This handles
the case where a peer publishes several reachable IPs (LAN +
secondary interface + outbound IP + rendezvous-observed public IP)
and only some of them are actually reachable from the connecting
side."""
from __future__ import annotations

import asyncio
import socket
from pathlib import Path
from types import SimpleNamespace
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.rendezvous_client import RendezvousClient
from one_link.rendezvous_proto import Endpoint
from one_link.rendezvous_server import RendezvousApp, ServerConfig
from one_link.state import State


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub,
        fingerprint=fp, short_id=fp[:8], hostname="testhost",
    )


async def _start_listener() -> tuple[asyncio.AbstractServer, int, list[asyncio.StreamWriter]]:
    """Stand up a tiny TCP listener. Each accepted connection is held
    open until the client closes its writer; the handler then closes
    its own writer too so the connection task terminates and doesn't
    dangle through pytest's event-loop teardown."""
    accepted: list[asyncio.StreamWriter] = []

    async def _handle(reader, writer):
        accepted.append(writer)
        try:
            try:
                await reader.read(1)
            except (ConnectionError, OSError, asyncio.IncompleteReadError):
                pass
        finally:
            writer.close()
            with __import__("contextlib").suppress(BaseException):
                await writer.wait_closed()

    server = await asyncio.start_server(_handle, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    return server, port, accepted


async def _stop_listener(
    server: asyncio.AbstractServer,
    accepted: list[asyncio.StreamWriter],
) -> None:
    """Close all accepted connections, then close the server. Order
    matters: closing the server alone leaves accepted-connection tasks
    blocked on read() — those tasks dangle through pytest teardown
    and on Windows can hang the event loop."""
    for w in list(accepted):
        with __import__("contextlib").suppress(BaseException):
            w.close()
    server.close()
    with __import__("contextlib").suppress(BaseException):
        await asyncio.wait_for(server.wait_closed(), timeout=2.0)


def _free_port() -> int:
    """Reserve and release a port to get a high probability that
    nothing is listening on it (for the negative test)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ─── _dial_first_responsive ────────────────────────────────────────

@pytest.mark.asyncio
async def test_dial_first_responsive_returns_only_responsive_candidate():
    me = _new_identity()
    daemon = Daemon(me)

    # One real listener + two ports nothing is listening on.
    server, port, accepted = await _start_listener()
    try:
        bad1, bad2 = _free_port(), _free_port()
        candidates = [
            ("127.0.0.1", bad1),
            ("127.0.0.1", port),
            ("127.0.0.1", bad2),
        ]
        reader, writer, winning = await daemon._dial_first_responsive(
            candidates, timeout=2.0
        )
        try:
            assert winning == ("127.0.0.1", port)
        finally:
            writer.close()
            with __import__("contextlib").suppress(Exception):
                await writer.wait_closed()
    finally:
        await _stop_listener(server, accepted)


@pytest.mark.asyncio
async def test_dial_first_responsive_raises_when_all_fail():
    me = _new_identity()
    daemon = Daemon(me)
    candidates = [
        ("127.0.0.1", _free_port()),
        ("127.0.0.1", _free_port()),
    ]
    with pytest.raises(OSError):
        await daemon._dial_first_responsive(candidates, timeout=1.0)


@pytest.mark.asyncio
async def test_dial_first_responsive_raises_on_empty_candidates():
    me = _new_identity()
    daemon = Daemon(me)
    with pytest.raises(OSError):
        await daemon._dial_first_responsive([])


@pytest.mark.asyncio
async def test_dial_first_responsive_picks_fastest_listener_under_stagger():
    """Two listeners — confirm we get a working connection (we don't
    actually depend on which one wins; both are equally valid)."""
    me = _new_identity()
    daemon = Daemon(me)

    server_a, port_a, acc_a = await _start_listener()
    server_b, port_b, acc_b = await _start_listener()
    try:
        candidates = [("127.0.0.1", port_a), ("127.0.0.1", port_b)]
        reader, writer, winning = await daemon._dial_first_responsive(
            candidates, timeout=2.0
        )
        try:
            assert winning in candidates
        finally:
            writer.close()
            with __import__("contextlib").suppress(Exception):
                await writer.wait_closed()
    finally:
        await _stop_listener(server_a, acc_a)
        await _stop_listener(server_b, acc_b)


# ─── _collect_dial_candidates ──────────────────────────────────────

@pytest.mark.asyncio
async def test_collect_candidates_lan_only_when_no_rendezvous():
    me = _new_identity()
    daemon = Daemon(me)
    daemon.rendezvous = None
    peer = Peer(short_id="abc12345", hostname="b", address="192.168.1.10",
                port=51234, ed_pub_hex="11" * 32)
    cands = await daemon._collect_dial_candidates(peer)
    assert cands == [("192.168.1.10", 51234)]


@pytest.mark.asyncio
async def test_collect_candidates_dedupes_repeated_endpoints():
    """If the rendezvous reports the same endpoint as `peer.address` /
    `port`, it shouldn't appear twice in the candidate list."""
    base, rdz, runner = await _async_start_rendezvous()
    try:
        me = _new_identity()
        b_id = _new_identity()
        # B registers an endpoint identical to what the consumer will
        # pass via Peer.
        b_client = RendezvousClient(
            private_key=b_id.private, pubkey=b_id.public_bytes,
            rendezvous_urls=[base],
            advertise_endpoints=[Endpoint("192.168.1.10", 51234)],
        )
        await b_client.start()
        try:
            daemon = Daemon(me)
            from one_link.rendezvous_client import RendezvousClient as RC
            daemon.rendezvous = RC(
                private_key=me.private, pubkey=me.public_bytes,
                rendezvous_urls=[base],
                advertise_endpoints=[],
            )
            await daemon.rendezvous.start()
            try:
                peer = Peer(
                    short_id=b_id.short_id, hostname="b",
                    address="192.168.1.10", port=51234,
                    ed_pub_hex=b_id.public_bytes.hex(),
                )
                cands = await daemon._collect_dial_candidates(peer)
                # mDNS endpoint comes first; rendezvous-advertised dup is
                # collapsed; rendezvous-observed (127.0.0.1) is added.
                assert cands[0] == ("192.168.1.10", 51234)
                assert ("192.168.1.10", 51234) not in cands[1:]
                # The rendezvous-observed loopback IP should show up since
                # the test runs on localhost.
                assert any(c[0] == "127.0.0.1" for c in cands)
            finally:
                await daemon.rendezvous.stop()
        finally:
            await b_client.stop()
    finally:
        await runner.cleanup()


async def _async_start_rendezvous():
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
    return f"http://127.0.0.1:{port}", rdz, runner


@pytest.mark.asyncio
async def test_collect_candidates_tolerates_rendezvous_failure():
    """If the rendezvous lookup raises / returns None, candidate
    collection still returns the LAN endpoint we already have."""
    me = _new_identity()
    daemon = Daemon(me)

    class _BrokenRDZ:
        async def lookup(self, _pk):
            raise RuntimeError("simulated rendezvous outage")

    daemon.rendezvous = _BrokenRDZ()  # type: ignore
    peer = Peer(short_id="abc12345", hostname="b", address="192.168.1.10",
                port=51234, ed_pub_hex="11" * 32)
    cands = await daemon._collect_dial_candidates(peer)
    assert cands == [("192.168.1.10", 51234)]


# ─── _dial_peer high-level path ────────────────────────────────────

@pytest.mark.asyncio
async def test_dial_peer_single_candidate_path():
    """When the rendezvous returns nothing extra, _dial_peer reduces
    to a vanilla open_connection (cheap path, no eyeballs overhead)."""
    me = _new_identity()
    daemon = Daemon(me)
    daemon.rendezvous = None

    server, port, accepted = await _start_listener()
    try:
        peer = Peer(
            short_id="abc12345", hostname="b",
            address="127.0.0.1", port=port,
            ed_pub_hex="11" * 32,
        )
        reader, writer = await daemon._dial_peer(peer)
        try:
            assert writer is not None
        finally:
            writer.close()
            with __import__("contextlib").suppress(Exception):
                await writer.wait_closed()
    finally:
        await _stop_listener(server, accepted)


@pytest.mark.asyncio
async def test_dial_peer_uses_rendezvous_alts_when_primary_fails():
    """Primary peer.address is bad; rendezvous-advertised endpoint
    points at a working listener. _dial_peer must succeed via the
    fallback."""
    base, rdz, runner = await _async_start_rendezvous()
    try:
        me = _new_identity()
        b_id = _new_identity()

        # Stand up a real listener on a known port; we'll have B
        # advertise that port via the rendezvous.
        server, good_port, accepted = await _start_listener()
        try:
            b_client = RendezvousClient(
                private_key=b_id.private, pubkey=b_id.public_bytes,
                rendezvous_urls=[base],
                advertise_endpoints=[Endpoint("127.0.0.1", good_port)],
            )
            await b_client.start()
            try:
                daemon = Daemon(me)
                from one_link.rendezvous_client import RendezvousClient as RC
                daemon.rendezvous = RC(
                    private_key=me.private, pubkey=me.public_bytes,
                    rendezvous_urls=[base],
                    advertise_endpoints=[],
                )
                await daemon.rendezvous.start()
                try:
                    bad_port = _free_port()
                    peer = Peer(
                        short_id=b_id.short_id, hostname="b",
                        address="127.0.0.1", port=bad_port,
                        ed_pub_hex=b_id.public_bytes.hex(),
                    )
                    reader, writer = await daemon._dial_peer(peer, timeout=2.0)
                    try:
                        assert writer is not None
                    finally:
                        writer.close()
                        with __import__("contextlib").suppress(Exception):
                            await writer.wait_closed()
                finally:
                    await daemon.rendezvous.stop()
            finally:
                await b_client.stop()
        finally:
            await _stop_listener(server, accepted)
    finally:
        await runner.cleanup()
