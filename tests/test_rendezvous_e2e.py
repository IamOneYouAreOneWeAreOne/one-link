"""End-to-end test: real chat over rendezvous between two daemons.

Spins up:
  1. A real RendezvousApp on a localhost port.
  2. Two real Daemon instances configured to use that rendezvous,
     each with its own State + identity, both pinned to each other.
  3. Brings up daemon B's peer server, then has daemon A look up B
     via the rendezvous and send a chat message.

Asserts that:
  - the message arrives in B's persistent store
  - resolution went through the rendezvous (mDNS is bypassed)
  - delivery survives B's IP not being on mDNS at all

This is the test that the previous polish-wave audit said was missing.
"""
from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from typing import AsyncIterator

import aiohttp
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.rendezvous_proto import Endpoint
from one_link.rendezvous_server import RendezvousApp, ServerConfig
from one_link.state import State


def _new_identity(hostname: str = "test") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=hostname,
    )


async def _start_rendezvous() -> tuple[str, RendezvousApp, aiohttp.web.AppRunner]:
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.1,
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


async def _start_minimal_peer_server(daemon: Daemon) -> tuple[asyncio.AbstractServer, int]:
    """Start a TCP server that drives the daemon's _handle_peer
    handshake. Mirrors what Daemon.start() does for the peer
    listener but bypasses the heavier daemon init (we don't want
    a full daemon.start() — just enough to receive a real chat
    over the channel)."""
    server = await asyncio.start_server(
        daemon._handle_peer, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]
    return server, port


@pytest.mark.asyncio
async def test_chat_through_rendezvous_when_mdns_is_bypassed(
    rendezvous, tmp_path: Path
):
    """A and B are paired in each other's state DBs but neither has
    mDNS running. A looks up B via the rendezvous and sends a chat
    message. The message must reach B's persistent store, proving the
    cross-internet send path works end-to-end."""
    base, _rdz = rendezvous

    me_a = _new_identity("alice-laptop")
    me_b = _new_identity("bob-laptop")

    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    state_b = State(db_path=tmp_path / "b" / "state.db")

    # Each side has the other pinned in its DB so trust gates pass.
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes, hostname=me_b.hostname,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    state_b.upsert_peer(
        fingerprint=me_a.fingerprint, short_id=me_a.short_id,
        pubkey=me_a.public_bytes, hostname=me_a.hostname,
    )
    state_b.set_peer_trust(me_a.fingerprint, "pinned")

    # Both pin the rendezvous URL.
    state_a.set_rendezvous_urls([base])
    state_b.set_rendezvous_urls([base])

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None  # bypass mDNS entirely

    daemon_b = Daemon(me_b)
    daemon_b.state = state_b
    daemon_b.discovery = None
    # B needs a place to listen — minimal peer server.
    server_b, b_peer_port = await _start_minimal_peer_server(daemon_b)

    # Bring up rendezvous clients on both daemons. B advertises its
    # actual peer-port so A can dial it. A just registers (no listener
    # needed for an outbound-only test).
    daemon_a._rendezvous_peer_port = 0  # type: ignore[attr-defined]
    daemon_b._rendezvous_peer_port = b_peer_port  # type: ignore[attr-defined]

    await daemon_a.update_rendezvous_urls([base])
    await daemon_b.update_rendezvous_urls([base])

    try:
        # Sanity: rendezvous resolution returns SOME endpoint with B's
        # peer-port. The exact host depends on what B's daemon picked
        # up via discover_local_endpoints — could be a LAN IP or the
        # outbound-IP trick. Either way the port must match B's listener.
        peer_b = await daemon_a.resolve_peer_endpoint(me_b.fingerprint)
        assert peer_b is not None, "A could not resolve B via rendezvous"
        assert peer_b.port == b_peer_port, (
            f"resolved port {peer_b.port} != B's listener {b_peer_port}"
        )
        assert peer_b.ed_pub_hex == me_b.public_bytes.hex()

        # Send a real chat message from A to B over the rendezvous-
        # discovered endpoint. send_text uses _dial_peer (happy-eyeballs)
        # under the hood; we expect the connection to succeed and the
        # ACK to come back. send_text returns {"sent": <msg>, "ack": <ack>}.
        result = await daemon_a.send_text(peer_b, "hello from across the internet")
        assert result["ack"]["t"] == "ACK", f"unexpected reply: {result!r}"
        assert result["sent"]["body"] == "hello from across the internet"

        # Give B's persistence a moment to commit.
        await asyncio.sleep(0.1)

        # The message must be in B's recent_messages.
        msgs = state_b.recent_messages(limit=10)
        bodies = [m.body for m in msgs]
        assert "hello from across the internet" in bodies, (
            f"message did not land in B's store: {bodies!r}"
        )
    finally:
        # Tear down outbound sessions to free their writers.
        for fp in list(daemon_a._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_a._drop_outbound_session(fp)
        for fp in list(daemon_b._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_b._drop_outbound_session(fp)
        if daemon_a.rendezvous is not None:
            await daemon_a.rendezvous.stop()
        if daemon_b.rendezvous is not None:
            await daemon_b.rendezvous.stop()
        # Audit fix: relay-listener clients each own a ClientSession.
        for listener in list(daemon_a._relay_listener_clients):  # type: ignore[attr-defined]
            await listener.stop()
        for listener in list(daemon_b._relay_listener_clients):  # type: ignore[attr-defined]
            await listener.stop()
        server_b.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server_b.wait_closed(), timeout=2.0)
        state_a.close()
        state_b.close()


@pytest.mark.asyncio
async def test_chat_via_rendezvous_uses_resolve_for_send_path(
    rendezvous, tmp_path: Path
):
    """Sanity: resolve_for_send respects the trust gate AND the
    rendezvous fallback. Pinned peer not on mDNS → resolves via
    rendezvous. Unpinned peer not on mDNS → returns None."""
    base, _rdz = rendezvous

    me_a = _new_identity("alice")
    me_b = _new_identity("bob")
    me_c = _new_identity("charlie")

    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")

    # B is pinned, C is not.
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    state_a.upsert_peer(
        fingerprint=me_c.fingerprint, short_id=me_c.short_id,
        pubkey=me_c.public_bytes,
    )
    state_a.set_rendezvous_urls([base])

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    # Both B and C register with the rendezvous independently.
    from one_link.rendezvous_client import RendezvousClient
    client_b = RendezvousClient(
        private_key=me_b.private, pubkey=me_b.public_bytes,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("10.0.0.1", 51001)],
    )
    client_c = RendezvousClient(
        private_key=me_c.private, pubkey=me_c.public_bytes,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("10.0.0.2", 51002)],
    )
    await client_b.start()
    await client_c.start()
    await daemon_a.update_rendezvous_urls([base])

    try:
        # Pinned + on rendezvous → resolves.
        b_peer = await daemon_a.resolve_for_send(me_b.fingerprint)
        assert b_peer is not None
        assert b_peer.ed_pub_hex == me_b.public_bytes.hex()

        # Unpinned (pending) → blocked at trust gate, even though
        # rendezvous knows them.
        c_peer = await daemon_a.resolve_for_send(me_c.fingerprint)
        assert c_peer is None
    finally:
        if daemon_a.rendezvous is not None:
            await daemon_a.rendezvous.stop()
        # Audit fix: also stop relay-listener clients spun up by
        # update_rendezvous_urls — each owns its own aiohttp session.
        for listener in list(daemon_a._relay_listener_clients):
            await listener.stop()
        await client_b.stop()
        await client_c.stop()
        state_a.close()


@pytest.mark.asyncio
async def test_resolve_returns_none_when_rendezvous_offline(
    tmp_path: Path,
):
    """If the configured rendezvous is unreachable, the daemon must
    fall back gracefully — resolve_peer_endpoint returns None,
    nothing crashes, no exception bubbles up."""
    me_a = _new_identity("alice")
    me_b = _new_identity("bob")
    state_a = State(db_path=tmp_path / "state.db")
    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    # Configure a URL that nothing is listening on.
    state_a.set_rendezvous_urls(["http://127.0.0.1:1"])

    daemon = Daemon(me_a)
    daemon.state = state_a
    daemon.discovery = None
    await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]

    try:
        peer = await daemon.resolve_peer_endpoint(me_b.fingerprint)
        assert peer is None
    finally:
        if daemon.rendezvous is not None:
            await daemon.rendezvous.stop()
        # Audit fix: relay-listener clients also own a ClientSession.
        for listener in list(daemon._relay_listener_clients):
            await listener.stop()
        state_a.close()
