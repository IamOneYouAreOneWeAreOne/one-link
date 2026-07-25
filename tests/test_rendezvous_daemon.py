"""Integration tests for v0.5.1 — daemon ↔ rendezvous wiring.

Two layers:
  1. Direct: `Daemon.resolve_peer_endpoint(peer_fp)` falls back to
     rendezvous lookup when the peer isn't on mDNS. We mock the
     daemon shape just enough to exercise that method against a real
     rendezvous server.
  2. End-to-end: start a real rendezvous, configure two real daemons
     to use it, verify the /api/rendezvous endpoint reports the
     observed self and that paired peers can be resolved off-LAN.
"""
from __future__ import annotations

import json
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
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk,
        public=pub_obj,
        public_bytes=pub_bytes,
        fingerprint=fp,
        short_id=fp[:8],
        hostname="testhost",
    )


async def _start_rendezvous() -> tuple[str, RendezvousApp, aiohttp.web.AppRunner]:
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


@pytest_asyncio.fixture
async def rendezvous() -> AsyncIterator[tuple[str, RendezvousApp]]:
    base, rdz, runner = await _start_rendezvous()
    try:
        yield base, rdz
    finally:
        await runner.cleanup()


# ─── direct: resolve_peer_endpoint via rendezvous ────────────────────

@pytest.mark.asyncio
async def test_resolve_peer_endpoint_falls_back_to_rendezvous(
    rendezvous, tmp_path: Path
):
    """Daemon A has B as a paired peer in state but mDNS doesn't see B.
    The rendezvous knows where B is. resolve_peer_endpoint must return
    a Peer record built from the rendezvous reply."""
    base, rdz = rendezvous

    # Identities for A (us) and B (the peer we're resolving).
    me = _new_identity()
    b_id = _new_identity()

    # B "registers" with the rendezvous on its own.
    b_advertised_host = "192.168.7.10"
    b_advertised_port = 51234
    b_client = RendezvousClient(
        private_key=b_id.private, pubkey=b_id.public_bytes,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint(b_advertised_host, b_advertised_port)],
        capabilities=["chat"],
    )
    await b_client.start()

    # Build a daemon for A with state that has B pinned, then start its
    # own rendezvous client.
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=b_id.fingerprint,
            short_id=b_id.short_id,
            pubkey=b_id.public_bytes,
            hostname="B-laptop",
        )
        state.set_peer_trust(b_id.fingerprint, "pinned")
        state.set_rendezvous_urls([base])

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None  # force the rendezvous fallback path
        # Start a real RendezvousClient on the daemon.
        await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]
        try:
            peer = await daemon.resolve_peer_endpoint(b_id.fingerprint)
            assert peer is not None
            # Advertised endpoint comes first (the rendezvous-observed
            # *port* is the HTTP source port, not the peer-server port,
            # so we never use it directly — only the observed host
            # paired with an advertised port). _collect_dial_candidates
            # produces both (advertised, advertised) and (observed_host,
            # advertised_port); resolve_peer_endpoint returns the first.
            assert peer.address == b_advertised_host
            assert peer.port == b_advertised_port
            assert peer.ed_pub_hex == b_id.public_bytes.hex()
        finally:
            if daemon.rendezvous is not None:
                await daemon.rendezvous.stop()
            for listener in list(daemon._relay_listener_clients):
                await listener.stop()
            await b_client.stop()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_resolve_peer_endpoint_returns_none_when_unknown(
    rendezvous, tmp_path: Path
):
    """Peer is paired locally but the rendezvous doesn't have it."""
    base, _rdz = rendezvous
    me = _new_identity()
    b_id = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=b_id.fingerprint,
            short_id=b_id.short_id,
            pubkey=b_id.public_bytes,
        )
        state.set_peer_trust(b_id.fingerprint, "pinned")
        state.set_rendezvous_urls([base])

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None
        await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]
        try:
            peer = await daemon.resolve_peer_endpoint(b_id.fingerprint)
            assert peer is None
        finally:
            if daemon.rendezvous is not None:
                await daemon.rendezvous.stop()
            for listener in list(daemon._relay_listener_clients):
                await listener.stop()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_resolve_peer_endpoint_skips_unpaired(
    rendezvous, tmp_path: Path
):
    """An unpaired (pending) peer should NOT be resolvable via
    rendezvous — that path is only for trusted contacts."""
    base, _rdz = rendezvous
    me = _new_identity()
    b_id = _new_identity()

    b_client = RendezvousClient(
        private_key=b_id.private, pubkey=b_id.public_bytes,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("h", 1)],
    )
    await b_client.start()

    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=b_id.fingerprint,
            short_id=b_id.short_id,
            pubkey=b_id.public_bytes,
        )
        # NOT pinned.
        state.set_rendezvous_urls([base])

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None
        await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]
        try:
            # resolve_for_send respects the pinning gate. (Direct
            # resolve_peer_endpoint doesn't gate by trust by design —
            # it's a lower-level primitive — so test resolve_for_send.)
            peer = await daemon.resolve_for_send(b_id.fingerprint)
            assert peer is None
        finally:
            if daemon.rendezvous is not None:
                await daemon.rendezvous.stop()
            for listener in list(daemon._relay_listener_clients):
                await listener.stop()
            await b_client.stop()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_resolve_peer_endpoint_prefers_mdns_when_available(
    rendezvous, tmp_path: Path
):
    """If the peer is BOTH on mDNS and registered with rendezvous,
    mDNS wins (it's lower-latency and confirmed-reachable)."""
    base, _rdz = rendezvous
    me = _new_identity()
    b_id = _new_identity()

    # B registers a misleading endpoint with the rendezvous.
    b_client = RendezvousClient(
        private_key=b_id.private, pubkey=b_id.public_bytes,
        rendezvous_urls=[base],
        advertise_endpoints=[Endpoint("99.99.99.99", 1)],
    )
    await b_client.start()

    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=b_id.fingerprint,
            short_id=b_id.short_id,
            pubkey=b_id.public_bytes,
        )
        state.set_peer_trust(b_id.fingerprint, "pinned")
        state.set_rendezvous_urls([base])

        # Fake discovery that returns B at the *correct* LAN address.
        lan_peer = Peer(
            short_id=b_id.short_id,
            hostname="B",
            address="192.168.1.42",
            port=51234,
            ed_pub_hex=b_id.public_bytes.hex(),
        )
        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = SimpleNamespace(
            registry=SimpleNamespace(list=lambda: [lan_peer])
        )
        await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]
        try:
            peer = await daemon.resolve_peer_endpoint(b_id.fingerprint)
            assert peer is not None
            assert peer.address == "192.168.1.42"  # mDNS wins
        finally:
            if daemon.rendezvous is not None:
                await daemon.rendezvous.stop()
            for listener in list(daemon._relay_listener_clients):
                await listener.stop()
            await b_client.stop()
    finally:
        state.close()


@pytest.mark.asyncio
async def test_daemon_without_rendezvous_urls_runs_lan_only(tmp_path: Path):
    """Daemon must start cleanly even with no rendezvous configured —
    LAN-only mode. resolve_peer_endpoint returns None for unknown peers
    and never attempts a network call."""
    me = _new_identity()
    b_id = _new_identity()
    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint=b_id.fingerprint,
            short_id=b_id.short_id,
            pubkey=b_id.public_bytes,
        )
        state.set_peer_trust(b_id.fingerprint, "pinned")
        # Deliberately NO rendezvous URLs.

        daemon = Daemon(me)
        daemon.state = state
        daemon.discovery = None
        await daemon._start_rendezvous(peer_port=0)  # type: ignore[attr-defined]

        assert daemon.rendezvous is None
        peer = await daemon.resolve_peer_endpoint(b_id.fingerprint)
        assert peer is None
    finally:
        state.close()


# ─── state-layer URL helpers ────────────────────────────────────────

def test_state_rendezvous_urls_round_trip(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        assert state.get_rendezvous_urls() == []
        state.set_rendezvous_urls([
            "https://rdz.example.com",
            "  https://other.example.com/  ",
        ])
        out = state.get_rendezvous_urls()
        # Sorted, deduped, trailing-slash-stripped, whitespace-trimmed.
        assert out == ["https://other.example.com", "https://rdz.example.com"]
    finally:
        state.close()


def test_state_rendezvous_urls_rejects_non_http(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        with pytest.raises(ValueError):
            state.set_rendezvous_urls(["ws://not-allowed.example"])
        with pytest.raises(ValueError):
            state.set_rendezvous_urls(["ftp://nope"])
    finally:
        state.close()


def test_state_rendezvous_urls_handles_empty_and_blank(tmp_path: Path):
    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_rendezvous_urls(["https://x", "", "  ", "https://y"])
        assert state.get_rendezvous_urls() == ["https://x", "https://y"]
    finally:
        state.close()


# ─── server.py: /api/rendezvous endpoints ───────────────────────────

@pytest.mark.asyncio
async def test_api_rendezvous_get_when_unconfigured(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = SimpleNamespace(
            state=state,
            rendezvous=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)

        class _Req:
            query: dict = {}
            match_info: dict = {}

        resp = await server.api_get_rendezvous(_Req())
        body = json.loads(resp.text)
        assert body["urls"] == []
        assert body["active"] is False
        assert body["observed_self"] == {}
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_rendezvous_set_persists_urls_and_live_applies(tmp_path: Path):
    """v0.5.3: POST /api/rendezvous applies the URL change immediately
    — no restart required. The daemon's update_rendezvous_urls() is
    invoked with the persisted list."""
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    applied_urls: list[list[str]] = []

    async def _fake_update(urls):
        applied_urls.append(list(urls))

    try:
        daemon = SimpleNamespace(
            state=state,
            rendezvous=None,
            update_rendezvous_urls=_fake_update,
            ui_server=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)

        class _Req:
            def __init__(self, body):
                self._body = body
                self.query: dict = {}
                self.match_info: dict = {}

            async def json(self):
                return self._body

        resp = await server.api_set_rendezvous(_Req({"urls": ["https://r.example"]}))
        body = json.loads(resp.text)
        assert body["ok"] is True
        assert body["urls"] == ["https://r.example"]
        assert body["active"] is False  # daemon.rendezvous still None in this fake
        # Live re-config applied
        assert applied_urls == [["https://r.example"]]
        # And persisted
        assert state.get_rendezvous_urls() == ["https://r.example"]
    finally:
        state.close()


@pytest.mark.asyncio
async def test_update_rendezvous_urls_switches_live_between_rendezvous(
    tmp_path: Path,
):
    """Daemon configured for rendezvous A; live re-config to B.
    Old registration on A should be revoked; new registration on B
    should appear. No daemon restart involved."""
    base_a, rdz_a, run_a = await _start_rendezvous()
    base_b, rdz_b, run_b = await _start_rendezvous()
    try:
        me = _new_identity()
        state = State(db_path=tmp_path / "state.db")
        try:
            state.set_rendezvous_urls([base_a])

            daemon = Daemon(me)
            daemon.state = state
            daemon.discovery = None
            await daemon._start_rendezvous(peer_port=51234)  # type: ignore[attr-defined]
            try:
                # Confirm A has us; B doesn't.
                assert rdz_a.registry.get(me.public_bytes) is not None
                assert rdz_b.registry.get(me.public_bytes) is None

                # Live switch.
                state.set_rendezvous_urls([base_b])
                await daemon.update_rendezvous_urls([base_b])

                # Now B has us; A no longer does (revoked on stop).
                assert rdz_b.registry.get(me.public_bytes) is not None
                assert rdz_a.registry.get(me.public_bytes) is None

                # Switch to empty — disables rendezvous entirely.
                await daemon.update_rendezvous_urls([])
                assert daemon.rendezvous is None
                assert rdz_b.registry.get(me.public_bytes) is None
            finally:
                if daemon.rendezvous is not None:
                    await daemon.rendezvous.stop()
        finally:
            state.close()
    finally:
        await run_a.cleanup()
        await run_b.cleanup()


@pytest.mark.asyncio
async def test_api_rendezvous_set_rejects_bad_protocol(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = SimpleNamespace(
            state=state,
            rendezvous=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)

        class _Req:
            def __init__(self, body):
                self._body = body
                self.query: dict = {}
                self.match_info: dict = {}

            async def json(self):
                return self._body

        resp = await server.api_set_rendezvous(_Req({"urls": ["ws://nope"]}))
        assert resp.status == 400
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_rendezvous_set_rejects_non_list(tmp_path: Path):
    from one_link.server import UIServer

    state = State(db_path=tmp_path / "state.db")
    try:
        daemon = SimpleNamespace(
            state=state,
            rendezvous=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)

        class _Req:
            def __init__(self, body):
                self._body = body
                self.query: dict = {}
                self.match_info: dict = {}

            async def json(self):
                return self._body

        resp = await server.api_set_rendezvous(_Req({"urls": "not a list"}))
        assert resp.status == 400
    finally:
        state.close()
