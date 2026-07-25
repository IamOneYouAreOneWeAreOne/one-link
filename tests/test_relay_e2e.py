"""End-to-end tests: encrypted relay between two real daemons.

Spins up:
  1. A real RendezvousApp (with relay enabled) on a localhost port.
  2. Two real Daemon instances configured to use that rendezvous.
  3. Forces direct dial to fail (no listener on the receiver) so the
     ONLY remaining path is the relay.
  4. Verifies a chat message gets from sender → relay → receiver,
     persists in the receiver's state, and the ACK round-trips.

This test proves the entire relay stack: protocol parsing, sealed-
sender envelope, server-side multiplexing, listener auth, daemon-
level fall-through when direct dial fails, and the encrypted One Link
channel running unchanged on top of the relay-tunneled bytes.
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
from one_link.relay_client import SEALED_RELAY_HANDSHAKE_MAGIC
from one_link.relay_proto import FRAME_DATA, SESSION_ID_BYTES
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


async def _start_relay_rendezvous() -> tuple[str, RendezvousApp, aiohttp.web.AppRunner]:
    config = ServerConfig(
        host="127.0.0.1", port=0,
        rate_per_ip_per_min=10_000,
        rate_register_per_pubkey_per_min=10_000,
        eviction_interval_s=0.1,
        enable_relay=True,
        relay_connect_per_ip_per_min=10_000,
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
async def relay_rendezvous() -> AsyncIterator[tuple[str, RendezvousApp]]:
    base, rdz, runner = await _start_relay_rendezvous()
    try:
        yield base, rdz
    finally:
        await runner.cleanup()
        # aiohttp closes plain-TCP transports asynchronously after session,
        # websocket, and runner cleanup.  Yield one loop turn so those close
        # callbacks finish before pytest collects unclosed connections under
        # ``-W error`` or tears down the test loop.
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_chat_through_encrypted_relay(
    relay_rendezvous,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Both daemons configured with the same relay-enabled rendezvous.
    A's _dial_peer for B finds NO direct candidates (B isn't on mDNS,
    has no advertised endpoints with usable ports), so falls through
    to relay. Real chat message → ACK round-trip → persisted in B."""
    base, rdz = relay_rendezvous

    # Capture the exact DATA payloads parsed by the relay in both directions.
    # This is intentionally below the client abstractions: a routing-table or
    # log-only assertion would miss identity keys in channel HELLO/REPLY.
    import one_link.rendezvous_server as rendezvous_server_module

    relay_wire_payloads: list[bytes] = []
    original_frame_metadata = rendezvous_server_module._relay_frame_metadata

    def _capture_relay_frame(buf: bytes) -> tuple[int, bytes, int]:
        result = original_frame_metadata(buf)
        if result[0] == FRAME_DATA:
            relay_wire_payloads.append(bytes(memoryview(buf)[1 + SESSION_ID_BYTES :]))
        return result

    monkeypatch.setattr(
        rendezvous_server_module,
        "_relay_frame_metadata",
        _capture_relay_frame,
    )

    me_a = _new_identity("alice-laptop")
    me_b = _new_identity("bob-laptop")

    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")
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

    state_a.set_rendezvous_urls([base])
    state_b.set_rendezvous_urls([base])

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None  # bypass mDNS

    daemon_b = Daemon(me_b)
    daemon_b.state = state_b
    daemon_b.discovery = None

    # Bring up rendezvous + relay listeners on both. peer_port=0 means
    # neither advertises a real listener; the only way to reach B is
    # the relay.
    daemon_a._rendezvous_peer_port = 0  # type: ignore[attr-defined]
    daemon_b._rendezvous_peer_port = 0  # type: ignore[attr-defined]

    await daemon_a.update_rendezvous_urls([base])
    await daemon_b.update_rendezvous_urls([base])

    # Give the relay listeners a moment to register their slots.
    await asyncio.sleep(0.5)

    try:
        # Confirm B's relay listener is registered on the rendezvous.
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/metrics") as r:
                m = await r.json()
        assert m["relay_listeners_active"] >= 2, (
            f"both daemons should have registered relay listeners: {m!r}"
        )
        assert m["relay_blinded_listeners_active"] >= 2
        assert m["relay_legacy_identity_listeners_active"] == 0
        assert m["relay_destination_identity_exposure"] is False
        assert me_a.public_bytes not in rdz._relay_listeners
        assert me_b.public_bytes not in rdz._relay_listeners
        assert all(
            listener.routing_mode == "pairwise_blinded_v1"
            for listener in rdz._unique_relay_listeners()
        )
        for daemon in (daemon_a, daemon_b):
            relay_truth = daemon.relay_routing_runtime_truth()
            assert relay_truth["pairwise_blinded_active"] is True
            assert relay_truth["legacy_identity_route_active"] is False
            assert (
                relay_truth["destination_identity_exposure"]
                == "no_identity_public_key_on_relay_wire"
            )
            assert (
                relay_truth["identity_bearing_channel_first_flight"]
                == "sealed_recipient_only_v1"
            )

        # Synthesize a peer record for B as A would learn it (no direct
        # endpoint, just pubkey). _dial_peer should find no direct
        # candidate and fall through to relay.
        from one_link.discovery import Peer
        b_via_relay = Peer(
            short_id=me_b.short_id,
            hostname=me_b.hostname,
            address="",        # empty → no direct candidates
            port=0,
            ed_pub_hex=me_b.public_bytes.hex(),
        )

        # Real send_text — this exercises:
        #   1. _get_outbound_session → _dial_peer
        #   2. _dial_peer → no direct, falls to _dial_via_relay
        #   3. open_relay_outbound on the rendezvous, gets stream pair
        #   4. ch.initiate runs encrypted handshake over the stream
        #   5. CAPS exchange, then TEXT message + ACK
        #   6. B's relay listener delivers session to _handle_peer,
        #      which validates handshake, records msg, sends ACK
        result = await asyncio.wait_for(
            daemon_a.send_text(b_via_relay, "hello via relay"),
            timeout=15.0,
        )
        assert result["ack"]["t"] == "ACK", f"unexpected: {result!r}"
        assert result["sent"]["body"] == "hello via relay"

        # Give B's persistence a moment to commit.
        await asyncio.sleep(0.2)

        msgs = state_b.recent_messages(limit=10)
        bodies = [m.body for m in msgs]
        assert "hello via relay" in bodies, (
            f"message did not land in B's state: {bodies!r}"
        )

        # Bytes really did pass through the relay.
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/metrics") as r:
                m = await r.json()
        assert m["relay_sessions_total"] >= 1
        assert m["relay_bytes_forwarded"] > 0

        # Both identity-bearing channel first flights must be sealed before
        # the relay parses them. Every later channel frame is already AEAD
        # ciphertext. Assert against the relay's exact observed DATA bytes,
        # not merely client-side serialization or server routing state.
        assert relay_wire_payloads
        sealed_first_flights = [
            payload
            for payload in relay_wire_payloads
            if len(payload) >= 4 + len(SEALED_RELAY_HANDSHAKE_MAGIC)
            and payload[4 : 4 + len(SEALED_RELAY_HANDSHAKE_MAGIC)]
            == SEALED_RELAY_HANDSHAKE_MAGIC
        ]
        assert len(sealed_first_flights) == 2
        observed_relay_data = b"".join(relay_wire_payloads)
        assert me_a.public_bytes not in observed_relay_data
        assert me_b.public_bytes not in observed_relay_data
    finally:
        for fp in list(daemon_a._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_a._drop_outbound_session(fp)
        for fp in list(daemon_b._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_b._drop_outbound_session(fp)
        if daemon_a.rendezvous is not None:
            await daemon_a.rendezvous.stop()
        if daemon_b.rendezvous is not None:
            await daemon_b.rendezvous.stop()
        for listener in list(daemon_a._relay_listener_clients):  # type: ignore[attr-defined]
            await listener.stop()
        for listener in list(daemon_b._relay_listener_clients):  # type: ignore[attr-defined]
            await listener.stop()
        state_a.close()
        state_b.close()


@pytest.mark.asyncio
async def test_relay_listen_auth_nonce_cannot_be_replayed(relay_rendezvous):
    """A captured listen auth blob cannot reclaim or replace a listener
    inside the timestamp window."""
    base, rdz = relay_rendezvous
    me = _new_identity("listener")

    from one_link.relay_proto import sign_listen_auth
    auth = sign_listen_auth(private_key=me.private, pubkey=me.public_bytes)

    async with aiohttp.ClientSession() as s:
        ws1 = await s.ws_connect(f"{base}/api/v1/relay/listen")
        try:
            await ws1.send_json(auth.to_wire())
            await asyncio.sleep(0.1)
            assert rdz._relay_listeners.get(me.public_bytes) is not None

            ws2 = await s.ws_connect(f"{base}/api/v1/relay/listen")
            try:
                await ws2.send_json(auth.to_wire())
                msg = await asyncio.wait_for(ws2.receive(), timeout=2.0)
                assert msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                )
                assert ws2.close_code == 4001
                assert rdz._relay_listeners.get(me.public_bytes) is not None
            finally:
                await ws2.close()
        finally:
            await ws1.close()


@pytest.mark.asyncio
async def test_relay_fallback_only_used_when_direct_dial_fails(
    relay_rendezvous, tmp_path: Path
):
    """Sanity: if direct dial succeeds, we don't go through the relay.
    Set up B with a real local listener, A reaches it directly. Relay
    bytes_forwarded should stay 0."""
    base, _rdz = relay_rendezvous

    me_a = _new_identity()
    me_b = _new_identity()

    (tmp_path / "a").mkdir(parents=True, exist_ok=True)
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    state_a = State(db_path=tmp_path / "a" / "state.db")
    state_b = State(db_path=tmp_path / "b" / "state.db")

    state_a.upsert_peer(
        fingerprint=me_b.fingerprint, short_id=me_b.short_id,
        pubkey=me_b.public_bytes,
    )
    state_a.set_peer_trust(me_b.fingerprint, "pinned")
    state_b.upsert_peer(
        fingerprint=me_a.fingerprint, short_id=me_a.short_id,
        pubkey=me_a.public_bytes,
    )
    state_b.set_peer_trust(me_a.fingerprint, "pinned")

    daemon_a = Daemon(me_a)
    daemon_a.state = state_a
    daemon_a.discovery = None

    daemon_b = Daemon(me_b)
    daemon_b.state = state_b
    daemon_b.discovery = None

    server_b = await asyncio.start_server(
        daemon_b._handle_peer, host="127.0.0.1", port=0
    )
    b_port = server_b.sockets[0].getsockname()[1]

    try:
        # No rendezvous on A, no relay listener — so direct dial is
        # the ONLY path. Relay metrics must stay 0.
        from one_link.discovery import Peer
        peer_b = Peer(
            short_id=me_b.short_id, hostname="b",
            address="127.0.0.1", port=b_port,
            ed_pub_hex=me_b.public_bytes.hex(),
        )
        result = await asyncio.wait_for(
            daemon_a.send_text(peer_b, "hello direct"),
            timeout=10.0,
        )
        assert result["ack"]["t"] == "ACK"

        # Confirm relay was untouched.
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/metrics") as r:
                m = await r.json()
        assert m["relay_sessions_total"] == 0
        assert m["relay_bytes_forwarded"] == 0
    finally:
        for fp in list(daemon_a._outbound_sessions):  # type: ignore[attr-defined]
            await daemon_a._drop_outbound_session(fp)
        server_b.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server_b.wait_closed(), timeout=2.0)
        state_a.close()
        state_b.close()
