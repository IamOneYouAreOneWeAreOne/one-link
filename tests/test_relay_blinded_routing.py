"""Executable security contract for pairwise-blinded live relay routing."""

from __future__ import annotations

import asyncio
import json
import logging
import time

import aiohttp
import pytest
from aiohttp import web
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import relay_client, relay_routing
from one_link.relay_client import RelayListenerClient, open_relay_outbound
from one_link.relay_proto import decode_frame, encode_data_frame
from one_link.relay_routing import (
    MAX_PAIRED_ROUTE_PEERS,
    ROUTING_EPOCH_MS,
    ROUTING_GRACE_MS,
    ROUTING_PROTOCOL_VERSION,
    DerivedRoute,
    RouteConnectAuth,
    RouteListenAuth,
    RouteRegistration,
    _route_registration_signing_bytes,
    _routes_digest,
    build_route_listen_auth,
    derive_dial_routes,
    derive_route,
    epoch_for_timestamp,
    listener_route_epochs,
    route_expiry_ms,
    route_listen_wire,
    route_tag_for_authority,
    sign_route_connect_auth,
)
from one_link.rendezvous_proto import _b64
from one_link.rendezvous_server import RendezvousApp, ServerConfig


def _identity() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes_raw()


def _paired_route(
    source_private: Ed25519PrivateKey,
    source_public: bytes,
    destination_private: Ed25519PrivateKey,
    destination_public: bytes,
    *,
    epoch: int,
) -> tuple[DerivedRoute, DerivedRoute]:
    source_view = derive_route(
        local_private_key=source_private,
        local_public_key=source_public,
        peer_public_key=destination_public,
        recipient_public_key=destination_public,
        epoch=epoch,
    )
    destination_view = derive_route(
        local_private_key=destination_private,
        local_public_key=destination_public,
        peer_public_key=source_public,
        recipient_public_key=destination_public,
        epoch=epoch,
    )
    return source_view, destination_view


def test_pairwise_route_is_symmetric_directional_rotating_and_identity_blinded() -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    timestamp = 1_800_000_000_000
    epoch = epoch_for_timestamp(timestamp)

    source_view, destination_view = _paired_route(
        source_private,
        source_public,
        destination_private,
        destination_public,
        epoch=epoch,
    )
    assert source_view.route_tag == destination_view.route_tag
    assert source_view.auth_public == destination_view.auth_public
    assert source_view.route_tag == route_tag_for_authority(
        auth_public=source_view.auth_public,
        epoch=source_view.epoch,
    )

    next_route = derive_route(
        local_private_key=source_private,
        local_public_key=source_public,
        peer_public_key=destination_public,
        recipient_public_key=destination_public,
        epoch=epoch + 1,
    )
    reverse_direction = derive_route(
        local_private_key=source_private,
        local_public_key=source_public,
        peer_public_key=destination_public,
        recipient_public_key=source_public,
        epoch=epoch,
    )
    assert next_route.route_tag != source_view.route_tag
    assert reverse_direction.route_tag != source_view.route_tag

    listen_auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=[source_public],
        timestamp_ms=timestamp,
        nonce=b"l" * 16,
    )
    listen_auth.verify(server_now_ms=timestamp)
    route = next(
        item for item in listen_auth.routes if item.route_tag == source_view.route_tag
    )
    connector = sign_route_connect_auth(
        source_view,
        timestamp_ms=timestamp,
        nonce=b"c" * 16,
    )
    connector.verify(
        expected_route_tag=route.route_tag,
        expected_auth_public=route.auth_public,
        expires_at_ms=route.expires_at_ms,
        server_now_ms=timestamp,
    )

    relay_wire = json.dumps(
        {"listen": listen_auth.to_wire(), "connect": connector.to_wire()},
        sort_keys=True,
    )
    for identity_public in (source_public, destination_public):
        assert identity_public.hex() not in relay_wire
        assert _b64(identity_public) not in relay_wire


def test_epoch_rotation_pre_registers_next_and_bounds_previous_grace() -> None:
    epoch = 10_000
    epoch_start = epoch * ROUTING_EPOCH_MS
    during_grace = listener_route_epochs(at_ms=epoch_start + 1)
    after_grace = listener_route_epochs(at_ms=epoch_start + ROUTING_GRACE_MS)
    assert during_grace == (epoch, epoch + 1, epoch - 1)
    assert after_grace == (epoch, epoch + 1)
    assert route_expiry_ms(epoch - 1) == epoch_start + ROUTING_GRACE_MS


def test_listener_derives_pair_root_once_per_peer_across_rotation_epochs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination_private, destination_public = _identity()
    peer_public_keys = [_identity()[1] for _ in range(4)]
    ecdh_calls = 0
    original_ecdh = relay_routing._pairwise_ecdh

    def _counted_ecdh(local_seed: bytes, peer_public: bytes) -> bytes:
        nonlocal ecdh_calls
        ecdh_calls += 1
        return original_ecdh(local_seed, peer_public)

    monkeypatch.setattr(relay_routing, "_pairwise_ecdh", _counted_ecdh)
    timestamp = 10_000 * ROUTING_EPOCH_MS + 1  # current + next + grace previous
    auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=peer_public_keys,
        timestamp_ms=timestamp,
    )
    assert len(auth.routes) == len(peer_public_keys) * 3
    assert ecdh_calls == len(peer_public_keys)


def test_route_protocol_rejects_tamper_expiry_unknown_fields_and_unbounded_peers() -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    timestamp = 1_800_000_000_000
    route = derive_dial_routes(
        local_private_key=source_private,
        local_public_key=source_public,
        recipient_public_key=destination_public,
        timestamp_ms=timestamp,
    )[0]
    proof = sign_route_connect_auth(route, timestamp_ms=timestamp, nonce=b"n" * 16)

    tampered = proof.to_wire()
    tampered["epoch"] = int(tampered["epoch"]) + 1
    parsed = RouteConnectAuth.from_wire(tampered)
    with pytest.raises(ValueError, match="epoch|expiry|signature"):
        parsed.verify(
            expected_route_tag=route.route_tag,
            expected_auth_public=route.auth_public,
            expires_at_ms=route.expires_at_ms,
            server_now_ms=timestamp,
        )

    expired_time = route_expiry_ms(route.epoch)
    expired_proof = sign_route_connect_auth(route, timestamp_ms=expired_time)
    with pytest.raises(ValueError, match="expired"):
        expired_proof.verify(
            expected_route_tag=route.route_tag,
            expected_auth_public=route.auth_public,
            expires_at_ms=route.expires_at_ms,
            server_now_ms=expired_time,
        )

    auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=[source_public],
        timestamp_ms=timestamp,
    )
    unknown = dict(auth.to_wire())
    unknown["ignored"] = True
    with pytest.raises(ValueError, match="fields invalid"):
        RouteListenAuth.from_wire(unknown)

    excessive_peers = [index.to_bytes(32, "big") for index in range(1, MAX_PAIRED_ROUTE_PEERS + 2)]
    with pytest.raises(ValueError, match="peer bound"):
        build_route_listen_auth(
            local_private_key=destination_private,
            local_public_key=destination_public,
            paired_peer_public_keys=excessive_peers,
            timestamp_ms=timestamp,
        )


def _attacker_listener_auth_for_observed_tag(
    observed: RouteRegistration,
    *,
    timestamp_ms: int,
) -> RouteListenAuth:
    attacker = Ed25519PrivateKey.generate()
    unsigned = RouteRegistration(
        epoch=observed.epoch,
        route_tag=observed.route_tag,
        auth_public=attacker.public_key().public_bytes_raw(),
        expires_at_ms=observed.expires_at_ms,
        signature=b"\x00" * 64,
    )
    digest = _routes_digest((unsigned,))
    nonce = b"h" * 16
    signature = attacker.sign(
        _route_registration_signing_bytes(
            timestamp_ms=timestamp_ms,
            nonce=nonce,
            routes_digest=digest,
            route=unsigned,
        )
    )
    return RouteListenAuth(
        timestamp_ms=timestamp_ms,
        nonce=nonce,
        routes_digest=digest,
        routes=(
            RouteRegistration(
                epoch=unsigned.epoch,
                route_tag=unsigned.route_tag,
                auth_public=unsigned.auth_public,
                expires_at_ms=unsigned.expires_at_ms,
                signature=signature,
            ),
        ),
    )


async def _start_server(
    *, relay_max_route_keys: int = 4_096
) -> tuple[str, RendezvousApp, web.AppRunner]:
    rendezvous = RendezvousApp(
        ServerConfig(
            host="127.0.0.1",
            port=0,
            enable_relay=True,
            rate_per_ip_per_min=10_000,
            relay_connect_per_ip_per_min=10_000,
            rate_listener_replace_per_pubkey_per_min=10_000,
            relay_max_route_keys=relay_max_route_keys,
            eviction_interval_s=0.05,
        )
    )
    runner = web.AppRunner(rendezvous.make_app(), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    port = sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", rendezvous, runner


@pytest.mark.asyncio
async def test_server_route_table_capacity_fails_closed_before_install() -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    del source_private
    auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=[source_public],
    )
    assert len(auth.routes) >= 2
    base, rendezvous, runner = await _start_server(relay_max_route_keys=1)
    websocket: aiohttp.ClientWebSocketResponse | None = None
    try:
        async with aiohttp.ClientSession() as session:
            websocket = await session.ws_connect(f"{base}/api/v2/relay/listen")
            await websocket.send_json(auth.to_wire())
            result = await asyncio.wait_for(websocket.receive(), timeout=1.0)
            assert result.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }
            assert websocket.close_code == 4003
            assert not rendezvous._relay_listeners
    finally:
        if websocket is not None:
            await websocket.close()
        await runner.cleanup()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_v2_listener_rejects_duplicate_fields_and_json_depth_bombs() -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    del source_private
    auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=[source_public],
    )
    canonical = json.dumps(auth.to_wire(), separators=(",", ":"))
    version_field = f'"v":"{ROUTING_PROTOCOL_VERSION}"'
    duplicate_version = canonical.replace(
        version_field,
        f'{version_field},{version_field}',
        1,
    )
    depth_bomb = "[" * 65 + "0" + "]" * 65
    base, rendezvous, runner = await _start_server()
    try:
        async with aiohttp.ClientSession() as session:
            for invalid_auth in (duplicate_version, depth_bomb):
                websocket = await session.ws_connect(f"{base}/api/v2/relay/listen")
                await websocket.send_str(invalid_auth)
                result = await asyncio.wait_for(websocket.receive(), timeout=1.0)
                assert result.type in {
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.ERROR,
                }
                assert websocket.close_code == 4001
                await websocket.close()
        assert not rendezvous._relay_listeners
    finally:
        await runner.cleanup()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_listener_client_refreshes_pair_authority_without_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_private, first_public = _identity()
    second_private, second_public = _identity()
    destination_private, destination_public = _identity()
    del first_private, second_private
    paired = [first_public]
    base, rendezvous, runner = await _start_server()
    monkeypatch.setattr(relay_client, "RELAY_ROUTE_REFRESH_POLL_S", 0.01)
    build_calls = 0
    original_build = relay_routing.build_route_listen_auth

    def _counted_build(**kwargs):
        nonlocal build_calls
        build_calls += 1
        return original_build(**kwargs)

    monkeypatch.setattr(relay_routing, "build_route_listen_auth", _counted_build)

    async def _unexpected_session(_reader, _writer) -> None:
        raise AssertionError("test did not open a relay data session")

    listener = RelayListenerClient(
        rendezvous_url=base,
        private_key=destination_private,
        pubkey=destination_public,
        on_session=_unexpected_session,
        paired_peer_pubkeys_provider=lambda: tuple(paired),
    )
    await listener.start()
    try:
        current_epoch = epoch_for_timestamp(int(time.time() * 1000))
        first_route = derive_route(
            local_private_key=destination_private,
            local_public_key=destination_public,
            peer_public_key=first_public,
            recipient_public_key=destination_public,
            epoch=current_epoch,
        )
        for _ in range(100):
            if first_route.route_tag in rendezvous._relay_listeners:
                break
            await asyncio.sleep(0.01)
        assert first_route.route_tag in rendezvous._relay_listeners
        assert listener.routing_mode == "pairwise_blinded_v1"
        assert listener.destination_identity_exposure == "no_identity_public_key_on_relay_wire"
        assert (
            listener.channel_first_flight_identity_protection
            == "sealed_recipient_only_v1"
        )
        await asyncio.sleep(0.05)
        assert build_calls == 1

        paired[:] = [second_public]
        second_route = derive_route(
            local_private_key=destination_private,
            local_public_key=destination_public,
            peer_public_key=second_public,
            recipient_public_key=destination_public,
            epoch=current_epoch,
        )
        for _ in range(200):
            if (
                second_route.route_tag in rendezvous._relay_listeners
                and first_route.route_tag not in rendezvous._relay_listeners
            ):
                break
            await asyncio.sleep(0.01)
        assert second_route.route_tag in rendezvous._relay_listeners
        assert first_route.route_tag not in rendezvous._relay_listeners
        assert build_calls == 2
    finally:
        await listener.stop()
        await runner.cleanup()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_v2_listener_fails_closed_on_unsealed_channel_first_flight() -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    base, rendezvous, runner = await _start_server()
    rejected = asyncio.Event()
    rejection_errors: list[str] = []

    async def _expect_rejection(reader, _writer) -> None:
        try:
            await reader.readexactly(4)
        except ValueError as exc:
            rejection_errors.append(str(exc))
            rejected.set()
            return
        raise AssertionError("v2 listener accepted an unsealed channel first flight")

    listener = RelayListenerClient(
        rendezvous_url=base,
        private_key=destination_private,
        pubkey=destination_public,
        on_session=_expect_rejection,
        paired_peer_pubkeys_provider=lambda: (source_public,),
    )
    connector: aiohttp.ClientWebSocketResponse | None = None
    await listener.start()
    try:
        current = int(time.time() * 1000)
        route = derive_dial_routes(
            local_private_key=source_private,
            local_public_key=source_public,
            recipient_public_key=destination_public,
            timestamp_ms=current,
        )[0]
        for _ in range(100):
            if route.route_tag in rendezvous._relay_listeners:
                break
            await asyncio.sleep(0.01)
        assert route.route_tag in rendezvous._relay_listeners

        async with aiohttp.ClientSession() as session:
            connector = await session.ws_connect(
                f"{base}/api/v2/relay/connect/{_b64(route.route_tag)}"
            )
            await connector.send_json(sign_route_connect_auth(route).to_wire())
            ready = await asyncio.wait_for(connector.receive_json(), timeout=1.0)
            session_id = bytes.fromhex(ready["session_id"])

            # This has the shape of the historical plaintext channel HELLO.
            # A valid paired route is not enough to opt out of first-flight
            # sealing: the destination tears the session down before channel
            # parsing or identity acceptance.
            raw_hello = source_public + b"\x00" * 116
            raw_channel_frame = len(raw_hello).to_bytes(4, "big") + raw_hello
            await connector.send_bytes(encode_data_frame(session_id, raw_channel_frame))
            await asyncio.wait_for(rejected.wait(), timeout=2.0)
            assert rejection_errors
            assert "sealed relay handshake" in rejection_errors[0]
    finally:
        if connector is not None:
            await connector.close()
        await listener.stop()
        await runner.cleanup()
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_live_blinded_relay_has_no_identity_route_and_rejects_replay_hijack(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_private, source_public = _identity()
    destination_private, destination_public = _identity()
    current = int(time.time() * 1000)
    listen_auth = build_route_listen_auth(
        local_private_key=destination_private,
        local_public_key=destination_public,
        paired_peer_public_keys=[source_public],
        timestamp_ms=current,
        nonce=b"r" * 16,
    )
    dial_route = derive_dial_routes(
        local_private_key=source_private,
        local_public_key=source_public,
        recipient_public_key=destination_public,
        timestamp_ms=current,
    )[0]
    registration = next(
        route for route in listen_auth.routes if route.route_tag == dial_route.route_tag
    )
    connector_auth = sign_route_connect_auth(
        dial_route, timestamp_ms=current, nonce=b"q" * 16
    )

    base, rendezvous, runner = await _start_server()
    caplog.set_level(logging.INFO, logger="one_link.rendezvous_server")
    listener: aiohttp.ClientWebSocketResponse | None = None
    connector: aiohttp.ClientWebSocketResponse | None = None
    replay: aiohttp.ClientWebSocketResponse | None = None
    hijack: aiohttp.ClientWebSocketResponse | None = None
    post_removal_hijack: aiohttp.ClientWebSocketResponse | None = None
    try:
        async with aiohttp.ClientSession() as session:
            listener = await session.ws_connect(f"{base}/api/v2/relay/listen")
            await listener.send_json(listen_auth.to_wire())
            await asyncio.sleep(0.05)

            url = f"{base}/api/v2/relay/connect/{_b64(dial_route.route_tag)}"
            connector = await session.ws_connect(url)
            await connector.send_json(connector_auth.to_wire())
            ready = await asyncio.wait_for(connector.receive_json(), timeout=1.0)
            incoming = await asyncio.wait_for(listener.receive_json(), timeout=1.0)
            assert ready["t"] == "ready"
            assert incoming == {"t": "incoming", "session_id": ready["session_id"]}

            session_id = bytes.fromhex(ready["session_id"])
            await connector.send_bytes(encode_data_frame(session_id, b"opaque-channel-bytes"))
            forwarded = decode_frame(
                (await asyncio.wait_for(listener.receive(), timeout=1.0)).data
            )
            assert forwarded.session_id == session_id
            assert forwarded.payload == b"opaque-channel-bytes"

            # A captured connector proof is one-use inside the replay window.
            replay = await session.ws_connect(url)
            await replay.send_json(connector_auth.to_wire())
            replay_result = await asyncio.wait_for(replay.receive(), timeout=1.0)
            assert replay_result.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }
            assert replay.close_code == 4001

            # Observing a tag does not confer listener-replacement authority.
            attacker_auth = _attacker_listener_auth_for_observed_tag(
                registration,
                timestamp_ms=int(time.time() * 1000),
            )
            with pytest.raises(ValueError, match="self-certified"):
                attacker_auth.verify()
            hijack = await session.ws_connect(f"{base}/api/v2/relay/listen")
            await hijack.send_json(attacker_auth.to_wire())
            hijack_result = await asyncio.wait_for(hijack.receive(), timeout=1.0)
            assert hijack_result.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }
            assert hijack.close_code == 4001
            assert rendezvous._relay_listeners[dial_route.route_tag].ws is not hijack

            relay_wire = json.dumps(
                {"listen": listen_auth.to_wire(), "connect": connector_auth.to_wire()}
            ) + url
            relay_log = caplog.text
            for identity_public in (source_public, destination_public):
                assert identity_public.hex() not in relay_wire
                assert _b64(identity_public) not in relay_wire
                assert identity_public.hex() not in relay_log
                assert _b64(identity_public) not in relay_log

            assert source_public not in rendezvous._relay_listeners
            assert destination_public not in rendezvous._relay_listeners
            active_listener = rendezvous._relay_listeners[dial_route.route_tag]
            assert active_listener.routing_mode == "pairwise_blinded_v1"
            assert destination_public not in active_listener.route_auth_pubs.values()
            assert source_public not in active_listener.route_auth_pubs.values()

            # Atomic refresh removes obsolete admission tags, installs a newly
            # paired peer's current/next tags, and leaves an already-authenticated
            # encrypted channel alive so long transfers are not cut every epoch.
            _replacement_source_private, replacement_source_public = _identity()
            refreshed = build_route_listen_auth(
                local_private_key=destination_private,
                local_public_key=destination_public,
                paired_peer_public_keys=[replacement_source_public],
                timestamp_ms=int(time.time() * 1000),
            )
            await listener.send_json(route_listen_wire(refreshed, refresh=True))
            for _ in range(40):
                if dial_route.route_tag not in rendezvous._relay_listeners:
                    break
                await asyncio.sleep(0.01)
            assert dial_route.route_tag not in rendezvous._relay_listeners
            assert all(
                route.route_tag in rendezvous._relay_listeners
                for route in refreshed.routes
            )
            with pytest.raises(aiohttp.WSServerHandshakeError) as missing_route:
                await session.ws_connect(url)
            assert missing_route.value.status == 404

            # The tag remains unclaimable even after removal: it is
            # self-certified from its epoch verification key, so a new key
            # cannot validate the observed tag and no unbounded tombstone is
            # needed to remember prior ownership.
            post_removal_auth = _attacker_listener_auth_for_observed_tag(
                registration,
                timestamp_ms=int(time.time() * 1000),
            )
            post_removal_hijack = await session.ws_connect(
                f"{base}/api/v2/relay/listen"
            )
            await post_removal_hijack.send_json(post_removal_auth.to_wire())
            post_removal_result = await asyncio.wait_for(
                post_removal_hijack.receive(), timeout=1.0
            )
            assert post_removal_result.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }
            assert post_removal_hijack.close_code == 4001

            await connector.send_bytes(encode_data_frame(session_id, b"active-session-survives"))
            post_refresh = decode_frame(
                (await asyncio.wait_for(listener.receive(), timeout=1.0)).data
            )
            assert post_refresh.payload == b"active-session-survives"
    finally:
        for websocket in (post_removal_hijack, hijack, replay, connector, listener):
            if websocket is not None:
                await websocket.close()
        await runner.cleanup()
        await asyncio.sleep(0)


def test_protocol_version_and_epoch_are_explicit_and_bounded() -> None:
    assert ROUTING_PROTOCOL_VERSION == "OL-RELAY-ROUTE-1"
    assert ROUTING_EPOCH_MS == 10 * 60 * 1000


@pytest.mark.asyncio
async def test_low_level_outbound_cannot_silently_downgrade_to_identity_route() -> None:
    _private, destination_public = _identity()
    with pytest.raises(RuntimeError, match="legacy public-key routing was not explicitly enabled"):
        await open_relay_outbound("http://unused.invalid", destination_public)
