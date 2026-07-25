"""Adversarial regressions for the rendezvous HTTP/proxy boundary."""

from __future__ import annotations

import base64
import asyncio
import logging
from dataclasses import replace
from pathlib import Path

import aiohttp
import pytest

from one_link import rdz_blind, rendezvous_server
from one_link.relay_proto import sign_listen_auth
from one_link.rendezvous_proto import Endpoint, LookupAck, MAX_REQUEST_BYTES
from one_link.rendezvous_server import (
    Registration,
    RendezvousApp,
    ServerConfig,
)


async def _start(
    config: ServerConfig,
) -> tuple[str, RendezvousApp, aiohttp.web.AppRunner]:
    rendezvous = RendezvousApp(config)
    runner = aiohttp.web.AppRunner(rendezvous.make_app(), access_log=None)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, host="127.0.0.1", port=0)
    await site.start()
    port = list(site._server.sockets)[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", rendezvous, runner


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_http_body_limit_matches_protocol_instead_of_websocket_frame_limit() -> None:
    app = RendezvousApp(ServerConfig()).make_app()
    assert app._client_max_size == MAX_REQUEST_BYTES


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"host": ""}, "host"),
        ({"port": -1}, "port"),
        ({"max_registrations": 0}, "max_registrations"),
        ({"rate_per_ip_per_min": 0}, "rate_per_ip_per_min"),
        ({"eviction_interval_s": float("nan")}, "eviction_interval_s"),
        ({"max_concurrent_connections": 0}, "max_concurrent_connections"),
        ({"memory_budget_bytes": 0}, "memory_budget_bytes"),
        ({"trust_proxy_headers": 1}, "trust_proxy_headers"),
        ({"relay_session_idle_s": "forever"}, "relay_session_idle_s"),
    ],
)
def test_invalid_resource_and_identity_configuration_fails_closed(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        RendezvousApp(replace(ServerConfig(), **changes))  # type: ignore[arg-type]


def test_shipped_memory_envelope_fits_and_unsafe_old_shape_fails_closed() -> None:
    shipped = ServerConfig(enable_relay=True)
    assert rendezvous_server._estimated_process_memory_bytes(shipped) <= shipped.memory_budget_bytes

    unsafe = replace(
        shipped,
        max_registrations=200_000,
        max_attacker_state_keys=200_000,
    )
    with pytest.raises(ValueError, match="memory_budget_bytes"):
        RendezvousApp(unsafe)


def test_every_attacker_keyed_limiter_uses_declared_cap() -> None:
    app = RendezvousApp(ServerConfig(max_attacker_state_keys=17))
    limiters = (
        app.rate_per_ip,
        app.rate_register_per_pubkey,
        app.rate_lookup_per_ip,
        app.rate_new_pubkey_per_ip,
        app.rate_listener_replace_per_pubkey,
        app.rate_relay_connect_per_ip,
    )
    assert {limiter.max_keys for limiter in limiters} == {17}

    for index in range(100):
        app.rate_per_ip.admit(f"203.0.113.{index}")
    assert len(app.rate_per_ip._hits) == 17
    assert all(len(bucket) == 2 for bucket in app.rate_per_ip._hits.values())


def test_rate_limiter_capacity_fails_closed_without_resetting_live_buckets() -> None:
    limiter = rendezvous_server._RateLimiter(rate_per_min=2, max_keys=2)

    assert limiter.admit("198.51.100.1")
    assert limiter.admit("198.51.100.2")
    assert not limiter.admit("198.51.100.3")
    assert set(limiter._hits) == {"198.51.100.1", "198.51.100.2"}

    # The rejected third identity must not evict/reset the first identity's
    # partially consumed bucket.
    assert limiter.admit("198.51.100.1")
    assert not limiter.admit("198.51.100.1")


def test_nonce_and_signature_caps_count_values_not_only_identities() -> None:
    app = RendezvousApp(ServerConfig(max_attacker_state_keys=2))
    timestamp = rendezvous_server.now_ms()
    pubkey = b"p" * 32

    assert app._admit_relay_listen_nonce(pubkey, timestamp, b"a" * 16)
    assert app._admit_relay_listen_nonce(pubkey, timestamp, b"b" * 16)
    assert not app._admit_relay_listen_nonce(pubkey, timestamp, b"c" * 16)
    assert len(app._relay_listen_nonces) == 2

    assert app._admit_signed_message_once("register", pubkey, timestamp, b"a" * 64)
    assert app._admit_signed_message_once("register", pubkey, timestamp, b"b" * 64)
    assert not app._admit_signed_message_once("register", pubkey, timestamp, b"c" * 64)
    assert len(app._signed_replay_cache) == 2


def test_container_limits_and_declared_process_budget_cannot_drift() -> None:
    root = Path(__file__).resolve().parents[1]
    entrypoint = (root / "deploy/rendezvous/entrypoint.sh").read_text(encoding="utf-8")
    dockerfile = (root / "deploy/rendezvous/Dockerfile").read_text(encoding="utf-8")
    compose = (root / "deploy/rendezvous/docker-compose.yml").read_text(encoding="utf-8")

    for document in (entrypoint, dockerfile, compose):
        assert "20000" in document
        assert "536870912" in document
        assert "134217728" in document
    assert "MAX_CONCURRENT_CONNECTIONS:-64" in entrypoint
    assert "RELAY_MAX_ROUTE_KEYS:-4096" in entrypoint
    assert "MAX_CONCURRENT_CONNECTIONS=64" in dockerfile
    assert "RELAY_MAX_ROUTE_KEYS=4096" in dockerfile
    assert 'MAX_CONCURRENT_CONNECTIONS: "64"' in compose
    assert 'RELAY_MAX_ROUTE_KEYS: "4096"' in compose
    assert 'mem_limit: "512M"' in compose
    assert "stop_grace_period: 120s" in compose

    nginx = (root / "deploy/rendezvous/nginx.conf.example").read_text(encoding="utf-8")
    assert "return 308 https://$server_name$request_uri;" in nginx
    assert "https://$host" not in nginx
    assert nginx.count("access_log off;") == 2
    assert nginx.count("error_log /var/log/nginx/one-link-rendezvous-error.log emerg;") == 2
    assert "client_max_body_size 8k;" in nginx
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "proxy_add_x_forwarded_for" not in nginx
    assert nginx.count('proxy_set_header Forwarded "";') == 2
    assert nginx.count('proxy_set_header Cookie "";') == 2
    assert nginx.count("proxy_hide_header Set-Cookie;") == 2
    assert nginx.count("proxy_hide_header Server;") == 2
    assert "limit_req_zone $binary_remote_addr" in nginx
    assert "limit_conn_zone $binary_remote_addr" in nginx
    assert nginx.count("limit_req_status 429;") == 2
    assert "limit_conn one_link_rendezvous_connections 32;" in nginx
    assert "location = /metrics" in nginx
    assert "location ~ ^/api/v[12]/relay/" in nginx


@pytest.mark.asyncio
async def test_production_runner_disables_raw_request_target_access_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    started = asyncio.Event()
    cleaned = asyncio.Event()

    class FakeRunner:
        def __init__(self, app: aiohttp.web.Application, **kwargs: object) -> None:
            captured["app"] = app
            captured.update(kwargs)

        async def setup(self) -> None:
            return None

        async def cleanup(self) -> None:
            cleaned.set()

    class FakeSite:
        def __init__(self, runner: FakeRunner, **kwargs: object) -> None:
            captured["runner"] = runner
            captured["site_kwargs"] = kwargs

        async def start(self) -> None:
            started.set()

    monkeypatch.setattr(rendezvous_server.web, "AppRunner", FakeRunner)
    monkeypatch.setattr(rendezvous_server.web, "TCPSite", FakeSite)
    loop = asyncio.get_running_loop()

    def unsupported_signal_handler(*_args: object) -> None:
        raise NotImplementedError

    monkeypatch.setattr(loop, "add_signal_handler", unsupported_signal_handler)

    task = asyncio.create_task(
        rendezvous_server._serve_forever(ServerConfig(host="127.0.0.1", port=0))
    )
    await asyncio.wait_for(started.wait(), timeout=1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert captured["access_log"] is None
    assert cleaned.is_set()


@pytest.mark.asyncio
async def test_rate_limit_log_uses_route_template_not_lookup_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        rate_per_ip_per_min=1,
        rate_lookup_per_ip_per_min=100,
    )
    base, _rdz, runner = await _start(config)
    token = _b64(b"S" * 32)
    caplog.set_level(logging.INFO, logger="one_link.rendezvous_server")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base}/api/v2/lookup_token/{token}") as response:
                assert response.status == 404
            async with session.get(f"{base}/api/v2/lookup_token/{token}") as response:
                assert response.status == 429
        assert token not in caplog.text
        assert "/api/v2/lookup_token/{token_b64}" in caplog.text
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_health_is_minimal_and_rate_limited() -> None:
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        rate_per_ip_per_min=1,
    )
    base, _rdz, runner = await _start(config)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base}/health") as response:
                assert response.status == 200
                assert await response.json() == {"ok": True}
            async with session.get(f"{base}/health") as response:
                assert response.status == 429
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_ipv6_interface_rotation_cannot_reset_per_ip_quota() -> None:
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        trust_proxy_headers=True,
        rate_per_ip_per_min=1,
    )
    base, _rdz, runner = await _start(config)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{base}/health",
                headers={"X-Forwarded-For": "2001:db8:1234:5678::1"},
            ) as response:
                assert response.status == 200
            async with session.get(
                f"{base}/health",
                headers={"X-Forwarded-For": "2001:db8:1234:5678:ffff::2"},
            ) as response:
                assert response.status == 429
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_browser_presence_cors_is_narrow_and_credential_free() -> None:
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        rate_per_ip_per_min=100,
        rate_lookup_per_ip_per_min=100,
    )
    base, _rdz, runner = await _start(config)
    preflight_headers = {
        "Origin": "https://browser-peer.example",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "content-type",
    }
    peer_html = (Path(__file__).resolve().parents[1] / "src/one_link/web/peer.html").read_text(
        encoding="utf-8"
    )
    builder = peer_html[
        peer_html.index("async function _buildSignedRegister") : peer_html.index(
            "function _normalizeRdzUrl"
        )
    ]
    signing_object = builder[builder.index("const signing = {") : builder.index("const canonical")]
    assert "capabilities: capabilities.slice()" in signing_object
    assert "transport_caps:" not in signing_object

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from one_link.rendezvous_proto import sign_register

    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes_raw()
    browser_capabilities = [
        "browser_peer",
        "manual_signal_v1",
        "webrtc_v1",
        "webtransport_v1",
    ]
    browser_wire = sign_register(
        private_key=signing_key,
        pubkey=public_key,
        ttl_s=300,
        advertised_endpoints=[],
        nat_type="unknown",
        capabilities=browser_capabilities,
    ).to_wire()
    assert set(browser_wire) == {
        "v",
        "type",
        "pubkey_b64",
        "timestamp_ms",
        "ttl_s",
        "advertised_endpoints",
        "nat_type",
        "capabilities",
        "signature",
    }
    try:
        async with aiohttp.ClientSession() as session:
            async with session.options(
                f"{base}/api/v1/register", headers=preflight_headers
            ) as response:
                assert response.status == 204
                assert response.headers["Access-Control-Allow-Origin"] == "*"
                assert response.headers["Access-Control-Allow-Methods"] == "POST"
                assert response.headers["Access-Control-Allow-Headers"] == "Content-Type"
                assert "Access-Control-Allow-Credentials" not in response.headers

            async with session.post(
                f"{base}/api/v1/register",
                headers={"Origin": "https://browser-peer.example"},
                json=browser_wire,
            ) as response:
                assert response.status == 200, await response.text()
                assert response.headers["Access-Control-Allow-Origin"] == "*"

            async with session.get(
                f"{base}/api/v1/lookup/{_b64(public_key)}",
                headers={"Origin": "https://browser-peer.example"},
            ) as response:
                assert response.status == 200, await response.text()
                assert response.headers["Access-Control-Allow-Origin"] == "*"
                lookup = LookupAck.from_wire(await response.json())
                assert lookup.capabilities == browser_capabilities

            async with session.post(
                f"{base}/api/v1/register",
                headers={"Origin": "https://browser-peer.example"},
                json={},
            ) as response:
                assert response.status == 400
                assert response.headers["Access-Control-Allow-Origin"] == "*"

            async with session.post(
                f"{base}/api/v1/register",
                headers={
                    "Origin": "https://browser-peer.example",
                    "Content-Type": "application/json",
                },
                data=b"{",
            ) as response:
                assert response.status == 400
                assert response.headers["Access-Control-Allow-Origin"] == "*"

            async with session.post(
                f"{base}/api/v1/register",
                headers={
                    "Origin": "https://browser-peer.example",
                    "Content-Type": "application/json",
                },
                data=b"x" * (MAX_REQUEST_BYTES + 1),
            ) as response:
                assert response.status == 413
                assert response.headers["Access-Control-Allow-Origin"] == "*"

            async with session.get(
                f"{base}/api/v1/lookup/{_b64(b'm' * 32)}",
                headers={"Origin": "https://browser-peer.example"},
            ) as response:
                assert response.status == 404
                assert response.headers["Access-Control-Allow-Origin"] == "*"

            async with session.options(f"{base}/metrics", headers=preflight_headers) as response:
                assert response.status == 405
                assert "Access-Control-Allow-Origin" not in response.headers

            for private_path in ("/health", "/metrics"):
                async with session.get(
                    base + private_path,
                    headers={"Origin": "https://browser-peer.example"},
                ) as response:
                    assert response.status == 200
                    assert "Access-Control-Allow-Origin" not in response.headers

            async with session.options(
                f"{base}/api/v1/register",
                headers={
                    **preflight_headers,
                    "Access-Control-Request-Headers": "authorization",
                },
            ) as response:
                assert response.status == 403
                assert "Access-Control-Allow-Origin" not in response.headers
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_blinded_lookup_has_same_response_cap_as_v1() -> None:
    config = ServerConfig(
        host="127.0.0.1",
        port=0,
        rate_per_ip_per_min=100,
        rate_lookup_per_ip_per_min=100,
    )
    base, rdz, runner = await _start(config)
    pubkey = b"p" * 32
    rdz.registry.upsert(
        Registration(
            pubkey=pubkey,
            observed_endpoint=Endpoint("203.0.113.9", 50_000),
            advertised_endpoints=[
                Endpoint(f"10.0.0.{index}", 40_000 + index) for index in range(8)
            ],
            nat_type="unknown",
            capabilities=[f"cap-{index}" for index in range(24)],
            registered_at_ms=0,
            expires_at_ms=rendezvous_server.now_ms() + 60_000,
        )
    )
    token = rdz_blind.derive_blinded_token(
        peer_pub=pubkey,
        epoch_id=rdz_blind.current_epoch_id(),
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{base}/api/v2/lookup_token/{_b64(token)}") as response:
                assert response.status == 200
                ack = LookupAck.from_wire(await response.json())
        assert len(ack.advertised_endpoints) == 3
        assert len(ack.capabilities) == 16
    finally:
        await runner.cleanup()


def test_refresh_retires_historical_blinded_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = rendezvous_server.Registry(max_entries=10)
    pubkey = b"k" * 32
    registration = Registration(
        pubkey=pubkey,
        observed_endpoint=Endpoint("203.0.113.1", 50_000),
        advertised_endpoints=[],
        nat_type="unknown",
        capabilities=[],
        registered_at_ms=0,
        expires_at_ms=60_000,
    )
    monkeypatch.setattr(rdz_blind, "current_epoch_id", lambda: 100)
    registry.upsert(registration)
    historical = rdz_blind.derive_blinded_token(peer_pub=pubkey, epoch_id=100)
    assert registry.get_by_token(historical) is registration

    monkeypatch.setattr(rdz_blind, "current_epoch_id", lambda: 200)
    registry.upsert(registration)
    assert registry.get_by_token(historical) is None
    assert len(registry._token_index) == 3


def test_registry_expiry_heap_preserves_eviction_order_and_stays_bounded() -> None:
    registry = rendezvous_server.Registry(max_entries=3)

    def registration(marker: int, expires_at_ms: int) -> Registration:
        return Registration(
            pubkey=bytes([marker]) * 32,
            observed_endpoint=Endpoint("203.0.113.1", 50_000),
            advertised_endpoints=[],
            nat_type="unknown",
            capabilities=[],
            registered_at_ms=0,
            expires_at_ms=expires_at_ms,
        )

    registry.upsert(registration(1, 300))
    registry.upsert(registration(2, 100))
    registry.upsert(registration(3, 200))
    # Refreshing key 2 leaves a stale 100-ms heap record. Full-capacity insert
    # must ignore it and evict key 3, the earliest *current* registration.
    registry.upsert(registration(2, 400))
    registry.upsert(registration(4, 500))
    assert registry.get(bytes([2]) * 32) is not None
    assert registry.get(bytes([3]) * 32) is None

    for expires in range(401, 1_401):
        registry.upsert(registration(2, expires))
    assert len(registry._expiry_heap) <= max(64, 4 * len(registry))

    assert registry.evict_expired(350) == 1
    assert registry.get(bytes([1]) * 32) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/relay/listen",
        f"/api/v1/relay/connect/{_b64(b'd' * 32)}",
    ],
)
async def test_browser_origin_cannot_open_relay_websocket(path: str) -> None:
    base, rdz, runner = await _start(ServerConfig(host="127.0.0.1", port=0, enable_relay=True))
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(aiohttp.WSServerHandshakeError) as raised:
                await session.ws_connect(
                    base + path,
                    headers={"Origin": "https://attacker.example"},
                )
            assert raised.value.status == 403
        assert not rdz._relay_listeners
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_relay_websocket_enables_heartbeat_and_disables_compression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, object]] = []
    real_response = aiohttp.web.WebSocketResponse

    def observed_response(*args: object, **kwargs: object) -> aiohttp.web.WebSocketResponse:
        captured.append(dict(kwargs))
        return real_response(*args, **kwargs)

    monkeypatch.setattr(rendezvous_server.web, "WebSocketResponse", observed_response)
    base, _rdz, runner = await _start(ServerConfig(host="127.0.0.1", port=0, enable_relay=True))
    try:
        async with aiohttp.ClientSession() as session:
            websocket = await session.ws_connect(f"{base}/api/v1/relay/listen")
            await websocket.close()
        assert captured
        assert captured[0]["heartbeat"] == 30.0
        assert captured[0]["compress"] is False
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_listener_closes_on_unexpected_text_after_authentication() -> None:
    base, rdz, runner = await _start(
        ServerConfig(
            host="127.0.0.1",
            port=0,
            enable_relay=True,
            rate_per_ip_per_min=100,
        )
    )
    # Import locally so the production server cannot accidentally acquire a
    # test-only identity dependency through this module.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    pubkey = signing_key.public_key().public_bytes_raw()
    auth = sign_listen_auth(private_key=signing_key, pubkey=pubkey)
    try:
        async with aiohttp.ClientSession() as session:
            websocket = await session.ws_connect(f"{base}/api/v1/relay/listen")
            await websocket.send_json(auth.to_wire())
            for _ in range(100):
                if pubkey in rdz._relay_listeners:
                    break
                await asyncio.sleep(0.01)
            assert pubkey in rdz._relay_listeners
            await websocket.send_str("unexpected-control-flood")
            message = await websocket.receive(timeout=2.0)
            assert message.type in {
                aiohttp.WSMsgType.CLOSE,
                aiohttp.WSMsgType.CLOSED,
                aiohttp.WSMsgType.ERROR,
            }
            assert websocket.close_code == 1003
    finally:
        await runner.cleanup()
