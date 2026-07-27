"""Live sovereignty transitions must converge before they persist."""

from __future__ import annotations

import asyncio
import json
import threading
from types import SimpleNamespace

import pytest

from one_link.daemon import Daemon, SovereigntyTransitionError
from one_link.server import UIServer


class _State:
    def __init__(self, preset: str = "just_works") -> None:
        self.settings: dict[str, str] = {"sovereignty_preset": preset}
        self.urls = ["https://rendezvous.example"]
        self.fail_next_preset_write = False

    def get_setting(self, key: str, default=None):
        return self.settings.get(key, default)

    def set_setting(self, key: str, value: str) -> None:
        self.settings[key] = value
        if key == "sovereignty_preset" and self.fail_next_preset_write:
            self.fail_next_preset_write = False
            raise OSError("simulated durable write failure")

    def delete_setting(self, key: str) -> None:
        self.settings.pop(key, None)

    def get_rendezvous_urls(self) -> list[str]:
        return list(self.urls)


class _Discovery:
    def __init__(self, events: list[str], *, running: bool) -> None:
        self.events = events
        self.is_running = running
        self.registry = SimpleNamespace(peers={"stale": object()})
        self.fail_stop_once = False

    async def start(self) -> None:
        self.events.append("mdns:start")
        self.is_running = True

    async def stop(self) -> None:
        self.events.append("mdns:stop")
        self.is_running = False
        if self.fail_stop_once:
            self.fail_stop_once = False
            raise OSError("simulated mDNS stop failure")

    async def update_rendezvous_urls(self, urls: list[str]) -> None:
        self.events.append(f"mdns:rdz:{','.join(urls)}")


class _Rendezvous:
    def __init__(self, events: list[str], label: str = "new") -> None:
        self.events = events
        self.label = label
        self.observed_self = {}

    async def start(self) -> None:
        self.events.append(f"rendezvous:{self.label}:start")

    async def stop(self) -> None:
        self.events.append(f"rendezvous:{self.label}:stop")


class _Relay:
    def __init__(self, events: list[str], label: str = "new", **_kwargs) -> None:
        self.events = events
        self.label = label

    async def start(self) -> None:
        self.events.append(f"relay:{self.label}:start")

    async def stop(self) -> None:
        self.events.append(f"relay:{self.label}:stop")


async def _idle_update_loop() -> None:
    await asyncio.Event().wait()


def _daemon(
    state: _State,
    discovery: _Discovery,
    events: list[str],
) -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon.state = state
    daemon.discovery = discovery
    daemon.rendezvous = None
    daemon._relay_listener_clients = []
    daemon._rendezvous_peer_port = 7117
    daemon._sovereignty_transition_target = None
    daemon._sovereignty_transition_lock = asyncio.Lock()
    daemon._rendezvous_lifecycle_lock = asyncio.Lock()
    daemon._update_check_network_lock = asyncio.Lock()
    daemon._lan_discovery_network_lock = asyncio.Lock()
    daemon._update_check_task = None
    daemon._update_check_loop = _idle_update_loop
    daemon.me = SimpleNamespace(
        private=object(),
        public_bytes=b"p" * 32,
        fingerprint="aa" * 32,
        short_id="aaaaaaaa",
        hostname="test-device",
    )
    daemon.ui_server = None
    daemon._handle_relay_inbound_session = _idle_update_loop
    daemon._events = events
    daemon._outbound_log = []
    daemon._outbound_log_max = 200
    return daemon


def _patch_rendezvous_constructors(monkeypatch, events: list[str]) -> None:
    from one_link import relay_client, rendezvous_client

    monkeypatch.setattr(
        rendezvous_client,
        "discover_local_endpoints",
        lambda **_kwargs: [],
    )
    monkeypatch.setattr(
        rendezvous_client,
        "RendezvousClient",
        lambda **_kwargs: _Rendezvous(events),
    )
    monkeypatch.setattr(
        relay_client,
        "RelayListenerClient",
        lambda **kwargs: _Relay(events, **kwargs),
    )


@pytest.mark.asyncio
async def test_just_works_to_quiet_stops_public_runtime_before_persist(
    monkeypatch,
) -> None:
    events: list[str] = []
    state = _State("just_works")
    # Stale explicit ON values must not loosen Quiet's ceiling.
    state.settings.update({
        "update_check_enabled": "true",
        "rendezvous_enabled": "true",
        "turn_relay_enabled": "true",
    })
    discovery = _Discovery(events, running=True)
    daemon = _daemon(state, discovery, events)
    daemon.rendezvous = _Rendezvous(events, "old")
    daemon._relay_listener_clients = [_Relay(events, "old")]
    daemon._update_check_task = asyncio.create_task(_idle_update_loop())

    result = await daemon.apply_sovereignty_preset("quiet")

    assert state.get_setting("sovereignty_preset") == "quiet"
    assert daemon._update_check_task is None
    assert daemon.rendezvous is None
    assert daemon._relay_listener_clients == []
    assert discovery.is_running is True  # Quiet remains LAN-only, with mDNS.
    assert "rendezvous:old:stop" in events
    assert "relay:old:stop" in events
    assert "mdns:stop" not in events
    assert result["runtime"] == {
        "update_check_task_active": False,
        "mdns_active": True,
        "rendezvous_active": False,
        "relay_listener_count": 0,
        "relay_routing": {
            "modes": [],
            "pairwise_blinded_active": False,
            "legacy_identity_route_active": False,
            "destination_identity_exposure": "relay_not_registered",
            "identity_bearing_channel_first_flight": "relay_not_registered",
            "legacy_migration_override_enabled": False,
        },
    }
    status = json.loads(
        (await UIServer(daemon).api_sovereignty_status(
            SimpleNamespace(query={})
        )).text
    )
    assert status["features"]["update_check"] == {
        "enabled": False,
        "source": "preset",
    }
    assert status["features"]["rendezvous"]["enabled"] is False
    assert status["features"]["rendezvous"]["source"] == "preset"
    assert status["features"]["turn_relay_preset"] == {
        "enabled": False,
        "source": "preset",
    }


@pytest.mark.asyncio
async def test_off_grid_stops_mdns_and_clears_stale_registry() -> None:
    events: list[str] = []
    state = _State("quiet")
    discovery = _Discovery(events, running=True)
    daemon = _daemon(state, discovery, events)

    result = await daemon.apply_sovereignty_preset("off_grid")

    assert state.get_setting("sovereignty_preset") == "off_grid"
    assert discovery.is_running is False
    assert discovery.registry.peers == {}
    assert events.count("mdns:stop") == 1
    assert result["runtime"]["mdns_active"] is False


@pytest.mark.asyncio
async def test_off_grid_to_just_works_starts_newly_permitted_runtime(
    monkeypatch,
) -> None:
    events: list[str] = []
    state = _State("off_grid")
    discovery = _Discovery(events, running=False)
    daemon = _daemon(state, discovery, events)
    _patch_rendezvous_constructors(monkeypatch, events)

    result = await daemon.apply_sovereignty_preset("just_works")
    try:
        assert state.get_setting("sovereignty_preset") == "just_works"
        assert "mdns:start" in events
        assert "rendezvous:new:start" in events
        assert "relay:new:start" in events
        assert result["runtime"]["update_check_task_active"] is True
        assert result["runtime"]["mdns_active"] is True
        assert result["runtime"]["rendezvous_active"] is True
    finally:
        await daemon._set_update_check_runtime(False)
        await daemon.update_rendezvous_urls([])


@pytest.mark.asyncio
async def test_persist_failure_restores_prior_setting_and_runtime(
    monkeypatch,
) -> None:
    events: list[str] = []
    state = _State("just_works")
    state.fail_next_preset_write = True
    discovery = _Discovery(events, running=True)
    daemon = _daemon(state, discovery, events)
    _patch_rendezvous_constructors(monkeypatch, events)
    daemon.rendezvous = _Rendezvous(events, "old")
    daemon._relay_listener_clients = [_Relay(events, "old")]
    daemon._update_check_task = asyncio.create_task(_idle_update_loop())

    with pytest.raises(SovereigntyTransitionError, match="durable write failure"):
        await daemon.apply_sovereignty_preset("off_grid")

    try:
        assert state.get_setting("sovereignty_preset") == "just_works"
        assert discovery.is_running is True
        assert daemon.rendezvous is not None
        assert daemon._relay_listener_clients
        assert daemon._update_check_task is not None
        assert not daemon._update_check_task.done()
        assert "mdns:stop" in events and "mdns:start" in events
    finally:
        await daemon._set_update_check_runtime(False)
        await daemon.update_rendezvous_urls([])


@pytest.mark.asyncio
async def test_runtime_failure_rolls_back_and_handler_returns_non_2xx(
    monkeypatch,
) -> None:
    events: list[str] = []
    state = _State("just_works")
    discovery = _Discovery(events, running=True)
    discovery.fail_stop_once = True
    daemon = _daemon(state, discovery, events)
    _patch_rendezvous_constructors(monkeypatch, events)
    daemon.rendezvous = _Rendezvous(events, "old")
    daemon._relay_listener_clients = [_Relay(events, "old")]
    daemon._update_check_task = asyncio.create_task(_idle_update_loop())

    class _Request:
        async def json(self):
            return {"name": "off_grid"}

    response = await UIServer(daemon).api_sovereignty_preset_set(_Request())
    try:
        assert response.status == 503
        assert json.loads(response.text)["error"] == (
            "live sovereignty transition failed"
        )
        assert state.get_setting("sovereignty_preset") == "just_works"
        assert discovery.is_running is True
        assert daemon.rendezvous is not None
        assert daemon._update_check_task is not None
    finally:
        await daemon._set_update_check_runtime(False)
        await daemon.update_rendezvous_urls([])


@pytest.mark.asyncio
async def test_discover_all_off_grid_denies_without_scanner_call(
    monkeypatch,
) -> None:
    from one_link import lan_discovery

    called = 0

    async def _scan(**_kwargs):
        nonlocal called
        called += 1
        return []

    monkeypatch.setattr(lan_discovery, "full_scan", _scan)
    state = _State("off_grid")
    daemon = SimpleNamespace(state=state, discovery=None)
    response = await UIServer(daemon).api_discover_all(
        SimpleNamespace(query={})
    )
    assert response.status == 403
    assert json.loads(response.text)["code"] == "lan_discovery_disabled"
    assert called == 0


@pytest.mark.asyncio
async def test_off_grid_transition_drains_inflight_lan_scan(monkeypatch) -> None:
    from one_link import lan_discovery

    events: list[str] = []
    entered = asyncio.Event()
    release = asyncio.Event()

    async def _scan(**_kwargs):
        events.append("scan:entered")
        entered.set()
        await release.wait()
        events.append("scan:finished")
        return []

    monkeypatch.setattr(lan_discovery, "full_scan", _scan)
    monkeypatch.setattr(lan_discovery, "load_recent_cached_devices", lambda: [])
    monkeypatch.setattr(
        lan_discovery,
        "assess_network_health",
        lambda _devices: SimpleNamespace(
            ap_isolation_suspected=False,
            captive_portal_suspected=False,
            ipv6_only_suspected=False,
            has_default_gateway=False,
            gateway_ip=None,
            reasons=[],
        ),
    )
    state = _State("just_works")
    discovery = _Discovery(events, running=True)
    daemon = _daemon(state, discovery, events)
    server = UIServer(daemon)

    scan_task = asyncio.create_task(
        server.api_discover_all(SimpleNamespace(query={}))
    )
    await asyncio.wait_for(entered.wait(), timeout=1.0)
    transition = asyncio.create_task(
        daemon.apply_sovereignty_preset("off_grid")
    )
    await asyncio.sleep(0)
    assert not transition.done()
    release.set()
    scan_response = await scan_task
    await transition

    assert scan_response.status == 200
    assert events.index("scan:finished") < events.index("mdns:stop")
    denied = await server.api_discover_all(SimpleNamespace(query={}))
    assert denied.status == 403


@pytest.mark.asyncio
async def test_quiet_transition_waits_for_update_worker_to_really_return(
    monkeypatch,
) -> None:
    from one_link import update_check

    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()

    # Stub the function the handler actually calls. It moved from fetch_latest
    # to check_for_update, which tries the tagged channel and falls back to the
    # rolling prerelease -- /releases/latest excludes prereleases, so the old
    # entry point could never see the channel users download from. The stub
    # takes no required arguments because the handler passes none.
    def _fetch(*_args, **_kwargs):
        entered.set()
        if not release.wait(timeout=5.0):
            raise TimeoutError("test did not release update worker")
        events.append("update:returned")
        from one_link import __version__ as local_version

        return update_check.CheckResult(
            status="same",
            local_version=local_version,
            latest_version=local_version,
        )

    monkeypatch.setattr(update_check, "check_for_update", _fetch)
    state = _State("just_works")
    discovery = _Discovery(events, running=True)
    daemon = _daemon(state, discovery, events)
    server = UIServer(daemon)
    server._update_cache = None

    check_task = asyncio.create_task(
        server.api_update_check(SimpleNamespace(query={}))
    )
    assert await asyncio.to_thread(entered.wait, 1.0)
    transition = asyncio.create_task(
        daemon.apply_sovereignty_preset("quiet")
    )
    await asyncio.sleep(0)
    assert not transition.done()
    release.set()
    response = await check_task
    await transition

    assert response.status == 200
    assert events.index("update:returned") < events.index("mdns:rdz:")
    disabled = await server.api_update_check(SimpleNamespace(query={}))
    assert json.loads(disabled.text)["status"] == "disabled"
