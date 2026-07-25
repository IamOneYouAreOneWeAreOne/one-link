"""Regression coverage for transport/discovery exception boundaries.

These paths run at third-party network-library boundaries where best-effort
cleanup is appropriate, but send and route-state failures must never look like
success or disappear without operator-visible evidence.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
from types import ModuleType, SimpleNamespace

import pytest

from one_link import discovery, lan_discovery, peer_https
from one_link.peer_rtc import BrowserPeer, BrowserPeerManager


class _FailingDataChannel:
    readyState = "open"

    def send(self, _data: str) -> None:
        raise RuntimeError("data-channel queue is closed")


def _rtc_peer() -> BrowserPeer:
    peer = BrowserPeer(
        fingerprint="sha256:" + "ab" * 32,
        pubkey_bytes=b"p" * 32,
    )
    peer.control_dc = _FailingDataChannel()
    return peer


def test_data_channel_send_reports_queue_failure(caplog: pytest.LogCaptureFixture) -> None:
    manager = BrowserPeerManager(SimpleNamespace())
    peer = _rtc_peer()

    with caplog.at_level(logging.WARNING, logger="one_link.peer_rtc"):
        queued = manager.send_dc(peer, "control", {"v": 1, "t": "ping"})

    assert queued is False
    assert "send on control failed" in caplog.text


def test_unsent_attestation_nonce_is_rolled_back(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from one_link import handshake_attestation

    monkeypatch.setattr(
        handshake_attestation,
        "fresh_challenge_for_peer",
        lambda: b"n" * 32,
    )
    manager = BrowserPeerManager(SimpleNamespace())
    peer = _rtc_peer()

    with caplog.at_level(logging.WARNING, logger="one_link.peer_rtc"):
        started = manager.init_attestation(peer)

    assert started is False
    assert peer.attestation_challenge is None
    assert peer.attestation_challenge_dc_id is None
    assert "attestation challenge was not queued" in caplog.text


@pytest.mark.asyncio
async def test_mdns_resolver_future_exception_is_observable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    listener = discovery._AsyncListener(
        registry=discovery.Registry(),
        self_short_id="self0001",
        zc=SimpleNamespace(),
        loop=asyncio.get_running_loop(),
    )

    async def _broken_resolve(_type: str, _name: str) -> None:
        raise RuntimeError("resolver exploded")

    logged = asyncio.Event()

    class _LogSignal(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if "resolve failed for peer._onelink._tcp.local." in record.getMessage():
                logged.set()

    logger = logging.getLogger("one_link.discovery")
    signal = _LogSignal()
    logger.addHandler(signal)
    monkeypatch.setattr(listener, "_resolve", _broken_resolve)
    try:
        with caplog.at_level(logging.WARNING, logger="one_link.discovery"):
            listener._schedule_resolve("_onelink._tcp.local.", "peer._onelink._tcp.local.")
            # The resolver callback crosses a thread-safe Future boundary.
            # Synchronize on the emitted diagnostic instead of using a fixed
            # sleep, which could expire first on loaded CI runners.
            await asyncio.wait_for(logged.wait(), timeout=1.0)
    finally:
        logger.removeHandler(signal)

    assert "resolve failed for peer._onelink._tcp.local." in caplog.text
    assert "resolver exploded" in caplog.text


@pytest.mark.asyncio
async def test_mdns_listener_stop_cancels_and_drains_pending_resolvers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    listener = discovery._AsyncListener(
        registry=discovery.Registry(),
        self_short_id="self0001",
        zc=SimpleNamespace(),
        loop=asyncio.get_running_loop(),
    )
    entered = asyncio.Event()
    cancelled = asyncio.Event()

    async def _pending_resolve(_type: str, _name: str) -> None:
        entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    monkeypatch.setattr(listener, "_resolve", _pending_resolve)
    listener._schedule_resolve(
        "_onelink._tcp.local.", "peer._onelink._tcp.local."
    )
    await asyncio.wait_for(entered.wait(), timeout=1.0)

    await asyncio.wait_for(listener.stop(), timeout=1.0)

    assert cancelled.is_set()
    assert listener._resolve_futures == set()


@pytest.mark.asyncio
async def test_mdns_shutdown_logs_stale_advertisement_risk_and_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []

    class _Browser:
        async def async_cancel(self) -> None:
            calls.append("cancel")
            raise RuntimeError("cancel failed")

    class _Zeroconf:
        async def async_unregister_service(self, _info: object) -> None:
            calls.append("unregister")
            raise RuntimeError("goodbye failed")

        async def async_close(self) -> None:
            calls.append("close")
            raise RuntimeError("close failed")

    instance = discovery.Discovery("self0001", "host", 7117, "11" * 32)
    instance._browser = _Browser()  # type: ignore[assignment]
    instance._zc = _Zeroconf()  # type: ignore[assignment]
    instance._info = object()  # type: ignore[assignment]

    with caplog.at_level(logging.DEBUG, logger="one_link.discovery"):
        await instance.stop()

    assert calls == ["cancel", "unregister", "close"]
    assert "advertisement may remain until TTL" in caplog.text
    assert instance._browser is None
    assert instance._zc is None
    assert instance._info is None


@pytest.mark.asyncio
async def test_mdns_txt_update_failure_is_not_silent(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from zeroconf import asyncio as zeroconf_asyncio

    class _Info:
        def __init__(self, **_kwargs: object) -> None:
            pass

    class _Zeroconf:
        zeroconf = object()

        async def async_update_service(self, _info: object) -> None:
            raise RuntimeError("multicast interface disappeared")

    monkeypatch.setattr(zeroconf_asyncio, "AsyncServiceInfo", _Info)
    monkeypatch.setattr(discovery, "_best_local_ipv4", lambda: "192.168.1.10")
    instance = discovery.Discovery("self0001", "host", 7117, "11" * 32)
    instance._zc = _Zeroconf()  # type: ignore[assignment]
    instance._info = object()  # type: ignore[assignment]

    with caplog.at_level(logging.WARNING, logger="one_link.discovery"):
        await instance.update_rendezvous_urls(["https://relay.example"])

    assert instance.rendezvous_urls == ["https://relay.example"]
    assert "peers may retain stale routes" in caplog.text
    assert "multicast interface disappeared" in caplog.text


@pytest.mark.asyncio
async def test_mdns_scan_fails_closed_when_event_enum_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Never treat an unknown/Removed callback as an Added device."""

    root_module = ModuleType("zeroconf")
    asyncio_module = ModuleType("zeroconf.asyncio")
    browser_starts: list[str] = []

    class _AsyncZeroconf:
        zeroconf = object()

    class _AsyncServiceBrowser:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            browser_starts.append("started")

    class _AsyncServiceInfo:
        pass

    asyncio_module.AsyncZeroconf = _AsyncZeroconf  # type: ignore[attr-defined]
    asyncio_module.AsyncServiceBrowser = _AsyncServiceBrowser  # type: ignore[attr-defined]
    asyncio_module.AsyncServiceInfo = _AsyncServiceInfo  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "zeroconf", root_module)
    monkeypatch.setitem(sys.modules, "zeroconf.asyncio", asyncio_module)

    with caplog.at_level(logging.WARNING, logger="one_link.lan_discovery"):
        devices = await lan_discovery.scan_mdns_browse_all(timeout_s=0.0)

    assert devices == []
    assert browser_starts == []
    assert "zeroconf unavailable" in caplog.text


def test_local_ip_self_filter_only_suppresses_network_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _programming_error(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("unexpected resolver contract violation")

    monkeypatch.setattr(socket, "getaddrinfo", _programming_error)
    with pytest.raises(RuntimeError, match="resolver contract violation"):
        lan_discovery._local_ips()


def test_default_gateway_probe_failure_is_diagnosable(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def _unavailable(*_args: object, **_kwargs: object) -> list[str]:
        raise ValueError("trusted route utility unavailable")

    monkeypatch.setattr(lan_discovery, "resolve_argv", _unavailable)
    with caplog.at_level(logging.DEBUG, logger="one_link.lan_discovery"):
        assert lan_discovery._default_gateway() == ""

    assert "windows_default_gateway" in caplog.text
    assert "error_type=ValueError" in caplog.text
    assert "trusted route utility unavailable" not in caplog.text


def test_https_address_detection_only_suppresses_network_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _BrokenSocket:
        def connect(self, _target: object) -> None:
            raise RuntimeError("unexpected socket contract violation")

        def close(self) -> None:
            pass

    monkeypatch.setattr(peer_https.socket, "socket", lambda *_args: _BrokenSocket())
    with pytest.raises(RuntimeError, match="socket contract violation"):
        peer_https._detect_lan_addresses()


def test_unexpected_root_ca_loader_failure_does_not_replace_trust_anchor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    root_cert = peer_https.root_ca_path(tmp_path)
    root_key = peer_https.root_ca_key_path(tmp_path)
    root_cert.parent.mkdir(parents=True)
    root_cert.write_bytes(b"existing root certificate")
    root_key.write_bytes(b"existing root private key")
    minted: list[bool] = []

    def _unexpected_loader_failure(_base) -> object:
        raise RuntimeError("unexpected crypto provider failure")

    def _record_mint(*_args: object, **_kwargs: object) -> object:
        minted.append(True)
        raise AssertionError("trust anchor must not be replaced")

    monkeypatch.setattr(peer_https, "_load_root_ca", _unexpected_loader_failure)
    monkeypatch.setattr(peer_https, "_mint_root_ca", _record_mint)

    with pytest.raises(RuntimeError, match="crypto provider failure"):
        peer_https.generate_self_signed(tmp_path)

    assert minted == []
    assert root_cert.read_bytes() == b"existing root certificate"
    assert root_key.read_bytes() == b"existing root private key"


def test_transient_root_ca_read_failure_does_not_replace_trust_anchor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    root_cert = peer_https.root_ca_path(tmp_path)
    root_key = peer_https.root_ca_key_path(tmp_path)
    root_cert.parent.mkdir(parents=True)
    root_cert.write_bytes(b"existing root certificate")
    root_key.write_bytes(b"existing root private key")
    minted: list[bool] = []

    def _transient_read_failure(_base) -> object:
        raise PermissionError("certificate store is temporarily locked")

    def _record_mint(*_args: object, **_kwargs: object) -> object:
        minted.append(True)
        raise AssertionError("trust anchor must not be replaced")

    monkeypatch.setattr(peer_https, "_load_root_ca", _transient_read_failure)
    monkeypatch.setattr(peer_https, "_mint_root_ca", _record_mint)

    with pytest.raises(PermissionError, match="temporarily locked"):
        peer_https.generate_self_signed(tmp_path)

    assert minted == []
    assert root_cert.read_bytes() == b"existing root certificate"
    assert root_key.read_bytes() == b"existing root private key"
