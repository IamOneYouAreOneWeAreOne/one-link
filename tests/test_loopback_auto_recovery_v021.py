"""Loopback routing is not owner authentication.

Pre-v0.21.x, the index handler's silent stale-token recovery was
gated on `_is_loopback_bound()` — i.e. the daemon's bind config
had to be 127.0.0.1. A LAN-bound daemon (0.0.0.0) sent local
browsers to the ACCESS DENIED help page even when the request
came from the same machine.

`_request_from_loopback` identifies a network route, not an OS uid. Another
local account or sandboxed process can connect and spoof browser navigation
headers, so loopback must never mint owner/session credentials.

This file pins:
  1. `_request_from_loopback` honors the SOURCE IP including
     IPv6 (::1) and IPv4-mapped IPv6 (::ffff:127.0.0.1).
  2. No local-document helper is used as an authentication primitive.
  3. Cross-machine sources stay denied.
  4. The boot-time API call uses _bootApiGetWithRetry so a single
     auth-race failure can't fire the 'Can't reach One Link' toast.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


_SERVER = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"
)
_INDEX_HTML = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
)


@pytest.fixture(scope="module")
def server_src() -> str:
    return _SERVER.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


# ── helper-level tests ────────────────────────────────────────────


def _mk_server(bind_host: str = "0.0.0.0"):
    """Build a minimal UIServer instance for helper-level tests.
    We bypass __init__ via __new__ + sets only the attributes the
    helpers under test need. This keeps the test fast (no port
    bind, no DB warmup) and isolates the auth-helper logic."""
    from one_link.server import UIServer
    s = UIServer.__new__(UIServer)
    s.bind_host = bind_host
    s.port = 7117
    s.token = "x" * 64
    return s


def _mk_request(*, peer_ip: str | None, sec_fetch_dest: str = "document",
                accept: str = "text/html", host: str = "127.0.0.1:7117"):
    """Build a fake aiohttp Request just rich enough for the helpers.
    Uses MagicMock for the transport so .get_extra_info('peername')
    returns the configured peer IP."""
    transport = None
    if peer_ip is not None:
        transport = MagicMock()
        transport.get_extra_info.return_value = (peer_ip, 12345)
    headers = {}
    if sec_fetch_dest:
        headers["Sec-Fetch-Dest"] = sec_fetch_dest
    if accept:
        headers["Accept"] = accept
    req = SimpleNamespace(
        transport=transport,
        remote=peer_ip,
        headers=headers,
        host=host,
        query={},
        cookies={},
        method="GET",
        scheme="http",
    )
    return req


def test_request_from_loopback_recognizes_ipv4():
    s = _mk_server()
    req = _mk_request(peer_ip="127.0.0.1")
    assert s._request_from_loopback(req) is True


def test_request_from_loopback_recognizes_ipv6():
    s = _mk_server()
    req = _mk_request(peer_ip="::1")
    assert s._request_from_loopback(req) is True


def test_request_from_loopback_recognizes_v4_mapped_v6():
    """Dual-stack listeners frequently surface 127.0.0.1 as
    ::ffff:127.0.0.1. That's still the same local kernel routing
    a local-process packet, so we must treat it as loopback."""
    s = _mk_server()
    req = _mk_request(peer_ip="::ffff:127.0.0.1")
    assert s._request_from_loopback(req) is True


def test_request_from_loopback_rejects_lan_peer():
    s = _mk_server()
    req = _mk_request(peer_ip="192.168.1.50")
    assert s._request_from_loopback(req) is False


def test_request_from_loopback_rejects_empty_peer():
    s = _mk_server()
    req = _mk_request(peer_ip=None)
    assert s._request_from_loopback(req) is False


# ── source-code structural pins ───────────────────────────────────


def test_request_from_loopback_helper_present(server_src):
    assert "def _request_from_loopback(" in server_src, (
        "missing _request_from_loopback transport-policy helper"
    )


def test_loopback_source_helper_covers_v4_mapped_v6(server_src):
    """Pin the dual-stack handling so a refactor can't drop it."""
    idx = server_src.find("def _request_from_loopback(")
    body = server_src[idx:idx + 1500]
    assert "::ffff:" in body, (
        "_request_from_loopback must strip the ::ffff: IPv4-mapped "
        "IPv6 prefix; dual-stack listeners surface loopback this way"
    )


def test_loopback_navigation_is_not_an_authentication_primitive(server_src):
    assert "def _is_local_document_navigation(" not in server_src
    assert "or local_document_reopen" not in server_src
    assert "same uid context" not in server_src


# ── UI: silent boot retry ─────────────────────────────────────────


def test_boot_api_call_uses_silent_retry_helper(index_html):
    """The initial /api/me must go through _bootApiGetWithRetry so
    a single transient 401 (cookie race after daemon restart, etc.)
    can't fire the 'Can't reach One Link' toast."""
    assert "function _bootApiGetWithRetry(" in index_html, (
        "missing _bootApiGetWithRetry helper — boot is one-shot, will "
        "show offline toast on any auth race"
    )
    # The init() body must use the helper, not raw api.get for /api/me.
    idx = index_html.find("async function init() {")
    assert idx > 0
    body = index_html[idx:idx + 800]
    assert '_bootApiGetWithRetry("/api/me")' in body, (
        "init() doesn't route through the silent-retry helper"
    )


def test_boot_retry_helper_attempts_multiple_times(index_html):
    """Defense against a refactor that reduces the retry count back
    to 1 (which is the same as no retry)."""
    idx = index_html.find("function _bootApiGetWithRetry(")
    body = index_html[idx:idx + 800]
    # Default attempts >= 3 so the helper actually retries.
    assert "attempts = 3" in body or "attempts=3" in body, (
        "boot retry helper should default to >= 3 attempts"
    )
    # Backoff must wait between attempts (not just busy-loop).
    assert "setTimeout" in body, (
        "boot retry helper should sleep between attempts so a real "
        "outage isn't hammered immediately"
    )
