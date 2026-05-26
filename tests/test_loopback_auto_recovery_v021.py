"""v0.21.x: same-machine browser auto-recovery.

Pre-v0.21.x, the index handler's silent stale-token recovery was
gated on `_is_loopback_bound()` — i.e. the daemon's bind config
had to be 127.0.0.1. A LAN-bound daemon (0.0.0.0) sent local
browsers to the ACCESS DENIED help page even when the request
came from the same machine.

v0.21.x adds `_request_from_loopback` so the recovery decision
looks at the request's SOURCE IP (peer IP), not the daemon's
bind. A request whose peer IP is 127.0.0.1 / ::1 came from a
process on the same machine. That process could read `ui.token`
from disk already, so trusting it for silent cookie recovery
adds no attack surface. Cross-machine requests (peer IP outside
the loopback set) stay strictly token-gated.

This file pins:
  1. `_request_from_loopback` honors the SOURCE IP including
     IPv6 (::1) and IPv4-mapped IPv6 (::ffff:127.0.0.1).
  2. `_is_local_document_navigation` returns True for loopback-
     sourced browser tabs even when the daemon is LAN-bound.
  3. Cross-machine sources stay denied (no silent recovery).
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


# ── _is_local_document_navigation upgrade ─────────────────────────


def test_local_doc_nav_true_for_loopback_source_on_lan_bound_daemon():
    """The whole point of the fix: a LAN-bound daemon (0.0.0.0)
    must still recognize same-machine browsers as local doc
    navigations so the silent-recovery path fires."""
    s = _mk_server(bind_host="0.0.0.0")
    req = _mk_request(peer_ip="127.0.0.1")
    assert s._is_local_document_navigation(req) is True


def test_local_doc_nav_false_for_lan_source_on_lan_bound_daemon():
    """Cross-machine browsers are NOT trusted for silent recovery;
    they must present a valid token like before."""
    s = _mk_server(bind_host="0.0.0.0")
    req = _mk_request(peer_ip="192.168.1.50")
    assert s._is_local_document_navigation(req) is False


def test_local_doc_nav_still_true_for_loopback_bound_legacy_path():
    """The pre-v0.21.x recovery path (loopback-bound daemon) must
    keep working unchanged. Regression guard."""
    s = _mk_server(bind_host="127.0.0.1")
    # Even without a peer IP (some test paths), bind-loopback +
    # Host header check + document accept should suffice.
    req = _mk_request(
        peer_ip=None,
        accept="text/html",
        host="127.0.0.1:7117",
    )
    assert s._is_local_document_navigation(req) is True


def test_local_doc_nav_false_when_xhr_dest():
    """Sec-Fetch-Dest=empty (XHR/fetch) is NOT a top-level
    document nav. A CSRF-bait page could send loopback-sourced
    fetches; those must still fail the document-nav check so
    we don't silently mint a cookie for them."""
    s = _mk_server(bind_host="0.0.0.0")
    req = _mk_request(peer_ip="127.0.0.1", sec_fetch_dest="empty")
    assert s._is_local_document_navigation(req) is False


# ── source-code structural pins ───────────────────────────────────


def test_request_from_loopback_helper_present(server_src):
    assert "def _request_from_loopback(" in server_src, (
        "missing _request_from_loopback helper — auth auto-recovery "
        "would fall back to bind-config-only check"
    )


def test_loopback_source_helper_covers_v4_mapped_v6(server_src):
    """Pin the dual-stack handling so a refactor can't drop it."""
    idx = server_src.find("def _request_from_loopback(")
    body = server_src[idx:idx + 1500]
    assert "::ffff:" in body, (
        "_request_from_loopback must strip the ::ffff: IPv4-mapped "
        "IPv6 prefix; dual-stack listeners surface loopback this way"
    )


def test_local_doc_nav_uses_request_source(server_src):
    """The is_local_document_navigation upgrade must consult the
    new loopback-source helper, not just the bind config."""
    idx = server_src.find("def _is_local_document_navigation(")
    body = server_src[idx:idx + 1500]
    assert "_request_from_loopback(" in body, (
        "_is_local_document_navigation must accept loopback-by-source "
        "or LAN-bound daemons send local browsers to the access-denied "
        "page instead of recovering"
    )


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
