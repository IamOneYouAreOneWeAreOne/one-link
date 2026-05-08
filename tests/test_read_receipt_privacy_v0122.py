"""v0.12.2 — Read-receipt privacy toggles.

The READ_MARKER wire kind, daemon broadcast, state.peer_read_markers
table, and the ✓ / ✓✓ message render were all in the codebase
already (since v0.7.6). What was missing for "every major company
parity" was the privacy controls:

  - send_read_receipts (default true) — when off, the daemon's
    send_read_marker() short-circuits before dialing the peer, so
    peers never learn what you've read.
  - display_read_receipts (default true) — when off, peers' READ_MARKER
    events are ignored at render time; outbound messages always
    show ✓ regardless of whether peers have read them.

Plus a UX polish: the ✓✓ tooltip now reads "Read at HH:MM" using
the receive timestamp captured locally when the WS event arrived.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="rcpt-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── settings defaults + roundtrip ────────────────────────────

@pytest.mark.asyncio
async def test_default_send_read_receipts_is_true(http):
    client, _, _, token = http
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["send_read_receipts"] is True


@pytest.mark.asyncio
async def test_default_display_read_receipts_is_true(http):
    client, _, _, token = http
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["display_read_receipts"] is True


@pytest.mark.asyncio
async def test_send_read_receipts_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"send_read_receipts": False})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["send_read_receipts"] is False


@pytest.mark.asyncio
async def test_display_read_receipts_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"display_read_receipts": False})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["display_read_receipts"] is False


@pytest.mark.asyncio
async def test_two_toggles_are_independent(http):
    """The classic privacy pattern: 'don't tell others what I read,
    but DO tell me what they read'. Send=False + Display=True must
    be expressible without coupling."""
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token), json={
        "send_read_receipts": False,
        "display_read_receipts": True,
    })
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["send_read_receipts"] is False
    assert j["display_read_receipts"] is True


# ───────── daemon honors send_read_receipts ─────────────────────────

@pytest.mark.asyncio
async def test_send_read_marker_short_circuits_when_off(http):
    """When send_read_receipts is off, send_read_marker must NOT
    dial the peer. Pin via the {skipped:'privacy'} response shape."""
    client, daemon, state, token = http
    state.set_setting("send_read_receipts", "false")

    # Build a fake peer object compatible with send_read_marker.
    class _FakePeer:
        short_id = "x"
        ed_pub_hex = "00" * 32
        address = "127.0.0.1"
        port = 9999
        fingerprint = "aa" * 32

    result = await daemon.send_read_marker(_FakePeer(), up_to_ts_ms=999)
    assert result.get("skipped") == "privacy"
    assert result.get("sent") is None


@pytest.mark.asyncio
async def test_send_read_marker_default_attempts_send(http):
    """Default-on must NOT short-circuit. We expect either a
    successful 'sent' field or an error from the dial — both
    indicate the gate let the request through."""
    client, daemon, _, token = http

    class _FakePeer:
        short_id = "x"
        ed_pub_hex = "00" * 32
        address = "127.0.0.1"
        port = 9999
        fingerprint = "aa" * 32

    result = await daemon.send_read_marker(_FakePeer(), up_to_ts_ms=999)
    assert result.get("skipped") != "privacy"
    # The fake peer can't actually be dialed; the result shape will
    # carry an error, but importantly NOT skipped='privacy'.


# ───────── UI surface ───────────────────────────────────────────────

def test_privacy_pane_has_send_toggle(index_html: str):
    assert 'id="set-send-receipts"' in index_html


def test_privacy_pane_has_display_toggle(index_html: str):
    assert 'id="set-display-receipts"' in index_html


def test_settings_save_payload_includes_both_toggles(index_html: str):
    idx = index_html.find('"#settings-save").onclick')
    snippet = index_html[idx:idx + 5000]
    assert "send_read_receipts:" in snippet
    assert "display_read_receipts:" in snippet


def test_runtime_cache_includes_display_flag(index_html: str):
    """display_read_receipts is read from state.runtimeSettings on
    every render, so it MUST land in that cache during
    loadAndApplySettings + the settings-open handler."""
    idx = index_html.find("async function loadAndApplySettings()")
    snippet = index_html[idx:idx + 1500]
    assert "display_read_receipts:" in snippet


def test_render_gates_on_display_setting(index_html: str):
    """The ✓✓ render must check runtimeSettings.display_read_receipts
    or the toggle is decorative."""
    idx = index_html.find("read-receipt checkmark on outbound")
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "display_read_receipts" in snippet
    # Specifically: when off, we should always render ✓ (not ✓✓).
    assert "displayReceipts" in snippet


def test_render_uses_received_at_for_tooltip(index_html: str):
    """Pin the "Read at HH:MM" tooltip — without received_at the
    tooltip falls back to "Read" which is fine but worse UX."""
    idx = index_html.find("read-receipt checkmark on outbound")
    snippet = index_html[idx:idx + 1500]
    assert "readMarkerReceivedAt" in snippet
    assert "Read at" in snippet


def test_ws_handler_records_received_at(index_html: str):
    """Inbound read_marker WS event must capture Date.now() so the
    tooltip can render the timestamp."""
    idx = index_html.find('m.type === "read_marker"')
    snippet = index_html[idx:idx + 1000]
    assert "readMarkerReceivedAt" in snippet
    assert "Date.now()" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
