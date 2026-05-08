"""v0.12.3 — Typing indicators.

New ephemeral wire kind: TYPING. Carries expires_in_ms (5s default,
clamped 0–10s server-side). The daemon broadcasts a peer_typing WS
event so any open tab on the receiver renders "User is typing…"
until the deadline.

Privacy:
  - send_typing_indicators (default on) — daemon's send_typing()
    short-circuits when off; peers never learn we're composing.
  - display_typing_indicators (default on) — when off, peer_typing
    WS events still arrive but the inbound TYPING handler skips
    the broadcast so the banner never appears.

Debouncing:
  - Daemon-side: 2.5s/peer, indexed by fingerprint via
    self._last_typing_sent_to.
  - Client-side mirror: same 2.5s window via _lastTypingFiredAt
    so we don't even make the round trip on a fast typer.
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
        fingerprint=fp, short_id=fp[:8], hostname="typing-host",
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


# ───────── Settings defaults + persistence ──────────────────────────

@pytest.mark.asyncio
async def test_default_send_typing_is_true(http):
    client, _, _, token = http
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["send_typing_indicators"] is True


@pytest.mark.asyncio
async def test_default_display_typing_is_true(http):
    client, _, _, token = http
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["display_typing_indicators"] is True


@pytest.mark.asyncio
async def test_send_typing_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"send_typing_indicators": False})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["send_typing_indicators"] is False


@pytest.mark.asyncio
async def test_display_typing_persists(http):
    client, _, _, token = http
    await client.post("/api/settings", headers=_h(token),
                      json={"display_typing_indicators": False})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["display_typing_indicators"] is False


# ───────── Daemon honors send_typing_indicators ─────────────────────

@pytest.mark.asyncio
async def test_send_typing_short_circuits_when_off(http):
    client, daemon, state, token = http
    state.set_setting("send_typing_indicators", "false")

    class _FakePeer:
        short_id = "x"
        ed_pub_hex = "00" * 32
        address = "127.0.0.1"
        port = 9999
        fingerprint = "aa" * 32

    r = await daemon.send_typing(_FakePeer())
    assert r.get("skipped") == "privacy"


@pytest.mark.asyncio
async def test_send_typing_debounces(http):
    """Two sends within 2.5s must produce skipped='debounced' on
    the second call. Pin so a refactor can't accidentally remove
    the wire-flood guard."""
    client, daemon, _, token = http

    class _FakePeer:
        short_id = "y"
        ed_pub_hex = "11" * 32
        address = "127.0.0.1"
        port = 9999
        fingerprint = "bb" * 32

    p = _FakePeer()
    # First call: not debounced. Will fail at the dial but should
    # NOT carry skipped='debounced'. Second call right after must.
    await daemon.send_typing(p)
    r2 = await daemon.send_typing(p)
    assert r2.get("skipped") == "debounced"


# ───────── POST /api/peers/{fp}/typing ──────────────────────────────

@pytest.mark.asyncio
async def test_typing_endpoint_returns_200_when_peer_offline(http):
    client, _, _, token = http
    resp = await client.post(
        f"/api/peers/{'cc' * 32}/typing", headers=_h(token), json={},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["delivered"] is False


# ───────── UI surface ───────────────────────────────────────────────

def test_privacy_pane_has_send_typing_toggle(index_html: str):
    assert 'id="set-send-typing"' in index_html


def test_privacy_pane_has_display_typing_toggle(index_html: str):
    assert 'id="set-display-typing"' in index_html


def test_settings_save_includes_typing_toggles(index_html: str):
    idx = index_html.find('"#settings-save").onclick')
    snippet = index_html[idx:idx + 5000]
    assert "send_typing_indicators:" in snippet
    assert "display_typing_indicators:" in snippet


def test_typing_banner_markup_present(index_html: str):
    assert 'id="convo-typing"' in index_html
    assert 'id="convo-typing-name"' in index_html


def test_input_event_fires_typing_endpoint(index_html: str):
    """Pin the wiring: input event handler must POST to the typing
    endpoint when there's a selected peer."""
    idx = index_html.find('$("#input").addEventListener("input"')
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    assert "/typing" in snippet
    assert "send_typing_indicators" in snippet


def test_input_handler_respects_client_debounce(index_html: str):
    """Client-side mirror of the 2.5s daemon debounce."""
    idx = index_html.find('$("#input").addEventListener("input"')
    snippet = index_html[idx:idx + 1500]
    assert "_lastTypingFiredAt" in snippet
    assert "2500" in snippet


def test_ws_handler_caches_expires_at(index_html: str):
    idx = index_html.find('m.type === "peer_typing"')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "state.peerTyping" in snippet
    assert "expires_at_ms" in snippet
    assert "renderTypingBanner()" in snippet


def test_ws_handler_gates_on_display_setting(index_html: str):
    idx = index_html.find('m.type === "peer_typing"')
    snippet = index_html[idx:idx + 800]
    assert "display_typing_indicators" in snippet


def test_render_typing_banner_function_present(index_html: str):
    assert "function renderTypingBanner()" in index_html


def test_render_auto_hides_after_expiry(index_html: str):
    idx = index_html.find("function renderTypingBanner()")
    snippet = index_html[idx:idx + 1500]
    assert "Date.now() >= exp" in snippet
    assert "setInterval(renderTypingBanner" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
