"""v0.10.4 — presence indicators (online / away / dnd / invisible).

Self-status persisted as a setting + propagated via CAPS field +
new PRESENCE wire kind for live updates. Receiver caches peer
presence in daemon._peer_presence and broadcasts peer_presence
WS events. UI: status pill in top header + colored dot tints
on each peer's avatar.

invisible is purely cosmetic privacy — it goes out as 'offline'
on the wire so peers can't tell we're online.
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
        fingerprint=fp, short_id=fp[:8], hostname="presence-host",
    )


@pytest.fixture
def daemon(tmp_path: Path):
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    d = Daemon(me)
    d.state = state
    d.discovery = None
    d._outbound_sessions = {}
    d._inbound_regime = {}
    d.folder_engine = None
    yield d
    state.close()


# ───────── self presence ─────────────────────────────────────────────

def test_default_presence_is_online(daemon):
    assert daemon.get_my_presence() == "online"


@pytest.mark.asyncio
async def test_set_my_presence_persists(daemon):
    await daemon.set_my_presence("away")
    assert daemon.get_my_presence() == "away"


@pytest.mark.asyncio
async def test_set_my_presence_validates(daemon):
    with pytest.raises(ValueError):
        await daemon.set_my_presence("hyper")


@pytest.mark.asyncio
async def test_invisible_reports_offline_on_wire(daemon):
    """invisible is purely cosmetic — outgoing CAPS frames must
    say 'offline' so paired peers can't tell we're connected."""
    await daemon.set_my_presence("invisible")
    caps = daemon._build_my_caps()
    assert caps["presence"] == "offline"


@pytest.mark.asyncio
async def test_caps_carries_chosen_presence(daemon):
    await daemon.set_my_presence("dnd")
    caps = daemon._build_my_caps()
    assert caps["presence"] == "dnd"


# ───────── peer presence cache ───────────────────────────────────────

def test_record_peer_presence_caches(daemon):
    daemon.record_peer_presence("aa" * 32, "away")
    assert daemon._peer_presence["aa" * 32] == "away"


def test_record_peer_presence_normalizes_case(daemon):
    daemon.record_peer_presence("aa" * 32, "AWAY")
    assert daemon._peer_presence["aa" * 32] == "away"


def test_record_peer_presence_rejects_invalid(daemon):
    """Unknown values must NOT poison the cache."""
    daemon.record_peer_presence("aa" * 32, "online")
    daemon.record_peer_presence("aa" * 32, "yelling")
    assert daemon._peer_presence["aa" * 32] == "online"


def test_record_peer_presence_no_op_for_missing_fp(daemon):
    daemon.record_peer_presence("", "online")
    daemon.record_peer_presence(None, "online")
    # No exception, no entries.
    assert "" not in daemon._peer_presence


# ───────── server endpoint + /api/me + /api/peers ───────────────────

@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    state.upsert_peer(
        fingerprint="aa" * 32, short_id="alice",
        pubkey=b"\x00" * 32, hostname="alice",
    )
    state.set_peer_trust("aa" * 32, "pinned")
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


@pytest.mark.asyncio
async def test_endpoint_set_presence(http):
    client, daemon, _, token = http
    resp = await client.post(
        "/api/presence", headers=_h(token), json={"status": "away"},
    )
    assert resp.status == 200
    j = await resp.json()
    assert j["presence"] == "away"
    assert daemon.get_my_presence() == "away"


@pytest.mark.asyncio
async def test_endpoint_rejects_bad_status(http):
    client, _, _, token = http
    resp = await client.post(
        "/api/presence", headers=_h(token), json={"status": "yelling"},
    )
    assert resp.status == 400


@pytest.mark.asyncio
async def test_api_me_includes_presence(http):
    client, daemon, _, token = http
    await daemon.set_my_presence("dnd")
    resp = await client.get("/api/me", headers=_h(token))
    j = await resp.json()
    assert j["presence"] == "dnd"


@pytest.mark.asyncio
async def test_api_peers_includes_peer_presence(http):
    client, daemon, _, token = http
    daemon.record_peer_presence("aa" * 32, "away")
    resp = await client.get("/api/peers", headers=_h(token))
    j = await resp.json()
    p = next(x for x in j["peers"] if x["fingerprint"] == "aa" * 32)
    assert p["presence"] == "away"


@pytest.mark.asyncio
async def test_api_peers_default_presence_is_online(http):
    """Peer that hasn't reported presence yet must default to
    'online' — otherwise the avatar dot would render as gray."""
    client, _, _, token = http
    resp = await client.get("/api/peers", headers=_h(token))
    j = await resp.json()
    p = next(x for x in j["peers"] if x["fingerprint"] == "aa" * 32)
    assert p["presence"] == "online"


# ───────── UI surface ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_top_header_has_presence_pill(index_html: str):
    assert 'id="presence-pill"' in index_html
    assert 'id="presence-dot"' in index_html


def test_presence_menu_has_all_four_states(index_html: str):
    assert 'id="presence-menu"' in index_html
    for state_v in ("online", "away", "dnd", "invisible"):
        assert f'data-presence="{state_v}"' in index_html


def test_apply_presence_helper_present(index_html: str):
    assert "function applyPresenceUI(" in index_html
    assert "async function setMyPresence(" in index_html


def test_init_applies_persisted_presence(index_html: str):
    """init() reads /api/me and calls applyPresenceUI so the dot
    matches the user's last choice across reloads. v0.21.x routes
    init()'s /api/me through _bootApiGetWithRetry (silent 3-retry
    helper for boot-time auth races); the persisted-presence
    snippet must still follow that boot call."""
    # Prefer the boot-retry path (new); fall back to the legacy
    # api.get path so this pin keeps working if a future refactor
    # removes the retry wrapper.
    idx = index_html.find('_bootApiGetWithRetry("/api/me")')
    if idx < 0:
        idx = index_html.find('await api.get("/api/me")')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "applyPresenceUI(me.presence" in snippet


def test_self_presence_ws_handler_present(index_html: str):
    """Other tabs changing presence must sync via WS."""
    assert 'm.type === "self_presence"' in index_html


def test_peer_presence_ws_handler_re_renders(index_html: str):
    idx = index_html.find('m.type === "peer_presence"')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "renderPeers()" in snippet


def test_peer_avatar_dot_tints_by_presence(index_html: str):
    """Pin the CSS rules that color the avatar dot per presence."""
    for css in (".peer.presence-online", ".peer.presence-away",
                ".peer.presence-dnd", ".peer.presence-offline"):
        assert css in index_html


def test_render_peers_adds_presence_class(index_html: str):
    """The peer row must get a presence-* class so the CSS above
    actually applies."""
    # The class string is built on the row inside renderPeers; find
    # the construction expression directly.
    assert "`presence-${reported}`" in index_html


def test_peer_list_hash_includes_presence(index_html: str):
    """Otherwise the sidebar wouldn't re-render when presence
    changes."""
    idx = index_html.find("function _peerListHash(")
    snippet = index_html[idx:idx + 2000]
    assert "p.presence" in snippet


def test_inbound_caps_records_peer_presence():
    """daemon's CAPS handler must call record_peer_presence so the
    cache + WS broadcast fire on every CAPS exchange."""
    src = Path("src/one_link/daemon.py").read_text(encoding="utf-8")
    # Find the CAPS-receive site (peer_caps assignment) and check
    # record_peer_presence is invoked nearby.
    idx = src.find('"presence": msg.get("presence")')
    assert idx > 0, "CAPS receiver doesn't surface peer presence"
    # Within the next ~1 KB, we should also call record_peer_presence.
    snippet = src[idx:idx + 1500]
    assert "record_peer_presence" in snippet


def test_presence_wire_kind_handled():
    """A standalone PRESENCE frame must update the cache without
    persisting as a TEXT message."""
    src = Path("src/one_link/daemon.py").read_text(encoding="utf-8")
    assert 'if t == "PRESENCE":' in src
    idx = src.find('if t == "PRESENCE":')
    snippet = src[idx:idx + 600]
    assert "record_peer_presence" in snippet


def test_set_my_presence_broadcasts_to_sessions():
    """Changing status must fan out a PRESENCE frame on every
    open outbound session so peers update in real time."""
    src = Path("src/one_link/daemon.py").read_text(encoding="utf-8")
    idx = src.find("async def set_my_presence(")
    snippet = src[idx:idx + 2000]
    assert "_outbound_sessions" in snippet
    assert '"PRESENCE"' in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
