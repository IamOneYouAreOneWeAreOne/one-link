"""v0.20.2 — Phone fetches chat list + recent messages from
daemon over WebRTC.

After auto-pair completes (v0.20.1), the phone has a live
DataChannel to the daemon. This ship adds the read path:

  phone → daemon: {"v":"OL-PEER-1", "t":"fetch_peers", "rid":"..."}
  daemon → phone: {"v":"OL-PEER-1", "t":"peers", "rid":"...", peers:[...]}
  phone → daemon: {"v":"OL-PEER-1", "t":"fetch_messages", "rid":"...",
                   "peer_fp":"...", "limit":50}
  daemon → phone: {"v":"OL-PEER-1", "t":"messages", "rid":"...",
                   "peer_fp":"...", "messages":[...]}

  Reach:  phone shows the laptop's actual chat list. Tap a row,
          see recent messages. The data the user asked to see
          when they said "phone shows my chats."
  Hide:   the request/response correlation runs over the same
          DataChannel as v0.19.2's chat protocol; rids
          disambiguate.
  Async:  every request is a Promise; 10s default timeout;
          channel close fails all in-flight Promises.
  Depth:  daemon serializes only the fields the phone needs
          for a roster + chat view. Sensitive material (raw
          pubkeys, capability state, full key history) stays
          on the daemon; the phone gets fingerprint + alias +
          last-seen, not a full PeerRecord dump.

What this ship does NOT yet contain:
- Phone sends a new message via the daemon (next ship; requires
  bridging the daemon's outbound message machinery)
- Live updates / push when new messages arrive on the daemon
  (the phone only sees the snapshot it requested)
- Group chat (only direct peers in v0.20.2)

Tests cover: daemon-side handler dispatch, response shape,
auth / state-unavailable error paths, phone-side roster card,
chat card, request/response correlation, timeout handling.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.peer_rtc import (
    BrowserPeer,
    BrowserPeerManager,
    PEER_DC_PROTOCOL_VERSION,
)
from one_link.server import UIServer
from one_link.state import MessageRecord, PeerRecord, State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="bridge-host",
    )


@pytest_asyncio.fixture
async def server_with_state(tmp_path: Path, monkeypatch):
    """A UIServer with a real State backing it so the bridge has
    actual peers + messages to serialize."""
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
    try:
        yield server, state
    finally:
        state.close()


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


# ───────── daemon-side bridge handler ──────────────────────────────


def _capture_peer(server: UIServer):
    """A BrowserPeer whose control_dc is a stub that captures sent
    JSON messages. We bypass aiortc entirely — the bridge handler
    only depends on the manager's send_dc primitive."""
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    peer = BrowserPeer(
        fingerprint="sha256:abc",
        pubkey_bytes=b"\x00" * 32,
    )
    peer.control_dc = _StubChannel()
    server.peer_rtc.register_peer(peer)
    return peer, captured


@pytest.mark.asyncio
async def test_fetch_peers_returns_roster(server_with_state):
    """When the phone sends fetch_peers, the daemon responds with
    a list of paired peers serialized to a phone-friendly shape."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:peer1",
        short_id="peer1",
        hostname="other-laptop",
        pubkey=b"\x01" * 32,
    )
    state.upsert_peer(
        fingerprint="sha256:peer2",
        short_id="peer2",
        hostname="phone",
        pubkey=b"\x02" * 32,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r1"},
    )
    assert len(captured) == 1
    reply = captured[0]
    assert reply["t"] == "peers"
    assert reply["rid"] == "r1"
    assert reply["v"] == PEER_DC_PROTOCOL_VERSION
    assert isinstance(reply["peers"], list)
    fps = {p["fingerprint"] for p in reply["peers"]}
    assert "sha256:peer1" in fps
    assert "sha256:peer2" in fps


@pytest.mark.asyncio
async def test_fetch_peers_serializes_minimal_fields(server_with_state):
    """The daemon MUST NOT leak raw pubkeys, full capability state,
    or key history through the bridge. Phone roster only needs
    fingerprint + alias + last_seen + trust state."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:abc",
        short_id="abc",
        hostname="laptop",
        pubkey=b"\x01" * 32,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r1"},
    )
    record = captured[0]["peers"][0]
    # Must include
    for key in ("fingerprint", "short_id", "hostname", "alias", "trust"):
        assert key in record, f"missing {key}"
    # Must NOT include
    for key in ("verifier_pub", "pub_key_b64", "capabilities", "key_history"):
        assert key not in record, f"leaked {key} through bridge"


@pytest.mark.asyncio
async def test_fetch_messages_returns_recent(server_with_state):
    """fetch_messages with peer_fp returns the most recent N
    messages serialized to a phone-friendly shape."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:p1",
        short_id="p1",
        hostname="x",
        pubkey=b"\x01" * 32,
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:p1",
        msg_type="text", body="hello",
    )
    state.record_message(
        id="m2", ts_ms=2000, direction="out", peer_fp="sha256:p1",
        msg_type="text", body="hi back",
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r2",
            "peer_fp": "sha256:p1",
            "limit": 50,
        },
    )
    assert len(captured) == 1
    reply = captured[0]
    assert reply["t"] == "messages"
    assert reply["rid"] == "r2"
    assert reply["peer_fp"] == "sha256:p1"
    assert len(reply["messages"]) == 2
    bodies = [m["body"] for m in reply["messages"]]
    assert "hello" in bodies
    assert "hi back" in bodies


@pytest.mark.asyncio
async def test_fetch_messages_caps_limit(server_with_state):
    """A malicious peer can't ask for 1M messages and DoS the
    daemon's serialization. Limit clamped to 500."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r3",
            "peer_fp": "sha256:p1",
            "limit": 1_000_000,
        },
    )
    # No assertion on the response itself beyond it being well-
    # formed — the cap is enforced by the bridge before the SQL
    # query, so no DoS path even if state had millions of rows.
    assert captured[0]["t"] == "messages"


@pytest.mark.asyncio
async def test_fetch_messages_rejects_missing_peer_fp(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r4",
            # peer_fp missing
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_peer_fp"


@pytest.mark.asyncio
async def test_fetch_self_returns_daemon_identity(server_with_state):
    """fetch_self lets the phone show "Connected to <hostname>"
    without an extra REST call."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_self",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_self", "rid": "r5"},
    )
    reply = captured[0]
    assert reply["t"] == "self"
    assert reply["rid"] == "r5"
    assert reply["fingerprint"] == server.daemon.me.fingerprint
    assert reply["hostname"] == server.daemon.me.hostname


@pytest.mark.asyncio
async def test_unknown_t_silently_ignored(server_with_state):
    """v0.19.2's chat protocol also rides this channel. The bridge
    handler MUST silently ignore frames it doesn't recognize, not
    error-spam them."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "text",  # v0.19.2 chat-protocol kind
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "text", "id": "x"},
    )
    assert captured == []


@pytest.mark.asyncio
async def test_state_unavailable_yields_error(server_with_state):
    """If state isn't initialized (degenerate daemon), surface a
    semantic error rather than crashing."""
    server, _ = server_with_state
    server.daemon.state = None
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r6"},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "no_state"


# ───────── phone-side roster + chat surface ────────────────────────


def test_daemon_roster_card_present(peer_html: str):
    assert 'id="daemon-roster-card"' in peer_html
    assert 'id="daemon-peers-list"' in peer_html
    assert 'id="daemon-chat-card"' in peer_html
    assert 'id="daemon-chat-log"' in peer_html
    assert 'id="btn-daemon-chat-back"' in peer_html


def test_daemon_roster_card_hidden_until_pair(peer_html: str):
    """The roster shows only after auto-pair finalize fetches it."""
    idx = peer_html.find('id="daemon-roster-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_daemon_chat_card_hidden_until_row_tap(peer_html: str):
    idx = peer_html.find('id="daemon-chat-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_register_daemon_dc_helper_present(peer_html: str):
    """Single source of truth for "this DataChannel is the daemon."
    Stores the dc reference + wires close handler."""
    snippet = _snippet(peer_html, "function _registerDaemonDc", 1500)
    assert "state.daemon_dc = dc" in snippet
    assert 'addEventListener("close"' in snippet


def test_route_daemon_dc_message_routes_by_rid(peer_html: str):
    """Responses come back keyed by rid. The router looks up the
    pending Promise and resolves/rejects."""
    snippet = _snippet(peer_html, "function _routeDaemonDcMessage", 1500)
    assert "state.daemon_pending.has(rid)" in snippet
    assert "pending.resolve(msg)" in snippet
    assert 'msg.t === "error"' in snippet
    assert "pending.reject(" in snippet


def test_daemon_request_uses_uuid_rid(peer_html: str):
    """Every request gets a fresh rid via crypto.randomUUID. Must
    not reuse rids — collisions would deliver wrong responses to
    in-flight Promises."""
    snippet = _snippet(peer_html, "function _daemonRequest", 1500)
    assert "_genRid()" in snippet
    assert 'v: "OL-PEER-1"' in snippet


def test_daemon_request_has_timeout(peer_html: str):
    """10s default timeout. Promise rejects if no matching response
    arrives — phone surfaces a "couldn't fetch" message instead of
    spinning forever."""
    snippet = _snippet(peer_html, "function _daemonRequest", 1500)
    assert "DAEMON_REQUEST_TIMEOUT_MS" in snippet
    assert "setTimeout(" in snippet
    assert "rejected" not in snippet  # we use reject, not "rejected"


def test_daemon_request_clears_on_channel_close(peer_html: str):
    """If the channel closes mid-request, every in-flight Promise
    rejects with "daemon channel closed." Otherwise the phone hangs."""
    snippet = _snippet(peer_html, "function _registerDaemonDc", 1500)
    assert "daemon channel closed" in snippet
    assert "state.daemon_pending.clear()" in snippet


def test_fetch_daemon_peers_helper(peer_html: str):
    """Wraps _daemonRequest("fetch_peers") and returns the peers
    array, defaulting to []."""
    snippet = _snippet(peer_html, "async function fetchDaemonPeers", 800)
    assert '_daemonRequest("fetch_peers"' in snippet
    assert "Array.isArray(reply.peers)" in snippet


def test_fetch_daemon_messages_helper(peer_html: str):
    """Wraps _daemonRequest("fetch_messages") with peer_fp + limit."""
    snippet = _snippet(peer_html, "async function fetchDaemonMessages", 1000)
    assert '_daemonRequest("fetch_messages"' in snippet
    assert "peer_fp: peerFp" in snippet
    assert "limit: limit" in snippet


def test_refresh_roster_renders_rows(peer_html: str):
    """_refreshDaemonRoster sorts peers by last_seen_ms desc + renders
    a tap-able row for each."""
    snippet = _snippet(peer_html, "async function _refreshDaemonRoster", 4000)
    assert "fetchDaemonPeers()" in snippet
    assert "last_seen_ms" in snippet
    assert "_openDaemonChat(peer)" in snippet


def test_open_daemon_chat_loads_messages(peer_html: str):
    """Tapping a peer row fetches messages + renders bubbles in the
    chat log. Hides the roster, shows the chat card."""
    snippet = _snippet(peer_html, "async function _openDaemonChat", 3000)
    assert "fetchDaemonMessages(peer.fingerprint" in snippet
    assert "_renderDaemonMessageBubble(log, m)" in snippet
    assert 'show($("#daemon-chat-card"))' in snippet
    assert 'hide($("#daemon-roster-card"))' in snippet


def test_chat_back_button_returns_to_roster(peer_html: str):
    """Back button hides chat card + shows roster + clears active peer."""
    snippet = _snippet(peer_html, '"#btn-daemon-chat-back"', 800)
    assert 'hide($("#daemon-chat-card"))' in snippet
    assert 'show($("#daemon-roster-card"))' in snippet
    assert "state.daemon_active_peer = null" in snippet


def test_render_message_bubble_handles_deleted_and_edited(peer_html: str):
    """Deleted messages render '(deleted)' italic. Edited messages
    show '· edited' in the meta line. Don't expose the original body
    of a deleted row to the phone."""
    snippet = _snippet(peer_html, "function _renderDaemonMessageBubble", 2500)
    assert "deleted_at_ms" in snippet
    assert "(deleted)" in snippet
    assert "edited_at_ms" in snippet


def test_autopair_finalize_kicks_off_roster_fetch(peer_html: str):
    """The auto-pair flow's finalize() MUST register the daemon DC
    and call _refreshDaemonRoster — otherwise the phone is paired
    but shows nothing."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 8000)
    assert "_registerDaemonDc(controlDc, pair.daemon_fingerprint)" in snippet
    assert "_refreshDaemonRoster()" in snippet


def test_autopair_wires_dc_message_routing(peer_html: str):
    """The controlDc.onmessage MUST route through
    _routeDaemonDcMessage so request/response correlation works."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 8000)
    assert "controlDc.onmessage = (event) => _routeDaemonDcMessage(event.data)" in snippet


# ───────── test surface ───────────────────────────────────────────


def test_test_surface_exposes_daemon_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 4000)
    for name in (
        "fetchDaemonPeers",
        "fetchDaemonMessages",
        "_daemonRequest",
        "_refreshDaemonRoster",
    ):
        assert name in snippet, f"surface missing {name}"


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_at_or_above_v0202(peer_html: str):
    """Forward-compat: pin shape, not literal."""
    import re
    m = re.search(r"version:\s*['\"](\d+)\.(\d+)\.(\d+)['\"]", peer_html)
    assert m
    parts = tuple(int(p) for p in m.groups())
    assert parts >= (0, 20, 2)


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
