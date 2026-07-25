"""Direct and group typing indicators.

New ephemeral wire kind: TYPING. Carries expires_in_ms (5s default,
clamped 0–10s server-side). The daemon broadcasts a peer_typing WS
event so any open tab on the receiver renders "User is typing…"
until the deadline.

Privacy:
  - send_typing_indicators (default on) — daemon's send_typing()
    short-circuits when off; peers never learn we're composing.
  - display_typing_indicators (default on) — when off, peer_typing
    metadata is neither cached nor broadcast, so the banner never appears.
  - settings-store absence, read failure, or malformed values fail closed.

Debouncing:
  - Daemon-side: 2.5s per direct peer or immutable group id.
  - Client-side mirror: same per-conversation window so switching
    conversations cannot suppress a valid signal.
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path
from types import SimpleNamespace

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link import groups as gmod
from one_link import groups_crypto as gc
from one_link.discovery import Peer
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State
from one_link.wire import decode_msg, make_msg


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="typing-host",
    )


def _persist_group(
    state: State,
    *,
    owner: Identity,
    members: list[Identity],
) -> bytes:
    created = gmod.sign_create_group(
        private_key=owner.private,
        pubkey=owner.public_bytes,
        name="Typing group",
    )
    events = [created]
    for offset, member in enumerate(members, start=1):
        events.append(
            gmod.sign_add_member(
                private_key=owner.private,
                pubkey=owner.public_bytes,
                group_id=created.group_id,
                member_pubkey=member.public_bytes,
                timestamp_ms=created.timestamp_ms + offset,
            )
        )
    for event in events:
        state.upsert_group_event(
            group_id=event.group_id,
            event_id=event.event_id,
            timestamp_ms=event.timestamp_ms,
            wire_dict=event.to_wire(),
        )
    return created.group_id


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
    client, daemon, _, token = http
    daemon._peer_typing["aa" * 32] = 2**62
    daemon._group_typing[(b"g" * 16, "bb" * 32)] = 2**62
    await client.post("/api/settings", headers=_h(token),
                      json={"display_typing_indicators": False})
    j = await (await client.get("/api/settings", headers=_h(token))).json()
    assert j["display_typing_indicators"] is False
    assert daemon._peer_typing == {}
    assert daemon._group_typing == {}


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
async def test_send_typing_fails_closed_when_privacy_store_raises(
    http,
    monkeypatch: pytest.MonkeyPatch,
):
    _, daemon, state, _ = http

    def _broken_setting(_key: str):
        raise OSError("state read failed")

    async def _unexpected_send(*_args, **_kwargs):
        raise AssertionError("privacy-state failure must not touch the wire")

    monkeypatch.setattr(state, "get_setting", _broken_setting)
    monkeypatch.setattr(daemon, "send_to", _unexpected_send)
    peer = SimpleNamespace(
        short_id="privacy",
        ed_pub_hex="22" * 32,
        address="127.0.0.1",
        port=9999,
        fingerprint="dd" * 32,
    )

    result = await daemon.send_typing(peer)

    assert result == {"sent": None, "skipped": "privacy_state_unavailable"}


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


@pytest.mark.asyncio
async def test_send_group_typing_fans_out_only_to_current_pinned_members(
    tmp_path: Path,
):
    me = _identity()
    alice = _identity()
    bob = _identity()
    state = State(db_path=tmp_path / "group-send.db")
    daemon = Daemon(me)
    daemon.state = state
    gid = _persist_group(state, owner=me, members=[alice, bob])
    for member in (alice, bob):
        state.upsert_peer(
            fingerprint=member.fingerprint,
            short_id=member.short_id,
            pubkey=member.public_bytes,
        )
        state.set_peer_trust(member.fingerprint, "pinned")

    resolved: list[str] = []
    sent: list[tuple[str, dict]] = []

    async def _resolve(fp: str):
        resolved.append(fp)
        return SimpleNamespace(fingerprint=fp)

    async def _send_to(peer, messages):
        sent.append((peer.fingerprint, messages[0]))
        return [{"t": "ACK", "of": messages[0]["id"]}]

    daemon.resolve_for_send = _resolve  # type: ignore[method-assign]
    daemon.send_to = _send_to  # type: ignore[method-assign]
    try:
        result = await daemon.send_group_typing(group_id=gid)
        assert result["recipients"] == 2
        assert result["delivered"] == 2
        assert result["failures"] == []
        assert set(resolved) == {alice.fingerprint, bob.fingerprint}
        assert {fp for fp, _ in sent} == {alice.fingerprint, bob.fingerprint}
        assert all(msg["t"] == "GROUP_TYPING" for _, msg in sent)
        assert all(gc._b64d(msg["group_id_b64"]) == gid for _, msg in sent)

        second = await daemon.send_group_typing(group_id=gid)
        assert second == {"sent": None, "skipped": "debounced"}
        assert len(sent) == 2
    finally:
        state.close()


@pytest.mark.asyncio
async def test_send_group_typing_honors_privacy_before_resolution(tmp_path: Path):
    me = _identity()
    alice = _identity()
    state = State(db_path=tmp_path / "group-private.db")
    daemon = Daemon(me)
    daemon.state = state
    gid = _persist_group(state, owner=me, members=[alice])
    state.set_setting("send_typing_indicators", "false")

    async def _unexpected_resolve(_fp: str):
        raise AssertionError("privacy-disabled typing must not resolve or dial")

    daemon.resolve_for_send = _unexpected_resolve  # type: ignore[method-assign]
    try:
        result = await daemon.send_group_typing(group_id=gid)
        assert result == {"sent": None, "skipped": "privacy"}
    finally:
        state.close()


@pytest.mark.asyncio
async def test_send_group_typing_fails_closed_when_privacy_store_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    me = _identity()
    state = State(db_path=tmp_path / "group-private-failure.db")
    daemon = Daemon(me)
    daemon.state = state

    def _broken_setting(_key: str):
        raise OSError("state read failed")

    def _unexpected_group_state(_group_id: bytes):
        raise AssertionError("privacy-state failure must precede group resolution")

    monkeypatch.setattr(state, "get_setting", _broken_setting)
    monkeypatch.setattr(daemon, "_group_state_for", _unexpected_group_state)
    try:
        result = await daemon.send_group_typing(group_id=b"g" * 16)
        assert result == {"sent": None, "skipped": "privacy_state_unavailable"}
    finally:
        state.close()


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


@pytest.mark.asyncio
async def test_typing_endpoint_checks_privacy_before_peer_resolution(
    http,
    monkeypatch: pytest.MonkeyPatch,
):
    client, daemon, state, token = http
    state.set_setting("send_typing_indicators", "false")

    async def _unexpected_resolve(_fp: str):
        raise AssertionError("privacy-disabled typing must not resolve a route")

    monkeypatch.setattr(daemon, "resolve_for_send", _unexpected_resolve)
    response = await client.post(
        f"/api/peers/{'ee' * 32}/typing",
        headers=_h(token),
        json={},
    )

    assert response.status == 200
    assert await response.json() == {
        "ok": True,
        "delivered": False,
        "skipped": "privacy",
    }


@pytest.mark.asyncio
async def test_group_typing_endpoint_reports_bounded_delivery(http):
    client, daemon, state, token = http
    gid = _persist_group(state, owner=daemon.me, members=[])

    async def _send_group_typing(*, group_id: bytes):
        assert group_id == gid
        return {
            "sent": {"t": "GROUP_TYPING"},
            "recipients": 3,
            "delivered": 2,
            "failures": [{"fingerprint": "x", "error": "offline"}],
        }

    daemon.send_group_typing = _send_group_typing  # type: ignore[method-assign]
    response = await client.post(
        f"/api/groups/{gid.hex()}/typing",
        headers=_h(token),
        json={},
    )
    assert response.status == 200
    assert await response.json() == {
        "ok": True,
        "delivered": True,
        "delivered_count": 2,
        "recipient_count": 3,
        "failed_count": 1,
        "skipped": None,
    }


@pytest.mark.asyncio
async def test_inbound_group_typing_requires_current_membership_and_privacy(
    tmp_path: Path,
):
    me = _identity()
    alice = _identity()
    outsider = _identity()
    state = State(db_path=tmp_path / "group-inbound.db")
    daemon = Daemon(me)
    daemon.state = state
    gid = _persist_group(state, owner=me, members=[alice])
    for peer in (alice, outsider):
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

    broadcasts: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=broadcasts.append)

    class _Channel:
        def __init__(self, peer: Identity):
            self.peer_ed_pub = peer.public_bytes
            self.peer_short_id = peer.short_id
            self.sent: list[dict] = []

        async def send(self, raw: bytes) -> None:
            self.sent.append(decode_msg(raw))

    def _message(peer: Identity) -> dict:
        return make_msg(
            "GROUP_TYPING",
            peer.short_id,
            group_id_b64=gc._b64(gid),
            expires_in_ms=5_000,
        )

    try:
        alice_channel = _Channel(alice)
        await daemon._on_peer_message(alice_channel, _message(alice))
        assert alice_channel.sent[-1].get("rejected") is None
        assert broadcasts[-1]["type"] == "group_typing"
        assert broadcasts[-1]["group_id_hex"] == gid.hex()
        assert broadcasts[-1]["peer_fp"] == alice.fingerprint
        assert (gid, alice.fingerprint) in daemon._group_typing

        state.set_setting("display_typing_indicators", "false")
        broadcasts.clear()
        await daemon._on_peer_message(alice_channel, _message(alice))
        assert alice_channel.sent[-1].get("rejected") is None
        assert broadcasts == []
        assert (gid, alice.fingerprint) not in daemon._group_typing

        outsider_channel = _Channel(outsider)
        await daemon._on_peer_message(outsider_channel, _message(outsider))
        assert outsider_channel.sent[-1]["rejected"] == "group_not_member"
        assert (gid, outsider.fingerprint) not in daemon._group_typing
    finally:
        state.close()


@pytest.mark.asyncio
async def test_inbound_direct_typing_privacy_read_failure_is_not_cached_or_broadcast(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    me = _identity()
    alice = _identity()
    state = State(db_path=tmp_path / "direct-inbound-private.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=alice.fingerprint,
        short_id=alice.short_id,
        pubkey=alice.public_bytes,
    )
    state.set_peer_trust(alice.fingerprint, "pinned")
    broadcasts: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=broadcasts.append)

    class _Channel:
        peer_ed_pub = alice.public_bytes
        peer_short_id = alice.short_id

        def __init__(self):
            self.sent: list[dict] = []

        async def send(self, raw: bytes) -> None:
            self.sent.append(decode_msg(raw))

    def _broken_setting(_key: str):
        raise OSError("state read failed")

    monkeypatch.setattr(state, "get_setting", _broken_setting)
    channel = _Channel()
    try:
        await daemon._on_peer_message(
            channel,
            make_msg("TYPING", alice.short_id, expires_in_ms=5_000),
        )
        assert channel.sent[-1].get("rejected") is None
        assert broadcasts == []
        assert alice.fingerprint not in daemon._peer_typing
    finally:
        state.close()


def test_typing_state_pruner_retires_all_ephemeral_maps() -> None:
    daemon = Daemon(_identity())
    daemon._peer_typing = {"expired": 9, "live": 11}
    daemon._group_typing = {
        (b"a" * 16, "expired"): 10,
        (b"b" * 16, "live"): 12,
    }
    daemon._last_typing_sent_to = {"expired": 6.9, "live": 8.0}
    daemon._last_group_typing_sent_to = {b"a" * 16: 7.0, b"b" * 16: 9.0}

    daemon._prune_typing_state(now_ms=10, monotonic_now=10.0)

    assert daemon._peer_typing == {"live": 11}
    assert daemon._group_typing == {(b"b" * 16, "live"): 12}
    assert daemon._last_typing_sent_to == {"live": 8.0}
    assert daemon._last_group_typing_sent_to == {b"b" * 16: 9.0}


@pytest.mark.asyncio
async def test_two_daemon_group_typing_round_trip_is_ephemeral(tmp_path: Path):
    alice = _identity()
    bob = _identity()
    alice_state = State(db_path=tmp_path / "alice.db")
    bob_state = State(db_path=tmp_path / "bob.db")
    alice_daemon = Daemon(alice)
    bob_daemon = Daemon(bob)
    alice_daemon.state = alice_state
    bob_daemon.state = bob_state
    alice_daemon.discovery = None
    bob_daemon.discovery = None

    for state, peer in ((alice_state, bob), (bob_state, alice)):
        state.upsert_peer(
            fingerprint=peer.fingerprint,
            short_id=peer.short_id,
            pubkey=peer.public_bytes,
        )
        state.set_peer_trust(peer.fingerprint, "pinned")

    gid = _persist_group(alice_state, owner=alice, members=[bob])
    for event in alice_state.list_group_events(gid):
        bob_state.upsert_group_event(
            group_id=gid,
            event_id=event["event_id"],
            timestamp_ms=event["timestamp_ms"],
            wire_dict=event,
        )

    broadcasts: list[dict] = []
    bob_daemon.ui_server = SimpleNamespace(broadcast=broadcasts.append)
    server = await asyncio.start_server(
        bob_daemon._handle_peer,
        host="127.0.0.1",
        port=0,
    )
    assert server.sockets
    bob_port = int(server.sockets[0].getsockname()[1])
    bob_peer = Peer(
        short_id=bob.short_id,
        hostname="bob",
        address="127.0.0.1",
        port=bob_port,
        ed_pub_hex=bob.public_bytes.hex(),
    )
    alice_daemon.discovery = SimpleNamespace(
        registry=SimpleNamespace(
            list=lambda: [bob_peer],
            find=lambda _needle: bob_peer,
        ),
    )
    try:
        result = await asyncio.wait_for(
            alice_daemon.send_group_typing(group_id=gid),
            timeout=10.0,
        )
        assert result["recipients"] == 1
        assert result["delivered"] == 1
        event = next(item for item in broadcasts if item.get("type") == "group_typing")
        assert event["group_id_hex"] == gid.hex()
        assert event["peer_fp"] == alice.fingerprint
        assert alice_state.recent_group_messages(group_id=gid) == []
        assert bob_state.recent_group_messages(group_id=gid) == []
    finally:
        for fp in list(alice_daemon._outbound_sessions):
            await alice_daemon._drop_outbound_session(fp)
        for fp in list(bob_daemon._outbound_sessions):
            await bob_daemon._drop_outbound_session(fp)
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), timeout=2.0)
        alice_state.close()
        bob_state.close()


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


def test_input_event_fires_group_typing_endpoint(index_html: str):
    idx = index_html.find('$("#input").addEventListener("input"')
    snippet = index_html[idx : idx + 2200]
    assert "/api/groups/${state.selectedGroup}/typing" in snippet
    assert "Group typing not implemented" not in index_html


def test_input_handler_respects_client_debounce(index_html: str):
    """Client-side mirror of the 2.5s daemon debounce."""
    idx = index_html.find('$("#input").addEventListener("input"')
    snippet = index_html[idx:idx + 1500]
    assert "_lastTypingFiredAt" in snippet
    assert "2500" in snippet


def test_ws_handler_caches_expires_at(index_html: str):
    idx = index_html.find('m.type === "peer_typing"')
    assert idx > 0
    snippet = index_html[idx:idx + 1400]
    assert "state.peerTyping" in snippet
    assert "expires_at_ms" in snippet
    assert "renderTypingBanner()" in snippet


def test_ws_handler_caches_group_typing_by_group_and_peer(index_html: str):
    idx = index_html.find('m.type === "group_typing"')
    assert idx > 0
    snippet = index_html[idx : idx + 1000]
    assert "state.groupTyping[gid][m.peer_fp]" in snippet
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
    snippet = index_html[idx:idx + 4000]
    assert "now >= exp" in snippet
    assert "state.selectedGroup" in snippet
    assert "delete state.groupTyping[state.selectedGroup]" in snippet
    assert "setInterval(renderTypingBanner" in snippet


def test_render_prunes_unselected_typing_state(index_html: str):
    idx = index_html.find("function renderTypingBanner()")
    snippet = index_html[idx:idx + 5000]
    assert "Object.entries(state.peerTyping || {})" in snippet
    assert "Object.entries(state.groupTyping || {})" in snippet
    assert "delete state.groupTyping[gid]" in snippet


def test_ws_typing_events_are_schema_and_deadline_bounded(index_html: str):
    idx = index_html.find('m.type === "peer_typing"')
    snippet = index_html[idx:idx + 1800]
    assert "[0-9a-f]{64}" in snippet
    assert "Number.isSafeInteger(deadline)" in snippet
    assert "deadline > Date.now() + 15000" in snippet
    group_idx = index_html.find('m.type === "group_typing"')
    group_snippet = index_html[group_idx:group_idx + 1400]
    assert "[0-9a-f]{32}" in group_snippet


def test_disabling_display_typing_clears_browser_cache(index_html: str):
    idx = index_html.find("if (!payload.display_typing_indicators)")
    assert idx > 0
    snippet = index_html[idx:idx + 300]
    assert "state.peerTyping = {}" in snippet
    assert "state.groupTyping = {}" in snippet
    assert "renderTypingBanner()" in snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
