"""v0.19.2 — Browser-as-peer: message store + send/receive over
the control DataChannel.

Once two browsers complete v0.19.1 SAS pairing, this ship gives
them an actual chat. Outgoing text goes over the OL-MSG-1
protocol on the v0.18.0 control DataChannel; incoming text is
acked back. Both directions persist to IndexedDB so a page
reload reloads history.

  Reach:  two browsers can chat. The text never touches a
          server, the daemon, or any third party. DTLS at the
          WebRTC layer + face-to-face SAS verification are the
          only trust roots.
  Hide:   message records live in origin-private IndexedDB
          (`messages.v1`). Each row is keyed by
          `<peer_fp>::<padded_ts>::<id>` so per-peer reads sort
          natively by timestamp without a secondary index.
  Async:  send/receive both await IDB writes. Send-acks are
          best-effort: a missing ack from the peer doesn't break
          the local row, just leaves it un-ticked.
  Depth:  protocol version `OL-MSG-1` so a future-ship migration
          to MLS-backed message wrap (encrypted at rest) is
          discriminable from current rows. Body cap of 64 KB.

What this ship does NOT yet contain:
- Multi-peer chat tabs (only the active WebRTC peer chats)
- At-rest message encryption (v0.19.4 wraps with the v0.16.1 KDF)
- Offline outbox (queued send when the channel is closed)

Tests pin: protocol constants, IDB layout, key composition (so
sort order survives), send + receive contracts, ack handling,
chat UI auto-show after pairing, test surface.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


# ───────── protocol constants ───────────────────────────────────────

def test_msg_protocol_version_pinned(peer_html: str):
    """The version constant gates future-ship rotation. Body cap +
    DB name + store name pinned for forward compat."""
    assert 'MSG_PROTOCOL_VERSION = "OL-MSG-1"' in peer_html
    assert 'MSG_DB_NAME = "one-link-peer-messages"' in peer_html
    assert 'MSG_STORE_NAME = "messages.v1"' in peer_html
    assert "MSG_BODY_MAX_BYTES = 64 * 1024" in peer_html


def test_message_id_uses_random_uuid(peer_html: str):
    """crypto.randomUUID is the cleanest source of unique IDs in
    the browser. Fall back to randomBytes only on very old browsers
    (we already require modern crypto, so the fallback is defensive
    only)."""
    snippet = _snippet(peer_html, "function _newMessageId", 800)
    assert "crypto.randomUUID" in snippet
    assert "_randomBytes" in snippet  # fallback


# ───────── IDB layout + key composition ─────────────────────────────

def test_msg_key_zero_pads_timestamp(peer_html: str):
    """The composite-ish key is `<peer>::<ts>::<id>`. Timestamp MUST
    be zero-padded to 15 chars so cursor.continue() returns rows in
    chronological order. Naked numeric ts fails: "100" sorts before
    "9" in string-compare land."""
    snippet = _snippet(peer_html, "function _msgKey", 600)
    assert 'padStart(15, "0")' in snippet


def test_msg_db_keypath_is_key(peer_html: str):
    """The objectStore keyPath is "key" (the composite-ish field on
    each record). Future ships that add indexes on peer_fp or ts
    layer on top, but the primary key is the sort-friendly composite."""
    snippet = _snippet(peer_html, "function _openMessagesDb", 1500)
    assert 'keyPath: "key"' in snippet
    assert "MSG_DB_VERSION" in snippet


def test_save_message_validates_required_fields(peer_html: str):
    """Records without peer_fp / id / ts are meaningless. Surface the
    error rather than silently writing junk that breaks the cursor
    range."""
    snippet = _snippet(peer_html, "async function saveMessage", 1500)
    assert "rec.peer_fp" in snippet
    assert "rec.id" in snippet
    assert "rec.ts" in snippet


def test_load_messages_uses_idb_key_range(peer_html: str):
    """loadMessages MUST use IDBKeyRange.bound to scope the cursor
    to a single peer. Loading the whole store and filtering in JS
    would be O(n) per fetch."""
    snippet = _snippet(peer_html, "async function loadMessages", 2500)
    assert "IDBKeyRange.bound" in snippet
    assert 'openCursor(range, "next")' in snippet


def test_clear_messages_present(peer_html: str):
    """User-facing 'clear chat' is the only way to drop history;
    pin so a refactor doesn't drop the helper."""
    assert "async function clearMessages(peerFp)" in peer_html


# ───────── send contract ────────────────────────────────────────────

def test_send_chat_requires_active_pair(peer_html: str):
    """Without a finished pair on the active session, send fails
    loudly. Don't silently drop or queue."""
    snippet = _snippet(peer_html, "async function sendChatMessage", 2200)
    assert "no paired peer on the active connection" in snippet
    assert "p.finished" in snippet
    assert "p.remote_hello" in snippet


def test_send_chat_validates_body(peer_html: str):
    """Empty / whitespace-only / oversized bodies all reject. The
    64KB cap protects the peer from a single message saturating
    the control channel."""
    snippet = _snippet(peer_html, "async function sendChatMessage", 2200)
    assert "empty message" in snippet
    assert "MSG_BODY_MAX_BYTES" in snippet


def test_send_chat_persists_outgoing(peer_html: str):
    """Even if the channel send succeeds, we MUST also save locally
    — the wire is best-effort + the peer's ack is best-effort. The
    sender's local copy is the source of truth for their history."""
    snippet = _snippet(peer_html, "async function sendChatMessage", 2200)
    assert 'direction: "out"' in snippet
    assert "saveMessage(rec)" in snippet


def test_send_chat_uses_send_control(peer_html: str):
    """All chat traffic rides the v0.18.0 control channel — same
    wire that pair_hello/confirm uses. Don't introduce a parallel
    transport without an explicit ship + version bump."""
    snippet = _snippet(peer_html, "async function sendChatMessage", 2200)
    assert "sendControl(p.session, wire)" in snippet


# ───────── receive contract ────────────────────────────────────────

def test_receive_handler_checks_protocol_version(peer_html: str):
    """Mismatch on the incoming envelope → silent drop. The router
    is shared between protocols, so chat must ignore non-OL-MSG-1
    traffic instead of mis-handling it."""
    snippet = _snippet(peer_html, "async function _onChatTextReceived", 2200)
    assert "envelope.v !== MSG_PROTOCOL_VERSION" in snippet


def test_receive_handler_persists_in(peer_html: str):
    snippet = _snippet(peer_html, "async function _onChatTextReceived", 2200)
    assert 'direction: "in"' in snippet
    assert "saveMessage(rec)" in snippet


def test_receive_handler_sends_ack(peer_html: str):
    """The ack lets the sender mark the bubble as delivered. Best-
    effort: if sendControl throws (channel closed mid-recv), don't
    block the local-save path."""
    snippet = _snippet(peer_html, "async function _onChatTextReceived", 2200)
    assert 't: "ack"' in snippet
    assert "sendControl(p.session" in snippet


def test_receive_handler_oversize_drops_silently(peer_html: str):
    """An oversized incoming body MUST NOT be persisted (rate-limit
    safety). Drop without ack so the sender retries — but note this
    is best-effort; a malicious peer could still spam."""
    snippet = _snippet(peer_html, "async function _onChatTextReceived", 2200)
    assert "MSG_BODY_MAX_BYTES" in snippet


def test_ack_handler_marks_outgoing_delivered(peer_html: str):
    """When the peer's ack arrives, find the matching outgoing row
    and set ack_ms. The bubble's text updates to reflect."""
    snippet = _snippet(peer_html, "async function _onChatAckReceived", 2200)
    assert "ack_ms" in snippet
    assert "saveMessage(target)" in snippet
    assert "_markBubbleAcked(id)" in snippet


# ───────── chat UI ──────────────────────────────────────────────────

def test_chat_card_present(peer_html: str):
    assert 'id="chat-card"' in peer_html
    assert 'id="chat-log"' in peer_html
    assert 'id="chat-input"' in peer_html
    assert 'id="btn-chat-send"' in peer_html
    assert 'id="chat-status"' in peer_html


def test_chat_card_hidden_until_pair_finalize(peer_html: str):
    idx = peer_html.find('id="chat-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_chat_input_uses_16px_font_for_ios(peer_html: str):
    """iOS Safari zooms inputs with font-size < 16px. Composer MUST
    bump to 16px on phone form-factor — this peer page targets phone
    primarily."""
    idx = peer_html.find('id="chat-input"')
    open_start = peer_html.rfind("<textarea", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "font-size:16px" in tag.replace(" ", "")


def test_chat_send_keyboard_shortcut(peer_html: str):
    """Enter sends, Shift+Enter inserts newline. Standard messenger
    convention; phone keyboards have a 'Send' / 'Done' that maps to
    Enter."""
    idx = peer_html.find('"#chat-input"')
    handler_idx = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler_idx:handler_idx + 800]
    assert '"Enter"' in snippet
    assert "!e.shiftKey" in snippet


def test_chat_send_button_disables_during_send(peer_html: str):
    """sendControl + saveMessage round-trip can take a moment;
    disable the button so a double-tap doesn't double-send."""
    idx = peer_html.find('"#btn-chat-send"')
    handler_idx = peer_html.find("addEventListener", idx)
    snippet = peer_html[handler_idx:handler_idx + 1500]
    assert "btn.disabled = true" in snippet
    assert "btn.disabled = false" in snippet


def test_chat_card_auto_shows_after_pair(peer_html: str):
    """Once both sides confirm match, the chat card auto-opens.
    The hook lives in the wrapper around _maybeFinalizePairing —
    so test that the wrap exists + that the success branch awaits
    _showChatCard()."""
    snippet = _snippet(peer_html, "_maybeFinalizePairing = async function", 1500)
    assert "_showChatCard()" in snippet
    assert "p.local_confirm === true" in snippet
    assert "p.remote_confirm === true" in snippet


def test_show_chat_card_loads_history(peer_html: str):
    """When the chat card opens, hydrate from IDB so a returning
    user sees their last conversation immediately."""
    snippet = _snippet(peer_html, "async function _showChatCard", 2400)
    assert "loadMessages(peer.fingerprint" in snippet
    assert "_appendChatBubble(rec)" in snippet


def test_append_chat_bubble_marks_direction(peer_html: str):
    """Outgoing bubbles align right with accent fill; incoming
    align left with neutral fill. This is the visual cue the user
    relies on to read the conversation."""
    snippet = _snippet(peer_html, "function _appendChatBubble", 3000)
    assert 'rec.direction === "out"' in snippet
    assert 'alignSelf = "flex-end"' in snippet
    assert 'alignSelf = "flex-start"' in snippet


def test_append_chat_bubble_shows_delivered_when_acked(peer_html: str):
    """Outgoing rows with ack_ms set show a "delivered" badge so
    the sender knows the peer received it."""
    snippet = _snippet(peer_html, "function _appendChatBubble", 3000)
    assert "delivered" in snippet
    assert "rec.ack_ms" in snippet


# ───────── control-message router wrap ─────────────────────────────

def test_router_wrap_dispatches_msg_protocol(peer_html: str):
    """The chat handlers wire INTO the existing _routeControlMessage
    so pair AND chat both run on the same control channel without
    stomping each other."""
    snippet = _snippet(peer_html, "_routeControlMessage = function", 1500)
    assert "_origRouteControlMessage(session, kind, data)" in snippet
    assert "msg.v !== MSG_PROTOCOL_VERSION" in snippet
    assert "_onChatTextReceived(msg)" in snippet
    assert "_onChatAckReceived(msg)" in snippet


# ───────── test surface ─────────────────────────────────────────────

def test_test_surface_exposes_message_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 4000)
    for name in (
        "saveMessage",
        "loadMessages",
        "clearMessages",
        "sendChatMessage",
    ):
        assert name in snippet, f"surface missing {name}"


# ───────── version pin ──────────────────────────────────────────────

def test_version_bumped_to_v0192(peer_html: str):
    assert 'version: "0.19.2"' in peer_html


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
