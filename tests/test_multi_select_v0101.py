"""v0.10.1 — multi-select messages + forward to another conversation.

Pure UI ship — no schema, no new server endpoint. Forward reuses
the existing /api/send + /api/groups/{gid}/send routes; we just
client-side iterate over the selected messages and re-send each
to the chosen target with a "↪ Forwarded" prefix.

Tests pin the surface contract: state machine, action bar, forward
modal, selection lifecycle (enter/toggle/exit), conversation
switching exits selection.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── action bar markup ──────────────────────────────────────────

def test_select_bar_present(index_html: str):
    assert 'id="select-bar"' in index_html
    assert 'id="sb-count"' in index_html
    for action in ("sb-forward", "sb-copy", "sb-pin", "sb-delete", "sb-cancel"):
        assert f'id="{action}"' in index_html, f"missing {action}"


def test_forward_picker_modal_present(index_html: str):
    assert 'id="forward-backdrop"' in index_html
    assert 'id="forward-search"' in index_html
    assert 'id="forward-list"' in index_html


# ───────── state machine ──────────────────────────────────────────────

def test_state_fields_initialized(index_html: str):
    assert "state.selecting = false" in index_html
    assert "state.selectedMessageIds = new Set()" in index_html


def test_helpers_present(index_html: str):
    for fn in ("enterSelection", "exitSelection",
               "toggleMessageSelected", "renderSelectionBar",
               "paintSelectionMarks", "bindSelectionToBubble",
               "selectionCopy", "selectionDelete", "selectionPin",
               "openForwardPicker", "closeForwardPicker",
               "renderForwardTargets", "forwardTo"):
        assert f"function {fn}(" in index_html, f"missing {fn}"


def test_right_click_enters_selection(index_html: str):
    """contextmenu on a bubble must seed selection mode."""
    idx = index_html.find("function bindSelectionToBubble(")
    snippet = index_html[idx:idx + 1500]
    assert 'addEventListener("contextmenu"' in snippet
    assert "enterSelection(msg.id)" in snippet


def test_click_in_selection_toggles(index_html: str):
    """Plain click while selecting toggles, but ONLY while
    selecting (otherwise normal click fires inline links etc)."""
    idx = index_html.find("function bindSelectionToBubble(")
    snippet = index_html[idx:idx + 1500]
    assert 'addEventListener("click"' in snippet
    assert "if (!state.selecting) return" in snippet
    assert "toggleMessageSelected(msg.id)" in snippet


def test_link_clicks_not_intercepted(index_html: str):
    """Clicks on inline <a> tags in a bubble shouldn't be hijacked
    by selection toggling — otherwise URLs in messages stop opening."""
    idx = index_html.find("function bindSelectionToBubble(")
    snippet = index_html[idx:idx + 1500]
    assert 'e.target.tagName === "A"' in snippet


# ───────── action handlers ────────────────────────────────────────────

def test_copy_uses_clipboard_api(index_html: str):
    idx = index_html.find("async function selectionCopy(")
    snippet = index_html[idx:idx + 1000]
    assert "navigator.clipboard.writeText(" in snippet


def test_delete_only_offered_for_own_recent_messages(index_html: str):
    """The Delete button must disable when ANY selected message is
    inbound OR outside the 5-min edit cooldown — matches per-bubble
    Delete eligibility from v0.7.6."""
    idx = index_html.find("function renderSelectionBar(")
    snippet = index_html[idx:idx + 1500]
    assert "5 * 60 * 1000" in snippet  # 5-min cooldown
    assert 'm.dir !== "out"' in snippet
    assert 'sb-delete").disabled' in snippet


def test_delete_confirms_before_acting(index_html: str):
    idx = index_html.find("async function selectionDelete(")
    snippet = index_html[idx:idx + 1500]
    assert "confirm(" in snippet


def test_delete_calls_per_message_endpoint(index_html: str):
    idx = index_html.find("async function selectionDelete(")
    snippet = index_html[idx:idx + 1500]
    assert "/api/messages/" in snippet
    assert "/delete" in snippet


# ───────── forward picker ────────────────────────────────────────────

def test_forward_picker_lists_pinned_peers_and_groups(index_html: str):
    idx = index_html.find("function renderForwardTargets(")
    snippet = index_html[idx:idx + 2500]
    assert 'p.trust === "pinned"' in snippet
    assert "state.groups" in snippet


def test_forward_picker_supports_filter(index_html: str):
    idx = index_html.find("function renderForwardTargets(")
    snippet = index_html[idx:idx + 2500]
    # Filter must compare lowercased substring on both peers + groups.
    assert ".toLowerCase()" in snippet
    assert ".includes(f)" in snippet


def test_forward_to_uses_existing_send_endpoints(index_html: str):
    """No new wire endpoint — re-use /api/send (peer) and
    /api/groups/{gid}/send (group). The forward marker is
    purely a body prefix."""
    idx = index_html.find("async function forwardTo(")
    snippet = index_html[idx:idx + 2000]
    assert '"/api/send"' in snippet
    assert "/send`" in snippet  # group send template
    assert "↪ Forwarded" in snippet


def test_forward_iterates_in_chronological_order(index_html: str):
    """Forwarding multiple messages must preserve the order they
    were sent in — out-of-order forwards confuse readers."""
    idx = index_html.find("async function forwardTo(")
    snippet = index_html[idx:idx + 2000]
    assert "(a, b) => (a.ts || 0) - (b.ts || 0)" in snippet


# ───────── lifecycle ─────────────────────────────────────────────────

def test_switching_peer_exits_selection(index_html: str):
    """selectPeer must drop selection so IDs from the previous
    conversation don't leak into the new one."""
    idx = index_html.find("function selectPeer(shortId)")
    snippet = index_html[idx:idx + 600]
    assert "exitSelection()" in snippet


def test_switching_group_exits_selection(index_html: str):
    idx = index_html.find("async function selectGroup(gidHex)")
    snippet = index_html[idx:idx + 600]
    assert "exitSelection()" in snippet


def test_escape_exits_selection(index_html: str):
    """Esc is the universal 'cancel out of this mode' key."""
    # find the Esc handler scoped to selection
    matches = [
        i for i in range(len(index_html))
        if index_html.startswith('e.key === "Escape" && state.selecting', i)
    ]
    assert len(matches) >= 1, "missing Esc → exit selection handler"


def test_group_messages_also_get_selection_hooks(index_html: str):
    """The 1:1 path AND the group-render path both need to wire
    bindSelectionToBubble — otherwise multi-select would only work
    in one mode."""
    idx = index_html.find("function renderGroupConversation(")
    snippet = index_html[idx:idx + 4000]
    assert "bindSelectionToBubble(b," in snippet


# ───────── version ────────────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
