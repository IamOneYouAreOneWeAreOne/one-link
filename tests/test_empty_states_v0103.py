"""v0.10.3 — empty-state polish + first-pair nudge.

Pure UI ship. Every blank surface (Files, Folders, Activity,
conversation pane, sidebar peers) gets a hero glyph + heading +
one-line explanation through a shared `richEmpty` helper.

After the FIRST successful pair with any peer, a "say hi" callout
slides in above the chat. Click → pre-fills 👋 in the composer
+ auto-sends. Tracked per-fingerprint in localStorage so the
nudge doesn't re-pop on subsequent pairings.

These tests pin the surface contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── rich-empty helper ─────────────────────────────────────────

def test_rich_empty_helper_present(index_html: str):
    assert "function richEmpty(" in index_html


def test_rich_empty_class_styled(index_html: str):
    assert ".empty.rich {" in index_html
    assert ".empty.rich .rich-glyph" in index_html
    assert ".empty.rich h4" in index_html


# ───────── pane empty states ─────────────────────────────────────────

def test_files_empty_uses_rich(index_html: str):
    """The Files pane's no-files-yet state must call richEmpty
    so it shows a glyph + heading instead of a plain text line."""
    idx = index_html.find("if (files.length === 0) {")
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "richEmpty(" in snippet
    assert "Inbox is quiet" in snippet


def test_folders_empty_uses_rich(index_html: str):
    """The empty branch of refreshFolders must use richEmpty (the
    standard glyph + heading + body shape) so the folders pane
    visual rhythm matches other empty states. v0.21.x renamed the
    inline gate from `if (state.folders.length === 0) {` to a
    pre-computed `isEmpty` flag so the secondary actions
    (Clear/Refresh) can be hidden in the same branch; the pin
    now looks for that flag + the richEmpty call within range."""
    idx = index_html.find("async function refreshFolders()")
    assert idx > 0
    body = index_html[idx:idx + 3000]
    assert "isEmpty" in body, (
        "refreshFolders should use an isEmpty flag for the empty branch"
    )
    assert "richEmpty(" in body, (
        "folders empty state must use the richEmpty(glyph, heading, body) "
        "shape so it matches other empty surfaces in the app"
    )


def test_activity_empty_uses_rich(index_html: str):
    """The activity feed's empty state must use richEmpty too."""
    # Multiple "No events yet" sites — find the JS render call.
    idx = index_html.find("list.appendChild(richEmpty(")
    assert idx > 0
    # Confirm at least one richEmpty in renderActivityFeed.
    activity_idx = index_html.find("function renderActivityFeed(")
    snippet = index_html[activity_idx:activity_idx + 2500]
    assert "richEmpty(" in snippet


# ───────── conversation pane CTAs ────────────────────────────────────

def test_conv_empty_has_pair_cta(index_html: str):
    assert 'id="convo-empty-pair"' in index_html
    assert 'id="convo-empty-help"' in index_html


def test_conv_empty_pair_button_opens_discover(index_html: str):
    """Clicking 'Pair a new device' on the empty pane should fire
    the existing discover-modal opener."""
    idx = index_html.find('"#convo-empty-pair"')
    snippet = index_html[idx:idx + 600]
    assert "open-discover-modal" in snippet


def test_conv_empty_help_opens_rdz_help(index_html: str):
    idx = index_html.find('"#convo-empty-help"')
    snippet = index_html[idx:idx + 600]
    assert "rdzHelpBackdrop" in snippet


def test_conv_empty_shows_keyboard_tips(index_html: str):
    """Surface Ctrl+K and ? in the empty pane so new users discover
    the palette + shortcuts modal."""
    assert "Ctrl+K" in index_html
    assert ">?</kbd>" in index_html or '<kbd>?</kbd>' in index_html


# ───────── first-pair nudge ──────────────────────────────────────────

def test_nudge_helpers_present(index_html: str):
    assert "function maybeShowFirstPairNudge(" in index_html
    assert "function renderFirstPairNudge(" in index_html


def test_nudge_storage_key_pinned(index_html: str):
    """A constant key avoids typo drift across reloads."""
    assert 'FIRST_PAIR_KEY' in index_html
    assert '"one_link.first_pair_shown"' in index_html


def test_nudge_only_shows_once_per_peer(index_html: str):
    """maybeShowFirstPairNudge must early-return when the
    fingerprint is already in the shown set."""
    idx = index_html.find("function maybeShowFirstPairNudge(")
    snippet = index_html[idx:idx + 1000]
    assert "_firstPairShownSet()" in snippet
    assert "_markFirstPairShown(" in snippet


def test_nudge_say_hi_button_prefills_emoji(index_html: str):
    """The 'Say hi' click should pre-fill the composer with 👋
    and auto-press Send. Pin so a refactor doesn't drop the
    pre-fill behavior."""
    idx = index_html.find("function renderFirstPairNudge(")
    snippet = index_html[idx:idx + 2500]
    assert '"👋"' in snippet
    assert "btn-send" in snippet


def test_nudge_auto_dismisses_after_30s(index_html: str):
    """Untouched nudges should fade after 30s so they don't
    linger forever."""
    idx = index_html.find("function renderFirstPairNudge(")
    snippet = index_html[idx:idx + 2500]
    assert "30_000" in snippet


def test_peer_trust_ws_pinned_triggers_nudge(index_html: str):
    """The peer_trust → pinned WS path must call
    maybeShowFirstPairNudge so the nudge actually fires after a
    real pair."""
    idx = index_html.find('m.type === "peer_trust"')
    snippet = index_html[idx:idx + 1500]
    assert "maybeShowFirstPairNudge(m.fingerprint)" in snippet


# ───────── version ────────────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
