"""v0.14.3 — Phone tier: cut Files / Folders / Activity surfaces.

Ship-spec from `docs/PHONE_TIER.md`:

  Reach:  zero new affordances. The point is removal: phone users
          stop seeing pane-tabs that don't translate to phone form-
          factor (filesystem-level folder sync) or aren't part of
          a daily-use flow (cross-peer activity timeline).
  Hide:   Files + Folders nav buttons + panels gain `.desktop-only`
          (cut entirely on phone, no override). Activity nav button
          gains `data-tier="advanced"` (revealable via show-advanced).
          Activity PANEL is intentionally NOT tagged — its display
          is gated by the button's visibility, and tagging the
          aside would clobber the inline `display: flex` the click
          handler sets.
  Async:  none — purely UI gating.
  Depth:  programmatic-click paths in transfer pill + mesh tile
          go through `_phoneCannotShow` so a hidden Files pane
          can never be activated by a downstream code path.

Tests pin every tag + the guard helper + every call site.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── nav tab tags ─────────────────────────────────────────────

def test_files_nav_button_is_desktop_only(index_html: str):
    """Files nav tab MUST be cut on phone. Phone users get the
    composer's attach + share-sheet flow instead of a separate pane."""
    assert (
        '<button class="btn desktop-only" data-pane="files" id="btn-files">Files</button>'
        in index_html
    )


def test_folders_nav_button_is_desktop_only(index_html: str):
    """Folder-sync semantics (watch a directory) don't translate to
    phone OS sandboxes. Cut entirely."""
    assert (
        '<button class="btn desktop-only" data-pane="folders" id="btn-folders">Folders</button>'
        in index_html
    )


def test_activity_nav_button_is_advanced_tier(index_html: str):
    """Activity is operator-grade insight; revealed by show-advanced
    instead of cut entirely."""
    idx = index_html.find('id="btn-mesh"')
    assert idx > 0
    snippet = index_html[max(0, idx - 200):idx + 200]
    assert 'data-pane="mesh"' in snippet
    assert 'data-tier="advanced"' in snippet


def test_chat_nav_button_unchanged(index_html: str):
    """Chat tab MUST remain visible on phone — that's the whole
    surface. Don't accidentally tag it. Inspect ONLY the button
    element itself, not adjacent siblings."""
    btn_idx = index_html.find('data-pane="convo"')
    assert btn_idx > 0
    # Walk back to the opening <button and forward to the closing >.
    open_tag_start = index_html.rfind("<button", 0, btn_idx)
    open_tag_end = index_html.find(">", btn_idx)
    button_tag = index_html[open_tag_start:open_tag_end + 1]
    assert "desktop-only" not in button_tag
    assert 'data-tier="advanced"' not in button_tag


# ───────── pane asides ──────────────────────────────────────────────

def test_files_panel_aside_is_desktop_only(index_html: str):
    """Defense in depth: even if a programmatic path manages to fire
    the Files button click, the panel itself stays display:none on
    phone via `.desktop-only` + `!important`."""
    idx = index_html.find('id="files-panel"')
    assert idx > 0
    snippet = index_html[max(0, idx - 200):idx + 200]
    assert 'class="files desktop-only"' in snippet


def test_folders_panel_aside_is_desktop_only(index_html: str):
    idx = index_html.find('id="folders-panel"')
    assert idx > 0
    snippet = index_html[max(0, idx - 200):idx + 200]
    assert 'class="files desktop-only"' in snippet


def test_mesh_panel_aside_is_NOT_data_tier_tagged(index_html: str):
    """The Activity ASIDE is deliberately untagged. Tagging it would
    invoke the `display: revert !important` reveal rule, which would
    clobber the inline `display: flex` the click handler sets. Phone
    visibility is gated by the BUTTON's `data-tier="advanced"`."""
    idx = index_html.find('id="mesh-panel"')
    assert idx > 0
    snippet = index_html[max(0, idx - 200):idx + 400]
    # The aside line itself must not carry data-tier.
    aside_line_start = snippet.rfind("<aside", 0, snippet.find('id="mesh-panel"'))
    aside_line_end = snippet.find(">", snippet.find('id="mesh-panel"'))
    aside_line = snippet[aside_line_start:aside_line_end + 1]
    assert 'data-tier="advanced"' not in aside_line


# ───────── _phoneCannotShow guard ───────────────────────────────────

def test_phone_cannot_show_helper_present(index_html: str):
    """The single-source-of-truth guard for programmatic pane nav.
    Don't rename — every downstream caller relies on this name."""
    assert "function _phoneCannotShow(paneBtn)" in index_html


def test_phone_cannot_show_returns_true_when_btn_missing(index_html: str):
    """A missing button is treated as un-showable. Avoids null-deref
    if a future ship removes the Files pane outright."""
    idx = index_html.find("function _phoneCannotShow(paneBtn)")
    snippet = index_html[idx:idx + 600]
    assert "if (!paneBtn) return true;" in snippet


def test_phone_cannot_show_only_blocks_on_phone(index_html: str):
    """Desktop + tablet form-factors must NEVER be blocked, even if
    a button somehow has `.desktop-only` — that class is phone-only
    semantics by design."""
    idx = index_html.find("function _phoneCannotShow(paneBtn)")
    snippet = index_html[idx:idx + 600]
    assert 'data-form-factor' in snippet
    assert '!== "phone"' in snippet
    assert "return false" in snippet


def test_phone_cannot_show_checks_desktop_only_class(index_html: str):
    """The class membership check is the actual gating signal."""
    idx = index_html.find("function _phoneCannotShow(paneBtn)")
    snippet = index_html[idx:idx + 600]
    assert 'classList.contains("desktop-only")' in snippet


# ───────── programmatic click guards ────────────────────────────────

def test_transfer_pill_click_guarded(index_html: str):
    """Tapping the in-flight transfer pill on phone must not silently
    set state.filesMode and refreshFiles against a hidden pane."""
    # Find the transfer pill onclick — pin it via a unique anchor.
    idx = index_html.find("Click to open Files")
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert "_phoneCannotShow(filesBtn)" in snippet


def test_mesh_tile_active_click_guarded(index_html: str):
    """The mesh-panel "active" tile drills into Files → Sent. Same
    guard required, even though the user must already be in
    advanced tier to reach the tile."""
    idx = index_html.find("function _handleMeshTile(kind)")
    assert idx > 0
    snippet = index_html[idx:idx + 1500]
    # The "active" branch specifically must call the guard.
    active_idx = snippet.find('kind === "active"')
    assert active_idx > 0
    active_snippet = snippet[active_idx:active_idx + 600]
    assert "_phoneCannotShow(filesBtn)" in active_snippet


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_matches_package(index_html: str):
    """Forward-compatible: stays green across later bumps. Pin the
    literal "0.14.3" value somewhere else if a release-gate test
    is needed."""
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
