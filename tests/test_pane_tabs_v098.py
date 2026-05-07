"""v0.9.8 — pane-switcher tabs moved from sidebar bottom to top header.

Old: Chat / Files / Folders / Activity sat at the bottom of the
LEFT sidebar in `.side-foot`. Clicking "Files" popped a panel on
the RIGHT, which felt disconnected — the click was on one side
of the screen and the result on the other.

New: tabs live in the top header inside `.pane-tabs`, centered
between the brand and the user info. Same JS handler binding;
clicking still toggles the right-side panes. Visually less
disorienting because the tabs are at the top spanning both
columns.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_pane_tabs_in_header(index_html: str):
    """The four tabs must live inside the top header in <nav class='pane-tabs'>."""
    assert '<nav class="pane-tabs"' in index_html
    # All four buttons present.
    for label in ("Chat", "Files", "Folders", "Activity"):
        assert f">{label}</button>" in index_html


def test_old_side_foot_block_removed(index_html: str):
    """The four-button block must no longer exist inside <div class='side-foot'>."""
    sf_count = index_html.count('<div class="side-foot">')
    assert sf_count == 0, "side-foot wrapper still present"


def test_data_pane_attributes_intact(index_html: str):
    """The pane-switching JS keys off data-pane attributes; pin
    that all four are still set correctly on the buttons."""
    for pane in ("convo", "files", "folders", "mesh"):
        assert f'data-pane="{pane}"' in index_html


def test_handler_bound_to_new_selector(index_html: str):
    """The click handler that toggles panes must use the new
    `.pane-tabs .btn` selector — otherwise the buttons render but
    do nothing."""
    assert 'document.querySelectorAll(".pane-tabs .btn")' in index_html
    assert 'document.querySelectorAll(".side-foot .btn")' not in index_html


def test_existing_id_anchors_preserved(index_html: str):
    """v0.8.8's transfer-pill onclick targets [data-pane='files'];
    v0.7.7's btn-files / btn-folders / btn-mesh ids are also used
    elsewhere. Pin that those still resolve to the new home."""
    assert 'id="btn-files"' in index_html
    assert 'id="btn-folders"' in index_html
    assert 'id="btn-mesh"' in index_html


def test_default_active_tab_is_chat(index_html: str):
    """Initial active class belongs to Chat — the app starts with
    the conversation visible, panes closed."""
    # Find the Chat button line and check it has class active.
    idx = index_html.find('data-pane="convo"')
    assert idx > 0
    # Walk back to the opening <button> tag.
    btn_start = index_html.rfind('<button', 0, idx)
    btn_html = index_html[btn_start:idx + 50]
    assert "active" in btn_html


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
