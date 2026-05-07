"""v0.9.7 — UX polish: reveal feedback + rendezvous help simplification.

Three concrete UX bugs the user hit:
1. "Reveal" buttons looked dead — Explorer windows pop *behind* the
   browser, no immediate UI feedback so the click felt unresponsive.
2. "Open inbox folder" felt slow — same issue + Explorer takes a
   moment to render.
3. Rendezvous help modal was wordy + non-actionable.

Fixes:
- Server: switch inbox-open to os.startfile (ShellExecute, reuses
  existing Explorer window when available). Use list-form Popen
  for /select reveal so the comma-separated arg is unambiguous.
- Client: rename "Reveal" → "Show in folder", add immediate toast
  on click, distinct toast on throttled response.
- Help modal: lead with "Wi-Fi only is fine" + advanced setup
  details behind a disclosure + shortcut to Settings.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


# ───────── server: list-form Popen + os.startfile ────────────────────

def test_inbox_reveal_uses_startfile_on_windows():
    """v0.9.7: switched inbox-open to os.startfile for faster
    perceived performance + reusing an existing Explorer window."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_inbox_reveal(")
    snippet = src[idx:idx + 2500]
    assert 'os.startfile(' in snippet
    # Make sure we're using it for the win32 branch specifically.
    win_idx = snippet.find('sys.platform == "win32"')
    osstart_idx = snippet.find("os.startfile(", win_idx)
    next_branch_idx = snippet.find("sys.platform ==", win_idx + 30)
    assert win_idx > 0
    assert osstart_idx > 0
    assert osstart_idx < next_branch_idx, "os.startfile must be in win32 branch"


def test_file_reveal_uses_list_form_popen():
    """The string-form Popen was the suspect for 'reveal looks dead'.
    List form is unambiguous — the /select,<path> argv token is
    passed as one element, no quoting bugs."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_reveal(")
    snippet = src[idx:idx + 2500]
    # List-form: ["explorer.exe", f"/select,{path}"]
    assert '["explorer.exe", f"/select,{path}"]' in snippet
    # No more f-string command-line form
    assert 'f\'explorer.exe /select,"{norm}"\'' not in snippet


def test_traversal_still_blocked_in_reveal():
    """Defensive — pin the traversal check stays present in
    the new code path."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_reveal(")
    snippet = src[idx:idx + 2500]
    assert 'safe = Path(name).name' in snippet
    assert '"bad name"' in snippet


def test_disable_reveal_env_still_honored():
    """Test runs set ONE_LINK_DISABLE_REVEAL=1 to suppress real
    Explorer pop-ups; the new code paths must still honor it."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    inbox_idx = src.find("async def api_inbox_reveal(")
    file_idx = src.find("async def api_file_reveal(")
    assert "ONE_LINK_DISABLE_REVEAL" in src[inbox_idx:inbox_idx + 2500]
    assert "ONE_LINK_DISABLE_REVEAL" in src[file_idx:file_idx + 2500]


# ───────── UI: feedback + relabeling ─────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_reveal_button_relabeled(index_html: str):
    """'Reveal' was opaque to users — they didn't know what it
    meant. 'Show in folder' is self-describing."""
    # Two reveal buttons exist (chat-bubble + files-panel row).
    # Both must be relabeled.
    reveal_count = index_html.count('null, "Reveal")')
    show_count = index_html.count('null, "Show in folder")')
    assert reveal_count == 0, "stray 'Reveal' button label still present"
    assert show_count >= 2, "expected 2+ 'Show in folder' buttons"


def test_reveal_clicks_show_immediate_toast(index_html: str):
    """The click handler must pop a toast IMMEDIATELY, not wait on
    the round-trip — otherwise the Explorer window opens behind
    the browser and the user thinks nothing happened."""
    # Find any of the reveal click handlers.
    idx = index_html.find('reveal.onclick = async () => {')
    assert idx > 0
    # Within ~600 chars of the handler, expect 'Opening folder' toast.
    snippet = index_html[idx:idx + 800]
    assert 'toast("Opening folder' in snippet


def test_open_inbox_button_shows_immediate_toast(index_html: str):
    idx = index_html.find('"#btn-open-inbox"')
    assert idx > 0
    snippet = index_html[idx:idx + 800]
    assert 'toast("Opening inbox folder' in snippet


def test_throttled_reveal_surfaces_distinct_toast(index_html: str):
    """If the server throttles (1-per-second cap), the UI must
    still tell the user — silently swallowing the click looks
    like a bug."""
    idx = index_html.find('reveal.onclick = async () => {')
    snippet = index_html[idx:idx + 800]
    assert 'res?.throttled' in snippet


# ───────── rendezvous help modal simplification ──────────────────────

def test_rdz_help_leads_with_wifi_only_message(index_html: str):
    """The default answer for most users is 'you don't need this' —
    that should be the first sentence, not the third."""
    idx = index_html.find('id="rdz-help-backdrop"')
    snippet = index_html[idx:idx + 2500]
    assert 'Wi-Fi network' in snippet
    assert "perfect for household use" in snippet


def test_rdz_help_close_label_changed(index_html: str):
    """'Got it' was passive; 'Wi-Fi only is fine' is reassuring."""
    assert 'Wi-Fi only is fine</button>' in index_html


def test_rdz_help_advanced_disclosure_present(index_html: str):
    """Tech setup details belong behind a disclosure, not in the
    primary modal text."""
    idx = index_html.find('id="rdz-help-backdrop"')
    snippet = index_html[idx:idx + 2500]
    assert '<details class="rdz-advanced">' in snippet
    assert '<summary>How to set one up' in snippet


def test_rdz_help_has_settings_shortcut(index_html: str):
    """Power users get a one-click route from the help modal to
    the settings rendezvous panel."""
    assert 'id="rdz-help-settings"' in index_html
    idx = index_html.find('"#rdz-help-settings"')
    snippet = index_html[idx:idx + 600]
    assert "btn-settings" in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
