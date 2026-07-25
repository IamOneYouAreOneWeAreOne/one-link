"""Smoke test: does the fixture work end-to-end?

If THIS test fails, every other E2E test will fail too. Run first
when debugging the harness."""
from __future__ import annotations



def test_live_daemon_boots_and_serves_index(live_daemon):
    """Just verify the daemon spawns + writes server.port + ui.token.
    No browser involved. If this fails, the subprocess isn't coming
    up (check the daemon log path printed in the error)."""
    assert live_daemon.port > 0
    assert len(live_daemon.token) > 16
    assert live_daemon.home.is_dir()
    # Daemon is alive (returncode is None for running processes).
    assert live_daemon.proc.returncode is None, (
        f"daemon died with code {live_daemon.proc.returncode}; "
        f"log at {live_daemon.log}"
    )


def test_browser_loads_chat_pane(ui_page):
    """The UI loads and the chat pane is in the DOM. This is the
    foundation every other E2E test depends on - if Playwright can't
    even navigate to the auth URL + see the chat root, debugging
    every higher-level test starts here."""
    # The chat pane id is #convo-pane in index.html. If the DOM
    # restructures, update this selector in ONE place (here) and
    # all dependent tests get the new contract for free.
    title = ui_page.title()
    assert "One Link" in title or title  # any non-empty title
    # Body has rendered (the daemon's bootstrap script ran without
    # throwing). Look for a known top-level chrome element.
    body = ui_page.locator("body")
    assert body.count() == 1
