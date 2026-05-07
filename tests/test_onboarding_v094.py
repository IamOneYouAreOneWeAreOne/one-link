"""v0.9.4 — first-run onboarding wizard.

A 4-step modal that guides a new user from blank slate to "ready
to chat": welcome → display name → SAS explainer → ready. Gated
by a localStorage flag (primary) + a daemon-persisted setting
(backup, so a fresh browser tab on a paired daemon doesn't
re-pop the wizard).

These tests cover the persistence-flag plumbing on both ends and
the UI surface contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from one_link.state import State


@pytest.fixture
def state(tmp_path: Path) -> State:
    s = State(db_path=tmp_path / "state.db")
    yield s
    s.close()


# ───────── settings persistence ──────────────────────────────────────

def test_onboarding_flag_persistable(state: State):
    """The state.set_setting / get_setting helpers underpinning the
    daemon-side onboarding flag must round-trip cleanly."""
    assert state.get_setting("onboarding_completed") is None
    state.set_setting("onboarding_completed", "true")
    assert state.get_setting("onboarding_completed") == "true"


def test_onboarding_flag_overwrite(state: State):
    state.set_setting("onboarding_completed", "true")
    state.set_setting("onboarding_completed", "false")
    assert state.get_setting("onboarding_completed") == "false"


# ───────── server endpoint shape ─────────────────────────────────────

def test_set_settings_accepts_onboarding_flag():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_set_settings(")
    snippet = src[idx:idx + 2500]
    assert '"onboarding_completed" in data' in snippet
    assert 'set_setting(\n                "onboarding_completed",' in snippet


def test_api_me_surfaces_onboarding_flag():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_me(")
    snippet = src[idx:idx + 2500]
    assert '"onboarding_completed":' in snippet
    assert 'get_setting("onboarding_completed")' in snippet


# ───────── UI surface ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_onboarding_overlay_exists(index_html: str):
    assert 'id="onboarding-backdrop"' in index_html


def test_four_step_progression(index_html: str):
    """Pin all 4 steps so a future refactor can't silently drop one."""
    for n in (1, 2, 3, 4):
        assert f'data-step="{n}"' in index_html


def test_skip_button_present(index_html: str):
    assert 'id="onboarding-skip"' in index_html


def test_helpers_present(index_html: str):
    for fn in ("maybeShowOnboarding", "showOnboardingStep",
               "_markOnboardingComplete", "finishOnboarding"):
        assert f"function {fn}(" in index_html, fn


def test_skip_persists_flag(index_html: str):
    """Skip must persist completion (both local + remote) so the
    wizard doesn't keep popping every time the user reloads."""
    idx = index_html.find('"#onboarding-skip"')
    snippet = index_html[idx:idx + 400]
    assert "_markOnboardingComplete" in snippet


def test_finish_saves_display_name(index_html: str):
    idx = index_html.find("async function finishOnboarding(")
    snippet = index_html[idx:idx + 1500]
    assert '/api/settings' in snippet
    assert 'display_name' in snippet


def test_localstorage_storage_key_present(index_html: str):
    """A constant key avoids typos drifting the gate behavior
    across reloads."""
    assert "ONBOARDING_STORAGE_KEY" in index_html
    assert '"one_link.onboarding_completed"' in index_html


def test_returning_user_with_peers_skipped(index_html: str):
    """If state.peers.size > 0 the user is returning; the wizard
    must auto-mark complete + close instead of popping."""
    idx = index_html.find("function maybeShowOnboarding(")
    snippet = index_html[idx:idx + 1200]
    assert "state.peers.size > 0" in snippet
    assert "_markOnboardingComplete" in snippet


def test_daemon_persisted_flag_honored(index_html: str):
    """Fresh browser tab on a paired daemon must skip the wizard
    even with no localStorage value, by trusting state.me.onboarding_completed."""
    idx = index_html.find("function maybeShowOnboarding(")
    snippet = index_html[idx:idx + 1200]
    assert "state.me?.onboarding_completed" in snippet


def test_init_pops_after_state_loaded(index_html: str):
    """The wizard call must come AFTER refreshPeers + /api/me so we
    know whether to pop."""
    idx = index_html.find("async function init()")
    snippet = index_html[idx:idx + 2500]
    refresh_idx = snippet.find("await refreshPeers()")
    show_idx = snippet.find("maybeShowOnboarding()")
    assert refresh_idx > 0 and show_idx > refresh_idx


def test_enter_key_advances_name_step(index_html: str):
    """Enter on the name input must advance the wizard — otherwise
    keyboard-first users get stuck pressing the button."""
    # Grab the keydown listener (not the value-read site).
    idx = index_html.find('$("#onboarding-name")?.addEventListener("keydown"')
    assert idx > 0, "missing keydown listener on onboarding-name"
    snippet = index_html[idx:idx + 600]
    assert 'e.key === "Enter"' in snippet


def test_progress_dots_present(index_html: str):
    """Visual progress indicator ties the steps together — pin it
    so a CSS refactor doesn't drop it silently."""
    assert 'id="onboarding-progress"' in index_html
    # Four dots, one per step
    progress_block = index_html[
        index_html.find('id="onboarding-progress"'):
        index_html.find('id="onboarding-progress"') + 500
    ]
    assert progress_block.count('<span class="dot') >= 4


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
