"""Visual capture: take screenshots of every key UI surface and
save them as CI artifacts for human review.

This is the pragmatic Phase 2 form. Full pixel-diff visual regression
needs more infrastructure than this session can ship cleanly (font
rendering varies by OS Chromium build, the Python Playwright bindings
don't ship `to_have_screenshot` snapshot comparison like the TS ones
do, and the cross-OS-baseline problem needs either a snapshot library
like syrupy or a fuzzy-comparison helper).

What we ship instead: a test that ALWAYS passes (never gates CI on a
pixel) but always captures named screenshots into the configured
artifact dir. CI's upload-artifact step already retains
`test-results/` on the e2e job, so screenshots travel out for human
eyeball review every push.

When you ship a UI change:
  1. Run this test locally, look at the new screenshots in
     tests/e2e/screenshots/.
  2. Compare them by eye to the previous run.
  3. If the change is intentional, commit the new screenshots.

The screenshot files THEMSELVES become the de-facto baselines in
git history - any future visual reviewer can `git log -p` a
screenshot file and see exactly when + why a UI surface changed.
"""
from __future__ import annotations

from pathlib import Path

import pytest


_SCREENSHOT_DIR = Path(__file__).resolve().parent / "screenshots"


@pytest.fixture(autouse=True, scope="module")
def _ensure_screenshot_dir():
    _SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)


def _capture(page, name: str, *, locator=None, full_page: bool = False):
    """Capture a screenshot to tests/e2e/screenshots/<name>.png."""
    out = _SCREENSHOT_DIR / f"{name}.png"
    # Stabilize: hide time-varying elements (ping ms, presence
    # timestamps, animated chrome) so successive captures of the
    # same state are pixel-stable across runs on the same machine.
    page.add_style_tag(content="""
        .latency-pill, [data-pulse-ts], #activity-since-clock,
        #presence-ts, time, .toast, .toast-container,
        #onboarding-backdrop { visibility: hidden !important; }
        * { animation-duration: 0s !important;
            transition-duration: 0s !important; }
    """)
    if locator is not None:
        locator.screenshot(path=str(out))
    else:
        page.screenshot(path=str(out), full_page=full_page)
    return out


# ── named captures ──────────────────────────────────────────────────


def test_capture_initial_ui(ui_page):
    """The boot state every user sees on first connect."""
    ui_page.wait_for_load_state("networkidle")
    path = _capture(ui_page, "01_initial_ui", full_page=False)
    assert path.is_file()


def test_capture_top_navigation(ui_page):
    """Top nav: Chat / Files / Folders / Activity + identity chip."""
    ui_page.wait_for_load_state("networkidle")
    nav = ui_page.locator(".convo-h, .top-nav, header").first
    if nav.count() == 0:
        pytest.skip("top nav not found")
    path = _capture(ui_page, "02_top_navigation", locator=nav)
    assert path.is_file()


def test_capture_sidebar(ui_page):
    """Left sidebar with identity + devices + pair button."""
    ui_page.wait_for_load_state("networkidle")
    sidebar = ui_page.locator(".sidebar, #sidebar").first
    if sidebar.count() == 0:
        pytest.skip("sidebar not found")
    path = _capture(ui_page, "03_sidebar_empty", locator=sidebar)
    assert path.is_file()


def test_capture_files_pane(ui_page):
    """Files pane (empty inbox state)."""
    ui_page.wait_for_load_state("networkidle")
    files_btn = ui_page.get_by_text("Files", exact=True).first
    if files_btn.count() == 0:
        pytest.skip("Files tab not found")
    files_btn.click()
    ui_page.wait_for_timeout(400)
    path = _capture(ui_page, "04_files_pane")
    assert path.is_file()


def test_capture_folders_pane(ui_page):
    """Folders pane with the Add form + Browse button - the
    surface we just fixed the picker bug in."""
    ui_page.wait_for_load_state("networkidle")
    folders_btn = ui_page.get_by_text("Folders", exact=True).first
    if folders_btn.count() == 0:
        pytest.skip("Folders tab not found")
    folders_btn.click()
    ui_page.wait_for_timeout(400)
    path = _capture(ui_page, "05_folders_pane")
    assert path.is_file()


def test_capture_activity_pane(ui_page):
    """Activity pane (empty state on a fresh daemon)."""
    ui_page.wait_for_load_state("networkidle")
    activity_btn = ui_page.get_by_text("Activity", exact=True).first
    if activity_btn.count() == 0:
        pytest.skip("Activity tab not found")
    activity_btn.click()
    ui_page.wait_for_timeout(400)
    path = _capture(ui_page, "06_activity_pane")
    assert path.is_file()


def test_capture_search_input_open(ui_page):
    """The search input we just fixed (icon-trigger vs placeholder
    overlap). Force-show + capture the open state via clip-region
    so we don't depend on the parent .convo-h visibility (which
    requires a peer to be selected)."""
    ui_page.wait_for_load_state("networkidle")
    # Force the search wrap visible regardless of parent state by
    # injecting CSS that overrides the conditional display.
    ui_page.evaluate(
        """() => {
            const w = document.getElementById('search-wrap');
            if (!w) return;
            w.classList.add('open');
            w.style.cssText =
                'position:fixed;top:8px;right:8px;'
              + 'display:flex;width:280px;z-index:99999;'
              + 'background:var(--bg-2);padding:6px;border-radius:6px;';
        }"""
    )
    ui_page.wait_for_timeout(300)
    search = ui_page.locator("#search-wrap").first
    if search.count() == 0:
        pytest.skip("search wrap not present in this build")
    if not search.is_visible():
        pytest.skip("could not force search wrap visible")
    path = _capture(ui_page, "07_search_input_open", locator=search)
    assert path.is_file()
