"""v0.21.x browser-driven E2E tests.

Catches the bug-class that pure code audits cannot see: pixel
overlap, iframe security headers blocking inline previews, click
handlers hijacking disclosure widgets, dialog z-order regressions,
welcome-state appearing under a 0-results search banner, single-
letter searches returning nothing, etc.

Tests in this directory load the real `src/one_link/web/index.html`
in a real Chromium via Playwright, interact with the DOM the way a
user would, and assert outcomes the way a user would experience them.

Run with:

    pip install -e .[e2e]
    playwright install chromium    # one-time
    python -m pytest tests/e2e -v
"""
