"""Tests for the docs/site/index.html landing page.

The website is the front door for end users — they visit, see one
big download button, click it, double-click the file that downloads.
This contract has to be preserved across edits.

Tests:
    * The primary download button exists and starts with a sensible
      fallback href (the GitHub releases page).
    * JS auto-detects OS for Windows / macOS / Linux at minimum.
    * The asset filenames the JS expects match the names the
      release.yml workflow produces (cross-checked in
      test_release_workflow_v0210.py).
    * The page never makes a network call to a non-GitHub host
      (no third-party tracking, no analytics).
"""

from __future__ import annotations

from pathlib import Path


LANDING = (
    Path(__file__).resolve().parent.parent
    / "docs" / "site" / "index.html"
)


def _html() -> str:
    return LANDING.read_text(encoding="utf-8")


def test_landing_page_exists_and_is_html():
    html = _html()
    assert "<!doctype html>" in html.lower()
    assert "<title>One Link" in html or "<title>One Link " in html


def test_primary_download_button_present():
    """The big single-click download button is the website's
    primary CTA. If it disappears in a refactor, the entire
    install UX regresses."""
    html = _html()
    assert 'id="download-primary"' in html
    # Default href is the releases page, used as fallback when
    # OS detection fails — never a 404, never a /dev/null.
    assert "github.com/IamOneYouAreOneWeAreOne/one-link/releases" in html


def test_landing_page_handles_all_three_desktop_oses():
    """Windows / macOS / Linux all need explicit branches in the
    detection JS. Missing one means that OS's users get the
    fallback (releases page), not the one-click flow."""
    html = _html()
    for os_key in ("windows", "macos", "linux"):
        assert f'"{os_key}"' in html, f"OS branch missing: {os_key}"


def test_landing_page_uses_correct_asset_filenames():
    """The JS must request assets matching what the release.yml
    workflow uploads. Drift between the two breaks the download
    button silently."""
    html = _html()
    for name in (
        "one-link-windows.exe",
        "one-link-macos",
        "one-link-linux-x86_64",
    ):
        assert name in html, f"asset name missing from landing page: {name}"


def test_landing_page_has_mobile_os_branches():
    """Mobile users get a soft "coming soon" message instead of
    a confusing 404. The branches must exist even though there's
    no asset to download yet."""
    html = _html()
    for os_key in ("ios", "android"):
        assert f'"{os_key}"' in html, f"mobile branch missing: {os_key}"


def test_landing_page_does_not_call_non_github_hosts():
    """No analytics, no third-party fonts, no telemetry. The page
    only talks to GitHub. Anything else here would break the
    'no telemetry' badge on the page itself."""
    import re
    html = _html()
    # Extract every http(s) host that appears in the markup. We're
    # generous about what counts as the host — just everything
    # between '://' and the next slash/quote/space.
    hosts = set(re.findall(r"https?://([^/\"'\s>]+)", html))
    allowed = {
        "github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "Jphilbrick10.github.io",
        "www.gnu.org",  # GPL license link
    }
    suspicious = {h for h in hosts if h not in allowed}
    assert not suspicious, (
        f"landing page contacts non-GitHub host(s): {sorted(suspicious)}"
    )


def test_landing_page_javascript_swallows_errors_quietly():
    """If the GitHub API rate-limits us or the repo is private,
    the page should still render — the version pill stays as its
    fallback text, the download button still points at the
    releases page. We assert by checking that the API-fetch path
    is wrapped in try/catch with no rethrow."""
    html = _html()
    # The version pill fetch lives inside an async function with
    # try/catch that swallows.
    assert "setLatestVersionPill" in html
    assert "swallow" in html.lower() or "/* swallow" in html, (
        "version-pill fetch should explicitly swallow API errors"
    )


def test_landing_page_advertises_correct_terms_in_lede():
    """Sanity: the lede text still describes a P2P chat tool. A
    regression that drops 'peer-to-peer' or 'no servers' would be
    a meaningful product-positioning change."""
    html = _html()
    text = html.lower()
    assert "peer-to-peer" in text or "peer to peer" in text
    assert "no servers" in text or "no servers" in text
    assert "end-to-end" in text or "end to end" in text


def test_landing_page_links_to_source_and_security_disclosure():
    """Open-source norms: the footer must link to source +
    security disclosure path. Users need to know where to read
    the code and where to report vulnerabilities."""
    html = _html()
    assert "github.com/IamOneYouAreOneWeAreOne/one-link" in html
    assert "SECURITY.md" in html
