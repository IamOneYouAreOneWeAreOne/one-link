"""v0.21.x preview-system polish: file-bubble UX + format coverage.

Four discrete bugs surfaced in user testing, plus a feature expansion:

1. PDF preview iframe rendered a sad-face icon. Cause: the global
   security middleware sets ``X-Frame-Options: DENY`` on every
   response, which blocks the iframe from rendering /api/files/{name}
   even though both parent + iframe are same-origin.

2. Clicking the file-bubble 'Details' disclosure also bubbled up to
   the bubble's whole-bubble click handler, which opens the file in a
   new tab. User saw the file open instead of the details panel
   expanding.

3. The conversation search input had a redundant 'Search' label
   span absolute-positioned over the input's placeholder text,
   producing overlapping characters ('SearcSearch this...').

4. Preview kinds were limited to pdf/markdown/code/text. Modern users
   expect inline rendering for video, audio, SVG, and HTML files too.
"""
from __future__ import annotations

from pathlib import Path

import pytest


# Module-level cached reads keep the suite quick.
_INDEX_HTML_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
)
_SERVER_PY_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "one_link" / "server.py"
)


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def server_src() -> str:
    return _SERVER_PY_PATH.read_text(encoding="utf-8")


# ── Bug 1: PDF iframe blocked by X-Frame-Options ──────────────────


def test_api_file_download_overrides_x_frame_options_for_inline_preview(server_src):
    """The global security middleware sets X-Frame-Options: DENY on
    every response (server.py:1150). /api/files/{name} is the src
    target of the inline PDF/video/audio preview iframe, so it MUST
    override DENY with SAMEORIGIN (or the modern CSP equivalent)
    or the iframe stays blank.

    Pin the override so a future security pass that removes it
    breaks the preview UX in CI rather than in the user's browser."""
    idx = server_src.find("async def api_file_download(")
    assert idx > 0, "api_file_download handler not found"
    end = server_src.find("\n    async def ", idx + 10)
    body = server_src[idx:end if end > 0 else idx + 2000]
    assert '"X-Frame-Options": "SAMEORIGIN"' in body, (
        "/api/files/{name} response must override the global "
        "X-Frame-Options: DENY with SAMEORIGIN so the inline "
        "preview iframe can render"
    )
    assert 'frame-ancestors' in body, (
        "Modern browsers honor CSP frame-ancestors over the legacy "
        "X-Frame-Options header; both must be set"
    )


# ── Bug 2: Details click bubbles to bubble-open handler ────────────


def test_file_bubble_click_handler_exempts_details_disclosure(index_html):
    """Clicking the <details><summary>Details</summary>... disclosure
    inside a completed file bubble used to also fire the bubble's
    own click handler, which calls openMessageFile and opens the
    file in a new tab. The exemption selector must include
    'details' and 'summary' so the disclosure toggles cleanly
    without hijacking the user's click."""
    # Locate the openHandler exemption block.
    idx = index_html.find("openHandler = (ev) => {")
    assert idx > 0, "file-bubble openHandler not found"
    body = index_html[idx:idx + 1200]
    assert "details, summary" in body, (
        "openHandler's ev.target.closest(...) exemption list must "
        "include 'details, summary' so clicking the file-bubble's "
        "Details disclosure doesn't also open the file"
    )


# ── Bug 3: search input overlapping placeholder / icon-trigger ─────


def test_conversation_search_icon_trigger_does_not_collide_with_placeholder(index_html):
    """The conversation header has a search wrapper with an
    icon-trigger span absolute-positioned at left:8px inside an
    input whose placeholder reads 'Search this conversation…'.
    The span used to contain the literal word 'Search', which
    overlapped with the placeholder's leading 'Search' producing
    the visible 'SearcSearch this...' garble.

    The fix: replace the literal word with a magnifier icon
    glyph that fits in the 22px padding gap."""
    idx = index_html.find('<div class="search" id="search-wrap">')
    assert idx > 0, "search wrapper not found in convo header"
    body = index_html[idx:idx + 400]
    # The literal text 'Search' inside the icon-trigger span is the bug.
    assert '<span class="icon-trigger">Search</span>' not in body, (
        "icon-trigger must not contain the literal word 'Search' - "
        "it overlaps with the input's placeholder"
    )
    # And the magnifier emoji should be in place.
    assert '🔍' in body, (
        "icon-trigger should use a magnifier glyph (🔍) so the "
        "visual stays inside the 22px padding gap"
    )


# ── Bug 4: preview format coverage expansion ───────────────────────


@pytest.mark.parametrize("ext,expected_kind", [
    # Video
    ("mp4", "video"),
    ("webm", "video"),
    ("mov", "video"),
    ("m4v", "video"),
    ("mkv", "video"),
    ("ogv", "video"),
    # Audio (attached, not voice-note recordings)
    ("mp3", "audio"),
    ("wav", "audio"),
    ("ogg", "audio"),
    ("oga", "audio"),
    ("m4a", "audio"),
    ("aac", "audio"),
    ("flac", "audio"),
    ("opus", "audio"),
    # SVG -> image kind (renders via <img>)
    ("svg", "image"),
    # HTML -> sandboxed iframe (no credentials)
    ("html", "html-sandboxed"),
    ("htm", "html-sandboxed"),
])
def test_server_preview_kinds_cover_modern_formats(ext, expected_kind):
    """Every common video/audio/svg/html extension a normal user
    sends MUST map to a stream-able preview kind on the server.
    Anything missing here means the user gets a 415 'preview not
    available' response, which means the preview link doesn't
    appear at all."""
    from one_link.server import UIServer
    assert UIServer.PREVIEW_KINDS.get(ext) == expected_kind, (
        f".{ext} files must preview as '{expected_kind}'; got "
        f"{UIServer.PREVIEW_KINDS.get(ext)!r}"
    )


def test_stream_kinds_return_stream_url_metadata_not_bytes(tmp_path, monkeypatch):
    """For stream-able kinds the daemon returns metadata + a
    stream_url; it must NOT read the bytes into memory (a 5 GB
    video would OOM the daemon). Pin by inspecting the preview
    handler's source."""
    src = _SERVER_PY_PATH.read_text(encoding="utf-8")
    idx = src.find('if kind in ("pdf", "video", "audio", "image", "html-sandboxed"):')
    assert idx > 0, (
        "preview handler must early-return for stream-able kinds "
        "before reading any bytes"
    )
    # The metadata branch must end with `stream_url` and must NOT
    # contain a path.open() above the early-return.
    above = src[max(0, idx - 1500):idx]
    assert "path.open(" not in above, (
        "preview handler reads bytes before the stream-kind early "
        "return - a large video would OOM the daemon"
    )


@pytest.mark.parametrize("kind,renderer_name,el_tag", [
    ("video", "renderVideoPreview", "<video"),
    ("audio", "renderAudioPreview", "<audio"),
    ("image", "renderImagePreview", "<img"),
    ("html-sandboxed", "renderHtmlPreview", "<iframe"),
])
def test_index_html_has_renderer_for_each_stream_kind(
    index_html, kind, renderer_name, el_tag,
):
    """Every server-side preview kind needs a matching client
    renderer wired into renderPreviewByKind. Pin: the renderer
    function exists, dispatches the right HTML element, and is
    referenced from the kind dispatcher."""
    assert f"function {renderer_name}(" in index_html, (
        f"renderer {renderer_name} for kind '{kind}' is missing"
    )
    # Dispatcher branches on the kind.
    dispatch_idx = index_html.find("function renderPreviewByKind(")
    assert dispatch_idx > 0
    dispatch_body = index_html[dispatch_idx:dispatch_idx + 1800]
    assert f'kind === "{kind}"' in dispatch_body, (
        f"renderPreviewByKind dispatcher missing branch for '{kind}'"
    )
    assert renderer_name in dispatch_body, (
        f"renderPreviewByKind dispatcher does not call {renderer_name}"
    )


def test_html_preview_iframe_is_credential_less_sandboxed(index_html):
    """An HTML file sender could be malicious. The HTML preview
    iframe MUST NOT include 'allow-same-origin' in its sandbox -
    that flag is what lets embedded content read the host's
    cookies / localStorage / make authenticated fetches back to
    the daemon. Scripts are still allowed (an HTML file with no JS
    is rare), but they run in a credential-less anonymous origin."""
    idx = index_html.find("function renderHtmlPreview(")
    assert idx > 0
    body = index_html[idx:idx + 1500]
    # Extract the sandbox value.
    import re
    m = re.search(r'sandbox["\s,]*"([^"]+)"', body)
    assert m, "renderHtmlPreview must set a sandbox attribute"
    sandbox = m.group(1)
    assert "allow-same-origin" not in sandbox, (
        "HTML preview sandbox MUST NOT grant allow-same-origin - "
        "that would let attacker HTML read One Link cookies and "
        "make authenticated daemon API calls"
    )
    assert "allow-scripts" in sandbox, (
        "HTML preview should still allow scripts (an HTML page "
        "with no JS is rare); the credential gap is the security "
        "boundary, not script execution"
    )


def test_search_zero_results_shows_no_matches_state_not_welcome(index_html):
    """When a conversation search returns 0 hits, the chat area
    must render a dedicated 'No matches' empty state - NOT the
    paired-but-never-messaged welcome screen ('Send the first
    message...'). The welcome screen is misleading after the
    user has explicitly searched + sees the 0-results banner.

    Pin: the search-empty branch (a) is GUARDED by the
    state.searchResults != null check, (b) renders BEFORE the
    first-action-empty welcome branch (otherwise the welcome
    branch wins by virtue of running first), and (c) ships a
    'Clear search' button so the user has an obvious way out
    without scrolling back to the header."""
    # Find renderMessages's filtered-empty handling.
    idx = index_html.find("if (filtered.length === 0 && state.searchResults != null)")
    assert idx > 0, (
        "search-aware empty-state branch is missing from "
        "renderMessages - filtered=[] would fall through to the "
        "first-action-empty welcome screen even during search"
    )
    branch = index_html[idx:idx + 1800]
    assert '"search-empty"' in branch, (
        "search-empty branch must use the .search-empty class so "
        "CSS reuses the empty-state look without showing the "
        "welcome chips"
    )
    assert "No matches" in branch
    assert "Clear search" in branch, (
        "the no-results state needs a one-click escape - mirror "
        "the search banner's Clear button"
    )
    # The search-empty branch must come BEFORE the first-action
    # branch so it wins for the search-with-0-hits case.
    welcome_idx = index_html.find("first-action-empty", idx)
    assert welcome_idx > idx, (
        "search-empty branch must be ordered BEFORE the "
        "first-action-empty welcome branch or the welcome branch "
        "still wins"
    )


def test_search_empty_state_shares_styling_with_welcome_state(index_html):
    """CSS: .search-empty must reuse the .first-action-empty visual
    treatment so the two empty states feel like one design
    language. Pin: the selector list includes both."""
    # Find the CSS rule.
    css_idx = index_html.find(".first-action-empty,\n  .search-empty")
    assert css_idx > 0, (
        ".search-empty must be added to the .first-action-empty "
        "selector list so the no-matches state inherits the "
        "centered card layout instead of falling through to "
        "browser defaults"
    )


def test_client_preview_kinds_match_server_preview_kinds(index_html, server_src):
    """The client-side PREVIEW_KINDS Map gates whether the 'Show
    preview' link APPEARS in a file bubble. If it lags behind the
    server's whitelist, a .mp4 from a peer never gets a preview
    offer even though the daemon would happily serve it.

    Pin: every server-side ext keyword appears in the client-side
    Map for the four newly-added kinds."""
    new_exts = (
        "mp4", "webm", "mov", "m4v", "mkv", "ogv",
        "mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "opus",
        "svg",
        "html", "htm",
    )
    # Slice the PREVIEW_KINDS Map literal so we don't false-match
    # on the same string elsewhere in the 30k-line file.
    map_idx = index_html.find("const PREVIEW_KINDS = new Map([")
    assert map_idx > 0
    map_end = index_html.find("]);", map_idx)
    map_body = index_html[map_idx:map_end]
    for ext in new_exts:
        assert f'"{ext}"' in map_body, (
            f"client-side PREVIEW_KINDS Map missing .{ext} - "
            f"users won't see a 'Show preview' link on this format"
        )
