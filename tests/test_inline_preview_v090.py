"""v0.9.0 — inline previews for markdown / code / plain-text files.

When a received file's extension is on the whitelist, the chat
bubble exposes a "Show preview" toggle that fetches the content
via /api/files/{name}/preview and renders inline. Markdown gets a
real subset renderer (headings, lists, quotes, fenced code, hr +
inline syntax). Code gets a line-numbered monospace block. Plain
text gets a wrapping pre.

These tests cover the server endpoint (whitelist, traversal, size
cap, encoding) and the UI helper presence.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

# Use existing inbox-rooting fixture pattern from other tests.
from one_link import paths as paths_mod


@pytest.fixture
def inbox(tmp_path: Path, monkeypatch) -> Path:
    """Point ONE_LINK_HOME at a tmp dir so inbox_dir() resolves
    inside it for the duration of the test."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # paths.py caches data_dir(); reset its memoization if any.
    target = paths_mod.inbox_dir()
    target.mkdir(parents=True, exist_ok=True)
    return target


# ───────── server endpoint shape (smoke) ─────────────────────────────

def test_preview_route_registered():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert (
        'r.add_get(r"/api/files/{name:.+}/preview", '
        'self._guarded(self.api_file_preview))'
    ) in src


def test_preview_handler_present():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert "async def api_file_preview(" in src
    assert "PREVIEW_KINDS" in src
    assert "PREVIEW_MAX_BYTES" in src


def test_preview_kinds_table_includes_markdown_and_code():
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    # Markdown + a few code variants must be present.
    for ext, kind in [("md", "markdown"), ("py", "code"),
                      ("js", "code"), ("yaml", "code"),
                      ("txt", "text"), ("log", "text")]:
        assert f'"{ext}": "{kind}"' in src, f"missing {ext} → {kind}"


def test_preview_size_cap_is_finite():
    """Cap must be small enough that a binary file slipping past
    the whitelist can't OOM the daemon."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    # 256KB is the documented value.
    assert "256 * 1024" in src


def test_preview_handles_unicode_decode_error_gracefully():
    """Bad UTF-8 should fall back to lossy decode, not 500."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_preview(")
    assert idx > 0
    snippet = src[idx:idx + 4000]
    assert "UnicodeDecodeError" in snippet
    assert 'errors="replace"' in snippet


def test_preview_validates_traversal():
    """Path() name normalization must catch ../foo and absolute paths."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_preview(")
    snippet = src[idx:idx + 4000]
    assert "Path(name).name" in snippet
    assert "bad name" in snippet


# ───────── UI helpers ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_preview_kinds_match_server(index_html: str):
    """JS PREVIEW_KINDS Map must mirror the server's PREVIEW_KINDS
    dict — anything browseable client-side must also be servable."""
    assert "const PREVIEW_KINDS = new Map(" in index_html
    # Spot-check parity on a few entries.
    for key in ('["md","markdown"]', '["py","code"]',
                '["txt","text"]', '["yaml","code"]'):
        assert key in index_html, f"missing UI mapping {key}"


def test_markdown_renderer_present(index_html: str):
    assert "function renderMarkdownDoc(" in index_html
    assert "function renderCodePreview(" in index_html
    assert "function renderTextPreview(" in index_html
    assert "function previewKindForName(" in index_html


def test_markdown_renderer_handles_headings(index_html: str):
    """Spot-check the # heading regex is in the renderer body."""
    idx = index_html.find("function renderMarkdownDoc(")
    snippet = index_html[idx:idx + 5000]
    assert r"^(#{1,6})\s+" in snippet


def test_markdown_renderer_handles_fenced_code(index_html: str):
    idx = index_html.find("function renderMarkdownDoc(")
    snippet = index_html[idx:idx + 5000]
    assert "```" in snippet
    assert "<pre>" not in snippet  # built via document.createElement, not raw HTML
    assert 'document.createElement("pre")' in snippet


def test_markdown_renderer_handles_lists(index_html: str):
    idx = index_html.find("function renderMarkdownDoc(")
    snippet = index_html[idx:idx + 5000]
    assert "ulM" in snippet or "[-*+]" in snippet
    assert 'document.createElement(ordered ? "ol" : "ul")' in snippet


def test_code_preview_has_line_numbers(index_html: str):
    """The code preview must include a line-number gutter so 'show
    preview' on a 200-line script is actually useful."""
    idx = index_html.find("function renderCodePreview(")
    snippet = index_html[idx:idx + 1500]
    assert "gutter" in snippet
    assert "ln" in snippet


def test_file_bubble_wires_preview_toggle(index_html: str):
    """Make sure renderFileBubble actually calls previewKindForName
    + creates the host div + fetches via /api/files/.../preview.

    Window is generous because the v0.21.x file-bubble click-to-open
    feature added an outbound-thumbnail block + click handler before
    the preview-toggle wiring — the pin still has to be in the same
    function, not anywhere in the file.
    """
    idx = index_html.find("function renderFileBubble(msg)")
    snippet = index_html[idx:idx + 12000]
    assert "previewKindForName(" in snippet
    assert "preview-toggle-link" in snippet
    assert "/preview" in snippet
    assert "renderPreviewByKind(" in snippet


def test_no_raw_html_in_markdown_renderer(index_html: str):
    """Markdown renderer must NOT use innerHTML or .insertAdjacentHTML
    on user content. XSS risk."""
    idx = index_html.find("function renderMarkdownDoc(")
    snippet = index_html[idx:idx + 5000]
    # Allowed: blocks built with document.createElement + textContent
    # Disallowed: innerHTML = ... raw user content
    assert ".innerHTML =" not in snippet
    assert "insertAdjacentHTML" not in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
