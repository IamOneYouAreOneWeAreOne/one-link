"""v0.9.5 — inline PDF preview via browser-native viewer.

PDFs were deferred from v0.9.0 because vendoring PDF.js (~600 KB)
seemed disproportionate. v0.9.5 takes the simpler path: ship an
<iframe src=/api/files/{name}> + let the browser render it. Every
modern browser (Chrome, Edge, Safari, Firefox) ships PDF support
natively, so we add zero vendored bytes.

Server returns metadata only for PDFs (no content read), so a
100 MB PDF doesn't OOM the daemon.

These tests pin the contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest


# ───────── server endpoint ───────────────────────────────────────────

def test_pdf_in_preview_kinds():
    """Server's PREVIEW_KINDS must list pdf so the whitelist check
    in api_file_preview lets PDFs through."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert '"pdf": "pdf"' in src


def test_pdf_handler_does_not_read_bytes():
    """A 100 MB PDF can't be read into memory. The handler must
    short-circuit BEFORE the cap-read for kind='pdf'."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_preview(")
    snippet = src[idx:idx + 4000]
    # The pdf-special-case branch must be reached BEFORE the cap read.
    pdf_idx = snippet.find('if kind == "pdf":')
    read_idx = snippet.find("path.open(\"rb\")")
    assert pdf_idx > 0
    assert read_idx > 0
    assert pdf_idx < read_idx


def test_pdf_response_has_stream_url():
    """The PDF metadata response must include a stream_url so the
    UI's iframe knows where to point."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_file_preview(")
    snippet = src[idx:idx + 4000]
    assert '"stream_url"' in snippet
    assert "/api/files/" in snippet


# ───────── UI surface ────────────────────────────────────────────────

@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


def test_preview_kinds_map_includes_pdf(index_html: str):
    assert '["pdf","pdf"]' in index_html


def test_pdf_renderer_present(index_html: str):
    assert "function renderPdfPreview(" in index_html


def test_pdf_renderer_uses_iframe(index_html: str):
    """No inline raw-HTML — must use document.createElement('iframe')."""
    idx = index_html.find("function renderPdfPreview(")
    snippet = index_html[idx:idx + 1500]
    assert 'document.createElement("iframe")' in snippet
    # Forbid raw-HTML setting.
    assert "innerHTML =" not in snippet


def test_pdf_iframe_is_sandboxed(index_html: str):
    """The PDF iframe must include a sandbox attribute so a
    malicious PDF (yes, that's a thing) can't break out into the
    parent doc."""
    idx = index_html.find("function renderPdfPreview(")
    snippet = index_html[idx:idx + 1500]
    assert 'setAttribute(\n      "sandbox"' in snippet or 'setAttribute("sandbox"' in snippet


def test_pdf_renderer_dispatch_wired(index_html: str):
    """renderPreviewByKind must dispatch kind === 'pdf' to the
    PDF renderer."""
    idx = index_html.find("function renderPreviewByKind(")
    snippet = index_html[idx:idx + 1000]
    assert 'kind === "pdf"' in snippet
    assert "renderPdfPreview(" in snippet


def test_file_bubble_passes_stream_url(index_html: str):
    """The file-bubble caller must thread stream_url + name through
    so the iframe gets a valid src."""
    idx = index_html.find("function renderFileBubble(msg)")
    snippet = index_html[idx:idx + 12000]
    assert "stream_url" in snippet


def test_pdf_fallback_link_present(index_html: str):
    """If the browser's built-in PDF viewer is disabled, an
    'Open PDF in new tab' anchor must be visible as fallback."""
    idx = index_html.find("function renderPdfPreview(")
    snippet = index_html[idx:idx + 1500]
    assert "Open PDF in new tab" in snippet


def test_pdf_iframe_lazy_loaded(index_html: str):
    """Lazy-loading the iframe avoids a fetch until the user
    scrolls to the bubble. Cheap, big win on big chats."""
    idx = index_html.find("function renderPdfPreview(")
    snippet = index_html[idx:idx + 1500]
    assert 'setAttribute("loading", "lazy")' in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
