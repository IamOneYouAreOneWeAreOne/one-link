"""A release bundle must not carry developer diagnostics.

Audit finding: `one_link/web/dr_test.html` -- a Double Ratchet self-test
harness, served UNGUARDED at `/dr_test` -- was present in the shipped Windows
bundle (verified against the live `auto-latest` artifact). It is loopback-only
and CSP-locked and exposes no secrets, so the severity is low, but it is
surface a user never asked for and cannot benefit from.

The route already has the right behaviour for a bundle without it:

    p = WEB_DIR / "dr_test.html"
    if not p.is_file():
        return web.Response(status=404, text="dr_test.html not bundled")

That branch existed and was unreachable, because the packaging always shipped
the file. Excluding it in the build makes the 404 the real shipped behaviour.

These tests pin both halves -- the exclusion in the build, and the daemon
answering 404 rather than raising when the file is absent -- because either one
alone would let the page come back.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BUILDER = REPO / "scripts" / "build_binary.py"


def test_the_builder_excludes_the_self_test_page() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    assert "one_link/web/dr_test.html" in text, (
        "dr_test.html is no longer excluded from release bundles"
    )
    # Both separators, because the filter matches raw PyInstaller source paths.
    #
    # Asserted against the SOURCE TEXT, not a normalised copy. The first version
    # of this line did `text.replace("\\\\", "\\")` first, which accepted both
    # the correct `"one_link\\web\\..."` and the single-backslash form I had
    # actually written. `\w` and `\d` are invalid escape sequences: Python keeps
    # the backslash, so the value was right by accident, while emitting a
    # SyntaxWarning that will become an error in a future release. The build
    # printed that warning on every run and this test stayed green -- a
    # deliberately lenient assertion is a gate that cannot fail.
    assert '"one_link\\\\web\\\\dr_test.html"' in text, (
        "the Windows-separator exclusion must be written with escaped "
        "backslashes, matching the neighbouring entries"
    )
    assert '"one_link\\web\\dr_test.html"' not in text.replace('\\\\', '\x00'), (
        "the exclusion uses raw backslashes, which are invalid escape sequences"
    )


def test_the_exclusion_sits_with_the_other_forbidden_paths() -> None:
    """It must be in the list the spec actually applies, not a stray constant."""
    text = BUILDER.read_text(encoding="utf-8")
    start = text.index("forbidden_paths = [")
    end = text.index("]", start)
    block = text[start:end]
    assert "dr_test.html" in block, (
        "the exclusion is not inside forbidden_paths, so the spec filter will "
        "never see it"
    )


@pytest.mark.asyncio
async def test_the_route_answers_404_when_the_page_is_absent(tmp_path, monkeypatch) -> None:
    """The shipped behaviour once the file is gone.

    Without this, excluding the asset could turn a harmless page into a 500 on
    a route that is still registered -- trading a low-severity finding for a
    higher-severity one.
    """
    from one_link import server as server_mod

    monkeypatch.setattr(server_mod, "WEB_DIR", tmp_path)
    ui = server_mod.UIServer.__new__(server_mod.UIServer)
    response = await ui._dr_test_page(None)  # type: ignore[arg-type]
    assert response.status == 404
    assert "not bundled" in response.text


@pytest.mark.asyncio
async def test_the_route_still_serves_when_the_page_IS_present(tmp_path, monkeypatch) -> None:
    """Control: the 404 above must come from ABSENCE, not from a broken route."""
    from one_link import server as server_mod

    (tmp_path / "dr_test.html").write_text("<h1>self test</h1>", encoding="utf-8")
    monkeypatch.setattr(server_mod, "WEB_DIR", tmp_path)
    ui = server_mod.UIServer.__new__(server_mod.UIServer)
    response = await ui._dr_test_page(None)  # type: ignore[arg-type]
    assert response.status == 200
    assert "self test" in response.text
    assert "default-src 'self'" in response.headers.get("Content-Security-Policy", "")
