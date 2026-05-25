"""v0.21.x bug-class: ASCII letters used as placeholder glyphs.

After shipping 23+ commits of UX polish, an honest user spotted
the literal ASCII letter `v` rendering as the dropdown caret on
the identity pill (`I am One v`). Then a sweep found two more
('x' as close-button glyph, 'GO' as an onboarding-step glyph).

None of the prior audits caught these because:
  - Plain-English tests assert known-bad -> known-good strings;
    they don't ask "is every visible character intentional?"
  - Playwright tests assert behavior, not visual correctness.
  - Visual-capture screenshots were uploaded as CI artifacts
    but never reviewed by a human.
  - The Explore-agent audits had ~600 word output caps + focused
    on the obvious wins (jargon, vague messages, button labels).

This file is the explicit regression for that bug-class:
placeholder text someone meant to come back to but didn't. Each
test names the specific anti-pattern + greps the rendered HTML.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


_INDEX_HTML = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "index.html"
_PEER_HTML = Path(__file__).resolve().parents[1] / "src" / "one_link" / "web" / "peer.html"


@pytest.fixture(scope="module")
def index_html() -> str:
    return _INDEX_HTML.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def peer_html() -> str:
    return _PEER_HTML.read_text(encoding="utf-8")


# ── single-ASCII-letter elements (the v-as-caret pattern) ──────────


_LOWERCASE_LETTERS = "abcdefghijklmnopqrstuvwxyz"


def _find_single_letter_elements(html: str) -> list[tuple[int, str]]:
    """Return (line_number, snippet) for any element whose visible
    text content is a single lowercase ASCII letter. That's the
    pattern that produced the 'v' caret bug + the 'x' close-button
    bug. Skips elements with class names containing 'mono' (those
    are intentional code displays)."""
    hits: list[tuple[int, str]] = []
    # Match <tag ...>X</tag> where X is one lowercase letter.
    # Conservative: only check <span>, <button>, <div> tags.
    pattern = re.compile(
        r'<(?P<tag>span|button|div)(?P<attrs>[^>]*)>'
        r'\s*(?P<letter>[a-z])\s*'
        r'</\1>',
    )
    line_offsets = [0]
    for c in html:
        if c == "\n":
            line_offsets.append(line_offsets[-1] + 1)
        else:
            line_offsets[-1] += 1
    # Compute byte offset -> line number lazily.
    def _line(pos: int) -> int:
        return html[:pos].count("\n") + 1

    for m in pattern.finditer(html):
        attrs = m.group("attrs")
        # Skip if class name suggests intentional code / mono.
        if 'class="mono' in attrs or "class='mono" in attrs:
            continue
        # Skip if it's literally just <span>I</span> (e.g. 'I am
        # One' would be a problem but we don't render single 'I'
        # as a span anywhere - guard anyway by allowing 'I' since
        # it's the personal pronoun).
        letter = m.group("letter")
        if letter == "i":  # allow the lowercase pronoun 'i' if it ever appears
            continue
        snippet = html[max(0, m.start() - 30): m.end() + 30].replace("\n", " ")
        hits.append((_line(m.start()), snippet))
    return hits


def test_no_single_lowercase_letter_used_as_glyph_in_index(index_html):
    """The 'v as caret' bug class. After fix: NO element in
    index.html should have a single lowercase ASCII letter as
    its entire visible content. Use a proper Unicode glyph
    (▾ ✕ × ↻ etc) instead."""
    hits = _find_single_letter_elements(index_html)
    assert not hits, (
        f"single-lowercase-letter glyphs found in index.html "
        f"(the 'v as caret' bug class):\n"
        + "\n".join(f"  line {ln}: {snippet!r}" for ln, snippet in hits[:10])
    )


def test_no_single_lowercase_letter_used_as_glyph_in_peer(peer_html):
    """Same gate for the phone UI."""
    hits = _find_single_letter_elements(peer_html)
    assert not hits, (
        f"single-lowercase-letter glyphs found in peer.html:\n"
        + "\n".join(f"  line {ln}: {snippet!r}" for ln, snippet in hits[:10])
    )


# ── ASCII letter inside aria-label paired with letter content ──────


def test_close_buttons_use_unicode_x_not_ascii_x(index_html, peer_html):
    """Close-button glyphs MUST use the proper × (multiplication
    sign U+00D7) or ✕ (heavy multiplication X U+2715), NOT the
    ASCII letter 'x'. The ASCII letter renders too small + too
    italic vs the typographic glyph."""
    for name, html in [("index.html", index_html), ("peer.html", peer_html)]:
        bad = re.findall(
            r'<button[^>]*aria-label="[^"]*[Cc]lose[^"]*"[^>]*>\s*x\s*</button>',
            html,
        )
        assert not bad, (
            f"{name}: close buttons using ASCII 'x' instead of × / ✕: "
            f"{bad[:3]}"
        )


# ── placeholder markers (TODO / FIXME / lorem ipsum) ───────────────


def test_no_leftover_todo_or_fixme_in_user_visible_html(index_html, peer_html):
    """TODO / FIXME / XXX / HACK / PLACEHOLDER / 'lorem ipsum' in
    user-visible HTML are unfinished placeholders someone meant
    to come back to. Allowed in HTML comments + JS string
    literals that are clearly internal. Check the rendered
    text-content patterns."""
    forbidden = [
        "TODO",
        "FIXME",
        "PLACEHOLDER",
        "lorem ipsum",
        "Lorem Ipsum",
        "foo bar baz",
    ]
    for name, html in [("index.html", index_html), ("peer.html", peer_html)]:
        # Strip HTML comments + JS // comments before scanning.
        stripped = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
        stripped = re.sub(r"^\s*//.*$", "", stripped, flags=re.MULTILINE)
        for word in forbidden:
            # Match only when it appears as a word INSIDE tag content
            # or as the visible text of an element.
            if re.search(
                rf">\s*[^<]*\b{re.escape(word)}\b[^<]*\s*<", stripped,
            ):
                pytest.fail(
                    f"{name} contains visible {word!r} - "
                    f"unfinished placeholder copy reached user-facing HTML"
                )


# ── onboarding glyph slots use unicode emoji, not text fillers ────


def test_onboarding_glyphs_are_unicode_not_text_fillers(index_html):
    """Each onboarding-step starts with a <div class="onboarding-glyph">
    that contains an emoji / unicode glyph. A previous step used
    the literal text 'GO' as a filler. Pin that every glyph slot
    contains either an emoji, a unicode symbol, or an <img>."""
    # Find every onboarding-glyph div + extract its content.
    glyphs = re.findall(
        r'<div class="onboarding-glyph"[^>]*>(.+?)</div>',
        index_html,
        flags=re.DOTALL,
    )
    assert glyphs, "no onboarding glyphs found - markup restructured?"
    for g in glyphs:
        g_stripped = g.strip()
        if g_stripped.startswith("<img"):
            continue  # img is fine
        # Reject content that's ALL ascii letters (the 'GO' bug).
        if re.fullmatch(r"[A-Za-z]+", g_stripped):
            pytest.fail(
                f"onboarding-glyph contains ASCII-only text {g_stripped!r} - "
                f"use a unicode emoji or an <img> instead"
            )


# ── identity pill caret is a proper chevron ───────────────────────


def test_presence_caret_uses_proper_chevron_glyph(index_html):
    """The presence-pill caret used to be the literal ASCII letter
    'v'. Pin the fix: it must be ▾ (or ▼ or ⌄), with aria-hidden
    so screen readers don't announce the glyph."""
    m = re.search(
        r'<span class="presence-caret"[^>]*>(.+?)</span>',
        index_html,
    )
    assert m, "presence-caret span not found - markup restructured?"
    content = m.group(1).strip()
    assert content != "v", (
        "presence-caret is still the literal ASCII letter 'v'; "
        "use the down-chevron glyph ▾ instead"
    )
    # Positive: should be ▾ (U+25BE) or ▼ (U+25BC) or ⌄ (U+2304).
    assert content in ("▾", "▼", "⌄"), (
        f"presence-caret content {content!r} is not a recognized "
        f"chevron glyph"
    )


# ── example-username leak (Alex / Josh / etc) ─────────────────────


def test_filename_display_strips_internal_collision_prefix(index_html):
    """Files in the daemon's inbox get a `<13-digit-timestamp>_<16-
    hex-hash>_` prefix to guarantee filename uniqueness when two
    peers send the same name. That prefix is useful on disk but
    UGLY in a chat bubble - users were seeing
    '1779676087532_0d1e262c1c60b45f_paper.pdf' instead of
    'paper.pdf'. Pin the displayFileName helper + its use at both
    the chat-bubble + files-list render sites."""
    assert "function displayFileName(" in index_html, (
        "displayFileName helper missing - chat bubbles will show "
        "the internal collision-prefix to users"
    )
    # The regex shape must match the daemon's prefix exactly.
    assert r"^\d{13}_[0-9a-fA-F]{16}_(.+)$" in index_html, (
        "displayFileName's prefix regex must match the daemon's "
        "<timestamp>_<hash>_ format exactly"
    )
    # Chat-bubble render site uses it.
    assert 'displayFileName(msg.name || "file")' in index_html, (
        "chat-bubble file name render must call displayFileName"
    )
    # Files-list render site uses it (display_name fallback chain).
    assert "f.display_name || displayFileName(f.name)" in index_html, (
        "files-pane row name must call displayFileName too"
    )


def test_no_personal_name_examples_in_user_visible_copy(index_html, peer_html):
    """Examples like 'Alex's laptop' or 'Bob's phone' look like
    leftover dev placeholders to a non-technical user. Allowed
    in code comments + audit notes. Forbidden in user-visible
    HTML."""
    # Common engineer-example names that show up in dev-stage UIs.
    forbidden_names = ["Alex's", "Alice's", "Bob's", "Charlie's", "Josh's"]
    for name, html in [("index.html", index_html), ("peer.html", peer_html)]:
        stripped = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
        for personal in forbidden_names:
            if re.search(rf">\s*[^<]*{re.escape(personal)}[^<]*\s*<", stripped):
                pytest.fail(
                    f"{name} contains {personal!r} in user-visible copy; "
                    f"use a generic example like 'Family Photos' or "
                    f"'My laptop' instead"
                )
