"""Doctrine of Invisibility lint.

Enforces the forbidden-surface catalog from
``docs/DOCTRINE_OF_INVISIBILITY.md §3`` against the user-facing
source. Every PR runs this; a match without an inline exemption
fails the build.

Exemption syntax (inline, in the line containing the match OR the
line immediately above):

    // doctrine-ok: <reason or §X.Y.Z reference>
    <!-- doctrine-ok: <reason or §X.Y.Z reference> -->
    # doctrine-ok: <reason or §X.Y.Z reference>

The reason should cite a doctrine clause or a written ADR. The lint
does not inspect the reason content; reviewers do, in PR review.

Scope (the surfaces this lint covers):

    src/one_link/web/index.html
    src/one_link/web/peer.html
    src/one_link/web/sw.js

dr.js / dr_test.html / manifest.json are intentionally OUT of scope
(internal dev test pages, not part of the user surface).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Source paths
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "src" / "one_link" / "web"

# Files that are part of the user-facing surface. Each is linted in
# strict mode unless explicitly exempted at the line via the
# annotation syntax above.
USER_FACING_FILES = (
    WEB_DIR / "index.html",
    WEB_DIR / "peer.html",
    WEB_DIR / "sw.js",
)


# ---------------------------------------------------------------------------
# Forbidden patterns — one per clause in DOCTRINE_OF_INVISIBILITY.md §3
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Clause:
    id: str           # e.g. "§3.1.a"
    name: str         # e.g. "No advanced settings menu"
    pattern: re.Pattern[str]


def _p(pat: str) -> re.Pattern[str]:
    return re.compile(pat, re.IGNORECASE)


CLAUSES: tuple[Clause, ...] = (
    # §3.1 Configuration surfaces
    Clause("§3.1.a", "No advanced settings menu",
           _p(r"\b(advanced|developer|power[- ]?user)\s+(settings|options|mode)\b")),
    Clause("§3.1.b", "No codec picker",
           _p(r"\b(codec|encoding|bitrate)\s+(picker|selector|preference|chooser)\b")),
    Clause("§3.1.c", "No device picker mid-call",
           _p(r"\b(microphone|camera|speaker|display)\s+selector\b")),
    Clause("§3.1.d", "No relay/route picker",
           _p(r"\b(relay|turn|p2p)\s+(mode|toggle|preference|selector)\b")),
    Clause("§3.1.e", "No bandwidth/quality picker",
           _p(r"\b(hd|sd|low[- ]?data|save[- ]?data|data[- ]?saver)\s+mode\b")),
    Clause("§3.1.f", "No per-conversation notification settings",
           _p(r"\b(ringtone|vibration|notification)\s+(picker|selector|preference)\b")),

    # §3.2 Error / status surfaces
    Clause("§3.2.a", "No 'Reconnecting...' overlay",
           _p(r"\b(reconnecting|reestablishing|trying[- ]?to[- ]?connect)\b")),
    Clause("§3.2.b", "No 'Connection unstable' toast",
           _p(r"\b(connection|network)\s+(unstable|poor|weak|slow)\b")),
    Clause("§3.2.c", "No quality bars or signal indicators",
           _p(r"\b(signal|connection|quality)\s+(bar|indicator|strength)\b")),
    Clause("§3.2.c.2", "No good/fair/poor connection label",
           _p(r"\b(good|fair|poor)\s+connection\b")),
    Clause("§3.2.d", "No error codes (Error NNN / 0xNNN)",
           _p(r"\berror\s+code\s*[:#]?\s*\d+\b")),
    Clause("§3.2.e", "No 'Call failed'",
           _p(r"\bcall\s+(failed|could[- ]?not|disconnected|lost)\b")),
    Clause("§3.2.f", "No 'User not registered'",
           _p(r"\b(not\s+(registered|installed|a\s+user)|doesn'?t\s+have)\b\s+(one\s*link)?")),
    Clause("§3.2.g", "No 'Update required to call'",
           _p(r"\b(update|upgrade)\s+(required|needed)\b")),
    Clause("§3.2.h", "No 'Please try again'",
           _p(r"\bplease\s+try\s+again\b")),

    # §3.3 Modal interruptions
    Clause("§3.3.a", "No CAPTCHA",
           _p(r"\b(captcha|recaptcha|hcaptcha|human\s+verification)\b")),
    Clause("§3.3.b", "No 'Verify your phone/email'",
           _p(r"\bverify\s+your\s+(phone|email)\b")),
    Clause("§3.3.d", "No 'Are you sure?' confirmations",
           _p(r"\bare\s+you\s+sure\b")),
    Clause("§3.3.d.2", "No 'Confirm hangup' style modals",
           _p(r"\bconfirm\s+(hangup|end\s+call|delete\s+conversation)\b")),
    Clause("§3.3.e", "No analytics consent banner",
           _p(r"\b(cookies?|analytics|telemetry|diagnostics)\s+(banner|consent|opt[- ]?in)\b")),

    # §3.4 Tiering / commerce
    Clause("§3.4.a", "No paywall",
           _p(r"\bunlock\s+(premium|pro|plus|hd)\b")),
    Clause("§3.4.a.2", "No subscribe upsell",
           _p(r"\b(subscribe|upgrade)\s+(to|for)\s+(pro|premium|plus|hd|unlimited)\b")),
    Clause("§3.4.a.3", "No in-app purchase surface",
           _p(r"\b(in[- ]?app[- ]?purchase|iap|monthly[- ]?plan|annual[- ]?plan)\b")),
    Clause("§3.4.b", "No 'Get HD' upsell",
           _p(r"\b(hd|4k|hi[- ]?def)\s+(upgrade|plan|tier)\b")),
    Clause("§3.4.c", "No region-locked features",
           _p(r"\b(unavailable|not\s+available)\s+in\s+your\s+(country|region|area)\b")),
    Clause("§3.4.d", "No 'Limited time offer'",
           # Catches commerce-urgency framing. Does NOT catch
           # "expires in N minutes" — that's a legitimate security-
           # affordance TTL (pair codes, capability tokens). Pure
           # countdown surfaces on a call surface are caught by
           # §3.11.a instead.
           _p(r"\b(limited[- ]?time(\s+(offer|deal))?|act\s+now|only\s+\d+\s+(left|remaining)\s+at\s+this\s+price)\b")),

    # §3.5 Privacy theater
    Clause("§3.5.a", "No vague 'bank-level encryption' reassurance",
           _p(r"\b(bank[- ]?level|military[- ]?grade|enterprise[- ]?grade)\s+(encryption|security)\b")),
    Clause("§3.5.a.2", "No 'Your privacy matters' platitude",
           _p(r"\byour\s+privacy\s+matters\b")),
    Clause("§3.5.b", "No 'Recorded for quality assurance'",
           _p(r"\bmay\s+be\s+recorded\b")),
    Clause("§3.5.b.2", "No 'recorded for quality'",
           _p(r"\b(recorded|recording)\s+for\s+quality\b")),

    # §3.6 Hardware abstraction leaks
    Clause("§3.6.a", "No 'Battery low; call may end'",
           _p(r"\bbattery\s+(low|warning|critical)\b")),
    Clause("§3.6.b", "No thermal warnings",
           _p(r"\b(overheating|device\s+is\s+hot|performance\s+throttled)\b")),
    Clause("§3.6.c", "No network type labels",
           _p(r"\bon\s+(wi[- ]?fi|cellular|5g|4g|lte|3g)\b")),

    # §3.7 Process leaks
    Clause("§3.7.a", "No 'Establishing connection...' style process indicators",
           _p(r"\b(establishing|negotiating|handshaking|authenticating)\s+(connection|session|call|key)\b")),
    Clause("§3.7.c", "No 'Checking for updates...' at call time",
           _p(r"\bchecking\s+for\s+updates?\b")),

    # §3.8 Reactive degradation surfaces
    Clause("§3.8.a", "No 'Switching to audio only' notification",
           _p(r"\bswitching\s+to\s+(audio[- ]?only|low[- ]?quality)\b")),
    Clause("§3.8.b", "No 'Network slow / bandwidth limited' label",
           _p(r"\b(network|bandwidth)\s+(slow|limited|low)\s+(mode|warning|notice)\b")),
    Clause("§3.8.c", "No 'Reducing video quality' announcement",
           _p(r"\b(reducing|lowering)\s+(video\s+)?(quality|resolution|bitrate)\b")),

    # §3.9 Identity surfaces — raw fingerprint hex (NN:NN:NN:...)
    Clause("§3.9.a", "No raw colon-separated fingerprint hex",
           _p(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){4,}\b")),
    Clause("§3.9.b", "No PEM key blocks in UI",
           _p(r"-{3,}\s*BEGIN\s+(\w+\s+)?KEY\s*-{3,}")),
    Clause("§3.9.c", "No 'Trust level / trust score' UI",
           _p(r"\btrust\s+(level|score)\b")),
    Clause("§3.9.c.2", "No 'NN% trust' UI",
           _p(r"\b\d+%\s+trust\b")),
    Clause("§3.9.d", "No 'Please add a profile picture' requirement",
           _p(r"\b(required|please\s+add)\b[^.\n]{0,40}\b(profile\s+picture|avatar|display\s+name)\b")),

    # §3.10 Persistence / history
    Clause("§3.10.a", "No 'Missed call(s)' surface",
           _p(r"\b(missed\s+call|missed\s+\(?\d+\)?\s+calls?)\b")),
    Clause("§3.10.b", "No 'Call history' / 'Call log' / 'Recents' tab",
           _p(r"\bcall\s+(log|history|recents?)\b")),
    Clause("§3.10.c", "No 'Delete call history' button",
           _p(r"\bdelete\s+call\s+(log|history)\b")),

    # §3.11 Time and waiting
    Clause("§3.11.a", "No countdown timer surface",
           _p(r"\b\d+\s+(seconds?|minutes?)\s+(left|remaining|until)\b")),

    # §3.12 Decision fatigue
    Clause("§3.12.a", "No 'Choose your privacy level'",
           _p(r"\bprivacy\s+(level|preset|mode)\s+(picker|selector|chooser)?")),
    Clause("§3.12.c", "No 'Tip of the day' / 'Did you know'",
           _p(r"\b(did\s+you\s+know|pro\s+tip|tip\s+of\s+the\s+day)\b")),
    Clause("§3.12.c.2", "No onboarding tour",
           _p(r"\bonboarding\s+(tour|tutorial|coach[- ]?marks)\b")),
)


# ---------------------------------------------------------------------------
# Comment stripping + exemption parsing
# ---------------------------------------------------------------------------

_JS_LINE_COMMENT = re.compile(r"(^|[^:])//.*$", re.MULTILINE)
_JS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_PY_LINE_COMMENT = re.compile(r"#.*$", re.MULTILINE)

# Match the presence of a 'doctrine-ok:' annotation on a line. The
# reason content is left to PR review — the lint only needs to know
# the line is exempted. Reviewers police whether the reason cites a
# real clause or ADR per §6.3.
_DOCTRINE_OK = re.compile(r"doctrine[- ]?ok\s*:", re.IGNORECASE)


def _strip_comments(content: str, suffix: str) -> str:
    """Return content with comments replaced by spaces (preserving line numbers).

    We replace with spaces (not deletion) so line numbers stay aligned with the
    original file when reporting violations.
    """

    def _blank(m: re.Match[str]) -> str:
        # preserve newlines so line numbering survives
        return "".join(c if c == "\n" else " " for c in m.group(0))

    if suffix in (".html", ".htm"):
        content = _HTML_COMMENT.sub(_blank, content)
        content = _JS_BLOCK_COMMENT.sub(_blank, content)
        # index.html embeds large <script> blocks; their JS line
        # comments (//) must be stripped too, otherwise we false-
        # positive on phrases inside engineer comments. The
        # negative-look-behind on `:` keeps URLs like https://example
        # untouched (the `:` precedes // in URLs).
        content = _JS_LINE_COMMENT.sub(_blank, content)
    elif suffix == ".js":
        content = _JS_BLOCK_COMMENT.sub(_blank, content)
        content = _JS_LINE_COMMENT.sub(_blank, content)
    elif suffix == ".py":
        content = _PY_LINE_COMMENT.sub(_blank, content)
    return content


# Annotation exemption window. An inline ``doctrine-ok:`` annotation
# exempts:
#   - the line it sits on
#   - the line immediately above (so trailing annotations work)
#   - the next N lines below (to cover multi-line HTML blocks where
#     the annotation is placed at the opening tag and the offending
#     text wraps onto subsequent lines)
# 10 lines is enough for any reasonably-sized HTML paragraph or
# code block without making annotations too coarse-grained.
_EXEMPT_LOOKAHEAD = 10


def _lines_with_doctrine_ok(original: str) -> set[int]:
    """Return set of 1-based line numbers carrying a doctrine-ok annotation.

    An annotation at line L exempts lines in the window
    ``[L-1, L+_EXEMPT_LOOKAHEAD]``. The exemption stops at the next
    blank line OR at the next doctrine-ok annotation, whichever comes
    first — so the window does not bleed past structural boundaries.
    """
    lines = original.splitlines()
    exempt: set[int] = set()
    for idx, raw in enumerate(lines):
        if not _DOCTRINE_OK.search(raw):
            continue
        line_no = idx + 1
        exempt.add(line_no)
        if line_no - 1 >= 1:
            exempt.add(line_no - 1)
        # Extend the window forward until a blank line or another
        # doctrine-ok annotation interrupts it.
        for look in range(1, _EXEMPT_LOOKAHEAD + 1):
            j = idx + look
            if j >= len(lines):
                break
            nxt = lines[j]
            if nxt.strip() == "":
                break
            if _DOCTRINE_OK.search(nxt):
                break
            exempt.add(j + 1)
    return exempt


# ---------------------------------------------------------------------------
# Lint engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Violation:
    path: Path
    line: int
    clause: Clause
    matched_text: str

    def render(self) -> str:
        rel = self.path.relative_to(ROOT)
        return (
            f"  {rel}:{self.line}\n"
            f"    {self.clause.id} — {self.clause.name}\n"
            f"    match: {self.matched_text!r}"
        )


def _scan_text(path: Path, content: str) -> list[Violation]:
    suffix = path.suffix.lower()
    stripped = _strip_comments(content, suffix)
    exempt_lines = _lines_with_doctrine_ok(content)

    violations: list[Violation] = []
    for clause in CLAUSES:
        for match in clause.pattern.finditer(stripped):
            # Compute 1-based line number from match position.
            line_no = stripped.count("\n", 0, match.start()) + 1
            if line_no in exempt_lines:
                continue
            snippet = match.group(0)
            violations.append(
                Violation(path=path, line=line_no, clause=clause, matched_text=snippet)
            )
    return violations


def scan_all() -> list[Violation]:
    """Public entry point used by tests + CLI."""
    all_violations: list[Violation] = []
    for path in USER_FACING_FILES:
        if not path.exists():
            continue
        content = path.read_text(encoding="utf-8")
        all_violations.extend(_scan_text(path, content))
    return all_violations


# ---------------------------------------------------------------------------
# Pytest entry points
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", USER_FACING_FILES, ids=lambda p: p.name)
def test_doctrine_of_invisibility(path: Path) -> None:
    """Per-file pytest entry. Lints each user-facing surface independently.

    Each clause and each match is reported with file:line, clause id, clause
    name, and the literal matched text. Reviewers should fix the violation
    OR add an inline ``doctrine-ok: <reason>`` annotation citing the relevant
    clause or ADR.
    """
    if not path.exists():
        pytest.skip(f"{path} does not exist in this checkout")
    content = path.read_text(encoding="utf-8")
    violations = _scan_text(path, content)
    if violations:
        header = (
            f"\nDoctrine of Invisibility violations in {path.relative_to(ROOT)}\n"
            f"(see docs/DOCTRINE_OF_INVISIBILITY.md):\n"
        )
        body = "\n\n".join(v.render() for v in violations)
        footer = (
            "\n\nFix each violation OR add an inline "
            "'doctrine-ok: <reason>' annotation citing the doctrine clause "
            "or a written ADR (see §6.3 of the doctrine document)."
        )
        pytest.fail(header + body + footer)


def test_doctrine_clauses_compile() -> None:
    """Sanity: every clause has a compiled regex with a non-empty pattern."""
    seen_ids: set[str] = set()
    for c in CLAUSES:
        assert c.id, "clause id cannot be empty"
        assert c.id not in seen_ids, f"duplicate clause id: {c.id}"
        seen_ids.add(c.id)
        assert c.name, f"clause {c.id} has no name"
        assert c.pattern.pattern, f"clause {c.id} has empty pattern"


def test_doctrine_lint_can_be_invoked_standalone() -> None:
    """The scan_all entry point must return a list — even when zero files match."""
    result = scan_all()
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Doctrine-ok parser self-test (cheap regression guard)
# ---------------------------------------------------------------------------

def test_doctrine_ok_annotation_recognised_html() -> None:
    src = (
        "<p>Reconnecting now</p>\n"
        "<p>Reconnecting now</p> <!-- doctrine-ok: §3.2.a covered by ADR-0001 -->\n"
    )
    exempt = _lines_with_doctrine_ok(src)
    # The exemption sits on line 2; it exempts lines 1, 2, 3.
    assert 2 in exempt
    assert 1 in exempt


def test_doctrine_ok_annotation_recognised_js() -> None:
    src = (
        "showError('reconnecting');\n"
        "showError('reconnecting'); // doctrine-ok: §3.2.a covered by ADR-0001\n"
    )
    exempt = _lines_with_doctrine_ok(src)
    assert 2 in exempt


def test_strip_html_comments() -> None:
    src = "before <!-- reconnecting --> after\nnext line\n"
    out = _strip_comments(src, ".html")
    # Newlines preserved, content blanked.
    assert "reconnecting" not in out
    assert out.count("\n") == src.count("\n")


def test_clause_catches_basic_violation_in_isolation() -> None:
    """End-to-end: a known violation in synthetic source is reported."""
    fake_path = ROOT / "_fake_doctrine_test.html"
    src = "<div>Trying to connect to Mom...</div>\n"
    violations = _scan_text(fake_path, src)
    ids = {v.clause.id for v in violations}
    assert "§3.2.a" in ids


def test_clause_skipped_when_annotated() -> None:
    fake_path = ROOT / "_fake_doctrine_test.html"
    src = (
        "<!-- doctrine-ok: §3.2.a — synthetic test for self-test -->\n"
        "<div>Trying to connect to Mom...</div>\n"
    )
    violations = _scan_text(fake_path, src)
    ids = {v.clause.id for v in violations}
    assert "§3.2.a" not in ids
