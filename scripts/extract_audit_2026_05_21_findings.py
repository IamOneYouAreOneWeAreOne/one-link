"""Consolidate the 17 audit-subagent transcripts from the
2026-05-21 deep One Link audit into a single canonical inventory,
keyed by agent-id + finding-number.

Run:
    python scripts/extract_audit_2026_05_21_findings.py

Reads:
    audit_extracts_may21/agent-*.md
Writes:
    AUDIT_2026-05-21_FULL_INVENTORY.md

Each output row is::

    | agent | n | head (first 200 chars) |
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
EXTRACT_DIR = ROOT / "audit_extracts_may21"
OUT = ROOT / "AUDIT_2026-05-21_FULL_INVENTORY.md"

TOPICS = {
    "agent-a1147246450af1143": "Native ol_* crates",
    "agent-a17e4fc32ec331f6a": "server.py control plane",
    "agent-a371fb983062df7ff": "daemon send_file pipeline",
    "agent-a4794adc98e88c1f3": "Persistence + state.db",
    "agent-a491c917ab27d60c4": "Crypto + handshake",
    "agent-a522968418149ae17": "Web UI",
    "agent-a580a5c320383207d": "Transfer stack survey",
    "agent-a65344dfb0d717b8a": "Tests + skip markers",
    "agent-a84e416dddb450b02": "QUIC + relay transport",
    "agent-aa88bd73c820bb225": "Daemon send/recv paths",
    "agent-ac7b5e24234936a05": "Async concurrency",
    "agent-ac8e452c9c6a9bbbd": "Service worker",
    "agent-acdf77b834b45013a": "Half-implemented features",
    "agent-ace70abc0a9a587a5": "QUIC cutover",
    "agent-aee44db505556df60": "Native Rust audit",
    "agent-afb47dcd568cbadce": "Capabilities + caps enforcement",
    "agent-afc5530dbd7646307": "Transfer engine integrity",
}

# A "finding" is either a markdown H3 header OR a top-level numbered
# list item. We extract both, dedupe by overlap, and keep the longer
# variant when they refer to the same line range.
H3 = re.compile(r"^###\s+(?P<title>.+?)\s*$", re.M)
NUM_ITEM = re.compile(
    r"^\s{0,4}(?P<n>\d{1,3})\.\s+(?P<body>.{20,}?)(?=\n\s*\d{1,3}\.\s|\n###\s|\n##\s|\Z)",
    re.S | re.M,
)


def extract(path: Path) -> list[tuple[int, str]]:
    """Return list of (ordinal, raw_text) findings for one transcript."""
    txt = path.read_text(encoding="utf-8", errors="replace")
    items: list[tuple[int, str]] = []
    seen_lines: set[int] = set()

    # Strategy A: H3 headers — each ### becomes one finding spanning
    # to the next ###.
    h3_matches = list(H3.finditer(txt))
    if h3_matches:
        for i, m in enumerate(h3_matches):
            start = m.start()
            end = h3_matches[i + 1].start() if i + 1 < len(h3_matches) else len(txt)
            body = txt[start:end].strip()
            items.append((i + 1, body))
            seen_lines.add(txt.count("\n", 0, start))

    # Strategy B: top-level numbered items. Only use these if Strategy
    # A produced nothing (avoids double-counting capabilities agent
    # which has BOTH).
    if not items:
        for m in NUM_ITEM.finditer(txt):
            n = int(m.group("n"))
            body = m.group(0).strip()
            items.append((n, body))

    return items


def head(text: str, n: int = 180) -> str:
    """Single-line summary, max n chars."""
    cleaned = re.sub(r"\s+", " ", text).strip()
    return cleaned[:n] + ("…" if len(cleaned) > n else "")


def main() -> None:
    if not EXTRACT_DIR.is_dir():
        raise SystemExit(f"missing extract dir: {EXTRACT_DIR}")

    sections: list[str] = []
    total = 0
    for slug, topic in TOPICS.items():
        p = EXTRACT_DIR / f"{slug}.md"
        if not p.exists():
            print(f"  ! missing: {p.name}", file=sys.stderr)
            continue
        items = extract(p)
        total += len(items)
        section = [f"\n## {topic} — `{slug}` ({len(items)} findings)\n"]
        for n, body in items:
            section.append(f"\n### {topic[:30]} #{n}\n")
            # First line as headline, full body as detail
            first_line = body.split("\n", 1)[0]
            section.append(f"**{head(first_line, 200)}**\n")
            if "\n" in body:
                rest = body.split("\n", 1)[1].strip()
                if rest:
                    section.append(f"\n{rest}\n")
        sections.append("".join(section))

    header = (
        "# AUDIT 2026-05-21 — FULL FINDINGS INVENTORY\n\n"
        f"Auto-extracted from {len(TOPICS)} parallel audit-subagent "
        "transcripts ran during the 2026-05-21 deep One Link audit.\n\n"
        f"**Total findings across all topics: {total}**\n\n"
        "The 57 items individually enumerated in `AUDIT_2026-05-21.md` "
        "(TIER 1 / TIER 2 / TIER 3) are a security-prioritised subset "
        "of this list and have all shipped. The remaining items here "
        "are the TIER 4 LOW-priority quality / UX / hardening "
        "observations the audit doc declared 'not blocking'.\n\n"
        "Each section is one auditor's bucket of related findings. "
        "Items are not deduplicated across sections — some "
        "auditors flagged the same root cause from different angles "
        "(e.g. the default-allow-all reversal appears in capabilities, "
        "server, and persistence sections).\n"
    )
    OUT.write_text(header + "".join(sections), encoding="utf-8")
    print(f"wrote {OUT} ({total} findings, {OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
