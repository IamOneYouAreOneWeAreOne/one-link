"""What THIS build is, as opposed to what version it calls itself.

``__version__`` is ``0.21.0-alpha`` in every rolling build ever produced, so it
cannot answer "is my installed copy older than what the download button serves".
Two builds a month apart, one of which crashes at startup behind antivirus,
report the identical version string. An installed app therefore had no way to
know it was stale, and no way to tell its user.

The build stamps its source commit into a small JSON file that ships INSIDE the
bundle. A source checkout has no stamp and honestly reports nothing rather than
guessing: an unknown commit must never be compared as though it were known,
because "different from the published commit" would then be true for every
developer running from source.

Deliberately not written into a checked-in module: build_binary.py hashes the
source tree for its build manifest, and rewriting a .py during packaging would
make the artifact's own integrity record describe bytes that never existed in
git.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

STAMP_FILENAME = "one_link_build_stamp.json"

_COMMIT_LENGTH = 40
_MAX_STAMP_BYTES = 4096


def _candidate_paths() -> list[Path]:
    """Where a stamp may live, frozen or unpacked.

    PyInstaller extracts bundled data under ``sys._MEIPASS``; an unpacked
    onedir layout keeps it beside the executable; a source tree may have one
    next to this module if someone stamped it deliberately.
    """

    candidates: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if isinstance(meipass, str) and meipass:
        candidates.append(Path(meipass) / STAMP_FILENAME)
    executable = getattr(sys, "executable", "") or ""
    if getattr(sys, "frozen", False) and executable:
        candidates.append(Path(executable).parent / STAMP_FILENAME)
    candidates.append(Path(__file__).resolve().parent / STAMP_FILENAME)
    return candidates


def _read_stamp() -> dict[str, Any]:
    for path in _candidate_paths():
        try:
            if not path.is_file():
                continue
            if path.stat().st_size > _MAX_STAMP_BYTES:
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            return data
    return {}


def _valid_commit(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().lower()
    if len(candidate) != _COMMIT_LENGTH:
        return ""
    try:
        bytes.fromhex(candidate)
    except ValueError:
        return ""
    return candidate


def build_commit() -> str:
    """The 40-hex source commit this build was made from, or "" if unstamped.

    Never guesses. An empty result means "cannot compare", not "out of date".
    """

    return _valid_commit(_read_stamp().get("commit"))


def built_at() -> str:
    """RFC3339 build timestamp, or "" when unstamped. Display only."""

    value = _read_stamp().get("built_at")
    return value[:64] if isinstance(value, str) else ""


def build_channel() -> str:
    """``rolling``, ``release``, or ``source`` when there is no stamp."""

    value = _read_stamp().get("channel")
    if isinstance(value, str) and value in {"rolling", "release"}:
        return value
    return "source"


def describe() -> dict[str, str]:
    """Build identity for the update API and diagnostics."""

    return {
        "commit": build_commit(),
        "built_at": built_at(),
        "channel": build_channel(),
    }


def write_stamp(path: Path, *, commit: str, built_at: str, channel: str) -> Path:
    """Write a stamp for the packager. Refuses an invalid commit.

    Called by scripts/build_binary.py, which then bundles the file. Failing
    closed here matters: a stamp containing a truncated or non-hex commit would
    make every installed copy compare unequal to the published one and nag
    forever.
    """

    checked = _valid_commit(commit)
    if not checked:
        raise ValueError(f"build stamp needs a 40-hex commit, got {commit!r}")
    if channel not in {"rolling", "release"}:
        raise ValueError(f"build channel must be rolling or release, got {channel!r}")
    payload = {
        "commit": checked,
        "built_at": str(built_at)[:64],
        "channel": channel,
        "schema": 1,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
