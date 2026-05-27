"""Regression guard for the FILE_COMPRESSION NameError (2026-05-27).

THE BUG: push_folder_to_peer's blob-send loop referenced the
capability constant FILE_COMPRESSION, but daemon.py never imported
it. Every folder send with >=1 blob to actually transfer raised
``NameError: name 'FILE_COMPRESSION' is not defined`` the instant
after sending BLOB_OFFER. The surrounding ``except Exception``
swallowed it, closed the connection, and returned ok=False with
blobs_sent=0 — so NO folder ever delivered a file when there was
real data to move. Folders already in sync (0 wants) never hit the
code path, which is why it stayed hidden for so long.

These tests are cheap static + import guards. The true behavioral
proof is tests/test_folder_sync_e2e.py (two real daemons moving
bytes), which now passes; this file adds fast guards so a
re-introduction is caught without spinning up daemons.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from one_link import capabilities, daemon

SRC = Path(__file__).resolve().parents[1] / "src" / "one_link"


def test_file_compression_importable_from_daemon():
    """daemon.py must have FILE_COMPRESSION in its namespace — the
    blob-send loop dereferences it at runtime."""
    assert hasattr(daemon, "FILE_COMPRESSION"), (
        "daemon.py must import FILE_COMPRESSION; the blob-send loop "
        "in push_folder_to_peer references it and will NameError "
        "mid-transfer without it"
    )
    assert daemon.FILE_COMPRESSION == capabilities.FILE_COMPRESSION


def test_every_capability_constant_used_in_daemon_is_imported():
    """Static guard: every capability constant daemon.py references
    must resolve — either via a module-level import OR a function-local
    ``from one_link.capabilities import X`` inside the scope that uses
    it. Catches the whole class of 'used a capability constant without
    importing it' bugs (FILE_COMPRESSION was one).

    The check is conservative: a used name is OK if it's a module
    attribute OR it appears in ANY ``from one_link.capabilities import``
    statement anywhere in the file (covers function-local imports).
    Only names that are used but imported nowhere are flagged.
    """
    daemon_src = (SRC / "daemon.py").read_text(encoding="utf-8")
    tree = ast.parse(daemon_src)

    cap_names = {
        n for n in dir(capabilities)
        if n.isupper() and not n.startswith("_")
    }

    # Every capability name imported anywhere (module OR function level).
    imported_anywhere: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "one_link.capabilities":
            for alias in node.names:
                imported_anywhere.add(alias.asname or alias.name)

    used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in cap_names:
            used.add(node.id)

    missing = sorted(
        n for n in used
        if not hasattr(daemon, n) and n not in imported_anywhere
    )
    assert not missing, (
        f"daemon.py references capability constants it never "
        f"imported (module-level OR function-local): {missing}. Each "
        f"will NameError at runtime when its code path executes — "
        f"exactly the FILE_COMPRESSION folder-send bug from 2026-05-27."
    )


@pytest.mark.parametrize("symbol", [
    "FILE_COMPRESSION",
    "FOLDER_SYNC",
    "FOLDER_SYNC_BIDI_V1",
    "FILE_SWARM",
])
def test_core_folder_caps_present(symbol):
    assert hasattr(daemon, symbol), (
        f"{symbol} must be importable in daemon.py"
    )
