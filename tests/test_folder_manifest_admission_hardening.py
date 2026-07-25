"""Fail-closed admission tests for portable folder manifests."""

from __future__ import annotations

import unicodedata
from unittest.mock import MagicMock

import pytest

from one_link.daemon import Daemon


def _daemon_with_local_paths(*paths: str) -> Daemon:
    daemon = Daemon.__new__(Daemon)
    daemon.state = MagicMock()
    daemon.state.list_manifest.return_value = [
        {"file_path": path, "blob_hash": "a" * 64}
        for path in paths
    ]
    return daemon


def _live_entry(
    path: str,
    *,
    blob_hash: str = "b" * 64,
    size: int = 1,
) -> dict[str, object]:
    return {
        "file_path": path,
        "blob_hash": blob_hash,
        "size": size,
        "mtime_ms": 1,
        "vclock": {"peer": 1},
    }


@pytest.mark.parametrize(
    ("local_path", "remote_path", "message"),
    [
        ("Readme.txt", "readme.txt", "aliases an existing local path"),
        (
            "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt",
            unicodedata.normalize("NFD", "caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt"),
            "aliases an existing local path",
        ),
        (
            "archive.bin",
            "archive.bin/child.txt",
            "descends from an existing local file",
        ),
        (
            "reports/2026.txt",
            "reports",
            "collides with an existing local descendant",
        ),
    ],
)
def test_remote_manifest_rejects_portable_collisions_with_local_projection(
    local_path: str,
    remote_path: str,
    message: str,
) -> None:
    daemon = _daemon_with_local_paths(local_path)

    with pytest.raises(RuntimeError, match=message):
        daemon._validate_folder_manifest_against_local_paths(
            folder_name="docs",
            entries=[_live_entry(remote_path)],
        )


def test_manifest_rejects_one_hash_with_conflicting_sizes_before_merge() -> None:
    daemon = Daemon.__new__(Daemon)
    shared_hash = "c" * 64
    entries = [
        _live_entry("a.bin", blob_hash=shared_hash, size=1),
        _live_entry("b.bin", blob_hash=shared_hash, size=2),
    ]

    with pytest.raises(RuntimeError, match="conflicting sizes"):
        daemon._validate_folder_manifest_entries(entries)


@pytest.mark.parametrize(
    "path",
    [
        ".one-link-deadbeef.tmp",
        "nested/.one-link-staging.tmp",
        "nested/.one-link-restore.tmp/child",
    ],
)
def test_manifest_rejects_internal_staging_namespace(path: str) -> None:
    daemon = Daemon.__new__(Daemon)

    with pytest.raises(RuntimeError, match="reserved internal path"):
        daemon._validate_folder_manifest_entries([_live_entry(path)])


def test_manifest_schema_rejects_local_only_or_extension_fields() -> None:
    daemon = Daemon.__new__(Daemon)
    entry = _live_entry("report.txt")
    entry["updated_ms"] = 1

    with pytest.raises(RuntimeError, match="non-canonical entry schema"):
        daemon._validate_folder_manifest_entries([entry])


def test_manifest_path_validation_is_independent_of_host_path_flavor() -> None:
    """Windows-looking paths stay invalid even when tests run on POSIX."""

    daemon = Daemon.__new__(Daemon)
    for path in ("C:/escape.txt", "server\\share.txt", "CON.txt"):
        with pytest.raises(RuntimeError, match="unsafe path"):
            daemon._validate_folder_manifest_entries([_live_entry(path)])
