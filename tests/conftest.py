"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link.platform_guard import install_windows_platform_fastpath


install_windows_platform_fastpath()


# v0.7.x: process-wide gate so any subprocess daemon the test
# harness spawns inherits ONE_LINK_DISABLE_REVEAL=1. Without this,
# tests that exercise reveal endpoints (or anywhere the UI can
# trigger them) pop real File Explorer windows on the developer's
# machine. Set as early as possible — module-import time — so
# subprocess.Popen calls before any test runs already inherit it.
os.environ.setdefault("ONE_LINK_DISABLE_REVEAL", "1")

# v0.10.7: same idea for the native folder picker. Without this,
# any test that hits POST /api/fs/pick-folder without patching
# server._native_folder_picker would pop a real PowerShell /
# osascript / zenity folder dialog on the developer's screen.
os.environ.setdefault("ONE_LINK_DISABLE_NATIVE_PICKER", "1")

# v0.21.x: disable at-rest SQLCipher encryption for the test suite by
# default. Unit tests construct thousands of throwaway State() objects;
# routing each through the OS keychain (keyring) would pollute the
# developer's real credential store AND exhaust keychain / file handles
# at scale (observed as a 500+ ERROR cascade in the full suite). The
# at-rest encryption path has its OWN dedicated coverage in
# test_at_rest_encryption_v021.py, which opts back IN by setting
# ONE_LINK_PASSPHRASE explicitly (that always overrides this flag).
os.environ.setdefault("ONE_LINK_DISABLE_AT_REST_ENCRYPTION", "1")

# v0.21.x accept-first: a standalone incoming file is HELD pending the
# user's accept by DEFAULT in production. Most tests exercise the
# FILE_OFFER transfer mechanics and expect the receiver to proceed, so
# default the policy OFF for the suite. Tests that specifically cover
# accept-first delenv / setenv this to control it explicitly.
os.environ.setdefault("ONE_LINK_REQUIRE_FILE_ACCEPT", "0")


@pytest.fixture
def isolated_home(tmp_path: Path, monkeypatch) -> Path:
    """Point ONE_LINK_HOME at a fresh temp dir for the test."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    # Force re-import of paths so any cached values reset (we don't cache, but
    # be defensive).
    return tmp_path


@pytest.fixture
def isolated_homes(tmp_path: Path):
    """Two isolated homes for two-daemon tests. NOT setting env — caller spawns
    subprocesses with explicit env."""
    a = tmp_path / "A"
    b = tmp_path / "B"
    a.mkdir()
    b.mkdir()
    return a, b
