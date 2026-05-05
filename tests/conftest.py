"""Pytest fixtures shared across test modules."""

from __future__ import annotations

import os
from pathlib import Path

import pytest


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
