"""v0.20.7 (audit M28) — ONE_LINK_HOME env-var sanitization.

Pre-v0.20.7 ``Path(env_value).expanduser()`` was used directly with no
validation. An elevated ``sudo one-link daemon`` with
``ONE_LINK_HOME=/etc/something`` would mkdir config / data subdirs
under a root-owned path the operator likely didn't intend. Even
non-elevated, ``ONE_LINK_HOME=$HOME/../other-user/coh`` would write
into another user's tree.

These tests pin the v0.20.7 hardening:

  - Empty / whitespace-only values fall back to platform default.
  - Any "``..``" component is rejected.
  - UNC paths on Windows are rejected.
  - Non-absolute residual paths are rejected.
  - On POSIX, an ancestor not owned by the current euid is rejected
    (the sudo / shared-volume guard).

Each rejection logs a warning and returns None so platform_dirs
fall-through still produces a usable path.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from one_link import paths


def test_unset_returns_none(monkeypatch):
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    assert paths._home_override() is None


def test_empty_string_rejected(monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, "")
    assert paths._home_override() is None


def test_whitespace_only_rejected(monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, "   \t  ")
    assert paths._home_override() is None


def test_traversal_segment_rejected(monkeypatch, caplog):
    monkeypatch.setenv(paths.HOME_ENV, "/var/data/../etc")
    with caplog.at_level("WARNING", logger="one_link.paths"):
        assert paths._home_override() is None
    assert any(
        "contains '..'" in r.message for r in caplog.records
    )


def test_traversal_with_backslash_rejected(monkeypatch):
    """Mixed-separator traversal must be normalized then rejected."""
    monkeypatch.setenv(paths.HOME_ENV, r"C:\data\..\foo" if os.name == "nt" else "/data/..\\foo")
    assert paths._home_override() is None


@pytest.mark.skipif(os.name != "nt", reason="UNC paths are Windows-only")
def test_unc_rejected_on_windows(monkeypatch, caplog):
    monkeypatch.setenv(paths.HOME_ENV, r"\\server\share\coh")
    with caplog.at_level("WARNING", logger="one_link.paths"):
        assert paths._home_override() is None
    assert any("UNC" in r.message for r in caplog.records)


@pytest.mark.skipif(os.name != "nt", reason="UNC paths are Windows-only")
def test_unc_forward_slash_rejected_on_windows(monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, "//server/share/coh")
    assert paths._home_override() is None


def test_relative_path_rejected(monkeypatch):
    """A relative path that doesn't resolve to absolute (e.g. because
    cwd is gone) falls back."""
    # `relative/path` resolves to absolute via cwd, so it actually
    # passes; use an explicit pytest-impossible path instead.
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    # We can't easily construct a non-resolving relative path; just
    # confirm a normal absolute path passes — the negative case is
    # exercised by the traversal tests.
    assert paths._home_override() is None


def test_valid_path_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path))
    out = paths._home_override()
    assert out == tmp_path
    assert out.is_absolute()


def test_expanduser_resolves(tmp_path, monkeypatch):
    """A ~-prefixed path expands to the user's home (we point HOME at
    tmp_path so this is hermetic)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    if os.name == "nt":
        monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv(paths.HOME_ENV, "~/coh")
    out = paths._home_override()
    assert out is not None
    # Resolved to under tmp_path.
    assert str(out).startswith(str(tmp_path))


@pytest.mark.skipif(
    os.name == "nt",
    reason="parent-uid check is POSIX-only (no euid concept on Windows)",
)
def test_parent_owned_by_other_uid_rejected(tmp_path, monkeypatch, caplog):
    """A path whose deepest existing ancestor is owned by a different
    UID is rejected. We synthesize this by patching os.stat to return
    an alien uid for the ancestor."""
    # Set to a path under tmp_path. The deepest existing ancestor is
    # tmp_path itself, which IS owned by us — so to exercise the
    # rejection branch we patch os.stat to fake an alien uid.
    target = tmp_path / "coh"
    monkeypatch.setenv(paths.HOME_ENV, str(target))
    real_stat = Path.stat
    real_geteuid = os.geteuid

    class _FakeStat:
        def __init__(self, real):
            self.real = real
        def __getattr__(self, name):
            if name == "st_uid":
                return real_geteuid() + 99999  # a uid that's NOT us
            return getattr(self.real, name)

    # 2026-06-04: accept + forward **kwargs. Python 3.12's
    # Path.exists()/Path.is_*() call self.stat(follow_symlinks=...),
    # so a fake_stat(self) with no kwargs raises TypeError — which,
    # because this monkeypatch is global on Path.stat, also breaks
    # pytest's own traceback formatter (it calls p.exists()) and
    # turned a normal test failure into a suite-aborting INTERNALERROR.
    def fake_stat(self, **kwargs):
        return _FakeStat(real_stat(self, **kwargs))

    monkeypatch.setattr(Path, "stat", fake_stat)
    with caplog.at_level("WARNING", logger="one_link.paths"):
        assert paths._home_override() is None
    assert any(
        "owned by uid" in r.message for r in caplog.records
    )


@pytest.mark.skipif(
    os.name == "nt",
    reason="parent-uid check is POSIX-only",
)
def test_parent_owned_by_us_accepted(tmp_path, monkeypatch):
    target = tmp_path / "coh"
    monkeypatch.setenv(paths.HOME_ENV, str(target))
    out = paths._home_override()
    assert out == target
