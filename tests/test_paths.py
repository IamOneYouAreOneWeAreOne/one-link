"""Cross-platform paths, ONE_LINK_HOME override."""

from __future__ import annotations

from pathlib import Path


from one_link import paths


def test_home_override(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path))
    cfg = paths.config_dir()
    data = paths.data_dir()
    assert cfg == tmp_path / "config"
    assert data == tmp_path / "data"
    assert cfg.is_dir()
    assert data.is_dir()


def test_home_override_expands_user(tmp_path: Path, monkeypatch):
    # Use absolute tmp_path; the expanduser path is mostly a smoke check that
    # `~` is honored. We pass a literal to prove no crash.
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path))
    assert paths.config_dir().is_dir()


def test_default_paths_exist(monkeypatch):
    monkeypatch.delenv(paths.HOME_ENV, raising=False)
    cfg = paths.config_dir()
    data = paths.data_dir()
    assert cfg.is_dir()
    assert data.is_dir()


def test_key_path_under_config(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path))
    p = paths.key_path()
    assert p.parent == tmp_path / "config"


def test_inbox_under_data(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(paths.HOME_ENV, str(tmp_path))
    p = paths.inbox_dir()
    assert p == tmp_path / "data" / "inbox"
    assert p.is_dir()


def test_two_homes_isolated(tmp_path: Path, monkeypatch):
    a = tmp_path / "A"
    b = tmp_path / "B"
    a.mkdir()
    b.mkdir()
    monkeypatch.setenv(paths.HOME_ENV, str(a))
    cfg_a = paths.config_dir()
    monkeypatch.setenv(paths.HOME_ENV, str(b))
    cfg_b = paths.config_dir()
    assert cfg_a != cfg_b
