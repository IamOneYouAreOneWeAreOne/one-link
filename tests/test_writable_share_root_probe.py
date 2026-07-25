"""Regression tests for writable share-root selection probes."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from one_link import server as server_module
from one_link.server import _pick_writable_share_root, _probe_writable


def test_probe_writable_rejects_candidate_when_probe_cleanup_fails(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    candidate = tmp_path / "candidate"
    real_rmdir = Path.rmdir

    def fail_only_for_probe(path: Path) -> None:
        if path.parent == candidate and path.name.startswith(
            ".one_link_writable_probe_"
        ):
            raise PermissionError("simulated cleanup denial")
        real_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", fail_only_for_probe)

    with caplog.at_level(logging.WARNING, logger="one_link.server"):
        assert _probe_writable(candidate) is False

    probe_artifacts = list(candidate.glob(".one_link_writable_probe_*"))
    assert len(probe_artifacts) == 1
    assert probe_artifacts[0].is_dir()
    assert "probe cleanup failed" in caplog.text
    assert "rejecting candidate" in caplog.text


def test_probe_writable_accepts_candidate_only_after_clean_probe_cycle(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"

    assert _probe_writable(candidate) is True
    assert candidate.is_dir()
    assert list(candidate.iterdir()) == []


def test_pick_writable_share_root_fails_closed_when_all_candidates_fail(
    tmp_path: Path,
    monkeypatch,
    caplog,
) -> None:
    attempted: list[Path] = []

    def reject(candidate: Path) -> bool:
        attempted.append(candidate)
        return False

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path / "configured-home"))
    monkeypatch.setattr(server_module, "data_dir", lambda: tmp_path / "data")
    monkeypatch.setattr(server_module, "_probe_writable", reject)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.setattr(Path, "cwd", classmethod(lambda cls: tmp_path / "cwd"))

    with caplog.at_level(logging.ERROR, logger="one_link.server"):
        with pytest.raises(OSError, match="no writable One Link share-root"):
            _pick_writable_share_root()

    assert tmp_path / "cwd" / "One Link" in attempted
    assert len(attempted) == len(set(attempted))
    assert "No writable One Link share-root candidate" in caplog.text
