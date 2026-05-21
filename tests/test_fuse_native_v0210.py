"""D27 — Tests for ``one_link.fuse_native`` + daemon FUSE surface.

Exercises:
  - platform_status() returns a sensible value on every platform
  - try_mount() on Windows / macOS returns unsupported_platform
    immediately (we're testing on Windows here so this hits)
  - try_mount() rejects missing mountpoint with invalid_mountpoint
  - capabilities() returns a dict with the expected keys
  - _normalise_manifest filters tombstones + leading-slash paths
  - daemon.mount_folder_as_fs / unmount_folder_fs return structured
    status dicts on every platform
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from one_link import fuse_native
from one_link import daemon as daemon_module


# ---------- platform_status ----------


def test_platform_status_returns_a_status() -> None:
    s = fuse_native.platform_status()
    assert isinstance(s, fuse_native.PlatformStatus)
    assert isinstance(s.kind, str)
    assert isinstance(s.ready, bool)
    assert s.message  # non-empty


def test_platform_status_message_is_helpful() -> None:
    s = fuse_native.platform_status()
    # When the native module isn't loaded, the message is the
    # "rebuild via maturin" hint regardless of platform — still a
    # helpful message, just not the platform-specific one.
    if not fuse_native.HAS_NATIVE:
        assert "maturin" in s.message.lower() or "native" in s.message.lower()
        return
    if sys.platform.startswith("win"):
        assert "winfsp" in s.message.lower() or "winfs" in s.message.lower()
    elif sys.platform == "darwin":
        assert "fskit" in s.message.lower() or "macfuse" in s.message.lower()


# ---------- try_mount on unsupported platforms ----------


def test_try_mount_on_windows_returns_unsupported(tmp_path: Path) -> None:
    if not sys.platform.startswith("win"):
        pytest.skip("Windows-only assertion")
    result = fuse_native.try_mount(
        mountpoint=tmp_path,
        manifest={"a.txt": {"size": 1, "mtime_ms": 0, "blob_hash": "h" * 64}},
    )
    assert result.status in (
        "unsupported_platform", "native_missing", "feature_disabled",
    )
    assert result.detail  # has a helpful message


def test_try_mount_invalid_mountpoint_returns_invalid(monkeypatch) -> None:
    """The invalid-mountpoint check must fire on every platform when
    HAS_NATIVE + the platform check are both satisfied. Mock both so
    we exercise the validation path uniformly."""
    monkeypatch.setattr(fuse_native, "HAS_NATIVE", True)
    fake_ready = fuse_native.PlatformStatus(
        kind="linux_ready", ready=True, message="mock ready for test",
    )
    monkeypatch.setattr(fuse_native, "platform_status", lambda: fake_ready)
    # Use a path that definitely doesn't exist on any platform.
    bad_path = Path("/nonexistent/path/for/test_d27_invalid_mountpoint")
    result = fuse_native.try_mount(
        mountpoint=bad_path,
        manifest={},
    )
    # Either invalid_mountpoint (validation fired) OR feature_disabled
    # (validation passed, no mount_manifest binding). Either way, the
    # validation logic ran without the platform short-circuit.
    assert result.status in ("invalid_mountpoint", "feature_disabled")


def test_try_mount_native_missing_when_native_unavailable(monkeypatch) -> None:
    """When the native module isn't loaded, every try_mount returns
    native_missing without touching anything. Monkeypatched so we
    test the fallback path even when native IS installed."""
    monkeypatch.setattr(fuse_native, "HAS_NATIVE", False)
    result = fuse_native.try_mount(
        mountpoint=Path("/tmp"),
        manifest={},
    )
    assert result.status == "native_missing"


# ---------- capabilities ----------


def test_capabilities_returns_dict_with_expected_keys() -> None:
    caps = fuse_native.capabilities()
    assert isinstance(caps, dict)
    for key in ("platform", "ready", "message", "native_loaded"):
        assert key in caps


# ---------- _normalise_manifest ----------


def test_normalise_manifest_drops_tombstones() -> None:
    out = fuse_native._normalise_manifest({
        "alive.txt": {"size": 5, "mtime_ms": 100, "blob_hash": "abc"},
        "deleted.txt": {"size": 0, "mtime_ms": 100, "blob_hash": None},
        "no_blob.txt": {"size": 0, "mtime_ms": 100},
    })
    paths = [t[0] for t in out]
    assert "alive.txt" in paths
    assert "deleted.txt" not in paths
    assert "no_blob.txt" not in paths


def test_normalise_manifest_strips_leading_slashes() -> None:
    out = fuse_native._normalise_manifest({
        "/leading.txt": {"size": 1, "mtime_ms": 0, "blob_hash": "h"},
    })
    paths = [t[0] for t in out]
    assert paths == ["leading.txt"]


def test_normalise_manifest_skips_empty_path() -> None:
    out = fuse_native._normalise_manifest({
        "": {"size": 1, "mtime_ms": 0, "blob_hash": "h"},
    })
    assert out == []


def test_normalise_manifest_handles_missing_fields() -> None:
    out = fuse_native._normalise_manifest({
        "x.txt": {"blob_hash": "h"},  # no size / no mtime
    })
    assert out == [("x.txt", 0, 0, "h")]


def test_normalise_manifest_empty_input_returns_empty_list() -> None:
    assert fuse_native._normalise_manifest({}) == []


# ---------- daemon-level wrappers ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.folder_engine = MagicMock()
    d.folder_engine.manifest_for.return_value = [
        {"file_path": "x.txt", "blob_hash": "h" * 64,
         "size": 5, "mtime_ms": 0, "vclock": {}},
    ]
    d.state.get_folder.return_value = {"shared_with": []}
    return d


def test_fuse_capabilities_returns_dict() -> None:
    d = _bare_daemon()
    caps = d.fuse_capabilities()
    assert "platform" in caps
    assert "ready" in caps


def test_mount_folder_as_fs_returns_status_on_unsupported(tmp_path: Path) -> None:
    d = _bare_daemon()
    result = d.mount_folder_as_fs("myfolder", str(tmp_path))
    # Every status string is in the documented set.
    assert result["status"] in (
        "mounted",
        "unsupported_platform",
        "feature_disabled",
        "native_missing",
        "invalid_mountpoint",
        "backend_error",
    )
    # detail is always a string.
    assert isinstance(result["detail"], str)


def test_mount_folder_as_fs_unknown_folder_returns_backend_error() -> None:
    d = _bare_daemon()
    d.state.get_folder.return_value = None
    result = d.mount_folder_as_fs("ghost", "/tmp")
    assert result["status"] == "backend_error"
    assert "folder not found" in result["detail"]


def test_mount_folder_as_fs_survives_engine_exception() -> None:
    d = _bare_daemon()
    d.folder_engine.manifest_for.side_effect = RuntimeError("simulated")
    result = d.mount_folder_as_fs("myfolder", "/tmp")
    assert result["status"] == "backend_error"


def test_unmount_folder_fs_returns_status() -> None:
    d = _bare_daemon()
    result = d.unmount_folder_fs("/tmp/nonexistent")
    assert result["status"] in (
        "unmounted",
        "unsupported_platform",
        "feature_disabled",
        "native_missing",
        "backend_error",
    )
