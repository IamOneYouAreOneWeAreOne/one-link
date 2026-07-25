"""D27 — Tests for ``one_link.fuse_native`` + daemon FUSE surface.

Exercises:
  - platform_status() returns a sensible value on every platform
  - Windows / macOS report their adapters as unimplemented regardless
    of whether unrelated native acceleration is available
  - native-extension availability is distinct from filesystem-binding
    availability
  - try_mount() on Windows / macOS returns unsupported_platform
    immediately
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
    assert isinstance(s.backend, str)
    assert isinstance(s.reason, str)
    assert s.message  # non-empty


def test_platform_status_message_is_helpful() -> None:
    s = fuse_native.platform_status()
    if sys.platform.startswith("win"):
        assert s.reason == "adapter_unimplemented"
        assert "not implemented" in s.message.lower()
    elif sys.platform == "darwin":
        assert s.reason == "adapter_unimplemented"
        assert "not implemented" in s.message.lower()
    elif not fuse_native.HAS_NATIVE_EXTENSION:
        assert s.reason == "native_extension_missing"
        assert "unavailable" in s.message.lower()


@pytest.mark.parametrize(
    ("sys_platform", "machine", "expected_kind"),
    [
        ("darwin", "Darwin", "macos_unsupported"),
        ("win32", "Windows", "windows_unsupported"),
    ],
)
@pytest.mark.parametrize("native_available", [False, True])
def test_unimplemented_adapters_report_truth_independent_of_native_extension(
    monkeypatch,
    sys_platform: str,
    machine: str,
    expected_kind: str,
    native_available: bool,
) -> None:
    monkeypatch.setattr(fuse_native.sys, "platform", sys_platform)
    monkeypatch.setattr(fuse_native.platform, "system", lambda: machine)
    monkeypatch.setattr(
        fuse_native,
        "HAS_NATIVE_EXTENSION",
        native_available,
    )
    monkeypatch.setattr(
        fuse_native,
        "HAS_FILESYSTEM_MODULE",
        native_available,
    )
    monkeypatch.setattr(
        fuse_native,
        "HAS_FILESYSTEM_BINDING",
        native_available,
    )

    status = fuse_native.platform_status()

    assert status.kind == expected_kind
    assert status.ready is False
    assert status.backend == "none"
    assert status.reason == "adapter_unimplemented"
    assert "not implemented" in status.message.lower()
    assert "does not enable" in status.message.lower()


def test_native_extension_does_not_imply_filesystem_binding(monkeypatch) -> None:
    monkeypatch.setattr(fuse_native.sys, "platform", "linux")
    monkeypatch.setattr(fuse_native.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fuse_native, "HAS_NATIVE_EXTENSION", True)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_MODULE", False)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_BINDING", False)

    caps = fuse_native.capabilities()

    assert caps["native_extension_available"] is True
    assert caps["filesystem_module_available"] is False
    assert caps["filesystem_binding_available"] is False
    assert caps["native_loaded"] is False
    assert caps["ready"] is False
    assert caps["backend"] == "none"
    assert caps["reason"] == "filesystem_binding_missing"


def test_incomplete_filesystem_module_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(fuse_native.sys, "platform", "linux")
    monkeypatch.setattr(fuse_native.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fuse_native, "HAS_NATIVE_EXTENSION", True)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_MODULE", True)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_BINDING", False)

    status = fuse_native.platform_status()

    assert status.ready is False
    assert status.backend == "none"
    assert status.reason == "filesystem_binding_incomplete"


def test_empty_native_tag_never_implies_linux_readiness() -> None:
    status = fuse_native._status_for_tag("", "linux", "linux")
    assert status.ready is False
    assert status.backend == "none"
    assert status.reason == "filesystem_binding_incomplete"


# ---------- try_mount on unsupported platforms ----------


@pytest.mark.parametrize(
    ("sys_platform", "machine"),
    [("darwin", "Darwin"), ("win32", "Windows")],
)
def test_try_mount_on_unimplemented_adapter_returns_unsupported(
    monkeypatch,
    tmp_path: Path,
    sys_platform: str,
    machine: str,
) -> None:
    monkeypatch.setattr(fuse_native.sys, "platform", sys_platform)
    monkeypatch.setattr(fuse_native.platform, "system", lambda: machine)
    result = fuse_native.try_mount(
        mountpoint=tmp_path,
        manifest={"a.txt": {"size": 1, "mtime_ms": 0, "blob_hash": "h" * 64}},
    )
    assert result.status == "unsupported_platform"
    assert "not implemented" in result.detail.lower()


def test_try_mount_invalid_mountpoint_returns_invalid(monkeypatch) -> None:
    """The invalid-mountpoint check must fire on every platform when
    the platform capability is ready. Mock that status so we exercise
    validation independently of the host's real adapter."""
    fake_ready = fuse_native.PlatformStatus(
        kind="linux_ready",
        ready=True,
        message="mock ready for test",
        backend="fuse",
        reason="ready",
    )
    monkeypatch.setattr(fuse_native, "platform_status", lambda: fake_ready)
    # Use a path that definitely doesn't exist on any platform.
    bad_path = Path("/nonexistent/path/for/test_d27_invalid_mountpoint")
    result = fuse_native.try_mount(
        mountpoint=bad_path,
        manifest={},
        blob_reader=lambda _blob, _offset, _size: b"",
    )
    assert result.status == "invalid_mountpoint"


def test_try_mount_native_missing_when_native_unavailable(monkeypatch) -> None:
    """When the native module isn't loaded, every try_mount returns
    native_missing without touching anything. Monkeypatched so we
    test the fallback path even when native IS installed."""
    monkeypatch.setattr(fuse_native.sys, "platform", "linux")
    monkeypatch.setattr(fuse_native.platform, "system", lambda: "Linux")
    monkeypatch.setattr(fuse_native, "HAS_NATIVE_EXTENSION", False)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_MODULE", False)
    monkeypatch.setattr(fuse_native, "HAS_FILESYSTEM_BINDING", False)
    result = fuse_native.try_mount(
        mountpoint=Path("/tmp"),
        manifest={},
    )
    assert result.status == "native_missing"


# ---------- capabilities ----------


def test_capabilities_returns_dict_with_expected_keys() -> None:
    caps = fuse_native.capabilities()
    assert isinstance(caps, dict)
    for key in (
        "platform",
        "ready",
        "backend",
        "reason",
        "message",
        "native_loaded",
        "native_extension_available",
        "filesystem_module_available",
        "filesystem_binding_available",
    ):
        assert key in caps


# ---------- _normalise_manifest ----------


def test_normalise_manifest_drops_tombstones() -> None:
    out = fuse_native._normalise_manifest(
        {
            "alive.txt": {"size": 5, "mtime_ms": 100, "blob_hash": "ab" * 32},
            "deleted.txt": {"size": 0, "mtime_ms": 100, "blob_hash": None},
            "no_blob.txt": {"size": 0, "mtime_ms": 100},
        }
    )
    paths = [t[0] for t in out]
    assert "alive.txt" in paths
    assert "deleted.txt" not in paths
    assert "no_blob.txt" not in paths


def test_normalise_manifest_rejects_noncanonical_leading_slash() -> None:
    with pytest.raises(ValueError, match="canonical"):
        fuse_native._normalise_manifest(
            {
                "/leading.txt": {
                    "size": 1,
                    "mtime_ms": 0,
                    "blob_hash": "ab" * 32,
                },
            }
        )


def test_normalise_manifest_rejects_empty_path() -> None:
    with pytest.raises(ValueError, match="empty"):
        fuse_native._normalise_manifest(
            {
                "": {"size": 1, "mtime_ms": 0, "blob_hash": "ab" * 32},
            }
        )


def test_normalise_manifest_handles_missing_fields() -> None:
    out = fuse_native._normalise_manifest(
        {
            "x.txt": {"blob_hash": "ab" * 32},  # no size / no mtime
        }
    )
    assert out == [("x.txt", 0, 0, "ab" * 32)]


def test_normalise_manifest_empty_input_returns_empty_list() -> None:
    assert fuse_native._normalise_manifest({}) == []


@pytest.mark.parametrize(
    "path",
    ["../escape", "a/../escape", "a//b", "a/./b", "a\nb"],
)
def test_normalise_manifest_rejects_adversarial_paths(path: str) -> None:
    with pytest.raises(ValueError):
        fuse_native._normalise_manifest(
            {path: {"size": 1, "mtime_ms": 0, "blob_hash": "ab" * 32}}
        )


@pytest.mark.parametrize(
    "row",
    [
        {"size": -1, "mtime_ms": 0, "blob_hash": "ab" * 32},
        {"size": True, "mtime_ms": 0, "blob_hash": "ab" * 32},
        {"size": 1, "mtime_ms": -1, "blob_hash": "ab" * 32},
        {"size": 1, "mtime_ms": 0, "blob_hash": "AB" * 32},
        {"size": 1, "mtime_ms": 0, "blob_hash": "ab"},
    ],
)
def test_normalise_manifest_rejects_invalid_metadata(row: dict) -> None:
    with pytest.raises((TypeError, ValueError)):
        fuse_native._normalise_manifest({"a.txt": row})


def test_normalise_manifest_rejects_file_ancestor_collision() -> None:
    with pytest.raises(ValueError, match="descends"):
        fuse_native._normalise_manifest(
            {
                "a": {"size": 1, "mtime_ms": 0, "blob_hash": "ab" * 32},
                "a/b": {"size": 1, "mtime_ms": 0, "blob_hash": "cd" * 32},
            }
        )


def test_try_mount_requires_verified_blob_reader_before_native_call(
    monkeypatch,
    tmp_path: Path,
) -> None:
    fake_ready = fuse_native.PlatformStatus(
        kind="linux_ready",
        ready=True,
        message="ready",
        backend="fuse",
        reason="ready",
    )
    binding = MagicMock()
    monkeypatch.setattr(fuse_native, "platform_status", lambda: fake_ready)
    monkeypatch.setattr(fuse_native, "_native_fuse", binding)

    result = fuse_native.try_mount(
        mountpoint=tmp_path,
        manifest={"a": {"size": 1, "mtime_ms": 0, "blob_hash": "ab" * 32}},
    )

    assert result.status == "backend_error"
    assert "blob_reader" in result.detail
    binding.mount_manifest.assert_not_called()


def test_try_mount_passes_strict_manifest_and_reader_to_native_binding(
    monkeypatch,
    tmp_path: Path,
) -> None:
    fake_ready = fuse_native.PlatformStatus(
        kind="linux_ready",
        ready=True,
        message="ready",
        backend="fuse",
        reason="ready",
    )
    binding = MagicMock()
    reader = lambda _blob, _offset, _size: b"x"  # noqa: E731
    monkeypatch.setattr(fuse_native, "platform_status", lambda: fake_ready)
    monkeypatch.setattr(fuse_native, "_native_fuse", binding)

    result = fuse_native.try_mount(
        mountpoint=tmp_path,
        manifest={"a": {"size": 1, "mtime_ms": 0, "blob_hash": "ab" * 32}},
        fs_name="folder name,unsafe",
        blob_reader=reader,
    )

    assert result.status == "mounted"
    binding.mount_manifest.assert_called_once_with(
        mountpoint=str(tmp_path),
        manifest=[("a", 1, 0, "ab" * 32)],
        blob_reader=reader,
        fs_name="folder_name_unsafe",
        read_only=True,
        allow_other=False,
    )


def test_native_package_declares_real_linux_mount_feature() -> None:
    repo = Path(__file__).resolve().parents[1]
    cargo = (repo / "native" / "one_link_native" / "Cargo.toml").read_text(
        encoding="utf-8"
    )
    maturin = (repo / "native" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'ol_fuse           = { path = "../ol_fuse" }' in cargo
    assert 'linux-mount = ["ol_fuse/linux-mount"]' in cargo
    assert '"linux-mount"' in maturin


# ---------- daemon-level wrappers ----------


def _bare_daemon():
    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.state = MagicMock()
    d.folder_engine = MagicMock()
    d.folder_engine.manifest_for.return_value = [
        {"file_path": "x.txt", "blob_hash": "h" * 64, "size": 5, "mtime_ms": 0, "vclock": {}},
    ]
    d.state.get_folder.return_value = {"shared_with": []}
    d.blob_store = MagicMock()
    d.blob_store.has.return_value = True
    d.blob_store.size.return_value = 5
    return d


def test_fuse_capabilities_returns_dict() -> None:
    d = _bare_daemon()
    caps = d.fuse_capabilities()
    assert "platform" in caps
    assert "ready" in caps
    assert "backend" in caps
    assert "reason" in caps


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
        "invalid_manifest",
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


def test_mount_folder_passes_verified_cas_reader_to_native(
    monkeypatch,
    tmp_path: Path,
) -> None:
    d = _bare_daemon()
    captured: dict = {}

    def _try_mount(**kwargs):
        captured.update(kwargs)
        return fuse_native.MountResult("mounted")

    monkeypatch.setattr(fuse_native, "try_mount", _try_mount)
    result = d.mount_folder_as_fs("myfolder", str(tmp_path))

    assert result["status"] == "mounted"
    assert callable(captured["blob_reader"])
    d.blob_store.has.assert_called_once_with("h" * 64)
    d.blob_store.size.assert_called_once_with("h" * 64)


def test_mount_folder_refuses_missing_or_size_mismatched_blob(tmp_path: Path) -> None:
    d = _bare_daemon()
    d.blob_store.has.return_value = False
    missing = d.mount_folder_as_fs("myfolder", str(tmp_path))
    assert missing["status"] == "backend_error"
    assert "verified blob unavailable" in missing["detail"]

    d.blob_store.has.return_value = True
    d.blob_store.size.return_value = 4
    mismatched = d.mount_folder_as_fs("myfolder", str(tmp_path))
    assert mismatched["status"] == "invalid_manifest"
    assert "size does not match" in mismatched["detail"]


def test_mount_blob_reader_returns_bounded_verified_slices(tmp_path: Path) -> None:
    from one_link.blobstore import BlobStore

    d = daemon_module.Daemon.__new__(daemon_module.Daemon)
    d.blob_store = BlobStore(tmp_path / "blobs")
    blob_hash = d.blob_store.put_bytes(b"0123456789")

    assert d._read_mounted_blob_slice(blob_hash, 2, 4) == b"2345"
    assert d._read_mounted_blob_slice(blob_hash, 10, 4) == b""
    with pytest.raises(ValueError, match="blob hash"):
        d._read_mounted_blob_slice("not-a-hash", 0, 1)
    with pytest.raises(ValueError, match="read size"):
        d._read_mounted_blob_slice(blob_hash, 0, 16 * 1024 * 1024 + 1)


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
