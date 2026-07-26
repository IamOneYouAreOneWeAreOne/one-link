from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import zipfile

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package_standalone_bundle.py"


def _module():
    spec = importlib.util.spec_from_file_location("package_standalone_bundle", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # ``dataclasses`` resolves annotations through the defining module while
    # decorating ``Entry``.  Mirror normal import semantics for this direct
    # script load so that the regression suite exercises the real CLI module.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_complete_onedir_is_deterministic_and_integrity_indexed(tmp_path):
    module = _module()
    bundle = tmp_path / "dist" / "one-link"
    internal = bundle / "_internal" / "one_link" / "web"
    internal.mkdir(parents=True)
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    (internal / "index.html").write_text("current UI", encoding="utf-8")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    module.package_bundle(bundle, first, executable="one-link", epoch=1_700_000_001)
    module.package_bundle(bundle, second, executable="one-link", epoch=1_700_000_001)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.testzip() is None
        assert "one-link/one-link" in archive.namelist()
        assert "one-link/_internal/one_link/web/index.html" in archive.namelist()
        manifest = archive.read("one-link/BUNDLE_SHA256SUMS").decode("utf-8")
        assert manifest.startswith("# sha256\tkind\tbytes\tpath\ttarget\n")
        assert "\tFILE\t8\tone-link/one-link\t\n" in manifest
        assert "one-link/one-link" in manifest
        assert "one-link/_internal/one_link/web/index.html" in manifest
        mode = archive.getinfo("one-link/one-link").external_attr >> 16
        if os.name != "nt":
            assert mode & stat.S_IXUSR


def test_large_files_are_streamed_without_path_read_bytes(tmp_path, monkeypatch):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    payload = bundle / "runtime-model.onnx"
    block = bytes(range(256)) * 4096
    with payload.open("wb") as stream:
        for _ in range(12):
            stream.write(block)
    expected_size = 12 * len(block)

    def _forbid_read_bytes(_path):
        raise AssertionError("standalone packaging must stream large files")

    monkeypatch.setattr(Path, "read_bytes", _forbid_read_bytes)
    output = tmp_path / "bundle.zip"
    module.package_bundle(
        bundle,
        output,
        executable="one-link",
        epoch=1_700_000_000,
    )

    with zipfile.ZipFile(output) as archive:
        member = archive.getinfo("one-link/runtime-model.onnx")
        assert member.file_size == expected_size
        manifest = archive.read("one-link/BUNDLE_SHA256SUMS").decode("utf-8")
        assert f"\tFILE\t{expected_size}\tone-link/runtime-model.onnx\t\n" in manifest


def test_missing_launcher_is_rejected(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    (bundle / "data.bin").write_bytes(b"data")
    with pytest.raises(module.BundleError, match="executable is missing"):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link.exe",
            epoch=1_700_000_000,
        )


def test_out_of_tree_symlink_is_rejected(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    outside = tmp_path / "secret"
    outside.write_text("do not ship", encoding="utf-8")
    link = bundle / "escape"
    try:
        # RELATIVE, so the escape rule is what rejects this. Pointing at the
        # absolute path instead trips the "target is absolute" check first --
        # which is how this test used to pass while never once exercising the
        # containment rule it is named for.
        link.symlink_to(Path("..") / "secret")
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")
    # On Windows every symlink is a reparse point, and the packager rejects
    # that whole class before target classification (junction/reparse
    # semantics are their own attack surface, and Windows bundles never ship
    # links). Both messages are the same fail-closed outcome.
    expected = (
        "reparse point" if os.name == "nt" else "escapes relocated archive"
    )
    with pytest.raises(module.BundleError, match=expected):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


def test_absolute_symlink_is_rejected_even_when_target_is_in_tree(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    target = bundle / "payload.bin"
    target.write_bytes(b"payload")
    link = bundle / "absolute-link"
    try:
        link.symlink_to(target.resolve())
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    # Windows rejects the reparse-point class before target classification.
    expected = "reparse point" if os.name == "nt" else "target is absolute"
    with pytest.raises(module.BundleError, match=expected):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


def test_safe_symlink_is_integrity_indexed_with_target_digest(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    internal = bundle / "_internal"
    internal.mkdir(parents=True)
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    (internal / "payload.bin").write_bytes(b"payload")
    link = bundle / "current-payload"
    target = "_internal/payload.bin"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    output = tmp_path / "bundle.zip"
    if os.name == "nt":
        # Windows bundles never ship links: the packager refuses the whole
        # reparse-point class, so "safe" relative symlinks are POSIX-only.
        with pytest.raises(module.BundleError, match="reparse point"):
            module.package_bundle(
                bundle,
                output,
                executable="one-link",
                epoch=1_700_000_000,
            )
        return
    module.package_bundle(
        bundle,
        output,
        executable="one-link",
        epoch=1_700_000_000,
    )

    digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("one-link/BUNDLE_SHA256SUMS").decode("utf-8")
        assert (
            f"{digest}\tSYMLINK\t{len(target)}\t"
            f"one-link/current-payload\t{target}\n"
        ) in manifest
        link_info = archive.getinfo("one-link/current-payload")
        assert stat.S_ISLNK(link_info.external_attr >> 16)
        assert archive.read(link_info).decode("utf-8") == target


def test_output_inside_input_bundle_is_rejected(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)

    with pytest.raises(module.BundleError, match="must not be inside"):
        module.package_bundle(
            bundle,
            bundle / "release.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


@pytest.mark.parametrize("manifest_name", ["BUNDLE_SHA256SUMS", "bundle_sha256sums"])
def test_source_cannot_collide_with_reserved_manifest(tmp_path, manifest_name):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    (bundle / manifest_name).write_text("untrusted manifest", encoding="utf-8")

    with pytest.raises(module.BundleError, match="reserved manifest"):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


def test_casefold_colliding_members_are_rejected(tmp_path):
    if os.path.normcase("ReadMe") == os.path.normcase("readme"):
        pytest.skip("host filesystem cannot represent the collision")

    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    upper = bundle / "ReadMe"
    lower = bundle / "readme"
    upper.write_text("upper", encoding="utf-8")
    lower.write_text("lower", encoding="utf-8")
    if len({path.name for path in bundle.iterdir() if path.name.casefold() == "readme"}) < 2:
        pytest.skip("host filesystem cannot represent the collision")

    with pytest.raises(module.BundleError, match="case-colliding"):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


@pytest.mark.parametrize(
    "archive_name",
    [
        "one-link/CON",
        "one-link/CONIN$",
        "one-link/COM¹.txt",
        "one-link/filename.",
        "one-link/filename ",
        "one-link/file.txt:alternate-stream",
    ],
)
def test_portable_archive_paths_reject_windows_aliases_and_ads(archive_name):
    module = _module()
    with pytest.raises(module.BundleError, match="Windows-"):
        module._validate_portable_archive_path(archive_name)


@pytest.mark.parametrize(
    "archive_name",
    [
        "one-link//payload.bin",
        "one-link/./payload.bin",
        "one-link/payload.bin/",
    ],
)
def test_portable_archive_paths_require_canonical_spelling(archive_name):
    module = _module()
    with pytest.raises(module.BundleError, match="unsafe archive path"):
        module._validate_portable_archive_path(archive_name)


def test_collection_enforces_directory_budget(tmp_path, monkeypatch):
    import one_link.build_identity as build_identity

    module = _module()
    bundle = tmp_path / "one-link"
    (bundle / "nested").mkdir(parents=True)
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    monkeypatch.setattr(build_identity, "STABLE_FROZEN_MAX_DIRECTORIES", 1)

    with pytest.raises(module.BundleError, match="directory budget exceeded"):
        module.package_bundle(
            bundle,
            tmp_path / "bundle.zip",
            executable="one-link",
            epoch=1_700_000_000,
        )


def test_archive_revalidation_rejects_member_tampering(tmp_path):
    module = _module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    valid = tmp_path / "valid.zip"
    tampered = tmp_path / "tampered.zip"
    module.package_bundle(
        bundle,
        valid,
        executable="one-link",
        epoch=1_700_000_000,
    )

    with zipfile.ZipFile(valid, "r") as source, zipfile.ZipFile(
        tampered,
        "w",
    ) as destination:
        for info in source.infolist():
            payload = source.read(info)
            if info.filename == "one-link/one-link":
                assert len(payload) == len(b"tampered")
                payload = b"tampered"
            destination.writestr(info, payload)

    with pytest.raises(module.BundleError, match="member digest mismatch"):
        module.validate_bundle_archive(
            tampered,
            expected_executable="one-link/one-link",
        )
