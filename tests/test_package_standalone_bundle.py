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


def test_apple_framework_two_hop_symlink_chain_is_resolved(tmp_path):
    """macOS .app bundles carry Apple's canonical framework layout:
    Python.framework/Python -> Versions/Current/Python, where
    Versions/Current is itself a link to Versions/3.x. A one-hop textual
    check called that real bundle malformed and blocked the first macOS
    release binary; the chain must resolve while every safety property
    (no escape, no '..', bounded hops, target must exist) holds."""
    if os.name == "nt":
        pytest.skip("Windows bundles never ship links (reparse class refused)")
    module = _module()
    bundle = tmp_path / "one-link"
    versions = bundle / "_internal" / "Python.framework" / "Versions"
    (versions / "3.12").mkdir(parents=True)
    (versions / "3.12" / "Python").write_bytes(b"framework-binary")
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    try:
        (versions / "Current").symlink_to("3.12")
        (bundle / "_internal" / "Python.framework" / "Python").symlink_to(
            "Versions/Current/Python"
        )
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    output = tmp_path / "bundle.zip"
    module.package_bundle(bundle, output, executable="one-link", epoch=1_700_000_000)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "one-link/_internal/Python.framework/Python" in names
    assert "one-link/_internal/Python.framework/Versions/Current" in names


def test_symlink_cycle_is_refused_not_hung(tmp_path):
    """Chain resolution is bounded: a link cycle must be a definite error."""
    if os.name == "nt":
        pytest.skip("Windows bundles never ship links (reparse class refused)")
    module = _module()
    bundle = tmp_path / "one-link"
    (bundle / "_internal").mkdir(parents=True)
    executable = bundle / "one-link"
    executable.write_bytes(b"launcher")
    executable.chmod(0o755)
    try:
        (bundle / "_internal" / "a").symlink_to("b")
        (bundle / "_internal" / "b").symlink_to("a")
    except OSError:
        pytest.skip("symbolic links are unavailable on this host")

    output = tmp_path / "bundle.zip"
    # On a real filesystem the collector reaches the cycle first and refuses
    # it as a symlink loop; the ZIP verifier's own BundleError path for the
    # same class is pinned by the synthetic-archive test below. Either way
    # the contract is a DEFINITE ERROR rather than a hang, and BundleError
    # is itself a RuntimeError.
    with pytest.raises(RuntimeError):
        module.package_bundle(bundle, output, executable="one-link", epoch=1_700_000_000)


def _synthetic_archive(path, members):
    """Build a ZIP with real symlink modes + a matching manifest.

    Lets the chain resolver be exercised on hosts (Windows) where creating
    on-disk symlinks is impossible, so the macOS framework contract is
    pinned everywhere rather than skipped exactly where it regressed.
    """
    rows = ["# sha256\tkind\tbytes\tpath\ttarget"]
    with zipfile.ZipFile(path, "w") as archive:
        for name, kind, payload in members:
            data = payload.encode("utf-8") if isinstance(payload, str) else payload
            info = zipfile.ZipInfo(name, date_time=(2024, 1, 1, 0, 0, 0))
            mode = 0o120777 if kind == "SYMLINK" else 0o100755
            info.external_attr = mode << 16
            info.create_system = 3
            archive.writestr(info, data)
            digest = hashlib.sha256(data).hexdigest()
            target = payload if kind == "SYMLINK" else ""
            rows.append(f"{digest}\t{kind}\t{len(data)}\t{name}\t{target}")
        manifest = ("\n".join(rows) + "\n").encode("utf-8")
        info = zipfile.ZipInfo("one-link/BUNDLE_SHA256SUMS", date_time=(2024, 1, 1, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        info.create_system = 3
        archive.writestr(info, manifest)


def test_framework_chain_resolves_and_cycles_refuse_on_every_host(tmp_path):
    """Host-independent proof of the macOS framework contract."""
    module = _module()
    good = tmp_path / "good.zip"
    _synthetic_archive(
        good,
        [
            ("one-link/one-link", "FILE", b"launcher"),
            ("one-link/_internal/Python.framework/Versions/3.12/Python", "FILE", b"fw"),
            ("one-link/_internal/Python.framework/Versions/Current", "SYMLINK", "3.12"),
            ("one-link/_internal/Python.framework/Python", "SYMLINK", "Versions/Current/Python"),
        ],
    )
    module.validate_bundle_archive(good, expected_executable="one-link/one-link")

    cyclic = tmp_path / "cyclic.zip"
    _synthetic_archive(
        cyclic,
        [
            ("one-link/one-link", "FILE", b"launcher"),
            ("one-link/_internal/a", "SYMLINK", "b"),
            ("one-link/_internal/b", "SYMLINK", "a"),
        ],
    )
    with pytest.raises(module.BundleError):
        module.validate_bundle_archive(cyclic, expected_executable="one-link/one-link")

    escaping = tmp_path / "escaping.zip"
    _synthetic_archive(
        escaping,
        [
            ("one-link/one-link", "FILE", b"launcher"),
            ("one-link/_internal/hop", "SYMLINK", "../../outside"),
        ],
    )
    with pytest.raises(module.BundleError):
        module.validate_bundle_archive(escaping, expected_executable="one-link/one-link")
