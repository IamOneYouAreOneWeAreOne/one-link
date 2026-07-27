"""Packaged artifact parity gate.

The stale-tarball failure mode is simple: source contains the fix, but
the binary/tarball people test or download was built earlier or without
dynamic modules/package data. These tests pin the release-side validator
that catches that before a public artifact goes out.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import ssl
import subprocess
import sys
import tomllib
from pathlib import Path
import zipfile

import pytest


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "validate_packaged_artifact.py"
from one_link.build_identity import STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES

# The validator compares native_version against the REAL project version, so
# fixtures must track it dynamically or every release bump breaks them here.
from one_link import __version__ as _CORE_VERSION

_NATIVE_VERSION_FIXTURE = f"{_CORE_VERSION}.0"

EXPECTED_STABLE_EXCLUDES = STABLE_FROZEN_EXCLUDED_MODULE_PREFIXES


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "validate_packaged_artifact",
        SCRIPT,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _valid_install_inventory_payload(bundle: Path, exe: Path) -> dict[str, object]:
    from one_link import build_identity

    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    files = {
        f"bundle/{path.relative_to(bundle).as_posix()}": hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in bundle.rglob("*")
        if path.is_file()
    }
    runtime_modules = {
        module: "PRESENT" for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES
    }
    forbidden_runtime_modules = {
        module: "ABSENT" for module in build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES
    }
    return {
        "version": "0.21.0-alpha",
        "inventory_mode": "frozen_onedir_bundle",
        "inventory_root": str(bundle),
        "files": files,
        "file_count": len(files),
        "missing": [],
        "unsafe_entries": [],
        "rollup_sha256": "a" * 64,
        "frozen_binary_sha256": digest,
        "verification_status": "inventory_only",
        "authenticity_verified": False,
        "runtime_modules": runtime_modules,
        "runtime_module_count": len(runtime_modules),
        "runtime_module_manifest_sha256": (build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256),
        "missing_runtime_modules": [],
        "forbidden_runtime_modules": forbidden_runtime_modules,
        "forbidden_runtime_module_count": len(forbidden_runtime_modules),
        "forbidden_runtime_module_manifest_sha256": (
            build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256
        ),
        "present_forbidden_runtime_modules": [],
    }


def _complete_inventory_bundle(bundle: Path) -> Path:
    repo = SCRIPT.parent.parent
    bundle.mkdir(parents=True)
    exe = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"frozen-executable")
    package = bundle / "_internal" / "one_link"
    for subtree in ("web", "data"):
        shutil.copytree(repo / "src" / "one_link" / subtree, package / subtree)
    manifest = package / "_build" / "runtime-source-manifest.json"
    manifest.parent.mkdir(parents=True)
    validator = _load_module()
    manifest.write_bytes(
        validator._canonical_manifest_bytes(validator._expected_runtime_source_manifest(repo))
    )
    return exe


def _complete_macos_inventory_bundle(app: Path) -> Path:
    repo = SCRIPT.parent.parent
    executable = app / "Contents" / "MacOS" / "one-link"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"frozen-macos-executable")
    (app / "Contents" / "Info.plist").write_text(
        "<plist><dict></dict></plist>",
        encoding="utf-8",
    )
    frameworks = app / "Contents" / "Frameworks"
    resources = app / "Contents" / "Resources"
    frameworks.mkdir()
    resources.mkdir()
    (frameworks / "base_library.zip").write_bytes(b"python-base-library")
    package = resources / "one_link"
    for subtree in ("web", "data"):
        shutil.copytree(repo / "src" / "one_link" / subtree, package / subtree)
    validator = _load_module()
    manifest = package / "_build" / "runtime-source-manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(
        validator._canonical_manifest_bytes(validator._expected_runtime_source_manifest(repo))
    )
    return executable


def _good_spec() -> str:
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES
    from one_link.build_info import STAMP_FILENAME
    from one_link.native_cdc import native_library_name, native_platform_tag

    native_name = native_library_name()
    native_tag = native_platform_tag()

    return "\n".join(
        [
            "ONE_LINK_PREVIEW_ML = False",
            "datas = [('src/one_link/web', 'one_link/web'), "
            "('src/one_link/data', 'one_link/data'), "
            "('build/release-contract/runtime-source-manifest.json', 'one_link/_build'), "
            f"('build/release-contract/{STAMP_FILENAME}', 'one_link'), "
            f"('build/native-cdc/{native_tag}/{native_name}.sha256', "
            f"'one_link/native/{native_tag}')]",
            f"binaries = [('build/native-cdc/{native_tag}/{native_name}', "
            f"'one_link/native/{native_tag}')]",
            f"hiddenimports = {list(EXPECTED_STABLE_RUNTIME_MODULES)!r}",
            "hiddenimports += collect_submodules('zeroconf')",
            "hiddenimports += collect_submodules('cryptography')",
            "hiddenimports += collect_submodules('aiohttp')",
            "hiddenimports += collect_submodules('one_link_native')",
            "a = Analysis([], binaries=binaries, datas=datas, hiddenimports=hiddenimports, excludes=[",
            *[f"    {name!r}," for name in EXPECTED_STABLE_EXCLUDES],
            "])",
        ]
    )


def test_validator_script_imports_cleanly():
    mod = _load_module()
    assert callable(mod.main)
    assert callable(mod.validate_spec)
    assert mod.REQUIRED_STABLE_EXCLUDES == EXPECTED_STABLE_EXCLUDES


def test_validator_help_does_not_advertise_a_native_waiver():
    mod = _load_module()
    help_text = mod.build_arg_parser().format_help()
    assert "--allow-native-missing" in help_text
    assert "always rejected" in help_text
    assert "complete native runtime" in help_text


def test_frozen_sigstore_exclusion_preserves_source_and_release_verification_dependency():
    repo = SCRIPT.parent.parent
    project = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    core = project["project"]["dependencies"]
    release = project["project"]["optional-dependencies"]["release"]
    assert any(dependency.startswith("sigstore") for dependency in core)
    assert any(dependency.startswith("sigstore") for dependency in release)
    assert {
        "sigstore",
        "sigstore_models",
        "rekor_types",
        "tuf",
        "securesystemslib",
        "pydantic",
        "pydantic_core",
        "rich",
    } <= set(EXPECTED_STABLE_EXCLUDES)


def test_psutil_is_a_core_runtime_dependency_not_a_dev_only_accident():
    project = tomllib.loads(
        (SCRIPT.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    assert any(dependency.startswith("psutil") for dependency in project["dependencies"])
    assert not any(
        dependency.startswith("psutil")
        for dependency in project["optional-dependencies"]["dev"]
    )


def test_source_version_reader_never_executes_package_code(tmp_path):
    mod = _load_module()
    init_py = tmp_path / "src" / "one_link" / "__init__.py"
    init_py.parent.mkdir(parents=True)
    marker = tmp_path / "executed.txt"
    init_py.write_text(
        f'__version__ = "9.8.7"\nopen({str(marker)!r}, "w", encoding="utf-8").write("bad")\n',
        encoding="utf-8",
    )
    assert mod._load_source_version(tmp_path) == "9.8.7"
    assert not marker.exists()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "data:text/plain,no", "//host/path"])
def test_live_request_rejects_non_http_schemes(url):
    mod = _load_module()
    with pytest.raises(mod.GateFailure, match="must use http or https"):
        mod._request(url)


def test_live_request_never_sends_owner_token_over_remote_plain_http():
    mod = _load_module()
    with pytest.raises(mod.GateFailure, match="loopback HTTP.*HTTPS"):
        mod._request("http://192.168.1.25:7117/api/status", token="owner-secret")


def test_live_https_probe_never_disables_certificate_verification(monkeypatch):
    mod = _load_module()
    contexts = []

    class _Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

    class _Response:
        status = 200
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"{}"

    def _context(*, cafile=None):
        context = _Context()
        contexts.append((cafile, context))
        return context

    monkeypatch.setattr(mod.ssl, "create_default_context", _context)
    monkeypatch.setattr(
        mod.urllib.request,
        "urlopen",
        lambda *_args, **_kwargs: _Response(),
    )

    status, _headers, _body = mod._request(
        "https://example.test/api/status",
        token="owner-secret",
    )

    assert status == 200
    assert len(contexts) == 1
    assert contexts[0][0] is None
    assert contexts[0][1].check_hostname is True
    assert contexts[0][1].verify_mode == ssl.CERT_REQUIRED


def test_validate_spec_requires_dynamic_imports_and_package_data(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    checks = mod.validate_spec(spec)
    assert any("one_link.sessions" in c for c in checks)
    assert any("one_link/data" in c for c in checks)


def test_validate_spec_rejects_native_collect_all_metadata_and_local_path_surface(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace(
            "hiddenimports += collect_submodules('one_link_native')",
            "_d, _b, _h = collect_all('one_link_native')",
        ),
        encoding="utf-8",
    )
    with pytest.raises(mod.GateFailure, match="no collect_all"):
        mod.validate_spec(spec)


def test_validate_spec_rejects_dead_native_collector_bypass(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace(
            "hiddenimports += collect_submodules('one_link_native')",
            "if False:\n    hiddenimports += collect_submodules('one_link_native')",
        ),
        encoding="utf-8",
    )

    with pytest.raises(mod.GateFailure, match="exact live top-level"):
        mod.validate_spec(spec)


@pytest.mark.parametrize(
    "excluded",
    [
        *EXPECTED_STABLE_EXCLUDES,
    ],
)
def test_validate_spec_requires_every_stable_preview_exclusion(tmp_path, excluded):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec().replace(f"'{excluded}',", ""), encoding="utf-8")
    with pytest.raises(mod.GateFailure, match=excluded.replace(".", r"\.")):
        mod.validate_spec(spec)


def test_validate_spec_rejects_missing_recovery_api(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace("'one_link.recovery_api',", ""),
        encoding="utf-8",
    )
    with pytest.raises(mod.GateFailure, match="one_link.recovery_api"):
        mod.validate_spec(spec)


def test_validate_spec_rejects_missing_package_data(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec().replace("('src/one_link/data', 'one_link/data'), ", ""),
        encoding="utf-8",
    )
    with pytest.raises(mod.GateFailure, match="one_link/data"):
        mod.validate_spec(spec)


def test_validate_spec_rejects_unreviewed_data_or_submodule_collection(tmp_path):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(
        _good_spec()
        .replace("datas = [", "datas = [('secret.txt', 'unreviewed'), ")
        .replace(
            "hiddenimports += collect_submodules('one_link_native')",
            "hiddenimports += collect_submodules('one_link_native')\n"
            "hiddenimports += collect_submodules('packaging')",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        mod.GateFailure,
        match="exact stable package-data.*exact live top-level collect_submodules",
    ):
        mod.validate_spec(spec)


@pytest.mark.parametrize(
    "preview_fragment",
    [
        "ONE_LINK_PREVIEW_ML = True",
        "ONE_LINK_PREVIEW_ML = False\ndatas += [('assets/models/x', 'assets/models/x')]",
        "ONE_LINK_PREVIEW_ML = False\n_d, _b, _h = collect_all('onnxruntime')",
    ],
)
def test_validate_spec_rejects_preview_payload_in_stable_artifact(
    tmp_path,
    preview_fragment,
):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    base = _good_spec().replace("ONE_LINK_PREVIEW_ML = False", "")
    spec.write_text(preview_fragment + "\n" + base, encoding="utf-8")
    with pytest.raises(mod.GateFailure, match="preview"):
        mod.validate_spec(spec)


def test_stable_onedir_scan_rejects_preview_model_bytes(tmp_path):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    model = bundle / "_internal" / "assets" / "models" / "voice"
    model.mkdir(parents=True)
    (bundle / "one-link.exe").write_bytes(b"launcher")
    (model / "checkpoint.onnx.data").write_bytes(b"weights")
    with pytest.raises(mod.GateFailure, match="forbidden preview/dev/tooling/local-build"):
        mod.validate_stable_bundle_contents(bundle)


def test_stable_onedir_scan_accepts_normal_runtime_tree(tmp_path, monkeypatch):
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    mod = _load_module()
    bundle = tmp_path / "one-link"
    runtime = bundle / "_internal" / "one_link" / "web"
    runtime.mkdir(parents=True)
    (bundle / "one-link.exe").write_bytes(b"launcher")
    (runtime / "index.html").write_text("ok", encoding="utf-8")
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (EXPECTED_STABLE_RUNTIME_MODULES, {}),
    )
    assert "nested PYZ inspected" in mod.validate_stable_bundle_contents(bundle)


@pytest.mark.parametrize(
    "relative",
    [
        "_internal/lxml/etree.cp314-win_amd64.pyd",
        "_internal/hypothesis/vendor/pretty.py",
        "_internal/mypy_extensions.cp314-win_amd64.pyd",
        "_internal/sigstore-4.4.0.dist-info/METADATA",
        "_internal/pydantic_core/_pydantic_core.cp314-win_amd64.pyd",
        "_internal/torch/lib/torch_cuda.dll",
        "_internal/torch_cuda.dll",
        "_internal/one_link_native-0.21.0.dist-info/direct_url.json",
        "_internal/one_link_native-0.21.0.dist-info/uv_cache.json",
    ],
)
def test_stable_onedir_scan_rejects_physical_dev_or_local_build_payload(
    tmp_path,
    relative,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    payload = bundle / relative
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"forbidden")
    (bundle / "one-link.exe").write_bytes(b"launcher")
    with pytest.raises(mod.GateFailure, match="forbidden preview/dev/tooling/local-build"):
        mod.validate_stable_bundle_contents(bundle)


def test_stable_nested_pyz_scan_uses_exact_namespace_boundaries(tmp_path, monkeypatch):
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    (bundle / "one-link.exe").write_bytes(b"launcher")
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (
            EXPECTED_STABLE_RUNTIME_MODULES + ("packaging.numpyish", "click.wheelhouse"),
            {},
        ),
    )
    assert "nested PYZ inspected" in mod.validate_stable_bundle_contents(bundle)

    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (EXPECTED_STABLE_RUNTIME_MODULES + ("numpy.f2py",), {}),
    )
    with pytest.raises(mod.GateFailure, match=r"nested PYZ.*numpy\.f2py"):
        mod.validate_stable_bundle_contents(bundle)


def test_stable_nested_pyz_scan_fails_closed_when_archive_is_not_inspectable(
    tmp_path,
):
    mod = _load_module()
    executable = tmp_path / "one-link.exe"
    executable.write_bytes(b"not-a-pyinstaller-archive")
    with pytest.raises(mod.GateFailure, match="parse frozen executable archive"):
        mod.validate_stable_bundle_contents(executable)


def test_nested_pyz_reader_extracts_and_hashes_code_objects_directly(
    tmp_path,
    monkeypatch,
):
    from PyInstaller.archive import readers
    from one_link.build_identity import (
        EXPECTED_STABLE_RUNTIME_MODULES,
        normalized_code_sha256,
    )

    mod = _load_module()
    executable = tmp_path / "one-link.exe"
    executable.write_bytes(b"synthetic-carchive")
    code_objects = {
        module: compile(
            f"MODULE_INDEX = {index}\n",
            f"<frozen {module}>",
            "exec",
            dont_inherit=True,
        )
        for index, module in enumerate(EXPECTED_STABLE_RUNTIME_MODULES)
    }

    class _SyntheticPyz:
        toc = {module: (False, 0, 1) for module in code_objects}

        @staticmethod
        def extract(module):
            return code_objects[module]

    class _SyntheticCArchive:
        toc = {"PYZ.pyz": (0, 0, 0, "z")}

        def __init__(self, path):
            assert Path(path) == executable.resolve()

        @staticmethod
        def open_embedded_archive(name):
            assert name == "PYZ.pyz"
            return _SyntheticPyz()

    monkeypatch.setattr(readers, "CArchiveReader", _SyntheticCArchive)
    modules, digests = mod._embedded_python_archive(executable)

    assert set(modules) == set(EXPECTED_STABLE_RUNTIME_MODULES)
    assert digests == {
        module: normalized_code_sha256(code)
        for module, code in code_objects.items()
    }


def test_physical_python_zip_scan_supports_directory_containing_macos_app(tmp_path):
    mod = _load_module()
    container = tmp_path / "staged"
    app = container / "one-link.app"
    _complete_macos_inventory_bundle(app)
    base_library = app / "Contents" / "Frameworks" / "base_library.zip"
    with zipfile.ZipFile(base_library, "w") as archive:
        archive.writestr("encodings/__init__.pyc", b"stdlib-bytecode")

    assert mod._inspect_physical_python_archives(container) == (1, 1)


def test_physical_python_zip_scan_rejects_forbidden_namespace(tmp_path):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    internal = bundle / "_internal"
    internal.mkdir(parents=True)
    (bundle / "one-link.exe").write_bytes(b"launcher")
    with zipfile.ZipFile(internal / "base_library.zip", "w") as archive:
        archive.writestr("numpy/f2py.pyc", b"forbidden-bytecode")

    with pytest.raises(mod.GateFailure, match=r"forbidden modules.*numpy\.f2py"):
        mod._inspect_physical_python_archives(bundle)


def test_independent_bundle_walk_enforces_directory_budget(tmp_path, monkeypatch):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    (bundle / "nested").mkdir(parents=True)
    (bundle / "one-link.exe").write_bytes(b"launcher")
    monkeypatch.setattr(mod, "STABLE_FROZEN_MAX_DIRECTORIES", 1)

    with pytest.raises(mod.GateFailure, match="directory budget exceeded"):
        mod._independent_bundle_hashes(bundle)


def test_artifact_root_link_is_rejected_before_enumeration(tmp_path):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    (bundle / "one-link.exe").write_bytes(b"launcher")
    alias = tmp_path / "aliased-bundle"
    try:
        alias.symlink_to(bundle, target_is_directory=True)
    except OSError:
        pytest.skip("directory symbolic links are unavailable on this host")

    with pytest.raises(mod.GateFailure, match="root is a link/reparse point"):
        mod._find_artifact_executable(alias)


def test_nested_unreviewed_launcher_is_never_accepted_as_primary(tmp_path):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    nested = bundle / "backup"
    nested.mkdir(parents=True)
    (nested / "one-link.exe").write_bytes(b"unreviewed-launcher")

    with pytest.raises(mod.GateFailure, match="exactly one reviewed"):
        mod._find_artifact_executable(bundle)


def test_safe_bundle_link_digest_accepts_contained_relative_and_rejects_escape(
    tmp_path,
):
    mod = _load_module()
    root = tmp_path / "bundle"
    link = root / "links" / "payload"
    link.parent.mkdir(parents=True)
    (root / "target.bin").write_bytes(b"target")
    digest = mod._safe_relative_link_sha256(
        root,
        link,
        link_target="../target.bin",
    )
    assert len(digest) == 64
    assert digest == mod._safe_relative_link_sha256(
        root,
        link,
        link_target="../target.bin",
    )

    (tmp_path / "outside.bin").write_bytes(b"outside")
    with pytest.raises(mod.GateFailure, match="escapes artifact"):
        mod._safe_relative_link_sha256(
            root,
            link,
            link_target="../../outside.bin",
        )
    with pytest.raises(mod.GateFailure, match="absolute"):
        mod._safe_relative_link_sha256(
            root,
            link,
            link_target=str((tmp_path / "outside.bin").resolve()),
        )


def test_validate_version_rejects_stale_binary_output(tmp_path, monkeypatch):
    mod = _load_module()
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["one-link", "--version"],
            returncode=0,
            stdout="one-link, version 0.20.0",
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    with pytest.raises(mod.GateFailure, match="packaged version mismatch"):
        mod.validate_version(exe, "0.21.0-alpha")


def test_validate_version_accepts_current_binary_output(tmp_path, monkeypatch):
    mod = _load_module()
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=["one-link", "--version"],
            returncode=0,
            stdout="one-link, version 0.21.0-alpha",
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    assert "0.21.0-alpha" in mod.validate_version(exe, "0.21.0-alpha")


def test_artifact_commands_run_from_disposable_home_without_python_overrides(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"fake")
    monkeypatch.setenv("PYTHONPATH", str(SCRIPT.parent.parent / "src"))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "host-python"))
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "venv"))
    monkeypatch.setenv("ONE_LINK_DATA_DIR", str(tmp_path / "host-state"))
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["cwd"] = Path(kwargs["cwd"])
        observed["cwd_existed"] = Path(kwargs["cwd"]).is_dir()
        observed["env"] = kwargs["env"]
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="one-link, version 0.21.0-alpha",
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    assert "0.21.0-alpha" in mod.validate_version(exe, "0.21.0-alpha")

    command = observed["command"]
    assert command == [str(exe.resolve()), "--version"]
    assert observed["cwd_existed"] is True
    assert Path(observed["cwd"]).resolve() != SCRIPT.parent.parent.resolve()
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert "PYTHONPATH" not in environment
    assert "PYTHONHOME" not in environment
    assert "VIRTUAL_ENV" not in environment
    assert "ONE_LINK_DATA_DIR" not in environment
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["HOME"] == environment["USERPROFILE"]


def test_validate_install_inventory_accepts_complete_frozen_bundle(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    payload = _valid_install_inventory_payload(bundle, exe)
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )

    result = mod.validate_install_inventory(
        bundle,
        "0.21.0-alpha",
    )
    assert f"covers {payload['file_count']} files" in result
    assert "stable runtime modules" in result
    assert "source package-data files plus exact Python source manifest match" in result


def test_validate_install_inventory_accepts_current_macos_app_layout(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    app = tmp_path / "one-link.app"
    exe = _complete_macos_inventory_bundle(app)
    payload = _valid_install_inventory_payload(app, exe)
    payload["inventory_mode"] = "frozen_macos_app_bundle"
    payload["inventory_root"] = str(app)
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )

    result = mod.validate_install_inventory(app, "0.21.0-alpha")
    assert "exact Python source manifest match" in result
    assert mod._find_artifact_executable(app) == exe


@pytest.mark.parametrize(
    ("case", "match"),
    [
        ("wrong_count", "count mismatch"),
        ("wrong_digest", "manifest digest"),
        ("omitted_module", "inventory keys"),
        ("external_origin", "incomplete or externally shadowed"),
        ("reported_missing", "incomplete or externally shadowed"),
    ],
)
def test_validate_install_inventory_rejects_runtime_manifest_mismatch(
    tmp_path,
    monkeypatch,
    case,
    match,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    payload = _valid_install_inventory_payload(bundle, exe)
    runtime_modules = payload["runtime_modules"]
    assert isinstance(runtime_modules, dict)
    target = "one_link.storage_lifecycle"
    if case == "wrong_count":
        payload["runtime_module_count"] = int(payload["runtime_module_count"]) - 1
    elif case == "wrong_digest":
        payload["runtime_module_manifest_sha256"] = "0" * 64
    elif case == "omitted_module":
        runtime_modules.pop(target)
    elif case == "external_origin":
        runtime_modules[target] = "OUTSIDE_EXPECTED_ROOT"
    elif case == "reported_missing":
        payload["missing_runtime_modules"] = [target]
    else:  # pragma: no cover - parametrization contract
        raise AssertionError(case)

    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match=match):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_install_inventory_rejects_self_reported_file_omission(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    payload = _valid_install_inventory_payload(bundle, exe)
    omitted = bundle / "_internal" / "omitted-runtime.bin"
    omitted.write_bytes(b"must be independently discovered")
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match="independent artifact walk"):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_install_inventory_rejects_stale_packaged_web_asset(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    (bundle / "_internal" / "one_link" / "web" / "sw.js").write_text(
        "stale worker",
        encoding="utf-8",
    )
    payload = _valid_install_inventory_payload(bundle, exe)
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match="web/data payload"):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_install_inventory_rejects_unexpected_old_package_asset(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    (bundle / "_internal" / "one_link" / "web" / "retired-worker.js").write_text(
        "stale asset",
        encoding="utf-8",
    )
    payload = _valid_install_inventory_payload(bundle, exe)
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match="unexpected=.*retired-worker"):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_install_inventory_rejects_stale_python_source_manifest(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    exe = _complete_inventory_bundle(bundle)
    manifest = bundle / "_internal" / "one_link" / "_build" / "runtime-source-manifest.json"
    manifest.write_text('{"schema":"stale"}\n', encoding="utf-8")
    payload = _valid_install_inventory_payload(bundle, exe)
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match="source manifest differs"):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_runtime_imports_requires_loadable_stable_and_absent_preview(
    tmp_path,
    monkeypatch,
):
    from one_link import build_identity

    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    exe = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"frozen-executable")
    runtime_modules = {
        module: "IMPORTED" for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES
    }
    source_manifest = mod._expected_runtime_source_manifest(SCRIPT.parent.parent)
    runtime_code_sha256 = {
        module: entry["normalized_code_sha256"]
        for module, entry in source_manifest["modules"].items()
    }
    forbidden = {module: "ABSENT" for module in build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES}
    native_modules = {
        module: "IMPORTED" for module in build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES
    }
    payload = {
        "runtime_modules": runtime_modules,
        "runtime_module_count": len(runtime_modules),
        "runtime_module_manifest_sha256": (build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256),
        "runtime_code_sha256": runtime_code_sha256,
        "runtime_import_errors": {},
        "invalid_runtime_modules": [],
        "runtime_source_manifest_sha256": hashlib.sha256(
            mod._canonical_manifest_bytes(source_manifest)
        ).hexdigest(),
        "runtime_source_manifest_status": "PRESENT",
        "forbidden_runtime_modules": forbidden,
        "forbidden_runtime_module_count": len(forbidden),
        "forbidden_runtime_module_manifest_sha256": (
            build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256
        ),
        "present_forbidden_runtime_modules": [],
        "native_package_status": "IMPORTED",
        "native_version": _NATIVE_VERSION_FIXTURE,
        "native_runtime_modules": native_modules,
        "native_runtime_module_count": len(native_modules),
        "native_runtime_module_manifest_sha256": (
            build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256
        ),
        "invalid_native_runtime_modules": [],
        "verification_status": "runtime_imports_ok",
    }
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (tuple(runtime_modules), runtime_code_sha256),
    )
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "runtime-import-smoke"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    assert "imported" in mod.validate_runtime_imports(bundle)

    runtime_modules["one_link.storage_lifecycle"] = "IMPORT_ERROR"
    payload["verification_status"] = "runtime_imports_failed"
    payload["invalid_runtime_modules"] = ["one_link.storage_lifecycle"]
    with pytest.raises(mod.GateFailure, match="runtime imports"):
        mod.validate_runtime_imports(bundle)


def test_validate_runtime_imports_rejects_stale_bytecode_and_native_abi(
    tmp_path,
    monkeypatch,
):
    from one_link import build_identity

    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    exe = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"frozen-executable")
    source_manifest = mod._expected_runtime_source_manifest(SCRIPT.parent.parent)
    runtime_code = {
        module: entry["normalized_code_sha256"]
        for module, entry in source_manifest["modules"].items()
    }
    runtime_modules = {
        module: "IMPORTED" for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES
    }
    forbidden = {module: "ABSENT" for module in build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES}
    native_modules = {
        module: "IMPORTED" for module in build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES
    }
    payload = {
        "runtime_modules": runtime_modules,
        "runtime_module_count": len(runtime_modules),
        "runtime_module_manifest_sha256": (build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256),
        "runtime_code_sha256": runtime_code,
        "invalid_runtime_modules": [],
        "runtime_source_manifest_status": "PRESENT",
        "runtime_source_manifest_sha256": hashlib.sha256(
            mod._canonical_manifest_bytes(source_manifest)
        ).hexdigest(),
        "forbidden_runtime_modules": forbidden,
        "forbidden_runtime_module_count": len(forbidden),
        "forbidden_runtime_module_manifest_sha256": (
            build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES_SHA256
        ),
        "present_forbidden_runtime_modules": [],
        "native_package_status": "IMPORTED",
        "native_version": _NATIVE_VERSION_FIXTURE,
        "native_runtime_modules": native_modules,
        "native_runtime_module_count": len(native_modules),
        "native_runtime_module_manifest_sha256": (
            build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES_SHA256
        ),
        "invalid_native_runtime_modules": [],
        "verification_status": "runtime_imports_ok",
    }

    def fake_run(*_args, **_kwargs):
        return subprocess.CompletedProcess(
            args=[str(exe), "runtime-import-smoke"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (tuple(runtime_modules), dict(runtime_code)),
    )
    target = "one_link.storage_lifecycle"
    runtime_code[target] = "0" * 64
    with pytest.raises(mod.GateFailure, match="bytecode differs"):
        mod.validate_runtime_imports(bundle)

    runtime_code[target] = source_manifest["modules"][target]["normalized_code_sha256"]
    native_target = build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES[0]
    native_modules[native_target] = "IMPORT_ERROR"
    payload["invalid_native_runtime_modules"] = [native_target]
    with pytest.raises(mod.GateFailure, match="native extension ABI"):
        mod.validate_runtime_imports(bundle)


def test_runtime_import_gate_rejects_forged_candidate_json_before_execution(
    tmp_path,
    monkeypatch,
):
    """Candidate self-reporting cannot conceal stale bytes in the nested PYZ."""
    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    executable.write_bytes(b"frozen-executable")
    source_manifest = mod._expected_runtime_source_manifest(SCRIPT.parent.parent)
    reported_good_digests = {
        module: entry["normalized_code_sha256"]
        for module, entry in source_manifest["modules"].items()
    }
    corrupt_digests = dict(reported_good_digests)
    corrupt_digests["one_link.storage_lifecycle"] = "0" * 64

    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (tuple(corrupt_digests), corrupt_digests),
    )

    def _forbid_candidate_execution(*_args, **_kwargs):
        raise AssertionError(
            "direct PYZ parity must fail before trusting candidate-emitted JSON"
        )

    monkeypatch.setattr(mod, "_run_artifact_command", _forbid_candidate_execution)
    with pytest.raises(mod.GateFailure, match="direct nested-PYZ bytecode differs"):
        mod.validate_runtime_imports(bundle, SCRIPT.parent.parent)


def test_validate_runtime_features_requires_exact_side_effect_free_contract(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    exe = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"frozen-executable")
    expected = {
        "aiortc_datachannel": "OK",
        "keyring_backend": "OK",
        "native_cdc_scan": "OK",
        "packaging_updater": "OK",
        "pillow_tray_icon": "OK",
        "psutil_process": "OK",
        "pyav_primitives": "OK",
        "pystray_backend": "OK",
        "qrcode_svg_stdlib": "OK",
        "sigstore_frozen_update_boundary": (
            "NOT_APPLICABLE_FROZEN_UPDATES_DISABLED"
        ),
        "sqlcipher_roundtrip": "OK",
        "watchdog_observer": "OK",
    }
    assert mod.RUNTIME_FEATURE_EXPECTED_STATUSES == expected
    payload = {
        "features": expected,
        "feature_count": len(expected),
        "feature_errors": {},
        "numpy_status": "ABSENT",
        "side_effect_policy": (
            "no_external_network_no_ui_no_keychain_access_isolated_temporary_io_only"
        ),
        "verification_status": "runtime_features_ok",
    }
    monkeypatch.setattr(
        mod,
        "_run_artifact_command",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "runtime-feature-smoke", "--json"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    assert "representative dependency operations" in mod.validate_runtime_features(bundle)

    payload["numpy_status"] = "PRESENT"
    with pytest.raises(mod.GateFailure, match="NumPy"):
        mod.validate_runtime_features(bundle)


def test_validate_runtime_features_rejects_missing_or_failed_feature(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    executable = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    executable.write_bytes(b"frozen-executable")
    features = dict(mod.RUNTIME_FEATURE_EXPECTED_STATUSES)
    features["pyav_primitives"] = "IMPORT_ERROR"
    payload = {
        "features": features,
        "feature_count": len(features),
        "feature_errors": {"pyav_primitives": "ImportError"},
        "numpy_status": "ABSENT",
        "side_effect_policy": "no_network_no_ui_no_keychain_access_no_database_write",
        "verification_status": "runtime_features_failed",
    }
    monkeypatch.setattr(
        mod,
        "_run_artifact_command",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(executable), "runtime-feature-smoke", "--json"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        ),
    )
    with pytest.raises(mod.GateFailure, match="statuses differ"):
        mod.validate_runtime_features(executable)


def test_validate_install_inventory_rejects_incomplete_runtime_gate(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    exe = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_bytes(b"frozen-executable")
    monkeypatch.setattr(
        mod.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[str(exe), "verify-this-install"],
            returncode=1,
            stdout=json.dumps(
                {
                    "verification_status": "incomplete_install",
                    "missing": ["bundle/_internal/base_library.zip"],
                }
            ),
            stderr="",
        ),
    )

    with pytest.raises(mod.GateFailure, match="inventory exited 1"):
        mod.validate_install_inventory(bundle, "0.21.0-alpha")


def test_validate_peer_headers_accepts_current_phone_shell_markers(monkeypatch):
    mod = _load_module()
    body = (
        b"<title>One Link -- Peer</title>"
        b"daemon-global-search-input"
        b"setup_device_invite"
        b"cert-authed reconnect"
    )

    monkeypatch.setattr(
        mod,
        "_request",
        lambda *_a, **_kw: (
            200,
            {
                "cache-control": "no-cache, must-revalidate",
                "etag": '"abc"',
            },
            body,
        ),
    )
    assert "ETag" in mod.validate_peer_headers("https://127.0.0.1:7118", None)


def test_validate_peer_headers_rejects_stale_phone_shell(monkeypatch):
    mod = _load_module()
    monkeypatch.setattr(
        mod,
        "_request",
        lambda *_a, **_kw: (
            200,
            {
                "cache-control": "no-cache, must-revalidate",
                "etag": '"abc"',
            },
            b"<title>One Link -- Peer</title>",
        ),
    )
    with pytest.raises(mod.GateFailure, match="daemon-global-search-input"):
        mod.validate_peer_headers("https://127.0.0.1:7118", None)


def test_cli_static_gate_passes_with_skip_version(tmp_path, monkeypatch, capsys):
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (EXPECTED_STABLE_RUNTIME_MODULES, {}),
    )
    monkeypatch.setattr(mod, "validate_native_cdc_payload", lambda _artifact: "native ok")
    rc = mod.main(
        [
            "--artifact",
            str(exe),
            "--spec",
            str(spec),
            "--skip-version",
            "--skip-runtime-inventory",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "PACKAGED ARTIFACT PARITY: PASS" in out


def test_cli_fails_when_spec_missing_dynamic_import(tmp_path, capsys):
    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text("hiddenimports = []\n", encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    rc = mod.main(
        [
            "--artifact",
            str(exe),
            "--spec",
            str(spec),
            "--skip-version",
            "--skip-runtime-inventory",
        ]
    )
    err = capsys.readouterr().err
    assert rc == 1
    assert "one_link.sessions" in err
    assert "one_link.recovery_api" in err


def test_final_release_zip_is_safely_extracted_and_all_gates_run_from_download(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    packager_path = SCRIPT.with_name("package_standalone_bundle.py")
    packager_spec = importlib.util.spec_from_file_location(
        "_test_release_bundle_packager",
        packager_path,
    )
    assert packager_spec is not None and packager_spec.loader is not None
    packager = importlib.util.module_from_spec(packager_spec)
    sys.modules[packager_spec.name] = packager
    packager_spec.loader.exec_module(packager)

    bundle = tmp_path / "one-link"
    bundle.mkdir()
    executable = bundle / "one-link.exe"
    executable.write_bytes(b"launcher")
    # package_bundle REFUSES a POSIX bundle whose executable has no execute bit
    # -- correctly, since such a zip is unusable once extracted. This fixture
    # created a mode-0644 launcher, so the test only ever passed on Windows
    # (where the check is skipped) and failed on Linux for a fixture defect
    # rather than a product one. Model a real bundle instead.
    executable.chmod(0o755)
    release_zip = tmp_path / "one-link-windows-x86_64.zip"
    packager.package_bundle(
        bundle,
        release_zip,
        executable=executable.name,
        epoch=1_700_000_000,
    )

    calls: list[tuple[str, Path]] = []

    def _record(name):
        def _gate(artifact, *_args, **_kwargs):
            calls.append((name, Path(artifact)))
            return f"{name} ok"

        return _gate

    for gate in (
        "validate_stable_bundle_contents",
        "validate_native_cdc_payload",
        "validate_version",
        "validate_install_inventory",
        "validate_runtime_imports",
        "validate_runtime_features",
        "validate_frozen_e2e",
    ):
        monkeypatch.setattr(mod, gate, _record(gate))

    result = mod.validate_release_archive(
        release_zip,
        bundle,
        repo=SCRIPT.parent.parent,
        expected_version="0.21.0-alpha",
        run_frozen_e2e=True,
    )

    assert "manifest and every member digest revalidated" in result
    assert "two-daemon E2E" in result
    assert [name for name, _artifact in calls] == [
        "validate_stable_bundle_contents",
        "validate_native_cdc_payload",
        "validate_version",
        "validate_install_inventory",
        "validate_runtime_imports",
        "validate_runtime_features",
        "validate_frozen_e2e",
    ]
    extracted_paths = {artifact for _name, artifact in calls}
    assert len(extracted_paths) == 1
    assert bundle not in extracted_paths
    assert next(iter(extracted_paths)).name == "one-link"


def test_final_release_zip_rejects_traversal_before_creating_destination(
    tmp_path,
    monkeypatch,
):
    mod = _load_module()
    bundle = tmp_path / "one-link"
    bundle.mkdir()
    (bundle / "one-link.exe").write_bytes(b"launcher")
    release_zip = tmp_path / "malicious.zip"
    with zipfile.ZipFile(release_zip, "w") as archive:
        archive.writestr("one-link/one-link.exe", b"launcher")
        archive.writestr("one-link/../../escaped/payload.bin", b"escape")
        archive.writestr(
            "one-link/BUNDLE_SHA256SUMS",
            "# sha256\tkind\tbytes\tpath\ttarget\n",
        )

    mkdir_calls: list[Path] = []

    def _unexpected_mkdir(path, *_args, **_kwargs):
        mkdir_calls.append(Path(path))
        raise AssertionError("an unsafe archive reached the extraction mutation boundary")

    monkeypatch.setattr(Path, "mkdir", _unexpected_mkdir)

    with pytest.raises(mod.GateFailure, match="manifest/hash validation failed"):
        mod.validate_release_archive(
            release_zip,
            bundle,
            repo=SCRIPT.parent.parent,
            expected_version="0.21.0-alpha",
            run_frozen_e2e=False,
        )
    assert mkdir_calls == []
    assert not (tmp_path / "escaped").exists()


def test_live_probe_functions_are_called_when_base_url_supplied(
    tmp_path,
    monkeypatch,
    capsys,
):
    from one_link.build_identity import EXPECTED_STABLE_RUNTIME_MODULES

    mod = _load_module()
    spec = tmp_path / "one-link.spec"
    spec.write_text(_good_spec(), encoding="utf-8")
    exe = tmp_path / ("one-link.exe" if sys.platform == "win32" else "one-link")
    exe.write_text("fake", encoding="utf-8")
    called: list[str] = []

    monkeypatch.setattr(
        mod, "validate_peer_headers", lambda *_a: called.append("peer") or "peer ok"
    )
    monkeypatch.setattr(
        mod, "validate_recovery_routes", lambda *_a: called.append("recovery") or "recovery ok"
    )
    monkeypatch.setattr(mod, "validate_alpn", lambda *_a: called.append("alpn") or "alpn ok")
    monkeypatch.setattr(
        mod, "validate_cert_chain_with_openssl", lambda *_a: called.append("chain") or "chain ok"
    )
    monkeypatch.setattr(
        mod,
        "_embedded_python_archive",
        lambda _exe: (EXPECTED_STABLE_RUNTIME_MODULES, {}),
    )
    monkeypatch.setattr(mod, "validate_native_cdc_payload", lambda _artifact: "native ok")

    rc = mod.main(
        [
            "--artifact",
            str(exe),
            "--spec",
            str(spec),
            "--skip-version",
            "--skip-runtime-inventory",
            "--base-url",
            "https://127.0.0.1:7118",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert called == ["peer", "recovery", "alpn", "chain"]
    assert "chain ok" in out


def test_cert_chain_probe_falls_back_to_python_ssl(monkeypatch):
    mod = _load_module()
    called: list[tuple[str, int]] = []

    def fake_run(*_args, **_kwargs):
        raise FileNotFoundError("openssl")

    def fake_python_ssl(host, port, cacert):
        called.append((host, port))
        return "TLS serves a chain with 2 certificates"

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod, "_validate_cert_chain_with_python_ssl", fake_python_ssl)
    out = mod.validate_cert_chain_with_openssl("https://127.0.0.1:7118", None)
    assert out == "TLS serves a chain with 2 certificates"
    assert called == [("127.0.0.1", 7118)]
