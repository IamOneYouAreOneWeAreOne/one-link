"""Fail-closed tests for the local install inventory command."""

from __future__ import annotations

import hashlib
import json
import stat
import sys
import types
from pathlib import Path

from click.testing import CliRunner

from one_link.cli import cli


def _complete_fake_package(root: Path) -> None:
    from one_link import build_identity

    for relative in build_identity._FINGERPRINT_FILES:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(f"fixture:{relative}".encode())


def _accept_all_runtime_modules(monkeypatch) -> None:
    """Keep filesystem-fixture tests focused on their intended failure."""
    from one_link import build_identity

    monkeypatch.setattr(
        build_identity,
        "stable_runtime_module_statuses",
        lambda _root: {
            module: "PRESENT" for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES
        },
    )
    monkeypatch.setattr(
        build_identity,
        "stable_forbidden_runtime_module_statuses",
        lambda _root: {
            module: "ABSENT" for module in build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES
        },
    )


def _fake_frozen_onedir(tmp_path: Path, monkeypatch) -> Path:
    """Create the minimum valid managed onedir layout for CLI tests."""
    from one_link.native_cdc import native_library_name, native_platform_tag

    bundle = tmp_path / "one-link"
    executable = bundle / ("one-link.exe" if sys.platform == "win32" else "one-link")
    internal = bundle / "_internal"
    package = internal / "one_link"
    native_package = internal / "one_link_native"
    cdc_root = package / "native" / native_platform_tag()
    cdc_library = cdc_root / native_library_name()

    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"frozen-launcher-with-pyz")
    (internal / "base_library.zip").parent.mkdir(parents=True, exist_ok=True)
    (internal / "base_library.zip").write_bytes(b"python-base-library")
    (package / "web").mkdir(parents=True)
    (package / "web" / "index.html").write_text("<main>One Link</main>", encoding="utf-8")
    (package / "data").mkdir(parents=True)
    (package / "data" / "bip39-english.txt").write_text("abandon\n", encoding="utf-8")
    (package / "data" / "oui_prefixes.txt.gz").write_bytes(b"fake-gzip")
    (package / "_build").mkdir(parents=True)
    (package / "_build" / "runtime-source-manifest.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    cdc_root.mkdir(parents=True)
    cdc_library.write_bytes(b"fresh-native-cdc")
    cdc_library.with_suffix(cdc_library.suffix + ".sha256").write_text(
        f"{hashlib.sha256(cdc_library.read_bytes()).hexdigest()}  {cdc_library.name}\n",
        encoding="ascii",
    )
    native_package.mkdir(parents=True)
    (native_package / "__init__.py").write_text("", encoding="utf-8")
    extension_suffix = ".pyd" if sys.platform == "win32" else ".so"
    (native_package / f"one_link_native{extension_suffix}").write_bytes(b"native-extension")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "_MEIPASS", str(internal), raising=False)
    _accept_all_runtime_modules(monkeypatch)
    return bundle


def _fake_frozen_macos_app(tmp_path: Path, monkeypatch) -> Path:
    """Model PyInstaller 6's Frameworks/Resources macOS app layout."""
    from one_link.native_cdc import native_library_name, native_platform_tag

    app = tmp_path / "one-link.app"
    contents = app / "Contents"
    executable = contents / "MacOS" / "one-link"
    frameworks = contents / "Frameworks"
    resources = contents / "Resources"
    runtime_package = frameworks / "one_link"
    data_package = resources / "one_link"
    native_package = frameworks / "one_link_native"
    cdc_root = runtime_package / "native" / native_platform_tag()
    cdc_library = cdc_root / native_library_name()

    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"macos-frozen-launcher")
    (contents / "Info.plist").write_text("<plist/>", encoding="utf-8")
    frameworks.mkdir()
    resources.mkdir()
    (frameworks / "base_library.zip").write_bytes(b"python-base-library")
    (data_package / "web").mkdir(parents=True)
    (data_package / "web" / "index.html").write_text("One Link", encoding="utf-8")
    (data_package / "data").mkdir(parents=True)
    (data_package / "data" / "bip39-english.txt").write_text(
        "abandon\n",
        encoding="utf-8",
    )
    (data_package / "data" / "oui_prefixes.txt.gz").write_bytes(b"fake-gzip")
    (data_package / "_build").mkdir(parents=True)
    (data_package / "_build" / "runtime-source-manifest.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    cdc_root.mkdir(parents=True)
    cdc_library.write_bytes(b"fresh-native-cdc")
    sidecar = data_package / "native" / native_platform_tag() / f"{cdc_library.name}.sha256"
    sidecar.parent.mkdir(parents=True)
    sidecar.write_text(
        f"{hashlib.sha256(cdc_library.read_bytes()).hexdigest()}  {cdc_library.name}\n",
        encoding="ascii",
    )
    native_package.mkdir()
    (native_package / "__init__.py").write_text("", encoding="utf-8")
    extension_suffix = ".pyd" if sys.platform == "win32" else ".so"
    (native_package / f"one_link_native{extension_suffix}").write_bytes(b"native-extension")

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setattr(sys, "_MEIPASS", str(frameworks), raising=False)
    _accept_all_runtime_modules(monkeypatch)
    return app


def test_expected_stable_runtime_manifest_exactly_matches_source_tree() -> None:
    from one_link import build_identity

    root = build_identity.package_root()
    discovered: set[str] = set()
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if relative.name == "__init__.py":
            suffix = ".".join(relative.parent.parts)
        else:
            suffix = ".".join(relative.with_suffix("").parts)
        module = "one_link" if not suffix else f"one_link.{suffix}"
        if module in build_identity.STABLE_RUNTIME_EXCLUDED_MODULES:
            continue
        if any(
            module == prefix or module.startswith(f"{prefix}.")
            for prefix in build_identity.STABLE_RUNTIME_EXCLUDED_PREFIXES
        ):
            continue
        discovered.add(module)

    expected = build_identity.EXPECTED_STABLE_RUNTIME_MODULES
    assert expected == tuple(sorted(expected)), "manifest must be canonical and sorted"
    assert len(expected) == len(set(expected)), "manifest contains duplicate modules"
    assert tuple(sorted(discovered)) == expected
    assert len(expected) >= 190
    assert (
        build_identity.stable_runtime_manifest_sha256()
        == build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256
    )


def test_runtime_module_statuses_reject_missing_external_and_broken_specs(
    tmp_path,
    monkeypatch,
) -> None:
    from importlib.machinery import ModuleSpec

    from one_link import build_identity

    expected_root = tmp_path / "managed"
    expected_root.mkdir()
    modules = (
        "one_link.broken",
        "one_link.external",
        "one_link.missing",
        "one_link.present",
    )
    monkeypatch.setattr(build_identity, "EXPECTED_STABLE_RUNTIME_MODULES", modules)

    class _CodeLoader:
        def get_code(self, _module: str):
            return compile("value = 1\n", "present.py", "exec")

    def fake_find_spec(module: str):
        if module == "one_link.broken":
            raise ImportError("broken importer")
        if module == "one_link.missing":
            return None
        if module == "one_link.external":
            return ModuleSpec(module, _CodeLoader(), origin=str(tmp_path / "shadow.py"))
        return ModuleSpec(
            module,
            _CodeLoader(),
            origin=str(expected_root / "present.py"),
        )

    monkeypatch.setattr(build_identity.importlib.util, "find_spec", fake_find_spec)
    assert build_identity.stable_runtime_module_statuses(expected_root) == {
        "one_link.broken": "SPEC_ERROR",
        "one_link.external": "OUTSIDE_EXPECTED_ROOT",
        "one_link.missing": "MISSING",
        "one_link.present": "PRESENT",
    }


def test_runtime_module_statuses_require_loadable_code(tmp_path, monkeypatch) -> None:
    from importlib.machinery import ModuleSpec

    from one_link import build_identity

    expected_root = tmp_path / "managed"
    expected_root.mkdir()
    modules = ("one_link.no_code", "one_link.unloadable")
    monkeypatch.setattr(build_identity, "EXPECTED_STABLE_RUNTIME_MODULES", modules)

    class _NoCodeLoader:
        def get_code(self, _module: str):
            return None

    class _BrokenCodeLoader:
        def get_code(self, _module: str):
            raise ImportError("corrupt bytecode")

    def fake_find_spec(module: str):
        loader = _NoCodeLoader() if module.endswith("no_code") else _BrokenCodeLoader()
        return ModuleSpec(module, loader, origin=str(expected_root / f"{module}.py"))

    monkeypatch.setattr(build_identity.importlib.util, "find_spec", fake_find_spec)
    assert build_identity.stable_runtime_module_statuses(expected_root) == {
        "one_link.no_code": "MISSING_CODE",
        "one_link.unloadable": "UNLOADABLE_CODE",
    }


def test_forbidden_runtime_statuses_distinguish_absent_internal_and_external(
    tmp_path,
    monkeypatch,
) -> None:
    from importlib.machinery import ModuleSpec

    from one_link import build_identity

    expected_root = tmp_path / "managed"
    expected_root.mkdir()
    modules = ("absent", "external", "internal")
    monkeypatch.setattr(build_identity, "STABLE_RUNTIME_FORBIDDEN_MODULES", modules)

    def fake_find_spec(module: str):
        if module == "absent":
            return None
        origin = expected_root / "bad.py" if module == "internal" else tmp_path / "shadow.py"
        return ModuleSpec(module, object(), origin=str(origin))

    monkeypatch.setattr(build_identity.importlib.util, "find_spec", fake_find_spec)
    assert build_identity.stable_forbidden_runtime_module_statuses(expected_root) == {
        "absent": "ABSENT",
        "external": "PRESENT_OUTSIDE_BUNDLE",
        "internal": "PRESENT_IN_BUNDLE",
    }


def test_verify_command_fails_closed_on_missing_runtime_module(monkeypatch) -> None:
    from one_link import build_identity

    missing_module = "one_link.storage_lifecycle"

    def statuses(_root: Path) -> dict[str, str]:
        return {
            module: "MISSING" if module == missing_module else "PRESENT"
            for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES
        }

    monkeypatch.setattr(build_identity, "stable_runtime_module_statuses", statuses)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["missing_runtime_modules"] == [missing_module]
    assert f"runtime-module/{missing_module}" in payload["missing"]
    assert payload["verification_status"] == "incomplete_install"


# ── command registration + basic shape ─────────────────────────────


def test_verify_command_is_registered():
    """Top-level `one-link verify-this-install` exists and shows
    help text mentioning the trust property."""
    result = CliRunner().invoke(cli, ["verify-this-install", "--help"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "version" in out
    assert "rollup" in out or "hash" in out


def test_verify_command_runs_clean_on_source_install():
    """A source-tree run should exit 0 + emit the version + rollup
    + per-file hashes for every load-bearing file. No file should
    show as MISSING (the test runs against the repo itself, so
    every file in _FINGERPRINT_FILES exists)."""
    result = CliRunner().invoke(cli, ["verify-this-install", "--inventory-only"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "One Link version:" in out
    assert "Rollup" in out
    assert "MISSING" not in out, (
        "load-bearing source files reported missing; either the "
        "fingerprint list is stale or the repo install is incomplete"
    )


# ── JSON mode for tooling ─────────────────────────────────────────


def test_verify_command_json_mode_emits_parseable_output():
    """--json flag emits a single JSON object the CI release pipeline
    can parse to compare hashes across rebuilds."""
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "version" in data
    assert "rollup_sha256" in data
    assert "files" in data
    assert isinstance(data["files"], dict)
    assert "frozen_binary_sha256" in data
    assert data["verification_status"] == "inventory_only"
    assert data["authenticity_verified"] is False
    assert data["inventory_mode"] == "source_or_installed_packages"
    assert data["inventory_root"] == data["package_root"]
    assert data["file_count"] > 9
    assert data["native_package_root"] is not None
    assert any(Path(name).name.startswith("one_link_native.") for name in data["files"])
    assert data["runtime_module_count"] == len(data["runtime_modules"])
    assert data["missing_runtime_modules"] == []
    assert set(data["runtime_modules"].values()) == {"PRESENT"}
    assert len(data["runtime_module_manifest_sha256"]) == 64
    assert data["forbidden_runtime_modules"] == {}
    assert data["forbidden_runtime_module_count"] == 0
    assert len(data["forbidden_runtime_module_manifest_sha256"]) == 64
    # Source install -> frozen_binary is null.
    assert data["frozen_binary_sha256"] is None


def test_verify_command_rollup_is_deterministic():
    """Two consecutive runs MUST emit the same rollup. If the rollup
    depends on mtime / non-deterministic ordering, an auditor's
    'compare against release notes' workflow breaks."""
    args = ["verify-this-install", "--json", "--inventory-only"]
    r1 = CliRunner().invoke(cli, args)
    r2 = CliRunner().invoke(cli, args)
    d1 = json.loads(r1.output)
    d2 = json.loads(r2.output)
    assert d1["rollup_sha256"] == d2["rollup_sha256"]
    assert d1["files"] == d2["files"]


def test_verify_command_rollup_changes_when_a_load_bearing_file_changes(tmp_path, monkeypatch):
    """If ANY load-bearing source file's bytes change, the rollup
    must change too. Otherwise tampering would be invisible to the
    verify command, which defeats its whole purpose."""
    # Read the baseline.
    r0 = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    baseline = json.loads(r0.output)
    baseline_rollup = baseline["rollup_sha256"]

    # Temporarily redirect the build_identity's package_root to a
    # tmp copy with one file mutated; verify the rollup changes.
    import shutil
    from one_link import build_identity

    real_root = build_identity.package_root()

    fake_root = tmp_path / "one_link_fake"
    fake_root.mkdir()
    # Copy every fingerprint file into the fake root.
    for rel in build_identity._FINGERPRINT_FILES:
        src = real_root / rel
        dst = fake_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_file():
            shutil.copy2(src, dst)
    # Mutate one file by appending a byte.
    with (fake_root / "__init__.py").open("ab") as handle:
        handle.write(b"\n# tamper\n")

    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    _accept_all_runtime_modules(monkeypatch)
    r1 = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    mutated = json.loads(r1.output)
    assert mutated["rollup_sha256"] != baseline_rollup, (
        "rollup did NOT change after tampering with __init__.py; "
        "the verify command is not tamper-detecting which is the "
        "whole point of the trust gate"
    )


def test_verify_command_fails_when_required_files_are_missing(tmp_path, monkeypatch):
    """An explicitly requested inventory still fails on an incomplete install."""
    from one_link import build_identity

    fake_root = tmp_path / "stripped"
    fake_root.mkdir()
    # Don't copy any files - every fingerprint file is "missing".
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    _accept_all_runtime_modules(monkeypatch)
    result = CliRunner().invoke(cli, ["verify-this-install", "--inventory-only"])
    assert result.exit_code == 1
    # Should be visible in either stdout or stderr - check both.
    full = (result.output or "") + (result.stderr or "")
    assert "WARNING" in full
    assert "MISSING" in (result.output or "")
    for rel in build_identity._FINGERPRINT_FILES:
        assert rel in (result.output or ""), f"missing-file list does not name {rel!r}"


def test_verify_command_json_mode_lists_missing_files_under_missing_key(tmp_path, monkeypatch):
    """JSON mode promotes 'missing' from a string in the human
    output to a structured list - lets a release pipeline gate
    on missing-file presence."""
    from one_link import build_identity

    fake_root = tmp_path / "stripped"
    fake_root.mkdir()
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    _accept_all_runtime_modules(monkeypatch)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert result.exit_code == 1
    data = json.loads(result.output)
    assert isinstance(data["missing"], list)
    # Every fingerprint file should be in the missing list.
    assert set(data["missing"]) == set(build_identity._FINGERPRINT_FILES)


def test_verify_command_without_baseline_fails_closed():
    result = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    assert result.exit_code == 2
    data = json.loads(result.output)
    assert data["verification_status"] == "baseline_required"
    assert data["baseline_match"] is None
    assert data["authenticity_verified"] is False


def test_verify_command_compares_exact_supplied_rollup():
    inventory = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    rollup = json.loads(inventory.output)["rollup_sha256"]

    matching = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--expected-rollup", rollup],
    )
    assert matching.exit_code == 0
    matched = json.loads(matching.output)
    assert matched["verification_status"] == "matches_supplied_baseline"
    assert matched["baseline_match"] is True
    assert matched["authenticity_verified"] is False

    wrong = "0" * 64 if rollup != "0" * 64 else "1" * 64
    mismatching = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--expected-rollup", wrong],
    )
    assert mismatching.exit_code == 1
    assert json.loads(mismatching.output)["verification_status"] == "baseline_mismatch"


def test_verify_command_never_recommends_wildcard_sigstore_identity():
    from one_link import cli as cli_module

    source = __import__("inspect").getsource(cli_module.verify_this_install.callback)
    assert "certificate-identity-regexp" not in source
    assert "'.*'" not in source
    assert ".github/workflows/release.yml@refs/tags/v" in source


def test_verify_command_hashes_files_outside_legacy_fingerprint_subset(tmp_path, monkeypatch):
    from one_link import build_identity

    fake_root = tmp_path / "complete"
    _complete_fake_package(fake_root)
    extra = fake_root / "web" / "arbitrary-runtime-asset.bin"
    extra.write_bytes(b"first")
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    _accept_all_runtime_modules(monkeypatch)

    first = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert first.exit_code == 0, first.output
    first_data = json.loads(first.output)
    assert "web/arbitrary-runtime-asset.bin" in first_data["files"]
    assert len(first_data["files"]["web/arbitrary-runtime-asset.bin"]) == 64

    extra.write_bytes(b"second")
    second = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert second.exit_code == 0, second.output
    assert json.loads(second.output)["rollup_sha256"] != first_data["rollup_sha256"]


def test_verify_command_rejects_link_like_inventory_entry(tmp_path, monkeypatch):
    from one_link import build_identity

    fake_root = tmp_path / "linked"
    _complete_fake_package(fake_root)
    suspect = fake_root / "web" / "linked-runtime-asset.bin"
    suspect.write_bytes(b"not trusted through a link")
    monkeypatch.setattr(build_identity, "package_root", lambda: fake_root)
    _accept_all_runtime_modules(monkeypatch)

    original_lstat = Path.lstat

    def link_aware_lstat(path: Path):
        metadata = original_lstat(path)
        if path == suspect:
            return type(
                "LinkMetadata",
                (),
                {
                    "st_mode": stat.S_IFLNK,
                    "st_file_attributes": 0,
                },
            )()
        return metadata

    monkeypatch.setattr(Path, "lstat", link_aware_lstat)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verification_status"] == "incomplete_install"
    assert payload["unsafe_entries"] == ["web/linked-runtime-asset.bin"]
    assert payload["files"]["web/linked-runtime-asset.bin"] == "UNSAFE_LINK"


def test_verify_command_fails_closed_when_native_package_is_absent(monkeypatch):
    from one_link import build_identity

    monkeypatch.setattr(build_identity, "native_package_root", lambda: None)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    assert payload["verification_status"] == "incomplete_install"
    assert payload["files"]["one_link_native/<package>"] == "MISSING"
    assert payload["native_package_root"] is None


def test_verify_frozen_onedir_hashes_every_file_once_without_source_false_positives(
    tmp_path,
    monkeypatch,
):
    bundle = _fake_frozen_onedir(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    physical_files = [path for path in bundle.rglob("*") if path.is_file()]
    executable_label = "bundle/one-link.exe" if sys.platform == "win32" else "bundle/one-link"
    assert payload["inventory_mode"] == "frozen_onedir_bundle"
    assert payload["inventory_root"] == str(bundle)
    assert payload["missing"] == []
    assert payload["unsafe_entries"] == []
    assert payload["file_count"] == len(physical_files)
    assert payload["frozen_binary_sha256"] == payload["files"][executable_label]
    assert list(payload["files"]).count(executable_label) == 1
    assert "__init__.py" not in payload["files"]
    assert not any(name.startswith("one_link_native/") for name in payload["files"])
    assert "bundle/_internal/one_link_native/__init__.py" in payload["files"]
    assert set(payload["forbidden_runtime_modules"].values()) == {"ABSENT"}
    assert payload["present_forbidden_runtime_modules"] == []


def test_verify_frozen_macos_app_uses_frameworks_runtime_and_whole_app_inventory(
    tmp_path,
    monkeypatch,
):
    app = _fake_frozen_macos_app(tmp_path, monkeypatch)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["inventory_mode"] == "frozen_macos_app_bundle"
    assert Path(payload["inventory_root"]) == app
    executable_label = "bundle/Contents/MacOS/one-link"
    assert payload["frozen_binary_sha256"] == payload["files"][executable_label]
    assert "bundle/Contents/Resources/one_link/web/index.html" in payload["files"]
    assert "bundle/Contents/Frameworks/base_library.zip" in payload["files"]
    assert payload["missing"] == []
    assert payload["unsafe_entries"] == []


def test_runtime_import_smoke_imports_every_stable_module_and_rejects_preview(
    tmp_path,
    monkeypatch,
):
    import importlib
    from importlib.machinery import ModuleSpec

    from one_link import build_identity

    bundle = _fake_frozen_onedir(tmp_path, monkeypatch)

    class _CodeLoader:
        def get_code(self, module: str):
            return compile(f"module_name = {module!r}\n", f"{module}.py", "exec")

    loader = _CodeLoader()
    manifest_modules = {}
    python_modules = {}
    for module in build_identity.EXPECTED_STABLE_RUNTIME_MODULES:
        code = loader.get_code(module)
        manifest_modules[module] = {
            "source_path": f"fixture/{module}.py",
            "source_sha256": "0" * 64,
            "normalized_code_sha256": build_identity.normalized_code_sha256(code),
        }
        loaded = types.ModuleType(module)
        loaded.__spec__ = ModuleSpec(module, loader, origin=f"{module}.py")
        python_modules[module] = loaded

    manifest = {
        "schema": "one-link-runtime-source-manifest-v1",
        "python_cache_tag": sys.implementation.cache_tag,
        "python_optimization": sys.flags.optimize,
        "runtime_module_manifest_sha256": (build_identity.EXPECTED_STABLE_RUNTIME_MODULES_SHA256),
        "modules": manifest_modules,
    }
    manifest_path = bundle / "_internal" / "one_link" / "_build" / "runtime-source-manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    native_package = types.ModuleType("one_link_native")
    native_package.__file__ = str(bundle / "_internal" / "one_link_native" / "__init__.py")
    native_extension = types.ModuleType("one_link_native.one_link_native")
    extension_suffix = ".pyd" if sys.platform == "win32" else ".so"
    native_extension.__file__ = str(
        bundle / "_internal" / "one_link_native" / f"one_link_native{extension_suffix}"
    )
    native_package.one_link_native = native_extension
    # The smoke compares native against the REAL core version; track it
    # dynamically so a release bump cannot strand this fixture.
    from one_link import __version__ as _core_version

    native_package.__version__ = f"{_core_version}.0"
    native_package.chunk_version = f"{_core_version}.0"
    native_modules = {}
    for module in build_identity.EXPECTED_NATIVE_RUNTIME_SUBMODULES:
        short_name = module.rsplit(".", 1)[1]
        loaded = types.ModuleType(short_name)
        native_modules[module] = loaded
        setattr(native_package, short_name, loaded)

    def fake_import(module: str):
        if module == "one_link_native":
            return native_package
        if module in native_modules:
            return native_modules[module]
        return python_modules[module]

    monkeypatch.setattr(importlib, "import_module", fake_import)
    # This command normally executes in a fresh frozen process. The unit test
    # deliberately invokes it in pytest's long-lived interpreter, where an
    # earlier preview-codec test may already have populated ``sys.modules``.
    # Remove that unrelated process history so the fixture models the actual
    # artifact boundary; monkeypatch restores every entry after the test.
    forbidden_prefixes = tuple(build_identity.STABLE_RUNTIME_FORBIDDEN_MODULES)
    for loaded_name in tuple(sys.modules):
        if any(
            loaded_name == prefix or loaded_name.startswith(f"{prefix}.")
            for prefix in forbidden_prefixes
        ):
            monkeypatch.delitem(sys.modules, loaded_name, raising=False)
    result = CliRunner().invoke(cli, ["runtime-import-smoke", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["verification_status"] == "runtime_imports_ok"
    assert set(payload["runtime_modules"].values()) == {"IMPORTED"}
    assert payload["runtime_code_sha256"] == {
        module: entry["normalized_code_sha256"] for module, entry in manifest_modules.items()
    }
    assert set(payload["forbidden_runtime_modules"].values()) == {"ABSENT"}
    assert payload["native_package_status"] == "IMPORTED"
    assert set(payload["native_runtime_modules"].values()) == {"IMPORTED"}
    assert payload["runtime_module_count"] == len(build_identity.EXPECTED_STABLE_RUNTIME_MODULES)


def test_runtime_feature_smoke_refuses_non_frozen_source_process(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.delattr(sys, "_MEIPASS", raising=False)
    result = CliRunner().invoke(cli, ["runtime-feature-smoke", "--json"])
    assert result.exit_code != 0
    assert "frozen-release gate" in result.output


def test_verify_frozen_onedir_extra_and_tampered_files_change_rollup(
    tmp_path,
    monkeypatch,
):
    bundle = _fake_frozen_onedir(tmp_path, monkeypatch)
    first = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert first.exit_code == 0, first.output
    baseline = json.loads(first.output)

    extra = bundle / "_internal" / "unexpected-runtime.bin"
    extra.write_bytes(b"extra")
    second = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert second.exit_code == 0, second.output
    with_extra = json.loads(second.output)
    assert with_extra["rollup_sha256"] != baseline["rollup_sha256"]
    assert "bundle/_internal/unexpected-runtime.bin" in with_extra["files"]

    index = bundle / "_internal" / "one_link" / "web" / "index.html"
    index.write_text("tampered", encoding="utf-8")
    mismatch = CliRunner().invoke(
        cli,
        [
            "verify-this-install",
            "--json",
            "--expected-rollup",
            with_extra["rollup_sha256"],
        ],
    )
    assert mismatch.exit_code == 1, mismatch.output
    assert json.loads(mismatch.output)["verification_status"] == "baseline_mismatch"


def test_verify_frozen_onedir_rejects_unsafe_entry(tmp_path, monkeypatch):
    bundle = _fake_frozen_onedir(tmp_path, monkeypatch)
    suspect = bundle / "_internal" / "linked-runtime.bin"
    suspect.write_bytes(b"link-target")
    original_lstat = Path.lstat

    def link_aware_lstat(path: Path):
        metadata = original_lstat(path)
        if path == suspect:
            return type(
                "LinkMetadata",
                (),
                {"st_mode": stat.S_IFLNK, "st_file_attributes": 0},
            )()
        return metadata

    monkeypatch.setattr(Path, "lstat", link_aware_lstat)
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    label = "bundle/_internal/linked-runtime.bin"
    assert payload["verification_status"] == "incomplete_install"
    assert payload["files"][label] == "UNSAFE_LINK"
    assert label in payload["unsafe_entries"]


def test_verify_frozen_onedir_rejects_missing_expected_layout_entry(
    tmp_path,
    monkeypatch,
):
    bundle = _fake_frozen_onedir(tmp_path, monkeypatch)
    (bundle / "_internal" / "base_library.zip").unlink()
    result = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )

    assert result.exit_code == 1, result.output
    payload = json.loads(result.output)
    label = "bundle/_internal/base_library.zip"
    assert payload["verification_status"] == "incomplete_install"
    assert payload["files"][label] == "MISSING"
    assert label in payload["missing"]


def test_verify_frozen_onedir_preserves_fail_closed_baseline_modes(
    tmp_path,
    monkeypatch,
):
    _fake_frozen_onedir(tmp_path, monkeypatch)
    inventory = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--inventory-only"],
    )
    assert inventory.exit_code == 0, inventory.output
    rollup = json.loads(inventory.output)["rollup_sha256"]

    default = CliRunner().invoke(cli, ["verify-this-install", "--json"])
    assert default.exit_code == 2, default.output
    default_payload = json.loads(default.output)
    assert default_payload["verification_status"] == "baseline_required"
    assert default_payload["authenticity_verified"] is False

    exact = CliRunner().invoke(
        cli,
        ["verify-this-install", "--json", "--expected-rollup", rollup],
    )
    assert exact.exit_code == 0, exact.output
    exact_payload = json.loads(exact.output)
    assert exact_payload["verification_status"] == "matches_supplied_baseline"
    assert exact_payload["authenticity_verified"] is False
