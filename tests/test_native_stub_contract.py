"""Release-contract tests for the canonical ``one_link_native`` stubs.

The native extension is a package of PyO3-created submodules, with type
information shipped inline as a PEP 561 package.  A partial or stale stub
wheel can silently turn whole native modules into ``Any``.  These tests
therefore compare the live extension's export registry to the source-of-truth
stub AST and verify that maturin packages every module stub.
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from typing import Iterable

import pytest

try:
    import one_link_native as _loaded_native_runtime
except ImportError:
    _NATIVE_RUNTIME: types.ModuleType | None = None
else:
    _NATIVE_RUNTIME = _loaded_native_runtime

REPO_ROOT = Path(__file__).resolve().parents[1]
STUB_DIR = REPO_ROOT / "native" / "one_link_native"
LEGACY_NATIVE_STUB_DIR = REPO_ROOT / "native" / "one_link_native-stubs"
LEGACY_STUB_DIR = REPO_ROOT / "stubs" / "one_link_native-stubs"


def _assigned_names(target: ast.expr) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.List, ast.Tuple)):
        for element in target.elts:
            yield from _assigned_names(element)


def _stub_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                names.update(_assigned_names(target))
        elif isinstance(node, ast.AnnAssign):
            names.update(_assigned_names(node.target))
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    names.add(alias.asname or alias.name.split(".", maxsplit=1)[0])
    return names


def _literal_stub_all(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets):
            value = ast.literal_eval(node.value)
            assert isinstance(value, list)
            assert all(isinstance(item, str) for item in value)
            return value
    pytest.fail(f"{path} must declare a literal __all__ matching the extension")


def _runtime_modules() -> dict[str, types.ModuleType]:
    runtime = _native_runtime()
    return {
        name: value
        for name in runtime.__all__
        if isinstance((value := getattr(runtime, name)), types.ModuleType)
    }


def _native_runtime() -> types.ModuleType:
    if _NATIVE_RUNTIME is None:
        pytest.skip("one_link_native must be built for live runtime parity checks")
    return _NATIVE_RUNTIME


def test_top_level_export_registry_matches_canonical_stub_exactly() -> None:
    runtime = _native_runtime()
    assert _literal_stub_all(STUB_DIR / "__init__.pyi") == list(runtime.__all__)


def test_every_runtime_submodule_and_public_export_is_stubbed() -> None:
    runtime_modules = _runtime_modules()
    assert len(runtime_modules) == 33

    stub_modules = {path.stem for path in STUB_DIR.glob("*.pyi") if path.name != "__init__.pyi"}
    assert stub_modules == set(runtime_modules)

    missing_by_module: dict[str, list[str]] = {}
    for name, module in runtime_modules.items():
        declared = _stub_names(STUB_DIR / f"{name}.pyi")
        missing = sorted(set(module.__all__) - declared)
        if missing:
            missing_by_module[name] = missing
    assert not missing_by_module


def test_proximity_stub_advertises_only_the_truthful_candidate_api() -> None:
    """A research candidate must never regain a native Factor-2 key name."""
    runtime = _native_runtime().proximity_pair
    runtime_exports = set(runtime.__all__)
    stub_exports = _stub_names(STUB_DIR / "proximity_pair.pyi")
    truthful = {
        "derive_unconfirmed_candidate",
        "py_derive_unconfirmed_candidate",
    }
    unsafe_legacy = {
        "derive_factor2_secret",
        "py_derive_factor2_secret",
    }

    assert truthful <= runtime_exports
    assert truthful <= stub_exports
    assert unsafe_legacy.isdisjoint(runtime_exports)
    assert unsafe_legacy.isdisjoint(stub_exports)


def test_runtime_exception_surface_is_declared_and_complete() -> None:
    runtime = _native_runtime()
    runtime_exceptions = {
        name
        for name in runtime.__all__
        if isinstance((value := getattr(runtime, name)), type) and issubclass(value, Exception)
    }
    assert runtime_exceptions == {
        "OlError",
        "OlChunkError",
        "OlAeadError",
        "OlWalError",
        "OlChunkStoreError",
        "OlQuicError",
        "OlBloomError",
        "OlFountainError",
        "OlFecError",
        "OlRatchetError",
        "OlPqKemError",
        "OlErasureError",
        "OlBanditError",
        "OlCapabilityError",
        "OlCrdtError",
        "OlHwKeyError",
    }
    assert runtime_exceptions <= _stub_names(STUB_DIR / "__init__.pyi")


def test_stub_package_has_one_source_of_truth_and_complete_wheel_manifest() -> None:
    assert not list(LEGACY_STUB_DIR.glob("*"))
    assert not list(LEGACY_NATIVE_STUB_DIR.glob("*"))

    native_pyproject = (REPO_ROOT / "native" / "pyproject.toml").read_text(encoding="utf-8")
    assert 'path = "one_link_native/*.pyi"' in native_pyproject
    assert 'path = "one_link_native/py.typed"' in native_pyproject
    assert (STUB_DIR / "py.typed").is_file()


def test_stubtest_allowlist_is_metadata_and_static_aliases_only() -> None:
    entries = {
        line.strip()
        for line in (STUB_DIR / "stubtest_allowlist.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert entries == {
        r"one_link_native\.[^.]+\.__all__",
        r"one_link_native\.aead\.AeadKind",
        r"one_link_native\.aead\.ChunkInput",
        r"one_link_native\.aead\.EncryptedChunkInput",
        r"one_link_native\.confidential\.AttestationTuple",
        r"one_link_native\.quic\.Frame",
        r"one_link_native\.quic\.InboundFrame",
        r"one_link_native\.quic\.Response",
        r"one_link_native\.one_link_native",
        r"one_link_native\.src",
    }


def test_fuse_binding_is_packaged_but_never_overclaims_platform_support() -> None:
    runtime = _native_runtime()
    assert "fuse" in runtime.__all__
    assert hasattr(runtime, "fuse")
    assert (STUB_DIR / "fuse.pyi").is_file()
    fuse = runtime.fuse
    assert set(fuse.__all__) == {
        "platform_status",
        "mount_manifest",
        "unmount",
        "is_mounted",
        "MAX_MANIFEST_ENTRIES",
        "MAX_FS_PATH_BYTES",
        "MAX_FS_NAME_BYTES",
        "READ_ONLY",
    }
    assert fuse.READ_ONLY is True
    status = fuse.platform_status()
    assert status in {
        "linux_fuser_ready",
        "linux_fuser_disabled",
        "macos_unsupported",
        "windows_unsupported",
        "other_unsupported",
    }
    if sys.platform == "win32":
        assert status == "windows_unsupported"
    elif sys.platform == "darwin":
        assert status == "macos_unsupported"
