"""PyInstaller build-spec and native packaging guardrails.

The public binary is the highest-risk artifact: it can be stale even
when source is correct, or miss dynamically imported modules/data that
tests exercise only from the source tree. These tests exercise
scripts/build_binary.py without actually running PyInstaller.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest


SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "scripts" / "build_binary.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("build_binary", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FakeCompleted:
    def __init__(self, returncode: int = 0, stdout: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _fake_exe_path(repo: Path) -> Path:
    out_name = "one-link.exe" if sys.platform == "win32" else "one-link"
    return repo / "dist" / out_name


def _install_fake_runner(monkeypatch, mod, *, native_rc: int = 0):
    captured_cmds: list[list[str]] = []
    repo = SCRIPT.parent.parent
    fake_exe = _fake_exe_path(repo)

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(list(cmd))
        if any("build_native_cdc.py" in str(a) for a in cmd):
            return FakeCompleted(returncode=native_rc)
        if any("PyInstaller" in str(a) for a in cmd):
            fake_exe.parent.mkdir(parents=True, exist_ok=True)
            fake_exe.write_bytes(b"fake")
        return FakeCompleted(
            returncode=0,
            stdout="one-link, version 0.21.0-alpha",
        )

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **kw: FakeCompleted())
    return captured_cmds, fake_exe


def _pyinstaller_cmds(cmds: list[list[str]]) -> list[list[str]]:
    return [c for c in cmds if any("PyInstaller" in str(arg) for arg in c)]


def _native_cdc_cmds(cmds: list[list[str]]) -> list[list[str]]:
    return [c for c in cmds if any("build_native_cdc.py" in str(arg) for arg in c)]


def test_build_binary_script_imports_cleanly():
    mod = _load_module()
    assert callable(mod.main)


def test_build_binary_includes_collect_all_when_native_installed(monkeypatch):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(monkeypatch, mod)

    try:
        import one_link_native  # noqa: F401
    except ImportError:
        pytest.skip("one_link_native not installed in test env")

    try:
        assert mod.main() == 0
    finally:
        try:
            fake_exe.unlink()
        except OSError:
            pass

    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds, f"native CDC build never invoked: {captured_cmds}"
    assert "--required" in native_cmds[0], (
        "Release binary builds must fail if native CDC cannot rebuild; "
        "otherwise a stale locked DLL can be silently bundled."
    )
    pyinst_cmds = _pyinstaller_cmds(captured_cmds)
    assert pyinst_cmds, f"PyInstaller never invoked. Captured: {captured_cmds}"
    joined = " ".join(pyinst_cmds[0])
    assert "build" in joined and "one-link.spec" in joined

    repo = SCRIPT.parent.parent
    spec_text = (repo / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "one_link.sessions" in spec_text
    assert "one_link.recovery_api" in spec_text
    assert "one_link/data" in spec_text
    assert "collect_all('one_link_native')" in spec_text


def test_build_binary_skips_native_collect_when_missing(monkeypatch):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(monkeypatch, mod)

    real_import = (
        __builtins__["__import__"]
        if isinstance(__builtins__, dict)
        else __builtins__.__import__
    )

    def blocked_import(name, *args, **kwargs):
        if name == "one_link_native" or name.startswith("one_link_native."):
            raise ImportError("test: pretending one_link_native is absent")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", blocked_import)

    try:
        assert mod.main() == 0
    finally:
        try:
            fake_exe.unlink()
        except OSError:
            pass

    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds and "--required" in native_cmds[0]
    assert _pyinstaller_cmds(captured_cmds)

    repo = SCRIPT.parent.parent
    spec_text = (repo / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "one_link.sessions" in spec_text
    assert "one_link.recovery_api" in spec_text
    assert "one_link/data" in spec_text
    assert "collect_all('one_link_native')" not in spec_text


def test_build_binary_stops_when_required_native_cdc_build_fails(monkeypatch):
    mod = _load_module()
    captured_cmds, _fake_exe = _install_fake_runner(
        monkeypatch, mod, native_rc=1,
    )

    assert mod.main() == 1
    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds and "--required" in native_cmds[0]
    assert not _pyinstaller_cmds(captured_cmds), (
        "PyInstaller must not run after a required native CDC build failure"
    )


def test_build_binary_dev_escape_hatch_allows_native_cdc_fallback(monkeypatch):
    mod = _load_module()
    captured_cmds, fake_exe = _install_fake_runner(monkeypatch, mod)

    try:
        assert mod.main(["--allow-native-cdc-fallback"]) == 0
    finally:
        try:
            fake_exe.unlink()
        except OSError:
            pass

    native_cmds = _native_cdc_cmds(captured_cmds)
    assert native_cmds
    assert "--required" not in native_cmds[0]
    assert _pyinstaller_cmds(captured_cmds)
