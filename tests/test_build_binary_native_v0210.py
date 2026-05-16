"""Tests for the PyInstaller spec — does it bundle one_link_native?

Phase 4 of the production-install plan. The script auto-detects
whether one_link_native is installed in the active env. If it is,
PyInstaller is invoked with `--collect-all one_link_native` so the
.pyd / .so / .dylib files get baked into the exe.

We do NOT run PyInstaller in CI here (it takes ~2 minutes and
produces an 85MB exe per invocation). Instead we exercise the
spec-building logic by patching subprocess.run + import-detection
and asserting on the argv that WOULD be invoked.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


SCRIPT = (
    Path(__file__).resolve().parent.parent
    / "scripts" / "build_binary.py"
)


def _load_module():
    """Load scripts/build_binary.py as a module. It's a script, not a
    package, so we use importlib's spec_from_file_location dance."""
    spec = importlib.util.spec_from_file_location("build_binary", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_build_binary_script_imports_cleanly():
    """The script must be importable without running its main() —
    that's what spec_from_file_location guarantees and lets us
    monkey-patch internals before main() ever fires."""
    mod = _load_module()
    assert callable(mod.main)


def test_build_binary_includes_collect_all_when_native_installed(tmp_path, monkeypatch):
    """When one_link_native imports successfully, the PyInstaller argv
    must include `--collect-all one_link_native`. This is the
    regression guard that proves the native fast path will be
    bundled in any future build the maintainer runs."""
    mod = _load_module()

    captured_cmds: list[list[str]] = []
    repo = SCRIPT.parent.parent
    out_name = "one-link.exe" if sys.platform == "win32" else "one-link"
    fake_exe = repo / "dist" / out_name

    class FakeCompleted:
        def __init__(self):
            self.returncode = 0
            self.stdout = "one-link, version 0.21.0-alpha"
            self.stderr = ""

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(list(cmd))
        # When the script invokes PyInstaller, create the fake exe so
        # the existence check at the end of main() passes. main()
        # deletes dist/ before this point, so we recreate the file
        # here as a side-effect of the mocked PyInstaller call.
        if any("PyInstaller" in str(a) for a in cmd):
            fake_exe.parent.mkdir(parents=True, exist_ok=True)
            fake_exe.write_bytes(b"fake")
        return FakeCompleted()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **kw: FakeCompleted())

    # Force one_link_native to "import successfully" — the script
    # checks via `import one_link_native`. We make sure it's
    # actually importable in the test env (it is, since we
    # already built and installed the wheel in this session).
    # If somehow it's missing in CI, skip rather than fail.
    try:
        import one_link_native  # noqa: F401
    except ImportError:
        pytest.skip(
            "one_link_native not installed in test env — Phase 4 "
            "bundling test can only run after the wheel is installed"
        )

    try:
        rc = mod.main()
        assert rc == 0, f"build_binary.main() returned {rc}"
    finally:
        # Clean up the fake exe so a subsequent run doesn't think a
        # real binary exists.
        try:
            fake_exe.unlink()
        except OSError:
            pass

    # Find the PyInstaller invocation among the captured commands.
    pyinst_cmds = [
        c for c in captured_cmds
        if any("PyInstaller" in str(arg) for arg in c)
    ]
    assert pyinst_cmds, (
        f"PyInstaller never invoked. Captured: {captured_cmds}"
    )
    pyinst_cmd = pyinst_cmds[0]
    # The contract: the generated spec bundles the native crate via
    # collect_all. The CLI invocation points at that spec so we can
    # post-filter heavy transient DLLs after Analysis.
    joined = " ".join(pyinst_cmd)
    assert "build" in joined and "one-link.spec" in joined
    spec_text = (repo / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "collect_all('one_link_native')" in spec_text, (
        "Generated PyInstaller spec does NOT bundle the native crate."
    )


def test_build_binary_skips_native_collect_when_missing(tmp_path, monkeypatch):
    """If one_link_native is NOT installed, the script must build
    anyway without --collect-all. The produced exe still runs (falls
    back to pure-Python paths)."""
    mod = _load_module()

    captured_cmds: list[list[str]] = []
    repo = SCRIPT.parent.parent
    out_name = "one-link.exe" if sys.platform == "win32" else "one-link"
    fake_exe = repo / "dist" / out_name

    class FakeCompleted:
        def __init__(self):
            self.returncode = 0
            self.stdout = ""
            self.stderr = ""

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(list(cmd))
        if any("PyInstaller" in str(a) for a in cmd):
            fake_exe.parent.mkdir(parents=True, exist_ok=True)
            fake_exe.write_bytes(b"fake")
        return FakeCompleted()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    monkeypatch.setattr(mod.subprocess, "Popen", lambda *a, **kw: FakeCompleted())

    # Patch the import inside the script so it sees one_link_native
    # as missing. The script does `import one_link_native` inside a
    # try/except — we intercept by removing it from sys.modules and
    # blocking the import.
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def blocked_import(name, *args, **kwargs):
        if name == "one_link_native" or name.startswith("one_link_native."):
            raise ImportError("test: pretending one_link_native is absent")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr("builtins.__import__", blocked_import)

    try:
        rc = mod.main()
        assert rc == 0
    finally:
        try:
            fake_exe.unlink()
        except OSError:
            pass

    pyinst_cmds = [
        c for c in captured_cmds
        if any("PyInstaller" in str(arg) for arg in c)
    ]
    assert pyinst_cmds
    joined = " ".join(pyinst_cmds[0])
    assert "build" in joined and "one-link.spec" in joined
    spec_text = (repo / "build" / "one-link.spec").read_text(encoding="utf-8")
    assert "collect_all('one_link_native')" not in spec_text, (
        "build proceeded to collect one_link_native even though the "
        "import raised — the auto-detection logic is broken"
    )
