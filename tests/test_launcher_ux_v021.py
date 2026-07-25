"""Native splash + friendly-error-dialog wiring.

The launcher's UX before this commit was: console window opens,
prints "starting daemon...", silently hangs ~30s, prints "daemon
failed to start cleanly", exits 2. With these two modules wired in,
the user sees a splash window immediately on double-click and a
real Retry/Open-logs/Quit dialog if it fails.

Tkinter dialogs themselves aren't headless-friendly, so the tests
here cover the non-GUI parts: subprocess spawn helpers, log-tail
reader, file-manager-reveal helper, icon discovery, and the
launcher's retry-on-failure plumbing.
"""
from __future__ import annotations

import inspect
import subprocess
import sys
from types import SimpleNamespace
from unittest import mock


# ─── splash ─────────────────────────────────────────────────────────────

def test_splash_module_imports():
    from one_link import splash
    assert hasattr(splash, "run_splash")
    assert hasattr(splash, "_find_icon")
    assert hasattr(splash, "_on_parent_disconnect")


def test_splash_find_icon_returns_existing_png_or_none(tmp_path, monkeypatch):
    from one_link import splash
    # In a source checkout the icon file actually exists at
    # src/one_link/web/assets/one-glyph.png — find_icon should
    # discover it via the package-relative search path.
    result = splash._find_icon()
    # Either we find a real file, or we cleanly return None. Never
    # a path to a file that doesn't exist.
    assert result is None or result.is_file()


def test_splash_find_icon_prefers_bundle_dir(tmp_path, monkeypatch):
    """When PyInstaller's _MEIPASS is set, the bundle-extracted icon
    wins over the source-tree one. Important because the bundled exe
    might run from a folder where the source assets aren't present."""
    from one_link import splash
    fake_bundle = tmp_path / "_meipass"
    fake_assets = fake_bundle / "one_link" / "web" / "assets"
    fake_assets.mkdir(parents=True)
    fake_icon = fake_assets / "one-glyph.png"
    fake_icon.write_bytes(b"fake-png")
    monkeypatch.setattr(sys, "_MEIPASS", str(fake_bundle), raising=False)
    assert splash._find_icon() == fake_icon


# ─── error dialog: log-tail reader ─────────────────────────────────────

def test_read_log_tail_returns_last_n_lines(tmp_path):
    from one_link import error_dialog
    p = tmp_path / "sample.log"
    p.write_text("a\nb\nc\nd\ne\nf\ng\n", encoding="utf-8")
    out = error_dialog._read_log_tail(p, max_lines=3)
    assert out.splitlines() == ["e", "f", "g"]


def test_read_log_tail_skips_blank_lines(tmp_path):
    from one_link import error_dialog
    p = tmp_path / "sparse.log"
    p.write_text("\n\nfirst\n\nsecond\n\n\nthird\n\n", encoding="utf-8")
    out = error_dialog._read_log_tail(p, max_lines=2)
    assert out.splitlines() == ["second", "third"]


def test_read_log_tail_handles_missing_file(tmp_path):
    from one_link import error_dialog
    assert error_dialog._read_log_tail(tmp_path / "nope.log") == ""


def test_read_log_tail_handles_unicode_safely(tmp_path):
    from one_link import error_dialog
    p = tmp_path / "u.log"
    # Mix of ASCII + UTF-8 + an invalid byte that must NOT crash the reader.
    with open(p, "wb") as f:
        f.write(b"hello\n")
        f.write("ǭ line".encode("utf-8") + b"\n")
        f.write(b"\xff\xfe broken byte\n")
    out = error_dialog._read_log_tail(p, max_lines=3)
    assert "hello" in out and "line" in out  # broken byte is replaced, not raised


def test_read_log_tail_seek_negative_safely(tmp_path):
    """A log smaller than the 4 KB seek-back must not raise. Common
    case on first launch — log is brand new and tiny."""
    from one_link import error_dialog
    p = tmp_path / "tiny.log"
    p.write_text("just one line", encoding="utf-8")
    out = error_dialog._read_log_tail(p, max_lines=5)
    assert out == "just one line"


# ─── error dialog: reveal helper ───────────────────────────────────────

def test_reveal_in_file_manager_uses_platform_command(tmp_path, monkeypatch):
    from one_link import error_dialog
    calls = []
    monkeypatch.setattr(
        error_dialog,
        "launch_system_opener",
        lambda path, **kw: calls.append((path, kw)),
    )
    error_dialog._reveal_in_file_manager(tmp_path)
    assert calls == [(tmp_path, {})]


def test_reveal_in_file_manager_swallows_errors(tmp_path, monkeypatch):
    """Best-effort — must NEVER raise; the user is already in the
    error-recovery path, we cannot pile a second crash on top."""
    from one_link import error_dialog
    def _boom(*a, **k):
        raise OSError("simulated")
    monkeypatch.setattr(error_dialog, "launch_system_opener", _boom)
    error_dialog._reveal_in_file_manager(tmp_path)  # must not raise


# ─── launcher splash spawn / close helpers ─────────────────────────────

def test_spawn_splash_returns_subprocess_or_none(monkeypatch):
    """Spawn failures must NOT bring down the launcher. The splash
    is a nice-to-have; if tkinter or the subprocess can't start, the
    launcher proceeds without the splash."""
    from one_link import app as app_mod

    fake_proc = SimpleNamespace(stdin=SimpleNamespace(close=lambda: None),
                                wait=lambda timeout=None: 0,
                                terminate=lambda: None,
                                pid=12345)

    def fake_popen(*a, **kw):
        return fake_proc
    monkeypatch.setattr(app_mod.subprocess, "Popen", fake_popen)
    out = app_mod._spawn_splash()
    assert out is fake_proc

    def boom(*a, **kw):
        raise OSError("simulated fail")
    monkeypatch.setattr(app_mod.subprocess, "Popen", boom)
    assert app_mod._spawn_splash() is None


def test_spawn_splash_command_targets_correct_entry(monkeypatch):
    from one_link import app as app_mod
    captured = {}
    def fake_popen(args, **kw):
        captured["args"] = list(args)
        captured["kwargs"] = kw
        return SimpleNamespace(stdin=None, pid=1)
    monkeypatch.setattr(app_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(app_mod.sys, "frozen", False, raising=False)
    app_mod._spawn_splash()
    assert captured["args"][1:] == ["-P", "-m", "one_link.splash"]


def test_close_splash_handles_none():
    from one_link import app as app_mod
    # None means "no splash was spawned". Must be a clean no-op,
    # never raise.
    app_mod._close_splash(None)


def test_close_splash_closes_stdin_first(monkeypatch):
    """The splash's stdin-EOF watcher is the cleanest dismiss path.
    Confirm we close the pipe before reaching for terminate()."""
    from one_link import app as app_mod
    events = []
    fake_stdin = SimpleNamespace(close=lambda: events.append("stdin-close"))
    fake_proc = SimpleNamespace(
        stdin=fake_stdin,
        wait=lambda timeout=None: events.append("wait") or 0,
        terminate=lambda: events.append("terminate"),
    )
    app_mod._close_splash(fake_proc)
    assert events[0] == "stdin-close"
    assert "terminate" not in events  # graceful wait succeeded → no kill needed


def test_close_splash_falls_back_to_terminate_on_hung_splash(monkeypatch):
    from one_link import app as app_mod
    def _hang(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="splash", timeout=2)
    fake_proc = SimpleNamespace(
        stdin=SimpleNamespace(close=lambda: None),
        wait=_hang,
        terminate=mock.MagicMock(),
    )
    app_mod._close_splash(fake_proc)
    fake_proc.terminate.assert_called_once()


# ─── icon diagnostic line in build_binary.py ───────────────────────────

def test_build_binary_logs_icon_diagnostic_line():
    """A future "I shipped an exe without the icon" debugging session
    is the WORST. Lock in the CI-visible log line that tells us
    whether --icon was passed."""
    import scripts.build_binary as bb
    src = inspect.getsource(bb)
    assert "[build] icon embedded:" in src
    assert "[build] WARNING: icon not found" in src


# ─── run_app retry semantics ───────────────────────────────────────────

def test_run_app_retry_on_failure_uses_error_dialog():
    """The launcher's failure path must offer a retry via the
    friendly dialog, not just exit 2 silently. Source-level pin so a
    future "tidy up" PR can't accidentally remove the retry loop."""
    from one_link import app as app_mod
    src = inspect.getsource(app_mod.run_app)
    assert "show_startup_failure" in src
    assert 'choice == "retry"' in src or 'choice != "retry"' in src
    assert "max_attempts" in src
