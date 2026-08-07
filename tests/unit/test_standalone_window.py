"""Tests for the Chromium app-mode window launcher — now the FALLBACK path.

As of the native shell (§10.4, `native/ol_shell`), One Link opens its own window and never
touches a browser. This file tests what happens when it cannot: no shell binary in the bundle,
no WebView2 runtime, a shell that refuses to render a modified interface. The app-mode window is
then still far better than a browser tab, so the ladder is: our window -> app mode -> plain tab.

EVERY TEST HERE DISABLES THE NATIVE SHELL EXPLICITLY, via the `no_native_shell` fixture. Before
that fixture existed these tests passed for the wrong reason on machines with no Rust toolchain
and failed on machines that had built the shell — a suite whose verdict depends on whether a
developer happens to have run `cargo build` is measuring the developer, not the code.
"""

from __future__ import annotations

import os
import subprocess
import sys
from unittest import mock

import pytest


@pytest.fixture(autouse=True)
def no_native_shell(monkeypatch):
    """Force the app-mode path by making One Link's own window unavailable.

    Autouse on purpose: this file is ABOUT the fallback, and a test here that accidentally
    exercised the native shell would be silently testing something else.
    """
    from one_link import app as app_mod

    monkeypatch.setattr(app_mod, "_shell_path", lambda: None)


def test_find_chromium_browser_exe_returns_path_or_none():
    """Detector must return either an absolute filepath OR None.
    Never raises."""
    from one_link.app import _find_chromium_browser_exe

    result = _find_chromium_browser_exe()
    assert result is None or (isinstance(result, str) and os.path.isfile(result))


def test_open_browser_url_standalone_invokes_app_mode_when_chrome_found():
    """When standalone=True AND a Chromium browser is on disk, we
    invoke ``<browser> --app=URL --new-window`` via subprocess.Popen
    rather than ``os.startfile`` (which always opens the default
    browser as a tab)."""
    from one_link import app as app_mod

    captured = []

    fake_browser = sys.executable

    def fake_popen(args, **kwargs):
        captured.append({"args": list(args), "kwargs": kwargs})

        class _FakeProc:
            pass

        return _FakeProc()

    with mock.patch.object(
        app_mod, "_find_chromium_browser_exe", return_value=fake_browser
    ):
        with mock.patch.object(
            app_mod, "_is_existing_app_window_running", return_value=False
        ):
            with mock.patch.object(
                app_mod,
                "launch_explicit_command",
                side_effect=fake_popen,
            ):
                app_mod._open_browser_url(
                    "http://127.0.0.1:7117/?t=abc", standalone=True
                )

    assert len(captured) == 1
    args = captured[0]["args"]
    assert args[0] == fake_browser
    # --app=URL must be present as a single flag.
    assert any(a.startswith("--app=") for a in args)
    assert any(a == "--app=http://127.0.0.1:7117/?t=abc" for a in args)
    # --new-window keeps the app-window separate from existing browser tabs.
    assert "--new-window" in args


def test_open_browser_url_standalone_passes_reliable_isolation_flags():
    """The app-mode invocation must pass a small, reliable flag set.

    We keep the isolated app profile and first-run suppression, but avoid
    a large --disable-features list because that over-hardened launch could
    prevent a visible app window on Windows.
    """
    from one_link import app as app_mod

    captured = []
    fake_browser = sys.executable

    def fake_popen(args, **kwargs):
        captured.append(list(args))

        class _FakeProc:
            pass

        return _FakeProc()

    with mock.patch.object(
        app_mod, "_find_chromium_browser_exe", return_value=fake_browser
    ):
        with mock.patch.object(
            app_mod, "_is_existing_app_window_running", return_value=False
        ):
            with mock.patch.object(
                app_mod,
                "launch_explicit_command",
                side_effect=fake_popen,
            ):
                app_mod._open_browser_url(
                    "http://127.0.0.1:7117/?t=abc", standalone=True
                )

    assert len(captured) == 1
    args = captured[0]
    # Every required suppression / isolation flag is present.
    assert any(a.startswith("--user-data-dir=") for a in args), args
    assert "--no-first-run" in args
    assert "--no-default-browser-check" in args
    assert not any(a.startswith("--disable-features=") for a in args)
    assert "--disable-sync" not in args


def test_open_browser_url_standalone_false_skips_app_mode():
    """When standalone=False (the --browser-tab flag), we should NOT
    invoke a Chromium app-mode launch even if one is available."""
    from one_link import app as app_mod

    chrome_called = []

    def fake_popen(args, **kwargs):
        chrome_called.append(args)

    with mock.patch.object(
        app_mod,
        "_find_chromium_browser_exe",
        return_value=r"C:\msedge.exe",
    ):
        with mock.patch.object(app_mod.subprocess, "Popen", side_effect=fake_popen):
            with mock.patch.object(app_mod, "launch_loopback_url") as fallback:
                app_mod._open_browser_url(
                    "http://127.0.0.1:7117/?t=abc", standalone=False
                )

    # No Chromium subprocess invocation when standalone=False.
    assert chrome_called == []
    fallback.assert_called_once()


def test_open_browser_url_still_opens_when_stale_app_window_is_detected():
    """A stale/minimized app-mode process must not make desktop clicks silent."""
    from one_link import app as app_mod

    with mock.patch.object(
        app_mod,
        "_find_chromium_browser_exe",
        return_value=r"C:\msedge.exe",
    ):
        with mock.patch.object(
            app_mod, "_is_existing_app_window_running", return_value=True
        ):
            with mock.patch.object(app_mod, "launch_explicit_command") as launch:
                with mock.patch.object(app_mod, "launch_loopback_url") as fallback:
                    app_mod._open_browser_url(
                        "http://127.0.0.1:7117/?t=abc", standalone=True
                    )

    assert launch.called
    assert not fallback.called


def test_open_browser_url_falls_back_when_no_chromium():
    """If Chromium is absent, use the fixed OS loopback URL launcher."""
    from one_link import app as app_mod

    with mock.patch.object(
        app_mod, "_find_chromium_browser_exe", return_value=None
    ):
        with mock.patch.object(app_mod.subprocess, "Popen") as popen:
            with mock.patch.object(app_mod, "launch_loopback_url") as fallback:
                app_mod._open_browser_url(
                    "http://127.0.0.1:7117/?t=abc", standalone=True
                )

    # Chromium Popen NOT called because no browser was found.
    assert not popen.called
    fallback.assert_called_once()


def test_open_browser_url_falls_back_when_chromium_launch_fails():
    """If the Chromium launch itself raises, fall through to the
    default-browser path. User still sees their UI."""
    from one_link import app as app_mod

    def explode(*args, **kwargs):
        raise OSError("simulated launch failure")

    with mock.patch.object(
        app_mod, "_find_chromium_browser_exe", return_value=r"C:\msedge.exe"
    ):
        with mock.patch.object(
            app_mod, "_is_existing_app_window_running", return_value=False
        ):
            with mock.patch.object(
                app_mod,
                "launch_explicit_command",
                side_effect=explode,
            ):
                with mock.patch.object(app_mod, "launch_loopback_url") as fallback:
                    app_mod._open_browser_url(
                        "http://127.0.0.1:7117/?t=abc", standalone=True
                    )

    fallback.assert_called_once()


def test_run_app_signature_accepts_standalone_kwarg():
    """The run_app entry point must accept the standalone= kwarg
    threaded through from cli.app."""
    from one_link.app import run_app
    import inspect

    sig = inspect.signature(run_app)
    assert "standalone" in sig.parameters
    # Default should be True (app-mode is the default UX).
    assert sig.parameters["standalone"].default is True


def test_desktop_launcher_waits_for_slow_packaged_daemon_startup():
    """Packaged Windows startup can take longer than source startup."""
    from one_link.app import _wait_for_daemon
    import inspect

    sig = inspect.signature(_wait_for_daemon)
    assert sig.parameters["timeout"].default >= 45.0


@pytest.mark.skipif(
    os.name != "nt",
    reason=(
        "exercises the Windows-only taskkill fallback in _terminate_pid; "
        "the os.name='nt' monkeypatch can't fully simulate Windows signal "
        "semantics on POSIX (subprocess.run is never reached), so run it "
        "where it's real — the windows-latest CI leg covers it"
    ),
)
def test_terminate_pid_windows_fallback_uses_absolute_taskkill(monkeypatch):
    from one_link import app as app_mod

    calls = []

    def fake_kill(pid, sig):
        if sig == 0:
            return None
        return None

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(app_mod.os, "name", "nt", raising=False)
    monkeypatch.setattr(app_mod.os, "getpid", lambda: 9999)
    monkeypatch.setattr(app_mod.os, "kill", fake_kill)
    monkeypatch.setattr(app_mod.time, "time", iter([0.0, 10.0]).__next__)
    monkeypatch.setattr(app_mod.subprocess, "run", fake_run)

    assert app_mod._terminate_pid(1234, timeout=0.0) is True
    assert calls
    argv, kwargs = calls[0]
    assert argv[0].endswith(r"System32\taskkill.exe")
    assert argv[1:] == ["/PID", "1234", "/T", "/F"]
    assert kwargs["check"] is False


def test_spawn_daemon_uses_python_module_in_source_mode(tmp_path):
    from one_link import app as app_mod

    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)

        class _FakeProc:
            pass

        return _FakeProc()

    def fake_detached(args, log_path, **kwargs):
        captured["args"] = list(args)
        captured["log_path"] = log_path
        captured["kwargs"] = kwargs

        class _FakeProc:
            pass

        return _FakeProc()

    with mock.patch.object(app_mod, "data_dir", return_value=tmp_path):
        with mock.patch.object(app_mod.subprocess, "Popen", side_effect=fake_popen):
            detached_patch = (
                mock.patch.object(
                    app_mod,
                    "_spawn_daemon_windows_detached",
                    side_effect=fake_detached,
                )
                if os.name == "nt"
                else mock.patch.object(app_mod, "_spawn_daemon_windows_detached")
            )
            with detached_patch:
                with mock.patch.object(sys, "frozen", False, create=True):
                    app_mod._spawn_daemon()

    assert captured["args"][:4] == [sys.executable, "-P", "-m", "one_link.cli"]
    assert captured["args"][4:] == ["daemon", "-v"]


def test_spawn_daemon_uses_cli_args_inside_frozen_binary(tmp_path):
    from one_link import app as app_mod

    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)

        class _FakeProc:
            pass

        return _FakeProc()

    def fake_detached(args, log_path, **kwargs):
        captured["args"] = list(args)
        captured["log_path"] = log_path
        captured["kwargs"] = kwargs

        class _FakeProc:
            pass

        return _FakeProc()

    with mock.patch.object(app_mod, "data_dir", return_value=tmp_path):
        with mock.patch.object(app_mod.subprocess, "Popen", side_effect=fake_popen):
            detached_patch = (
                mock.patch.object(
                    app_mod,
                    "_spawn_daemon_windows_detached",
                    side_effect=fake_detached,
                )
                if os.name == "nt"
                else mock.patch.object(app_mod, "_spawn_daemon_windows_detached")
            )
            with detached_patch:
                with mock.patch.object(sys, "frozen", True, create=True):
                    app_mod._spawn_daemon()

    assert captured["args"] == [sys.executable, "daemon", "-v"]


def test_running_daemon_compatibility_requires_source_fingerprint():
    from one_link import __version__
    from one_link.app import RunningDaemon
    from one_link.build_identity import source_fingerprint

    good = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={
            "ok": True,
            "app_version": __version__,
            "source_fingerprint": source_fingerprint(),
            "protocol_version": "OL1.2",
            "schema_version": 20,
        },
    )
    stale = RunningDaemon(
        control_port=1,
        server_port=2,
        token="t",
        status={**good.status, "source_fingerprint": "stale"},
    )

    assert good.compatible is True
    assert stale.compatible is False
