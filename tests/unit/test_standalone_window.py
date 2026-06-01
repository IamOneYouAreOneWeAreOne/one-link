"""Tests for the standalone Chromium app-mode window launcher.

Default flow: when Edge or Chrome is found on disk, the daemon opens
the UI URL in a frameless ``--app=URL`` window instead of a regular
browser tab. Fallback path goes through the default browser.
"""

from __future__ import annotations

import os
import subprocess
import sys
from unittest import mock

import pytest


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

    fake_browser = (
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
        if os.name == "nt"
        else "/usr/bin/msedge"
    )

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
            with mock.patch.object(app_mod.subprocess, "Popen", side_effect=fake_popen):
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
    fake_browser = r"C:\msedge.exe"

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
            with mock.patch.object(app_mod.subprocess, "Popen", side_effect=fake_popen):
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
            with mock.patch.object(
                app_mod.webbrowser, "open", return_value=True
            ) as wb_open:
                with mock.patch.object(
                    app_mod.os, "startfile", create=True, return_value=None
                ) as startfile:
                    app_mod._open_browser_url(
                        "http://127.0.0.1:7117/?t=abc", standalone=False
                    )

    # No Chromium subprocess invocation when standalone=False.
    assert chrome_called == []
    # One of the fallbacks fired.
    if os.name == "nt":
        assert startfile.called
    else:
        assert wb_open.called


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
            with mock.patch.object(app_mod.subprocess, "Popen") as popen:
                popen.return_value.poll.return_value = None
                with mock.patch.object(
                    app_mod.os, "startfile", create=True, return_value=None
                ) as startfile:
                    app_mod._open_browser_url(
                        "http://127.0.0.1:7117/?t=abc", standalone=True
                    )

    assert popen.called
    assert not startfile.called


def test_open_browser_url_falls_back_when_no_chromium():
    """If neither Edge nor Chrome is found, fall back to the default
    browser via os.startfile / webbrowser.open."""
    from one_link import app as app_mod

    with mock.patch.object(
        app_mod, "_find_chromium_browser_exe", return_value=None
    ):
        with mock.patch.object(app_mod.subprocess, "Popen") as popen:
            with mock.patch.object(
                app_mod.webbrowser, "open", return_value=True
            ) as wb_open:
                with mock.patch.object(
                    app_mod.os, "startfile", create=True, return_value=None
                ) as startfile:
                    app_mod._open_browser_url(
                        "http://127.0.0.1:7117/?t=abc", standalone=True
                    )

    # Chromium Popen NOT called because no browser was found.
    assert not popen.called
    if os.name == "nt":
        assert startfile.called
    else:
        assert wb_open.called


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
            with mock.patch.object(app_mod.subprocess, "Popen", side_effect=explode):
                with mock.patch.object(
                    app_mod.os, "startfile", create=True, return_value=None
                ) as startfile:
                    with mock.patch.object(
                        app_mod.webbrowser, "open", return_value=True
                    ) as wb_open:
                        app_mod._open_browser_url(
                            "http://127.0.0.1:7117/?t=abc", standalone=True
                        )

    if os.name == "nt":
        assert startfile.called
    else:
        assert wb_open.called


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

    assert captured["args"][:3] == [sys.executable, "-m", "one_link.cli"]
    assert captured["args"][3:] == ["daemon", "-v"]


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
