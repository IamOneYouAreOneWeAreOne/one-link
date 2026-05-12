"""Tests for the standalone Chromium app-mode window launcher.

Default flow: when Edge or Chrome is found on disk, the daemon opens
the UI URL in a frameless ``--app=URL`` window instead of a regular
browser tab. Fallback path goes through the default browser.
"""

from __future__ import annotations

import os
import subprocess
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
