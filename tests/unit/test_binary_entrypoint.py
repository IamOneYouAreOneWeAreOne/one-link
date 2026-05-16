"""PyInstaller / ``python -m one_link`` entrypoint behavior."""

from __future__ import annotations

import os
import sys
from unittest import mock


def test_no_arg_binary_launch_promotes_to_app_not_browser_daemon():
    """Double-click launch should open the app launcher, not daemon --open.

    ``daemon --open`` opens a browser tab/window directly. The app launcher
    is the idempotent path that reuses the backend and avoids duplicate
    windows.
    """
    from one_link import __main__ as main_mod

    with mock.patch.object(sys, "argv", ["one-link.exe"]):
        with mock.patch.dict(os.environ, {"ONE_LINK_AUTO_OPEN": "1"}):
            main_mod._auto_promote_to_app()
            assert sys.argv == ["one-link.exe", "app"]
            assert "ONE_LINK_AUTO_OPEN" not in os.environ


def test_arg_binary_launch_is_left_unchanged():
    from one_link import __main__ as main_mod

    with mock.patch.object(sys, "argv", ["one-link.exe", "daemon", "--no-open"]):
        main_mod._auto_promote_to_app()
        assert sys.argv == ["one-link.exe", "daemon", "--no-open"]
