"""Entry point for ``python -m one_link`` and the PyInstaller binary.

When invoked with NO arguments (the "user just double-clicked the
installer" case), we promote it to ``one-link app`` so users get the
desktop-style app launcher instead of a browser tab. Power users
(``one-link --help``, ``one-link send``, etc.) get unchanged behavior.
"""

from __future__ import annotations

import os
import sys

from one_link.cli import main


def _auto_promote_to_app() -> None:
    """If the user passed no args, behave as `one-link app`.

    Detected sentinels: argv has only the program name, OR the
    binary was launched from a Finder/Explorer / desktop shortcut
    (no controlling TTY, no args). Both produce the same intent:
    "open the app."
    """
    if len(sys.argv) > 1:
        return
    # Promote.
    sys.argv = [sys.argv[0], "app"]
    # Make sure a double-clicked binary never falls through to daemon
    # auto-open behavior in a child process. The app launcher owns the
    # one visible window.
    os.environ.pop("ONE_LINK_AUTO_OPEN", None)


if __name__ == "__main__":
    _auto_promote_to_app()
    raise SystemExit(main() or 0)
