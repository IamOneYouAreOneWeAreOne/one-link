"""Entry point for ``python -m one_link`` and the PyInstaller binary.

When invoked with NO arguments (the "user just double-clicked the
installer" case), we promote it to ``one-link daemon --open`` so
the UI opens in their browser without them having to read help
text. Power users (``one-link --help``, ``one-link send``, etc.)
get unchanged behavior.
"""

from __future__ import annotations

import os
import sys

from one_link.cli import main


def _auto_promote_to_daemon() -> None:
    """If the user passed no args, behave as `one-link daemon --open`.

    Detected sentinels: argv has only the program name, OR the
    binary was launched from a Finder/Explorer / desktop shortcut
    (no controlling TTY, no args). Both produce the same intent:
    "open the app."
    """
    if len(sys.argv) > 1:
        return
    # Promote.
    sys.argv = [sys.argv[0], "daemon", "--open"]
    # Make sure ONE_LINK_AUTO_OPEN is set too so any subprocess /
    # tray inheritance does the right thing.
    os.environ["ONE_LINK_AUTO_OPEN"] = "1"


if __name__ == "__main__":
    _auto_promote_to_daemon()
    raise SystemExit(main() or 0)
