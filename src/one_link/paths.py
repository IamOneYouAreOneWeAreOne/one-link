from __future__ import annotations

import os
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir

APP = "One_link"
AUTHOR = "Coherence"

# ONE_LINK_HOME overrides both config and data dirs. Useful for running
# multiple daemons on one machine (smoke testing) and for portable installs.
HOME_ENV = "ONE_LINK_HOME"


def _home_override() -> Path | None:
    v = os.environ.get(HOME_ENV)
    return Path(v).expanduser() if v else None


def config_dir() -> Path:
    h = _home_override()
    p = (h / "config") if h else Path(user_config_dir(APP, AUTHOR))
    p.mkdir(parents=True, exist_ok=True)
    return p


def data_dir() -> Path:
    h = _home_override()
    p = (h / "data") if h else Path(user_data_dir(APP, AUTHOR))
    p.mkdir(parents=True, exist_ok=True)
    return p


def key_path() -> Path:
    return config_dir() / "identity.key"


def peers_db_path() -> Path:
    return data_dir() / "peers.json"


# v0.10.0: per-daemon override for the inbox / "Downloads" folder.
# Set via set_inbox_override(path) at daemon startup from the
# settings table (`download_folder`). When None, the default
# data_dir() / "inbox" is used. This is a runtime-only override —
# we don't persist it through paths.py so tests + multi-daemon
# setups stay isolated.
_INBOX_OVERRIDE: Path | None = None


def set_inbox_override(path: Path | None) -> None:
    """Point inbox_dir() at a user-chosen folder. Pass None to
    reset to the default. Caller is responsible for ensuring the
    path exists + is writable."""
    global _INBOX_OVERRIDE
    if path is None:
        _INBOX_OVERRIDE = None
    else:
        _INBOX_OVERRIDE = Path(path).expanduser().resolve()


def inbox_dir() -> Path:
    if _INBOX_OVERRIDE is not None:
        # User-chosen folder. mkdir is no-op if it exists.
        _INBOX_OVERRIDE.mkdir(parents=True, exist_ok=True)
        return _INBOX_OVERRIDE
    p = data_dir() / "inbox"
    p.mkdir(parents=True, exist_ok=True)
    return p


def message_log_path() -> Path:
    return data_dir() / "messages.jsonl"
