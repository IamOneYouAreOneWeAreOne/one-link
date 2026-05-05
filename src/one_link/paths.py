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


def inbox_dir() -> Path:
    p = data_dir() / "inbox"
    p.mkdir(parents=True, exist_ok=True)
    return p


def message_log_path() -> Path:
    return data_dir() / "messages.jsonl"
