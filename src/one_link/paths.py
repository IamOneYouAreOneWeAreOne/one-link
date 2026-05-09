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
    """Resolve ONE_LINK_HOME if set, after sanitization.

    v0.20.7 (security audit M28): the previous implementation did
    Path(env_value).expanduser() with no validation, which let an
    attacker (or a stale setup script) point One Link at any path
    they liked — including ``/etc``, ``$HOME/../other-user``, or a
    UNC share on Windows. A daemon running with elevated
    privileges (sudo, installer, CI runner) would then mkdir
    config / data subdirs at the attacker's chosen location.

    The hardening:
      - Reject empty / whitespace-only values.
      - Reject any path component equal to ".." (no traversal).
      - Reject UNC paths on Windows (``\\\\server\\share``) — those
        route storage onto a network share, which is generally not
        what a multi-daemon-on-one-machine override is for.
      - Require absolute paths after expanduser/resolve to fail
        loudly on relative-path env injection.
    On rejection we log a clear warning and fall through to the
    default platform dirs.
    """
    v = os.environ.get(HOME_ENV)
    if v is None:
        return None
    raw = v.strip()
    if not raw:
        return None
    # No traversal segments — even after expanduser/resolve, ".."
    # in the original env value signals an attempt to break out of
    # whatever the operator thought the override would be.
    if ".." in raw.replace("\\", "/").split("/"):
        import logging
        logging.getLogger("one_link.paths").warning(
            "ONE_LINK_HOME contains '..' (rejected): %r — falling "
            "back to platform default",
            v,
        )
        return None
    # UNC on Windows: //server/share or \\server\share. Reject.
    if os.name == "nt":
        normalized = raw.replace("\\", "/")
        if normalized.startswith("//"):
            import logging
            logging.getLogger("one_link.paths").warning(
                "ONE_LINK_HOME is a UNC path (rejected): %r — "
                "falling back to platform default",
                v,
            )
            return None
    try:
        p = Path(raw).expanduser()
        # Resolve to an absolute path; fail if the value still
        # comes out relative (which can happen on a tmp-cwd layout
        # we don't control).
        if not p.is_absolute():
            try:
                p = p.resolve()
            except OSError:
                pass
        if not p.is_absolute():
            import logging
            logging.getLogger("one_link.paths").warning(
                "ONE_LINK_HOME is not an absolute path (rejected): "
                "%r — falling back to platform default",
                v,
            )
            return None
        return p
    except (ValueError, OSError) as e:
        import logging
        logging.getLogger("one_link.paths").warning(
            "ONE_LINK_HOME unparseable (%s): %r — falling back to "
            "platform default",
            e, v,
        )
        return None


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
