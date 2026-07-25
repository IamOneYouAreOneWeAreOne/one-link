"""Cross-platform user-mode auto-start at login.

The in-process supervisor handles software crashes — bugs that take
the daemon down get auto-restarted. It does NOT survive the
operating system terminating the whole process tree: log-off, sleep
+ hibernate that wakes into a fresh user session, fast-startup, or
explicit ``taskkill /F`` of the supervisor itself. For those, the OS
has to bring us back.

This module wires One Link into each platform's *user-mode*
auto-start mechanism (no admin / root needed):

  Windows: ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run``
           registry value pointing at ``one-link app --supervise --no-browser``.
  macOS:   ``~/Library/LaunchAgents/com.coherence.one-link.plist``.
  Linux:   ``~/.config/autostart/one-link.desktop`` (XDG autostart spec).

Each backend exposes the same trio: ``is_enabled()``, ``enable()``,
``disable()``. The implementations are intentionally simple; they
write a single artifact and read it back to check status. No daemons,
no admin elevation, no service installer dependency.

Why ``--no-browser`` on login start: opening a tab in the user's face
the second they log in is hostile. The daemon comes up silently, the
tray icon surfaces it, and the user clicks when they want to look at
it.
"""
from __future__ import annotations

import contextlib
import os
import plistlib
import secrets
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Optional

from one_link import __version__
from one_link.process_security import resolve_explicit_executable

AUTOSTART_NAME = "One Link"
AUTOSTART_ID = "com.coherence.one-link"
AUTOSTART_COMMENT = "One Link — peer-to-peer chat / files / calls (auto-started at login)"


# ─── command building ──────────────────────────────────────────────────

def _launch_command() -> list[str]:
    """Build the argv for "start One Link at login".

    Uses the current frozen binary or ``<sys.executable> -P -m one_link.cli``.
    PATH, adjacent launcher stubs, and the working directory are never
    consulted because this command persists across logins and would otherwise
    turn a transient search-path hijack into durable code execution.

    Always passes ``--supervise --no-browser``: supervised so a daemon
    crash auto-restarts; no browser so login doesn't pop a tab.
    """
    python_exe = resolve_explicit_executable(sys.executable)
    if getattr(sys, "frozen", False):
        return [python_exe, "app", "--supervise", "--no-browser"]
    return [
        python_exe,
        "-P",
        "-m",
        "one_link.cli",
        "app",
        "--supervise",
        "--no-browser",
    ]


def _quote_for_shell(args: list[str]) -> str:
    """Render argv for a Windows Run value or freedesktop Exec field.

    Different backends need a string (Windows registry, .desktop ``Exec=``,
    LaunchAgent ``ProgramArguments`` is the exception — it takes a list).
    Neither backend invokes a POSIX shell. Windows uses the same quoting
    algorithm as ``CreateProcess``; freedesktop Exec has its own double-quote
    and percent-field-code grammar.
    """
    if not args or any(
        not isinstance(arg, str)
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in arg)
        for arg in args
    ):
        raise ValueError("autostart argv must contain control-free strings")
    if os.name == "nt":
        return subprocess.list2cmdline(args)

    def desktop_quote(arg: str) -> str:
        # '%' introduces desktop field codes even inside quotes; '%%' is a
        # literal percent. Within double quotes, these four characters must be
        # backslash escaped by the Desktop Entry specification.
        escaped = arg.replace("%", "%%")
        for char in ("\\", '"', "`", "$"):
            escaped = escaped.replace(char, "\\" + char)
        return f'"{escaped}"'

    return " ".join(desktop_quote(arg) for arg in args)


def _atomic_private_write(path: Path, data: bytes) -> None:
    """Atomically publish a private autostart artifact without symlink writes."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        with contextlib.suppress(OSError):
            path.chmod(0o600)
        if hasattr(os, "O_DIRECTORY"):
            with contextlib.suppress(OSError):
                directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(OSError):
            temporary.unlink()


# ─── Windows backend (registry Run key) ────────────────────────────────

_WIN_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _win_is_enabled() -> bool:
    import winreg  # type: ignore[import]
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_RUN_KEY) as k:
            try:
                winreg.QueryValueEx(k, AUTOSTART_NAME)
                return True
            except FileNotFoundError:
                return False
    except OSError:
        return False


def _win_enable() -> Path:
    import winreg  # type: ignore[import]
    cmd = _quote_for_shell(_launch_command())
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _WIN_RUN_KEY) as k:
        winreg.SetValueEx(k, AUTOSTART_NAME, 0, winreg.REG_SZ, cmd)
    # The "artifact path" is conceptual for the registry — return a
    # human-readable identifier so the caller can print "wrote X" in
    # a uniform way across platforms.
    return Path(f"HKCU\\{_WIN_RUN_KEY}\\{AUTOSTART_NAME}")


def _win_disable() -> bool:
    import winreg  # type: ignore[import]
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, _WIN_RUN_KEY, 0, winreg.KEY_SET_VALUE,
        ) as k:
            try:
                winreg.DeleteValue(k, AUTOSTART_NAME)
                return True
            except FileNotFoundError:
                return False
    except OSError:
        return False


# ─── macOS backend (LaunchAgent plist) ─────────────────────────────────

def _macos_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{AUTOSTART_ID}.plist"


def _macos_is_enabled() -> bool:
    return _macos_plist_path().is_file()


def _macos_enable() -> Path:
    args = _launch_command()
    plist = plistlib.dumps(
        {
            "Label": AUTOSTART_ID,
            "ProgramArguments": args,
            "RunAtLoad": True,
            "KeepAlive": False,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )
    path = _macos_plist_path()
    _atomic_private_write(path, plist)
    return path


def _macos_disable() -> bool:
    path = _macos_plist_path()
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False


# ─── Linux backend (XDG autostart .desktop) ────────────────────────────

def _linux_desktop_path() -> Path:
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    root = Path(config_home).expanduser()
    if not root.is_absolute():
        raise ValueError("XDG_CONFIG_HOME must be absolute")
    return root / "autostart" / "one-link.desktop"


def _linux_is_enabled() -> bool:
    return _linux_desktop_path().is_file()


def _linux_enable() -> Path:
    cmd = _quote_for_shell(_launch_command())
    desktop = textwrap.dedent(f"""\
        [Desktop Entry]
        Type=Application
        Name={AUTOSTART_NAME}
        Comment={AUTOSTART_COMMENT}
        Exec={cmd}
        Terminal=false
        X-GNOME-Autostart-enabled=true
        X-One-Link-Version={__version__}
        """)
    path = _linux_desktop_path()
    _atomic_private_write(path, desktop.encode("utf-8"))
    return path


def _linux_disable() -> bool:
    path = _linux_desktop_path()
    if not path.exists():
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False


# ─── public dispatch ───────────────────────────────────────────────────

def _backend() -> str:
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def is_enabled() -> bool:
    """Return True if auto-start at login is registered for this user."""
    backend = _backend()
    if backend == "windows":
        return _win_is_enabled()
    if backend == "macos":
        return _macos_is_enabled()
    return _linux_is_enabled()


def enable() -> Path:
    """Register One Link to auto-start at the current user's next login.

    Idempotent — calling twice rewrites the same artifact with the
    current ``_launch_command()``. Useful after upgrading the binary
    to a different path: re-call enable() to point the auto-start at
    the new location. Returns the path / registry identifier that was
    written so the caller can print it.
    """
    backend = _backend()
    if backend == "windows":
        return _win_enable()
    if backend == "macos":
        return _macos_enable()
    return _linux_enable()


def disable() -> bool:
    """Remove the auto-start registration. Returns True if there was
    something to remove (i.e. it was previously enabled), False
    otherwise. Never raises on "already disabled"."""
    backend = _backend()
    if backend == "windows":
        return _win_disable()
    if backend == "macos":
        return _macos_disable()
    return _linux_disable()


def artifact_path() -> Optional[Path]:
    """Return the path / identifier that ``enable()`` writes to, even
    if not currently enabled. Used by status reporting and by tests."""
    backend = _backend()
    if backend == "windows":
        return Path(f"HKCU\\{_WIN_RUN_KEY}\\{AUTOSTART_NAME}")
    if backend == "macos":
        return _macos_plist_path()
    return _linux_desktop_path()
