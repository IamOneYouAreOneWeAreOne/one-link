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

import os
import shutil
import sys
import textwrap
from pathlib import Path
from typing import Optional

from one_link import __version__

AUTOSTART_NAME = "One Link"
AUTOSTART_ID = "com.coherence.one-link"
AUTOSTART_COMMENT = "One Link — peer-to-peer chat / files / calls (auto-started at login)"


# ─── command building ──────────────────────────────────────────────────

def _launch_command() -> list[str]:
    """Build the argv for "start One Link at login".

    Prefers the frozen ``one-link`` binary when one is on PATH (the
    user installed the release zip). Falls back to
    ``<sys.executable> -m one_link.cli`` for source-checkout users.

    Always passes ``--supervise --no-browser``: supervised so a daemon
    crash auto-restarts; no browser so login doesn't pop a tab.
    """
    one_link_exe = shutil.which("one-link") or shutil.which("one-link.exe")
    if one_link_exe:
        return [one_link_exe, "app", "--supervise", "--no-browser"]
    return [sys.executable, "-m", "one_link.cli", "app",
            "--supervise", "--no-browser"]


def _quote_for_shell(args: list[str]) -> str:
    """Render argv as a single shell-safe command string.

    Different backends need a string (Windows registry, .desktop ``Exec=``,
    LaunchAgent ``ProgramArguments`` is the exception — it takes a list).
    Round-trippable through any reasonable shell; spaces are escaped
    via double-quoting on Windows + single-quoting on POSIX.
    """
    if os.name == "nt":
        out: list[str] = []
        for a in args:
            if " " in a or "\t" in a:
                out.append(f'"{a}"')
            else:
                out.append(a)
        return " ".join(out)
    # POSIX: single-quote, escape any embedded single quotes.
    return " ".join(
        "'" + a.replace("'", "'\\''") + "'" for a in args
    )


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
    args_xml = "\n".join(f"    <string>{a}</string>" for a in args)
    plist = textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{AUTOSTART_ID}</string>
            <key>ProgramArguments</key>
            <array>
        {args_xml}
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <false/>
            <key>StandardOutPath</key>
            <string>/tmp/one-link-autostart.out</string>
            <key>StandardErrorPath</key>
            <string>/tmp/one-link-autostart.err</string>
        </dict>
        </plist>
        """)
    path = _macos_plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plist, encoding="utf-8")
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
    return Path(config_home) / "autostart" / "one-link.desktop"


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
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(desktop, encoding="utf-8")
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
