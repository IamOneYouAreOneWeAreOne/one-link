"""`one-link app` — launch the desktop UI.

Behavior:
  1. If a daemon is already running, just open the browser to its UI URL.
  2. Otherwise, spawn a daemon as a child of this command and open the
     browser. When the user closes the launcher (Ctrl-C), the spawned
     daemon stops.

This is the path most users hit for "open it and use it." It always
works because every modern OS has a default browser; we don't depend
on pywebview / pythonnet / etc.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import webbrowser
from typing import Optional

import click

from one_link import daemon as daemon_mod
from one_link import server as server_mod


def _alive(port: int, timeout: float = 0.3) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _resolve_running_daemon() -> Optional[tuple[int, int, str]]:
    """If a daemon is reachable, return (control_port, server_port, ui_token).
    Otherwise None."""
    try:
        ctrl = daemon_mod.read_control_port()
    except RuntimeError:
        return None
    if not _alive(ctrl):
        return None
    try:
        srv = server_mod.read_server_port()
        token = server_mod.read_ui_token()
    except RuntimeError:
        return None
    return ctrl, srv, token


def _wait_for_daemon(timeout: float = 12.0) -> Optional[tuple[int, int, str]]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _resolve_running_daemon()
        if r is not None:
            return r
        time.sleep(0.15)
    return None


def _spawn_daemon() -> subprocess.Popen:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )


def run_app(*, no_browser: bool = False) -> int:
    click.echo("One Link")
    spawned: Optional[subprocess.Popen] = None
    info = _resolve_running_daemon()
    if info is None:
        click.echo("  starting daemon …")
        spawned = _spawn_daemon()
        info = _wait_for_daemon()
        if info is None:
            click.echo("  ! daemon failed to start in time")
            try:
                spawned.terminate()
            except Exception:
                pass
            return 2
        click.echo("  daemon up.")
    else:
        click.echo("  using running daemon.")

    _, server_port, token = info
    url = f"http://127.0.0.1:{server_port}/?t={token}"
    click.echo(f"  open: {url}")
    if not no_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception as e:
            click.echo(f"  (couldn't auto-open browser: {e})")

    if spawned is not None:
        click.echo("\n  Daemon is running as a child of this terminal.")
        click.echo("  Close this window or Ctrl-C to stop.\n")
        try:
            spawned.wait()
        except KeyboardInterrupt:
            pass
        finally:
            try:
                spawned.terminate()
                spawned.wait(timeout=5)
            except subprocess.TimeoutExpired:
                spawned.kill()
            except Exception:
                pass
    return 0
