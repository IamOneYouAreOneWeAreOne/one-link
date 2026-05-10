"""`one-link app` - launch the desktop UI.

The launcher owns the "just works" contract:

1. Reuse a running daemon only when it proves it is this build.
2. Gracefully stop stale daemons instead of opening a mismatched UI/backend.
3. Spawn a fresh daemon and open the browser once the self-check passes.

Users should never need to know what a daemon, port, token, schema, or
background process is.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from typing import Optional

import click

from one_link import __version__
from one_link import daemon as daemon_mod
from one_link import server as server_mod
from one_link.paths import data_dir


@dataclass(frozen=True)
class RunningDaemon:
    control_port: int
    server_port: int
    token: str
    status: dict

    @property
    def compatible(self) -> bool:
        return (
            self.status.get("ok") is True
            and self.status.get("app_version") == __version__
            and bool(self.status.get("protocol_version"))
            and int(self.status.get("schema_version") or 0) > 0
        )


def _alive(port: int, timeout: float = 0.3) -> bool:
    return daemon_mod.is_daemon_alive(port, timeout=timeout)


def _daemon_is_lan_bound(info: "RunningDaemon") -> bool:
    """v0.15.4 — ask the daemon directly whether it's LAN-bound.
    Earlier versions probed via socket.connect() to the LAN IP, but
    Windows + Linux kernels route same-host connects to your own
    LAN IP back through loopback even when the listener is bound
    to 127.0.0.1 only — so the probe gave a false positive and
    --lan never actually rebound the daemon.

    The /api/status payload includes `bind_host` since v0.15.2;
    treating any non-loopback value as LAN-bound is the only
    reliable signal."""
    bind_host = info.status.get("bind_host")
    if not bind_host:
        # Pre-v0.15.2 daemon (no bind_host field) — assume worst
        # case (loopback) so --lan triggers a restart.
        return False
    return bind_host not in ("127.0.0.1", "localhost", "::1")


def _control_request(port: int, cmd: str, timeout: float = 2.0, **kwargs) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall((json.dumps({"cmd": cmd, **kwargs}) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        s.close()


def _ui_status(server_port: int, token: str, timeout: float = 1.5) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{server_port}/api/status",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as e:
        return {"ok": False, "error": str(e)}


def _runtime_matches_control(control_status: dict, ui_status: dict) -> bool:
    if ui_status.get("ok") is not True:
        return False
    control_me = control_status.get("me") or {}
    ui_me = ui_status.get("me") or {}
    control_fp = control_me.get("fingerprint")
    ui_fp = ui_me.get("fingerprint")
    if control_fp and ui_fp and control_fp != ui_fp:
        return False
    return ui_status.get("app_version") == control_status.get("app_version")


def _resolve_running_daemon() -> Optional[RunningDaemon]:
    """Return the reachable daemon plus its self-reported status."""
    try:
        ctrl = daemon_mod.read_control_port()
    except RuntimeError:
        return None
    if not _alive(ctrl):
        return None
    status = _control_request(ctrl, "status")
    if status.get("ok") is not True:
        return None
    srv = status.get("ui_server_port")
    if not isinstance(srv, int) or srv <= 0:
        srv = None
    try:
        token = server_mod.read_ui_token()
    except RuntimeError:
        return None
    if srv is None:
        try:
            srv = server_mod.read_server_port()
        except RuntimeError:
            return None
    ui_status = _ui_status(int(srv), token)
    if not _runtime_matches_control(status, ui_status):
        return None
    return RunningDaemon(ctrl, int(srv), token, status)


def _wait_for_daemon(timeout: float = 12.0) -> Optional[RunningDaemon]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _resolve_running_daemon()
        if r is not None:
            return r
        time.sleep(0.15)
    return None


def _lock_pid() -> int | None:
    p = data_dir() / daemon_mod.DAEMON_LOCK_FILE
    try:
        raw = p.read_text(encoding="ascii", errors="ignore").strip()
        return int(raw) if raw else None
    except Exception:
        return None


def _terminate_pid(pid: int, timeout: float = 5.0) -> bool:
    if pid <= 0 or pid == os.getpid():
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return True
        time.sleep(0.1)
    if os.name == "nt":
        # Console-less children can ignore SIGTERM on Windows. Last resort.
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
            )
        except Exception:
            pass
    return True


def _stop_incompatible_daemon(info: RunningDaemon) -> bool:
    """Best-effort stop for stale daemons before launching this build."""
    if info.compatible:
        return True
    status = info.status or {}
    if status.get("ok") is True:
        _control_request(info.control_port, "shutdown", timeout=2.0)
        deadline = time.time() + 6.0
        while time.time() < deadline:
            if not _alive(info.control_port):
                return True
            time.sleep(0.15)
    pid = status.get("pid")
    if not isinstance(pid, int):
        pid = _lock_pid()
    if isinstance(pid, int):
        return _terminate_pid(pid)
    return False


def _spawn_daemon() -> subprocess.Popen:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    return subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )


def _open_browser_url(url: str) -> None:
    if os.name == "nt":
        os.startfile(url)  # type: ignore[attr-defined]
        return
    opened = webbrowser.open(url, new=2)
    if not opened:
        raise RuntimeError("browser did not accept the URL")


def _detect_lan_ip() -> str:
    """v0.15.2 — best-effort LAN IPv4 detection. Opens a UDP socket
    and "connects" to a public address; the OS picks the right
    outbound interface but no packet is actually sent. Returns
    127.0.0.1 if there's no usable interface (e.g. airplane mode).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # 8.8.8.8 is Google DNS — never actually contacted, just used
        # as a routing target so the OS picks the egress interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _print_lan_warning(lan_ip: str, port: int, token: str) -> None:
    """v0.15.2 — yellow security warning + LAN URL. Made deliberately
    loud so a user who passed --lan understands the trust boundary
    they just opened: anyone on the same Wi-Fi who has the URL+token
    can reach the UI. Uses ASCII-only glyphs because Windows cp1252
    consoles raise UnicodeEncodeError on ⚠ (warning sign) — the
    crash happens AFTER the daemon spawns, leaving the user with a
    running daemon but no printed URL."""
    click.echo("")
    click.secho(
        "  ** LAN MODE - One Link UI is now exposed to your local network.",
        fg="yellow",
        bold=True,
    )
    click.echo(
        "     Anyone on this Wi-Fi who has the URL + token can access your UI."
    )
    click.echo(
        "     The token gates pairing + sending; treat the URL like a password."
    )
    click.echo("")
    click.secho(
        f"  Phone/LAN URL: http://{lan_ip}:{port}/?t={token}",
        fg="cyan",
        bold=True,
    )
    click.echo("")


def run_app(*, no_browser: bool = False, lan: bool = False) -> int:
    click.echo("One Link")
    # v0.15.2: --lan opt-in. Set BEFORE we try to reuse a running
    # daemon so any spawned-fresh daemon inherits the right bind
    # host. If a 127.0.0.1-bound daemon is already running, we'll
    # stop it and replace; the user explicitly asked for LAN mode.
    if lan:
        os.environ["ONE_LINK_BIND_HOST"] = "0.0.0.0"

    spawned: Optional[subprocess.Popen] = None
    info = _resolve_running_daemon()
    if info is None:
        # The control socket can appear a beat before the UI port/token are
        # published. Desktop shortcuts must treat that as "still starting",
        # not as permission to launch a competing daemon.
        info = _wait_for_daemon(timeout=2.0)

    # v0.15.2: --lan forces a daemon replacement when an existing
    # daemon is bound to loopback. We don't have a bind-host field
    # in the existing status payload (older daemons), so we
    # detect LAN-bind by trying to connect to the daemon via the
    # LAN IP — if that succeeds, the daemon is already LAN-bound.
    if lan and info is not None and info.compatible:
        if not _daemon_is_lan_bound(info):
            click.echo("  switching daemon to LAN mode...")
            _stop_incompatible_daemon(info)
            # Give the OS a moment to release the listening socket so
            # the freshly-spawned daemon can rebind the same port. On
            # Windows the TIME_WAIT can otherwise force the new daemon
            # to fall through to a higher candidate port.
            time.sleep(1.0)
            info = _wait_for_daemon(timeout=1.0)
            if info is not None:
                # Daemon survived our shutdown request? Rare; fall
                # through and accept whatever we end up with.
                pass

    if info is not None and not info.compatible:
        running = info.status.get("app_version") or "unknown"
        click.echo(f"  replacing stale daemon ({running} -> {__version__})...")
        _stop_incompatible_daemon(info)
        info = _wait_for_daemon(timeout=1.0)
        if info is not None and not info.compatible:
            info = None

    if info is None:
        click.echo("  starting daemon...")
        spawned = _spawn_daemon()
        info = _wait_for_daemon()
        if info is None or not info.compatible:
            click.echo("  ! daemon failed to start cleanly")
            try:
                spawned.terminate()
            except Exception:
                pass
            return 2
        click.echo("  daemon up.")
    else:
        click.echo("  using running daemon.")

    url = f"http://127.0.0.1:{info.server_port}/?t={info.token}"
    click.echo(f"  open: {url}")
    if not no_browser:
        try:
            _open_browser_url(url)
        except Exception as e:
            click.echo(f"  (couldn't auto-open browser: {e})")

    if lan:
        lan_ip = _detect_lan_ip()
        if lan_ip == "127.0.0.1":
            click.secho(
                "  (could not detect a LAN IP — is Wi-Fi/Ethernet up?)",
                fg="yellow",
            )
        else:
            _print_lan_warning(lan_ip, info.server_port, info.token)

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
