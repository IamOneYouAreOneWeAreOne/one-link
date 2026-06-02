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
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import click

from one_link import __version__
from one_link import daemon as daemon_mod
from one_link import server as server_mod
from one_link.build_identity import runtime_build_identity
from one_link.paths import data_dir
from one_link.safe_http import validated_urlopen


@dataclass(frozen=True)
class RunningDaemon:
    control_port: int
    server_port: int
    token: str
    status: dict

    @property
    def compatible(self) -> bool:
        build = runtime_build_identity()
        return (
            self.status.get("ok") is True
            and self.status.get("app_version") == __version__
            and self.status.get("source_fingerprint")
            == build["source_fingerprint"]
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
        with validated_urlopen(req, timeout=timeout, allow_loopback_http=True) as r:
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
    build = runtime_build_identity()
    return (
        ui_status.get("app_version") == control_status.get("app_version")
        and control_status.get("source_fingerprint")
        == build["source_fingerprint"]
        and ui_status.get("source_fingerprint")
        == build["source_fingerprint"]
    )


def _resolve_running_daemon() -> Optional[RunningDaemon]:
    """Return the reachable daemon plus its self-reported status.

    Side-effect-free: passes clear_stale=False so a poll during a
    daemon's boot never deletes the daemon's freshly-written
    control.port (which it writes once and never recreates)."""
    try:
        ctrl = daemon_mod.read_control_port(clear_stale=False)
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


def _wait_for_daemon(timeout: float = 45.0) -> Optional[RunningDaemon]:
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
            taskkill = (
                Path(os.environ.get("SystemRoot", r"C:\Windows"))
                / "System32"
                / "taskkill.exe"
            )
            subprocess.run(
                [str(taskkill), "/PID", str(int(pid)), "/T", "/F"],
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


DAEMON_LAUNCH_LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB before rotation
DAEMON_LAUNCH_LOG_KEEP = 3                       # keep .log.1 .. .log.3


def _rotate_daemon_launch_log(log_path: Path) -> None:
    """Size-based rotation for ``daemon-launch.err.log``.

    The file is now opened in append mode (not truncate) so the
    forensic trail survives the launcher → supervisor → daemon
    restart chain. Without rotation that file would grow forever; a
    flapping daemon could produce gigabytes. We rotate to .log.1, .2,
    .3 (oldest dropped) when the active file crosses
    DAEMON_LAUNCH_LOG_MAX_BYTES. Best-effort; failures are non-fatal
    because we are on a startup path where producing a fresh log is
    only the second priority — getting the daemon up is the first.
    """
    try:
        if not log_path.exists():
            return
        if log_path.stat().st_size < DAEMON_LAUNCH_LOG_MAX_BYTES:
            return
    except OSError:
        return
    # Shift .N → .N+1, drop the oldest.
    for i in range(DAEMON_LAUNCH_LOG_KEEP, 0, -1):
        src = log_path.with_suffix(log_path.suffix + f".{i}")
        dst = log_path.with_suffix(log_path.suffix + f".{i + 1}")
        if src.exists():
            try:
                if i == DAEMON_LAUNCH_LOG_KEEP:
                    src.unlink()
                else:
                    src.replace(dst)
            except OSError:
                pass
    try:
        log_path.replace(log_path.with_suffix(log_path.suffix + ".1"))
    except OSError:
        pass


def _spawn_daemon() -> subprocess.Popen:
    """Spawn the daemon child. Redirects stderr to a known log file
    instead of DEVNULL so the desktop-shortcut launch path (pythonw
    no-console) leaves an inspectable trail when the daemon fails to
    come up. Without this trail the user sees "daemon failed to start
    cleanly" with no diagnostic — every operator support call ends up
    needing the daemon re-launched with `-v` from a terminal just to
    capture the error.

    The log is APPENDED to across launches (was previously truncated
    on every spawn, which silently deleted the supervisor's startup
    record + every prior restart's traceback). Size-based rotation at
    DAEMON_LAUNCH_LOG_MAX_BYTES keeps disk usage bounded; older
    rotations live next to it as ``daemon-launch.err.log.1`` ... .3.
    """
    log_path = data_dir() / "daemon-launch.err.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _rotate_daemon_launch_log(log_path)

    if getattr(sys, "frozen", False):
        daemon_cmd = [sys.executable, "daemon", "-v"]
    else:
        daemon_cmd = [sys.executable, "-m", "one_link.cli", "daemon", "-v"]

    # Windows: the launcher (especially under PyInstaller --onefile and
    # when launched from a terminal that has its own Job Object) is
    # inside a Win32 Job Object that does NOT have
    # JOB_OBJECT_LIMIT_BREAKAWAY_OK set. That means a normal
    # subprocess.Popen with CREATE_BREAKAWAY_FROM_JOB is silently
    # ignored — the daemon stays in the parent's job and dies when
    # the launcher exits.
    #
    # The robust fix is to launch the daemon via the Windows shell,
    # which spawns the new process under explorer's tree (no shared
    # job). We use `cmd /c start "" /B exe daemon -v` then immediately
    # discover the resulting daemon PID by polling for the listen
    # socket / port file. This is the same technique GUI installers
    # use to start "fire and forget" background services.
    # PYTHONUNBUFFERED=1 — never lose the last 4 KiB of daemon stderr on
    # a crash. Without this, the child's stdout fd to daemon-launch.err.log
    # is block-buffered (~4 KiB); a final uncaught exception's traceback
    # gets queued in that buffer and dropped when the process exits
    # abruptly. We have lived through that exact symptom (silent
    # mid-conversation death, log ends with normal traffic, no
    # traceback) — line-flush mode for the child eliminates the entire
    # buffering-trap failure class.
    child_env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    if os.name == "nt":
        return _spawn_daemon_windows_detached(daemon_cmd, log_path, env=child_env)
    # POSIX: setsid() detaches from the controlling terminal and the
    # daemon survives the launcher exiting. No Job Object on Linux/mac.
    # Append (not truncate) so the supervisor's startup record + any
    # previous run's tail survive this spawn — rotation above keeps
    # disk usage bounded.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    return subprocess.Popen(
        daemon_cmd,
        stdout=subprocess.DEVNULL,
        stderr=(log_fh if log_fh is not None else subprocess.DEVNULL),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=child_env,
    )


def _spawn_supervisor() -> subprocess.Popen:
    """Spawn ``one-link supervisor`` instead of the daemon directly.

    The supervisor stays alive watching its child daemon, auto-
    restarting on crash with backoff + circuit breaker. From the
    launcher's perspective the two are interchangeable: both detach,
    both write to ``daemon-launch.err.log``, both surface on the
    same UI port. The difference is what happens on crash:

      * ``_spawn_daemon``     → crash = process gone, user reloads.
      * ``_spawn_supervisor`` → crash = automatic respawn, user's
        browser-side reconnect already covers the gap.

    Mirrors ``_spawn_daemon``'s frozen/source split and env exactly
    so the resulting process tree only differs by one CLI command
    name.
    """
    log_path = data_dir() / "daemon-launch.err.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    _rotate_daemon_launch_log(log_path)
    if getattr(sys, "frozen", False):
        cmd = [sys.executable, "supervisor"]
    else:
        cmd = [sys.executable, "-m", "one_link.cli", "supervisor"]
    child_env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    if os.name == "nt":
        return _spawn_daemon_windows_detached(cmd, log_path, env=child_env)
    # Append (not truncate) — see _spawn_daemon for the rationale.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=(log_fh if log_fh is not None else subprocess.DEVNULL),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
        env=child_env,
    )


def _spawn_daemon_windows_detached(
    daemon_cmd: list[str], log_path: Path,
    *, env: dict[str, str] | None = None,
) -> subprocess.Popen:
    """Spawn the daemon detached on Windows so it outlives the launcher.

    History: this used to write a .cmd file and invoke
    ``cmd /c start "" /B``. That `start` form mis-parsed the quoted
    interpreter path + ``-m`` args and returned "The system cannot find
    the path specified" (rc 1) — the daemon never launched, the log
    stayed empty, and a bare ``except: pass`` swallowed the failure, so
    the launcher waited out its full timeout and reported a false
    "daemon failed to start cleanly". This is the root cause of that bug.

    Now we spawn the interpreter DIRECTLY with detachment creation
    flags (verified reliable; no shell, no quoting hazard) and send the
    daemon's stdout+stderr to ``log_path`` so a real startup failure is
    actually diagnosable. We prefer full Job-Object breakaway (so the
    daemon survives a launcher in a kill-on-close job); if the parent
    job forbids breakaway we retry without it (still detaches from the
    console and survives a normal terminal/shortcut close)."""
    NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    DETACHED = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    NEW_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    BREAKAWAY = getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)

    # Append, never truncate — preserves the launcher's full forensic
    # chain (supervisor lines + every prior daemon run) across this
    # spawn. _rotate_daemon_launch_log() caps size from the calling
    # _spawn_daemon / _spawn_supervisor.
    try:
        log_fh = open(log_path, "ab")
    except OSError:
        log_fh = None
    out = log_fh if log_fh is not None else subprocess.DEVNULL

    base = NO_WINDOW | DETACHED | NEW_GROUP
    last_err: Exception | None = None
    for flags in (base | BREAKAWAY, base, 0):
        try:
            return subprocess.Popen(
                daemon_cmd,
                stdout=out,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
                close_fds=True,
                env=env,
            )
        except (OSError, ValueError) as e:
            # A restrictive Job Object can reject CREATE_BREAKAWAY_FROM_JOB
            # with "access denied"; drop the flag and retry. flags=0 is
            # the final, always-valid fallback (tracked child, but it
            # starts — strictly better than silently spawning nothing).
            last_err = e
            continue
    # Should be unreachable (flags=0 cannot raise these), but never
    # return a no-op handle that hides a non-spawn.
    raise RuntimeError(
        f"could not spawn daemon subprocess: {last_err}"
    )


def _default_window_geometry() -> tuple[int, int, int, int]:
    """Return (width, height, x, y) for the desktop window.

    Compute 80% of the primary monitor size, clamped to a sensible
    max (1400x900 — bigger feels overwhelming on dense layouts),
    centered on screen. Falls back to 1280x800 at (120, 80) when
    the screen size can't be detected.
    """
    width, height = 1280, 800
    screen_w, screen_h = 0, 0
    if os.name == "nt":
        try:
            import ctypes
            user32 = ctypes.windll.user32
            # SM_CXSCREEN / SM_CYSCREEN — primary monitor pixels.
            screen_w = int(user32.GetSystemMetrics(0))
            screen_h = int(user32.GetSystemMetrics(1))
        except Exception:
            pass
    else:
        # tkinter is in the stdlib; cheap probe that works on
        # macOS / Linux without GUI libs.
        try:
            import tkinter as _tk
            root = _tk.Tk()
            root.withdraw()
            screen_w = root.winfo_screenwidth()
            screen_h = root.winfo_screenheight()
            root.destroy()
        except Exception:
            pass
    if screen_w >= 800 and screen_h >= 600:
        # 80% of screen, but clamp the max so on 4K monitors the
        # window stays at a reasonable read width.
        width = min(int(screen_w * 0.80), 1400)
        height = min(int(screen_h * 0.80), 900)
    x = max(0, (screen_w - width) // 2) if screen_w else 120
    y = max(0, (screen_h - height) // 2) if screen_h else 80
    return width, height, x, y


def _find_chromium_browser_exe() -> Optional[str]:
    """Locate Edge or Chrome on the local machine. Used by the
    standalone-window launcher: both browsers support ``--app=URL``
    which opens a Chromium tab in a frameless standalone window
    (no tabs, no URL bar) — the closest to "native desktop app"
    we can get without bundling a runtime.

    Returns the absolute path to the browser exe, or ``None`` if
    neither is found. Edge wins the tie because it's preinstalled
    on every Windows 10/11 machine.
    """
    if os.name == "nt":
        candidates = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LocalAppData%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
        for p in candidates:
            if p and os.path.isfile(p):
                return p
        return None
    # POSIX: check $PATH.
    for name in ("microsoft-edge", "google-chrome", "chromium", "chrome"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _is_existing_app_window_running(profile_dir: Path) -> bool:
    """Return True if the isolated One Link app-mode profile already owns
    a visible top-level browser window.

    Double-clicking the exe repeatedly should feel idempotent. Without this
    guard every launch asks Edge/Chrome for another ``--app`` window, and on
    Windows that looks like One Link is "popping up" on a timer when a user
    has clicked more than once or an external launcher retries.
    """
    if os.name != "nt":
        return False
    try:
        import subprocess as _subprocess

        ps = (
            "$profile = $args[0]; "
            "Get-CimInstance Win32_Process | "
            "Where-Object { "
            "  $_.Name -match '^(msedge|chrome)\\.exe$' -and "
            "  $_.CommandLine -like ('*--user-data-dir=' + $profile + '*') -and "
            "  $_.CommandLine -like '*--app=http://127.0.0.1:*' "
            "} | Select-Object -First 1 -ExpandProperty ProcessId"
        )
        res = _subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps, str(profile_dir)],
            stdout=_subprocess.PIPE,
            stderr=_subprocess.DEVNULL,
            text=True,
            timeout=2.0,
            creationflags=(
                _subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            ),
            check=False,
        )
        return bool(res.stdout.strip())
    except Exception:
        return False


def _open_browser_url(url: str, *, standalone: bool = True) -> None:
    """Open ``url`` in the user's default browser, OR — when
    ``standalone`` is True (the default) — in a Chromium-style
    "app window" via ``msedge --app=URL`` / ``chrome --app=URL``.

    The app-mode flag tells the browser to:
    - drop the URL bar, tabs, and bookmark strip
    - open a single window with just the page content
    - use a separate process group so closing it doesn't take down
      other browser tabs

    Net visual effect: the user sees a One Link "desktop app" with
    just our UI — no browser chrome. Indistinguishable from a
    native app for everyday use.

    Falls back to ``os.startfile``/``webbrowser.open`` when no
    Chromium binary is found or the launch fails.
    """
    if standalone:
        browser = _find_chromium_browser_exe()
        if browser is not None:
            try:
                # --new-window guarantees a fresh window even if the
                # browser is already running; --app=URL is the
                # app-mode flag both Edge and Chrome accept.
                #
                # The extra flags suppress Edge's residual UI strip
                # (signin pill, first-run banner, default-browser
                # prompt) which otherwise renders as an empty gap
                # below the title bar. --user-data-dir isolates One
                # Link's Edge profile from the user's regular Edge
                # — no synced bookmarks, no extensions, no Microsoft
                # account, no "you already have this profile open"
                # conflicts when Edge is also open as a browser.
                profile_dir = data_dir() / "edge-app-profile"
                profile_dir.mkdir(parents=True, exist_ok=True)
                # Keep this launch path intentionally conservative. A
                # previous over-hardened flag set disabled a long list of
                # Edge/Chrome features and could make double-clicks look
                # dead on some Windows machines. These flags are the small
                # reliable set verified to open a visible isolated app
                # window while keeping One Link away from the user's normal
                # browser profile.
                # May 16 2026 — sensible default window size + position.
                # User reported "the app opens at half-view." Edge
                # --app= mode otherwise restores the LAST window
                # geometry from the isolated profile dir; on a fresh
                # profile that defaults to a small/awkward size. We
                # compute a window that's 80% of the primary screen
                # (clamped to 1400x900 max so on huge monitors the
                # window doesn't dominate) centered on screen.
                # Always make a user-triggered desktop launch visible.
                # A stale/minimized Edge app-mode process can still match
                # _is_existing_app_window_running(), which made double-clicks
                # look like One Link did nothing. Opening a fresh app window is
                # better than silently returning when the user explicitly
                # clicked the desktop app.
                win_w, win_h, win_x, win_y = _default_window_geometry()
                args = [
                    browser,
                    f"--app={url}",
                    "--new-window",
                    "--app-auto-launched",
                    f"--user-data-dir={profile_dir}",
                    "--window-name=One Link",
                    f"--window-size={win_w},{win_h}",
                    f"--window-position={win_x},{win_y}",
                    "--no-first-run",
                    "--no-default-browser-check",
                ]
                flags = (
                    subprocess.CREATE_NO_WINDOW
                    | subprocess.DETACHED_PROCESS
                    if os.name == "nt"
                    else 0
                )
                proc = subprocess.Popen(
                    args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=flags,
                    close_fds=True,
                )
                if os.name == "nt":
                    time.sleep(0.75)
                    if proc.poll() is not None or not _is_existing_app_window_running(
                        profile_dir
                    ):
                        os.startfile(url)  # type: ignore[attr-defined]
                return
            except Exception:
                # Standalone failed — fall through to default
                # browser. User gets a tab but at least sees something.
                pass
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


def _safe_echo(*args, **kwargs) -> None:
    """Best-effort console output for GUI-packaged launchers."""
    try:
        click.echo(*args, **kwargs)
    except OSError:
        return


def _safe_secho(*args, **kwargs) -> None:
    try:
        click.secho(*args, **kwargs)
    except OSError:
        return


def _print_lan_warning(lan_ip: str, port: int, token: str) -> None:
    """v0.15.2 — yellow security warning + LAN URL. Made deliberately
    loud so a user who passed --lan understands the trust boundary
    they just opened: anyone on the same Wi-Fi who has the URL+token
    can reach the UI. Uses ASCII-only glyphs because Windows cp1252
    consoles raise UnicodeEncodeError on ⚠ (warning sign) — the
    crash happens AFTER the daemon spawns, leaving the user with a
    running daemon but no printed URL."""
    _safe_echo("")
    _safe_secho(
        "  ** LAN MODE - One Link UI is now exposed to your local network.",
        fg="yellow",
        bold=True,
    )
    _safe_echo(
        "     Anyone on this Wi-Fi who has the URL + token can access your UI."
    )
    _safe_echo(
        "     The token gates pairing + sending; treat the URL like a password."
    )
    _safe_echo("")
    _safe_secho(
        f"  Phone/LAN URL: http://{lan_ip}:{port}/?t={token}",
        fg="cyan",
        bold=True,
    )
    _safe_echo("")


def _spawn_splash() -> Optional[subprocess.Popen]:
    """Open the native splash window the user sees while the daemon
    is coming up. Best-effort — if the splash subprocess can't
    spawn for any reason (no DISPLAY on Linux, broken tkinter, etc.)
    we return None and the launcher just proceeds without the splash.
    The splash watches its stdin pipe; closing the pipe (or this
    process exiting) makes it dismiss itself. No IPC protocol.
    """
    try:
        if getattr(sys, "frozen", False):
            cmd = [sys.executable, "splash"]
        else:
            cmd = [sys.executable, "-m", "one_link.splash"]
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        return subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags if os.name == "nt" else 0,
            close_fds=True,
        )
    except Exception:
        return None


def _close_splash(proc: Optional[subprocess.Popen]) -> None:
    """Dismiss the splash. Closes its stdin so the watcher thread
    inside the splash sees EOF and tears down the tk root cleanly.
    Falls back to terminate() if the close+wait races a hung splash."""
    if proc is None:
        return
    try:
        if proc.stdin is not None:
            try: proc.stdin.close()
            except Exception: pass
        try:
            proc.wait(timeout=2.0)
        except Exception:
            try: proc.terminate()
            except Exception: pass
    except Exception:
        pass


def run_app(
    *,
    no_browser: bool = False,
    standalone: bool = True,
    lan: bool = False,
    supervise: bool = False,
) -> int:
    # Splash window opens IMMEDIATELY — before any subprocess work —
    # so the user sees something the moment they double-click the
    # icon. Suppressed when --no-browser (headless launches, e.g.
    # autostart-at-boot) since there's nobody at the keyboard to
    # look at it. Failures spawning the splash are silently swallowed
    # — the launcher continues either way, the user just loses the
    # splash, no other harm done.
    splash_proc = None if no_browser else _spawn_splash()
    _safe_echo("One Link")
    # v0.15.2: --lan opt-in. Set BEFORE we try to reuse a running
    # daemon so any spawned-fresh daemon inherits the right bind
    # host. If a 127.0.0.1-bound daemon is already running, we'll
    # stop it and replace; the user explicitly asked for LAN mode.
    if lan:
        os.environ["ONE_LINK_BIND_HOST"] = "0.0.0.0"  # nosec B104

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
            _safe_echo("  switching daemon to LAN mode...")
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
        _safe_echo(f"  replacing stale daemon ({running} -> {__version__})...")
        _stop_incompatible_daemon(info)
        info = _wait_for_daemon(timeout=1.0)
        if info is not None and not info.compatible:
            info = None

    if info is None:
        # Spawn-and-wait, with one retry via the error dialog if the
        # daemon doesn't bind in time. The retry path covers the
        # transient cases (port still in TIME_WAIT from a previous
        # daemon, slow disk on first launch, antivirus scanning the
        # exe). Deterministic failures (corrupt install, missing dep)
        # fail both attempts and the user gets a friendly Quit.
        max_attempts = 2
        for attempt in range(1, max_attempts + 1):
            if supervise:
                _safe_echo("  starting daemon under supervisor...")
                spawned = _spawn_supervisor()
            else:
                _safe_echo("  starting daemon...")
                spawned = _spawn_daemon()
            info = _wait_for_daemon()
            if info is not None and info.compatible:
                _safe_echo("  daemon up.")
                break
            _safe_echo("  ! daemon failed to start cleanly")
            try: spawned.terminate()
            except Exception: pass
            spawned = None
            # Don't let the splash sit behind the error dialog.
            _close_splash(splash_proc)
            splash_proc = None
            if no_browser or attempt >= max_attempts:
                # Headless caller (autostart at boot) gets no dialog —
                # they're not at the keyboard to see it. Also bail
                # silently after the last attempt; the error dialog
                # would have shown on the prior attempt.
                return 2
            # Show the friendly retry/quit dialog. ``choice`` is
            # either "retry" (loop again) or "quit" (bail clean).
            from one_link.error_dialog import show_startup_failure
            choice = show_startup_failure(
                reason=(
                    "The background daemon couldn't come up within "
                    "the startup window. That's usually a transient "
                    "thing — another copy already running, a port "
                    "still releasing, or a slow disk on first launch."
                ),
                log_path=data_dir() / "daemon-launch.err.log",
                data_dir=data_dir(),
            )
            if choice != "retry":
                return 2
            # Reopen the splash for the retry attempt so the user
            # sees the same "Starting…" feedback as the first try.
            splash_proc = _spawn_splash()
    else:
        _safe_echo("  using running daemon.")

    url = f"http://127.0.0.1:{info.server_port}/?t={info.token}"
    _safe_echo(f"  open: {url}")
    if not no_browser:
        try:
            _open_browser_url(url, standalone=standalone)
        except Exception as e:
            _safe_echo(f"  (couldn't auto-open browser: {e})")
    # Browser tab is open (or we deliberately skipped it). Dismiss
    # the splash now so the user's eye moves to the chat UI, not the
    # "Starting…" panel sitting on top of it.
    _close_splash(splash_proc)
    splash_proc = None

    if lan:
        lan_ip = _detect_lan_ip()
        if lan_ip == "127.0.0.1":
            _safe_secho(
                "  (could not detect a LAN IP — is Wi-Fi/Ethernet up?)",
                fg="yellow",
            )
        else:
            _print_lan_warning(lan_ip, info.server_port, info.token)

    if spawned is not None:
        # The daemon is fully detached — Windows: spawned through the
        # shell out of the launcher's Job Object; POSIX: setsid() so
        # closing the terminal does not kill it. It will keep running
        # after this launcher process exits, so paired peers stay
        # online and in-flight transfers complete. The launcher's job
        # is done: report status and exit. The UI window (browser /
        # webview) owns its own lifetime now.
        _safe_echo("\n  Daemon is running in the background.")
        _safe_echo("  Your peers stay online even if you close this window.")
        _safe_echo("  To stop the daemon explicitly: `one-link daemon-stop`")
    return 0
