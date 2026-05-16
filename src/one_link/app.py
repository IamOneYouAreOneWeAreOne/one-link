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
    """Spawn the daemon child. Redirects stderr to a known log file
    instead of DEVNULL so the desktop-shortcut launch path (pythonw
    no-console) leaves an inspectable trail when the daemon fails to
    come up. Without this trail the user sees "daemon failed to start
    cleanly" with no diagnostic — every operator support call ends up
    needing the daemon re-launched with `-v` from a terminal just to
    capture the error.

    The log rotates per process (overwritten each launch) so it never
    grows unbounded; the daemon's own logging already handles
    long-term retention via its in-app log files.
    """
    log_path = data_dir() / "daemon-launch.err.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

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
    if os.name == "nt":
        return _spawn_daemon_windows_detached(daemon_cmd, log_path)
    # POSIX: setsid() detaches from the controlling terminal and the
    # daemon survives the launcher exiting. No Job Object on Linux/mac.
    try:
        log_fh = open(log_path, "wb")
    except OSError:
        log_fh = None
    return subprocess.Popen(
        daemon_cmd,
        stdout=subprocess.DEVNULL,
        stderr=(log_fh if log_fh is not None else subprocess.DEVNULL),
        stdin=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )


def _spawn_daemon_windows_detached(
    daemon_cmd: list[str], log_path: Path,
) -> subprocess.Popen:
    """Spawn the daemon truly detached on Windows by going through
    the shell. The launcher cannot kill it; closing the launcher
    window does not kill it; only an explicit `one-link daemon-stop`
    (or the user via Task Manager) will end it.

    Implementation: write the daemon's effective command line to a
    tiny .cmd file and invoke `cmd /c start "" /B`. The `start /B`
    keyword spawns the process WITHOUT inheriting the parent's job.
    """
    import tempfile
    # Quote each arg with the Windows rules — surround with " and
    # double internal "s.
    def _q(s: str) -> str:
        return '"' + s.replace('"', '""') + '"'

    exe_args = " ".join(_q(a) for a in daemon_cmd)
    # Redirect stdout/stderr inside the .cmd so we capture logs.
    redirect = f'>nul 2>"{log_path}"'
    cmd_text = (
        "@echo off\r\n"
        f'start "one-link-daemon" /B {exe_args} {redirect}\r\n'
    )
    # Write to a per-spawn .cmd file in temp so we don't conflict.
    fd, cmd_path = tempfile.mkstemp(prefix="one-link-spawn-", suffix=".cmd")
    try:
        os.write(fd, cmd_text.encode("utf-8"))
    finally:
        os.close(fd)

    # Run the .cmd. cmd.exe exits immediately after `start` returns.
    # The daemon is now an unrelated process tree under conhost.
    try:
        helper = subprocess.Popen(
            ["cmd.exe", "/c", cmd_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                | getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
                | getattr(subprocess, "CREATE_BREAKAWAY_FROM_JOB", 0x01000000)
            ),
            close_fds=True,
        )
        helper.wait(timeout=10)
    except Exception:
        # If the helper itself fails (rare), fall back to a normal
        # Popen — at least we tried.
        pass
    finally:
        try:
            os.unlink(cmd_path)
        except OSError:
            pass

    # The helper has exited; the daemon is now its own untracked
    # process. We return a stub Popen-like object so the caller's
    # `.wait()` path waits on a no-op (the launcher's wait-loop now
    # only exists to keep the console window open, not to track the
    # daemon).
    return _DetachedDaemonHandle()


class _DetachedDaemonHandle:
    """Popen-shaped stub for a fully detached daemon. .wait() blocks
    forever (until the launcher itself is killed); .terminate() is
    a no-op — explicit `one-link daemon-stop` is the supported way
    to end the detached daemon."""

    def wait(self, timeout=None):
        import time as _time
        if timeout is not None:
            _time.sleep(timeout)
            return None
        # Block forever; KeyboardInterrupt is the user's exit signal.
        while True:
            _time.sleep(60)

    def terminate(self):  # pragma: no cover — no-op
        return

    def kill(self):  # pragma: no cover — no-op
        return


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
                # Edge --app= mode on Win11 still reserves a visible
                # strip beneath the title bar. Three things contribute:
                #
                #   1. Win11 "Window Controls Overlay" — Edge reserves
                #      a region for the WCO API even when the page
                #      doesn't draw under it (WindowControlsOverlay,
                #      WebAppWindowControlsOverlay).
                #   2. Edge's sidebar / hubs / Copilot strip
                #      (msEdgeSidebar, msHubsSidebar, msEdgeCopilot,
                #      msEdgeFollow, msEdgeShoppingAssistant).
                #   3. Personalization / signin pill (msImplicitSignIn,
                #      Translate, InterestFeedV2).
                #
                # All disabled below. --app-auto-launched tells Edge
                # this is a launcher, not a browser session, which
                # further trims new-tab / restore UI. --window-name
                # gives Edge an explicit title-bar caption so it
                # doesn't lag waiting on the page title.
                disable_features = ",".join([
                    # Signin / personalization pills. The sovereignty
                    # promise of One Link — no corp accounts, no
                    # tracker — means the embedded runtime MUST NOT
                    # silently sign the user into Microsoft / Google
                    # via the Windows / OS-level account. These flags
                    # disable EVERY codepath that does that on first
                    # window open. May 15 2026 — expanded after a
                    # fresh-profile launch surfaced the "We are now
                    # syncing your browsing data" Microsoft Edge
                    # popup. That popup is Edge's first-run sync
                    # prompt; the flags below kill the codepath that
                    # triggers it.
                    "msImplicitSignIn",
                    "EdgeAccount",
                    "EdgeIdentitySignIn",
                    "EdgeShowAccountAvatar",
                    "IdentityConsistency",
                    "SyncTrustedVaultPassphraseRecovery",
                    "SignedExchangePrefetchCacheForNavigations",
                    "Translate",
                    "TranslateUI",
                    "InterestFeedV2",
                    # Edge sidebar / hubs / Copilot / shopping / follow.
                    "msEdgeSidebar",
                    "msHubsSidebar",
                    "msEdgeCopilot",
                    "msEdgeFollow",
                    "msEdgeShoppingAssistant",
                    "msEdgeAutomaticPasswordSave",
                    "msEdgeWalletInjection",
                    "msSplitButton",
                    # Telemetry / metrics / domain reliability.
                    "MetricsReportingFeature",
                    "DomainReliability",
                    "FieldTrialConfig",
                    "OptimizationHints",
                    # Window-controls-overlay reservation — the big
                    # one on Win11 Edge --app= mode.
                    "WindowControlsOverlay",
                    "WebAppWindowControlsOverlay",
                    # PWA promotion / install bubble.
                    "DesktopPWAsAppHomePage",
                    "DesktopPWAsTabStrip",
                    "PwaUpdateDialogForAppIcon",
                    # Misc residual UI.
                    "DownloadBubble",
                    "ChromeWebuiRefresh2023",
                ])
                # May 16 2026 — sensible default window size + position.
                # User reported "the app opens at half-view." Edge
                # --app= mode otherwise restores the LAST window
                # geometry from the isolated profile dir; on a fresh
                # profile that defaults to a small/awkward size. We
                # compute a window that's 80% of the primary screen
                # (clamped to 1400x900 max so on huge monitors the
                # window doesn't dominate) centered on screen.
                if _is_existing_app_window_running(profile_dir):
                    return
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
                    f"--disable-features={disable_features}",
                    "--disable-sync",
                    "--disable-sync-preferences",
                    "--disable-extensions",
                    "--no-experiments",
                    # May 15 2026 — sovereignty hardening. None of
                    # these turn off rendering; they turn off the
                    # corp-side data flows the embedded Edge/Chrome
                    # tries to start automatically.
                    "--disable-background-networking",
                    "--disable-domain-reliability",
                    "--disable-component-update",
                    "--disable-client-side-phishing-detection",
                    "--disable-default-apps",
                    "--metrics-recording-only",
                    "--no-pings",
                    "--no-service-autorun",
                    "--password-store=basic",
                ]
                flags = (
                    subprocess.CREATE_NO_WINDOW
                    | subprocess.DETACHED_PROCESS
                    if os.name == "nt"
                    else 0
                )
                subprocess.Popen(
                    args,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    creationflags=flags,
                    close_fds=True,
                )
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


def run_app(
    *,
    no_browser: bool = False,
    standalone: bool = True,
    lan: bool = False,
) -> int:
    click.echo("One Link")
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
            _open_browser_url(url, standalone=standalone)
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
        # The daemon is fully detached — Windows: spawned through the
        # shell out of the launcher's Job Object; POSIX: setsid() so
        # closing the terminal does not kill it. It will keep running
        # after this launcher process exits, so paired peers stay
        # online and in-flight transfers complete. The launcher's job
        # is done: report status and exit. The UI window (browser /
        # webview) owns its own lifetime now.
        click.echo("\n  Daemon is running in the background.")
        click.echo("  Your peers stay online even if you close this window.")
        click.echo("  To stop the daemon explicitly: `one-link daemon-stop`")
    return 0
