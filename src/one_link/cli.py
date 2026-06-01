"""one-link CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Optional

import click

from one_link import __version__
from one_link import crash_log
from one_link import daemon as daemon_mod
from one_link.identity import load_or_create
from one_link.safe_http import validated_urlopen


def _flush_stdio() -> None:
    """Best-effort flush of every logging handler + stderr + stdout.

    The launcher redirects the spawned daemon's stdout/stderr to a file
    (block-buffered) and merges stderr into stdout via
    ``stderr=subprocess.STDOUT``. PYTHONUNBUFFERED=1 makes the child
    line-flush on every write, but a final paranoid flush here closes
    the residual window between the last log call and process exit on
    abrupt termination paths.
    """
    try:
        for h in logging.getLogger().handlers:
            try: h.flush()
            except Exception: pass
    except Exception:
        pass
    try: sys.stderr.flush()
    except Exception: pass
    try: sys.stdout.flush()
    except Exception: pass


def _connect_control(timeout: float = 5.0) -> tuple[socket.socket, int]:
    try:
        port = daemon_mod.read_control_port()
    except RuntimeError as e:
        raise click.ClickException(
            f"daemon not running ({e}).\nstart it with:  one-link daemon"
        )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    try:
        s.connect(("127.0.0.1", port))
    except OSError as e:
        raise click.ClickException(
            f"could not reach daemon on 127.0.0.1:{port}: {e}\n"
            f"is the daemon running? try:  one-link daemon"
        )
    s.settimeout(timeout)
    return s, port


def _force_kill_windows_pid(pid: int) -> None:
    """Terminate a stale daemon process on Windows without invoking a shell."""
    if pid <= 0:
        raise ValueError("pid must be positive")
    taskkill = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
    subprocess.run(
        [str(taskkill), "/F", "/PID", str(int(pid))],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=3,
        check=False,
    )


def _request(cmd: str, *, timeout: float = 5.0, **kwargs) -> dict:
    """Single control-socket request/response round trip.

    Retries up to 4 times with exponential backoff (0.1, 0.4, 1.6s)
    on the documented Windows TCP control-socket churn pattern (EOF
    before service, or ConnectionRefusedError when the accept queue
    drains under suite-level subprocess churn). See
    ``tests/test_two_device_soak.py:85`` for the pattern's origin;
    the same retry policy lives in ``tests/harness.py``.
    Real daemon errors still surface as ClickException; only
    transient connection-churn cases retry.
    """
    import time as _time
    last_buf = b""
    backoff_s = (0.1, 0.4, 1.6)
    max_attempts = len(backoff_s) + 1
    last_conn_exc: Exception | None = None
    for attempt in range(max_attempts):
        s, _ = _connect_control(timeout=timeout)
        try:
            try:
                s.sendall(
                    (json.dumps({"cmd": cmd, **kwargs}) + "\n").encode("utf-8"),
                )
                buf = b""
                while not buf.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
            except (ConnectionAbortedError, ConnectionResetError, OSError) as e:
                last_conn_exc = e
                buf = b""
        finally:
            s.close()
        last_buf = buf
        if buf and buf.endswith(b"\n"):
            try:
                return json.loads(buf.decode("utf-8").strip() or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as e:
                raise click.ClickException(
                    f"daemon returned an invalid response while handling {cmd}: {e}"
                )
        if attempt < len(backoff_s):
            _time.sleep(backoff_s[attempt])
    # All attempts exhausted.
    if last_conn_exc is not None and not last_buf:
        raise click.ClickException(
            f"daemon connection dropped while handling {cmd}; "
            "One Link will keep durable transfer work and resume after restart "
            f"({last_conn_exc})"
        )
    try:
        return json.loads(last_buf.decode("utf-8").strip() or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise click.ClickException(
            f"daemon returned an invalid response while handling {cmd}: {e}"
        )


@click.group()
@click.version_option(__version__, prog_name="one-link")
def cli() -> None:
    """One Link — peer-to-peer LAN chat + file sync."""


@cli.command()
@click.option("-v", "--verbose", is_flag=True)
@click.option("--tray/--no-tray", default=True,
              help="Run a system tray icon alongside the daemon (default: on).")
@click.option("--open/--no-open", "open_browser", default=False,
              help="Auto-open the web UI in the default browser after "
                   "the local server is ready (default: off). Set ONE_LINK_AUTO_OPEN=1 to enable.")
def daemon(verbose: bool, tray: bool, open_browser: bool) -> None:
    """Run the One Link daemon (leave this in a terminal/service)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # Plant crash visibility BEFORE any of our threads spin up. An
    # uncaught exception in the tray loader, URL pusher, or auto-open
    # helper would otherwise be eaten by Python's default
    # threading.excepthook (prints to stderr — but stderr is redirected
    # by the launcher and may be block-buffered, so we have lost real
    # crashes here before). crash_log mirrors every uncaught exception
    # to data_dir()/crashes/<utc>-<reason>.txt with a synchronous fsync,
    # so a forensic record survives even an abrupt process exit.
    crash_log.install_excepthooks()
    # Visibility banner — every daemon launch announces whether it is
    # under the supervisor. The supervisor sets
    # ONE_LINK_SUPERVISED=1 on the child env so we can tell
    # post-hoc, from the log alone, which spawn path this run came
    # from. Without this banner a "daemon died silently" log gives no
    # answer to "was it supposed to auto-restart?".
    _supervised = os.environ.get("ONE_LINK_SUPERVISED") == "1"
    logging.getLogger("one_link.daemon").info(
        "daemon launch: pid=%d supervised=%s python=%s",
        os.getpid(),
        "yes" if _supervised else "NO (bare; no auto-restart on crash)",
        sys.version.split()[0],
    )
    # Auto-open is on either via --open OR ONE_LINK_AUTO_OPEN=1 in env
    # (PyInstaller-built GUI binary sets the env var so end users get
    # the browser the moment the daemon binds the local port).
    if not open_browser and os.environ.get("ONE_LINK_AUTO_OPEN") == "1":
        open_browser = True
    # v0.10.5/v0.12.2: optional tray icon. Start it off the critical daemon
    # boot path so slow Windows/Pillow/pystray initialization cannot delay
    # discovery, the control socket, or the local web UI coming online.
    # ``Any`` so the threaded tray loader can park the TrayIcon
    # without forcing the top-level cli module to import the
    # pystray-pulling tray module at decl time.
    tray_icon_holder: dict[str, Any] = {"icon": None}

    def _start_tray_icon() -> None:
        try:
            from one_link.tray import TrayIcon
            from one_link.paths import inbox_dir
            tray_icon = TrayIcon(
                on_quit=lambda: os.kill(os.getpid(), signal.SIGINT),
                inbox_path=inbox_dir(),
            )
            tray_icon_holder["icon"] = tray_icon
            if tray_icon.available:
                tray_icon.start()
                if tray_icon.available:
                    logging.getLogger("one_link.tray").info(
                        "tray icon active. Right-click for menu; click to open UI."
                    )
                else:
                    logging.getLogger("one_link.tray").info(
                        "tray icon unavailable; daemon is running without tray controls."
                    )
        except Exception as e:
            logging.getLogger("one_link.tray").info(
                "tray init skipped: %s", e,
            )

    if tray:
        threading.Thread(
            target=_start_tray_icon,
            daemon=True,
            name="one-link-tray-loader",
        ).start()

    # 2026-05-22 UX: once the daemon binds, push the actual URL
    # (with LAN IP, not loopback) into the tray so the hover-title
    # tells the user where their phone should connect.
    def _push_tray_url_when_ready() -> None:
        import time as _t
        import socket as _sk
        from one_link.paths import data_dir as _data_dir
        # Poll for server.port to appear, up to 10 s.
        deadline = _t.time() + 10.0
        port = None
        port_file = _data_dir() / "server.port"
        while _t.time() < deadline:
            try:
                if port_file.exists():
                    port = int(port_file.read_text(encoding="utf-8").strip())
                    break
            except Exception:
                pass
            _t.sleep(0.1)
        if port is None:
            return
        # Detect a LAN IP if the daemon is LAN-bound.
        lan = "127.0.0.1"
        try:
            s = _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM)
            s.connect(("8.8.8.8", 1))
            lan = s.getsockname()[0]
            s.close()
        except Exception:
            pass
        token = ""
        try:
            token = (_data_dir() / "ui.token").read_text(encoding="utf-8").strip()
        except Exception:
            pass
        url = f"http://{lan}:{port}/" + (f"?t={token}" if token else "")
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try:
                tray_icon.set_url(url)
            except Exception:
                pass

    threading.Thread(
        target=_push_tray_url_when_ready,
        daemon=True,
        name="one-link-tray-url-pusher",
    ).start()

    if open_browser:
        # Open the UI ~2.5 s after daemon boot starts. Long enough for
        # the local HTTP server to bind, short enough that the user
        # doesn't wait. The UI itself handles "daemon not ready yet"
        # with a small splash that auto-retries.
        def _open_when_ready() -> None:
            import time as _t
            import webbrowser as _wb
            from one_link.paths import data_dir as _data_dir
            _t.sleep(2.5)
            # Read the auth-gated UI port + token. Opening the bare
            # URL can strand the user on "sign-in needed" after a
            # restart; the bootstrap token is the supported owner path.
            port_file = _data_dir() / "server.port"
            token_file = _data_dir() / "ui.token"
            url = "http://127.0.0.1:7117/"
            try:
                if port_file.exists():
                    port = int(port_file.read_text(encoding="utf-8").strip())
                    token = token_file.read_text(encoding="utf-8").strip() if token_file.exists() else ""
                    url = f"http://127.0.0.1:{port}/" + (f"?t={token}" if token else "")
            except Exception:
                pass
            try:
                _wb.open(url)
                logging.getLogger("one_link.cli").info("opened browser at %s", url)
            except Exception as e:
                logging.getLogger("one_link.cli").info(
                    "could not auto-open browser: %s; visit the URL manually", e,
                )

        threading.Thread(
            target=_open_when_ready,
            daemon=True,
            name="one-link-open-browser",
        ).start()

    try:
        asyncio.run(daemon_mod.run())
    except RuntimeError as e:
        if "already running" in str(e):
            raise click.ClickException(str(e))
        # Anything else fell out of run() — fall through to the broad
        # crash-dump branch below so the operator gets a traceback file.
        logging.getLogger("one_link.daemon").critical(
            "daemon exited with uncaught RuntimeError", exc_info=True,
        )
        crash_log.dump_crash("daemon-uncaught", e)
        _flush_stdio()
        raise
    except (KeyboardInterrupt, SystemExit):
        # Clean operator-initiated exit — do not dump a crash report.
        raise
    except BaseException as e:  # noqa: BLE001 — last-chance catcher
        # Every uncaught exception that reaches here is, by definition,
        # the daemon dying. Log the full traceback via the logging
        # system (reaches daemon-launch.err.log) AND mirror to a
        # forensic crash file (survives stderr-buffer loss). Then flush
        # everything we can before re-raising.
        logging.getLogger("one_link.daemon").critical(
            "daemon exited with uncaught exception", exc_info=True,
        )
        crash_log.dump_crash("daemon-uncaught", e)
        _flush_stdio()
        raise
    finally:
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try: tray_icon.stop()
            except Exception: pass
        _flush_stdio()


@cli.command()
@click.option(
    "--max-crashes",
    default=5,
    show_default=True,
    type=click.IntRange(1, 100),
    help="Trip the supervisor's circuit breaker after this many "
         "crashes in --window-s seconds. A deterministic crash loop "
         "needs human attention, not infinite respawn.",
)
@click.option(
    "--window-s",
    default=60.0,
    show_default=True,
    type=click.FloatRange(1.0, 3600.0),
    help="Circuit-breaker rolling window in seconds.",
)
def supervisor(max_crashes: int, window_s: float) -> None:
    """Run the daemon under a watchdog that auto-restarts on crash.

    Spawns ``one-link daemon`` as a child, waits for exit, and on
    non-zero exit restarts with exponential backoff. Trips on too many
    crashes in the configured window so a broken build cannot
    spin-restart indefinitely. SIGINT/SIGTERM cleanly shuts the child
    down and exits without restart.
    """
    from one_link import supervisor as supervisor_mod

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    crash_log.install_excepthooks()
    rc = supervisor_mod.run(max_crashes=max_crashes, window_s=window_s)
    _flush_stdio()
    raise SystemExit(rc)


@cli.group()
def autostart():
    """Register / unregister One Link to start at user login.

    User-mode integration (no admin/root needed). Survives reboots,
    log-off, sleep + hibernate that the in-process supervisor cannot.
    Windows uses the HKCU Run key; macOS uses a LaunchAgent plist;
    Linux uses an XDG autostart .desktop entry.
    """


@autostart.command("status")
def autostart_status() -> None:
    """Print whether One Link is registered to start at login."""
    from one_link import autostart as autostart_mod
    enabled = autostart_mod.is_enabled()
    path = autostart_mod.artifact_path()
    click.echo("autostart: " + ("ENABLED" if enabled else "disabled"))
    if path is not None:
        click.echo(f"artifact:  {path}")
    click.echo("command:   " + " ".join(autostart_mod._launch_command()))


@autostart.command("enable")
def autostart_enable() -> None:
    """Register One Link to start at the next user login.

    Idempotent — calling again rewrites the artifact with the current
    launcher path (so upgrading the binary picks up the new path
    automatically when you re-enable)."""
    from one_link import autostart as autostart_mod
    path = autostart_mod.enable()
    click.echo(f"autostart enabled. Wrote: {path}")
    click.echo("One Link will start at your next login under the supervisor.")


@autostart.command("disable")
def autostart_disable() -> None:
    """Remove the auto-start registration."""
    from one_link import autostart as autostart_mod
    removed = autostart_mod.disable()
    if removed:
        click.echo("autostart disabled.")
    else:
        click.echo("autostart was not enabled — nothing to remove.")


@cli.command()
def whoami():
    """Show this device's identity."""
    me = load_or_create()
    click.echo(f"hostname:    {me.hostname}")
    click.echo(f"short_id:    {me.short_id}")
    click.echo(f"fingerprint: {me.fingerprint}")


@cli.group()
def backup():
    """Manage your 24-word recovery phrase.

    The phrase is your sovereign backup: write it down on paper,
    keep the paper somewhere safe. If you lose the device, type
    the phrase on a new install and your identity + at-rest
    data unlock — peers continue to recognize you.

    The phrase is NEVER transmitted off-device, NEVER synced to
    any cloud, NEVER stored in any third-party service. It exists
    only on your paper backup + the daemon's encrypted local state.
    """


@backup.command("show")
def backup_show():
    """Print the 24-word recovery phrase. Write it down on paper."""
    from one_link import master_seed, mnemonic
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` to create one (seed + identity\n"
            "will rotate; existing peers will see this as a key change).",
            err=True,
        )
        raise click.exceptions.Exit(1)
    phrase = mnemonic.encode(seed)
    click.echo("=" * 64)
    click.echo("WRITE THESE 24 WORDS DOWN ON PAPER. KEEP THE PAPER SAFE.")
    click.echo("This is the ONLY way to recover your One Link identity")
    click.echo("if you lose this device.")
    click.echo("=" * 64)
    words = phrase.split()
    for row in range(0, len(words), 4):
        line_words = words[row:row + 4]
        numbered = [f"{i+row+1:>2}. {w:<10}" for i, w in enumerate(line_words)]
        click.echo("  ".join(numbered))
    click.echo("=" * 64)
    click.echo("Anyone with these 24 words can take over your identity.")
    click.echo("Treat them like a physical bank PIN: paper-only, never typed")
    click.echo("into a website, never photographed, never sent to anyone.")
    click.echo("=" * 64)


@backup.command("init")
@click.option(
    "--force", is_flag=True,
    help="Rotate identity even if existing keys are in use.",
)
def backup_init(force):
    """Create a recoverable master seed for this install.

    Use this on an existing One Link install (which already has
    randomly-generated, non-recoverable keys) to switch to a
    seed-backed setup. After running this, your old identity is
    replaced — peers will see you as a "new" device with a
    different fingerprint and you'll need to re-pair with them.

    On a fresh install (no existing identity.key), the daemon
    auto-creates a seed on first launch. This command is for
    EXISTING installs that want to opt into recovery.
    """
    from one_link import master_seed
    from one_link.paths import data_dir, key_path
    if master_seed.has_seed(data_dir()):
        click.echo(
            "A master seed already exists. Run `one-link backup show`\n"
            "to view its 24-word phrase. To rotate the seed (and thus\n"
            "the identity), delete the seed file at\n"
            f"  {data_dir() / master_seed.SEED_FILENAME}\n"
            "and re-run this command.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if key_path().is_file() and not force:
        click.echo(
            "An existing identity key is in use. Initializing a master\n"
            "seed at this point will REPLACE that identity (peers will\n"
            "see you as a different device after the swap).\n"
            "Re-run with --force to confirm rotation.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    # If --force was passed and an identity exists: delete the old
    # identity so the daemon will derive a fresh one from the seed.
    if key_path().is_file() and force:
        try:
            key_path().unlink()
        except OSError as e:
            click.echo(f"Could not remove old identity: {e}", err=True)
            raise click.exceptions.Exit(1)
        # Also drop the DRK so it gets re-derived from the seed.
        from one_link.lockbox import DRK_FILENAME
        drk_path = data_dir() / DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            drk_path.unlink()
    seed, _ = master_seed.load_or_create_seed(data_dir())
    click.echo(
        "Master seed created. Run `one-link backup show` and write\n"
        "down the 24 words on paper. Then start the daemon — it will\n"
        "derive a fresh identity + at-rest key from the seed."
    )


@backup.command("restore")
@click.argument("phrase_words", nargs=-1)
@click.option(
    "--force", is_flag=True,
    help="Overwrite existing identity even if one is present.",
)
def backup_restore(phrase_words, force):
    """Restore identity from a 24-word recovery phrase.

    Use on a NEW device that you want to be the same identity as
    your old (lost) device. Type the 24 words separated by spaces:

        one-link backup restore word1 word2 ... word24

    Or paste them when prompted (no arguments).

    Refuses to run if an identity already exists, unless --force.
    The seed file is created from the phrase; on next daemon
    launch the identity + DRK derive from it.
    """
    from one_link import master_seed, mnemonic
    from one_link.paths import data_dir, key_path
    if master_seed.has_seed(data_dir()) and not force:
        click.echo(
            "A master seed already exists on this install. To replace\n"
            "it with a restored seed, re-run with --force.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if key_path().is_file() and not force:
        click.echo(
            "An existing identity key is in use. Restoring will\n"
            "REPLACE that identity. Re-run with --force to confirm.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt(
            "phrase", hide_input=True, prompt_suffix="> ",
        )
    else:
        raw = " ".join(phrase_words)
    try:
        seed = mnemonic.decode(raw)
    except ValueError as e:
        click.echo(f"Invalid phrase: {e}", err=True)
        raise click.exceptions.Exit(1)
    # Force-mode: clear out the old identity + DRK so they
    # re-derive from the restored seed on next launch.
    if force:
        with __import__("contextlib").suppress(OSError):
            key_path().unlink()
        from one_link.lockbox import DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            (data_dir() / DRK_FILENAME).unlink()
    master_seed.store_seed(data_dir(), seed)
    click.echo(
        "Master seed restored. Start the daemon — it will derive\n"
        "your identity + at-rest key from the restored seed.\n"
        "Peers paired with the original device will recognize you."
    )


@backup.command("test")
@click.argument("phrase_words", nargs=-1)
def backup_test(phrase_words):
    """Check whether a paper phrase matches the on-disk identity.

    Decodes the 24-word BIP-39 phrase and compares it (in constant
    time) to the master seed on this install. Writes nothing.

    Use BEFORE running `backup restore` to confirm you wrote the
    phrase down correctly. Useful as a periodic audit: every few
    months, type the phrase from your paper backup and confirm it
    still produces a green check.

    Exit codes mirror the UI's three colors:
      0 = green   (phrase matches the current identity)
      2 = amber   (valid phrase, no current identity OR different identity)
      1 = red     (phrase failed to decode)
    """
    from one_link import recovery_api
    from one_link.paths import data_dir
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt("phrase", hide_input=True, prompt_suffix="> ")
    else:
        raw = " ".join(phrase_words)
    res = recovery_api.test_phrase_against_current_seed(
        data_dir=data_dir(), phrase=raw,
    )
    if not res["valid_checksum"]:
        click.echo(f"INVALID PHRASE: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    if not res["has_current_identity"]:
        click.echo(
            "Valid 24-word phrase, but this device has no master seed "
            "to compare against."
        )
        raise click.exceptions.Exit(2)
    if res["matches_current_identity"]:
        click.echo("VERIFIED: this phrase matches your current identity.")
        return
    click.echo(
        "Valid 24-word phrase, but it does NOT match your current "
        "identity. This is a phrase for a different install.",
        err=True,
    )
    raise click.exceptions.Exit(2)


@backup.command("test-bundle")
@click.argument(
    "bundle_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.argument("phrase_words", nargs=-1)
def backup_test_bundle(bundle_path, phrase_words):
    """Check whether a .olbak file decrypts with a 24-word phrase.

    AEAD-decrypts the bundle in memory and reports the bundle's
    header timestamp + plaintext file count. Writes nothing to disk;
    the existing identity on this install is not touched.

    Use BEFORE running `backup import` to confirm the bundle + phrase
    pair is valid (e.g., after restoring a backup file from cold
    storage you haven't touched in months).

    Exit codes:
      0 = bundle decrypted + plaintext archive readable
      1 = phrase invalid OR bundle failed to decrypt
    """
    from one_link import recovery_api
    bundle_bytes = Path(bundle_path).read_bytes()
    if not phrase_words:
        click.echo(
            "Type the 24 words separated by spaces, then press Enter.\n"
            "(Hidden input; the phrase will not be echoed.)"
        )
        raw = click.prompt("phrase", hide_input=True, prompt_suffix="> ")
    else:
        raw = " ".join(phrase_words)
    res = recovery_api.test_bundle_against_phrase(
        phrase=raw, bundle_bytes=bundle_bytes,
    )
    if not res["valid_phrase"]:
        click.echo(f"INVALID PHRASE: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    if not res["valid_bundle"]:
        click.echo(f"BUNDLE DECRYPT FAILED: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    created = res.get("bundle_created_ms", 0)
    files = res.get("file_count", 0)
    click.echo(
        f"VERIFIED: bundle decrypts cleanly with this phrase.\n"
        f"  created_ms: {created}\n"
        f"  file_count: {files}"
    )


@backup.command("export")
@click.argument("out_path", type=click.Path(dir_okay=False, path_type=Path))
@click.option(
    "--include-files", is_flag=True,
    help=(
        "Also include everything under inbox/. Inboxes can be GB-sized; "
        "default is to bundle only the load-bearing state (sqlite + keys + "
        "settings). Identity, chat history, groups, and folder configs are "
        "ALWAYS included regardless of this flag."
    ),
)
def backup_export(out_path, include_files):
    """Write an encrypted backup bundle to OUT_PATH (a .olbak file).

    The bundle is sealed with a key derived from your master seed
    (the same seed your 24-word phrase encodes). It can ONLY be
    decrypted by an install that knows the seed: either this same
    daemon, or a fresh install where you've typed the 24 words via
    `one-link backup restore`.

    Without the seed the bundle is ciphertext indistinguishable
    from random. Drop it on a USB stick, upload to any cloud, mail
    it to yourself — without the 24 words it's unintelligible.

    Refuses to run if no master seed has been provisioned (run
    `one-link backup init` first to create one).
    """
    from one_link import backup_bundle, master_seed
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed has been provisioned for this install.\n"
            "Run `one-link backup init` first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    out_path = out_path.expanduser().resolve()
    if out_path.exists():
        click.echo(
            f"Refusing to overwrite existing file: {out_path}\n"
            "Pick a different path, or remove it first.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    try:
        n = backup_bundle.create_bundle_to_file(
            seed=seed,
            data_dir=data_dir(),
            out_path=out_path,
            include_files=include_files,
        )
    except (OSError, ValueError) as e:
        raise click.ClickException(f"export failed: {e}")
    click.echo(f"wrote {n} bytes -> {out_path}")
    click.echo(
        "This file is encrypted under your master seed. To restore it on a\n"
        "new device, copy it there + run `one-link backup import <path>`\n"
        "AFTER you've restored the 24-word phrase on that device."
    )


@backup.command("import")
@click.argument("bundle_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "--overwrite", is_flag=True,
    help="Replace files at the target if they already exist.",
)
@click.option(
    "--target-dir", type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Override the install's data dir (advanced; default is correct).",
)
def backup_import(bundle_path, overwrite, target_dir):
    """Decrypt and unpack a .olbak bundle into this install's data dir.

    Requires a master seed already provisioned on this install (via
    `one-link backup restore <24 words>`). The seed must match the
    one that sealed the bundle, or decryption fails.

    Default behavior refuses to clobber existing files in the
    target dir. Pass --overwrite to allow replacement (this is
    destructive: existing chat history etc. will be overwritten).
    """
    from one_link import backup_bundle, master_seed
    from one_link.paths import data_dir
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        click.echo(
            "No master seed on this install. Run\n"
            "  one-link backup restore <word1> <word2> ... <word24>\n"
            "first, using the 24-word phrase from the device this bundle came from.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    target = Path(target_dir).expanduser().resolve() if target_dir else data_dir()
    try:
        header, written = backup_bundle.restore_bundle_from_file(
            seed=seed,
            bundle_path=Path(bundle_path).expanduser().resolve(),
            target_dir=target,
            overwrite=overwrite,
        )
    except FileExistsError as e:
        click.echo(
            f"Refusing to overwrite existing file: {e}\n"
            "Re-run with --overwrite to replace, or pick a clean --target-dir.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    except ValueError as e:
        # Wrong seed, tampered file, bad magic, traversal attempt, etc.
        raise click.ClickException(f"import failed: {e}")
    except OSError as e:
        raise click.ClickException(f"import failed: {e}")
    click.echo(f"restored {len(written)} file(s) into {target}")
    if written:
        for name in written[:20]:
            click.echo(f"  - {name}")
        if len(written) > 20:
            click.echo(f"  ... and {len(written) - 20} more")
    click.echo(
        "Restart the daemon (or `one-link daemon`) so the new state is\n"
        "loaded into memory."
    )


@cli.group()
def recovery():
    """Social recovery — your social graph IS your backup layer.

    Instead of keeping a 24-word phrase on paper (and hoping it's
    not lost / read by a thief / destroyed in a fire), split your
    master seed into 5 Shamir shares and hand each to a different
    trusted contact. ANY 3 of the 5 reconstruct your identity on a
    new device. Up to 2 contacts can be malicious or coerced and
    still gain nothing — Shamir's information-theoretic threshold
    holds.

    Trust model: you trust that 3 of your 5 chosen contacts won't
    all collude against you. Different from custodial recovery
    (Apple iCloud, Google account) where ONE entity holds every-
    thing; here no platform — and no single person — can lock you
    out of your own identity.

    Workflow:

      one-link recovery setup <name1> <ed_pub_hex_1> ... <name5> <ed_pub_hex_5>
        Mints 5 wrapped shares + writes each to ./shares/<name>.olshare
        ready to deliver to the named contact (USB stick, in-person
        QR, encrypted email, channel message — the medium is up to
        you, the wrap is sealed).

      one-link recovery unwrap <share_path>
        For a CONTACT who has received a share addressed to them:
        decrypt it with this device's identity and print the share
        bytes (also as a QR-friendly base64 string ready to scan
        back to the recovering user).

      one-link recovery restore <share_blob_1> ... <share_blob_K>
        On a fresh device: reconstruct the master seed from K
        decrypted shares (each is the base64 the unwrap step
        emitted) and persist it. On next daemon start, identity +
        DRK + everything else derives from the recovered seed.
    """


@recovery.command("setup")
@click.argument("guardians", nargs=-1)
@click.option(
    "--threshold", "threshold_k", default=3, type=int,
    help="K in K-of-N (default 3)",
)
@click.option(
    "--out-dir", type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Where to write the wrapped shares (default ./shares/).",
)
def recovery_setup(
    guardians: tuple[str, ...],
    threshold_k: int,
    out_dir: Optional[Path],
) -> None:
    """Split this device's master seed into wrapped shares.

    GUARDIANS is a flat list of (name ed_pub_hex) pairs:

        one-link recovery setup \\
            mom    a1b2c3...64hex \\
            dad    11223344...64hex \\
            sister deadbeef...64hex \\
            old-laptop  abcdef...64hex \\
            backup-yubikey 99887766...64hex
    """
    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir
    if len(guardians) % 2 != 0 or len(guardians) < 4:
        raise click.ClickException(
            "GUARDIANS must be (name pub_hex) pairs; need at least 2 guardians.\n"
            "Example: one-link recovery setup mom abc... dad def... sister 123..."
        )
    parsed: list[tuple[str, bytes]] = []
    for i in range(0, len(guardians), 2):
        name = guardians[i]
        try:
            pub = bytes.fromhex(guardians[i + 1])
        except ValueError:
            raise click.ClickException(
                f"guardian {name!r}: pub_hex is not valid hex"
            )
        if len(pub) != 32:
            raise click.ClickException(
                f"guardian {name!r}: pub_hex must be 32 bytes (64 hex chars), "
                f"got {len(pub)} bytes"
            )
        parsed.append((name, pub))
    total_n = len(parsed)
    if not (2 <= threshold_k <= total_n):
        raise click.ClickException(
            f"--threshold must be 2 ≤ K ≤ N (got K={threshold_k}, N={total_n})"
        )
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        raise click.ClickException(
            "No master seed on this install. Run `one-link backup init` "
            "first to provision one (or `one-link backup restore <24 words>` "
            "to recover an existing identity)."
        )
    shares = social_recovery.setup_social_recovery(
        seed=seed, guardians=parsed, threshold_k=threshold_k,
    )
    target_dir = (
        Path(out_dir).expanduser().resolve() if out_dir
        else Path("./shares").expanduser().resolve()
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    for name, share in shares:
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        out = target_dir / f"{safe_name}.olshare"
        out.write_bytes(share.encoded)
    click.echo(
        f"wrote {len(shares)} shares ({threshold_k}-of-{total_n}) -> {target_dir}\n"
        f"deliver each .olshare file to the named guardian. Any {threshold_k} "
        f"of the {total_n} reconstruct your seed."
    )


@recovery.command("unwrap")
@click.argument(
    "share_path", type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
def recovery_unwrap(share_path):
    """Decrypt a share addressed to this device.

    Run as a guardian who has received a .olshare file from someone
    asking you to be a recovery contact. Prints the decrypted share
    bytes (hex) and a QR-friendly base64 form. The recovering
    person will paste / scan that base64 along with K-1 others.
    """
    import base64

    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir, key_path
    seed = master_seed.load_seed(data_dir())
    if seed is None:
        # Fall back to the raw identity key — older daemons without a
        # master seed still have an Ed25519 priv on disk.
        if not key_path().is_file():
            raise click.ClickException(
                "no master seed AND no identity.key — this device has no "
                "private key to unwrap a share with"
            )
        # Best-effort load of the raw priv seed from PEM. Same env
        # var as the daemon's normal identity-load path so an
        # operator with a passphrase-protected key on disk can
        # decrypt for recovery without supplying it twice.
        from cryptography.hazmat.primitives import serialization
        from one_link.identity import PASSPHRASE_ENV
        pw_env = os.environ.get(PASSPHRASE_ENV)
        pw = pw_env.encode("utf-8") if pw_env else None
        try:
            priv_obj = serialization.load_pem_private_key(
                key_path().read_bytes(), password=pw,
            )
        except Exception as e:
            raise click.ClickException(f"identity key load failed: {e}")
        # Only Ed25519 keys carry a raw seed; identity.key on disk is
        # always Ed25519 (we minted it that way), so narrow.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        if not isinstance(priv_obj, Ed25519PrivateKey):
            raise click.ClickException(
                "identity key on disk is not Ed25519 — cannot recover."
            )
        ed_seed = priv_obj.private_bytes_raw()
    else:
        ed_seed = master_seed.derive_identity_priv(seed).private_bytes_raw()

    blob = Path(share_path).read_bytes()
    try:
        idx, share_bytes = social_recovery.unwrap_share(
            wrapped=blob, my_ed_priv_seed=ed_seed,
        )
    except ValueError as e:
        raise click.ClickException(f"unwrap failed: {e}")
    parsed = social_recovery.WrappedShare.parse(blob)
    click.echo(
        f"share index:  {idx}\n"
        f"threshold:    {parsed.threshold}-of-{parsed.total}\n"
        f"setup_ms:     {parsed.setup_ms}\n"
    )
    # Encode as base64 for in-person paste / QR.
    payload = bytes([idx]) + share_bytes
    portable = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    click.echo(
        "Send this single string to the person recovering. They will\n"
        "combine it with shares from K-1 other contacts to reconstruct\n"
        "their identity. Treat it as sensitive: anyone holding K shares\n"
        "can take over the original device's identity.\n"
    )
    click.echo(portable)


@recovery.command("restore")
@click.argument("portable_shares", nargs=-1)
@click.option(
    "--force", is_flag=True,
    help="Overwrite an existing master seed on this device.",
)
def recovery_restore(portable_shares: tuple[str, ...], force: bool) -> None:
    """Reconstruct the master seed from K guardian shares.

    PORTABLE_SHARES is the list of base64 strings collected from the
    `recovery unwrap` step on each of K guardian devices.
    """
    import base64

    from one_link import master_seed, social_recovery
    from one_link.paths import data_dir, key_path
    if len(portable_shares) < 2:
        raise click.ClickException(
            "need at least 2 portable shares (from `recovery unwrap` on "
            "each guardian device)"
        )
    if master_seed.has_seed(data_dir()) and not force:
        click.echo(
            "A master seed already exists on this install. Re-run with\n"
            "--force to replace it. The existing identity will be REPLACED.",
            err=True,
        )
        raise click.exceptions.Exit(1)
    decrypted: list[tuple[int, bytes]] = []
    for s in portable_shares:
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            payload = base64.urlsafe_b64decode((s + pad).encode("ascii"))
        except Exception as e:
            raise click.ClickException(f"share {s[:8]}…: not valid base64 ({e})")
        if len(payload) < 2:
            raise click.ClickException(f"share {s[:8]}…: too short")
        idx = payload[0]
        share_bytes = payload[1:]
        decrypted.append((idx, share_bytes))
    try:
        seed = social_recovery.reconstruct_from_decrypted_shares(decrypted)
    except ValueError as e:
        raise click.ClickException(f"reconstruct failed: {e}")
    if force:
        with __import__("contextlib").suppress(OSError):
            key_path().unlink()
        from one_link.lockbox import DRK_FILENAME
        with __import__("contextlib").suppress(OSError):
            (data_dir() / DRK_FILENAME).unlink()
    master_seed.store_seed(data_dir(), seed)
    click.echo(
        "master seed reconstructed + persisted. Start the daemon — it\n"
        "will derive your identity + at-rest key from the recovered seed.\n"
        "Peers paired with the original device will recognize you."
    )


@recovery.command("test-shares")
@click.argument("portable_shares", nargs=-1)
def recovery_test_shares(portable_shares: tuple[str, ...]) -> None:
    """Check whether K guardian shares still reconstruct your identity.

    Non-destructive verification: combines the supplied portable
    shares in memory and compares the reconstructed seed against the
    on-disk master.seed in constant time. Writes nothing. The current
    identity on this device is not touched.

    Use as a periodic recovery audit: every few months, ask K
    guardians to send you their `recovery unwrap` output, paste them
    here, and confirm a green check. Catches guardians who lost their
    share BEFORE you actually need to recover.

    PORTABLE_SHARES are the base64 strings produced by
    `one-link recovery unwrap` on each guardian device (the same
    format `recovery restore` accepts).

    Exit codes mirror the UI's three colors:
      0 = green   (shares reconstruct your current identity)
      2 = amber   (valid quorum, no current identity OR different identity)
      1 = red     (shares failed to combine / not enough shares)
    """
    import base64

    from one_link import recovery_api
    from one_link.paths import data_dir
    if len(portable_shares) < 2:
        raise click.ClickException(
            "need at least 2 portable shares (from `recovery unwrap` on "
            "each guardian device)"
        )
    decrypted: list[tuple[int, bytes]] = []
    for s in portable_shares:
        try:
            pad = "=" * ((4 - len(s) % 4) % 4)
            payload = base64.urlsafe_b64decode((s + pad).encode("ascii"))
        except Exception as e:
            raise click.ClickException(f"share {s[:8]}...: not valid base64 ({e})")
        if len(payload) < 2:
            raise click.ClickException(f"share {s[:8]}...: too short")
        idx = payload[0]
        share_bytes = payload[1:]
        decrypted.append((idx, share_bytes))
    res = recovery_api.test_shares_against_current_seed(
        data_dir=data_dir(), shares=decrypted,
    )
    if not res["valid_recovery"]:
        click.echo(f"COMBINE FAILED: {res['error']}", err=True)
        raise click.exceptions.Exit(1)
    n = res["share_count"]
    if not res["has_current_identity"]:
        click.echo(
            f"Valid quorum ({n} shares), but this device has no master "
            "seed to compare against."
        )
        raise click.exceptions.Exit(2)
    if res["matches_current_identity"]:
        click.echo(
            f"VERIFIED: these {n} shares reconstruct your current identity."
        )
        return
    click.echo(
        f"Valid quorum ({n} shares), but it reconstructs a DIFFERENT "
        "identity. These shares are from someone else's recovery setup.",
        err=True,
    )
    raise click.exceptions.Exit(2)


@cli.command("native-status")
def native_status():
    """Show whether the native transfer accelerator is active."""
    from one_link.native_cdc import native_cdc_status

    st = native_cdc_status()
    click.echo(f"native_cdc: {'yes' if st.available else 'no'}")
    click.echo(f"engine:     {st.engine}")
    if st.library:
        click.echo(f"library:    {st.library}")
    if st.reason:
        click.echo(f"reason:     {st.reason}")


@cli.command("verify-this-install")
@click.option(
    "--json", "as_json", is_flag=True,
    help="Emit machine-readable JSON instead of human text.",
)
def verify_this_install(as_json):
    """Show + verify the load-bearing identity of this install.

    Prints the version, package root, a BLAKE3 content hash of every
    load-bearing source file, and a hash-of-hashes that matches the
    figure published in the release notes. Lets a user (or auditor)
    confirm that the binary + source files have not been tampered
    with since the signed release.

    The hash-of-hashes is also visible via `/api/me` so a Web-UI
    user can compare against the value here without leaving the
    browser. A mismatch means either (a) you patched the install
    locally (fine, just remember you did) or (b) someone else
    modified the files on disk (investigate).

    For Sigstore verification of the released artifact:

        cosign verify-blob \\
          --certificate-identity-regexp '.*' \\
          --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\
          --bundle one-link.exe.sigstore \\
          one-link.exe

    The verify-blob command + the publisher identity REGEX are
    documented in docs/RELEASE_CHECKLIST.md.
    """
    import hashlib
    import json as _json
    import sys as _sys

    from one_link import __version__
    from one_link.build_identity import _FINGERPRINT_FILES, package_root

    root = package_root()
    file_hashes: dict[str, str] = {}
    missing: list[str] = []
    rollup = hashlib.blake2s(digest_size=16)
    for rel in _FINGERPRINT_FILES:
        path = root / rel
        if not path.is_file():
            file_hashes[rel] = "MISSING"
            missing.append(rel)
            rollup.update(rel.encode("utf-8") + b":MISSING\n")
            continue
        h = hashlib.blake2s(digest_size=16)
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        digest = h.hexdigest()
        file_hashes[rel] = digest
        rollup.update(rel.encode("utf-8") + b":" + digest.encode("ascii") + b"\n")

    frozen_binary: Optional[str] = None
    if getattr(_sys, "frozen", False) and hasattr(_sys, "executable"):
        bin_path = Path(_sys.executable)
        if bin_path.is_file():
            bh = hashlib.blake2s(digest_size=32)
            with bin_path.open("rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    bh.update(chunk)
            frozen_binary = bh.hexdigest()

    out = {
        "version": __version__,
        "package_root": str(root),
        "files": file_hashes,
        "missing": missing,
        "rollup_blake2s_128": rollup.hexdigest(),
        "frozen_binary_blake2s_256": frozen_binary,
    }

    if as_json:
        click.echo(_json.dumps(out, indent=2, sort_keys=True))
        return

    click.echo(f"One Link version:   {__version__}")
    click.echo(f"Package root:       {root}")
    click.echo("")
    click.echo("Load-bearing source files (BLAKE2s-128 content hash):")
    name_w = max(len(n) for n in file_hashes)
    for name, h in sorted(file_hashes.items()):
        click.echo(f"  {name:<{name_w}}  {h}")
    if missing:
        click.echo("")
        click.echo(
            "WARNING: some load-bearing files are missing on disk.",
            err=True,
        )
        for m in missing:
            click.echo(f"  - {m}", err=True)
        click.echo(
            "This usually means the install is incomplete or "
            "tampered. Re-install from a verified source.",
            err=True,
        )
    click.echo("")
    click.echo(f"Rollup (compare with release notes): {rollup.hexdigest()}")
    if frozen_binary:
        click.echo(f"Frozen binary BLAKE2s-256:           {frozen_binary}")
        click.echo("")
        click.echo("To verify this binary against the published Sigstore bundle:")
        click.echo("  cosign verify-blob \\")
        click.echo("    --certificate-identity-regexp '.*' \\")
        click.echo(
            "    --certificate-oidc-issuer "
            "'https://token.actions.githubusercontent.com' \\"
        )
        click.echo(
            f"    --bundle {Path(_sys.executable).name}.sigstore \\"
        )
        click.echo(f"    {Path(_sys.executable).name}")
    else:
        click.echo("(running from source; no frozen-binary hash to report)")


@cli.command()
def peers():
    """List discovered peers on the LAN."""
    res = _request("peers")
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "unknown error"))
    me = res["me"]
    click.echo(f"me: {me['short_id']}  {me['hostname']}")
    plist = res["peers"]
    if not plist:
        click.echo("(no peers discovered yet — give it a few seconds)")
        return
    click.echo("")
    click.echo(f"{'short_id':10} {'hostname':24} {'address':18} port")
    click.echo("-" * 60)
    for p in plist:
        click.echo(
            f"{p['short_id']:10} {p['hostname']:24} {p['address']:18} {p['port']}"
        )


@cli.command()
@click.argument("peer")
@click.argument("body")
def send(peer, body):
    """Send a chat message to PEER (short_id or hostname)."""
    res = _request("send", timeout=30.0, peer=peer, body=body)
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send failed"))
    r = res["result"]
    click.echo(f"sent  id={r['sent']['id'][:8]}  ack={r['ack']['t']}")


@cli.command("send-file")
@click.argument("peer")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def send_file(peer, path):
    """Send a file to PEER. Any size."""
    size = path.stat().st_size
    click.echo(f"sending {path.name} ({size} bytes)...")
    timeout = max(300.0, min(3600.0, size / (512 * 1024)))
    res = _request(
        "send_file",
        timeout=timeout,
        peer=peer,
        path=str(path.resolve()),
    )
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send-file failed"))
    r = res["result"]
    click.echo(
        f"sent  blob={r['blob'][:12]}  chunks={r['chunks']}  size={r['size']}"
    )


@cli.command()
@click.option("--no-browser", is_flag=True, help="Don't auto-open a window.")
@click.option(
    "--browser-tab",
    is_flag=True,
    help=(
        "Open as a regular browser tab instead of a standalone "
        "Chromium app-mode window. Default opens in app-mode "
        "(frameless, no URL bar / tabs) when Edge or Chrome is "
        "available, falling back to a tab otherwise."
    ),
)
@click.option(
    "--lan/--loopback-only",
    default=True,
    help=(
        "Bind to 0.0.0.0 so devices on your local Wi-Fi (your phone, "
        "another laptop) can reach the UI. Use --loopback-only for "
        "local-computer-only mode."
    ),
)
@click.option(
    "--supervise/--no-supervise",
    default=True,
    help=(
        "Run the daemon under a watchdog that auto-restarts it on "
        "crash. The supervisor has exponential backoff + a "
        "circuit-breaker (5 crashes in 60s stops trying). The UI's "
        "client-side reconnect handles the restart gap. Default on; "
        "pass --no-supervise to launch the daemon bare (e.g. for "
        "interactive debugging where you want the crash to take down "
        "the process visibly)."
    ),
)
def app(no_browser, browser_tab, lan, supervise):
    """Open the One Link desktop app (auto-starts daemon, opens UI).

    Default opens a standalone Chromium-style app-mode window (no
    browser chrome — looks/feels like a native app). Pass
    ``--browser-tab`` to fall back to a regular browser tab, or
    ``--no-browser`` to start the daemon headless. ``--supervise``
    wraps the daemon in an auto-restart watchdog."""
    from one_link.app import run_app
    raise SystemExit(run_app(
        no_browser=no_browser,
        standalone=not browser_tab,
        lan=lan,
        supervise=supervise,
    ))


@cli.command("open-url")
@click.argument("url")
def open_url(url: str):
    """Open a one-link:// URL in the local desktop app."""
    import webbrowser

    from one_link import server as server_mod
    from one_link.app import run_app
    from one_link.protocol_handler import local_ui_url_for_deep_link

    code = run_app(no_browser=True, standalone=True, lan=False)
    if code != 0:
        raise SystemExit(code)
    try:
        local = local_ui_url_for_deep_link(
            url,
            port=server_mod.read_server_port(),
            token=server_mod.read_ui_token(),
        )
    except Exception as exc:
        raise click.ClickException(str(exc))
    click.echo(f"open: {local}")
    webbrowser.open(local)


@cli.command()
def chat():
    """Open the interactive terminal REPL. Auto-starts a daemon if none running."""
    from one_link.chat import run_chat
    raise SystemExit(run_chat())


@cli.command()
def audit():
    """Print a self-audit of this binary's network surface.

    Reports every kind of network call this build can make, sourced from
    the registered HTTP routes and the peer protocol's declared message
    types. Useful for verifying 'no telemetry, no calls home' claims.
    """
    res = _request("audit")
    if res.get("error") or res.get("ok") is False:
        # The control socket doesn't have audit; we go via the UI port.
        from one_link import server as server_mod
        try:
            ui_port = server_mod.read_server_port()
            token = server_mod.read_ui_token()
        except RuntimeError as e:
            raise click.ClickException(f"daemon not running ({e})")
        import urllib.request
        import json as _json
        req = urllib.request.Request(
            f"http://127.0.0.1:{ui_port}/api/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        try:
            with validated_urlopen(req, timeout=5, allow_loopback_http=True) as r:
                res = _json.loads(r.read())
        except Exception as e:
            raise click.ClickException(f"audit fetch failed: {e}")

    click.echo(f"One Link version {res.get('version', '?')}")
    click.echo(f"  UI bind:           {res.get('ui_bind')}")
    click.echo(f"  UI auth:           {res.get('ui_auth')}")
    click.echo(f"  External telemetry: {'NO' if res.get('no_external_telemetry') else 'YES'}")
    doctrine = res.get("sovereign_network", {})
    if doctrine:
        click.echo(f"  Mission:            {doctrine.get('mission', '')}")
        click.echo("  Principles:")
        for p in doctrine.get("principles", []):
            click.echo(f"    - {p}")
        click.echo("  Sovereign capabilities:")
        for c in doctrine.get("capabilities", []):
            click.echo(f"    - {c['name']} [{c['status']}]")
    pp = res.get("peer_protocol", {})
    click.echo("  Peer protocol:")
    click.echo(f"    transport:   {pp.get('transport')}")
    click.echo(f"    auth:        {pp.get('auth')}")
    click.echo(f"    encryption:  {pp.get('encryption')}")
    click.echo(f"    msg types:   {', '.join(pp.get('message_types', []))}")
    click.echo(f"    max frame:   {pp.get('max_frame_bytes')} bytes")
    if res.get("local_capabilities"):
        click.echo(f"    local caps:  {', '.join(res.get('local_capabilities', []))}")
    if pp.get("sessions"):
        click.echo("    sessions:")
        for s in pp.get("sessions", []):
            click.echo(f"      - {s.get('name')}")
    click.echo("  Outbound destinations:")
    for o in res.get("outbound_destinations", []):
        click.echo(f"    - {o['kind']}: {o['destination']}")
        click.echo(f"        protocol: {o['protocol']}")
    click.echo("  Local UI routes:")
    for r in res.get("local_ui_routes", []):
        click.echo(f"    {r['method']:6} {r['path']}")
    primitives = res.get("sovereign_primitives", [])
    if primitives:
        click.echo("  Sovereign primitives:")
        for p in primitives:
            status = p.get("status", "?")
            ref = p.get("audit_ref", "")
            click.echo(
                f"    {p['name']:42} [{status}]  {ref}"
            )
            click.echo(f"      {p['summary']}")


@cli.command()
@click.argument("query")
@click.option("--peer", default=None, help="Filter by peer (short_id or fingerprint).")
@click.option("--limit", default=50, type=int, help="Max results.")
def search(query, peer, limit):
    """Full-text search across message history."""
    from one_link import server as server_mod
    try:
        ui_port = server_mod.read_server_port()
        token = server_mod.read_ui_token()
    except RuntimeError as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.parse
    import urllib.request
    import json as _json
    qs = {"q": query, "limit": str(limit)}
    if peer:
        qs["peer"] = peer
    url = f"http://127.0.0.1:{ui_port}/api/search?{urllib.parse.urlencode(qs)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with validated_urlopen(req, timeout=10, allow_loopback_http=True) as r:
            res = _json.loads(r.read())
    except Exception as e:
        raise click.ClickException(f"search failed: {e}")

    msgs = res.get("messages", [])
    click.echo(f"{len(msgs)} result(s) for {query!r}\n")
    for m in msgs:
        if m.get("t") != "TEXT":
            continue
        ts = m.get("ts", 0)
        peer = m.get("peer", "?")
        body = m.get("body", "")
        click.echo(f"  [{ts}] {peer}: {body}")


@cli.command()
def tail():
    """Stream incoming and outgoing message events. Ctrl-C to stop."""
    s, _ = _connect_control()
    s.settimeout(None)
    try:
        s.sendall((json.dumps({"cmd": "tail"}) + "\n").encode("utf-8"))
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                obj = json.loads(line.decode("utf-8"))
                if obj.get("ok") is True and obj.get("tailing"):
                    click.echo("(tailing — Ctrl-C to stop)")
                    continue
                msg = obj.get("msg") or obj
                _print_event(msg)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


def _print_event(m: dict) -> None:
    direction = m.get("dir", "?")
    arrow = "<-" if direction == "in" else "->"
    peer = m.get("peer", "?")
    t = m.get("t", "?")
    if t == "TEXT":
        click.echo(f"[{m.get('ts','')}] {arrow} {peer}: {m.get('body','')}")
    elif t == "FILE_OFFER":
        click.echo(
            f"[{m.get('ts','')}] {arrow} {peer} OFFER {m.get('name','')} "
            f"({m.get('size','?')} bytes, blob={m.get('blob','')[:8]})"
        )
    elif t == "FILE_DONE":
        ok = "OK" if m.get("ok") else "BAD"
        click.echo(
            f"[{m.get('ts','')}] {arrow} {peer} FILE_DONE [{ok}] "
            f"{m.get('name','')} -> {m.get('path','')}"
        )
    else:
        click.echo(f"[{m.get('ts','')}] {arrow} {peer} {t}")


def _ui_request(method: str, path: str, *, payload=None) -> dict:
    """Helper for hitting the daemon's UI API from CLI commands."""
    from one_link import server as server_mod
    try:
        ui_port = server_mod.read_server_port()
        token = server_mod.read_ui_token()
    except RuntimeError as e:
        raise click.ClickException(f"daemon not running ({e})")

    import urllib.error
    import urllib.request
    import json as _json
    body = None
    headers = {"Authorization": f"Bearer {token}"}
    if payload is not None:
        body = _json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://127.0.0.1:{ui_port}{path}",
        data=body, headers=headers, method=method,
    )
    try:
        with validated_urlopen(req, timeout=30, allow_loopback_http=True) as r:
            return _json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read())
        except Exception:
            raise click.ClickException(f"{path} failed: {e}")
    except Exception as e:
        raise click.ClickException(f"{path} failed: {e}")


@cli.group()
def folder():
    """Synced-folder management. Folders sync between paired peers."""


@folder.command("add")
@click.argument("name")
@click.argument("local_path", type=click.Path(file_okay=False, path_type=Path))
@click.option("--share", "share", multiple=True,
              help="Peer fingerprint to share with (repeatable).")
def folder_add(name, local_path, share):
    """Designate a folder to sync. NAME is a label, LOCAL_PATH is the directory."""
    res = _ui_request("POST", "/api/folders", payload={
        "name": name,
        "local_path": str(local_path.expanduser().resolve()),
        "shared_with": list(share),
    })
    if res.get("error"):
        raise click.ClickException(res["error"])
    f = res.get("folder", {})
    click.echo(f"added: {f.get('name')}  ->  {f.get('local_path')}")
    if f.get("shared_with"):
        click.echo("  shared with:")
        for fp in f["shared_with"]:
            click.echo(f"    {fp[:16]}…")


@folder.command("list")
def folder_list():
    """List all configured sync folders."""
    res = _ui_request("GET", "/api/folders")
    folders = res.get("folders", [])
    if not folders:
        click.echo("(no folders configured — try: one-link folder add)")
        return
    click.echo(f"{'name':16} {'files':>6} {'in_store':>9}  path")
    click.echo("-" * 60)
    for f in folders:
        click.echo(
            f"{f['name']:16} {f.get('files', 0):>6} {f.get('in_store', 0):>9}  "
            f"{f['local_path']}"
        )
        if f.get("shared_with"):
            click.echo(f"{'':16} shared with: " + ", ".join(
                fp[:8] + "…" for fp in f["shared_with"]
            ))


@folder.command("share")
@click.argument("name")
@click.argument("fingerprint")
def folder_share(name, fingerprint):
    """Add a peer FINGERPRINT to the sharing list of folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/share",
                      payload={"peer_fp": fingerprint})
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"shared {name!r} with {fingerprint[:16]}…")


@folder.command("remove")
@click.argument("name")
def folder_remove(name):
    """Stop syncing folder NAME. Local files are not deleted."""
    res = _ui_request("DELETE", f"/api/folders/{name}")
    if res.get("error"):
        raise click.ClickException(res["error"])
    click.echo(f"removed: {name}")


@folder.command("sync")
@click.argument("name")
def folder_sync(name):
    """Force an immediate sync cycle for folder NAME."""
    res = _ui_request("POST", f"/api/folders/{name}/sync", payload={})
    if res.get("error"):
        raise click.ClickException(res["error"])
    for r in res.get("results", []):
        peer = r.get("peer_fp", "?")[:8] + "…"
        if r["status"] == "pushed":
            click.echo(
                f"  {peer}  pushed  wants={r.get('wants', 0)}  "
                f"blobs_sent={r.get('blobs_sent', 0)}"
            )
        else:
            click.echo(f"  {peer}  {r['status']}")


@cli.command("daemon-stop")
def daemon_stop():
    """Stop the background daemon.

    The daemon is detached from the launcher (so closing the desktop
    window does NOT stop it — paired peers stay online, in-flight
    transfers complete). Use this command when you actually want to
    shut down: One Link will no longer be reachable until you
    re-launch it.
    """
    try:
        port = daemon_mod.read_control_port()
    except RuntimeError:
        click.echo("daemon is not running.")
        return
    # Tell the daemon to shut down cleanly via the control port.
    try:
        sock, _ = _connect_control(timeout=3.0)
        sock.sendall(json.dumps({"cmd": "shutdown"}).encode() + b"\n")
        try:
            sock.recv(256)
        except Exception:
            pass
        sock.close()
        click.echo("daemon shutdown requested.")
    except Exception as e:
        # Fall back to PID-file termination.
        try:
            from one_link.paths import data_dir as _dd
            pid_path = _dd() / "daemon.pid"
            if pid_path.is_file():
                pid = int(pid_path.read_text().strip())
                if os.name == "nt":
                    _force_kill_windows_pid(pid)
                else:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                click.echo(f"daemon terminated (pid {pid}).")
                return
        except Exception:
            pass
        raise click.ClickException(f"could not stop daemon: {e}")


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
