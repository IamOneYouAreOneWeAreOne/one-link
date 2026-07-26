"""Interactive chat REPL — one-window experience.

`one-link chat` connects to a running daemon (or auto-starts one as a child)
and gives the user a single window where they can both type messages to
peers and see incoming traffic live.

Commands:
    /peers              list peers on the LAN
    /send-file P F      send file F to peer P
    /me                 show this device's identity
    /help               show this help
    /quit               exit (and stop the auto-started daemon, if any)

Sending a message: just type `<peer>: <message>` and press Enter.
`<peer>` accepts a hostname or short_id prefix.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, Optional

import click

from one_link import control_ipc
from one_link import daemon as daemon_mod
from one_link.paths import data_dir
from one_link.process_security import (
    hidden_creationflags,
    resolve_current_interpreter,
    sanitized_process_env,
)


def _ts(ms: Optional[int] = None) -> str:
    t = (ms or int(time.time() * 1000)) / 1000.0
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _request(port: int, *, timeout: float = 30.0, **req) -> dict:
    return control_ipc.request_control(port, req, timeout=timeout)


def _daemon_alive() -> Optional[int]:
    """If a running daemon is reachable, return its control port. Else None."""
    try:
        port_path = data_dir() / daemon_mod.CONTROL_PORT_FILE
        port = int(
            control_ipc.read_private_bytes_strict(
                port_path,
                max_bytes=64,
                label="control port",
            )
            .decode("ascii")
            .strip()
        )
    except (OSError, RuntimeError, UnicodeError, ValueError):
        return None
    return port if daemon_mod.is_daemon_alive(port, timeout=0.5) else None


def _spawn_daemon() -> tuple[subprocess.Popen, int]:
    """Spawn a daemon as a child of this chat process. Wait until reachable."""
    flags = 0
    if os.name == "nt":
        # Isolate console signals while retaining a child handle for cleanup.
        flags = hidden_creationflags() | getattr(
            subprocess,
            "CREATE_NEW_PROCESS_GROUP",
            0x00000200,
        )
    proc = subprocess.Popen(
        [
            resolve_current_interpreter(),
            "-P",
            "-m",
            "one_link.cli",
            "daemon",
            "--no-tray",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
        start_new_session=os.name != "nt",
        close_fds=True,
        env=sanitized_process_env(),
        cwd=str(Path(sys.executable).resolve().parent),
        shell=False,
    )
    # Wait long enough for slower Windows machines, but only return once the
    # control protocol itself answers. A port file alone is not readiness.
    deadline = time.time() + 20.0
    while time.time() < deadline:
        port = _daemon_alive()
        if port is not None:
            return proc, port
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("could not start daemon (timed out waiting for control port)")


def _stop_spawned_daemon(proc: subprocess.Popen, control_port: int) -> None:
    """Stop the exact daemon this REPL started, preferring authenticated IPC.

    Virtual-environment launchers can remain as a wrapper process around the
    real interpreter.  Terminating only the wrapper can orphan the daemon, so
    ask the authenticated daemon itself to shut down and wait for the complete
    child chain to unwind before using the process handle as a last resort.
    """
    if proc.poll() is not None:
        return
    try:
        response = _request(control_port, timeout=3.0, cmd="shutdown")
        if response.get("ok") is True:
            try:
                proc.wait(timeout=8.0)
                return
            except subprocess.TimeoutExpired:
                pass
    except (OSError, RuntimeError, ValueError):
        pass

    with contextlib.suppress(OSError):
        proc.terminate()
    try:
        proc.wait(timeout=5.0)
        return
    except (subprocess.TimeoutExpired, OSError):
        pass
    with contextlib.suppress(OSError):
        proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
        proc.wait(timeout=2.0)


def _format_event(ev: dict) -> Optional[str]:
    """Turn a tail event into a printable line; return None to suppress."""
    msg = ev.get("msg") if isinstance(ev, dict) and "msg" in ev else ev
    if not isinstance(msg, dict):
        return None
    t = msg.get("t")
    direction = msg.get("dir", "?")
    arrow = "<-" if direction == "in" else "->"
    peer = msg.get("peer", "?")
    ts = _ts(msg.get("ts"))
    if t == "TEXT":
        return f"[{ts}] {arrow} {peer}: {msg.get('body','')}"
    if t == "FILE_OFFER":
        return (
            f"[{ts}] {arrow} {peer}  offer {msg.get('name','?')} "
            f"({msg.get('size','?')} B)"
        )
    if t == "FILE_DONE":
        ok = "OK" if msg.get("ok") else "BAD"
        return (
            f"[{ts}] {arrow} {peer}  file [{ok}] "
            f"{msg.get('name','?')} -> {msg.get('path','?')}"
        )
    return None


class ChatSession:
    """Foreground REPL with a background tail-event reader."""

    def __init__(self, control_port: int):
        self.control_port = control_port
        self._stop = threading.Event()
        self._tail_socket: Optional[socket.socket] = None
        self._tail_stream: Optional[BinaryIO] = None
        self._tail_thread: Optional[threading.Thread] = None
        self.me_short_id: str = "?"
        self.me_hostname: str = "?"
        self._peers_cache: list[dict] = []

    # ─── peers ────────────────────────────────────────────────────────
    def refresh_peers(self) -> None:
        res = _request(self.control_port, cmd="peers")
        if res.get("ok"):
            self.me_short_id = res["me"]["short_id"]
            self.me_hostname = res["me"]["hostname"]
            self._peers_cache = res["peers"]

    def show_peers(self) -> None:
        self.refresh_peers()
        click.echo(f"  me:   {self.me_short_id}  ({self.me_hostname})")
        if not self._peers_cache:
            click.echo("  (no peers discovered yet — give it a few seconds)")
            return
        click.echo(f"  {'short_id':10} {'hostname':24} {'address':18} port")
        click.echo("  " + "-" * 60)
        for p in self._peers_cache:
            click.echo(
                f"  {p['short_id']:10} {p['hostname']:24} {p['address']:18} {p['port']}"
            )

    # ─── tail (background incoming-event printer) ─────────────────────
    def start_tail(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", self.control_port))
        secret = control_ipc.read_control_secret()
        credential, exchange = control_ipc.begin_authenticated_request(
            s,
            {"cmd": "tail"},
            secret=secret,
        )
        stream = s.makefile("rb")
        first = stream.readline(control_ipc.CONTROL_RESPONSE_MAX_BYTES + 2)
        if len(first) > control_ipc.CONTROL_RESPONSE_MAX_BYTES or not first.endswith(b"\n"):
            stream.close()
            s.close()
            raise RuntimeError("daemon returned an oversized tail response")
        envelope = json.loads(first.decode("utf-8"))
        ack = control_ipc.verify_server_response(envelope, credential, exchange)
        if ack.get("ok") is not True or not ack.get("tailing"):
            stream.close()
            s.close()
            raise RuntimeError(ack.get("error") or "daemon refused tail stream")
        # Keep the buffered reader so a tail event coalesced with the signed
        # acknowledgement is not lost between raw socket recv() calls.
        self._tail_stream = stream
        s.settimeout(None)
        self._tail_socket = s
        self._tail_thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._tail_thread.start()

    def _tail_loop(self) -> None:
        s = self._tail_socket
        if s is None:
            return
        try:
            while not self._stop.is_set():
                try:
                    stream = getattr(self, "_tail_stream", None)
                    if stream is None:
                        break
                    line = stream.readline(control_ipc.CONTROL_RESPONSE_MAX_BYTES + 2)
                except OSError:
                    break
                if not line:
                    break
                if len(line) > control_ipc.CONTROL_RESPONSE_MAX_BYTES or not line.endswith(b"\n"):
                    break
                if not line.strip():
                    continue
                try:
                    ev = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
                text = _format_event(ev)
                if text:
                    # Print event on its own line. Re-emit the prompt so
                    # the user knows where their cursor is. Plain print
                    # is acceptable; not perfectly redrawn while typing.
                    click.echo("\n" + text)
                    sys.stdout.write(">>> ")
                    sys.stdout.flush()
        finally:
            stream = getattr(self, "_tail_stream", None)
            if stream is not None:
                with contextlib.suppress(OSError):
                    stream.close()
            try:
                s.close()
            except OSError:
                pass

    # ─── send ─────────────────────────────────────────────────────────
    def send_text(self, peer: str, body: str) -> None:
        res = _request(self.control_port, cmd="send", peer=peer, body=body)
        if not res.get("ok"):
            click.echo(f"  ! {res.get('error', 'send failed')}")

    def send_file(self, peer: str, path: str) -> None:
        p = Path(path).expanduser()
        if not p.is_file():
            click.echo(f"  ! no such file: {p}")
            return
        click.echo(f"  hashing {p.name} ({p.stat().st_size} bytes) …")
        res = _request(
            self.control_port, cmd="send_file", peer=peer, path=str(p.resolve()),
            timeout=600.0,
        )
        if not res.get("ok"):
            click.echo(f"  ! {res.get('error', 'send_file failed')}")
            return
        r = res["result"]
        click.echo(f"  sent  blob={r['blob'][:12]}  chunks={r['chunks']}")

    # ─── lifecycle ────────────────────────────────────────────────────
    def stop(self) -> None:
        self._stop.set()
        # Do not close the buffered stream first.  The tail thread can hold
        # BufferedReader's internal lock while blocked in ``readline()``;
        # closing it from the REPL thread then deadlocks before the socket is
        # ever closed.  Shutting down the transport wakes the reader, after
        # which that thread owns normal stream cleanup in ``_tail_loop``.
        tail_socket = self._tail_socket
        if tail_socket is not None:
            with contextlib.suppress(OSError):
                tail_socket.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                tail_socket.close()

        tail_thread = self._tail_thread
        if tail_thread is not None and tail_thread is not threading.current_thread():
            tail_thread.join(timeout=2.0)

        # A thread that exited before entering its ``finally`` block cannot
        # retain the stream lock.  Close any residual handle only after the
        # join; never reintroduce the cross-thread BufferedReader deadlock.
        if tail_thread is None or not tail_thread.is_alive():
            tail_stream = self._tail_stream
            if tail_stream is not None:
                with contextlib.suppress(OSError):
                    tail_stream.close()
            self._tail_socket = None
            self._tail_stream = None
            self._tail_thread = None


def _print_help() -> None:
    click.echo(
        "  /peers              list peers on your LAN\n"
        "  /me                 show this device's identity\n"
        "  /send-file P F      send file F to peer P\n"
        "  /help               this help\n"
        "  /quit               exit (and stop auto-started daemon, if any)\n"
        "\n"
        "  to chat:    type    <peer>: <message>    and press Enter\n"
        "  <peer> can be a hostname or any prefix of a short_id"
    )


def run_chat() -> int:
    click.echo("One Link chat\n")
    spawned: Optional[subprocess.Popen] = None

    port = _daemon_alive()
    if port is None:
        click.echo("  starting daemon …")
        try:
            spawned, port = _spawn_daemon()
        except RuntimeError as e:
            click.echo(f"  ! {e}")
            return 2
        click.echo("  daemon up.")

    session = ChatSession(port)
    try:
        session.refresh_peers()
        click.echo(f"  you: {session.me_short_id}  ({session.me_hostname})")
        if session._peers_cache:
            names = ", ".join(p["short_id"] for p in session._peers_cache)
            click.echo(f"  peers: {names}")
        else:
            click.echo("  no peers yet — give it a few seconds, then /peers")
        click.echo("  type /help for commands. /quit to exit.\n")

        session.start_tail()

        while True:
            try:
                line = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                click.echo()
                break
            if not line:
                continue
            if line in ("/quit", "/exit"):
                break
            if line in ("/help", "/?"):
                _print_help()
                continue
            if line == "/peers":
                session.show_peers()
                continue
            if line == "/me":
                session.refresh_peers()
                click.echo(f"  {session.me_short_id}  ({session.me_hostname})")
                continue
            if line.startswith("/send-file "):
                rest = line[len("/send-file ") :].strip()
                # Accept either: <peer> "<path with spaces>" or <peer> <path>
                if rest.startswith('"') and '"' in rest[1:]:
                    # not common; fallback to split
                    parts = rest.split('"')
                    peer = parts[0].strip()
                    path = parts[1]
                else:
                    parts = rest.split(None, 1)
                    if len(parts) != 2:
                        click.echo("  usage: /send-file <peer> <path>")
                        continue
                    peer, path = parts
                session.send_file(peer, path)
                continue
            if ":" in line:
                peer, _, body = line.partition(":")
                peer = peer.strip()
                body = body.strip()
                if not peer or not body:
                    click.echo("  usage: <peer>: <message>")
                    continue
                session.send_text(peer, body)
                continue
            click.echo("  ?  type /help")

    finally:
        session.stop()
        if spawned is not None:
            click.echo("  stopping auto-started daemon …")
            _stop_spawned_daemon(spawned, port)
    return 0
