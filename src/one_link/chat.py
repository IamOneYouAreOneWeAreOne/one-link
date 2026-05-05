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

import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from one_link import daemon as daemon_mod


def _ts(ms: Optional[int] = None) -> str:
    t = (ms or int(time.time() * 1000)) / 1000.0
    return datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _request(port: int, *, timeout: float = 30.0, **req) -> dict:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    try:
        s.sendall((json.dumps(req) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        s.close()


def _daemon_alive() -> Optional[int]:
    """If a running daemon is reachable, return its control port. Else None."""
    try:
        port = daemon_mod.read_control_port()
    except RuntimeError:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", port))
        return port
    except OSError:
        return None
    finally:
        s.close()


def _spawn_daemon() -> tuple[subprocess.Popen, int]:
    """Spawn a daemon as a child of this chat process. Wait until reachable."""
    flags = 0
    if os.name == "nt":
        # Detach from any console; keep stdio piped so we can join.
        flags = subprocess.CREATE_NO_WINDOW
    proc = subprocess.Popen(
        [sys.executable, "-m", "one_link.cli", "daemon"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    # Wait up to 8s for the control socket to appear and respond.
    deadline = time.time() + 8.0
    while time.time() < deadline:
        port = _daemon_alive()
        if port is not None:
            return proc, port
        time.sleep(0.1)
    proc.terminate()
    raise RuntimeError("could not start daemon (timed out waiting for control port)")


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
        s.settimeout(None)
        s.connect(("127.0.0.1", self.control_port))
        s.sendall((json.dumps({"cmd": "tail"}) + "\n").encode("utf-8"))
        self._tail_socket = s
        self._tail_thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._tail_thread.start()

    def _tail_loop(self) -> None:
        s = self._tail_socket
        if s is None:
            return
        buf = b""
        try:
            while not self._stop.is_set():
                try:
                    chunk = s.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
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
        try:
            if self._tail_socket:
                self._tail_socket.close()
        except OSError:
            pass


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
            try:
                spawned.terminate()
                spawned.wait(timeout=5)
            except subprocess.TimeoutExpired:
                spawned.kill()
    return 0
