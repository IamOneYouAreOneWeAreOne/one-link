"""one-link CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import sys
from pathlib import Path

import click

from one_link import __version__
from one_link import daemon as daemon_mod
from one_link.identity import load_or_create


def _connect_control() -> tuple[socket.socket, int]:
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
    return s, port


def _request(cmd: str, **kwargs) -> dict:
    s, _ = _connect_control()
    try:
        s.sendall((json.dumps({"cmd": cmd, **kwargs}) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        return json.loads(buf.decode("utf-8").strip() or "{}")
    finally:
        s.close()


@click.group()
@click.version_option(__version__, prog_name="one-link")
def cli():
    """One_link — peer-to-peer LAN chat + file sync."""


@cli.command()
@click.option("-v", "--verbose", is_flag=True)
def daemon(verbose):
    """Run the One_link daemon (leave this in a terminal/service)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(daemon_mod.run())


@cli.command()
def whoami():
    """Show this device's identity."""
    me = load_or_create()
    click.echo(f"hostname:    {me.hostname}")
    click.echo(f"short_id:    {me.short_id}")
    click.echo(f"fingerprint: {me.fingerprint}")


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
    res = _request("send", peer=peer, body=body)
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send failed"))
    r = res["result"]
    click.echo(f"sent  id={r['sent']['id'][:8]}  ack={r['ack']['t']}")


@cli.command("send-file")
@click.argument("peer")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def send_file(peer, path):
    """Send a file to PEER. Any size."""
    click.echo(f"hashing {path.name} ({path.stat().st_size} bytes)…")
    res = _request("send_file", peer=peer, path=str(path.resolve()))
    if not res.get("ok"):
        raise click.ClickException(res.get("error", "send-file failed"))
    r = res["result"]
    click.echo(
        f"sent  blob={r['blob'][:12]}  chunks={r['chunks']}  size={r['size']}"
    )


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


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
