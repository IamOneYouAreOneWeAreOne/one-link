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
    """One Link — peer-to-peer LAN chat + file sync."""


@cli.command()
@click.option("-v", "--verbose", is_flag=True)
def daemon(verbose):
    """Run the One Link daemon (leave this in a terminal/service)."""
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
@click.option("--no-browser", is_flag=True, help="Don't auto-open a browser tab.")
def app(no_browser):
    """Open the One Link desktop app (auto-starts daemon, opens browser UI)."""
    from one_link.app import run_app
    raise SystemExit(run_app(no_browser=no_browser))


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
            with urllib.request.urlopen(req, timeout=5) as r:
                res = _json.loads(r.read())
        except Exception as e:
            raise click.ClickException(f"audit fetch failed: {e}")

    click.echo(f"One Link version {res.get('version', '?')}")
    click.echo(f"  UI bind:           {res.get('ui_bind')}")
    click.echo(f"  UI auth:           {res.get('ui_auth')}")
    click.echo(f"  External telemetry: {'NO' if res.get('no_external_telemetry') else 'YES'}")
    pp = res.get("peer_protocol", {})
    click.echo("  Peer protocol:")
    click.echo(f"    transport:   {pp.get('transport')}")
    click.echo(f"    auth:        {pp.get('auth')}")
    click.echo(f"    encryption:  {pp.get('encryption')}")
    click.echo(f"    msg types:   {', '.join(pp.get('message_types', []))}")
    click.echo(f"    max frame:   {pp.get('max_frame_bytes')} bytes")
    click.echo("  Outbound destinations:")
    for o in res.get("outbound_destinations", []):
        click.echo(f"    - {o['kind']}: {o['destination']}")
        click.echo(f"        protocol: {o['protocol']}")
    click.echo("  Local UI routes:")
    for r in res.get("local_ui_routes", []):
        click.echo(f"    {r['method']:6} {r['path']}")


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
        with urllib.request.urlopen(req, timeout=10) as r:
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


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
