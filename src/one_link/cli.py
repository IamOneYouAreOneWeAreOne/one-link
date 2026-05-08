"""one-link CLI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import socket
import sys
import threading
from pathlib import Path

import click

from one_link import __version__
from one_link import daemon as daemon_mod
from one_link.identity import load_or_create


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


def _request(cmd: str, *, timeout: float = 5.0, **kwargs) -> dict:
    s, _ = _connect_control(timeout=timeout)
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
@click.option("--tray/--no-tray", default=True,
              help="Run a system tray icon alongside the daemon (default: on).")
def daemon(verbose, tray):
    """Run the One Link daemon (leave this in a terminal/service)."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # v0.10.5/v0.12.2: optional tray icon. Start it off the critical daemon
    # boot path so slow Windows/Pillow/pystray initialization cannot delay
    # discovery, the control socket, or the local web UI coming online.
    tray_icon_holder: dict[str, object | None] = {"icon": None}

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
                logging.getLogger("one_link.tray").info(
                    "tray icon active. Right-click for menu; click to open UI."
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
    try:
        asyncio.run(daemon_mod.run())
    except RuntimeError as e:
        if "already running" in str(e):
            raise click.ClickException(str(e))
        raise
    finally:
        tray_icon = tray_icon_holder.get("icon")
        if tray_icon is not None:
            try: tray_icon.stop()
            except Exception: pass


@cli.command()
def whoami():
    """Show this device's identity."""
    me = load_or_create()
    click.echo(f"hostname:    {me.hostname}")
    click.echo(f"short_id:    {me.short_id}")
    click.echo(f"fingerprint: {me.fingerprint}")


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
    click.echo(f"preparing {path.name} ({path.stat().st_size} bytes)…")
    size = path.stat().st_size
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
        with urllib.request.urlopen(req, timeout=30) as r:
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


def main():
    cli()


if __name__ == "__main__":
    sys.exit(main() or 0)
