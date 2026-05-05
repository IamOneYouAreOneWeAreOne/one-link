"""HTTP + WebSocket UI server.

Exposes a local HTTP API and WebSocket event stream that the frontend
(`web/index.html`) consumes. Bound to 127.0.0.1 only — never reachable
from the network.

Endpoints:
    GET  /                       index.html
    GET  /static/<path>          static assets (none yet)
    GET  /api/me                 own identity
    GET  /api/peers              live peer list
    GET  /api/messages           recent messages (?peer=, ?room=, ?limit=)
    POST /api/send               body: {peer, body}
    POST /api/send-file          multipart: peer, file
    GET  /api/files              list received files in inbox/
    GET  /api/files/<name>       download an inbox file
    WS   /api/events             live event stream

Auth: bound to loopback only and gated by a process-local secret token
(written next to control.port; the frontend reads it from a cookie set on
first GET /). Token is rotated each daemon restart.
"""

from __future__ import annotations

import asyncio
import json
import logging
import mimetypes
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from aiohttp import WSMsgType, web

from one_link.paths import data_dir, inbox_dir

if TYPE_CHECKING:
    from one_link.daemon import Daemon

log = logging.getLogger("one_link.server")

WEB_DIR = Path(__file__).resolve().parent / "web"
TOKEN_FILE = "ui.token"
SERVER_PORT_FILE = "server.port"
COOKIE_NAME = "ol_ui"


def _token_path() -> Path:
    return data_dir() / TOKEN_FILE


def _server_port_path() -> Path:
    return data_dir() / SERVER_PORT_FILE


class UIServer:
    """Wraps the aiohttp app + the websocket event broker."""

    def __init__(self, daemon: "Daemon"):
        self.daemon = daemon
        self.token = secrets.token_urlsafe(32)
        self.app = web.Application(client_max_size=1024 * 1024 * 1024)  # 1 GiB upload
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.port: int = 0
        self._ws_clients: set[web.WebSocketResponse] = set()
        self._setup_routes()

    # ─── routes ───────────────────────────────────────────────────────
    def _setup_routes(self) -> None:
        r = self.app.router
        r.add_get("/", self._index)
        r.add_get("/api/me", self._guarded(self.api_me))
        r.add_get("/api/peers", self._guarded(self.api_peers))
        r.add_get("/api/messages", self._guarded(self.api_messages))
        r.add_post("/api/send", self._guarded(self.api_send))
        r.add_post("/api/send-file", self._guarded(self.api_send_file))
        r.add_get("/api/files", self._guarded(self.api_files))
        r.add_get(r"/api/files/{name:.+}", self._guarded(self.api_file_download))
        r.add_get("/api/events", self._guarded_ws(self.ws_events))

    # ─── auth helpers ─────────────────────────────────────────────────
    def _check_token(self, request: web.Request) -> bool:
        # Accept token from cookie OR Authorization header OR ?t= query.
        if request.cookies.get(COOKIE_NAME) == self.token:
            return True
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:] == self.token:
            return True
        if request.query.get("t") == self.token:
            return True
        return False

    def _guarded(self, handler):
        async def wrap(request: web.Request) -> web.StreamResponse:
            if not self._check_token(request):
                return web.json_response({"error": "unauthorized"}, status=401)
            return await handler(request)
        return wrap

    def _guarded_ws(self, handler):
        async def wrap(request: web.Request) -> web.WebSocketResponse:
            if not self._check_token(request):
                ws = web.WebSocketResponse()
                if ws.can_prepare(request).ok:
                    await ws.prepare(request)
                    await ws.close(code=4401, message=b"unauthorized")
                return ws
            return await handler(request)
        return wrap

    # ─── HTML index ───────────────────────────────────────────────────
    async def _index(self, request: web.Request) -> web.Response:
        try:
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        except FileNotFoundError:
            html = "<h1>One_link UI not bundled</h1>"
        # Set the auth cookie on first GET / from this browser.
        resp = web.Response(text=html, content_type="text/html")
        resp.set_cookie(
            COOKIE_NAME,
            self.token,
            httponly=True,
            samesite="Strict",
            max_age=86400,
            path="/",
        )
        return resp

    # ─── /api/me ──────────────────────────────────────────────────────
    async def api_me(self, request: web.Request) -> web.Response:
        me = self.daemon.me
        return web.json_response(
            {
                "short_id": me.short_id,
                "fingerprint": me.fingerprint,
                "hostname": me.hostname,
            }
        )

    # ─── /api/peers ───────────────────────────────────────────────────
    async def api_peers(self, request: web.Request) -> web.Response:
        peers = []
        if self.daemon.discovery:
            for p in self.daemon.discovery.registry.list():
                peers.append(
                    {
                        "short_id": p.short_id,
                        "hostname": p.hostname,
                        "address": p.address,
                        "port": p.port,
                        "ed_pub_hex": p.ed_pub_hex,
                        "online": True,
                    }
                )
        return web.json_response({"peers": peers})

    # ─── /api/messages ────────────────────────────────────────────────
    async def api_messages(self, request: web.Request) -> web.Response:
        """Return recent messages from the JSONL log.

        Query params:
            peer   — filter by peer short_id
            limit  — max messages (default 200)
        """
        from one_link.paths import message_log_path
        peer = request.query.get("peer")
        try:
            limit = max(1, min(int(request.query.get("limit", "200")), 5000))
        except ValueError:
            limit = 200
        path = message_log_path()
        if not path.exists():
            return web.json_response({"messages": []})
        msgs: list[dict] = []
        # Read tail efficiently. For now, just read the whole file (capped by
        # limit at the slice). At scale we'd swap to sqlite via state.py.
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if peer and obj.get("peer") != peer:
                continue
            msgs.append(obj)
        msgs = msgs[-limit:]
        return web.json_response({"messages": msgs})

    # ─── /api/send ────────────────────────────────────────────────────
    async def api_send(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        peer_needle = data.get("peer", "")
        body = data.get("body", "")
        if not peer_needle or not body:
            return web.json_response({"error": "peer and body required"}, status=400)
        peer = (
            self.daemon.discovery.registry.find(peer_needle)
            if self.daemon.discovery
            else None
        )
        if peer is None:
            return web.json_response({"error": f"no peer {peer_needle!r}"}, status=404)
        try:
            result = await self.daemon.send_text(peer, body)
            return web.json_response({"ok": True, "result": result})
        except Exception as e:
            log.exception("send failed: %s", e)
            return web.json_response({"error": str(e)}, status=500)

    # ─── /api/send-file ───────────────────────────────────────────────
    async def api_send_file(self, request: web.Request) -> web.Response:
        if not request.content_type or "multipart/form-data" not in request.content_type:
            return web.json_response({"error": "expected multipart/form-data"}, status=400)
        reader = await request.multipart()
        peer_needle: Optional[str] = None
        upload_path: Optional[Path] = None
        upload_name: str = "upload.bin"

        async for part in reader:
            if part.name == "peer":
                peer_needle = (await part.text()).strip()
            elif part.name == "file":
                upload_name = part.filename or "upload.bin"
                # Stream to a temp file inside data_dir so we don't OOM on big uploads.
                staging = data_dir() / "uploads"
                staging.mkdir(parents=True, exist_ok=True)
                upload_path = staging / f"{int(time.time()*1000)}_{upload_name}"
                with open(upload_path, "wb") as f:
                    while True:
                        chunk = await part.read_chunk(size=1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)

        if not peer_needle:
            return web.json_response({"error": "missing 'peer' field"}, status=400)
        if not upload_path or not upload_path.is_file():
            return web.json_response({"error": "missing 'file' field"}, status=400)

        peer = (
            self.daemon.discovery.registry.find(peer_needle)
            if self.daemon.discovery
            else None
        )
        if peer is None:
            return web.json_response({"error": f"no peer {peer_needle!r}"}, status=404)

        try:
            result = await self.daemon.send_file(peer, upload_path)
            return web.json_response({"ok": True, "result": result})
        except Exception as e:
            log.exception("send_file failed: %s", e)
            return web.json_response({"error": str(e)}, status=500)
        finally:
            try:
                if upload_path:
                    upload_path.unlink(missing_ok=True)
            except OSError:
                pass

    # ─── /api/files ───────────────────────────────────────────────────
    async def api_files(self, request: web.Request) -> web.Response:
        inbox = inbox_dir()
        files = []
        for f in inbox.iterdir():
            if f.is_file():
                stat = f.stat()
                files.append(
                    {
                        "name": f.name,
                        "size": stat.st_size,
                        "mtime_ms": int(stat.st_mtime * 1000),
                        "mime": mimetypes.guess_type(f.name)[0] or "application/octet-stream",
                    }
                )
        files.sort(key=lambda x: x["mtime_ms"], reverse=True)
        return web.json_response({"files": files})

    async def api_file_download(self, request: web.Request) -> web.StreamResponse:
        name = request.match_info["name"]
        # Path-traversal defense — same logic as the wire protocol.
        safe = Path(name).name
        if safe != name or not safe:
            return web.json_response({"error": "bad name"}, status=400)
        path = inbox_dir() / safe
        if not path.is_file():
            return web.json_response({"error": "not found"}, status=404)
        mime = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        return web.FileResponse(path, headers={"Content-Type": mime})

    # ─── WebSocket events ─────────────────────────────────────────────
    async def ws_events(self, request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        self._ws_clients.add(ws)
        # Send an initial snapshot so the UI has state before any pushes.
        await ws.send_json(
            {
                "type": "hello",
                "me": {
                    "short_id": self.daemon.me.short_id,
                    "fingerprint": self.daemon.me.fingerprint,
                    "hostname": self.daemon.me.hostname,
                },
            }
        )
        try:
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    log.warning("ws error: %s", ws.exception())
                # Otherwise: we don't accept client→server messages; UI uses HTTP.
        finally:
            self._ws_clients.discard(ws)
        return ws

    def broadcast(self, event: dict[str, Any]) -> None:
        """Push an event to all connected UI clients. Safe to call from any
        coroutine; closed sockets are pruned."""
        dead: list[web.WebSocketResponse] = []
        for ws in list(self._ws_clients):
            if ws.closed:
                dead.append(ws)
                continue
            try:
                # send_str is synchronous-ish — schedule it but don't await.
                asyncio.create_task(ws.send_json(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.discard(ws)

    # ─── lifecycle ────────────────────────────────────────────────────
    async def start(self) -> int:
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, host="127.0.0.1", port=0)
        await self.site.start()
        sock = self.site._server.sockets[0]  # type: ignore[union-attr]
        self.port = sock.getsockname()[1]
        _server_port_path().write_text(str(self.port))
        _token_path().write_text(self.token)
        log.info("UI server up — http://127.0.0.1:%d/  (token gated)", self.port)
        return self.port

    async def stop(self) -> None:
        for ws in list(self._ws_clients):
            try:
                await ws.close()
            except Exception:
                pass
        self._ws_clients.clear()
        if self.runner:
            await self.runner.cleanup()


def read_server_port() -> int:
    p = _server_port_path()
    if not p.exists():
        raise RuntimeError("UI server not running (no server.port file)")
    return int(p.read_text().strip())


def read_ui_token() -> str:
    p = _token_path()
    if not p.exists():
        raise RuntimeError("UI token file missing")
    return p.read_text().strip()
