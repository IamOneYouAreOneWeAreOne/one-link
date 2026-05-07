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
import base64
import contextlib
import json
import logging
import mimetypes
import os
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

# Stable UI port. When the daemon restarts, the browser tab at this URL
# stays alive. We fall through to 7118..7132 if the port is taken (other
# user on the same machine, dev test daemon, etc.), and to OS-assigned
# random port only as a last resort.
PREFERRED_UI_PORT = 7117
UI_PORT_FALLBACK_RANGE = 16


def _record_translated_error(translated: dict, exc: BaseException, source: str, context: dict | None = None) -> None:
    """v0.8.1: tee the translated error into the debug log so the
    Debug pane shows it with the same code + suggestion."""
    try:
        from one_link.debug_log import get_debug_log
        get_debug_log().record(
            severity="warn" if translated.get("status", 500) < 500 else "error",
            source=source,
            code=str(translated.get("code") or "unknown"),
            message=str(translated.get("error") or str(exc)),
            context=context or {},
            suggestion=str(translated.get("hint") or ""),
            traceback_str=None,
        )
    except Exception:
        pass


def _translate_send_error(exc: BaseException) -> dict:
    """Map a raised exception from daemon.send_text / send_file into a
    user-facing response body. The goal is that no one ever sees an
    opaque '/api/send 500' toast — every failure mode here gets a
    plain-English explanation and a suggested action.

    Returns a dict with at least: {status, code, error, hint}.
    Status is the HTTP status the caller should set.
    """
    # Crypto-level mismatch: AAD or key derivation diverged between
    # peers. The single most common cause is one device running an
    # older build than the other — the v0.7.0 wire-format change
    # binds AAD to the handshake transcript, which old builds don't.
    try:
        from cryptography.exceptions import InvalidTag
    except Exception:  # pragma: no cover
        InvalidTag = ()  # type: ignore[assignment]
    if isinstance(exc, InvalidTag):
        return {
            "status": 502,
            "code": "wire_version_mismatch",
            "error": "Secure send could not complete with this device yet.",
            "hint": "Keep One Link open on both devices. It will reconnect and use the best compatible path automatically.",
        }
    msg = str(exc).lower()
    if "capability" in msg and "disabled" in msg:
        return {
            "status": 403,
            "code": "capability_disabled",
            "error": "Sending to this device is disabled in your local policy.",
            "hint": "Open the conversation header and turn on the Files (or Chat) toggle in the Allow row.",
        }
    if "rejected" in msg:
        return {
            "status": 403,
            "code": "peer_rejected",
            "error": "This device is blocked.",
            "hint": "Click Allow device above to unblock, then re-pair.",
        }
    if "handshake" in msg or "0 bytes read" in msg:
        return {
            "status": 502,
            "code": "handshake_failed",
            "error": "Could not establish a secure connection with the other device.",
            "hint": "Make sure One Link is open there. One Link will keep healing the connection in the background.",
        }
    if "timeout" in msg or "timed out" in msg:
        return {
            "status": 504,
            "code": "timeout",
            "error": "The other device didn't respond in time.",
            "hint": "Check that One Link is open and on the same network on the other device.",
        }
    if "no peer" in msg or "unreachable" in msg or "not visible" in msg:
        return {
            "status": 502,
            "code": "peer_unreachable",
            "error": "The other device is not reachable.",
            "hint": "Make sure One Link is open on the other device and on the same Wi-Fi.",
        }
    # Catch-all: still better than a bare 500. Keep the original text
    # in error_detail for diagnostics.
    return {
        "status": 500,
        "code": "send_failed",
        "error": "Send failed.",
        "hint": "Keep both devices open. One Link will retry when the path is healthy again.",
        "error_detail": str(exc),
    }


def _msg_record_to_event(rec) -> dict:
    """Convert a state.MessageRecord into the wire-shaped dict the UI expects."""
    out = {
        "t": rec.msg_type,
        "id": rec.id,
        "ts": rec.ts_ms,
        "dir": rec.direction,
        "peer_fp": rec.peer_fp,
        "peer": rec.metadata.get("short_id") or (rec.peer_fp[:8] if rec.peer_fp else "?"),
        "room_id": rec.room_id,
    }
    if rec.body is not None:
        out["body"] = rec.body
    # v0.7.5: reply_to is a first-class wire field for inline-quote.
    if getattr(rec, "reply_to", None):
        out["reply_to"] = rec.reply_to
    # v0.7.6: edit / delete state.
    if getattr(rec, "edited_at_ms", None):
        out["edited_at_ms"] = rec.edited_at_ms
    if getattr(rec, "deleted_at_ms", None):
        out["deleted_at_ms"] = rec.deleted_at_ms
        out["deleted"] = True
    # Fold metadata back into the dict (skipping the ones we already added)
    for k, v in (rec.metadata or {}).items():
        if k in ("short_id",) or k in out:
            continue
        out[k] = v
    return out


def _transfer_record_to_event(rec) -> dict:
    pct = 0.0
    if rec.total_bytes > 0:
        pct = min(100.0, max(0.0, (rec.progress_bytes / rec.total_bytes) * 100.0))
    return {
        "id": rec.id,
        "direction": rec.direction,
        "peer_fp": rec.peer_fp,
        "kind": rec.kind,
        "name": rec.name,
        "size": rec.size,
        "blob_hash": rec.blob_hash,
        "status": rec.status,
        "progress_bytes": rec.progress_bytes,
        "total_bytes": rec.total_bytes,
        "progress_pct": round(pct, 2),
        "chunks_done": rec.chunks_done,
        "chunks_total": rec.chunks_total,
        "raw_bytes": rec.raw_bytes,
        "wire_bytes": rec.wire_bytes,
        "updated_ms": rec.updated_ms,
        "metadata": rec.metadata,
    }


def _token_path() -> Path:
    return data_dir() / TOKEN_FILE


def _server_port_path() -> Path:
    return data_dir() / SERVER_PORT_FILE


class UIServer:
    """Wraps the aiohttp app + the websocket event broker."""

    def __init__(self, daemon: "Daemon"):
        self.daemon = daemon
        # Persistent token: load from disk if a previous daemon left one,
        # so any open browser tab keeps working across restarts. New
        # install → fresh token. Token is never embedded in any wire
        # protocol; it's purely for the local UI surface.
        self.token = self._load_or_create_token()
        self.app = web.Application(client_max_size=1024 * 1024 * 1024)  # 1 GiB upload
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.port: int = 0
        self._ws_clients: set[web.WebSocketResponse] = set()
        self._setup_routes()
        # v0.8.1: live-push debug-log entries to the Debug pane.
        try:
            from one_link.debug_log import get_debug_log
            get_debug_log().attach_broadcast(self._on_debug_entry)
        except Exception:
            pass

    def _on_debug_entry(self, entry: dict) -> None:
        """Bridges debug_log entries to WS clients as `debug_event`."""
        with contextlib.suppress(Exception):
            self.broadcast({"type": "debug_event", "entry": entry})

    @staticmethod
    def _load_or_create_token() -> str:
        p = _token_path()
        try:
            existing = p.read_text(encoding="utf-8").strip()
            # Tokens we generate are 43 base64url chars (32 raw bytes).
            # Be lenient on length but enforce at least 32 chars so a
            # corrupted file can't turn into an unsafe short token.
            if len(existing) >= 32 and all(
                c.isalnum() or c in "-_" for c in existing
            ):
                return existing
        except (OSError, UnicodeDecodeError):
            pass
        return secrets.token_urlsafe(32)

    # ─── routes ───────────────────────────────────────────────────────
    def _setup_routes(self) -> None:
        r = self.app.router
        r.add_get("/", self._index)
        # Static assets (logo, favicon). NOT token-gated: these are
        # required to render the page itself before the cookie is set.
        assets_dir = WEB_DIR / "assets"
        if assets_dir.is_dir():
            r.add_static("/static/", path=str(assets_dir), show_index=False)
        r.add_get("/favicon.ico", self._favicon)
        r.add_get("/api/me", self._guarded(self.api_me))
        r.add_get("/api/status", self._guarded(self.api_status))
        r.add_get("/api/settings", self._guarded(self.api_get_settings))
        r.add_post("/api/settings", self._guarded(self.api_set_settings))
        r.add_get("/api/peers", self._guarded(self.api_peers))
        r.add_post("/api/peers/prune", self._guarded(self.api_prune_peers))
        r.add_get("/api/folders", self._guarded(self.api_list_folders))
        r.add_post("/api/folders", self._guarded(self.api_add_folder))
        r.add_delete(r"/api/folders/{name}", self._guarded(self.api_remove_folder))
        r.add_post(r"/api/folders/{name}/share", self._guarded(self.api_share_folder))
        r.add_post(r"/api/folders/{name}/unshare", self._guarded(self.api_unshare_folder))
        r.add_post(r"/api/folders/{name}/sync", self._guarded(self.api_sync_folder_now))
        r.add_post(r"/api/folders/{name}/policy", self._guarded(self.api_set_folder_policy))
        r.add_get(r"/api/folders/{name}/audit", self._guarded(self.api_folder_audit))
        r.add_post(r"/api/peers/{fp}/trust", self._guarded(self.api_set_trust))
        r.add_get(r"/api/peers/{fp}/capabilities", self._guarded(self.api_get_peer_capabilities))
        r.add_post(r"/api/peers/{fp}/capabilities", self._guarded(self.api_set_peer_capabilities))
        r.add_post(r"/api/peers/{fp}/capabilities/grant", self._guarded(self.api_grant_capability))
        r.add_post(r"/api/peers/{fp}/capabilities/revoke", self._guarded(self.api_revoke_capability))
        r.add_post(r"/api/peers/{fp}/profile", self._guarded(self.api_set_peer_profile))
        # v0.7.7 verified-in-person SAS confirm.
        r.add_post(r"/api/peers/{fp}/verify", self._guarded(self.api_set_peer_verified))
        r.add_delete(r"/api/peers/{fp}/verify", self._guarded(self.api_clear_peer_verified))
        # v0.7.8 key-change events.
        r.add_get("/api/key-change-events", self._guarded(self.api_list_key_change_events))
        r.add_post(r"/api/key-change-events/{event_id}/ack", self._guarded(self.api_ack_key_change_event))
        r.add_post(r"/api/peers/{fp}/key-change-events/ack-all", self._guarded(self.api_ack_peer_key_change_events))
        r.add_get(r"/api/peers/{fp}/key-history", self._guarded(self.api_get_peer_key_history))
        # v0.8.6 trust history (merged audit timeline for one peer).
        r.add_get(r"/api/peers/{fp}/trust-history", self._guarded(self.api_get_peer_trust_history))
        # v0.8.9 folder-sync conflicts (concurrent divergent edits).
        r.add_get("/api/folder-conflicts", self._guarded(self.api_list_folder_conflicts))
        r.add_post(r"/api/folder-conflicts/{conflict_id}/resolve",
                   self._guarded(self.api_resolve_folder_conflict))
        r.add_get("/api/capability-audit", self._guarded(self.api_capability_audit))
        r.add_get("/api/rendezvous", self._guarded(self.api_get_rendezvous))
        r.add_post("/api/rendezvous", self._guarded(self.api_set_rendezvous))
        r.add_post(r"/api/peers/{fp}/pair", self._guarded(self.api_pair_init))
        r.add_post(r"/api/peers/{fp}/pair-confirm", self._guarded(self.api_pair_confirm))
        r.add_post(r"/api/peers/{fp}/pair-reject", self._guarded(self.api_pair_reject))
        r.add_get(r"/api/peers/{fp}/sas", self._guarded(self.api_get_sas))
        r.add_get("/api/messages", self._guarded(self.api_messages))
        r.add_post(r"/api/messages/{msg_id}/react", self._guarded(self.api_react_message))
        r.add_post(r"/api/messages/{msg_id}/edit", self._guarded(self.api_edit_message))
        r.add_post(r"/api/messages/{msg_id}/delete", self._guarded(self.api_delete_message))
        r.add_post(r"/api/peers/{fp}/read", self._guarded(self.api_set_read_marker))
        # v0.8.0: group endpoints.
        r.add_get("/api/groups", self._guarded(self.api_list_groups))
        r.add_post("/api/groups", self._guarded(self.api_create_group))
        r.add_get(r"/api/groups/{gid}", self._guarded(self.api_get_group))
        r.add_post(r"/api/groups/{gid}/rename", self._guarded(self.api_rename_group))
        r.add_get(r"/api/groups/{gid}/messages", self._guarded(self.api_group_messages))
        r.add_post(r"/api/groups/{gid}/send", self._guarded(self.api_send_group))
        r.add_post(
            r"/api/groups/{gid}/messages/{msg_id}/react",
            self._guarded(self.api_react_group_message),
        )
        r.add_post(
            r"/api/groups/{gid}/messages/{msg_id}/edit",
            self._guarded(self.api_edit_group_message),
        )
        r.add_post(
            r"/api/groups/{gid}/messages/{msg_id}/delete",
            self._guarded(self.api_delete_group_message),
        )
        r.add_get(r"/api/groups/{gid}/invite-link", self._guarded(self.api_group_invite_link))
        r.add_post(r"/api/groups/{gid}/members", self._guarded(self.api_add_group_member))
        r.add_delete(
            r"/api/groups/{gid}/members/{member_fp}",
            self._guarded(self.api_remove_group_member),
        )
        r.add_post(r"/api/groups/{gid}/leave", self._guarded(self.api_leave_group))
        r.add_get("/api/search", self._guarded(self.api_search))
        # v0.8.1: developer backend.
        r.add_get("/api/debug/log", self._guarded(self.api_debug_log))
        r.add_post("/api/debug/log/clear", self._guarded(self.api_debug_clear))
        r.add_get("/api/debug/health", self._guarded(self.api_debug_health))
        r.add_post("/api/send", self._guarded(self.api_send))
        r.add_post("/api/send-file", self._guarded(self.api_send_file))
        r.add_get("/api/files", self._guarded(self.api_files))
        r.add_get("/api/transfers", self._guarded(self.api_transfers))
        r.add_post("/api/transfers/prune", self._guarded(self.api_prune_transfers))
        r.add_post(r"/api/transfers/{transfer_id:.+}/retry", self._guarded(self.api_retry_transfer))
        r.add_post(r"/api/transfers/{transfer_id:.+}/cancel", self._guarded(self.api_cancel_transfer))
        r.add_post(r"/api/peers/{fp}/resume", self._guarded(self.api_resume_peer_transfers))
        r.add_get("/api/outbox", self._guarded(self.api_list_outbox))
        r.add_post(r"/api/outbox/{id:\d+}/cancel", self._guarded(self.api_cancel_outbox))
        r.add_post(r"/api/outbox/flush", self._guarded(self.api_flush_outbox))
        r.add_delete(r"/api/transfers/{transfer_id:.+}", self._guarded(self.api_delete_transfer))
        r.add_post("/api/inbox/reveal", self._guarded(self.api_inbox_reveal))
        r.add_post(r"/api/files/{name:.+}/reveal", self._guarded(self.api_file_reveal))
        # v0.9.0: text preview endpoint. Must be registered BEFORE the
        # generic download route so /preview doesn't get swallowed by
        # the {name:.+} regex.
        r.add_get(r"/api/files/{name:.+}/preview", self._guarded(self.api_file_preview))
        r.add_get(r"/api/files/{name:.+}", self._guarded(self.api_file_download))
        r.add_get("/api/audit", self._guarded(self.api_audit))
        r.add_get("/api/events", self._guarded_ws(self.ws_events))

    # ─── auth helpers ─────────────────────────────────────────────────
    def _check_token(self, request: web.Request) -> bool:
        # Accept token from cookie or Authorization header. Query tokens
        # are intentionally limited to GET / bootstrap in _index so they
        # cannot leak into API/WebSocket URLs, logs, or browser history.
        if request.cookies.get(COOKIE_NAME) == self.token:
            return True
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and auth[7:] == self.token:
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

    async def _favicon(self, request: web.Request) -> web.StreamResponse:
        ico = WEB_DIR / "assets" / "one-glyph.ico"
        if ico.is_file():
            return web.FileResponse(ico)
        png = WEB_DIR / "assets" / "one-glyph.png"
        if png.is_file():
            return web.FileResponse(png)
        return web.Response(status=404)

    # ─── HTML index ───────────────────────────────────────────────────
    async def _index(self, request: web.Request) -> web.Response:
        bootstrap_ok = request.query.get("t") == self.token
        if request.query.get("t") and not bootstrap_ok:
            return web.Response(status=401, text="unauthorized")
        try:
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
        except FileNotFoundError:
            html = "<h1>One Link UI not bundled</h1>"
        if bootstrap_ok:
            scrub = (
                "<script>"
                "try{if(location.search){history.replaceState(null,'',location.pathname+location.hash)}}"
                "catch(e){}"
                "</script>"
            )
            if "</head>" in html:
                html = html.replace("</head>", scrub + "</head>", 1)
            else:
                html += scrub
        resp = web.Response(text=html, content_type="text/html")
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if bootstrap_ok or request.cookies.get(COOKIE_NAME) == self.token:
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
        display_name = None
        if self.daemon.state is not None:
            display_name = self.daemon.state.get_setting("display_name")
        try:
            from one_link import __version__ as ol_ver
        except Exception:
            ol_ver = "?"
        try:
            from one_link.daemon import PROTOCOL_VERSION
        except Exception:
            PROTOCOL_VERSION = "?"
        schema_version = 0
        if self.daemon.state is not None:
            with contextlib.suppress(Exception):
                schema_version = self.daemon.state.schema_version()
        return web.json_response({
            "short_id": me.short_id,
            "fingerprint": me.fingerprint,
            "hostname": me.hostname,
            "display_name": display_name or me.hostname,
            "app_version": ol_ver,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": schema_version,
        })

    async def api_status(self, request: web.Request) -> web.Response:
        state = self.daemon.state
        peers = state.list_peers() if state is not None else []
        folders = state.list_folders() if state is not None else []
        transfers = state.list_transfers(limit=25) if state is not None else []
        live = self.daemon.discovery.registry.list() if self.daemon.discovery else []
        return web.json_response({
            "version": __import__("one_link").__version__,
            "app_version": __import__("one_link").__version__,
            "protocol_version": __import__("one_link.daemon").daemon.PROTOCOL_VERSION,
            "schema_version": (
                state.schema_version() if state is not None else 0
            ),
            "me": {
                "short_id": self.daemon.me.short_id,
                "fingerprint": self.daemon.me.fingerprint,
                "hostname": self.daemon.me.hostname,
            },
            "peers": {
                "known": len(peers),
                "online": len(live),
                "pinned": sum(1 for p in peers if p.trust == "pinned"),
                "rejected": sum(1 for p in peers if p.trust == "rejected"),
            },
            "folders": {
                "count": len(folders),
                "shared": sum(1 for f in folders if f["shared_with"]),
            },
            "transfers": {
                "recent": [_transfer_record_to_event(t) for t in transfers[:10]],
                "active": sum(1 for t in transfers if t.status in ("queued", "offered", "active")),
            },
            "performance": {
                "sessions": self.daemon._session_stats(),
                "cdc_cache": self.daemon._chunk_cache_stats(),
            },
        })

    # ─── /api/settings ────────────────────────────────────────────────
    async def api_get_settings(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({})
        s = self.daemon.state.all_settings()
        # v0.7.3: pair_default_allow_all defaults to TRUE — every
        # SAS-paired device gets full caps unless the user opts in
        # to deny-by-default. (Reverses the v0.7.2 audit-finding-A
        # default after user feedback that the friction wasn't
        # worth it for trusted SAS-verified peers.)
        pair_allow_all_raw = s.get("pair_default_allow_all")
        pair_allow_all = (
            pair_allow_all_raw is None
            or pair_allow_all_raw.lower() in ("1", "true", "yes")
        )
        return web.json_response({
            "display_name": s.get("display_name"),
            "auto_accept_lan": s.get("auto_accept_lan", "false") == "true",
            "pair_default_allow_all": pair_allow_all,
        })

    async def api_set_settings(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        if "display_name" in data:
            v = data["display_name"]
            if v is None or v == "":
                self.daemon.state.delete_setting("display_name")
            else:
                self.daemon.state.set_setting("display_name", str(v))
        if "auto_accept_lan" in data:
            self.daemon.state.set_setting(
                "auto_accept_lan",
                "true" if data["auto_accept_lan"] else "false",
            )
        if "pair_default_allow_all" in data:
            self.daemon.state.set_setting(
                "pair_default_allow_all",
                "true" if data["pair_default_allow_all"] else "false",
            )
        return web.json_response({"ok": True})

    # ─── /api/peers ───────────────────────────────────────────────────
    async def api_peers(self, request: web.Request) -> web.Response:
        """Merge live mDNS-discovered peers with persistent peer DB.

        v0.4 contract — the sidebar problem:

        Default response (`/api/peers`): paired peers ONLY (trust='pinned').
        That's the user's ongoing list of devices they actually talk to.
        Online or offline, pinned is what gets rendered in the sidebar.

        Discovery-modal response (`/api/peers?include_unpaired=1`): paired
        + pending unpaired. This is the picker the user opens when they
        explicitly want to add a device. Aggressive ghost collapsing
        applies here:

          - own-pubkey peers are filtered (already handled below)
          - same-host pending peers are collapsed: if N>1 entries share
            the same advertised hostname AND we recognize that hostname
            as our own, only the most-recently-seen entry survives
          - rejected peers are not returned in either mode (use
            `?include_rejected=1` if a future UI surfaces a "blocked" view)
        """
        include_unpaired = request.query.get("include_unpaired") in ("1", "true", "yes")
        include_rejected = request.query.get("include_rejected") in ("1", "true", "yes")

        live: dict[str, dict] = {}  # fingerprint -> peer record
        local_names = {self.daemon.me.hostname}
        if self.daemon.state is not None:
            try:
                display_name = self.daemon.state.get_setting("display_name")
                if display_name:
                    local_names.add(display_name)
            except Exception:
                pass
        if self.daemon.discovery:
            for p in self.daemon.discovery.registry.list():
                fp = ""
                if p.ed_pub_hex:
                    try:
                        from one_link.identity import fingerprint_of
                        fp = fingerprint_of(bytes.fromhex(p.ed_pub_hex))
                    except ValueError:
                        fp = ""
                if fp and fp == self.daemon.me.fingerprint:
                    continue
                if p.short_id == self.daemon.me.short_id:
                    continue
                same_host = p.hostname in local_names
                live[fp or p.short_id] = {
                    "short_id": p.short_id,
                    "hostname": p.hostname,
                    "address": p.address,
                    "port": p.port,
                    "ed_pub_hex": p.ed_pub_hex,
                    "fingerprint": fp,
                    "online": True,
                    "trust": "pending",  # default if no DB row yet
                    "capabilities": [],
                    "allowed_capabilities": None,
                    "same_host": same_host,
                    # v0.7.3: device kind advertised via mDNS TXT
                    # (e.g. "macos-laptop", "windows-desktop").
                    "device_kind": getattr(p, "device_kind", "") or "",
                }
        # Merge persistent state
        if self.daemon.state is not None:
            try:
                for rec in self.daemon.state.list_peers():
                    # Skip ourselves
                    if rec.fingerprint == self.daemon.me.fingerprint:
                        continue
                    if rec.fingerprint in live:
                        live[rec.fingerprint]["trust"] = rec.trust
                        live[rec.fingerprint]["capabilities"] = (
                            self.daemon.state.get_peer_capabilities(rec.fingerprint)
                        )
                        live[rec.fingerprint]["allowed_capabilities"] = (
                            self.daemon.state.get_peer_capability_policy(rec.fingerprint)
                        )
                        live[rec.fingerprint]["last_seen_ms"] = rec.last_seen_ms
                        live[rec.fingerprint]["first_seen_ms"] = rec.first_seen_ms
                        # v0.7.3: per-device profile overlays.
                        live[rec.fingerprint]["local_alias"] = rec.local_alias
                        live[rec.fingerprint]["muted"] = bool(rec.muted)
                        live[rec.fingerprint]["display_name"] = rec.display_name
                        # v0.7.7: verified-in-person trust state.
                        live[rec.fingerprint]["verified_at_ms"] = rec.verified_at_ms
                        live[rec.fingerprint]["verified_method"] = rec.verified_method
                        live[rec.fingerprint]["verified_note"] = rec.verified_note
                        live[rec.fingerprint]["is_verified"] = rec.is_verified
                    else:
                        # Pending peers in the DB but not visible on mDNS are
                        # usually stale ghosts from a previous daemon/process.
                        # Drop them — the discovery modal only shows live mDNS hits.
                        if rec.trust == "pending":
                            continue
                        live[rec.fingerprint] = {
                            "short_id": rec.short_id,
                            "hostname": rec.hostname or "(offline)",
                            "address": rec.last_address,
                            "port": rec.last_port,
                            "ed_pub_hex": (rec.pubkey.hex() if rec.pubkey else ""),
                            "fingerprint": rec.fingerprint,
                            "online": False,
                            "trust": rec.trust,
                            "capabilities": self.daemon.state.get_peer_capabilities(
                                rec.fingerprint
                            ),
                            "allowed_capabilities": self.daemon.state.get_peer_capability_policy(
                                rec.fingerprint
                            ),
                            "last_seen_ms": rec.last_seen_ms,
                            "first_seen_ms": rec.first_seen_ms,
                            # v0.7.3: per-device profile overlays.
                            "local_alias": rec.local_alias,
                            "muted": bool(rec.muted),
                            "display_name": rec.display_name,
                            # v0.7.7: verified-in-person trust state.
                            "verified_at_ms": rec.verified_at_ms,
                            "verified_method": rec.verified_method,
                            "verified_note": rec.verified_note,
                            "is_verified": rec.is_verified,
                        }
            except Exception:
                pass

        # Same-host pending collapse: if multiple pending peers advertise
        # one of our own hostnames, keep only the most-recently-seen one.
        # The rest are almost always stale daemon instances on this box
        # whose mDNS records haven't expired yet.
        by_local_hostname: dict[str, list[dict]] = {}
        for p in live.values():
            if p.get("same_host") and p.get("trust") == "pending":
                key = (p.get("hostname") or "").lower()
                by_local_hostname.setdefault(key, []).append(p)
        ghosted_keys: set[str] = set()
        for group in by_local_hostname.values():
            if len(group) <= 1:
                continue
            # Keep the freshest (highest last_seen_ms; pending records may
            # not have one, fall back to address presence + port nonzero).
            def _freshness(rec: dict) -> tuple:
                return (
                    int(rec.get("last_seen_ms") or 0),
                    1 if rec.get("address") else 0,
                    int(rec.get("port") or 0),
                )
            group.sort(key=_freshness, reverse=True)
            for stale in group[1:]:
                ghosted_keys.add(stale.get("fingerprint") or stale.get("short_id"))

        # Filter according to mode + ghost collapse.
        # Order matters: rejected gets its own gate so include_rejected
        # works independently of include_unpaired.
        def _keep(p: dict) -> bool:
            key = p.get("fingerprint") or p.get("short_id")
            if key in ghosted_keys:
                return False
            trust = p.get("trust")
            if trust == "rejected":
                return include_rejected
            if trust == "pinned":
                return True
            # Pending: only in modal mode, and only if currently online
            if not include_unpaired:
                return False
            return bool(p.get("online"))

        kept = [p for p in live.values() if _keep(p)]

        # v0.5.6: stamp connection regime per peer. Outbound session
        # regime (most authoritative — that's the path our chat sends
        # would actually take). Falls back to inbound regime if we've
        # only received from the peer. Otherwise, classify by
        # peer.address (lan/internet) for online peers, or "offline".
        outbound = getattr(self.daemon, "_outbound_sessions", {}) or {}
        inbound = getattr(self.daemon, "_inbound_regime", {}) or {}
        from one_link.daemon import _classify_address_regime
        for p in kept:
            fp = p.get("fingerprint") or ""
            sess = outbound.get(fp)
            if sess is not None and getattr(sess, "regime", None):
                p["regime"] = sess.regime
            elif fp in inbound:
                p["regime"] = inbound[fp]
            elif p.get("online"):
                p["regime"] = _classify_address_regime(p.get("address") or "")
            else:
                p["regime"] = "offline"
            # v0.7.x: surface the peer's advertised app_version (from
            # CAPS) so the UI can warn before a wire-mismatch turns into
            # an opaque InvalidTag. None until first CAPS exchange.
            p["app_version"] = None
            peer_features = []
            if sess is not None:
                ch = getattr(sess, "channel", None)
                if ch is not None and getattr(ch, "peer_caps", None):
                    p["app_version"] = ch.peer_caps.get("app_version")
                    peer_features = ch.peer_caps.get("features") or []
            try:
                from one_link import __version__ as _local_app_version
                from one_link.capabilities import LOCAL_CAPABILITIES
                from one_link.protocol_compat import fallback_order, negotiate
                compat = negotiate(
                    local_version=_local_app_version,
                    peer_version=p.get("app_version"),
                    local_capabilities=LOCAL_CAPABILITIES,
                    peer_capabilities=peer_features,
                )
                p["compatibility"] = {
                    "compatible": compat.compatible,
                    "mode": compat.mode,
                    "transfer_mode": compat.transfer_mode,
                    "fallback_order": list(fallback_order(compat)),
                    "reasons": list(compat.reasons),
                }
            except Exception:
                p["compatibility"] = None
            # v0.7.0: per-pairing health metrics. last_alive_ms is wall-
            # clock time of the last bytes seen from this peer (in or
            # out). latency_ewma_ms is the rolling round-trip time
            # measured by the H4 PING/PONG probe. Both None for
            # never-contacted peers.
            health = getattr(self.daemon, "get_pair_health", lambda _fp: None)(fp)
            if health is not None:
                p["health"] = {
                    "last_alive_ms": health.get("last_alive_ms"),
                    "latency_ewma_ms": (
                        health.get("latency_ewma_ms")
                        if health.get("latency_ewma_ms") == health.get("latency_ewma_ms")
                        else None  # NaN guard
                    ),
                }
            else:
                p["health"] = None

        # v0.7.8: attach unacked key-change events per peer so the UI
        # can render a red badge / banner without a second round-trip.
        # `key_change_alert` carries the freshest unacked event (or
        # None) for direct rendering.
        if self.daemon.state is not None:
            try:
                # One bulk fetch — bucket by new_fingerprint client-side.
                unacked = self.daemon.state.list_key_change_events(
                    unacked_only=True, limit=1000,
                )
                by_fp: dict[str, list[dict]] = {}
                for ev in unacked:
                    by_fp.setdefault(ev["new_fingerprint"], []).append(ev)
                for p in kept:
                    fp = p.get("fingerprint") or ""
                    bucket = by_fp.get(fp, [])
                    p["key_change_unacked"] = len(bucket)
                    p["key_change_alert"] = bucket[0] if bucket else None
            except Exception:
                for p in kept:
                    p.setdefault("key_change_unacked", 0)
                    p.setdefault("key_change_alert", None)
        # Sort: paired first, then online, then by hostname
        peers = sorted(
            kept,
            key=lambda p: (
                p.get("trust") != "pinned",
                not p.get("online"),
                (p.get("hostname") or "").lower(),
            ),
        )
        return web.json_response({"peers": peers})

    # ─── POST /api/peers/prune ────────────────────────────────────────
    async def api_prune_peers(self, request: web.Request) -> web.Response:
        """Force a TCP-probe of every discovered peer; remove unreachable.
        Surfaces the same prune the daemon runs every 20s in the background,
        so the user can trigger an immediate cleanup."""
        if not self.daemon.discovery:
            return web.json_response({"removed": 0})
        before = len(self.daemon.discovery.registry.peers)
        try:
            removed = await self.daemon.discovery.prune_unreachable(timeout=0.5)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        after = len(self.daemon.discovery.registry.peers)
        return web.json_response({"removed": removed, "before": before, "after": after})

    # ─── /api/folders ─────────────────────────────────────────────────
    async def api_list_folders(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"folders": []})
        out = []
        for f in self.daemon.state.list_folders():
            entries = self.daemon.state.list_manifest(f["name"]) if self.daemon.folder_engine else []
            local = sum(1 for e in entries if e["blob_hash"] is not None)
            in_store = 0
            if self.daemon.blob_store:
                in_store = sum(
                    1 for e in entries
                    if e["blob_hash"] and self.daemon.blob_store.has(e["blob_hash"])
                )
            out.append({
                "name": f["name"],
                "local_path": f["local_path"],
                "shared_with": f["shared_with"],
                "peer_permissions": {
                    fp: self.daemon.state.get_folder_peer_permission(f["name"], fp)
                    for fp in f["shared_with"]
                },
                "created_ms": f["created_ms"],
                "files": local,
                "in_store": in_store,
            })
        return web.json_response({"folders": out})

    async def api_add_folder(self, request: web.Request) -> web.Response:
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        name = (data.get("name") or "").strip()
        local_path = (data.get("local_path") or "").strip()
        shared_with = data.get("shared_with") or []
        if not name or not local_path:
            return web.json_response(
                {"error": "name and local_path required"}, status=400,
            )
        if not isinstance(shared_with, list):
            return web.json_response(
                {"error": "shared_with must be a list of fingerprints"}, status=400,
            )
        # v0.7.2 sandbox optionals
        max_file_bytes = data.get("max_file_bytes")
        if max_file_bytes is not None and (
            not isinstance(max_file_bytes, int) or max_file_bytes < 0
        ):
            return web.json_response(
                {"error": "max_file_bytes must be a non-negative integer or null"},
                status=400,
            )
        ignored_patterns = data.get("ignored_patterns") or []
        if not isinstance(ignored_patterns, list):
            return web.json_response(
                {"error": "ignored_patterns must be a list of strings"}, status=400,
            )
        conflict_policy = data.get("conflict_policy", "latest-wins")
        if conflict_policy not in ("latest-wins", "local-priority", "peer-priority"):
            return web.json_response(
                {"error": f"invalid conflict_policy: {conflict_policy!r}"},
                status=400,
            )
        try:
            f = self.daemon.folder_engine.add_folder(
                name=name,
                local_path=Path(local_path),
                shared_with=[str(fp) for fp in shared_with],
                max_file_bytes=max_file_bytes,
                ignored_patterns=[str(p) for p in ignored_patterns],
                conflict_policy=conflict_policy,
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=409)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        # v0.7.1: every fp in shared_with gets folder caps auto-granted.
        for fp in shared_with:
            self._ensure_folder_caps_for(str(fp), note=f"folder={name}/add")
        return web.json_response({"ok": True, "folder": f})

    def _ensure_folder_caps_for(self, peer_fp: str, *, note: str = "") -> None:
        """v0.7.1: explicit user share = positive consent for folder
        traffic. Add FOLDER_SYNC + MERKLE_SYNC to the peer's policy
        allowlist so the deny-by-default gate doesn't block the
        immediately-following MANIFEST_PUSH/WANTS frames."""
        if self.daemon.state is None or not peer_fp:
            return
        try:
            from one_link.capabilities import FOLDER_SYNC, MERKLE_SYNC
            current = self.daemon.state.get_peer_capability_policy(peer_fp)
            if current is None:
                return  # policy=None means "default-allow legacy" — nothing to add
            wanted = set(current) | {FOLDER_SYNC, MERKLE_SYNC}
            if wanted == set(current):
                return
            new_policy = sorted(wanted)
            self.daemon.state.set_peer_capability_policy(
                peer_fp, new_policy,
                actor="ui-share-folder", note=note,
            )
            self.broadcast({
                "type": "peer_capabilities",
                "fingerprint": peer_fp,
                "allowed": new_policy,
            })
        except Exception:
            pass

    async def api_remove_folder(self, request: web.Request) -> web.Response:
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        name = request.match_info["name"]
        try:
            self.daemon.folder_engine.remove_folder(name)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        return web.json_response({"ok": True})

    async def api_share_folder(self, request: web.Request) -> web.Response:
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        name = request.match_info["name"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        peer_fp = (data.get("peer_fp") or "").strip()
        mode = (data.get("mode") or "rw").strip()
        if not peer_fp:
            return web.json_response({"error": "peer_fp required"}, status=400)
        if mode not in ("push", "pull", "rw"):
            return web.json_response(
                {"error": "mode must be push, pull, or rw"}, status=400,
            )
        try:
            self.daemon.folder_engine.share_with(name, peer_fp, mode=mode)
        except KeyError as e:
            return web.json_response({"error": str(e)}, status=404)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        # v0.7.1 deny-by-default: sharing a folder = user consent for
        # folder/merkle traffic with this peer.
        self._ensure_folder_caps_for(
            peer_fp, note=f"folder={name}/share/{mode}",
        )
        return web.json_response({"ok": True})

    async def api_unshare_folder(self, request: web.Request) -> web.Response:
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        name = request.match_info["name"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        peer_fp = (data.get("peer_fp") or "").strip()
        if not peer_fp:
            return web.json_response({"error": "peer_fp required"}, status=400)
        try:
            self.daemon.folder_engine.unshare_with(name, peer_fp)
        except KeyError as e:
            return web.json_response({"error": str(e)}, status=404)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        return web.json_response({"ok": True})

    async def api_set_folder_policy(self, request: web.Request) -> web.Response:
        """v0.7.2: update sandbox policy on a folder.
        Body: { max_file_bytes?, ignored_patterns?, conflict_policy? }
        Each field is optional; only the supplied ones are written."""
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        name = request.match_info["name"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        if "max_file_bytes" in data:
            v = data["max_file_bytes"]
            if v is not None and (not isinstance(v, int) or v < 0):
                return web.json_response(
                    {"error": "max_file_bytes must be a non-negative integer or null"},
                    status=400,
                )
            try:
                self.daemon.state.set_folder_max_file_bytes(name, v)
            except KeyError as e:
                return web.json_response({"error": str(e)}, status=404)
        if "ignored_patterns" in data:
            v = data["ignored_patterns"]
            if not isinstance(v, list):
                return web.json_response(
                    {"error": "ignored_patterns must be a list of strings"},
                    status=400,
                )
            try:
                self.daemon.state.set_folder_ignored_patterns(name, v)
            except KeyError as e:
                return web.json_response({"error": str(e)}, status=404)
        if "conflict_policy" in data:
            try:
                self.daemon.state.set_folder_conflict_policy(
                    name, str(data["conflict_policy"])
                )
            except KeyError as e:
                return web.json_response({"error": str(e)}, status=404)
            except ValueError as e:
                return web.json_response({"error": str(e)}, status=400)
        return web.json_response({
            "ok": True, "folder": self.daemon.state.get_folder(name),
        })

    async def api_folder_audit(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        name = request.match_info["name"]
        f = self.daemon.state.get_folder(name)
        if not f:
            return web.json_response({"error": "no such folder"}, status=404)
        peer_fp = request.query.get("peer_fp") or None
        action_filter = request.query.get("action") or None
        actions = [action_filter] if action_filter else None
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        events = self.daemon.state.list_folder_audit(
            folder_name=name, peer_fp=peer_fp, actions=actions, limit=limit,
        )
        return web.json_response({
            "folder": name, "root_id": f.get("root_id"),
            "events": events,
        })

    async def api_sync_folder_now(self, request: web.Request) -> web.Response:
        """Force an immediate sync cycle for one folder. Used by the UI 'sync now' button."""
        if self.daemon.state is None or self.daemon.folder_engine is None:
            return web.json_response(
                {"error": "folder sync not initialized"}, status=503,
            )
        name = request.match_info["name"]
        f = self.daemon.state.get_folder(name)
        if not f:
            return web.json_response({"error": "no such folder"}, status=404)
        results = []
        for peer_fp in f["shared_with"]:
            if not self.daemon._is_pinned(peer_fp):
                results.append({"peer_fp": peer_fp, "status": "not_pinned"})
                continue
            peer = None
            if self.daemon.discovery:
                for p in self.daemon.discovery.registry.list():
                    cand = self.daemon._peer_fp_from_peer(p)
                    if cand == peer_fp:
                        peer = p
                        break
            if peer is None:
                results.append({"peer_fp": peer_fp, "status": "offline"})
                continue
            try:
                r = await self.daemon.push_folder_to_peer(peer, name)
                results.append({"peer_fp": peer_fp, "status": "pushed", **r})
            except Exception as e:
                results.append({"peer_fp": peer_fp, "status": "error", "error": str(e)})
        return web.json_response({"ok": True, "results": results})

    # ─── POST /api/peers/{fp}/trust ───────────────────────────────────
    async def api_set_trust(self, request: web.Request) -> web.Response:
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        trust = data.get("trust")
        if trust not in ("pinned", "pending", "rejected"):
            return web.json_response(
                {"error": "trust must be one of: pinned, pending, rejected"},
                status=400,
            )
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)

        # If this peer isn't in the DB yet, try to auto-populate from mDNS
        # discovery info. This lets the user accept/block a peer they've
        # only seen via discovery, without first having to message them.
        if not self.daemon.state.get_peer(fp):
            seeded = False
            if self.daemon.discovery:
                from one_link.identity import fingerprint_of
                for p in self.daemon.discovery.registry.list():
                    if not p.ed_pub_hex:
                        continue
                    try:
                        pub = bytes.fromhex(p.ed_pub_hex)
                    except ValueError:
                        continue
                    if fingerprint_of(pub) == fp:
                        self.daemon.state.upsert_peer(
                            fingerprint=fp,
                            short_id=p.short_id,
                            pubkey=pub,
                            hostname=p.hostname,
                            address=p.address,
                            port=p.port,
                        )
                        seeded = True
                        break
            if not seeded:
                return web.json_response(
                    {"error": "peer not seen on the LAN (mDNS-stale or unknown)"},
                    status=404,
                )

        try:
            # v0.7.0: rejection is a unified tear-down (drop session,
            # cancel transfers, clear group chains). Pinning + pending
            # are simple state writes.
            if trust == "rejected":
                await self.daemon.revoke_peer(fp, actor="ui")
            else:
                self.daemon.state.set_peer_trust(fp, trust, actor="ui")
                self.broadcast({"type": "peer_trust", "fingerprint": fp, "trust": trust})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)
        return web.json_response({"ok": True, "trust": trust})

    async def api_get_peer_capabilities(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        return web.json_response({
            "fingerprint": fp,
            "advertised": self.daemon.state.get_peer_capabilities(fp),
            "allowed": self.daemon.state.get_peer_capability_policy(fp),
        })

    async def api_set_peer_capabilities(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        allowed = data.get("allowed")
        note = data.get("note") if isinstance(data.get("note"), str) else None
        if allowed is None:
            self.daemon.state.clear_peer_capability_policy(fp, actor="ui", note=note)
            return web.json_response({"ok": True, "fingerprint": fp, "allowed": None})
        if not isinstance(allowed, list):
            return web.json_response({"error": "allowed must be a list or null"}, status=400)
        from one_link.capabilities import LOCAL_CAPABILITIES, normalize_caps
        clean = [c for c in normalize_caps(allowed) if c in LOCAL_CAPABILITIES]
        self.daemon.state.set_peer_capability_policy(fp, clean, actor="ui", note=note)
        return web.json_response({"ok": True, "fingerprint": fp, "allowed": clean})

    async def api_grant_capability(self, request: web.Request) -> web.Response:
        """v0.7.1: cap-by-cap grant. Adds a single capability to the
        peer's policy allowlist (creates the policy if absent). Used
        by the UI to respond to a `capability_request` WS event."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        cap = data.get("cap") or data.get("capability")
        note = data.get("note") if isinstance(data.get("note"), str) else None
        from one_link.capabilities import LOCAL_CAPABILITIES, normalize_caps
        if not isinstance(cap, str) or cap not in LOCAL_CAPABILITIES:
            return web.json_response(
                {"error": f"unknown capability: {cap!r}"}, status=400
            )
        current = self.daemon.state.get_peer_capability_policy(fp) or []
        if cap in current:
            return web.json_response({
                "ok": True, "fingerprint": fp,
                "allowed": current, "added": False,
            })
        new_policy = sorted(set(current) | {cap})
        self.daemon.state.set_peer_capability_policy(
            fp, new_policy, actor="ui-grant", note=note,
        )
        self.broadcast({
            "type": "peer_capabilities",
            "fingerprint": fp,
            "allowed": new_policy,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "allowed": new_policy, "added": True,
        })

    async def api_revoke_capability(self, request: web.Request) -> web.Response:
        """v0.7.1: cap-by-cap revoke. Removes a single capability from
        the peer's policy allowlist. If the policy becomes empty, it
        stays as an explicit empty list (different from None) so the
        peer is denied everything until re-granted."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        cap = data.get("cap") or data.get("capability")
        note = data.get("note") if isinstance(data.get("note"), str) else None
        if not isinstance(cap, str):
            return web.json_response(
                {"error": "cap must be a string"}, status=400
            )
        current = self.daemon.state.get_peer_capability_policy(fp) or []
        if cap not in current:
            return web.json_response({
                "ok": True, "fingerprint": fp,
                "allowed": current, "removed": False,
            })
        new_policy = sorted(set(current) - {cap})
        self.daemon.state.set_peer_capability_policy(
            fp, new_policy, actor="ui-revoke", note=note,
        )
        self.broadcast({
            "type": "peer_capabilities",
            "fingerprint": fp,
            "allowed": new_policy,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "allowed": new_policy, "removed": True,
        })

    async def api_set_peer_profile(self, request: web.Request) -> web.Response:
        """v0.7.3: update per-device profile fields. Body keys are
        all optional; missing keys leave the field unchanged.
          - local_alias: string or null (clears alias)
          - muted: bool"""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        rec = self.daemon.state.get_peer(fp)
        if rec is None:
            return web.json_response({"error": "peer not found"}, status=404)
        kwargs: dict = {}
        if "local_alias" in data:
            v = data["local_alias"]
            if v is not None and not isinstance(v, str):
                return web.json_response(
                    {"error": "local_alias must be a string or null"},
                    status=400,
                )
            if isinstance(v, str) and len(v) > 64:
                return web.json_response(
                    {"error": "local_alias too long (max 64 chars)"},
                    status=400,
                )
            kwargs["local_alias"] = v
        if "muted" in data:
            v = data["muted"]
            if not isinstance(v, bool):
                return web.json_response(
                    {"error": "muted must be true or false"}, status=400,
                )
            kwargs["muted"] = v
        if not kwargs:
            return web.json_response({"error": "no fields to update"}, status=400)
        updated = self.daemon.state.set_peer_profile(fp, **kwargs)
        # Broadcast so every open tab refreshes its sidebar / drawer.
        self.broadcast({
            "type": "peer_profile",
            "fingerprint": fp,
            "local_alias": updated.local_alias if updated else None,
            "muted": bool(updated.muted) if updated else False,
            "display_name": updated.display_name if updated else None,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "local_alias": updated.local_alias if updated else None,
            "muted": bool(updated.muted) if updated else False,
            "display_name": updated.display_name if updated else None,
        })

    async def api_set_peer_verified(self, request: web.Request) -> web.Response:
        """v0.7.7: mark a peer as verified-in-person.
        POST body: {method: 'sas-digits'|'sas-qr'|'sas-audio'|'manual',
                    note?: string}
        Verification is a side-channel claim — the daemon takes the
        user's word for it (the protocol cannot prove the user
        actually compared SAS values). The audit trail (capability_audit
        with kind='verify_set') is the forensic record."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        method = data.get("method")
        if not isinstance(method, str) or not method:
            return web.json_response(
                {"error": "method required (sas-digits|sas-qr|sas-audio|manual)"},
                status=400,
            )
        note_raw = data.get("note")
        if note_raw is not None and not isinstance(note_raw, str):
            return web.json_response(
                {"error": "note must be a string or null"}, status=400,
            )
        try:
            updated = self.daemon.state.set_peer_verified(
                fp, method=method, note=note_raw, actor="ui",
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if updated is None:
            return web.json_response({"error": "peer not found"}, status=404)
        self.broadcast({
            "type": "peer_verified",
            "fingerprint": fp,
            "verified_at_ms": updated.verified_at_ms,
            "verified_method": updated.verified_method,
            "verified_note": updated.verified_note,
            "is_verified": updated.is_verified,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "verified_at_ms": updated.verified_at_ms,
            "verified_method": updated.verified_method,
            "verified_note": updated.verified_note,
            "is_verified": updated.is_verified,
        })

    async def api_clear_peer_verified(self, request: web.Request) -> web.Response:
        """v0.7.7: revoke a verified-in-person mark. Idempotent
        when not verified; 404 only when the peer doesn't exist."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        # Body is optional — supports {note: "rotated keys"} for a
        # human-readable reason captured in the audit log.
        note: Optional[str] = None
        if request.can_read_body:
            try:
                data = await request.json()
                if isinstance(data, dict):
                    raw = data.get("note")
                    if isinstance(raw, str):
                        note = raw.strip() or None
            except Exception:
                pass
        updated = self.daemon.state.clear_peer_verified(
            fp, actor="ui", note=note,
        )
        if updated is None:
            return web.json_response({"error": "peer not found"}, status=404)
        self.broadcast({
            "type": "peer_verified",
            "fingerprint": fp,
            "verified_at_ms": None,
            "verified_method": None,
            "verified_note": None,
            "is_verified": False,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "verified_at_ms": None,
            "verified_method": None,
            "verified_note": None,
            "is_verified": False,
        })

    # ─── key-change events (v0.7.8) ───────────────────────────────────

    async def api_list_key_change_events(self, request: web.Request) -> web.Response:
        """List recorded key-change (hostname-rotated-pubkey) events.
        Query params:
          - unacked=1 → only show events the user hasn't dismissed
          - peer={fp} → only events targeting this fingerprint
          - limit (default 200, capped at 1000)"""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        unacked_only = request.query.get("unacked") in ("1", "true", "yes")
        new_fp = request.query.get("peer") or None
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        events = self.daemon.state.list_key_change_events(
            unacked_only=unacked_only,
            new_fingerprint=new_fp,
            limit=limit,
        )
        return web.json_response({"events": events})

    async def api_ack_key_change_event(self, request: web.Request) -> web.Response:
        """Dismiss one key-change event by id."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            event_id = int(request.match_info["event_id"])
        except (KeyError, ValueError):
            return web.json_response({"error": "invalid event id"}, status=400)
        acked = self.daemon.state.ack_key_change_event(event_id)
        if acked:
            self.broadcast({"type": "key_change_acked", "event_id": event_id})
        return web.json_response({"ok": True, "event_id": event_id, "newly_acked": acked})

    async def api_ack_peer_key_change_events(self, request: web.Request) -> web.Response:
        """Dismiss every unacked event targeting one peer (the device
        drawer's 'Acknowledge' button). Returns the count just acked."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        n = self.daemon.state.ack_all_key_change_events_for(fp)
        if n:
            self.broadcast({
                "type": "key_change_acked_all",
                "fingerprint": fp, "acked": n,
            })
        return web.json_response({"ok": True, "fingerprint": fp, "acked": n})

    async def api_get_peer_key_history(self, request: web.Request) -> web.Response:
        """Return every (ed_pub_hex, fingerprint, first_seen, last_seen)
        ever observed for the peer's hostname. Used by the device
        drawer's Identity & trust → Key history disclosure."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        peer = self.daemon.state.get_peer(fp)
        if peer is None:
            return web.json_response({"error": "peer not found"}, status=404)
        if not peer.hostname:
            return web.json_response({"hostname": None, "history": []})
        history = self.daemon.state.list_hostname_keys(peer.hostname)
        return web.json_response({"hostname": peer.hostname, "history": history})

    async def api_get_peer_trust_history(self, request: web.Request) -> web.Response:
        """v0.8.6: merged trust timeline for one peer (capability_audit
        + key_change_events + first-seen + key history). Read-only;
        the UI renders this as a chronological list in the device
        drawer's 'Trust history' disclosure."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        peer = self.daemon.state.get_peer(fp)
        if peer is None:
            return web.json_response({"error": "peer not found"}, status=404)
        events = self.daemon.state.peer_trust_history(fp, limit=limit)
        return web.json_response({
            "fingerprint": fp,
            "hostname": peer.hostname,
            "events": events,
        })

    async def api_list_folder_conflicts(self, request: web.Request) -> web.Response:
        """v0.8.9: list manifest conflicts. Query params:
          - folder=name → only this folder
          - unresolved=1 → only unresolved
          - limit (default 200, capped at 1000)"""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        folder_name = request.query.get("folder") or None
        unresolved_only = request.query.get("unresolved") in ("1", "true", "yes")
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        conflicts = self.daemon.state.list_manifest_conflicts(
            folder_name=folder_name,
            unresolved_only=unresolved_only,
            limit=limit,
        )
        # Counter so the UI can show a badge without re-querying.
        unresolved_total = self.daemon.state.count_unresolved_manifest_conflicts()
        return web.json_response({
            "conflicts": conflicts,
            "unresolved_total": unresolved_total,
        })

    async def api_resolve_folder_conflict(self, request: web.Request) -> web.Response:
        """v0.8.9: resolve one manifest conflict.
        Body: {choice: 'mine'|'theirs'|'both'}.
        Idempotent — re-resolving an already-resolved conflict returns
        ok=false / already_resolved=true."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        if self.daemon.folder_engine is None:
            return web.json_response({"error": "folder sync not available"}, status=503)
        try:
            cid = int(request.match_info["conflict_id"])
        except (KeyError, ValueError):
            return web.json_response({"error": "invalid conflict id"}, status=400)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        choice = data.get("choice")
        if choice not in ("mine", "theirs", "both"):
            return web.json_response(
                {"error": "choice must be mine|theirs|both"}, status=400,
            )
        try:
            result = self.daemon.folder_engine.resolve_conflict(
                conflict_id=cid, choice=choice,
            )
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            return web.json_response(
                {"error": f"resolve failed: {e}"}, status=500,
            )
        # Live-broadcast so every open tab clears the badge.
        self.broadcast({
            "type": "folder_conflict_resolved",
            "conflict_id": cid,
            "resolution": choice,
            "folder_name": result.get("folder_name"),
        })
        return web.json_response(result)

    async def api_capability_audit(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.query.get("fp")
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        rows = self.daemon.state.recent_capability_audit(
            fingerprint=fp, limit=limit
        )
        return web.json_response({"events": rows})

    # ─── /api/rendezvous (v0.5.1) ─────────────────────────────────────
    async def api_get_rendezvous(self, request: web.Request) -> web.Response:
        """Report the daemon's current rendezvous status:
          - configured URLs
          - active client (running yes/no)
          - last self-observation per URL (so the user can confirm
            the rendezvous saw the right public IP)."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        urls = self.daemon.state.get_rendezvous_urls()
        observed: dict[str, dict] = {}
        if self.daemon.rendezvous is not None:
            for url, obs in self.daemon.rendezvous.observed_self.items():
                observed[url] = {
                    "observed_host": obs.observed_host,
                    "observed_port": obs.observed_port,
                    "expires_at_ms": obs.expires_at_ms,
                    "server_time_ms": obs.server_time_ms,
                }
        return web.json_response({
            "urls": urls,
            "active": self.daemon.rendezvous is not None,
            "observed_self": observed,
        })

    async def api_set_rendezvous(self, request: web.Request) -> web.Response:
        """Update the rendezvous URL list and apply *immediately* —
        no daemon restart required. The daemon revokes its existing
        registrations, drops the old client, and starts a fresh one
        against the new URL set. Empty list disables rendezvous
        entirely (LAN-only mode)."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        urls = data.get("urls")
        if urls is None or not isinstance(urls, list):
            return web.json_response({"error": "urls must be a list"}, status=400)
        if not all(isinstance(u, str) for u in urls):
            return web.json_response({"error": "urls must be a list of strings"}, status=400)
        try:
            self.daemon.state.set_rendezvous_urls(urls)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        # Live re-config — no restart. Applies the new URL list on the
        # running daemon.
        applied = self.daemon.state.get_rendezvous_urls()
        try:
            await self.daemon.update_rendezvous_urls(applied)
        except Exception as e:
            log.exception("rendezvous live re-config failed")
            return web.json_response({
                "ok": False,
                "urls": applied,
                "error": f"saved but failed to apply: {e}",
            }, status=500)
        return web.json_response({
            "ok": True,
            "urls": applied,
            "active": self.daemon.rendezvous is not None,
        })

    # ─── pairing ──────────────────────────────────────────────────────
    def _resolve_peer_for_pairing(self, fp: str):
        """Find a Peer object whose fingerprint matches `fp`. Pulls from
        live mDNS discovery; pairing requires the peer to be reachable."""
        if not self.daemon.discovery:
            return None
        from one_link.identity import fingerprint_of
        for p in self.daemon.discovery.registry.list():
            if not p.ed_pub_hex:
                continue
            try:
                pub = bytes.fromhex(p.ed_pub_hex)
            except ValueError:
                continue
            if fingerprint_of(pub) == fp:
                return p
        return None

    async def api_get_sas(self, request: web.Request) -> web.Response:
        """Return the SAS for a peer (deterministic — both sides see same)."""
        fp = request.match_info["fp"]
        peer = self._resolve_peer_for_pairing(fp)
        if peer is None:
            return web.json_response({"error": "peer not visible on LAN"}, status=404)
        from one_link.pairing import compute_sas, format_sas
        sas = compute_sas(self.daemon.me.public_bytes, bytes.fromhex(peer.ed_pub_hex))
        return web.json_response({"sas": sas, "formatted": format_sas(sas)})

    async def api_pair_init(self, request: web.Request) -> web.Response:
        fp = request.match_info["fp"]
        peer = self._resolve_peer_for_pairing(fp)
        if peer is None:
            return web.json_response({"error": "peer not visible on LAN"}, status=404)
        try:
            sas = await self.daemon.initiate_pair(peer)
        except Exception as e:
            log.exception("pair init failed")
            return web.json_response({"error": str(e)}, status=500)
        from one_link.pairing import format_sas
        return web.json_response({"ok": True, "sas": sas, "formatted": format_sas(sas)})

    async def api_pair_confirm(self, request: web.Request) -> web.Response:
        fp = request.match_info["fp"]
        peer = self._resolve_peer_for_pairing(fp)
        if peer is None:
            return web.json_response({"error": "peer not visible on LAN"}, status=404)
        try:
            result = await self.daemon.confirm_pair(peer)
            return web.json_response({"ok": True, **result})
        except Exception as e:
            log.exception("pair confirm failed")
            return web.json_response({"error": str(e)}, status=500)

    async def api_pair_reject(self, request: web.Request) -> web.Response:
        fp = request.match_info["fp"]
        peer = self._resolve_peer_for_pairing(fp)
        if peer is None:
            # Even if peer isn't reachable, we can still mark them rejected.
            if self.daemon.state and self.daemon.state.get_peer(fp):
                self.daemon.state.set_peer_trust(fp, "rejected", actor="ui")
            return web.json_response({"ok": True, "note": "peer offline; marked rejected locally"})
        try:
            await self.daemon.reject_pair(peer)
        except Exception as e:
            log.warning("pair reject send failed (still locally rejected): %s", e)
        return web.json_response({"ok": True})

    # ─── /api/messages ────────────────────────────────────────────────
    async def api_messages(self, request: web.Request) -> web.Response:
        """Return recent messages from sqlite, ordered chronologically.

        Query params:
            peer   — filter by peer short_id (UI-friendly) or fingerprint
            room   — filter by room id
            limit  — max messages (default 200, hard cap 5000)
        """
        peer_q = request.query.get("peer")
        room_q = request.query.get("room")
        try:
            limit = max(1, min(int(request.query.get("limit", "200")), 5000))
        except ValueError:
            limit = 200

        if self.daemon.state is None:
            return web.json_response({"messages": []})

        # Resolve short_id-or-prefix → fingerprint if needed.
        peer_fp: Optional[str] = None
        if peer_q:
            # If exact 64-hex BLAKE3 fingerprint, use directly.
            if len(peer_q) == 64 and all(c in "0123456789abcdef" for c in peer_q):
                peer_fp = peer_q
            else:
                # Try short_id lookup.
                rec = self.daemon.state.get_peer_by_short_id(peer_q)
                if rec:
                    peer_fp = rec.fingerprint
                else:
                    # Fallback: scan peer list for a prefix match.
                    for p in self.daemon.state.list_peers():
                        if p.short_id.startswith(peer_q):
                            peer_fp = p.fingerprint
                            break

        recs = self.daemon.state.recent_messages(
            peer_fp=peer_fp, room_id=room_q, limit=limit
        )
        msgs = [_msg_record_to_event(r) for r in recs]
        # v0.7.5: bulk-fetch reactions for the returned messages so
        # the UI can render the chip row in one shot.
        try:
            ids = [m.get("id") for m in msgs if m.get("id")]
            reactions = self.daemon.state.list_reactions_for_messages(ids)
        except Exception:
            reactions = {}
        for m in msgs:
            r = reactions.get(m.get("id"))
            if r:
                m["reactions"] = r
        return web.json_response({"messages": msgs})

    async def api_react_message(self, request: web.Request) -> web.Response:
        """v0.7.5: add or remove an emoji reaction on a message.
        Body: {emoji: str, op: "add"|"remove", peer: short_id_or_fp}
        Sends a REACTION frame to the peer that authored the
        message (so they can render the reaction in their UI too)
        and persists locally."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        msg_id = request.match_info["msg_id"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        emoji = data.get("emoji")
        op = data.get("op", "add")
        peer_needle = data.get("peer")
        if not isinstance(emoji, str) or not emoji or len(emoji) > 64:
            return web.json_response(
                {"error": "emoji must be a non-empty short string"},
                status=400,
            )
        if op not in ("add", "remove"):
            return web.json_response(
                {"error": "op must be 'add' or 'remove'"}, status=400,
            )
        # Resolve target peer. The frontend should pass the
        # conversation peer — that's whose copy of the message we're
        # reacting to.
        peer = None
        if peer_needle:
            peer = await self.daemon.resolve_for_send(str(peer_needle))
        if peer is None:
            # Persist locally even if peer is offline; the reaction
            # will reach them next time they're online via outbox-
            # style retry isn't implemented for reactions yet, so
            # this is best-effort.
            try:
                if op == "add":
                    self.daemon.state.record_reaction(
                        target_msg_id=msg_id,
                        peer_fp=self.daemon.me.fingerprint,
                        emoji=emoji,
                    )
                else:
                    self.daemon.state.remove_reaction(
                        target_msg_id=msg_id,
                        peer_fp=self.daemon.me.fingerprint,
                        emoji=emoji,
                    )
            except Exception as e:
                return web.json_response({"error": str(e)}, status=400)
            self.broadcast({
                "type": "reaction",
                "target": msg_id,
                "peer_fp": self.daemon.me.fingerprint,
                "emoji": emoji,
                "op": op,
            })
            return web.json_response({"ok": True, "delivered": False})
        try:
            await self.daemon.send_reaction(
                peer, target_msg_id=msg_id, emoji=emoji, op=op,
            )
            return web.json_response({"ok": True, "delivered": True})
        except Exception as e:
            log.warning("send_reaction failed: %s", e)
            translated = _translate_send_error(e)
            _record_translated_error(translated, e, source="server.api")
            return web.json_response(translated, status=translated["status"])

    async def api_edit_message(self, request: web.Request) -> web.Response:
        """v0.7.6: edit one of our previously-sent messages within
        the cooldown window. Body: {body, peer}."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        msg_id = request.match_info["msg_id"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        new_body = data.get("body")
        peer_needle = data.get("peer")
        if not isinstance(new_body, str) or not new_body.strip():
            return web.json_response(
                {"error": "body must be a non-empty string"}, status=400,
            )
        rec = self.daemon.state.get_message(msg_id)
        if rec is None:
            return web.json_response({"error": "message not found"}, status=404)
        if rec.direction != "out":
            return web.json_response(
                {"error": "can only edit your own outbound messages"}, status=403,
            )
        peer = await self.daemon.resolve_for_send(str(peer_needle)) \
            if peer_needle else None
        if peer is None:
            return web.json_response({"error": "peer offline"}, status=404)
        try:
            result = await self.daemon.send_edit(
                peer, target_msg_id=msg_id, new_body=new_body,
            )
            return web.json_response({"ok": True, "result": result})
        except RuntimeError as e:
            return web.json_response({"error": str(e)}, status=400)
        except Exception as e:
            log.warning("send_edit failed: %s", e)
            translated = _translate_send_error(e)
            _record_translated_error(translated, e, source="server.api")
            return web.json_response(translated, status=translated["status"])

    async def api_delete_message(self, request: web.Request) -> web.Response:
        """v0.7.6: soft-delete one of our previously-sent messages."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        msg_id = request.match_info["msg_id"]
        try:
            data = await request.json()
        except Exception:
            data = {}
        peer_needle = data.get("peer")
        rec = self.daemon.state.get_message(msg_id)
        if rec is None:
            return web.json_response({"error": "message not found"}, status=404)
        if rec.direction != "out":
            return web.json_response(
                {"error": "can only delete your own outbound messages"},
                status=403,
            )
        peer = await self.daemon.resolve_for_send(str(peer_needle)) \
            if peer_needle else None
        # Even if peer is offline, we delete locally — they'll see
        # the deletion next time they sync (in practice via ledger
        # replay; transient like reactions for now).
        if peer is None:
            now = int(time.time() * 1000)
            with contextlib.suppress(Exception):
                self.daemon.state.delete_message(id=msg_id, deleted_at_ms=now)
            self.broadcast({
                "type": "msg_delete",
                "target": msg_id,
                "deleted_at_ms": now,
            })
            return web.json_response({"ok": True, "delivered": False})
        try:
            result = await self.daemon.send_delete(peer, target_msg_id=msg_id)
            return web.json_response({"ok": True, "delivered": True, "result": result})
        except Exception as e:
            log.warning("send_delete failed: %s", e)
            translated = _translate_send_error(e)
            _record_translated_error(translated, e, source="server.api")
            return web.json_response(translated, status=translated["status"])

    async def api_set_read_marker(self, request: web.Request) -> web.Response:
        """v0.7.6: tell `peer` we've read up to ts X. Best-effort —
        idempotent, never blocks the caller."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception:
            data = {}
        try:
            up_to = int(data.get("up_to_ts_ms") or 0)
        except (TypeError, ValueError):
            return web.json_response(
                {"error": "up_to_ts_ms must be an integer"}, status=400,
            )
        if up_to <= 0:
            return web.json_response(
                {"error": "up_to_ts_ms required"}, status=400,
            )
        peer = await self.daemon.resolve_for_send(fp)
        if peer is None:
            return web.json_response({"ok": True, "delivered": False})
        try:
            await self.daemon.send_read_marker(peer, up_to_ts_ms=up_to)
            return web.json_response({"ok": True, "delivered": True})
        except Exception as e:
            log.debug("send_read_marker failed: %s", e)
            return web.json_response({"ok": True, "delivered": False})

    # ─── /api/groups (v0.8.0) ─────────────────────────────────────────

    def _materialize_group(self, gid: bytes) -> dict | None:
        """Internal helper: reduce events → membership + name +
        our role. Returns None if no events."""
        if self.daemon.state is None:
            return None
        try:
            wire_events = self.daemon.state.list_group_events(gid)
        except Exception:
            return None
        if not wire_events:
            return None
        from one_link import groups as gmod
        from one_link.identity import fingerprint_of
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        if gstate is None:
            return None
        my_pub = self.daemon.me.public_bytes
        my_role = gstate.role_of(my_pub)
        members = []
        for pub in gstate.members:
            fp = fingerprint_of(pub)
            rec = self.daemon.state.get_peer(fp)
            members.append({
                "fingerprint": fp,
                "pubkey_hex": pub.hex(),
                "role": gstate.role_of(pub),
                "display_name": (
                    rec.display_name if rec
                    else ("you" if pub == my_pub else fp[:8])
                ),
                "is_me": (pub == my_pub),
            })
        return {
            "group_id": gid.hex(),
            "name": gstate.name or "",
            "members": members,
            "member_count": len(gstate.members),
            "my_role": my_role,
            "is_member": my_pub in gstate.members,
        }

    async def api_list_groups(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"groups": []})
        gids = self.daemon.state.list_group_ids()
        out = []
        for gid in gids:
            mat = self._materialize_group(gid)
            if mat and mat.get("is_member"):
                out.append({
                    "group_id": mat["group_id"],
                    "name": mat["name"],
                    "member_count": mat["member_count"],
                    "my_role": mat["my_role"],
                })
        return web.json_response({"groups": out})

    async def api_create_group(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        name = (data.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name required"}, status=400)
        if len(name) > 64:
            return web.json_response({"error": "name too long"}, status=400)
        member_fps = data.get("members") or []
        if not isinstance(member_fps, list):
            return web.json_response(
                {"error": "members must be a list of fingerprints"},
                status=400,
            )
        unique_member_fps = []
        seen_fps = set()
        for fp in member_fps:
            s = str(fp)
            if s and s not in seen_fps:
                seen_fps.add(s)
                unique_member_fps.append(s)
        if len(unique_member_fps) < 2:
            return web.json_response(
                {
                    "error": (
                        "groups need at least 3 people total; "
                        "pick at least 2 paired devices"
                    )
                },
                status=400,
            )
        # Resolve each fp → pubkey via the peer record.
        member_pubkeys: list[bytes] = []
        seen_pubkeys = {self.daemon.me.public_bytes}
        for fp in unique_member_fps:
            rec = self.daemon.state.get_peer(fp)
            if rec is None or rec.trust != "pinned":
                return web.json_response(
                    {"error": f"member must be a paired (pinned) peer: {fp}"},
                    status=400,
                )
            if rec.pubkey and rec.pubkey not in seen_pubkeys:
                seen_pubkeys.add(rec.pubkey)
                member_pubkeys.append(rec.pubkey)
        if len(member_pubkeys) < 2:
            return web.json_response(
                {
                    "error": (
                        "groups need at least 3 people total; "
                        "use device chat for 1-on-1"
                    )
                },
                status=400,
            )
        try:
            result = await self.daemon.create_group(
                name=name, member_pubkeys=member_pubkeys,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            log.exception("create_group failed: %s", e)
            return web.json_response({"error": str(e)}, status=500)

    async def api_get_group(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        mat = self._materialize_group(gid)
        if mat is None:
            return web.json_response({"error": "group not found"}, status=404)
        return web.json_response(mat)

    async def api_rename_group(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            gid = bytes.fromhex(request.match_info["gid"])
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        name = (data.get("name") or "").strip()
        if not name:
            return web.json_response({"error": "name required"}, status=400)
        if len(name) > 64:
            return web.json_response({"error": "name too long"}, status=400)
        mat = self._materialize_group(gid)
        if mat is None or not mat.get("is_member"):
            return web.json_response({"error": "group not found"}, status=404)
        if mat.get("my_role") not in ("owner", "admin"):
            return web.json_response(
                {"error": "only group admins can rename a group"},
                status=403,
            )
        try:
            result = await self.daemon.rename_group(group_id=gid, name=name)
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_group_messages(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"messages": []})
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            limit = max(1, min(int(request.query.get("limit", "200")), 5000))
        except ValueError:
            limit = 200
        rows = self.daemon.state.recent_group_messages(group_id=gid, limit=limit)
        try:
            ids = [r.get("id") for r in rows if r.get("id")]
            reactions = self.daemon.state.list_reactions_for_messages(ids)
        except Exception:
            reactions = {}
        # rows carry raw bytes for sender_pub + group_id; rewrite for JSON.
        out = []
        for r in rows:
            sender_pub = r.get("sender_pub")
            item = {
                "id": r.get("id"),
                "group_id": gid_hex,
                "sender_pub_hex": (
                    sender_pub.hex() if isinstance(sender_pub, bytes)
                    else (str(sender_pub) if sender_pub else "")
                ),
                "epoch": r.get("epoch"),
                "counter": r.get("counter"),
                "direction": r.get("direction"),
                "body": r.get("body"),
                "reply_to": r.get("reply_to"),
                "edited_at_ms": r.get("edited_at_ms"),
                "original_body": r.get("original_body"),
                "deleted_at_ms": r.get("deleted_at_ms"),
                "deleted": bool(r.get("deleted_at_ms")),
                "ts_ms": r.get("ts_ms"),
            }
            rx = reactions.get(item["id"])
            if rx:
                item["reactions"] = rx
            out.append(item)
        return web.json_response({"messages": out})

    async def api_send_group(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        body = data.get("body")
        if not isinstance(body, str) or not body.strip():
            return web.json_response(
                {"error": "body must be a non-empty string"}, status=400,
            )
        reply_to_raw = data.get("reply_to")
        reply_to = (
            str(reply_to_raw)
            if isinstance(reply_to_raw, str) and reply_to_raw
            else None
        )
        try:
            result = await self.daemon.send_group_message(
                group_id=gid, body=body, reply_to=reply_to,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            log.exception("send_group_message failed: %s", e)
            return web.json_response({"error": str(e)}, status=500)

    async def api_react_group_message(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            gid = bytes.fromhex(request.match_info["gid"])
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        msg_id = request.match_info["msg_id"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        emoji = data.get("emoji")
        op = data.get("op", "add")
        if not isinstance(emoji, str) or not emoji or len(emoji) > 64:
            return web.json_response(
                {"error": "emoji must be a non-empty short string"},
                status=400,
            )
        if op not in ("add", "remove"):
            return web.json_response(
                {"error": "op must be 'add' or 'remove'"}, status=400,
            )
        rec = self.daemon.state.get_group_message(msg_id)
        if rec is None or rec.get("group_id") != gid:
            return web.json_response({"error": "message not found"}, status=404)
        try:
            result = await self.daemon.send_group_reaction(
                group_id=gid,
                target_msg_id=msg_id,
                emoji=emoji,
                op=op,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_edit_group_message(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            gid = bytes.fromhex(request.match_info["gid"])
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        msg_id = request.match_info["msg_id"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        body = data.get("body")
        if not isinstance(body, str) or not body.strip():
            return web.json_response(
                {"error": "body must be a non-empty string"}, status=400,
            )
        rec = self.daemon.state.get_group_message(msg_id)
        if rec is None or rec.get("group_id") != gid:
            return web.json_response({"error": "message not found"}, status=404)
        if rec.get("direction") != "out":
            return web.json_response(
                {"error": "can only edit your own outbound messages"},
                status=403,
            )
        try:
            result = await self.daemon.send_group_edit(
                group_id=gid,
                target_msg_id=msg_id,
                new_body=body,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_delete_group_message(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            gid = bytes.fromhex(request.match_info["gid"])
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        msg_id = request.match_info["msg_id"]
        rec = self.daemon.state.get_group_message(msg_id)
        if rec is None or rec.get("group_id") != gid:
            return web.json_response({"error": "message not found"}, status=404)
        if rec.get("direction") != "out":
            return web.json_response(
                {"error": "can only delete your own outbound messages"},
                status=403,
            )
        try:
            result = await self.daemon.send_group_delete(
                group_id=gid,
                target_msg_id=msg_id,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_group_invite_link(self, request: web.Request) -> web.Response:
        """Return a signed, offline-verifiable group invite token.

        The token does not grant membership by itself; it lets a paired
        One Link device prove which group it is asking to join. A group
        admin still signs the ADD_MEMBER event, preserving the group
        authority model instead of turning links into ambient access.
        """
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            gid = bytes.fromhex(request.match_info["gid"])
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        mat = self._materialize_group(gid)
        if mat is None or not mat.get("is_member"):
            return web.json_response({"error": "group not found"}, status=404)
        try:
            ttl_hours = max(
                1, min(int(request.query.get("ttl_hours", "168")), 24 * 30)
            )
        except ValueError:
            ttl_hours = 168
        payload = {
            "v": 1,
            "type": "one_link_group_invite",
            "group_id": gid.hex(),
            "name": mat.get("name") or "",
            "issuer_fp": self.daemon.me.fingerprint,
            "issuer_pub_hex": self.daemon.me.public_bytes.hex(),
            "issued_ms": int(time.time() * 1000),
            "expires_ms": int(time.time() * 1000) + ttl_hours * 60 * 60 * 1000,
            "nonce": secrets.token_urlsafe(18),
        }
        signed = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        sig_hex = self.daemon.me.sign(signed).hex()
        envelope = {"payload": payload, "signature_hex": sig_hex}
        token_raw = json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")
        token = base64.urlsafe_b64encode(token_raw).decode("ascii").rstrip("=")
        return web.json_response({
            "ok": True,
            "url": f"one-link://group-invite/{token}",
            "token": token,
            "expires_ms": payload["expires_ms"],
            "issuer_fp": payload["issuer_fp"],
        })

    async def api_add_group_member(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        fp = (data.get("fp") or "").strip()
        role = (data.get("role") or "member").strip()
        rec = self.daemon.state.get_peer(fp)
        if rec is None or rec.trust != "pinned" or not rec.pubkey:
            return web.json_response(
                {"error": "member must be a paired (pinned) peer"},
                status=400,
            )
        try:
            result = await self.daemon.add_group_member(
                group_id=gid, member_pubkey=rec.pubkey, role=role,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_remove_group_member(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        member_fp = request.match_info["member_fp"]
        rec = self.daemon.state.get_peer(member_fp)
        if rec is None or not rec.pubkey:
            return web.json_response({"error": "unknown member"}, status=404)
        try:
            result = await self.daemon.remove_group_member(
                group_id=gid, member_pubkey=rec.pubkey,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_leave_group(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            result = await self.daemon.remove_group_member(
                group_id=gid, member_pubkey=self.daemon.me.public_bytes,
            )
            return web.json_response({"ok": True, **result})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    # ─── /api/search ──────────────────────────────────────────────────
    # ─── /api/debug (v0.8.1 developer backend) ────────────────────────

    async def api_debug_log(self, request: web.Request) -> web.Response:
        """Recent failures with context + how-to-fix suggestion.
        Query: ?since_id=N (incremental), ?limit=N, ?severity=warn,error
        ?source=send_file,api ."""
        from one_link.debug_log import get_debug_log
        try:
            limit = max(1, min(int(request.query.get("limit", "200")), 1000))
        except ValueError:
            limit = 200
        since_id = request.query.get("since_id")
        try:
            since = int(since_id) if since_id else None
        except ValueError:
            since = None
        sev_q = request.query.get("severity") or ""
        severities = [s.strip() for s in sev_q.split(",") if s.strip()] or None
        src_q = request.query.get("source") or ""
        sources = [s.strip() for s in src_q.split(",") if s.strip()] or None
        entries = get_debug_log().tail(
            limit=limit, since_id=since,
            severity=severities, sources=sources,
        )
        return web.json_response({
            "entries": entries,
            "total": len(get_debug_log()),
        })

    async def api_debug_clear(self, request: web.Request) -> web.Response:
        from one_link.debug_log import get_debug_log
        n = get_debug_log().clear()
        return web.json_response({"ok": True, "removed": n})

    async def api_debug_health(self, request: web.Request) -> web.Response:
        """v0.8.1: structured self-check. Each check returns
        {ok: bool, name, detail}. Caller renders pass/fail rows
        + the daemon-page version compare."""
        checks: list[dict] = []
        # State db
        if self.daemon.state is None:
            checks.append({
                "name": "state_db",
                "ok": False,
                "detail": "state.db not opened (daemon misconfigured?)",
            })
        else:
            try:
                sv = self.daemon.state.schema_version()
                checks.append({
                    "name": "state_db",
                    "ok": True,
                    "detail": f"schema_version={sv}",
                })
            except Exception as e:
                checks.append({
                    "name": "state_db",
                    "ok": False,
                    "detail": f"schema introspection failed: {e}",
                })

        # Discovery
        if self.daemon.discovery is None:
            checks.append({
                "name": "discovery",
                "ok": False,
                "detail": "mDNS discovery not running",
            })
        else:
            n_peers = len(self.daemon.discovery.registry.list())
            checks.append({
                "name": "discovery",
                "ok": True,
                "detail": f"mDNS registry: {n_peers} live peer(s)",
            })

        # Peer-server listening
        ps = getattr(self.daemon, "_peer_server", None)
        checks.append({
            "name": "peer_server",
            "ok": ps is not None,
            "detail": (
                f"listening on port "
                f"{getattr(self.daemon, '_rendezvous_peer_port', '?')}"
                if ps is not None else "not listening"
            ),
        })

        # Active outbound sessions
        sessions = getattr(self.daemon, "_outbound_sessions", {}) or {}
        checks.append({
            "name": "outbound_sessions",
            "ok": True,
            "detail": f"{len(sessions)} active",
        })

        # Outbox depth
        try:
            pending = self.daemon.state.list_outbox(
                pending_only=True, limit=1000,
            ) if self.daemon.state else []
            checks.append({
                "name": "outbox",
                "ok": True,
                "detail": f"{len(pending)} message(s) waiting for delivery",
            })
        except Exception as e:
            checks.append({
                "name": "outbox",
                "ok": False,
                "detail": str(e),
            })

        # Paused transfers
        try:
            transfers = self.daemon.state.list_transfers(
                limit=500,
            ) if self.daemon.state else []
            paused = [t for t in transfers if t.status == "paused"]
            checks.append({
                "name": "paused_transfers",
                "ok": True,
                "detail": (
                    f"{len(paused)} paused, will auto-resume"
                    if paused else "no paused transfers"
                ),
            })
        except Exception as e:
            checks.append({
                "name": "paused_transfers",
                "ok": False,
                "detail": str(e),
            })

        from one_link import __version__ as ol_ver
        return web.json_response({
            "ok": all(c["ok"] for c in checks),
            "version": ol_ver,
            "checks": checks,
        })

    async def api_search(self, request: web.Request) -> web.Response:
        """FTS5 full-text search over message bodies.

        ?q=  required, FTS5 query
        ?peer=, ?room=, ?limit= optional filters
        """
        q = request.query.get("q", "").strip()
        if not q:
            return web.json_response({"error": "q required"}, status=400)
        try:
            limit = max(1, min(int(request.query.get("limit", "50")), 1000))
        except ValueError:
            limit = 50
        if self.daemon.state is None:
            return web.json_response({"messages": []})

        peer_q = request.query.get("peer")
        room_q = request.query.get("room")
        peer_fp: Optional[str] = None
        if peer_q:
            if len(peer_q) == 64:
                peer_fp = peer_q
            else:
                rec = self.daemon.state.get_peer_by_short_id(peer_q)
                if rec:
                    peer_fp = rec.fingerprint

        try:
            recs = self.daemon.state.search_messages(
                q, limit=limit, peer_fp=peer_fp, room_id=room_q
            )
        except Exception as e:
            return web.json_response({"error": f"bad query: {e}"}, status=400)
        msgs = [_msg_record_to_event(r) for r in recs]
        return web.json_response({"messages": msgs, "query": q})

    # ─── /api/send ────────────────────────────────────────────────────
    async def api_send(self, request: web.Request) -> web.Response:
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        peer_needle = data.get("peer", "")
        body = data.get("body", "")
        # v0.7.1: by default, fall back to outbox when the peer is
        # offline or the send fails with a transient/network error.
        # Set `queue_on_failure: false` to opt out (e.g. for the
        # control plane's strict send command).
        queue_on_failure = bool(data.get("queue_on_failure", True))
        # v0.7.5: optional reply_to threads this TEXT under a parent
        # message id. Validated as a 32-hex string-ish; daemon
        # tolerates anything string-shaped.
        reply_to_raw = data.get("reply_to")
        reply_to = str(reply_to_raw) if isinstance(reply_to_raw, str) and reply_to_raw else None
        if not peer_needle or not body:
            return web.json_response({"error": "peer and body required"}, status=400)
        # v0.5.1: also tries the rendezvous if the peer isn't on mDNS.
        peer = await self.daemon.resolve_for_send(peer_needle)
        target_fp = self._resolve_pinned_fp(peer_needle, peer)

        if peer is None:
            # Peer is offline. If we can address them as a pinned
            # fingerprint, queue the message instead of erroring.
            if queue_on_failure and target_fp:
                try:
                    entry = self.daemon.enqueue_text_outbox(target_fp, body)
                    return web.json_response({
                        "ok": True, "queued": True,
                        "outbox_id": entry["outbox_id"],
                        "msg": entry["msg"],
                        "reason": "peer_offline",
                    }, status=202)
                except Exception as enqueue_err:
                    log.warning("offline-enqueue failed: %s", enqueue_err)
            return web.json_response({"error": f"no peer {peer_needle!r}"}, status=404)
        try:
            result = await self.daemon.send_text(peer, body, reply_to=reply_to)
            return web.json_response({"ok": True, "result": result})
        except Exception as e:
            log.exception("send failed: %s", e)
            translated = _translate_send_error(e)
            # Queue on transient/network errors. Sticky deny errors
            # (capability_disabled, peer_rejected, wire_version_mismatch)
            # stay as immediate 4xx — re-attempting them won't help.
            queueable_codes = {
                "peer_unreachable", "handshake_failed",
                "timeout", "send_failed",
            }
            if (
                queue_on_failure
                and target_fp
                and translated.get("code") in queueable_codes
            ):
                try:
                    entry = self.daemon.enqueue_text_outbox(target_fp, body)
                    return web.json_response({
                        "ok": True, "queued": True,
                        "outbox_id": entry["outbox_id"],
                        "msg": entry["msg"],
                        "reason": translated.get("code"),
                        "after_failure": translated,
                    }, status=202)
                except Exception as enqueue_err:
                    log.warning(
                        "queue-on-failure enqueue failed: %s", enqueue_err
                    )
            return web.json_response(translated, status=translated["status"])

    def _resolve_pinned_fp(self, needle: str, peer_obj) -> str | None:
        """v0.7.1: best-effort map a UI peer needle (short id, fp,
        or hostname) to a pinned-peer fingerprint, even when the
        peer isn't currently visible. Used by the outbox-fallback
        path so a send to a sleeping device queues instead of 404s."""
        if self.daemon.state is None:
            return None
        # If we already resolved a live Peer with an ed_pub, derive its fp.
        if peer_obj is not None:
            try:
                from one_link.identity import fingerprint_of
                if getattr(peer_obj, "ed_pub_hex", None):
                    fp = fingerprint_of(bytes.fromhex(peer_obj.ed_pub_hex))
                    rec = self.daemon.state.get_peer(fp)
                    if rec and rec.trust == "pinned":
                        return fp
            except Exception:
                pass
        # Otherwise, try the needle as fp / short_id directly.
        n = (needle or "").strip()
        if not n:
            return None
        try:
            if len(n) == 64:
                rec = self.daemon.state.get_peer(n)
                if rec and rec.trust == "pinned":
                    return n
            if len(n) <= 16:
                rec = self.daemon.state.get_peer_by_short_id(n)
                if rec and rec.trust == "pinned":
                    return rec.fingerprint
        except Exception:
            pass
        return None

    # ─── /api/send-file ───────────────────────────────────────────────
    async def api_send_file(self, request: web.Request) -> web.Response:
        if not request.content_type or "multipart/form-data" not in request.content_type:
            return web.json_response({"error": "expected multipart/form-data"}, status=400)
        reader = await request.multipart()
        peer_needle: Optional[str] = None
        upload_path: Optional[Path] = None
        upload_name: str = "upload.bin"

        try:
            async for part in reader:
                if part.name == "peer":
                    peer_needle = (await part.text()).strip()
                elif part.name == "file":
                    upload_name = Path(part.filename or "upload.bin").name
                    if not upload_name or upload_name in (".", ".."):
                        upload_name = "upload.bin"
                    # Stream to a temp file inside data_dir so we don't OOM on big uploads.
                    staging = data_dir() / "uploads"
                    staging.mkdir(parents=True, exist_ok=True)
                    upload_path = staging / (
                        f"{int(time.time()*1000)}_{secrets.token_hex(8)}_{upload_name}"
                    )
                    with open(upload_path, "wb") as f:
                        while True:
                            chunk = await part.read_chunk(size=1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)
        except Exception as e:
            if upload_path is not None:
                with contextlib.suppress(OSError):
                    upload_path.unlink(missing_ok=True)
            log.warning("multipart upload failed before send: %s", e)
            return web.json_response({"error": "upload failed before send"}, status=400)

        if not peer_needle:
            return web.json_response({"error": "missing 'peer' field"}, status=400)
        if not upload_path or not upload_path.is_file():
            return web.json_response({"error": "missing 'file' field"}, status=400)

        # v0.5.1: also tries the rendezvous if the peer isn't on mDNS.
        peer = await self.daemon.resolve_for_send(peer_needle)
        if peer is None:
            return web.json_response({"error": f"no peer {peer_needle!r}"}, status=404)

        keep_upload_for_resume = False
        try:
            # v0.6.3: auto-retry once on ordinary transient failure.
            # v0.7.4: if send_file already created a paused transfer row,
            # return 202 and keep the staged upload so auto-resume has
            # bytes to send later instead of turning the pause into a 500.
            try:
                result = await self.daemon.send_file(peer, upload_path)
            except (RuntimeError, OSError) as first_err:
                if getattr(first_err, "transfer_id", None):
                    keep_upload_for_resume = True
                    return web.json_response(
                        {
                            "ok": True,
                            "paused": True,
                            "transfer_id": first_err.transfer_id,
                            "error": str(first_err),
                            "hint": "Transfer paused; it will resume automatically when the device reconnects.",
                        },
                        status=202,
                    )
                log.warning(
                    "send_file first attempt failed (%s) - retrying with "
                    "fresh resolve", first_err,
                )
                fresh_peer = await self.daemon.resolve_for_send(peer_needle)
                if fresh_peer is None:
                    raise first_err
                result = await self.daemon.send_file(fresh_peer, upload_path)
            return web.json_response({"ok": True, "result": result})
        except Exception as e:
            if getattr(e, "transfer_id", None):
                keep_upload_for_resume = True
                return web.json_response(
                    {
                        "ok": True,
                        "paused": True,
                        "transfer_id": e.transfer_id,
                        "error": str(e),
                        "hint": "Transfer paused; it will resume automatically when the device reconnects.",
                    },
                    status=202,
                )
            log.exception("send_file failed: %s", e)
            translated = _translate_send_error(e)
            _record_translated_error(translated, e, source="server.api")
            return web.json_response(translated, status=translated["status"])
        finally:
            try:
                if upload_path and not keep_upload_for_resume:
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

    async def api_transfers(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"transfers": []})
        peer_fp = request.query.get("peer_fp") or None
        try:
            limit = int(request.query.get("limit", "100"))
        except ValueError:
            limit = 100
        transfers = self.daemon.state.list_transfers(peer_fp=peer_fp, limit=limit)
        return web.json_response({
            "transfers": [_transfer_record_to_event(t) for t in transfers],
        })

    async def api_delete_transfer(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        transfer_id = request.match_info["transfer_id"]
        deleted = self.daemon.state.delete_transfer(transfer_id)
        return web.json_response({"ok": True, "deleted": deleted})

    async def api_retry_transfer(self, request: web.Request) -> web.Response:
        """v0.7.x: re-run send_file for a failed outbound transfer.
        Reads the original local path off the ledger row's metadata.
        Inbound transfers can't be retried from the receiver side."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        transfer_id = request.match_info["transfer_id"]
        rec = self.daemon.state.get_transfer(transfer_id)
        if rec is None:
            return web.json_response({"error": "transfer not found"}, status=404)
        if rec.direction != "out":
            return web.json_response(
                {"error": "only outbound transfers can be retried"}, status=400,
            )
        if rec.status not in ("failed", "complete"):
            return web.json_response(
                {"error": f"transfer is {rec.status} — not retriable"}, status=409,
            )
        path_str = (rec.metadata or {}).get("path")
        if not path_str:
            return web.json_response(
                {"error": "retry not possible — original path not recorded"},
                status=410,
            )
        path = Path(path_str)
        if not path.is_file():
            return web.json_response(
                {"error": f"source file no longer exists: {path}"},
                status=410,
            )
        # Resolve peer fresh — don't trust the cached endpoint that
        # might have caused the original failure.
        try:
            peers_for_fp = self.daemon.state.get_peer(rec.peer_fp)
        except Exception:
            peers_for_fp = None
        if peers_for_fp is None:
            return web.json_response(
                {"error": "peer record missing"}, status=404,
            )
        peer = await self.daemon.resolve_for_send(rec.peer_fp)
        if peer is None:
            return web.json_response({"error": "peer offline"}, status=404)
        try:
            result = await self.daemon.send_file(peer, path)
            return web.json_response({"ok": True, "result": result})
        except Exception as e:
            log.exception("retry_transfer failed: %s", e)
            translated = _translate_send_error(e)
            _record_translated_error(translated, e, source="server.api")
            return web.json_response(translated, status=translated["status"])

    async def api_cancel_transfer(self, request: web.Request) -> web.Response:
        """v0.7.4: cancel a paused transfer (mark as failed +
        reason='cancelled by user'). Idempotent: cancelling a
        non-existent or already-finished transfer returns ok."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        transfer_id = request.match_info["transfer_id"]
        rec = self.daemon.state.get_transfer(transfer_id)
        if rec is None:
            return web.json_response({"ok": True, "removed": False})
        if rec.status not in ("paused", "queued", "offered", "active"):
            return web.json_response({"ok": True, "already_terminal": True})
        self.daemon.state.update_transfer(
            transfer_id, status="failed",
            metadata={
                **(rec.metadata or {}),
                "error": "cancelled by user",
                "error_class": "CancelledByUser",
            },
        )
        return web.json_response({"ok": True})

    async def api_resume_peer_transfers(self, request: web.Request) -> web.Response:
        """v0.7.4: manually trigger the resume orchestrator for a
        peer. Useful when the user wants to retry a peer's paused
        transfers without waiting for the next idle session refresh."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        result = await self.daemon.resume_paused_transfers_for(fp)
        return web.json_response(result)

    async def api_prune_transfers(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception:
            data = {}
        statuses = data.get("statuses") or ["complete", "failed"]
        if not isinstance(statuses, list):
            return web.json_response({"error": "statuses must be a list"}, status=400)
        keep_latest = int(data.get("keep_latest", 50))
        older_than_ms = data.get("older_than_ms")
        removed = self.daemon.state.prune_transfers(
            statuses=[str(s) for s in statuses],
            older_than_ms=int(older_than_ms) if older_than_ms is not None else None,
            keep_latest=keep_latest,
        )
        return web.json_response({"ok": True, "removed": removed})

    # ─── /api/outbox (v0.7.1) ─────────────────────────────────────────
    async def api_list_outbox(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        peer_fp = request.query.get("peer_fp") or None
        pending_only = (request.query.get("pending", "1") != "0")
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        limit = max(1, min(limit, 1000))
        rows = self.daemon.state.list_outbox(
            peer_fp=peer_fp, pending_only=pending_only, limit=limit,
        )
        return web.json_response({
            "entries": [
                {
                    "id": r.id,
                    "peer_fp": r.peer_fp,
                    "msg_id": r.msg_id,
                    "msg_kind": r.msg_kind,
                    "msg_body": r.msg_body,
                    "enqueued_ms": r.enqueued_ms,
                    "attempts": r.attempts,
                    "last_attempt_ms": r.last_attempt_ms,
                    "last_error": r.last_error,
                    "delivered_ms": r.delivered_ms,
                    "delivered": r.delivered,
                }
                for r in rows
            ],
        })

    async def api_cancel_outbox(self, request: web.Request) -> web.Response:
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            entry_id = int(request.match_info["id"])
        except (KeyError, ValueError):
            return web.json_response({"error": "bad id"}, status=400)
        # Look up first so we can broadcast the right peer fingerprint.
        entry = self.daemon.state.get_outbox_entry(entry_id)
        if entry is None:
            return web.json_response({"error": "not found"}, status=404)
        if entry.delivered:
            return web.json_response(
                {"error": "already delivered"}, status=409,
            )
        removed = self.daemon.state.cancel_outbox(entry_id)
        if removed:
            self.broadcast({
                "type": "outbox_cancelled",
                "fingerprint": entry.peer_fp,
                "outbox_id": entry_id,
                "msg_id": entry.msg_id,
            })
        return web.json_response({"ok": True, "removed": removed})

    async def api_flush_outbox(self, request: web.Request) -> web.Response:
        """Force a flush attempt for one peer (or all paired peers
        with pending entries)."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception:
            data = {}
        peer_fp = data.get("peer_fp") if isinstance(data, dict) else None
        if peer_fp:
            result = await self.daemon.flush_outbox_for(str(peer_fp))
            return web.json_response({
                "ok": True, "results": [{"peer_fp": peer_fp, **result}],
            })
        # No peer specified: enumerate every peer with pending rows.
        pending = self.daemon.state.list_outbox(
            peer_fp=None, pending_only=True, limit=1000,
        )
        peer_fps = sorted({r.peer_fp for r in pending})
        results = []
        for fp in peer_fps:
            r = await self.daemon.flush_outbox_for(fp)
            results.append({"peer_fp": fp, **r})
        return web.json_response({"ok": True, "results": results})

    # ─── /api/audit ───────────────────────────────────────────────────
    async def api_audit(self, request: web.Request) -> web.Response:
        """Self-audit: report every kind of network call this binary makes,
        enumerated from the registered routes and the peer protocol's
        declared message types."""
        from one_link import wire as wire_mod
        from one_link.sovereign import doctrine
        # Local UI surface
        local_routes = []
        for resource in self.app.router.resources():
            for r in resource:
                method = r.method
                info = r.get_info()
                path = info.get("path") or info.get("formatter") or ""
                local_routes.append({"method": method, "path": path})
        # Peer-protocol surface — encoded directly in daemon._on_peer_message.
        peer_msg_types = [
            "CAPS",
            "TEXT",
            "FILE_OFFER",
            "FILE_WANTS",
            "FILE_CHUNK",
            "FILE_CDC_CHUNK",
            "FILE_DONE",
            "ACK",
            "PING",
            "PONG",
            "PAIR_REQUEST",
            "PAIR_CONFIRM",
            "PAIR_REJECT",
            "MANIFEST_PUSH",
            "MANIFEST_WANTS",
            "BLOB_OFFER",
            "BLOB_CHUNK",
        ]
        # Outbound network endpoints we ever connect to: only LAN peers
        # discovered via mDNS, never any external service.
        outbound = [
            {"kind": "lan_peer_tcp",
             "destination": "address advertised in mDNS (_onelink._tcp.local.)",
             "protocol": "TCP, X25519 + ChaCha20-Poly1305 framed"},
            {"kind": "mdns_multicast",
             "destination": "224.0.0.251:5353",
             "protocol": "UDP, mDNS service discovery"},
        ]
        return web.json_response({
            "version": __import__("one_link").__version__,
            "local_ui_routes": local_routes,
            "ui_bind": "127.0.0.1 only (loopback)",
            "ui_auth": "per-process random URL-safe token",
            "peer_protocol": {
                "transport": "TCP, port advertised via mDNS",
                "auth": "Ed25519 mutual signature in handshake",
                "encryption": "X25519 ECDH + HKDF + ChaCha20-Poly1305 (64-bit nonce counter)",
                "message_types": peer_msg_types,
                "max_frame_bytes": wire_mod.MAX_FRAME,
                "sessions": __import__("one_link.sessions").sessions.protocol_catalog(),
            },
            "local_capabilities": __import__(
                "one_link.capabilities"
            ).capabilities.LOCAL_CAPABILITIES,
            "performance": {
                "cdc_cache": self.daemon._chunk_cache_stats(),
                "file_transfer": {
                    "strategy": "content-defined chunk offer, receiver wants only missing chunks",
                    "compression": "adaptive zlib level 1 per CDC chunk when it saves at least 8%",
                },
                "folder_sync": {
                    "strategy": "Merkle root fast path plus CRDT manifest merge",
                },
                "sessions": self.daemon._session_stats(),
            },
            "outbound_destinations": outbound,
            "no_external_telemetry": True,
            "sovereign_network": doctrine(),
        })

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

    # v0.9.0: inline preview support. Whitelisted text-y extensions
    # only — defense-in-depth against the user clicking 'preview' on
    # a 50 MB binary file. Capped at 256 KB on read; any tail beyond
    # that is reported back as truncated=True.
    PREVIEW_MAX_BYTES = 256 * 1024
    PREVIEW_KINDS: dict = {
        # markdown variants → markdown renderer (subset)
        "md": "markdown", "markdown": "markdown", "mdown": "markdown",
        # code-ish: monospace + line numbers
        "py": "code", "js": "code", "mjs": "code", "cjs": "code",
        "ts": "code", "tsx": "code", "jsx": "code",
        "html": "code", "htm": "code",
        "css": "code", "scss": "code", "sass": "code", "less": "code",
        "json": "code", "yaml": "code", "yml": "code", "toml": "code",
        "xml": "code", "ini": "code", "conf": "code", "cfg": "code",
        "sh": "code", "bash": "code", "zsh": "code", "fish": "code",
        "ps1": "code", "bat": "code",
        "rb": "code", "go": "code", "rs": "code", "java": "code",
        "kt": "code", "swift": "code", "scala": "code",
        "c": "code", "h": "code", "cc": "code", "cpp": "code", "hpp": "code",
        "lua": "code", "r": "code", "pl": "code", "php": "code",
        "sql": "code", "graphql": "code", "proto": "code",
        # plain text → plain renderer
        "txt": "text", "log": "text", "csv": "text", "tsv": "text",
        "env": "text", "gitignore": "text", "gitattributes": "text",
        "license": "text", "readme": "text",
    }

    async def api_file_preview(self, request: web.Request) -> web.Response:
        """v0.9.0: read a small text-y file from the inbox + return its
        decoded content for inline rendering in the chat bubble.
        Whitelisted extensions only; >256 KB tail is reported as
        truncated. Path-traversal defended like the download endpoint."""
        name = request.match_info["name"]
        safe = Path(name).name
        if safe != name or not safe:
            return web.json_response({"error": "bad name"}, status=400)
        path = inbox_dir() / safe
        if not path.is_file():
            return web.json_response({"error": "not found"}, status=404)
        ext = safe.rsplit(".", 1)[-1].lower() if "." in safe else safe.lower()
        kind = self.PREVIEW_KINDS.get(ext)
        if kind is None:
            return web.json_response(
                {"error": "preview not available for this file type",
                 "extension": ext},
                status=415,
            )
        try:
            size = path.stat().st_size
        except OSError as e:
            return web.json_response({"error": f"stat: {e}"}, status=500)
        cap = self.PREVIEW_MAX_BYTES
        truncated = size > cap
        try:
            with path.open("rb") as f:
                raw = f.read(cap)
        except OSError as e:
            return web.json_response({"error": f"read: {e}"}, status=500)
        # Decode: prefer utf-8, fall back to latin-1 (which can't fail).
        # Replace bad bytes with U+FFFD so the user sees that part is
        # garbled rather than getting a 500.
        try:
            content = raw.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = raw.decode("utf-8", errors="replace")
            encoding = "utf-8-replace"
        return web.json_response({
            "name": safe,
            "extension": ext,
            "kind": kind,
            "encoding": encoding,
            "size": size,
            "preview_bytes": len(raw),
            "truncated": truncated,
            "content": content,
        })

    # Server-side debounce: explorer.exe spawns a new window each call,
    # so repeated rapid clicks from the UI (or a runaway loop) would
    # stack windows on top of the user's other work. One reveal per
    # second is the most a human would intentionally do.
    _last_reveal_ms: float = 0.0

    def _reveal_throttled(self) -> bool:
        now = time.time() * 1000
        if now - self._last_reveal_ms < 1000:
            return True
        self._last_reveal_ms = now
        return False

    async def api_file_reveal(self, request: web.Request) -> web.Response:
        # Open the OS file manager with the inbox file selected.
        # Same path-traversal defense as download.
        name = request.match_info["name"]
        safe = Path(name).name
        if safe != name or not safe:
            return web.json_response({"error": "bad name"}, status=400)
        path = (inbox_dir() / safe).resolve()
        if not path.is_file():
            return web.json_response({"error": "not found"}, status=404)
        if self._reveal_throttled():
            return web.json_response({"ok": True, "throttled": True})
        # v0.7.x: ONE_LINK_DISABLE_REVEAL=1 short-circuits the actual
        # subprocess.Popen so test runs (which may exercise reveal
        # endpoints via the integration suite) don't pop File Explorer
        # windows on the developer's screen.
        if os.environ.get("ONE_LINK_DISABLE_REVEAL") == "1":
            return web.json_response({"ok": True, "disabled": True})
        import subprocess
        import sys
        try:
            if sys.platform == "win32":
                # explorer.exe /select,<path> is the canonical pattern,
                # but it's notoriously brittle to subprocess quoting.
                # Use the raw command line so Windows can parse it the
                # way Explorer expects.
                norm = str(path).replace("/", "\\")
                subprocess.Popen(
                    f'explorer.exe /select,"{norm}"',
                    shell=False,
                )
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path.parent)])
        except OSError as e:
            return web.json_response({"error": f"reveal failed: {e}"}, status=500)
        return web.json_response({"ok": True})

    async def api_inbox_reveal(self, request: web.Request) -> web.Response:
        # Open the inbox folder itself (no specific file selected).
        path = inbox_dir().resolve()
        if self._reveal_throttled():
            return web.json_response({"ok": True, "path": str(path), "throttled": True})
        # See api_file_reveal — same env-gate so tests don't spawn
        # actual Explorer windows.
        if os.environ.get("ONE_LINK_DISABLE_REVEAL") == "1":
            return web.json_response({"ok": True, "path": str(path), "disabled": True})
        import subprocess
        import sys
        try:
            if sys.platform == "win32":
                norm = str(path).replace("/", "\\")
                subprocess.Popen(f'explorer.exe "{norm}"', shell=False)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except OSError as e:
            return web.json_response({"error": f"reveal failed: {e}"}, status=500)
        return web.json_response({"ok": True, "path": str(path)})

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
        # Try the well-known port first so browser tabs survive restarts.
        # Fall through 7118..7132 if taken, then OS-assigned random as
        # last resort.
        bound = False
        for candidate in range(
            PREFERRED_UI_PORT, PREFERRED_UI_PORT + UI_PORT_FALLBACK_RANGE
        ):
            try:
                site = web.TCPSite(self.runner, host="127.0.0.1", port=candidate)
                await site.start()
                self.site = site
                self.port = candidate
                bound = True
                break
            except OSError:
                # Port in use — try the next.
                continue
        if not bound:
            self.site = web.TCPSite(self.runner, host="127.0.0.1", port=0)
            await self.site.start()
            sock = self.site._server.sockets[0]  # type: ignore[union-attr]
            self.port = sock.getsockname()[1]
        _server_port_path().write_text(str(self.port))
        _token_path().write_text(self.token)
        log.info("UI server up — http://127.0.0.1:%d/", self.port)
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
