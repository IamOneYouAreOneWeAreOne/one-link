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
from collections import deque
import contextlib
import hmac
import json
import logging
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from one_link.platform_guard import install_windows_platform_fastpath

install_windows_platform_fastpath()

from aiohttp import WSMsgType, web

from one_link.paths import data_dir, inbox_dir
from one_link.transfer_doctor import enrich_transfer_event
from one_link.transfer_safety import classify_file_risk

if TYPE_CHECKING:
    from one_link.daemon import Daemon

log = logging.getLogger("one_link.server")

WEB_DIR = Path(__file__).resolve().parent / "web"
TOKEN_FILE = "ui.token"
SERVER_PORT_FILE = "server.port"


def _enumerate_sovereign_primitives() -> list[dict]:
    """Return the catalog of sovereignty / privacy primitives this
    binary ships. Surfaced via /api/audit so an inspecting user can
    see the full surface without grepping the source.

    Each entry is { module, name, status, summary, audit_ref }.
    ``status`` is "primitive" (cryptographic + tested but not yet
    wired into a live data path) or "live" (active in the daemon's
    request flow). When a primitive lights up live, bump its status
    here so the audit endpoint reflects reality.

    Probe each module via importlib so a missing primitive (e.g.
    optional install) cleanly degrades to "unavailable" instead of
    raising on /api/audit."""
    import importlib

    catalog = [
        ("one_link.threshold", "Shamir SSS",
         "primitive", "Threshold secret sharing over GF(256) for "
                      "split-key recovery", "Bundle 22"),
        ("one_link.master_seed", "Master seed + BIP-39 24-word recovery",
         "live", "Single recoverable secret; HKDF-domain-separated "
                 "derivation of identity / DRK / cluster / backup keys",
         "Bundle 23"),
        ("one_link.mnemonic", "BIP-39 mnemonic encoding",
         "live", "24-word phrase encodes 32-byte seed", "Bundle 23"),
        ("one_link.backup_bundle", ".olbak encrypted backup",
         "live", "AES-GCM-256 sealed daemon-state archive; key "
                 "derived from master seed via HKDF",
         "Bundle 24 (audit H23)"),
        ("one_link.path_pii", "Deterministic AES-SIV path encryption",
         "live", "Same path → same ciphertext (RFC 5297) so SQLite "
                 "indexes still work; opaque without seed",
         "Bundle 33 (audit M30)"),
        ("one_link.social_recovery", "Social recovery (3-of-5 trusted contacts)",
         "primitive", "Shamir shares wrapped to contact Ed25519 "
                      "identities via Ed25519↔X25519 birational map",
         "Bundle 35"),
        ("one_link.dht", "Kademlia DHT primitive",
         "primitive", "256-bit NodeID, XOR distance, k-buckets, "
                      "iterative O(log N) lookup",
         "Bundle 36"),
        ("one_link.pq_hybrid", "Post-quantum hybrid KEM",
         "primitive", "X25519+NullKEM today; ML-KEM-768 slot "
                      "pre-allocated in wire format. HKDF-combine "
                      "binds KEM names + transcript",
         "Bundle 37"),
        ("one_link.mls_treekem", "MLS TreeKEM (RFC 9420 §7)",
         "primitive", "Left-balanced binary tree, O(log N) group "
                      "ratchet, HKDF-derived path secrets",
         "Bundle 38"),
        ("one_link.sealed_sender", "Sealed Sender",
         "primitive", "Signal-style sender-identity hiding via "
                      "ECIES envelope + Ed25519 sig inside",
         "Bundle 39"),
        ("one_link.onion", "Onion routing",
         "primitive", "Layered ECIES so no single relay sees both "
                      "endpoints; Sphinx-inspired",
         "Bundle 40"),
        ("one_link.traffic_shaper", "Traffic shaping",
         "primitive", "Cover frames + fixed size to defeat timing/"
                      "size correlation analysis",
         "Bundle 41"),
        ("one_link.deletion_chain", "Provably-deletable messages",
         "primitive", "Forward-secret chain + signed deletion proofs",
         "Bundle 42"),
        ("one_link.rdz_blind", "Rendezvous blinding",
         "live", "HKDF-rotated lookup tokens per epoch — "
                 "rendezvous_server.py /api/v2/lookup_token serves "
                 "blinded queries; raw pubkey never appears on the "
                 "lookup wire",
         "Bundle 43+51"),
        ("one_link.caps_grants", "Signed capability grants",
         "live", "Fine-grained authority with auto-expiry — "
                 "offline-resilient revocation. Wired into "
                 "Daemon._capability_allowed via cap_store.CapStore",
         "Bundle 44+56"),
        ("one_link.cap_store", "Capability-grant store (active grants)",
         "live", "Per-daemon CapStore: verify-on-accept + replay "
                 "defense + auto-expiry on read + revoke-by-(granter|"
                 "subject)",
         "Bundle 56"),
        ("one_link.identity_dag", "Identity DAG (multi-device)",
         "primitive", "Root keypair signs device certs; per-device "
                      "Ed25519 priv never leaves the device",
         "Bundle 45"),
        ("one_link.vrf", "Verifiable Random Function (VRF)",
         "primitive", "Unbiased pseudorandom output with publicly-"
                      "verifiable proof; defeats eclipse attacks "
                      "in DHT routing. Secret-scalar mults via "
                      "_point_mul_ct (best-effort constant-time, "
                      "Bundle 57)",
         "Bundle 47+57"),
        ("one_link.ring_sig", "Ring signatures (anonymous group creds)",
         "primitive", "AOS construction on Ed25519. Signer's secret "
                      "scalar + nonce mults via _point_mul_ct so "
                      "per-position timing doesn't leak signer index",
         "Bundle 48+57"),
        ("one_link.psi", "Private Set Intersection",
         "primitive", "DH-OPRF based. All five secret-scalar mults "
                      "(server K, client blind, unblind) via "
                      "_point_mul_ct (Bundle 57)",
         "Bundle 49+57"),
        ("one_link.beacon", "Coherence Beacon (cross-LAN discovery)",
         "primitive", "IPv6 link-local multicast for peer discovery "
                      "across VLAN trunk ports where mDNS sandboxes",
         "Bundle 50"),
        ("one_link.beacon_listener", "Beacon UDP listener + emitter",
         "primitive", "asyncio DatagramProtocol on the multicast "
                      "group, periodic 1-Hz emit; daemon plumbs in",
         "Bundle 54"),
        ("one_link.dht_vrf_routing", "VRF-routed DHT (eclipse-resistant)",
         "primitive", "Lookup ranks candidates by VRF score instead "
                      "of raw XOR distance; attacker can't pre-bias "
                      "node IDs against a specific target",
         "Bundle 53"),
        ("one_link.sealed_relay", "Sealed sender + capability grant (relay path)",
         "primitive", "Combines Bundle 39 sealed-sender with Bundle 44 "
                      "capability grants. Relay sees opaque envelope; "
                      "recipient gets sender identity + auto-verified "
                      "auto-expiring grant atomically",
         "Bundle 52"),
        ("one_link.double_ratchet", "Double Ratchet",
         "primitive", "Forward secrecy + post-compromise security "
                      "(daemon path; channel.py wires it on CAPS)",
         "Bundle 11+"),
        ("one_link.lockbox", "At-rest secret wrap",
         "live", "AES-GCM wrap of chain_keys + UI token via DPAPI "
                 "(Windows) or scrypt-from-passphrase (POSIX)",
         "Bundle 11"),
    ]

    out = []
    for module_name, display_name, status, summary, audit_ref in catalog:
        try:
            importlib.import_module(module_name)
            available = True
        except Exception:
            available = False
        out.append({
            "module": module_name,
            "name": display_name,
            "status": status if available else "unavailable",
            "summary": summary,
            "audit_ref": audit_ref,
        })
    return out
COOKIE_NAME = "ol_ui"
MAX_JSON_REQUEST_BYTES = 256 * 1024
MAX_REQUEST_TARGET_BYTES = 8 * 1024
RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_FAILED_AUTH_ATTEMPTS = 32
MAX_SIGNALING_ATTEMPTS = 24

# Stable UI port. When the daemon restarts, the browser tab at this URL
# stays alive. We fall through to 7118..7132 if the port is taken (other
# user on the same machine, dev test daemon, etc.), and to OS-assigned
# random port only as a last resort.
PREFERRED_UI_PORT = 7117
UI_PORT_FALLBACK_RANGE = 16

# Discovery is intentionally soft state: mDNS can miss packets, Windows can
# leave stale network state around, and a peer may still be reachable through an
# already-open encrypted session. If we have touched the peer recently at the
# secure protocol layer, keep the UI online instead of flickering offline.
PEER_CONTACT_ONLINE_GRACE_MS = 2 * 60 * 1000


# v0.11.6 helpers for Storage + data settings.
def _parse_int_or_none(raw):
    """Settings table stores everything as TEXT. Convert to int when
    possible, else None — used for nullable numeric settings."""
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _normalize_ext_list(raw):
    """Accept a comma-separated extensions string and return a sorted
    deduped list of lowercase extensions without leading dots.
    Examples:
      "PNG, .jpg,jpeg, png" -> ["jpeg", "jpg", "png"]
      "" -> []
    """
    if not raw:
        return []
    seen = set()
    for tok in str(raw).split(","):
        t = tok.strip().lstrip(".").lower()
        if t:
            seen.add(t)
    return sorted(seen)


# v0.11.1 Profile palette. Eight presets cover the standard messaging-
# app palette space (purple/blue/teal/green/yellow/orange/red/pink).
# We validate against this set so the database can't be poisoned with
# garbage hex strings, and the UI picks from the same list. Adding a
# new color is a coordinated edit on both sides.
AVATAR_COLOR_PRESETS = (
    "#7c4dff",  # default purple (current avatar gradient base)
    "#3b82f6",  # blue
    "#06b6d4",  # teal
    "#10b981",  # green
    "#facc15",  # yellow
    "#f97316",  # orange
    "#ef4444",  # red
    "#ec4899",  # pink
)
# v0.11.1 bio cap. 140 chars matches the long-established "short
# status" convention from Twitter/Signal/Telegram.
BIO_MAX_LENGTH = 140


# ─── v0.10.6 native folder picker ─────────────────────────────────────
#
# The first cut used tkinter.filedialog. On Windows that pops a Tk Tcl
# wrapper around the system dialog — the title bar shows the Tk feather
# icon and the frame doesn't get DPI-scaled, so the whole thing looks
# fuzzy on hi-DPI displays. We now dispatch to the platform-native
# picker:
#   Windows : PowerShell + WinForms FolderBrowserDialog (Vista-style;
#             AutoUpgradeEnabled=$true makes it the same dialog
#             File Explorer uses).
#   macOS   : osascript "choose folder" — Cocoa native.
#   Linux   : zenity → kdialog → tkinter (last resort).
#
# Tests patch _native_folder_picker directly so they don't depend on
# any specific platform implementation.

_PICK_TIMEOUT_S = 600  # 10-min hard cap, enough for slow browsing.


def _pick_win_powershell(title: str) -> Optional[str]:
    """Native Windows folder picker via PowerShell + WinForms.
    Returns absolute path on success, None on cancel/unavailable."""
    safe_title = title.replace("'", "''")
    script = (
        "Add-Type -AssemblyName System.Windows.Forms | Out-Null\n"
        "$d = New-Object System.Windows.Forms.FolderBrowserDialog\n"
        f"$d.Description = '{safe_title}'\n"
        "$d.UseDescriptionForTitle = $true\n"
        "$d.AutoUpgradeEnabled = $true\n"
        "$d.ShowNewFolderButton = $true\n"
        "$null = $d.ShowDialog()\n"
        "Write-Output $d.SelectedPath\n"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=_PICK_TIMEOUT_S,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as e:
        log.debug("powershell folder picker failed: %s", e)
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def _pick_mac_osascript(title: str) -> Optional[str]:
    """Native macOS folder picker via osascript. Returns POSIX path."""
    safe = title.replace('"', '\\"')
    try:
        proc = subprocess.run(
            ["osascript", "-e",
             f'POSIX path of (choose folder with prompt "{safe}")'],
            capture_output=True, text=True, timeout=_PICK_TIMEOUT_S,
        )
    except Exception as e:
        log.debug("osascript folder picker failed: %s", e)
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip().rstrip("/")
    return out or None


def _pick_linux(title: str) -> Optional[str]:
    """Linux folder picker. Tries zenity (GNOME) then kdialog (KDE)."""
    home = os.path.expanduser("~")
    attempts = (
        ["zenity", "--file-selection", "--directory", f"--title={title}"],
        ["kdialog", "--getexistingdirectory", "--title", title, home],
    )
    for cmd in attempts:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_PICK_TIMEOUT_S,
            )
        except FileNotFoundError:
            continue
        except Exception as e:
            log.debug("%s folder picker failed: %s", cmd[0], e)
            continue
        if proc.returncode == 0:
            out = (proc.stdout or "").strip()
            return out or None
    # Both unavailable / cancelled — fall through to tkinter as a last
    # resort so headless-test environments still get a sensible result.
    return _pick_tkinter_fallback(title)


def _pick_tkinter_fallback(title: str) -> Optional[str]:
    """Last-resort fallback. We enable DPI awareness on Windows so at
    least the dialog isn't blurry on hi-DPI screens."""
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            import ctypes
            try:
                # Per-monitor v2 — sharpest on Win10+.
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
    try:
        import tkinter
        from tkinter import filedialog
    except Exception:
        return None
    try:
        root = tkinter.Tk()
    except Exception:
        return None
    try:
        root.withdraw()
        with contextlib.suppress(Exception):
            root.attributes("-topmost", True)
        with contextlib.suppress(Exception):
            root.lift()
        path = filedialog.askdirectory(
            parent=root, title=title, mustexist=True,
        )
    finally:
        with contextlib.suppress(Exception):
            root.destroy()
    return path or None


def _native_folder_picker(title: str) -> Optional[str]:
    """Dispatch to the most native folder picker available on this OS.
    Tests patch this entry point directly.

    Honors ONE_LINK_DISABLE_NATIVE_PICKER as a kill switch — set in
    the test fixture so no run can ever pop a real OS dialog even if
    a test forgets to patch."""
    if os.environ.get("ONE_LINK_DISABLE_NATIVE_PICKER"):
        return None
    if sys.platform == "win32":
        picked = _pick_win_powershell(title)
        if picked is not None:
            return picked
        # If PowerShell is missing or restricted, fall back to the
        # DPI-aware tk dialog so the user isn't completely stuck.
        return _pick_tkinter_fallback(title)
    if sys.platform == "darwin":
        picked = _pick_mac_osascript(title)
        if picked is not None:
            return picked
        return _pick_tkinter_fallback(title)
    return _pick_linux(title)


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
    if "ratchet header version" in msg or "ratchet frame too short" in msg:
        return {
            "status": 502,
            "code": "secure_session_desync",
            "error": "The secure connection needs to refresh before sending.",
            "hint": "One Link preserved the transfer and will retry on a fresh secure session automatically.",
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
    # v0.10.2: disappearing-message expiry. UI renders the
    # countdown badge from this field + the current time.
    if getattr(rec, "expires_at_ms", None):
        out["expires_at_ms"] = rec.expires_at_ms
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
    event = {
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
        "metadata": _compact_transfer_metadata(rec.metadata),
    }
    return enrich_transfer_event(event, now_ms=int(time.time() * 1000))


def _compact_transfer_metadata(metadata: dict | None) -> dict:
    """Return UI/API-safe transfer metadata.

    The durable ledger may keep a full chunk manifest so resume/dedup logic has
    complete truth. The browser and status endpoints should never receive that
    whole list: a multi-GB video can mean thousands of chunks and megabytes of
    JSON. Surface a compact manifest summary instead.
    """
    if not metadata:
        return {}
    out = dict(metadata)
    manifest = out.get("manifest")
    if isinstance(manifest, dict):
        chunks = manifest.get("chunks")
        chunk_count = (
            len(chunks) if isinstance(chunks, list)
            else int(manifest.get("chunk_count") or 0)
        )
        out["manifest"] = {
            "name": manifest.get("name"),
            "size": manifest.get("size"),
            "blob": manifest.get("blob"),
            "chunk_count": chunk_count,
        }
    return out


def _token_path() -> Path:
    return data_dir() / TOKEN_FILE


def _server_port_path() -> Path:
    return data_dir() / SERVER_PORT_FILE


def _detect_lan_ip() -> str:
    """v0.15.4 — best-effort LAN IPv4. UDP-connect-to-public-DNS
    trick: the OS picks the egress interface but no packet is
    actually sent. Returns 127.0.0.1 if there's no usable interface
    (airplane mode, no Wi-Fi). Same logic as one_link.app, duplicated
    here to keep server.py free of an app.py import (server is a
    leaf module; app launches the daemon and imports server)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


class UIServer:
    """Wraps the aiohttp app + the websocket event broker."""

    def __init__(self, daemon: "Daemon"):
        self.daemon = daemon
        # Persistent token: load from disk if a previous daemon left one,
        # so any open browser tab keeps working across restarts. New
        # install → fresh token. Token is never embedded in any wire
        # protocol; it's purely for the local UI surface.
        # v0.20.7: load via the daemon-aware path so a lockbox-wrapped
        # token round-trips correctly. Daemon.state may not yet have a
        # lockbox at the moment UIServer is constructed (depends on
        # init order); the loader handles that case by rotating to a
        # fresh cleartext token, which then gets re-wrapped on the
        # next ``write_text`` flush.
        self.token = self._load_or_create_token(daemon)
        self.app = web.Application(
            client_max_size=1024 * 1024 * 1024,  # 1 GiB upload
            middlewares=[self._security_middleware],
        )
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.port: int = 0
        # v0.15.2: which interface the UI server is bound to. Set in
        # start() — readers (e.g. /api/me, control "status" report)
        # surface this so the launcher knows whether LAN mode is on.
        self.bind_host: str = "127.0.0.1"
        self._ws_clients: set[web.WebSocketResponse] = set()
        self._rate_buckets: dict[tuple[str, str], deque[float]] = {}
        # v0.20.0: WebRTC peer manager for browser-as-peer connections.
        # Lazy-imported so daemons that don't ship aiortc still load
        # this module (the manager itself works fine; only the actual
        # peer-connection setup needs aiortc).
        from one_link.peer_rtc import BrowserPeerManager
        self.peer_rtc = BrowserPeerManager(daemon)
        # v0.20.4: HTTPS listener metadata. Declared here so tests
        # that create UIServer without calling start() can still
        # read these attributes without an AttributeError. Real
        # values populated by _start_https_listener().
        self.https_site = None
        self.https_port = None
        self.https_cert_fp_sha256 = None
        # v0.20.2: hook the data-bridge listener so browser-peers
        # can fetch peer rosters + recent messages from the daemon
        # over the DataChannel. Without this hook, /peer phones
        # connect but see nothing of the daemon's chat history.
        self.peer_rtc.add_dc_listener(self._handle_browser_peer_request)
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

    @web.middleware
    async def _security_middleware(
        self,
        request: web.Request,
        handler,
    ) -> web.StreamResponse:
        """Defense-in-depth around the local UI HTTP surface.

        The app legitimately needs a large multipart budget for file uploads.
        JSON/control endpoints do not. Keep the global aiohttp limit high for
        uploads, then apply a much smaller cap to JSON-like requests before
        any handler calls request.json().
        """

        target = request.raw_path or request.path_qs or request.path
        if len(target.encode("utf-8", errors="ignore")) > MAX_REQUEST_TARGET_BYTES:
            return web.json_response({"error": "request target too large"}, status=414)
        # v0.20.7 (security audit H10): defeat DNS-rebinding + cross-
        # origin WebSocket hijacking on the loopback-bound UI. A user
        # who visits attacker.com can be served a page whose DNS A
        # record was rebound to 127.0.0.1, which would let attacker JS
        # reach this listener. The cookie's SameSite=Strict + the auth
        # token already block most exploitation paths, but the
        # browser-canonical mitigation is to refuse Host headers that
        # don't belong to this listener and refuse Origin headers from
        # foreign origins. We only enforce when bound to loopback (the
        # default); --lan / 0.0.0.0 mode is an explicit user opt-in to
        # LAN exposure where we can't enumerate the legit Host values.
        if not self._accept_request_host(request):
            return web.json_response(
                {"error": "host header rejected"}, status=421
            )
        if not self._accept_request_origin(request):
            return web.json_response(
                {"error": "cross-origin request rejected"}, status=403
            )
        content_type = (request.content_type or "").lower()
        if (
            request.method in ("POST", "PUT", "PATCH", "DELETE")
            and (
                content_type == "application/json"
                or content_type.endswith("+json")
                or request.path not in ("/api/send-file",)
            )
        ):
            size = request.content_length
            if size is not None and size > MAX_JSON_REQUEST_BYTES:
                return web.json_response({"error": "json body too large"}, status=413)
        resp = await handler(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        # v0.20.7 (security audit M15): aiohttp emits "Server: Python/x.y
        # aiohttp/z.z.z" by default, which hands an attacker the exact
        # version of the request handler to scan for known CVEs. Replace
        # with a generic identifier; the daemon's actual version still
        # ships via /api/connect-info to authenticated clients.
        resp.headers["Server"] = "one-link"
        return resp

    # v0.20.7 (security audit H10): DNS-rebinding + CSWSH defenses.
    # Both helpers return True when the request is acceptable. They
    # return False (caller answers 421/403) only when the daemon is
    # on a loopback bind AND the request's Host or Origin would point
    # at a foreign origin. A --lan / 0.0.0.0 bind is an explicit user
    # opt-in to LAN exposure where we can't enumerate the legit Host
    # values browsers might present.
    _LOOPBACK_BIND_HOSTS = ("127.0.0.1", "localhost", "::1", "::")
    _LOOPBACK_VALID_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

    def _is_loopback_bound(self) -> bool:
        bind = (self.bind_host or "127.0.0.1").lower()
        return bind in self._LOOPBACK_BIND_HOSTS

    def _accept_request_host(self, request: web.Request) -> bool:
        if not self._is_loopback_bound():
            return True
        host_header = (request.host or "").strip().lower()
        if not host_header:
            return False
        # Handle bracketed IPv6 ([::1]:port).
        if host_header.startswith("["):
            if "]" not in host_header:
                return False
            host_only = host_header[1:host_header.index("]")]
        elif ":" in host_header:
            host_only = host_header.split(":", 1)[0]
        else:
            host_only = host_header
        return host_only in self._LOOPBACK_VALID_HOSTS

    def _accept_request_origin(self, request: web.Request) -> bool:
        # No Origin = direct fetch / same-origin nav. Browsers add
        # Origin on cross-origin requests + every WebSocket upgrade.
        origin = (request.headers.get("Origin") or "").strip()
        if not origin:
            return True
        if not self._is_loopback_bound():
            return True
        try:
            from urllib.parse import urlparse
            parsed = urlparse(origin)
            host = (parsed.hostname or "").lower()
        except Exception:
            return False
        return host in self._LOOPBACK_VALID_HOSTS

    async def _probe_owned_http_port(self, bind_host: str, port: int) -> bool:
        """Return True only if the HTTP listener reached on this port is us.

        Windows can allow a same-port bind path to appear successful while
        the browser-visible connection still reaches an older daemon with a
        different token. Before publishing server.port, verify the endpoint
        answers our own token-gated status request.
        """
        host = "127.0.0.1" if bind_host in ("0.0.0.0", "127.0.0.1") else bind_host
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=0.5,
            )
            request = (
                "GET /api/status HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Authorization: Bearer {self.token}\r\n"
                "Connection: close\r\n\r\n"
            )
            writer.write(request.encode("ascii"))
            await asyncio.wait_for(writer.drain(), timeout=0.5)
            head = await asyncio.wait_for(reader.read(256), timeout=0.8)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            first_line = head.split(b"\r\n", 1)[0]
            return b" 200 " in first_line
        except Exception as e:
            log.debug(
                "UI port ownership probe failed for %s:%d: %s",
                host, port, e,
            )
            return False

    # v0.20.7 (security audit M29): when the daemon has a lockbox
    # configured (ONE_LINK_PASSPHRASE set), persist the UI token in
    # wrapped form. File format:
    #   - cleartext (legacy): raw base64url token, possibly with
    #     trailing whitespace.
    #   - wrapped (new): "OLB1:" prefix + base64url(LockBox.wrap(token)).
    # The prefix disambiguates without needing a length check.
    _TOKEN_WRAPPED_PREFIX = "OLB1:"

    @staticmethod
    def _load_or_create_token(daemon: "Daemon | None" = None) -> str:
        import base64 as _b64
        p = _token_path()
        try:
            raw = p.read_text(encoding="utf-8").strip()
            if raw.startswith(UIServer._TOKEN_WRAPPED_PREFIX):
                # Wrapped path — needs the daemon's lockbox to unwrap.
                lb = None
                if daemon is not None and daemon.state is not None:
                    lb = getattr(daemon.state, "_lockbox", None)
                if lb is None:
                    log.warning(
                        "UI token file is wrapped but lockbox is not "
                        "configured; rotating to a fresh cleartext token"
                    )
                else:
                    try:
                        blob = _b64.urlsafe_b64decode(
                            raw[len(UIServer._TOKEN_WRAPPED_PREFIX):].encode("ascii")
                        )
                        plain = lb.unwrap(blob).decode("ascii")
                        if len(plain) >= 32 and all(
                            c.isalnum() or c in "-_" for c in plain
                        ):
                            return plain
                    except Exception as e:
                        log.warning(
                            "UI token unwrap failed (%s); rotating to "
                            "a fresh token", e,
                        )
            else:
                # Tokens we generate are 43 base64url chars (32 raw
                # bytes). Be lenient on length but enforce at least
                # 32 chars so a corrupted file can't turn into an
                # unsafe short token.
                if len(raw) >= 32 and all(
                    c.isalnum() or c in "-_" for c in raw
                ):
                    return raw
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
        # v0.14.0: Service Worker for background-sync (offline outbox)
        # + cache-first shell. Must be served from root scope to be
        # allowed to control "/" requests; not auth-gated since the
        # SW itself contains no PII (only the URL paths it caches +
        # the outbox-drain logic that re-uses the page's cookie).
        r.add_get("/sw.js", self._service_worker)
        # v0.15.0: Web App Manifest. Browsers fetch /manifest.json
        # from the page's `<link rel="manifest">`; presence + correct
        # MIME is what enables the install prompt + standalone-mode
        # behavior. Like sw.js, served unauthenticated because it
        # contains zero PII (just the app's display chrome).
        r.add_get("/manifest.json", self._manifest)
        # v0.16.0: browser-as-peer shell. Unauthenticated route —
        # the page authenticates itself via its own keypair (held
        # in OPFS), not the daemon's UI token. From this page the
        # browser is its own peer; the daemon is unrelated.
        r.add_get("/peer", self._peer_shell)
        r.add_get("/peer/", self._peer_shell)
        # v0.20.7 (security audit H7): JS port of the Double Ratchet
        # for browser-as-peer DataChannel transport. Standalone ESM
        # module + a self-test page that exercises the round-trip
        # in-browser (open /dr_test in any tab to see the suite).
        r.add_get("/dr.js", self._dr_module)
        r.add_get("/dr_test", self._dr_test_page)
        r.add_get("/dr_test.html", self._dr_test_page)
        # v0.20.0: WebRTC signaling endpoint for browser-as-peer ↔
        # daemon DataChannel transport. Unauthenticated WebSocket;
        # the browser authenticates via Ed25519 signature on the SDP
        # offer envelope (signed_offer.signature verified against
        # signed_offer.pubkey before we accept the peer connection).
        r.add_get("/api/v1/peer-rtc", self._peer_rtc_signaling)
        # v0.20.1: pair-by-QR token mint. Auth-gated (token holder
        # is the desktop user). Returns a fresh one-shot pairing
        # token that the browser-peer presents during signaling so
        # the daemon trusts it as a paired device with no manual
        # SAS confirm.
        r.add_post("/api/v1/peer-rtc/mint-pairing", self._guarded(self.api_mint_pairing))
        # v0.20.1: render the most-recently-minted pairing token's
        # LAN URL as an SVG QR. Hits the desktop UI's "Pair a phone"
        # surface; saves us shipping a JS QR library.
        r.add_get("/api/v1/peer-rtc/qr.svg", self._guarded(self.api_pair_qr))
        # v0.20.6: iOS Configuration Profile that installs the
        # daemon's self-signed cert as a trusted root. Phones load
        # this URL via Safari, which auto-prompts to install the
        # profile. After install, the regular pair URL (HTTPS)
        # works with zero "Not Private" warnings. Unauthenticated
        # because iOS Safari doesn't carry the bearer token across
        # the profile-install handoff; cert-as-data leaks no PII
        # since it's the same self-signed cert anyone on the LAN
        # would see during a TLS handshake anyway.
        r.add_get("/api/v1/peer-rtc/profile.mobileconfig", self._pair_profile)
        # v0.15.4: connect-info + QR for the phone-pairing flow.
        # Both auth-gated — they expose the LAN URL with the token.
        r.add_get("/api/connect-info", self._guarded(self.api_connect_info))
        r.add_get("/api/connect-info/qr.svg", self._guarded(self.api_connect_info_qr))
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
        # v0.10.2 disappearing messages — per-peer TTL.
        r.add_post(r"/api/peers/{fp}/ttl", self._guarded(self.api_set_peer_ttl))
        # v0.11.2 per-chat mute with duration (peer + group).
        r.add_post(r"/api/peers/{fp}/mute", self._guarded(self.api_set_peer_mute))
        r.add_post(r"/api/groups/{gid}/mute", self._guarded(self.api_set_group_mute))
        # v0.11.5 per-chat tools.
        r.add_delete(r"/api/peers/{fp}/history", self._guarded(self.api_clear_peer_history))
        r.add_delete(r"/api/groups/{gid}/history", self._guarded(self.api_clear_group_history))
        r.add_get(r"/api/peers/{fp}/export", self._guarded(self.api_export_peer))
        r.add_get(r"/api/groups/{gid}/export", self._guarded(self.api_export_group))
        r.add_get(r"/api/peers/{fp}/media", self._guarded(self.api_peer_media))
        # v0.11.6 storage breakdown.
        r.add_get("/api/storage/usage", self._guarded(self.api_storage_usage))
        # v0.12.1 server-persisted per-chat cosmetic state.
        # Single GET returns a snapshot of everything; PATCH-like
        # POST sets one field at a time. Keys are scope-prefixed to
        # avoid collision with other settings.
        r.add_get("/api/chat-prefs", self._guarded(self.api_get_chat_prefs))
        r.add_post("/api/chat-prefs", self._guarded(self.api_set_chat_pref))
        # v0.10.4 presence — set self status; broadcasts to peers.
        r.add_post("/api/presence", self._guarded(self.api_set_presence))
        # v0.10.6 native folder picker — pops a tk dialog on the
        # daemon's desktop. For local-only One Link sessions that's
        # the same machine the user is browsing from.
        r.add_post("/api/fs/pick-folder", self._guarded(self.api_pick_folder))
        # v0.7.8 key-change events.
        r.add_get("/api/key-change-events", self._guarded(self.api_list_key_change_events))
        r.add_post(r"/api/key-change-events/{event_id}/ack", self._guarded(self.api_ack_key_change_event))
        r.add_post(r"/api/peers/{fp}/key-change-events/ack-all", self._guarded(self.api_ack_peer_key_change_events))
        r.add_get(r"/api/peers/{fp}/key-history", self._guarded(self.api_get_peer_key_history))
        # v0.8.6 trust history (merged audit timeline for one peer).
        r.add_get(r"/api/peers/{fp}/trust-history", self._guarded(self.api_get_peer_trust_history))
        # v0.9.1 cross-peer activity feed (merged audit log).
        r.add_get("/api/activity", self._guarded(self.api_get_activity_feed))
        # v0.9.3 global search backing the Ctrl+K command palette.
        # NOTE: /api/search is the legacy per-conversation FTS
        # finder (see api_search). /api/palette is the merged-results
        # endpoint that searches messages + peers + groups + files
        # in one shot.
        r.add_get("/api/palette", self._guarded(self.api_global_search))
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
        # v0.12.3 typing indicator. POST-only; no GET because the
        # UI receives via WS peer_typing event (push, not pull).
        r.add_post(r"/api/peers/{fp}/typing", self._guarded(self.api_set_typing))
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
        # v0.11.3 promote/demote a group member.
        r.add_post(
            r"/api/groups/{gid}/members/{member_fp}/role",
            self._guarded(self.api_set_group_member_role),
        )
        r.add_delete(
            r"/api/groups/{gid}/members/{member_fp}",
            self._guarded(self.api_remove_group_member),
        )
        r.add_post(r"/api/groups/{gid}/leave", self._guarded(self.api_leave_group))
        r.add_get("/api/search", self._guarded(self.api_search))
        # v0.8.1: developer backend.
        r.add_get("/api/debug/log", self._guarded(self.api_debug_log))
        r.add_post("/api/debug/log/clear", self._guarded(self.api_debug_clear))
        # v0.11.4: /api/debug/health stays unauthenticated when the
        # daemon is loopback-bound (the original UX rationale: works
        # even when the session cookie has expired, "open this when
        # something feels broken"). v0.20.7 (security audit M14) closes
        # the LAN-exposure escape hatch: under --lan / 0.0.0.0 bind the
        # endpoint requires the token like every other /api route, so a
        # LAN-adjacent attacker can't fingerprint One Link via
        # schema_version + peer_count + disk paths.
        async def _health_guarded(request: web.Request) -> web.StreamResponse:
            if not self._is_loopback_bound():
                if not self._check_token(request):
                    if self._rate_limited(
                        "auth_fail",
                        self._client_rate_key(request),
                        limit=MAX_FAILED_AUTH_ATTEMPTS,
                    ):
                        return web.json_response(
                            {"error": "too many authentication attempts"},
                            status=429,
                        )
                    return web.json_response(
                        {"error": "unauthorized"}, status=401
                    )
            return await self.api_debug_health(request)
        r.add_get("/api/debug/health", _health_guarded)
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
        # v0.20.7 (security audit L12): use hmac.compare_digest for
        # constant-time equality so a timing oracle cannot be used to
        # extract token bytes one byte at a time. Token is 256 bits +
        # rate-limited at the _guarded layer, so brute-force is already
        # infeasible; this closes the primitive even so.
        cookie_token = request.cookies.get(COOKIE_NAME, "")
        if cookie_token and hmac.compare_digest(cookie_token, self.token):
            return True
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            presented = auth[7:]
            if presented and hmac.compare_digest(presented, self.token):
                return True
        return False

    def _client_rate_key(self, request: web.Request) -> str:
        peer = request.transport.get_extra_info("peername") if request.transport else None
        if isinstance(peer, tuple) and peer:
            return str(peer[0])
        return request.remote or "unknown"

    def _rate_limited(
        self,
        bucket_name: str,
        key: str,
        *,
        limit: int,
        window_seconds: float = RATE_LIMIT_WINDOW_SECONDS,
    ) -> bool:
        now = time.monotonic()
        bucket_key = (bucket_name, key)
        bucket = self._rate_buckets.setdefault(bucket_key, deque())
        cutoff = now - window_seconds
        while bucket and bucket[0] <= cutoff:
            bucket.popleft()
        if len(bucket) >= limit:
            return True
        bucket.append(now)
        return False

    def _guarded(self, handler):
        async def wrap(request: web.Request) -> web.StreamResponse:
            if not self._check_token(request):
                if self._rate_limited(
                    "auth_fail",
                    self._client_rate_key(request),
                    limit=MAX_FAILED_AUTH_ATTEMPTS,
                ):
                    return web.json_response(
                        {"error": "too many authentication attempts"},
                        status=429,
                    )
                return web.json_response({"error": "unauthorized"}, status=401)
            return await handler(request)
        return wrap

    def _guarded_ws(self, handler):
        async def wrap(request: web.Request) -> web.WebSocketResponse:
            if not self._check_token(request):
                if self._rate_limited(
                    "auth_fail",
                    self._client_rate_key(request),
                    limit=MAX_FAILED_AUTH_ATTEMPTS,
                ):
                    return web.Response(
                        status=429,
                        text="too many authentication attempts",
                    )
                ws = web.WebSocketResponse()
                if ws.can_prepare(request).ok:
                    await ws.prepare(request)
                    await ws.close(code=4401, message=b"unauthorized")
                return ws
            return await handler(request)
        return wrap

    async def _service_worker(self, request: web.Request) -> web.StreamResponse:
        """v0.14.0: serve sw.js from root with the right
        Service-Worker-Allowed scope header so it can control "/".
        Cache-Control set to no-store: a stale SW pinning an old
        shell is a debugging nightmare we'd rather avoid."""
        sw = WEB_DIR / "sw.js"
        if not sw.is_file():
            return web.Response(status=404, text="sw not bundled")
        body = sw.read_text(encoding="utf-8")
        resp = web.Response(text=body, content_type="application/javascript")
        resp.headers["Service-Worker-Allowed"] = "/"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def _manifest(self, request: web.Request) -> web.StreamResponse:
        """v0.15.0: serve manifest.json with the right content-type
        (`application/manifest+json`) — without it, some browsers
        (esp. Firefox) decline to install the PWA. Cache-Control is
        a moderate `max-age=3600` so an updated manifest reaches
        users within an hour without requiring a hard refresh."""
        mf = WEB_DIR / "manifest.json"
        if not mf.is_file():
            return web.Response(status=404, text="manifest not bundled")
        body = mf.read_text(encoding="utf-8")
        resp = web.Response(text=body, content_type="application/manifest+json")
        resp.headers["Cache-Control"] = "max-age=3600"
        return resp

    async def _peer_shell(self, request: web.Request) -> web.StreamResponse:
        """v0.16.0: browser-as-peer shell. Serves peer.html which is a
        self-contained page: the browser is its own One Link node with
        its own identity stored in OPFS, not the daemon's UI proxy.

        Unauthenticated by design. The page authenticates itself via
        its own keypair to other peers via WebRTC + rendezvous; the
        daemon's UI token is irrelevant here. The page can be served
        from any host (a phone PWA cache, a static mirror, the user's
        laptop) and the browser-peer logic is identical."""
        peer = WEB_DIR / "peer.html"
        if not peer.is_file():
            return web.Response(status=404, text="peer shell not bundled")
        body = peer.read_text(encoding="utf-8")
        resp = web.Response(text=body, content_type="text/html")
        # Tight CSP for the peer shell. We allow only same-origin
        # scripts (the browser-peer logic is bundled inline below; no
        # third-party JS), inline styles (CSS lives in the same
        # document), and connections to wss/https (rendezvous +
        # WebRTC signaling). data: images are needed for QR rendering.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' wss: https:; "
            "frame-ancestors 'none'"
        )
        # The peer page contains no PII per se — it's a shell that
        # builds identity client-side — so caching the HTML for an
        # hour is fine. The IDENTITY itself lives in OPFS, not the
        # HTML, so a stale shell is just stale code, not stale auth.
        resp.headers["Cache-Control"] = "max-age=3600"
        return resp

    async def _dr_module(self, request: web.Request) -> web.StreamResponse:
        """v0.20.7 (audit H7): JS Double Ratchet module. Standalone
        ESM file the peer shell imports for forward-secrecy + post-
        compromise security on the browser-as-peer DataChannel."""
        p = WEB_DIR / "dr.js"
        if not p.is_file():
            return web.Response(status=404, text="dr.js not bundled")
        body = p.read_text(encoding="utf-8")
        resp = web.Response(text=body, content_type="application/javascript")
        resp.headers["Cache-Control"] = "max-age=3600"
        return resp

    async def _dr_test_page(self, request: web.Request) -> web.StreamResponse:
        """v0.20.7 (audit H7): JS Double Ratchet self-test harness.
        Open /dr_test in any browser to run the unit-test suite for
        the module — exercises round-trip, replay rejection, tamper
        rejection, OOO delivery, small-order rejection, header
        encode/decode, kdf advance. Useful for verifying browser
        compatibility (X25519 in WebCrypto requires a recent build)."""
        p = WEB_DIR / "dr_test.html"
        if not p.is_file():
            return web.Response(status=404, text="dr_test.html not bundled")
        body = p.read_text(encoding="utf-8")
        resp = web.Response(text=body, content_type="text/html")
        # Self-test page: same-origin scripts only; no third-party fetches.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "frame-ancestors 'none'"
        )
        resp.headers["Cache-Control"] = "no-store"
        return resp

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
        # v0.20.7 (security audit H9): Content-Security-Policy on the
        # main UI. The previous response set X-Frame-Options + X-CTO
        # via the security middleware but no CSP, so a regression
        # that introduced an XSS sink would have nothing blocking
        # exfiltration. SECURITY.md commits to a strict CSP; this
        # gets us defense-in-depth coverage without breaking the
        # bundled UI's existing inline scripts/styles. Mirrors the
        # /peer shell CSP shape with adjustments for index's local
        # WebSocket target. Tighten further once the bundle is
        # refactored to remove inline scripts.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss: https:; "
            "media-src 'self' blob:; "
            "worker-src 'self' blob:; "
            "frame-src 'none'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'none'"
        )
        if bootstrap_ok or request.cookies.get(COOKIE_NAME) == self.token:
            # v0.20.7 (security audit M13): mark Secure when this very
            # request was served over HTTPS so the cookie can never be
            # echoed back over plain HTTP. We can't unconditionally set
            # Secure because the daemon also serves the same UI over
            # plain http://127.0.0.1 by default; setting Secure on a
            # plain-http response makes the browser drop the cookie.
            # Tying it to request.scheme keeps the loopback story
            # working while making the LAN-HTTPS path leak-proof.
            resp.set_cookie(
                COOKIE_NAME,
                self.token,
                httponly=True,
                samesite="Strict",
                secure=(request.scheme == "https"),
                max_age=86400,
                path="/",
            )
        return resp

    # ─── /api/connect-info ────────────────────────────────────────────
    def _connect_info(self) -> dict:
        """Return the dict the connect-info endpoint serializes. Pulled
        out so the QR endpoint can reuse the same URL string and not
        diverge on a refactor."""
        lan_ip = _detect_lan_ip()
        # If the daemon's loopback-bound, the LAN URL we'd encode
        # would be useless on a phone (127.0.0.1 from a phone hits
        # the phone itself). Surface a hint instead.
        lan_bound = (
            self.bind_host not in ("127.0.0.1", "localhost", "::1")
            and lan_ip != "127.0.0.1"
        )
        host_for_url = lan_ip if lan_bound else "127.0.0.1"
        url = f"http://{host_for_url}:{self.port}/?t={self.token}"
        return {
            "lan_ip": lan_ip,
            "port": self.port,
            "token": self.token,
            "bind_host": self.bind_host,
            "lan_bound": lan_bound,
            "lan_url": url,
        }

    async def api_connect_info(self, request: web.Request) -> web.Response:
        """v0.15.4: returns the URL + token + LAN binding state so the
        UI can render the "connect another device" affordance. Auth
        gated — this exposes the token; only the already-authenticated
        UI should see it."""
        return web.json_response(self._connect_info())

    async def api_connect_info_qr(self, request: web.Request) -> web.Response:
        """v0.15.4: returns an SVG QR code encoding the LAN URL. Auth
        gated for the same reason as the JSON variant. SVG is chosen
        over PNG because it scales crisply on phone retina displays
        and doesn't need Pillow."""
        info = self._connect_info()
        if not info["lan_bound"]:
            # Don't render a QR for the loopback URL; it's useless on
            # a phone. Return 409 + JSON hint so the UI can show the
            # "pass --lan" tip instead.
            return web.json_response(
                {
                    "error": "loopback_only",
                    "hint": (
                        "Daemon is bound to 127.0.0.1. Restart with "
                        "`one-link app --lan` to expose the UI to "
                        "your local Wi-Fi."
                    ),
                },
                status=409,
            )
        try:
            import qrcode
            import qrcode.image.svg
        except ImportError:
            return web.json_response(
                {"error": "qrcode_lib_missing", "hint": "pip install qrcode>=7"},
                status=500,
            )
        qr = qrcode.QRCode(border=2, box_size=8)
        qr.add_data(info["lan_url"])
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        import io
        buf = io.BytesIO()
        img.save(buf)
        svg_body = buf.getvalue().decode("utf-8")
        resp = web.Response(text=svg_body, content_type="image/svg+xml")
        # Don't cache: the URL contains the token, which can rotate.
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ─── /api/v1/peer-rtc — browser-as-peer WebRTC signaling + pair ──
    async def api_mint_pairing(self, request: web.Request) -> web.Response:
        """v0.20.1: mint a fresh single-use pairing token + return
        the laptop's connection info. The desktop UI will encode
        this into a QR for the user to scan with their phone.

        Returns: {token, ttl_ms, lan_url, daemon_pubkey_b64u,
                  daemon_fingerprint, ws_signaling_url}

        ws_signaling_url is the URL the browser-peer opens to
        exchange SDP. lan_url is the /peer page URL with the
        pairing token + daemon fingerprint embedded as query
        params (so the QR is one-scan magic)."""
        from one_link.peer_rtc import _b64u as _peer_b64u
        pp = self.peer_rtc.mint_pairing_token()
        # Daemon's own identity surface for the browser to pin.
        daemon_pub = self.daemon.me.public_bytes
        daemon_pub_b64u = _peer_b64u(daemon_pub)
        daemon_fp = self.daemon.me.fingerprint
        # v0.20.4 — pair URLs MUST use https:// when the daemon has
        # an HTTPS listener up, because phones running Safari /
        # Chrome over plain HTTP to a LAN IP can't access Web Crypto
        # (insecure context). With HTTPS the phone gets a "Not
        # Private" warning once, taps Continue, and Web Crypto
        # works from then on. Without HTTPS we still emit http://
        # so desktop browsers can use the pair flow over loopback,
        # but phones-over-LAN won't work.
        try:
            host = self.bind_host
            if host in ("0.0.0.0", "::", ""):
                from one_link.app import _detect_lan_ip
                host = _detect_lan_ip()
            if self.https_port:
                base = f"https://{host}:{self.https_port}"
                ws_scheme = "wss"
                ws_port = self.https_port
            else:
                base = f"http://{host}:{self.port}"
                ws_scheme = "ws"
                ws_port = self.port
        except Exception:
            base = f"http://{self.bind_host}:{self.port}"
            ws_scheme = "ws"
            ws_port = self.port
        ws_url = f"{ws_scheme}://{host}:{ws_port}/api/v1/peer-rtc"
        lan_url = (
            f"{base}/peer?pair={pp.token}&fp={daemon_fp}"
            f"&ws={ws_url}"
        )
        if self.https_cert_fp_sha256:
            # Embed the cert fingerprint so a future-ship phone-side
            # check can verify "this is the same cert my laptop
            # minted" before accepting the TLS connection. v0.20.4
            # just emits it; v0.20.5+ can pin against it.
            lan_url += f"&cert={self.https_cert_fp_sha256}"
        return web.json_response({
            "token": pp.token,
            "ttl_ms": pp.ttl_ms,
            "created_ms": pp.created_ms,
            "lan_url": lan_url,
            "https_available": self.https_port is not None,
            "https_cert_sha256": self.https_cert_fp_sha256,
            "daemon_pubkey_b64u": daemon_pub_b64u,
            "daemon_fingerprint": daemon_fp,
            "ws_signaling_url": ws_url,
            # v0.20.6 — iOS users need to install a Configuration
            # Profile FIRST so iOS trusts the self-signed cert.
            # We give the desktop UI two URLs to render as separate
            # QRs: one for the profile install (HTTP, always works),
            # one for the actual pair flow (HTTPS, only works after
            # profile is installed + trust toggled).
            "ios_profile_url": (
                f"http://{host}:{self.port}/api/v1/peer-rtc/profile.mobileconfig"
            ),
        })

    async def _pair_profile(self, request: web.Request) -> web.StreamResponse:
        """v0.20.6 — serve the iOS Configuration Profile that trusts
        the daemon's self-signed cert. iOS Safari recognises the
        `application/x-apple-aspen-config` MIME type and prompts the
        user to install. After install the cert is system-trusted
        and /peer over HTTPS loads without warnings.

        Two-step flow on the user's iPhone:
          1. Safari → this URL → iOS prompts "Install Profile"
          2. After install: Settings → General → About → Certificate
             Trust Settings → toggle on for "One Link Self-Signed CA"

        Both steps are required; Apple intentionally splits "install
        cert" from "trust cert for TLS." We surface this in the
        UI step-by-step.
        """
        try:
            from one_link.peer_https import build_mobileconfig
            from one_link.paths import data_dir
        except ImportError:
            return web.Response(status=501, text="peer_https module unavailable")
        try:
            payload = build_mobileconfig(data_dir())
        except Exception as e:
            log.warning("peer-https: mobileconfig build failed: %s", e)
            return web.Response(status=500, text=f"mobileconfig: {e}")
        resp = web.Response(
            body=payload,
            content_type="application/x-apple-aspen-config",
        )
        resp.headers["Cache-Control"] = "no-store"
        # Suggested file name when downloaded outside Safari.
        resp.headers["Content-Disposition"] = (
            'attachment; filename="one-link-trust.mobileconfig"'
        )
        return resp

    async def api_pair_qr(self, request: web.Request) -> web.StreamResponse:
        """v0.20.1: render an arbitrary URL as a QR SVG. Auth-gated.
        Used by the desktop UI to render the pairing URL the
        mint-pairing endpoint returned. Saves us shipping a JS
        QR library.

        Limit: 2KB URL cap. A QR holding more than that won't
        scan reliably on a phone camera anyway."""
        url = request.query.get("u", "").strip()
        if not url:
            return web.json_response(
                {"error": "missing_u", "hint": "pass `u=<url>` query param"},
                status=400,
            )
        if len(url) > 2048:
            return web.json_response(
                {"error": "url_too_long", "hint": "max 2048 chars"},
                status=413,
            )
        try:
            import qrcode
            import qrcode.image.svg
        except ImportError:
            return web.json_response(
                {"error": "qrcode_lib_missing", "hint": "pip install qrcode>=7"},
                status=500,
            )
        qr = qrcode.QRCode(border=2, box_size=8)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        import io
        buf = io.BytesIO()
        img.save(buf)
        svg_body = buf.getvalue().decode("utf-8")
        resp = web.Response(text=svg_body, content_type="image/svg+xml")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    async def _peer_rtc_signaling(
        self, request: web.Request
    ) -> web.WebSocketResponse:
        """v0.20.0: WebSocket signaling endpoint for browser-as-peer
        WebRTC connections. Handles the offer → answer + ICE trickle
        + DataChannel-up handshake, then closes the WS (the
        DataChannel is the live transport from then on).

        Authentication: the browser's first text frame is a signed
        offer envelope (Ed25519 over canonical JSON). We verify the
        signature against the claimed pubkey before any aiortc work
        starts — a malicious client can't make us spend CPU on SDP
        negotiation without proving control of a real keypair.

        Trust: if the offer envelope carries a valid pair_token, we
        consume the token and trust this pubkey as a freshly-paired
        device. Otherwise we check our roster of previously-paired
        pubkeys; if the pubkey is recognized, we accept. Unknown
        pubkey + no token → 4030 close.
        """
        # aiortc imports are lazy so this module loads even on
        # daemons without aiortc. If we get here, we need it.
        try:
            from aiortc import (
                RTCConfiguration,
                RTCIceServer,
                RTCPeerConnection,
                RTCSessionDescription,
            )
        except ImportError:
            return web.Response(status=501, text="aiortc not installed")

        from one_link.peer_rtc import (
            BrowserPeer,
            DAEMON_BULK_LABEL,
            DAEMON_CONTROL_LABEL,
            MAX_SIGNALING_TEXT_BYTES,
            PEER_RTC_PROTOCOL_VERSION,
        )

        if self._rate_limited(
            "peer_rtc_signaling",
            self._client_rate_key(request),
            limit=MAX_SIGNALING_ATTEMPTS,
        ):
            return web.Response(status=429, text="too many signaling attempts")

        ws = web.WebSocketResponse(heartbeat=20.0)
        await ws.prepare(request)

        peer: Optional[BrowserPeer] = None
        pc = None

        async def _send(msg: dict) -> None:
            with contextlib.suppress(Exception):
                await ws.send_json(msg)

        async def _send_error(code: str, message: str) -> None:
            await _send({
                "v": PEER_RTC_PROTOCOL_VERSION,
                "t": "error",
                "code": code,
                "message": message,
            })

        # Multi-vendor STUN. Same set the browser uses; both sides
        # converging on the same servers keeps NAT-traversal symmetric.
        stun_servers = [
            RTCIceServer(urls="stun:stun.l.google.com:19302"),
            RTCIceServer(urls="stun:global.stun.twilio.com:3478"),
            RTCIceServer(urls="stun:stun.cloudflare.com:3478"),
        ]
        config = RTCConfiguration(iceServers=stun_servers)

        try:
            async for msg in ws:
                if msg.type != WSMsgType.TEXT:
                    continue
                if len(msg.data.encode("utf-8", errors="ignore")) > MAX_SIGNALING_TEXT_BYTES:
                    await _send_error("frame_too_large", "signaling frame too large")
                    await ws.close(code=1009, message=b"signaling frame too large")
                    return ws
                try:
                    envelope = json.loads(msg.data)
                except json.JSONDecodeError:
                    await _send_error("bad_json", "invalid JSON")
                    continue
                if not isinstance(envelope, dict):
                    await _send_error("bad_envelope", "envelope must be object")
                    continue
                if envelope.get("v") != PEER_RTC_PROTOCOL_VERSION:
                    await _send_error("bad_version", "unsupported version")
                    continue
                t = envelope.get("t")
                if t == "offer":
                    # First-and-only offer per WS — verify signature.
                    try:
                        pubkey, fingerprint = (
                            self.peer_rtc.verify_offer_envelope(envelope)
                        )
                    except ValueError as e:
                        await _send_error("bad_offer", str(e))
                        await ws.close(code=4001, message=b"bad offer")
                        return ws
                    # Trust check: pair_token OR known pubkey.
                    pair_token = envelope.get("pair_token") or ""
                    redeemed = self.peer_rtc.redeem_pairing_token(pair_token) if pair_token else None
                    is_known = self.peer_rtc.is_paired(fingerprint)
                    if not redeemed and not is_known:
                        await _send_error(
                            "no_trust",
                            "no valid pairing token + pubkey not in roster",
                        )
                        await ws.close(code=4030, message=b"unpaired peer")
                        return ws
                    if redeemed:
                        self.peer_rtc.mark_paired(fingerprint)
                    # Set up the RTCPeerConnection.
                    pc = RTCPeerConnection(configuration=config)
                    peer = BrowserPeer(
                        fingerprint=fingerprint,
                        pubkey_bytes=pubkey,
                        pc=pc,
                        paired_ms=time.time() * 1000 if redeemed or is_known else None,
                    )

                    # Hook DataChannels created by the browser side.
                    @pc.on("datachannel")
                    def _on_datachannel(channel):
                        nonlocal peer
                        if peer is None:
                            return
                        label = channel.label
                        if label == DAEMON_CONTROL_LABEL:
                            peer.control_dc = channel
                        elif label == DAEMON_BULK_LABEL:
                            peer.bulk_dc = channel

                        @channel.on("message")
                        def _on_message(message):
                            kind = "control" if label == DAEMON_CONTROL_LABEL else "bulk"
                            asyncio.create_task(
                                self.peer_rtc._dispatch_dc(peer, kind, message)
                            )

                        @channel.on("close")
                        def _on_close():
                            log.info(
                                "peer-rtc: %s channel closed for %s",
                                label, peer.fingerprint if peer else "?",
                            )

                    @pc.on("connectionstatechange")
                    async def _on_connection_state():
                        if pc.connectionState in ("closed", "failed"):
                            if peer is not None:
                                self.peer_rtc._close_peer(peer)

                    # Apply offer + craft answer.
                    await pc.setRemoteDescription(
                        RTCSessionDescription(sdp=envelope["sdp"], type="offer")
                    )
                    answer = await pc.createAnswer()
                    await pc.setLocalDescription(answer)

                    self.peer_rtc.register_peer(peer)
                    log.info(
                        "peer-rtc: registered browser peer %s (paired_via=%s)",
                        fingerprint,
                        "token" if redeemed else "roster",
                    )
                    # v0.20.7 (security audit C1): sign the answer
                    # envelope with the daemon's Ed25519 private key
                    # AND surface the DTLS fingerprint extracted from
                    # the SDP as an explicit field. The browser then
                    # cross-checks the SDP's a=fingerprint against
                    # the signed claim, defeating a network MITM
                    # that could otherwise rewrite the SDP fingerprint
                    # to point at the attacker's own DTLS certificate.
                    # Without this binding, the existing offer-envelope
                    # signing on the browser side was a half-protocol;
                    # the daemon's answer was unsigned and the SDP
                    # fingerprint travelled inside it without any
                    # cryptographic anchor to the daemon's identity.
                    _peer_rtc_mod = __import__(
                        "one_link.peer_rtc",
                        fromlist=["_b64u", "_canonical", "_extract_dtls_fingerprint"],
                    )
                    sdp_text = pc.localDescription.sdp
                    answer_envelope = {
                        "v": PEER_RTC_PROTOCOL_VERSION,
                        "t": "answer",
                        "sdp": sdp_text,
                        "daemon_pubkey_b64u": _peer_rtc_mod._b64u(
                            self.daemon.me.public_bytes
                        ),
                        "daemon_fingerprint": self.daemon.me.fingerprint,
                        "dtls_fingerprint": _peer_rtc_mod._extract_dtls_fingerprint(sdp_text),
                        "ts": int(time.time() * 1000),
                    }
                    sig_bytes = self.daemon.me.sign(
                        _peer_rtc_mod._canonical(answer_envelope)
                    )
                    answer_envelope["signature"] = _peer_rtc_mod._b64u(sig_bytes)
                    await _send(answer_envelope)
                elif t == "ice":
                    # aiortc's RTCPeerConnection handles ICE candidate
                    # offer/answer internally during setLocal/Remote
                    # description; trickle is handled within those
                    # calls. We accept ICE messages from the browser
                    # for forward compat (if a future aiortc requires
                    # explicit addIceCandidate) but no-op them today.
                    pass
                elif t == "close":
                    break
                else:
                    await _send_error("unknown_t", f"unknown envelope type: {t!r}")
        except Exception as e:
            log.warning("peer-rtc: signaling error: %s", e)
        finally:
            # Once the WS closes, the WebRTC peer-connection lives on
            # independently — DataChannel is the live transport.
            with contextlib.suppress(Exception):
                await ws.close()
        return ws

    # ─── v0.20.2: browser-peer ↔ daemon data bridge ───────────────────
    async def _handle_browser_peer_request(
        self, peer: Any, channel_kind: str, msg_t: str, envelope: dict,
    ) -> None:
        """DataChannel listener registered on BrowserPeerManager.
        Bridges OL-PEER-1 fetch_* requests from browser peers to the
        daemon's existing state.list_peers / state.recent_messages.

        Wire (over the daemon control DataChannel):

          phone → daemon:
            {"v":"OL-PEER-1", "t":"fetch_peers", "rid":"<uuid>"}
            {"v":"OL-PEER-1", "t":"fetch_messages", "rid":"<uuid>",
             "peer_fp":"<fp>", "limit":<int>}

          daemon → phone:
            {"v":"OL-PEER-1", "t":"peers", "rid":"<echo>",
             "peers":[{fingerprint, hostname, alias, trust,
                       last_seen_ms, sas_short}]}
            {"v":"OL-PEER-1", "t":"messages", "rid":"<echo>",
             "peer_fp":"<fp>",
             "messages":[{id, ts_ms, direction, body, msg_type,
                          edited_at_ms, deleted_at_ms}]}
            {"v":"OL-PEER-1", "t":"error", "rid":"<echo>",
             "code":"...", "message":"..."}

        The browser peer dispatches responses on rid match; missing
        rid → drop. Failures (state unavailable, peer_fp not in
        roster) come back as `error` envelopes.
        """
        from one_link.peer_rtc import PEER_DC_PROTOCOL_VERSION

        rid = envelope.get("rid", "")

        def _send(reply: dict) -> None:
            reply.setdefault("v", PEER_DC_PROTOCOL_VERSION)
            if rid:
                reply["rid"] = rid
            self.peer_rtc.send_dc(peer, "control", reply)

        def _err(code: str, message: str) -> None:
            _send({"t": "error", "code": code, "message": message})

        state = self.daemon.state
        if state is None:
            _err("no_state", "daemon state unavailable")
            return

        if msg_t == "fetch_peers":
            try:
                peers = state.list_peers()
            except Exception as e:
                _err("query_failed", f"list_peers: {e}")
                return
            payload = []
            for p in peers:
                # Conservative serialization — only fields the phone
                # needs for a roster view. Sensitive material (raw
                # pubkeys, capability state) stays on the daemon.
                payload.append({
                    "fingerprint": getattr(p, "fingerprint", None),
                    "short_id": getattr(p, "short_id", None),
                    "hostname": getattr(p, "hostname", None),
                    "alias": getattr(p, "alias", None),
                    "trust": getattr(p, "trust", "unknown"),
                    "last_seen_ms": getattr(p, "last_seen_ms", None),
                    "verified_at_ms": getattr(p, "verified_at_ms", None),
                    "muted": bool(getattr(p, "muted", False)),
                })
            _send({"t": "peers", "peers": payload})
            return

        if msg_t == "fetch_messages":
            peer_fp = envelope.get("peer_fp")
            if not isinstance(peer_fp, str) or not peer_fp:
                _err("bad_peer_fp", "peer_fp required")
                return
            limit = envelope.get("limit", 50)
            if not isinstance(limit, int) or limit <= 0 or limit > 500:
                limit = 50
            try:
                msgs = state.recent_messages(peer_fp=peer_fp, limit=limit)
            except Exception as e:
                _err("query_failed", f"recent_messages: {e}")
                return
            payload = []
            for m in msgs:
                payload.append({
                    "id": getattr(m, "id", None),
                    "ts_ms": getattr(m, "ts_ms", None),
                    "direction": getattr(m, "direction", None),
                    "msg_type": getattr(m, "msg_type", None),
                    "body": getattr(m, "body", None),
                    "room_id": getattr(m, "room_id", None),
                    "edited_at_ms": getattr(m, "edited_at_ms", None),
                    "deleted_at_ms": getattr(m, "deleted_at_ms", None),
                })
            _send({"t": "messages", "peer_fp": peer_fp, "messages": payload})
            return

        if msg_t == "fetch_self":
            # Lightweight identity ping — phone uses this to populate
            # "Connected to <hostname>" without a separate API call.
            me = self.daemon.me
            _send({
                "t": "self",
                "fingerprint": me.fingerprint,
                "short_id": me.short_id,
                "hostname": me.hostname,
            })
            return

        # Unknown wire kind — silently ignore. v0.19.2's chat protocol
        # also rides this channel and we don't want to error-spam those
        # frames.

    # ─── /api/me ──────────────────────────────────────────────────────
    async def api_me(self, request: web.Request) -> web.Response:
        me = self.daemon.me
        display_name = None
        onboarding_completed = False
        if self.daemon.state is not None:
            display_name = self.daemon.state.get_setting("display_name")
            # v0.9.4: surface the persisted onboarding flag so a
            # fresh browser tab can skip the wizard if the daemon
            # has already seen it once.
            onboarding_completed = (
                self.daemon.state.get_setting("onboarding_completed") == "true"
            )
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
        # v0.10.6: per-user suggested folder path. The folders pane
        # used to show a hardcoded example with my dev box's username
        # in it; this surfaces a real path under THIS user's home.
        try:
            suggested_folder = str(Path.home() / "Documents" / "One Link")
        except Exception:
            suggested_folder = ""
        return web.json_response({
            "short_id": me.short_id,
            "fingerprint": me.fingerprint,
            "hostname": me.hostname,
            "display_name": display_name or me.hostname,
            "app_version": ol_ver,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": schema_version,
            "onboarding_completed": onboarding_completed,
            # v0.10.4: surface user's chosen presence so the UI's
            # status pill renders correctly on every load.
            "presence": self.daemon.get_my_presence(),
            "suggested_folder": suggested_folder,
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
            "bind_host": self.bind_host,
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
                "transfer_autopilot": self.daemon._transfer_autopilot_stats(),
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
        # v0.10.0 settings polish — surface theme + DND + sound +
        # log verbosity + custom download folder. Sane defaults so a
        # never-touched daemon Just Works.
        return web.json_response({
            "display_name": s.get("display_name"),
            "auto_accept_lan": s.get("auto_accept_lan", "false") == "true",
            "pair_default_allow_all": pair_allow_all,
            # Theme: 'dark' (default) | 'light' | 'auto' (follow OS)
            "theme": s.get("theme", "dark"),
            # Download folder: empty string = default (inbox_dir())
            "download_folder": s.get("download_folder", ""),
            # Do-not-disturb: 24-hour HH:MM strings; off if not enabled
            "dnd_enabled": s.get("dnd_enabled", "false") == "true",
            "dnd_start": s.get("dnd_start", "22:00"),
            "dnd_end": s.get("dnd_end", "07:00"),
            # Notification sound: master toggle
            "notification_sound": s.get("notification_sound", "true") == "true",
            # Log verbosity: error | warn | info | debug
            "log_level": s.get("log_level", "info"),
            # v0.11.1 Profile fields. bio is a short status; null/empty
            # means none. avatar_color is one of AVATAR_COLOR_PRESETS;
            # falls back to the first preset if unset.
            "bio": s.get("bio", "") or "",
            "avatar_color": s.get("avatar_color", AVATAR_COLOR_PRESETS[0]),
            "avatar_color_presets": list(AVATAR_COLOR_PRESETS),
            # v0.11.2 notification fine-tuning.
            # - notification_preview: include message body in the
            #   desktop notification (true) vs just "New message" (false).
            # - notify_on_reactions: ping when a peer adds/removes a
            #   reaction to one of my messages. Off matches what most
            #   power users want to silence the long tail of pings.
            "notification_preview": s.get("notification_preview", "true") == "true",
            "notify_on_reactions": s.get("notify_on_reactions", "true") == "true",
            # v0.12.2 — read receipts privacy.
            # send_read_receipts: when off, my client never tells
            # peers what I've read (no READ_MARKER wire frame).
            # display_read_receipts: when off, peers' READ_MARKER
            # events are ignored locally — ✓✓ never appears even
            # if the peer is sending receipts. Decoupled so the
            # standard messaging-app convention "I want privacy
            # but still want to see when others read mine" is
            # expressible.
            "send_read_receipts": s.get("send_read_receipts", "true") == "true",
            "display_read_receipts": s.get("display_read_receipts", "true") == "true",
            # v0.12.3 — typing indicator privacy. Same shape as
            # read receipts: send + display are independent so the
            # 'don't tell, but tell me' pattern is expressible.
            "send_typing_indicators": s.get("send_typing_indicators", "true") == "true",
            "display_typing_indicators": s.get("display_typing_indicators", "true") == "true",
            # v0.11.6 storage + data settings.
            # - default_dm_ttl_ms: applies to NEW pairings only;
            #   existing peers keep their dm_ttl_ms unchanged. None /
            #   0 = off.
            # - bandwidth_cap_kbps: 0 = unlimited. Pinned in settings
            #   for the transfer engine to consume; enforcement at
            #   the chunk-pacer is a follow-on.
            # - auto_accept_max_size_mb: 0 = no limit. Inbound files
            #   above this size require an explicit accept.
            # - auto_accept_extensions: comma-separated allowlist of
            #   file extensions (e.g. "png,jpg,pdf"). Empty = no
            #   filter. Lowercased + leading dots stripped on read.
            "default_dm_ttl_ms": _parse_int_or_none(s.get("default_dm_ttl_ms")),
            "bandwidth_cap_kbps": _parse_int_or_none(s.get("bandwidth_cap_kbps")) or 0,
            "auto_accept_max_size_mb": _parse_int_or_none(s.get("auto_accept_max_size_mb")) or 0,
            "auto_accept_extensions": _normalize_ext_list(
                s.get("auto_accept_extensions", "")
            ),
            "safety_max_file_tb": _parse_int_or_none(s.get("safety_max_file_tb")) or 16,
            "safety_min_free_mb": _parse_int_or_none(s.get("safety_min_free_mb")) or 2048,
            "safety_peer_active_transfers": (
                _parse_int_or_none(s.get("safety_peer_active_transfers")) or 3
            ),
            "safety_peer_active_gb": _parse_int_or_none(s.get("safety_peer_active_gb")) or 2048,
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
        # v0.9.4: persist onboarding completion server-side so a
        # fresh browser tab on a paired daemon doesn't re-pop the
        # wizard. Local storage is the primary gate; this is the
        # backup.
        if "onboarding_completed" in data:
            self.daemon.state.set_setting(
                "onboarding_completed",
                "true" if data["onboarding_completed"] else "false",
            )
        # v0.10.0 — settings polish. Each branch validates its input
        # so a malformed value can't poison the database.
        if "theme" in data:
            v = (data["theme"] or "dark")
            if v not in ("dark", "light", "auto"):
                return web.json_response(
                    {"error": "theme must be dark|light|auto"}, status=400,
                )
            self.daemon.state.set_setting("theme", v)
        if "download_folder" in data:
            v = data["download_folder"]
            if v is not None and not isinstance(v, str):
                return web.json_response(
                    {"error": "download_folder must be a string or null"},
                    status=400,
                )
            v = (v or "").strip()
            from one_link.paths import set_inbox_override
            if v:
                # Validate: path must exist + be a writable directory.
                # We don't auto-mkdir because the user may have a typo
                # we'd rather surface.
                p = Path(v)
                if not p.is_dir():
                    return web.json_response(
                        {"error": f"download_folder is not a directory: {v}"},
                        status=400,
                    )
                if not os.access(p, os.W_OK):
                    return web.json_response(
                        {"error": f"download_folder is not writable: {v}"},
                        status=400,
                    )
                resolved = str(p.resolve())
                self.daemon.state.set_setting("download_folder", resolved)
                # Apply immediately — next received file lands in the
                # new folder without a daemon restart.
                set_inbox_override(p.resolve())
            else:
                self.daemon.state.delete_setting("download_folder")
                set_inbox_override(None)
        if "dnd_enabled" in data:
            self.daemon.state.set_setting(
                "dnd_enabled",
                "true" if data["dnd_enabled"] else "false",
            )
        for key in ("dnd_start", "dnd_end"):
            if key in data:
                v = (data[key] or "").strip()
                # HH:MM 24-hour validation. Empty string clears.
                if v:
                    parts = v.split(":")
                    bad = (
                        len(parts) != 2
                        or not parts[0].isdigit()
                        or not parts[1].isdigit()
                        or not (0 <= int(parts[0]) < 24)
                        or not (0 <= int(parts[1]) < 60)
                    )
                    if bad:
                        return web.json_response(
                            {"error": f"{key} must be HH:MM 24-hour"},
                            status=400,
                        )
                    # Re-canonicalize so '7:5' stores as '07:05'.
                    v = f"{int(parts[0]):02d}:{int(parts[1]):02d}"
                    self.daemon.state.set_setting(key, v)
                else:
                    self.daemon.state.delete_setting(key)
        if "notification_sound" in data:
            self.daemon.state.set_setting(
                "notification_sound",
                "true" if data["notification_sound"] else "false",
            )
        if "log_level" in data:
            v = (data["log_level"] or "info").lower()
            if v not in ("error", "warn", "info", "debug"):
                return web.json_response(
                    {"error": "log_level must be error|warn|info|debug"},
                    status=400,
                )
            self.daemon.state.set_setting("log_level", v)
            # Apply immediately so the daemon's running logger
            # respects the change without a restart.
            import logging
            level_map = {
                "error": logging.ERROR, "warn": logging.WARNING,
                "info": logging.INFO,   "debug": logging.DEBUG,
            }
            logging.getLogger("one_link").setLevel(level_map[v])
        # v0.11.1 Profile: bio (short status) + avatar color preset.
        if "bio" in data:
            v = data["bio"]
            if v is None:
                self.daemon.state.delete_setting("bio")
            else:
                if not isinstance(v, str):
                    return web.json_response(
                        {"error": "bio must be a string"}, status=400,
                    )
                if len(v) > BIO_MAX_LENGTH:
                    return web.json_response(
                        {"error": f"bio max {BIO_MAX_LENGTH} chars"},
                        status=400,
                    )
                stripped = v.strip()
                if stripped:
                    self.daemon.state.set_setting("bio", stripped)
                else:
                    self.daemon.state.delete_setting("bio")
        if "avatar_color" in data:
            v = data["avatar_color"]
            if v is None or v == "":
                self.daemon.state.delete_setting("avatar_color")
            else:
                if v not in AVATAR_COLOR_PRESETS:
                    return web.json_response(
                        {
                            "error": (
                                "avatar_color must be one of "
                                f"{list(AVATAR_COLOR_PRESETS)}"
                            )
                        },
                        status=400,
                    )
                self.daemon.state.set_setting("avatar_color", v)
        # v0.11.2 — notification fine-tuning toggles. Bools only.
        for key in (
            "notification_preview", "notify_on_reactions",
            # v0.12.2 read receipts privacy.
            "send_read_receipts", "display_read_receipts",
            # v0.12.3 typing indicator privacy.
            "send_typing_indicators", "display_typing_indicators",
        ):
            if key in data:
                self.daemon.state.set_setting(
                    key, "true" if data[key] else "false",
                )
        # v0.11.6 — storage + data settings.
        if "default_dm_ttl_ms" in data:
            v = data["default_dm_ttl_ms"]
            if v is None or v == "" or v == 0:
                self.daemon.state.delete_setting("default_dm_ttl_ms")
            else:
                try:
                    iv = int(v)
                except (TypeError, ValueError):
                    return web.json_response(
                        {"error": "default_dm_ttl_ms must be a positive int or null"},
                        status=400,
                    )
                if iv <= 0:
                    self.daemon.state.delete_setting("default_dm_ttl_ms")
                else:
                    self.daemon.state.set_setting("default_dm_ttl_ms", str(iv))
        if "bandwidth_cap_kbps" in data:
            v = data["bandwidth_cap_kbps"]
            try:
                iv = int(v) if v is not None else 0
            except (TypeError, ValueError):
                return web.json_response(
                    {"error": "bandwidth_cap_kbps must be a non-negative int"},
                    status=400,
                )
            if iv < 0:
                return web.json_response(
                    {"error": "bandwidth_cap_kbps must be >= 0"}, status=400,
                )
            if iv == 0:
                self.daemon.state.delete_setting("bandwidth_cap_kbps")
            else:
                self.daemon.state.set_setting("bandwidth_cap_kbps", str(iv))
        if "auto_accept_max_size_mb" in data:
            v = data["auto_accept_max_size_mb"]
            try:
                iv = int(v) if v is not None else 0
            except (TypeError, ValueError):
                return web.json_response(
                    {"error": "auto_accept_max_size_mb must be a non-negative int"},
                    status=400,
                )
            if iv < 0:
                return web.json_response(
                    {"error": "auto_accept_max_size_mb must be >= 0"}, status=400,
                )
            if iv == 0:
                self.daemon.state.delete_setting("auto_accept_max_size_mb")
            else:
                self.daemon.state.set_setting("auto_accept_max_size_mb", str(iv))
        if "auto_accept_extensions" in data:
            raw = data["auto_accept_extensions"]
            if isinstance(raw, list):
                raw = ",".join(str(x) for x in raw)
            if raw is None:
                raw = ""
            if not isinstance(raw, str):
                return web.json_response(
                    {"error": "auto_accept_extensions must be a string or list"},
                    status=400,
                )
            normalized = _normalize_ext_list(raw)
            if normalized:
                self.daemon.state.set_setting(
                    "auto_accept_extensions", ",".join(normalized),
                )
            else:
                self.daemon.state.delete_setting("auto_accept_extensions")
        for key, default_value, min_value in (
            ("safety_max_file_tb", 16, 1),
            ("safety_min_free_mb", 2048, 256),
            ("safety_peer_active_transfers", 3, 1),
            ("safety_peer_active_gb", 2048, 1),
        ):
            if key in data:
                v = data[key]
                try:
                    iv = int(v) if v is not None else default_value
                except (TypeError, ValueError):
                    return web.json_response(
                        {"error": f"{key} must be an integer"}, status=400,
                    )
                if iv < min_value:
                    return web.json_response(
                        {"error": f"{key} must be >= {min_value}"}, status=400,
                    )
                if iv == default_value:
                    self.daemon.state.delete_setting(key)
                else:
                    self.daemon.state.set_setting(key, str(iv))
        # v0.12.0: refresh the daemon's in-memory cache of settings
        # that affect hot paths (bandwidth pacer + auto-accept
        # rules). Cheap; runs once per save.
        with contextlib.suppress(Exception):
            if hasattr(self.daemon, "refresh_runtime_settings"):
                self.daemon.refresh_runtime_settings()
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
                        # v0.10.2: per-peer disappearing-message TTL.
                        live[rec.fingerprint]["dm_ttl_ms"] = rec.dm_ttl_ms
                        # v0.11.2: per-chat mute with duration.
                        live[rec.fingerprint]["muted_until_ms"] = rec.muted_until_ms
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
                            # v0.10.2: per-peer disappearing-message TTL.
                            "dm_ttl_ms": rec.dm_ttl_ms,
                            # v0.11.2: per-chat mute with duration.
                            "muted_until_ms": rec.muted_until_ms,
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
        now_ms = int(time.time() * 1000)
        for p in kept:
            fp = p.get("fingerprint") or ""
            sess = outbound.get(fp)
            health = getattr(self.daemon, "get_pair_health", lambda _fp: None)(fp)
            last_alive_ms = None
            if health is not None:
                try:
                    last_alive_ms = int(health.get("last_alive_ms") or 0)
                except (TypeError, ValueError):
                    last_alive_ms = None
            recently_contacted = bool(
                last_alive_ms
                and last_alive_ms > 0
                and now_ms - last_alive_ms <= PEER_CONTACT_ONLINE_GRACE_MS
            )
            if sess is not None or fp in inbound or recently_contacted:
                p["online"] = True
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
            # v0.10.4: peer presence. Daemon caches the latest
            # reported value in _peer_presence; missing key = peer
            # never reported (treat as 'online' on the wire).
            peer_presence = getattr(self.daemon, "_peer_presence", {}) or {}
            p["presence"] = (
                peer_presence.get(fp, "online")
                if fp else "online"
            )
            # v0.7.0: per-pairing health metrics. last_alive_ms is wall-
            # clock time of the last bytes seen from this peer (in or
            # out). latency_ewma_ms is the rolling round-trip time
            # measured by the H4 PING/PONG probe. Both None for
            # never-contacted peers.
            if health is not None:
                latency = health.get("latency_ewma_ms")
                p["health"] = {
                    "last_alive_ms": health.get("last_alive_ms"),
                    "latency_ewma_ms": (
                        latency
                        if latency == latency
                        else None  # NaN guard
                    ),
                    "bandwidth_bps": health.get("bandwidth_bps"),
                    "reliability": health.get("reliability"),
                    "best_route": health.get("best_route"),
                    "route_scores": health.get("route_scores") or [],
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

    async def api_set_presence(self, request: web.Request) -> web.Response:
        """v0.10.4: set the user's presence (online | away | dnd |
        invisible). Persists, broadcasts to peers via PRESENCE wire
        frame, and re-broadcasts via WS so other browser tabs sync."""
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        s = data.get("status")
        try:
            applied = await self.daemon.set_my_presence(s)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        self.broadcast({"type": "self_presence", "presence": applied})
        return web.json_response({"ok": True, "presence": applied})

    async def api_pick_folder(self, request: web.Request) -> web.Response:
        """v0.10.6: open a native folder-picker dialog on the daemon's
        desktop and return the selected absolute path.

        Dispatches to the OS-native picker (Vista-style FolderBrowser
        on Windows, Cocoa choose-folder on macOS, zenity/kdialog on
        Linux). The picker runs in a worker thread because the dialog
        loops are blocking."""
        title = "Choose a folder to share with One Link"
        try:
            picked = await asyncio.to_thread(_native_folder_picker, title)
        except Exception as e:
            return web.json_response(
                {"error": f"folder picker failed: {e}", "available": False},
                status=500,
            )
        if picked is None:
            # Either the user cancelled OR no picker was available.
            # The UI falls back to the manual text path input.
            return web.json_response({"path": None, "cancelled": True})
        return web.json_response({"path": picked, "cancelled": False})

    async def api_set_peer_ttl(self, request: web.Request) -> web.Response:
        """v0.10.2: configure per-peer disappearing-message TTL.
        Body: {ttl_ms: int | null}. null → off (default).

        Sender's TTL applies to BOTH directions of the chat —
        outbound TEXT messages get expires_at_ms = ts_ms + ttl_ms,
        and the wire frame carries ttl_ms so the peer can persist
        the same expiry on their copy."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        raw = data.get("ttl_ms")
        if raw is None:
            ttl = None
        else:
            try:
                ttl = int(raw)
            except (TypeError, ValueError):
                return web.json_response(
                    {"error": "ttl_ms must be a positive integer or null"},
                    status=400,
                )
        try:
            updated = self.daemon.state.set_peer_dm_ttl(fp, ttl)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        if updated is None:
            return web.json_response({"error": "peer not found"}, status=404)
        self.broadcast({
            "type": "peer_ttl",
            "fingerprint": fp,
            "dm_ttl_ms": updated.dm_ttl_ms,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "dm_ttl_ms": updated.dm_ttl_ms,
        })

    async def api_set_peer_mute(self, request: web.Request) -> web.Response:
        """v0.11.2: per-peer mute with duration.

        Body: {duration_ms: int | null}
          - null → unmute
          - 0 → mute forever (no auto-expire)
          - N > 0 → mute for N ms (mute until now+N)

        We store the absolute deadline (muted_until_ms) so the mute
        survives daemon restarts without rearming a timer."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        if "duration_ms" not in data:
            return web.json_response(
                {"error": "duration_ms required (int or null)"},
                status=400,
            )
        raw = data["duration_ms"]
        if raw is None:
            until_ms = None
        else:
            try:
                d = int(raw)
            except (TypeError, ValueError):
                return web.json_response(
                    {"error": "duration_ms must be int or null"},
                    status=400,
                )
            if d < 0:
                return web.json_response(
                    {"error": "duration_ms must be >= 0"}, status=400,
                )
            until_ms = 0 if d == 0 else int(time.time() * 1000) + d
        rec = self.daemon.state.get_peer(fp)
        if rec is None:
            return web.json_response({"error": "peer not found"}, status=404)
        try:
            self.daemon.state.set_peer_muted_until(fp, until_ms)
        except ValueError as e:
            return web.json_response({"error": str(e)}, status=400)
        self.broadcast({
            "type": "peer_mute",
            "fingerprint": fp,
            "muted_until_ms": until_ms,
        })
        return web.json_response({
            "ok": True, "fingerprint": fp,
            "muted_until_ms": until_ms,
        })

    async def api_set_group_mute(self, request: web.Request) -> web.Response:
        """v0.11.2: per-group mute with duration. Stored as a settings
        key (`group_mute:<gid_hex>`) since groups don't have a
        persistent metadata table. Same duration semantics as
        api_set_peer_mute."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        # Validate it's actually hex (not strictly required since we
        # treat the id as opaque, but a 400 here saves us from
        # storing junk keys forever).
        try:
            bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        if "duration_ms" not in data:
            return web.json_response(
                {"error": "duration_ms required (int or null)"},
                status=400,
            )
        raw = data["duration_ms"]
        key = f"group_mute:{gid_hex}"
        if raw is None:
            self.daemon.state.delete_setting(key)
            until_ms = None
        else:
            try:
                d = int(raw)
            except (TypeError, ValueError):
                return web.json_response(
                    {"error": "duration_ms must be int or null"},
                    status=400,
                )
            if d < 0:
                return web.json_response(
                    {"error": "duration_ms must be >= 0"}, status=400,
                )
            until_ms = 0 if d == 0 else int(time.time() * 1000) + d
            self.daemon.state.set_setting(key, str(until_ms))
        self.broadcast({
            "type": "group_mute",
            "group_id": gid_hex,
            "muted_until_ms": until_ms,
        })
        return web.json_response({
            "ok": True, "group_id": gid_hex,
            "muted_until_ms": until_ms,
        })

    # ─── v0.11.5 per-chat tools ───────────────────────────────────────

    async def api_clear_peer_history(self, request: web.Request) -> web.Response:
        """v0.11.5: hard-delete every message row exchanged with this
        peer locally. The peer's copy is untouched; this is purely
        local data hygiene. Used by 'Clear chat history' in the
        device drawer."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        rec = self.daemon.state.get_peer(fp)
        if rec is None:
            return web.json_response({"error": "peer not found"}, status=404)
        deleted = self.daemon.state.clear_peer_history(fp)
        # Broadcast so any open tab refreshes its message list.
        self.broadcast({
            "type": "history_cleared", "scope": "peer",
            "fingerprint": fp, "deleted": deleted,
        })
        return web.json_response({"ok": True, "deleted": deleted})

    async def api_clear_group_history(self, request: web.Request) -> web.Response:
        """v0.11.5: hard-delete every message row in this group locally.
        Membership / event log is preserved — only chat content is
        wiped."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        deleted = self.daemon.state.clear_group_history(gid_hex)
        self.broadcast({
            "type": "history_cleared", "scope": "group",
            "group_id": gid_hex, "deleted": deleted,
        })
        return web.json_response({"ok": True, "deleted": deleted})

    async def api_export_peer(self, request: web.Request) -> web.Response:
        """v0.11.5: export the conversation with this peer as JSON
        (default) or Markdown. ?format=md|json. Downloads as a file
        via Content-Disposition: attachment."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        rec = self.daemon.state.get_peer(fp)
        if rec is None:
            return web.json_response({"error": "peer not found"}, status=404)
        fmt = (request.query.get("format") or "json").lower()
        if fmt not in ("json", "md", "markdown"):
            return web.json_response(
                {"error": "format must be json, md, or markdown"},
                status=400,
            )
        # Pull all (not just recent). 100k cap as a sanity bound; very
        # active chats can ship the rest via successive exports if
        # ever needed.
        msgs = self.daemon.state.recent_messages(peer_fp=fp, limit=100_000)
        peer_label = rec.display_name or rec.hostname or rec.short_id
        return self._render_conversation_export(
            messages=msgs, fmt=fmt,
            title=f"Conversation with {peer_label}",
            filename_stem=f"one-link-{rec.short_id}",
            self_label=self.daemon.me.hostname or "Me",
            other_label=peer_label,
        )

    async def api_export_group(self, request: web.Request) -> web.Response:
        """v0.11.5: same as api_export_peer but for a group's
        message log."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        fmt = (request.query.get("format") or "json").lower()
        if fmt not in ("json", "md", "markdown"):
            return web.json_response(
                {"error": "format must be json, md, or markdown"},
                status=400,
            )
        mat = self._materialize_group(bytes.fromhex(gid_hex))
        title = (mat.get("name") if mat else None) or f"Group {gid_hex[:8]}"
        # recent_group_messages already exists; pull a generous batch.
        with contextlib.suppress(Exception):
            self.daemon.state.recent_group_messages
        msgs = self.daemon.state.recent_group_messages(
            group_id=bytes.fromhex(gid_hex), limit=100_000,
        )
        return self._render_conversation_export(
            messages=msgs, fmt=fmt,
            title=f"Group: {title}",
            filename_stem=f"one-link-group-{gid_hex[:8]}",
            self_label=self.daemon.me.hostname or "Me",
            other_label=title,
            is_group=True,
        )

    def _render_conversation_export(
        self, *, messages, fmt: str,
        title: str, filename_stem: str,
        self_label: str, other_label: str,
        is_group: bool = False,
    ) -> web.Response:
        """Serialize a list of MessageRecord (or group equivalents)
        into JSON or Markdown + the right Content-Disposition header
        for browser download."""
        from datetime import datetime, timezone
        # Normalize each row into a small dict shape we can render
        # in either format. Groups have slightly different keys.
        rows: list[dict] = []
        for m in messages:
            ts = getattr(m, "ts_ms", None) or getattr(m, "timestamp_ms", None) or 0
            iso = datetime.fromtimestamp(ts / 1000, tz=timezone.utc).isoformat()
            who = "?"
            if hasattr(m, "direction"):
                who = self_label if m.direction == "out" else other_label
            elif hasattr(m, "author_pubkey"):
                if m.author_pubkey == self.daemon.me.public_bytes:
                    who = self_label
                else:
                    who = "peer"  # group sender label is informational
            rows.append({
                "id": getattr(m, "id", ""),
                "ts_ms": ts,
                "ts": iso,
                "who": who,
                "type": getattr(m, "msg_type", "text"),
                "body": getattr(m, "body", "") or "",
            })
        ts_now = int(time.time())
        if fmt == "json":
            payload = {
                "title": title,
                "exported_at_ms": ts_now * 1000,
                "is_group": is_group,
                "messages": rows,
            }
            body = json.dumps(payload, indent=2, ensure_ascii=False)
            ct = "application/json"
            ext = "json"
        else:
            lines = [f"# {title}", "", f"_Exported {ts_now}_", ""]
            for r in rows:
                lines.append(f"**{r['who']}** · {r['ts']}")
                if r["type"] == "file":
                    lines.append(f"📎 _file: {r['body']}_")
                else:
                    lines.append(r["body"] or "_(empty)_")
                lines.append("")
            body = "\n".join(lines)
            ct = "text/markdown"
            ext = "md"
        resp = web.Response(text=body, content_type=ct, charset="utf-8")
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="{filename_stem}-{ts_now}.{ext}"'
        )
        return resp

    async def api_storage_usage(self, request: web.Request) -> web.Response:
        """v0.11.6: per-chat storage breakdown for the Storage
        settings pane. Combines state rollups with peer/group
        display names so the UI can render a sortable table."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        peer_rows = self.daemon.state.storage_usage_by_peer()
        peer_out = []
        total_msgs = 0
        total_bytes = 0
        for r in peer_rows:
            rec = self.daemon.state.get_peer(r["peer_fp"])
            peer_out.append({
                "fingerprint": r["peer_fp"],
                "display_name": (
                    rec.display_name if rec else r["peer_fp"][:8]
                ),
                "msg_count": r["msg_count"],
                "file_count": r["file_count"],
                "file_bytes": r["file_bytes"],
            })
            total_msgs += r["msg_count"]
            total_bytes += r["file_bytes"]

        group_rows = self.daemon.state.storage_usage_by_group()
        group_out = []
        for g in group_rows:
            mat = None
            with contextlib.suppress(Exception):
                mat = self._materialize_group(bytes.fromhex(g["group_id"]))
            group_out.append({
                "group_id": g["group_id"],
                "name": (mat.get("name") if mat else None) or g["group_id"][:8],
                "msg_count": g["msg_count"],
            })
            total_msgs += g["msg_count"]

        return web.json_response({
            "peers": peer_out,
            "groups": group_out,
            "totals": {
                "msg_count": total_msgs,
                "file_bytes": total_bytes,
                "chat_count": len(peer_out) + len(group_out),
            },
        })

    # ─── v0.12.1 chat preferences (sync across user's devices) ─────────

    _CHAT_PREF_KINDS = ("color", "wallpaper", "archived")
    _CHAT_PREF_SCOPES = ("peer", "group")

    @staticmethod
    def _chat_pref_key(scope: str, identifier: str, kind: str) -> str:
        return f"chatpref:{scope}:{identifier}:{kind}"

    async def api_get_chat_prefs(self, request: web.Request) -> web.Response:
        """v0.12.1: snapshot of every persisted per-chat preference.

        Shape:
          {
            "peer":  { "<fp_hex>":  { "color": "#7c4dff", ... } },
            "group": { "<gid_hex>": { "archived": true, ... } }
          }

        Stored in the existing settings table under keys of the form
        `chatpref:<scope>:<id>:<kind>` so the daemon doesn't need a
        new schema migration."""
        if self.daemon.state is None:
            return web.json_response({"peer": {}, "group": {}})
        all_settings = self.daemon.state.all_settings()
        out: dict[str, dict[str, dict[str, Any]]] = {"peer": {}, "group": {}}
        for key, value in all_settings.items():
            if not key.startswith("chatpref:"):
                continue
            parts = key.split(":", 3)
            if len(parts) != 4:
                continue
            _, scope, identifier, kind = parts
            if scope not in self._CHAT_PREF_SCOPES:
                continue
            if kind not in self._CHAT_PREF_KINDS:
                continue
            scope_map = out[scope].setdefault(identifier, {})
            if kind == "archived":
                scope_map["archived"] = value == "true"
            else:
                scope_map[kind] = value
        return web.json_response(out)

    async def api_set_chat_pref(self, request: web.Request) -> web.Response:
        """v0.12.1: set or clear one preference.

        Body: {scope, id, kind, value}
          - scope: 'peer' | 'group'
          - id: peer fingerprint OR group_id_hex
          - kind: 'color' | 'wallpaper' | 'archived'
          - value: the new value, or null to clear

        Color and wallpaper are stored as hex strings; archived is
        stored as 'true' (set) / unset (cleared)."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        scope = data.get("scope")
        identifier = data.get("id")
        kind = data.get("kind")
        value = data.get("value")
        if scope not in self._CHAT_PREF_SCOPES:
            return web.json_response(
                {"error": f"scope must be one of {self._CHAT_PREF_SCOPES}"},
                status=400,
            )
        if kind not in self._CHAT_PREF_KINDS:
            return web.json_response(
                {"error": f"kind must be one of {self._CHAT_PREF_KINDS}"},
                status=400,
            )
        if not isinstance(identifier, str) or not identifier.strip():
            return web.json_response(
                {"error": "id must be a non-empty string"}, status=400,
            )
        # Identifier sanity check — peer fp is 64 hex chars; group
        # id is 32 hex chars. Reject anything not hex or out of
        # those bounds, so a malformed call can't poison settings.
        ident = identifier.strip().lower()
        if scope == "peer" and (
            len(ident) != 64 or any(c not in "0123456789abcdef" for c in ident)
        ):
            return web.json_response({"error": "bad peer fingerprint"}, status=400)
        if scope == "group" and (
            len(ident) < 8 or any(c not in "0123456789abcdef" for c in ident)
        ):
            return web.json_response({"error": "bad group id"}, status=400)
        key = self._chat_pref_key(scope, ident, kind)
        if value is None or value == "":
            self.daemon.state.delete_setting(key)
            stored = None
        elif kind == "archived":
            if not isinstance(value, bool):
                return web.json_response(
                    {"error": "archived value must be true|false|null"},
                    status=400,
                )
            if value:
                self.daemon.state.set_setting(key, "true")
                stored = True
            else:
                self.daemon.state.delete_setting(key)
                stored = False
        else:
            if not isinstance(value, str):
                return web.json_response(
                    {"error": f"{kind} value must be a hex color string or null"},
                    status=400,
                )
            v = value.strip().lower()
            if not v.startswith("#") or len(v) not in (4, 7):
                return web.json_response(
                    {"error": f"{kind} value must be a #rgb / #rrggbb hex"},
                    status=400,
                )
            if any(c not in "0123456789abcdef" for c in v[1:]):
                return web.json_response(
                    {"error": f"{kind} value must be a #rgb / #rrggbb hex"},
                    status=400,
                )
            self.daemon.state.set_setting(key, v)
            stored = v
        # Broadcast so other open tabs (and the same user's other
        # devices once they sync) refresh their UI immediately.
        self.broadcast({
            "type": "chat_pref",
            "scope": scope, "id": ident,
            "kind": kind, "value": stored,
        })
        return web.json_response({
            "ok": True, "scope": scope, "id": ident,
            "kind": kind, "value": stored,
        })

    async def api_peer_media(self, request: web.Request) -> web.Response:
        """v0.11.5: list files exchanged with this peer for the
        media gallery view in the device drawer."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        rec = self.daemon.state.get_peer(fp)
        if rec is None:
            return web.json_response({"error": "peer not found"}, status=404)
        msgs = self.daemon.state.list_peer_files(fp)
        out = []
        for m in msgs:
            md = m.metadata or {}
            out.append({
                "id": m.id,
                "ts_ms": m.ts_ms,
                "direction": m.direction,
                "name": md.get("filename") or m.body or "(file)",
                "size": md.get("size"),
                "mime": md.get("mime"),
            })
        return web.json_response({"items": out})

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

    async def api_get_activity_feed(self, request: web.Request) -> web.Response:
        """v0.9.1: cross-peer activity feed. Query params:
          - since (ms timestamp; default last 7 days)
          - kinds (comma-list of trust|key_change|transfer|conflict|peer)
          - peer (fingerprint; only show events tied to this peer)
          - limit (default 200, max 2000)"""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        try:
            since = request.query.get("since")
            since_ms = int(since) if since else None
        except ValueError:
            since_ms = None
        kinds_q = request.query.get("kinds")
        kinds = [k.strip() for k in kinds_q.split(",")] if kinds_q else None
        peer_fp = request.query.get("peer") or None
        try:
            limit = int(request.query.get("limit", "200"))
        except ValueError:
            limit = 200
        events = self.daemon.state.activity_feed(
            since_ms=since_ms, kinds=kinds, peer_fp=peer_fp, limit=limit,
        )
        return web.json_response({
            "events": events,
            "count": len(events),
        })

    async def api_global_search(self, request: web.Request) -> web.Response:
        """v0.9.3: global search backing the Ctrl+K command palette.
        Query params:
          - q (required, the search string)
          - limit (per-kind cap, default 10, max 50)
        Returns merged results across messages (FTS5), peers,
        groups, and inbox files."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        q = (request.query.get("q") or "").strip()
        if not q:
            return web.json_response({
                "query": "",
                "messages": [], "peers": [], "groups": [], "files": [],
            })
        try:
            limit = int(request.query.get("limit", "10"))
        except ValueError:
            limit = 10
        limit = max(1, min(limit, 50))

        # 1. State-backed: messages + peers + groups.
        state_hits = self.daemon.state.global_search(q, per_kind_limit=limit)

        # 2. Inbox files by name substring. Uses the existing inbox
        # listing helper to keep ordering / metadata consistent.
        files: list[dict] = []
        try:
            ql = q.lower()
            inbox = inbox_dir()
            if inbox.is_dir():
                rows = []
                for f in inbox.iterdir():
                    if not f.is_file():
                        continue
                    if ql not in f.name.lower():
                        continue
                    try:
                        st = f.stat()
                    except OSError:
                        continue
                    rows.append((f.name, int(st.st_size),
                                 int(st.st_mtime * 1000)))
                # Newest first.
                rows.sort(key=lambda r: r[2], reverse=True)
                for name, size, mtime in rows[:limit]:
                    files.append({"name": name, "size": size, "mtime_ms": mtime})
        except Exception as e:
            log.warning("global search file scan failed: %s", e)

        # Hostname enrichment for message rows so the UI can render
        # "from <peer name>" without a second roundtrip.
        peer_lookup: dict = {}
        try:
            for rec in self.daemon.state.list_peers():
                peer_lookup[rec.fingerprint] = rec.display_name
        except Exception:
            pass
        for m in state_hits.get("messages", []):
            m["peer_display_name"] = peer_lookup.get(m.get("peer_fp"))

        return web.json_response({
            "query": q,
            "messages": state_hits["messages"],
            "peers": state_hits["peers"],
            "groups": state_hits["groups"],
            "files": files,
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
        """Return the SAS for a peer (deterministic — both sides see same).

        v0.11.4: SAS is a pure function of the two pubkeys, so we don't
        need the peer to be online. If mDNS doesn't have them right
        now, fall back to the stored peer record. This unblocks
        in-person verification of an already-paired device that just
        happens to be offline at the moment the user opens the drawer."""
        fp = request.match_info["fp"]
        from one_link.pairing import compute_sas, format_sas

        # 1. Try the live mDNS registry first — that's the freshest
        #    pubkey and matches the previous behavior for online peers.
        peer = self._resolve_peer_for_pairing(fp)
        if peer is not None and peer.ed_pub_hex:
            try:
                pub = bytes.fromhex(peer.ed_pub_hex)
            except ValueError:
                pub = None
            if pub:
                sas = compute_sas(self.daemon.me.public_bytes, pub)
                return web.json_response(
                    {"sas": sas, "formatted": format_sas(sas)},
                )

        # 2. Fall back to the stored peer record. SAS doesn't require
        #    the peer to be online — both sides will compute the same
        #    value from their respective stored pubkeys.
        if self.daemon.state is not None:
            rec = self.daemon.state.get_peer(fp)
            if rec is not None and rec.pubkey:
                sas = compute_sas(self.daemon.me.public_bytes, rec.pubkey)
                return web.json_response(
                    {"sas": sas, "formatted": format_sas(sas)},
                )

        return web.json_response(
            {"error": "no pubkey on file for this peer"}, status=404,
        )

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

    async def api_set_typing(self, request: web.Request) -> web.Response:
        """v0.12.3: relay an ephemeral 'I'm typing' indicator to a
        peer. Best-effort, debounced server-side at 2.5s/peer.

        The UI calls this on every keystroke that lands a non-
        whitespace character; the daemon discards floods so the
        wire stays calm. Honors send_typing_indicators privacy
        setting; when off, returns 200 with skipped='privacy'."""
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        fp = request.match_info["fp"]
        peer = await self.daemon.resolve_for_send(fp)
        if peer is None:
            return web.json_response({"ok": True, "delivered": False})
        try:
            r = await self.daemon.send_typing(peer)
            return web.json_response({
                "ok": True,
                "delivered": r.get("error") is None and r.get("skipped") is None,
                "skipped": r.get("skipped"),
            })
        except Exception as e:
            log.debug("send_typing failed: %s", e)
            return web.json_response({"ok": True, "delivered": False})

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
                # v0.11.2: surface per-group mute deadline so the UI
                # can render a 🔕 indicator without an extra fetch.
                gid_hex = mat["group_id"]
                raw_mute = self.daemon.state.get_setting(f"group_mute:{gid_hex}")
                muted_until_ms: Optional[int]
                if raw_mute is None:
                    muted_until_ms = None
                else:
                    try:
                        muted_until_ms = int(raw_mute)
                    except ValueError:
                        muted_until_ms = None
                out.append({
                    "group_id": gid_hex,
                    "name": mat["name"],
                    "member_count": mat["member_count"],
                    "my_role": mat["my_role"],
                    "muted_until_ms": muted_until_ms,
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

    async def api_set_group_member_role(self, request: web.Request) -> web.Response:
        """v0.11.3: promote/demote a group member.

        Body: {role: 'owner' | 'admin' | 'member'}
        Authority: only owners can change roles (enforced server-side
        by the CRDT reducer rejecting non-owner CHANGE_ROLE events).
        """
        if self.daemon.state is None:
            return web.json_response({"error": "state not available"}, status=503)
        gid_hex = request.match_info["gid"]
        try:
            gid = bytes.fromhex(gid_hex)
        except ValueError:
            return web.json_response({"error": "bad group id"}, status=400)
        member_fp = request.match_info["member_fp"]
        try:
            data = await request.json()
        except Exception as e:
            return web.json_response({"error": f"bad json: {e}"}, status=400)
        new_role = (data.get("role") or "").strip()
        if new_role not in ("owner", "admin", "member"):
            return web.json_response(
                {"error": "role must be owner, admin, or member"},
                status=400,
            )
        rec = self.daemon.state.get_peer(member_fp)
        if rec is None or not rec.pubkey:
            return web.json_response({"error": "unknown member"}, status=404)
        try:
            result = await self.daemon.change_group_member_role(
                group_id=gid, member_pubkey=rec.pubkey, new_role=new_role,
            )
            return web.json_response({"ok": True, "role": new_role, **result})
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
        target_fp = self._resolve_pinned_fp(peer_needle, peer)
        if peer is None:
            if target_fp:
                keep_upload_for_resume = True
                try:
                    rec = self.daemon.queue_file_transfer(
                        peer_fp=target_fp,
                        path=upload_path,
                        reason="waiting for device",
                    )
                    return web.json_response(
                        {
                            "ok": True,
                            "queued": True,
                            "paused": True,
                            "transfer_id": rec.id if rec else None,
                            "hint": "Waiting for the device. One Link will send it automatically when the path is healthy.",
                        },
                        status=202,
                    )
                except Exception as e:
                    log.exception("queue_file_transfer failed: %s", e)
            with contextlib.suppress(OSError):
                upload_path.unlink(missing_ok=True)
            return web.json_response({
                "error": f"no peer {peer_needle!r}",
                "hint": "Pick a paired device. Once a paired device is known, One Link can wait and send automatically.",
            }, status=404)

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
                        "risk": classify_file_risk(f.name),
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
        if rec.status not in ("failed", "complete", "paused", "queued"):
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
            result = await self.daemon.send_file(peer, path, transfer_id=rec.id)
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
            "CHUNK_QUERY",
            "CHUNK_HAVE",
            "CHUNK_PULL",
            "CHUNK_DATA",
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
                    "autopilot": "route-scored binary/CDC strategy, BDP-aware windows, ACK-clocked self-tuning",
                },
                "transfer_autopilot": self.daemon._transfer_autopilot_stats(),
                "folder_sync": {
                    "strategy": "Merkle root fast path plus CRDT manifest merge",
                },
                "sessions": self.daemon._session_stats(),
            },
            "outbound_destinations": outbound,
            "no_external_telemetry": True,
            "sovereign_network": doctrine(),
            # v0.20.7+ (Bundles 22-45): every sovereignty / privacy
            # primitive shipped in this build, advertised so an
            # inspecting user can see the full surface without having
            # to grep the source tree. Each entry is a (name, status,
            # one-line summary) — name maps to the module that
            # implements it.
            "sovereign_primitives": _enumerate_sovereign_primitives(),
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
        # v0.9.5: PDFs handled by the browser's native viewer via
        # <iframe src=/api/files/{name}>. Server returns metadata
        # only (no content read) so a 100 MB PDF doesn't OOM.
        "pdf": "pdf",
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
        # v0.9.5: PDFs render via the browser's built-in viewer
        # (<iframe src=/api/files/{name}>), not by reading the
        # bytes server-side. Return metadata only so a 100 MB PDF
        # doesn't OOM the daemon.
        if kind == "pdf":
            return web.json_response({
                "name": safe,
                "extension": ext,
                "kind": kind,
                "size": size,
                "stream_url": f"/api/files/{safe}",
            })
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
                # v0.9.7: use list-form Popen — string form was
                # silently filing under "didn't work" for some users.
                # explorer.exe parses /select,<path> as a single
                # argv token (comma is part of the syntax, not a
                # separator), so pass it as one element.
                subprocess.Popen(
                    ["explorer.exe", f"/select,{path}"],
                )
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path.parent)])
        except OSError as e:
            return web.json_response({"error": f"reveal failed: {e}"}, status=500)
        return web.json_response({"ok": True, "path": str(path)})

    async def api_inbox_reveal(self, request: web.Request) -> web.Response:
        # Open the inbox folder itself (no specific file selected).
        path = inbox_dir().resolve()
        if self._reveal_throttled():
            return web.json_response({"ok": True, "path": str(path), "throttled": True})
        # See api_file_reveal — same env-gate so tests don't spawn
        # actual Explorer windows.
        if os.environ.get("ONE_LINK_DISABLE_REVEAL") == "1":
            return web.json_response({"ok": True, "path": str(path), "disabled": True})
        import sys
        try:
            if sys.platform == "win32":
                # v0.9.7: switch to os.startfile (ShellExecute under
                # the hood). Reuses an existing Explorer window if
                # one is open, displays significantly faster than
                # spawning a fresh explorer.exe via subprocess.
                os.startfile(str(path))
            elif sys.platform == "darwin":
                import subprocess
                subprocess.Popen(["open", str(path)])
            else:
                import subprocess
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
        # v0.15.2 — LAN-bind opt-in via env var. Default 127.0.0.1
        # (loopback only, the historical safe default). Setting
        # ONE_LINK_BIND_HOST=0.0.0.0 (or a specific LAN address)
        # exposes the UI to the LAN so a phone on the same Wi-Fi
        # can connect. The token still gates everything; the env
        # var only changes which interface answers.
        bind_host = os.environ.get("ONE_LINK_BIND_HOST") or "127.0.0.1"
        # Try the well-known port first so browser tabs survive restarts.
        # Fall through 7118..7132 if taken, then OS-assigned random as
        # last resort.
        #
        # v0.20.5 — the previous "ownership probe" raced with TIME_WAIT
        # entries from a just-killed daemon: bind() would succeed (so
        # we own the port) but the probe's connect would briefly hit
        # the kernel's TIME_WAIT-routing layer, fail to read a 200,
        # and we'd fall through to a higher port. Result: every
        # restart claimed a different port number, breaking every
        # bookmark + previously-minted pair URL. On Windows + Linux,
        # bind() succeeding ≠ "TIME_WAIT clear" but DOES mean "we
        # own this listener now" — connections will route to us, not
        # to the dead 5-tuples in TIME_WAIT. Probe removed.
        bound = False
        for candidate in range(
            PREFERRED_UI_PORT, PREFERRED_UI_PORT + UI_PORT_FALLBACK_RANGE
        ):
            try:
                site = web.TCPSite(self.runner, host=bind_host, port=candidate)
                await site.start()
                self.site = site
                self.port = candidate
                bound = True
                break
            except OSError:
                # Port in use by ANOTHER LISTENER — try the next.
                # TIME_WAIT entries don't cause this on Windows or
                # modern Linux; only an actively-listening rival
                # process does.
                continue
        if not bound:
            site = web.TCPSite(self.runner, host=bind_host, port=0)
            await site.start()
            sock = site._server.sockets[0]  # type: ignore[union-attr]
            self.site = site
            self.port = sock.getsockname()[1]
        self.bind_host = bind_host
        _server_port_path().write_text(str(self.port))
        # v0.20.7 (security audit M29): wrap the UI token with the
        # daemon's lockbox WHEN explicit passphrase mode is active.
        # Silent-mode lockboxes (the default at-rest wrap for
        # chain_keys) do NOT wrap the UI token because:
        #   1. The on-disk lifetime is brief — every daemon restart
        #      rotates the token.
        #   2. The launcher and external tooling read the file as
        #      raw text; wrapping silently would break that contract
        #      without a corresponding security gain (an attacker
        #      who can read the daemon's data dir during the
        #      session can also read the daemon's memory).
        # Explicit-passphrase mode is the user signaling "I want
        # paranoid at-rest"; in that mode we wrap the token too.
        import base64 as _b64
        token_disk = self.token
        try:
            lb = (
                getattr(self.daemon.state, "_lockbox", None)
                if self.daemon.state is not None else None
            )
            if lb is not None and not getattr(lb, "is_silent", True):
                blob = lb.wrap(self.token.encode("ascii"))
                token_disk = self._TOKEN_WRAPPED_PREFIX + _b64.urlsafe_b64encode(
                    blob
                ).decode("ascii")
        except Exception as e:
            log.warning(
                "UI token wrap failed (%s); falling back to cleartext", e,
            )
        _token_path().write_text(token_disk)
        # POSIX permission tighten so a multi-user box doesn't read it.
        with contextlib.suppress(OSError, NotImplementedError):
            os.chmod(_token_path(), 0o600)
        log.info("UI server up — http://%s:%d/", bind_host, self.port)

        # v0.20.4 — start a parallel HTTPS listener on port+1 so
        # phones can hit the daemon over a secure context (Web
        # Crypto Subtle requires HTTPS or localhost; a phone hitting
        # http://<lan-ip> can't generate Ed25519 keys, breaking the
        # whole browser-as-peer pair flow). The cert is self-signed,
        # generated on first run, persisted to <data_dir>/peer_https/.
        # Best-effort: if cert minting fails, log + skip; HTTP-only
        # daemons still work (just not from phone Safari).
        self.https_site = None
        self.https_port = None
        self.https_cert_fp_sha256 = None
        await self._start_https_listener(bind_host)

        return self.port

    async def _start_https_listener(self, bind_host: str) -> None:
        """v0.20.4 — start the parallel HTTPS listener with the
        self-signed cert. Lazy-imports peer_https so daemons that
        don't have the module still boot."""
        try:
            from one_link.peer_https import build_ssl_context, cert_path, cert_fingerprint_sha256
            from one_link.paths import data_dir
        except ImportError as e:
            log.info("peer-https unavailable: %s", e)
            return
        try:
            ctx = build_ssl_context(
                data_dir(),
                short_id=self.daemon.me.short_id,
            )
        except Exception as e:
            log.warning("peer-https: build_ssl_context failed: %s", e)
            return
        if ctx is None:
            log.info("peer-https: skipping (no cert)")
            return
        # Try port+1 first, then fall through to subsequent ports.
        bound = False
        for offset in range(1, UI_PORT_FALLBACK_RANGE + 1):
            candidate = self.port + offset
            try:
                site = web.TCPSite(
                    self.runner, host=bind_host, port=candidate, ssl_context=ctx,
                )
                await site.start()
            except OSError:
                continue
            self.https_site = site
            self.https_port = candidate
            bound = True
            break
        if not bound:
            log.warning("peer-https: couldn't bind any HTTPS port")
            return
        try:
            self.https_cert_fp_sha256 = cert_fingerprint_sha256(cert_path(data_dir()))
        except Exception:
            self.https_cert_fp_sha256 = None
        log.info(
            "UI server HTTPS up — https://%s:%d/ (cert sha256=%s)",
            bind_host, self.https_port,
            (self.https_cert_fp_sha256 or "?")[:16],
        )

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
