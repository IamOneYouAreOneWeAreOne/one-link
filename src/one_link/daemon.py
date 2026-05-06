"""One_link daemon.

Runs two asyncio servers:
  1. Peer server  — accepts connections from other One_link nodes on the LAN
                    on a TCP port advertised via mDNS.
  2. Control server — local-only (127.0.0.1) socket for the CLI to issue
                      commands (send / send-file / list-peers / tail).

For v0 the peer protocol is connection-per-action: initiator opens a TCP
connection, runs the encrypted handshake, sends one or more messages, gets
ACK, closes. Persistent peering comes later.

─── Security Invariants (post-audit) ─────────────────────────────────
Each rule below is enforced at exactly one place; violating callers will
break tests intentionally — do not add per-call workarounds.

 C1 — `send_to` is the sole outbound chat path; the legacy unguarded
      duplicate has been removed.
 H2 — `_inbound_is_rejected(peer_fp)` MUST run before any state mutation
      caused by an inbound frame (sqlite write, ingest, transfer record).
      `_handle_peer` and `_on_peer_message` both gate on it.
 H3 — Inbound handshakes are throttled per-IP and bounded by
      `HANDSHAKE_DEADLINE_S`. Loopback bypasses the gate
      (`HANDSHAKE_LOOPBACK_IPS`).
 H4 — Outbound sessions idle > `OUTBOUND_SESSION_PING_AFTER_S` are
      probed with PING/PONG before reuse.
 M1 — Inbound blob frames (BLOB_OFFER, BLOB_CHUNK) are accepted only if
      the blob hash is in `self._expected_blob_pulls[peer_fp]` — populated
      exclusively when we send MANIFEST_WANTS asking for it.
 M2 — CDC chunk sets are clamped to `declared_size` and per-chunk size
      (`CDC_MIN_CHUNK_BYTES` ≤ size ≤ `CDC_MAX_CHUNK_BYTES`); attacker can
      not amplify a small offer into a huge inbound stream.
 M5 — `_acquire_instance_lock` checks the existing PID's liveness in
      addition to the kernel advisory lock.
 M6 — mDNS advertisement defaults to `short_id` (non-PII); the OS
      hostname is leaked only if the user explicitly sets `display_name`.
 M7 — `MANIFEST_PUSH` early-exit requires BOTH `merkle_root` AND
      `entry_count` to match — peer can't lie about being in sync.
 H1 — Trust + capability-policy mutations are recorded in
      `capability_audit` (sqlite); see `/api/capability-audit`.

If you find code that mutates peer state without one of these gates,
treat it as a regression — re-run the red-team audit before merging.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import json
import logging
import os
import secrets
import socket
import time
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path

import blake3

from one_link import blobstore, channel as ch, foldersync
from one_link.capabilities import CHAT, FILES, FOLDER_SYNC, LOCAL_CAPABILITIES, normalize_caps
from one_link.cdc import (
    MAX_CHUNK_BYTES as CDC_MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES as CDC_MIN_CHUNK_BYTES,
    Chunk,
    chunk_path,
    index_path,
)
from one_link.crdt import ManifestEntry, VectorClock
from one_link.discovery import Discovery, Peer
from one_link.identity import Identity, fingerprint_of, load_or_create
from one_link.pairing import PairingTracker, PairState, compute_sas
from one_link.paths import (
    data_dir,
    inbox_dir,
    message_log_path,
)
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg

# Forward import to avoid hard dep when server.py loads daemon.py
try:
    from one_link.server import UIServer  # noqa: F401
except Exception:
    UIServer = None  # type: ignore[assignment]

log = logging.getLogger("one_link.daemon")

CONTROL_PORT_FILE = "control.port"
PEER_PORT_FILE = "peer.port"
DAEMON_LOCK_FILE = "daemon.lock"
CHUNK_SIZE = 256 * 1024  # 256 KiB plaintext per FILE_CHUNK
MAX_INCOMING_FILE_BYTES = 1024 * 1024 * 1024  # match UI upload cap
CDC_CACHE_MAX_BYTES = 512 * 1024 * 1024
COMPRESSION_MIN_BYTES = 2048
COMPRESSION_MIN_SAVINGS = 0.08
OUTBOUND_SESSION_IDLE_S = 300.0
# v0.6.3 robustness: bounded waits replace previously unbounded ones.
# Without these, a stale mDNS endpoint mapping to a TCP listener that
# doesn't speak the One Link protocol caused send_file to hang forever
# on `ch.initiate`. Now: handshake has 8s, per-chunk ACK has 30s, the
# whole file-send has a watchdog at 5min for a 1GB upload (~3MB/s
# floor — slow but not stuck).
HANDSHAKE_DEADLINE_OUTBOUND_S = 8.0
FILE_ACK_DEADLINE_S = 30.0
FILE_SEND_TOTAL_DEADLINE_S = 600.0
# H4: re-validate idle outbound sessions with a PING before reusing them.
# A NAT box / Wi-Fi roam / asymmetric-disconnect can silently kill a TCP
# session; without this probe the next send_to() would block on a dead
# socket until the OS-level keepalive (minutes). The probe deadline is
# short (1.5s) so a real failure forces a fast reopen.
OUTBOUND_SESSION_PING_AFTER_S = 30.0
OUTBOUND_SESSION_PING_DEADLINE_S = 1.5
# v0.7.1: dedup window for the capability_request WS event. A peer
# retrying a denied FILE_OFFER once a second shouldn't fire 60 toasts;
# the UI gets one prompt per (peer, cap) per minute.
CAPABILITY_REQUEST_DEDUP_S = 60.0
# H3: handshake hardening
HANDSHAKE_DEADLINE_S = 8.0          # peer has 8s to complete handshake
HANDSHAKE_PER_IP_INFLIGHT_MAX = 32  # concurrent handshakes from one IP
HANDSHAKE_PER_IP_RATE_WINDOW_S = 60.0
HANDSHAKE_PER_IP_RATE_MAX = 240     # attempts per window per IP
# Loopback gets a free pass — the test suite & the local UI talk to the
# daemon on 127.0.0.1 in tight bursts, and an attacker on loopback already
# owns the box.
HANDSHAKE_LOOPBACK_IPS = frozenset({"127.0.0.1", "::1", "localhost"})

# Capabilities this build advertises in CAPS messages.
# v0.5.4 bumps to OL1.2: CAPS optionally includes `share_rdz` so paired
# devices auto-inherit each other's rendezvous URL list. Older OL1.1
# peers ignore the field — strict-forward-compat.
PROTOCOL_VERSION = "OL1.2"
CAPS_FEATURES: list[str] = [
    *LOCAL_CAPABILITIES,
    "audit",
    "fts",
    "trust",
    "rdz_inherit",  # advertises that we'll inherit rdz urls from peers
]
# v0.5.4: cap on how many URLs we'll embed in CAPS or accept from a
# peer. Defends against a malicious peer flooding us with junk URLs
# during pairing. Each inherited URL is also bound by state.set_rendezvous_urls
# validation which rejects non-http(s).
MAX_SHARED_RENDEZVOUS_URLS = 16


def _build_caps(
    short_id: str,
    *,
    rendezvous_urls: list[str] | None = None,
    channel_bind: dict | None = None,
) -> dict:
    """Build a CAPS frame.

    `rendezvous_urls` (when provided + non-empty) becomes the
    `share_rdz` field — read by paired peers running v0.5.4+ to
    auto-inherit our rendezvous configuration. Pre-OL1.2 peers
    silently ignore it; we never put it on the wire if the local
    `share_rendezvous` setting is False.
    """
    extra: dict = {}
    if rendezvous_urls:
        # Cap to a sane size — see MAX_SHARED_RENDEZVOUS_URLS comment.
        extra["share_rdz"] = list(rendezvous_urls)[:MAX_SHARED_RENDEZVOUS_URLS]
    if channel_bind:
        extra["channel_bind"] = dict(channel_bind)
    # v0.7.x: advertise the build version so peers can show "your other
    # device is on an older version" before a wire-format mismatch
    # turns into a cryptic InvalidTag. Old peers ignore unknown fields.
    try:
        from one_link import __version__ as _ol_ver
        extra["app_version"] = _ol_ver
    except Exception:
        pass
    return make_msg(
        "CAPS",
        short_id,
        protocol=PROTOCOL_VERSION,
        features=list(CAPS_FEATURES),
        **extra,
    )


def _classify_address_regime(host: str) -> str:
    """v0.5.6: classify a remote host string as 'lan' (RFC 1918,
    loopback, link-local, IPv6 ULA, IPv6 link-local, carrier-grade
    NAT) or 'internet' (public). Pure string-based — same set the
    UI uses, kept consistent so server-side and client-side
    classification can't disagree.
    """
    if not host or not isinstance(host, str):
        return "internet"
    if host == "127.0.0.1" or host.startswith("127."):
        return "lan"
    if host == "::1":
        return "lan"
    if host.startswith("169.254."):
        return "lan"
    if host.startswith("10."):
        return "lan"
    if host.startswith("192.168."):
        return "lan"
    lower = host.lower()
    if lower.startswith("fe80:"):
        return "lan"
    if lower.startswith("fc") or lower.startswith("fd"):
        return "lan"
    # 172.16.0.0 – 172.31.255.255
    parts = host.split(".")
    if len(parts) >= 2 and parts[0] == "172":
        try:
            oct1 = int(parts[1])
            if 16 <= oct1 <= 31:
                return "lan"
        except ValueError:
            pass
    # 100.64.0.0/10 (carrier-grade NAT)
    if len(parts) >= 2 and parts[0] == "100":
        try:
            oct1 = int(parts[1])
            if 64 <= oct1 <= 127:
                return "lan"
        except ValueError:
            pass
    return "internet"


def _control_port_path() -> Path:
    return data_dir() / CONTROL_PORT_FILE


def _peer_port_path() -> Path:
    return data_dir() / PEER_PORT_FILE


def _pid_is_alive(pid: int) -> bool:
    """Return True if the given OS PID is currently a live process.

    Cross-platform, stdlib-only. False positives are acceptable (we'll
    refuse to start), false negatives are not (we'd corrupt state).
    """
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, wintypes.DWORD(pid)
        )
        if not handle:
            err = ctypes.get_last_error()
            # ERROR_ACCESS_DENIED (5) means the PID exists but we can't
            # query it — treat as alive (safer to refuse to start).
            return err == 5
        try:
            exit_code = wintypes.DWORD()
            ok = kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            if not ok:
                return True
            return exit_code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    else:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists, owned by another user
        except OSError:
            return False
        return True


@dataclass
class IncomingFile:
    name: str
    size: int
    blob_hex: str
    out_path: Path
    handle: object
    received: int = 0
    next_seq: int = 0
    hasher: object = None
    cdc_chunks: list[dict] | None = None
    cdc_missing: set[int] | None = None
    cdc_parts: dict[int, bytes] | None = None
    transfer_id: str | None = None


@dataclass
class OutboundSession:
    peer_fp: str
    peer: Peer
    channel: ch.Channel
    lock: asyncio.Lock
    last_used: float
    messages_sent: int = 0
    # v0.5.6: which transport regime carried this session?
    #   "lan"      — direct TCP, peer.address is RFC-1918/loopback/etc.
    #   "internet" — direct TCP, peer.address is a public address
    #   "relay"    — went through the encrypted-relay fallback
    #   "unknown"  — pre-v0.5.6 session, regime not stamped
    regime: str = "unknown"
    # v0.6.x audit: when the regime is "relay", the inbound-pump task
    # that drains the relay WebSocket needs to be awaited on cleanup
    # so the per-session aiohttp ClientSession can flush+close before
    # the loop exits. Otherwise pytest under -W error::ResourceWarning
    # surfaces "Unclosed client session" warnings as test ends race
    # with task finally-blocks.
    relay_pump_task: asyncio.Task | None = None


class Daemon:
    def __init__(self, me: Identity):
        self.me = me
        self.discovery: Discovery | None = None
        self._peer_server: asyncio.base_events.Server | None = None
        self._control_server: asyncio.base_events.Server | None = None
        self._tail_subs: set[asyncio.StreamWriter] = set()
        self._incoming_files: dict[str, IncomingFile] = {}
        self._incoming_blobs: dict[str, dict] = {}
        self.ui_server = None  # one_link.server.UIServer | None
        self.state: State | None = None
        self.pairing = PairingTracker()
        self._prune_task: asyncio.Task | None = None
        self._lock_file = None
        # Folder sync — populated in start() when state + blob store are up.
        self.folder_engine = None  # type: foldersync.FolderEngine | None
        self.blob_store = None     # type: blobstore.BlobStore | None
        self._folder_sync_task: asyncio.Task | None = None
        self._outbound_sessions: dict[str, OutboundSession] = {}
        # M1: track which blob hashes we've explicitly requested from each
        # peer (via MANIFEST_WANTS). BLOB_OFFER / BLOB_CHUNK frames whose
        # hash isn't in this set are silently dropped — a paired peer can't
        # use a folder-sync session as a write primitive into our blob store
        # for arbitrary content.
        self._expected_blob_pulls: dict[str, set[str]] = {}
        # H3: per-IP handshake throttling. `_handshake_history[ip]` is a
        # deque of recent attempt timestamps; `_handshake_inflight[ip]` is
        # the current count of concurrent in-flight handshakes from that IP.
        # Counts are dropped once the IP has zero history & zero in-flight,
        # so the dicts stay bounded.
        self._handshake_history: dict[str, list[float]] = {}
        self._handshake_inflight: dict[str, int] = {}
        # v0.5.1: optional rendezvous client. Started in start() iff URLs
        # are configured in state; stopped on shutdown. None when offline /
        # unconfigured — daemon falls back to mDNS-only behaviour.
        self.rendezvous = None  # type: rendezvous_client.RendezvousClient | None
        # v0.5.3: peer-server port stamped during start() so live re-config
        # of rendezvous URLs (no restart) can re-derive advertised endpoints.
        self._rendezvous_peer_port: int = 0
        # v0.5.4: Track which paired peers have offered us their rendezvous
        # URL list this session, so we don't repeatedly merge the same set
        # on every reconnect.
        self._inherited_rdz_from: set[str] = set()
        # v0.5.5: encrypted-relay listeners. One persistent WS per
        # configured rendezvous URL — the destination side of the
        # relay. Started/stopped alongside the rendezvous client by
        # `update_rendezvous_urls`. None when relay isn't enabled or
        # not running.
        self._relay_listener_clients: list = []
        # v0.5.6: per-peer connection regime, last-seen.
        # peer_fp -> {"outbound": str, "inbound": str, "ts": float}
        self._inbound_regime: dict[str, str] = {}
        # v0.7.0: per-pairing health metrics. Updated on every
        # successful send / receive. Surfaced in /api/peers so the
        # UI can show real "last alive" + latency instead of guessing
        # from mDNS visibility.
        # peer_fp -> {"last_alive_ms": int, "latency_ewma_ms": float}
        self._pair_health: dict[str, dict[str, float]] = {}
        # v0.7.1: dedup table for capability_request WS events.
        # (peer_fp, cap) -> monotonic ts of last UI prompt fired.
        self._capability_request_seen: dict[tuple[str, str], float] = {}
        # v0.7.1: outbox flush concurrency. One in-flight flush per
        # peer at a time — multiple session-up events shouldn't fire
        # parallel deliveries that ACK out of order.
        self._outbox_flush_locks: dict[str, asyncio.Lock] = {}
        self._outbox_flush_inflight: set[str] = set()
        # Endpoint announcements are untrusted route candidates until a
        # fresh encrypted handshake at that address proves the expected
        # peer fingerprint. Tracks background verification tasks.
        self._endpoint_verify_tasks: set[asyncio.Task] = set()

    def _build_my_caps(self) -> dict:
        """Build a CAPS frame for THIS daemon. Includes our rendezvous
        URL list when the local `share_rendezvous` setting is True
        (default) — paired peers running v0.5.4+ auto-adopt.
        """
        share = True
        urls: list[str] = []
        if self.state is not None:
            try:
                v = self.state.get_setting("share_rendezvous")
                # Default True unless explicitly opted out.
                share = v is None or v.lower() in ("1", "true", "yes")
                if share:
                    urls = self.state.get_rendezvous_urls()
            except Exception:
                share = False
        return _build_caps(
            self.me.short_id,
            rendezvous_urls=urls if share else None,
        )

    def _channel_bind_for(self, channel: ch.Channel) -> dict:
        """Session binding advertised inside encrypted CAPS."""
        return {
            "self_fp": self.me.fingerprint,
            "peer_fp": fingerprint_of(channel.peer_ed_pub),
            "transcript": getattr(channel, "transcript_hex", ""),
            "features": list(CAPS_FEATURES),
        }

    def _build_my_caps_for_channel(self, channel: ch.Channel) -> dict:
        msg = self._build_my_caps()
        msg["channel_bind"] = self._channel_bind_for(channel)
        return msg

    def _acquire_instance_lock(self) -> None:
        """Prevent duplicate daemons for the same config/data home.

        Two layers:
         1. OS-level advisory lock (fcntl.flock / msvcrt.locking) — strongest
            guarantee, kernel releases on process death.
         2. M5: stored PID liveness check — defence-in-depth for situations
            where (1) silently fails (NFS without lockd, corrupt locks on
            Windows network shares, copies of the lock file moved between
            homes). If the PID inside the file maps to a different live
            process we refuse even if the kernel lock granted.
        """
        lock_path = data_dir() / DAEMON_LOCK_FILE
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        f = open(lock_path, "a+b")
        try:
            # Pre-lock liveness check on existing PID.
            #
            # On Windows, msvcrt.locking byte-locks make the *file* readable
            # only by the holder, so a sibling daemon attempting this read
            # will get PermissionError — which is itself diagnostic
            # (someone has the lock). We still want to fall through to the
            # OS-level lock attempt below so we get the canonical
            # "already running" error path the rest of the system expects.
            try:
                f.seek(0)
                raw = f.read(64).decode("ascii", errors="ignore").strip()
                if raw:
                    existing_pid = int(raw)
                    if existing_pid != os.getpid() and _pid_is_alive(existing_pid):
                        raise RuntimeError(
                            "One Link daemon is already running "
                            f"(pid {existing_pid}) for this ONE_LINK_HOME"
                        )
            except (ValueError, UnicodeDecodeError, PermissionError, OSError):
                # Garbage / locked-by-other / I/O blip — overwrite below
                # once we hold the lock (or fail at the OS-lock step).
                pass
            if os.name == "nt":
                import msvcrt

                f.seek(0)
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as e:
                    raise RuntimeError(
                        "One Link daemon is already running for this ONE_LINK_HOME"
                    ) from e
            else:
                import fcntl

                try:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as e:
                    raise RuntimeError(
                        "One Link daemon is already running for this ONE_LINK_HOME"
                    ) from e
            f.seek(0)
            f.truncate()
            f.write(str(os.getpid()).encode("ascii"))
            f.flush()
            self._lock_file = f
        except Exception:
            f.close()
            raise

    def _release_instance_lock(self) -> None:
        if self._lock_file is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                self._lock_file.seek(0)
                with contextlib.suppress(OSError):
                    msvcrt.locking(self._lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                with contextlib.suppress(OSError):
                    fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
        finally:
            with contextlib.suppress(OSError):
                self._lock_file.close()
            self._lock_file = None

    # ─── persistence helper ─────────────────────────────────────────────
    def _persist(self, *, msg: dict, direction: str, peer_fp: str, peer_short_id: str) -> dict:
        """Record a message in sqlite and return the canonical event dict
        (with peer_fp + peer short_id) for tail / UI broadcast."""
        body = msg.get("body") if msg.get("t") == "TEXT" else None
        # Store everything-except-the-canonical fields as metadata so we
        # round-trip cleanly for tests and history reads.
        canonical = {"t", "id", "ts", "body"}
        metadata = {
            **{k: v for k, v in msg.items() if k not in canonical},
            "short_id": peer_short_id,
        }
        if self.state is not None:
            try:
                self.state.record_message(
                    id=msg["id"],
                    ts_ms=int(msg["ts"]),
                    direction=direction,
                    peer_fp=peer_fp,
                    msg_type=msg["t"],
                    body=body,
                    room_id=msg.get("room_id"),
                    metadata=metadata,
                )
            except Exception as e:
                log.warning("state.record_message failed: %s", e)
        return {**msg, "dir": direction, "peer": peer_short_id, "peer_fp": peer_fp}

    def _transfer_event(self, rec) -> dict:
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

    def _broadcast_transfer(self, rec) -> None:
        if self.ui_server is None or rec is None:
            return
        with contextlib.suppress(Exception):
            self.ui_server.broadcast({"type": "transfer", "transfer": self._transfer_event(rec)})

    def _upsert_transfer(self, **kwargs):
        if self.state is None:
            return None
        try:
            rec = self.state.upsert_transfer(**kwargs)
            self._broadcast_transfer(rec)
            return rec
        except Exception as e:
            log.warning("state.upsert_transfer failed: %s", e)
            return None

    def _update_transfer(self, transfer_id: str | None, **kwargs):
        if self.state is None or not transfer_id:
            return None
        try:
            rec = self.state.update_transfer(transfer_id, **kwargs)
            self._broadcast_transfer(rec)
            return rec
        except Exception as e:
            log.warning("state.update_transfer failed: %s", e)
            return None

    # v0.6.3: transfer-ledger watchdog.
    STUCK_TRANSFER_DEADLINE_MS = 5 * 60 * 1000  # 5 min without progress

    def _reap_stuck_transfers(self) -> int:
        """Mark any 'offered' or 'active' transfer as 'failed' if it
        hasn't been updated in STUCK_TRANSFER_DEADLINE_MS. Defends
        the UI against silent stalls (peer crashed, NAT dropped the
        connection, network change). Returns the count reaped."""
        if self.state is None:
            return 0
        now_ms = int(time.time() * 1000)
        cutoff = now_ms - self.STUCK_TRANSFER_DEADLINE_MS
        try:
            transfers = self.state.list_transfers(limit=500)
        except Exception:
            return 0
        reaped = 0
        for t in transfers:
            if t.status not in ("offered", "active"):
                continue
            if t.updated_ms > cutoff:
                continue
            try:
                rec = self.state.update_transfer(
                    t.id,
                    status="failed",
                    metadata={
                        **t.metadata,
                        "reaped": True,
                        "reaped_reason": "no_progress_within_deadline",
                        "reaped_at_ms": now_ms,
                    },
                )
                self._broadcast_transfer(rec)
                reaped += 1
                log.info(
                    "reaped stuck transfer %s (%s, last update %d ms ago)",
                    t.id, t.status, now_ms - t.updated_ms,
                )
            except Exception as e:
                log.warning("could not reap transfer %s: %s", t.id, e)
        return reaped

    # ─── peer (encrypted) side ──────────────────────────────────────────
    def _handshake_admit(self, ip: str) -> bool:
        """H3: per-IP rate + concurrency gate. Returns True if accepted.

        Loopback bypasses the gate — the local UI / CLI / test runner all
        talk to the daemon on 127.0.0.1 and an attacker who already has
        loopback access has bigger primitives than handshake spam.
        """
        if ip in HANDSHAKE_LOOPBACK_IPS:
            return True
        now = time.monotonic()
        cutoff = now - HANDSHAKE_PER_IP_RATE_WINDOW_S
        history = self._handshake_history.setdefault(ip, [])
        # Drop expired timestamps.
        i = 0
        for ts in history:
            if ts >= cutoff:
                break
            i += 1
        if i:
            del history[:i]
        if len(history) >= HANDSHAKE_PER_IP_RATE_MAX:
            return False
        if self._handshake_inflight.get(ip, 0) >= HANDSHAKE_PER_IP_INFLIGHT_MAX:
            return False
        history.append(now)
        self._handshake_inflight[ip] = self._handshake_inflight.get(ip, 0) + 1
        return True

    def _handshake_release(self, ip: str) -> None:
        if ip in HANDSHAKE_LOOPBACK_IPS:
            return
        n = self._handshake_inflight.get(ip, 0) - 1
        if n <= 0:
            self._handshake_inflight.pop(ip, None)
        else:
            self._handshake_inflight[ip] = n
        # If the rate-limit window is empty too, drop the bucket so the
        # dicts can't grow without bound under churn.
        if (
            ip not in self._handshake_inflight
            and not self._handshake_history.get(ip)
        ):
            self._handshake_history.pop(ip, None)

    async def _handle_peer(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        regime: str | None = None,
    ) -> None:
        """Inbound peer handler. `regime` is set by the caller:
          - None (TCP path): classified post-handshake from the
            socket's peer address.
          - "relay" (relay tunnel path): set by
            _handle_relay_inbound_session — the writer is a synthetic
            relay stream and `peername` would be misleading.
        """
        addr = writer.get_extra_info("peername")
        peer_ip = addr[0] if addr else ""
        if not self._handshake_admit(peer_ip):
            log.warning("handshake throttled from %s", peer_ip)
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return
        try:
            try:
                channel = await asyncio.wait_for(
                    ch.respond(reader, writer, self.me),
                    timeout=HANDSHAKE_DEADLINE_S,
                )
            except asyncio.TimeoutError:
                log.warning("handshake deadline exceeded from %s", addr)
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
                return
            except Exception as e:
                log.warning("handshake failed from %s: %s", addr, e)
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()
                return
        finally:
            self._handshake_release(peer_ip)
        log.info("peer connected: %s @ %s", channel.peer_short_id, addr)
        peer_fp = fingerprint_of(channel.peer_ed_pub)
        # v0.5.6: stamp regime so /api/peers can surface "via relay" /
        # "internet" / "lan" badges for the inbound side. Outbound
        # sessions are stamped separately on OutboundSession.
        inbound_regime = regime if regime is not None else _classify_address_regime(peer_ip)
        self._inbound_regime[peer_fp] = inbound_regime
        if self._inbound_is_rejected(peer_fp):
            log.warning("rejected peer attempted inbound connection: %s", peer_fp[:8])
            await channel.close()
            return
        if self.state is not None:
            try:
                hostname: str | None = None
                if self.discovery:
                    pinfo = self.discovery.registry.find(channel.peer_short_id)
                    if pinfo:
                        hostname = pinfo.hostname
                self.state.upsert_peer(
                    fingerprint=peer_fp,
                    short_id=channel.peer_short_id,
                    pubkey=channel.peer_ed_pub,
                    hostname=hostname,
                    address=addr[0] if addr else None,
                    port=addr[1] if addr else None,
                )
            except Exception as e:
                log.warning("upsert_peer failed: %s", e)

        # Send our capabilities eagerly (no ACK expected).
        try:
            await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
        except Exception as e:
            log.warning("CAPS send failed: %s", e)

        try:
            while True:
                try:
                    plaintext = await channel.recv()
                except asyncio.IncompleteReadError:
                    break
                msg = decode_msg(plaintext)
                await self._on_peer_message(channel, msg)
        except Exception as e:
            log.warning("peer loop error (%s): %s", channel.peer_short_id, e)
        finally:
            await channel.close()
            log.info("peer disconnected: %s", channel.peer_short_id)

    async def _on_peer_message(self, channel: ch.Channel, msg: dict) -> None:
        peer_fp = fingerprint_of(channel.peer_ed_pub)
        peer_sid = channel.peer_short_id
        # v0.7.0: any frame received from a paired peer = they're alive.
        self._stamp_pair_health(peer_fp)
        t = msg.get("t")
        # H2: rejected peers cannot drive any state mutation, including the
        # sqlite write that CAPS would have caused. They get an ACK with the
        # rejection reason so they can fail loudly instead of silently
        # retrying a write-amplification primitive against our DB.
        if self._inbound_is_rejected(peer_fp):
            with contextlib.suppress(Exception):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id,
                    of=msg.get("id"), rejected="peer_rejected",
                )))
            raise RuntimeError(f"rejected peer attempted message: {peer_fp[:8]}")
        if t == "CAPS":
            features = list(normalize_caps(msg.get("features", [])))
            bind = msg.get("channel_bind")
            if isinstance(bind, dict):
                expected_peer_fp = self.me.fingerprint
                expected_self_fp = peer_fp
                transcript = getattr(channel, "transcript_hex", "")
                if (
                    bind.get("peer_fp") != expected_peer_fp
                    or bind.get("self_fp") != expected_self_fp
                    or bind.get("transcript") != transcript
                ):
                    raise RuntimeError(
                        f"CAPS channel binding mismatch from {peer_fp[:8]}"
                    )
            channel.peer_caps = {
                "protocol": msg.get("protocol", "?"),
                "features": features,
                "from": msg.get("from"),
                "channel_bind": bind if isinstance(bind, dict) else None,
                "app_version": msg.get("app_version"),
            }
            if self.state is not None:
                with contextlib.suppress(Exception):
                    self.state.set_peer_capabilities(peer_fp, features)
            # v0.5.4: pair-time URL inheritance.
            # Adopt rendezvous URLs from the peer — but only if:
            #   1. Peer is pinned (we explicitly trusted them via SAS)
            #   2. We haven't already inherited from this peer this session
            #   3. We have an `inherit_rendezvous` setting on (default True)
            #   4. The URLs validate (state.set_rendezvous_urls rejects junk)
            shared = msg.get("share_rdz")
            if (
                isinstance(shared, list)
                and shared
                and self._is_pinned(peer_fp)
                and peer_fp not in self._inherited_rdz_from
            ):
                with contextlib.suppress(Exception):
                    self._inherit_rendezvous_urls_from(peer_fp, shared)
            log.info(
                "peer caps from %s: %s features=%s",
                peer_sid, channel.peer_caps["protocol"],
                channel.peer_caps["features"],
            )
            return  # no ACK needed
        if t == "TEXT":
            if not self._capability_allowed(peer_fp, CHAT):
                self._emit_capability_request(peer_fp, peer_sid, CHAT)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg["id"], rejected="capability_disabled",
                )))
                return
            ev = self._persist(msg=msg, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "FILE_OFFER":
            if not self._capability_allowed(peer_fp, FILES):
                self._emit_capability_request(peer_fp, peer_sid, FILES)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg["id"], rejected="capability_disabled",
                )))
                return
            blob = str(msg["blob"])
            if not self._valid_blob_hex(blob):
                raise RuntimeError("invalid FILE_OFFER blob hash")
            size = int(msg["size"])
            if size < 0 or size > MAX_INCOMING_FILE_BYTES:
                raise RuntimeError(f"invalid FILE_OFFER size: {size}")
            name = Path(str(msg["name"])).name
            if not name or name in (".", ".."):
                name = "unnamed.bin"
            cdc_chunks = self._normalize_cdc_chunks(msg.get("chunks"), declared_size=size)
            out_path = inbox_dir() / f"{blob[:8]}_{name}"
            handle = open(out_path, "wb")
            missing = None
            if cdc_chunks:
                missing = {
                    int(c["index"]) for c in cdc_chunks
                    if not self._chunk_cache_path(str(c["hash"])).is_file()
                }
            transfer_id = f"in:{blob}"
            self._incoming_files[blob] = IncomingFile(
                name=name,
                size=size,
                blob_hex=blob,
                out_path=out_path,
                handle=handle,
                hasher=blake3.blake3(),
                cdc_chunks=cdc_chunks,
                cdc_missing=missing,
                cdc_parts={},
                transfer_id=transfer_id,
            )
            self._upsert_transfer(
                id=transfer_id,
                direction="in",
                peer_fp=peer_fp,
                kind="file",
                name=name,
                size=size,
                blob_hash=blob,
                status="offered",
                progress_bytes=0 if missing else size if cdc_chunks else 0,
                total_bytes=size,
                chunks_done=(len(cdc_chunks) - len(missing or [])) if cdc_chunks else 0,
                chunks_total=len(cdc_chunks) if cdc_chunks else 0,
                metadata={
                    "mode": "cdc" if cdc_chunks else "stream",
                    "path": str(out_path),
                    "missing_chunks": len(missing or []),
                },
            )
            log.info(
                "file offer: %s (%d bytes) blob=%s from %s",
                name, msg["size"], blob[:8], peer_sid,
            )
            ev = self._persist(msg=msg, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            if cdc_chunks is not None:
                await channel.send(encode_msg(make_msg(
                    "FILE_WANTS", self.me.short_id,
                    of=msg["id"], blob=blob, wants=sorted(missing or []),
                )))
                if not missing:
                    await self._finish_cdc_file(blob, peer_fp, peer_sid, msg)
            else:
                await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "FILE_CHUNK":
            blob = str(msg["blob"])
            f = self._incoming_files.get(blob)
            if not f:
                log.warning("FILE_CHUNK with no offer: %s", blob[:8])
                return
            seq = int(msg.get("seq", -1))
            if seq != f.next_seq:
                self._abort_incoming_file(blob, f)
                raise RuntimeError(
                    f"FILE_CHUNK sequence mismatch for {blob[:8]}: "
                    f"expected {f.next_seq}, got {seq}"
                )
            try:
                data = base64.b64decode(msg["data"], validate=True)
            except (binascii.Error, ValueError) as e:
                self._abort_incoming_file(blob, f)
                raise RuntimeError(f"invalid FILE_CHUNK base64: {e}") from e
            if f.received + len(data) > f.size:
                self._abort_incoming_file(blob, f)
                raise RuntimeError(
                    f"FILE_CHUNK exceeds declared size for {blob[:8]}: "
                    f"{f.received + len(data)} > {f.size}"
                )
            f.handle.write(data)
            f.hasher.update(data)
            f.received += len(data)
            f.next_seq += 1
            self._update_transfer(
                f.transfer_id,
                status="active",
                progress_bytes=f.received,
                total_bytes=f.size,
                chunks_done=f.next_seq,
                chunks_total=max(f.next_seq, (f.size + CHUNK_SIZE - 1) // CHUNK_SIZE),
            )
            if msg.get("eof"):
                f.handle.close()
                got = f.hasher.hexdigest()
                ok = got == f.blob_hex and f.received == f.size
                done = {
                    "t": "FILE_DONE",
                    "id": msg["id"],
                    "ts": msg["ts"],
                    "from": msg["from"],
                    "name": f.name,
                    "size": f.size,
                    "path": str(f.out_path),
                    "blob": f.blob_hex,
                    "ok": ok,
                }
                ev = self._persist(msg=done, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
                self._broadcast_tail(ev)
                self._incoming_files.pop(blob, None)
                if not ok:
                    with contextlib.suppress(OSError):
                        f.out_path.unlink()
                    self._update_transfer(f.transfer_id, status="failed")
                else:
                    self._cache_file_chunks(f.out_path)
                    self._update_transfer(
                        f.transfer_id,
                        status="complete",
                        progress_bytes=f.size,
                        total_bytes=f.size,
                    )
                log.info("file done: %s ok=%s -> %s", f.name, ok, f.out_path)
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "FILE_CDC_CHUNK":
            await self._handle_file_cdc_chunk(channel, msg, peer_fp, peer_sid)
        elif t == "GROUP_KEY_OFFER":
            await self._handle_group_key_offer(channel, msg, peer_fp)
        elif t == "GROUP_MSG":
            await self._handle_group_msg(channel, msg, peer_fp, peer_sid)
        elif t == "ENDPOINT_UPDATE":
            await self._handle_endpoint_update(channel, msg, peer_fp, peer_sid)
        elif t == "PING":
            await channel.send(encode_msg(make_msg("PONG", self.me.short_id)))
        elif t == "PAIR_REQUEST":
            # Peer wants to pair with us. Compute the SAS (deterministic),
            # store as incoming, surface to UI for the user to verify.
            sas = compute_sas(self.me.public_bytes, channel.peer_ed_pub)
            ctx = self.pairing.get(peer_fp)
            if ctx is None or ctx.state in (PairState.NONE, PairState.PAIRED, PairState.REJECTED):
                ctx = self.pairing.begin(peer_fp=peer_fp, sas=sas, incoming=True)
            if self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "pair_request",
                    "peer_fp": peer_fp,
                    "peer_short_id": peer_sid,
                    "sas": sas,
                })
            log.info("PAIR_REQUEST from %s sas=%s ctx.state=%s",
                     peer_sid, sas, ctx.state.value)
            # ACK so the sender can close the connection cleanly.
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "PAIR_CONFIRM":
            # Peer says SAS matched on their side.
            ctx = self.pairing.they_confirm(peer_fp)
            if ctx is None:
                # We never started pairing on our side; treat as a fresh
                # incoming so the UI can prompt.
                sas = compute_sas(self.me.public_bytes, channel.peer_ed_pub)
                ctx = self.pairing.begin(peer_fp=peer_fp, sas=sas, incoming=True)
                self.pairing.they_confirm(peer_fp)
                ctx = self.pairing.get(peer_fp)
            # Re-fetch the latest ctx (in case other handlers mutated it
            # while we were processing).
            ctx = self.pairing.get(peer_fp) or ctx
            if ctx and ctx.both_confirmed and self.state is not None:
                # Defensive upsert in case the peer record was missed.
                try:
                    self.state.upsert_peer(
                        fingerprint=peer_fp,
                        short_id=peer_sid,
                        pubkey=channel.peer_ed_pub,
                    )
                except Exception:
                    pass
                self.state.set_peer_trust(peer_fp, "pinned", actor="pairing")
                # v0.7.1 deny-by-default: SAS pair grants CHAT only.
                # The user can grant files/folders/groups via the UI
                # prompt that fires on the first request.
                self._apply_default_capability_policy(peer_fp)
                if self.ui_server is not None:
                    self.ui_server.broadcast({
                        "type": "peer_trust",
                        "fingerprint": peer_fp,
                        "trust": "pinned",
                    })
                log.info("paired with %s (sas=%s)", peer_sid, ctx.sas)
            elif self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "pair_progress",
                    "peer_fp": peer_fp,
                    "they_confirmed": True,
                })
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "PAIR_REJECT":
            self.pairing.reject(peer_fp)
            if self.state is not None:
                try:
                    self.state.upsert_peer(
                        fingerprint=peer_fp, short_id=peer_sid,
                        pubkey=channel.peer_ed_pub,
                    )
                except Exception:
                    pass
                self.state.set_peer_trust(peer_fp, "rejected", actor="pairing")
            if self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "pair_rejected",
                    "peer_fp": peer_fp,
                    "peer_short_id": peer_sid,
                })
            log.info("pair rejected by %s", peer_sid)
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))

        # ─── folder sync wire protocol ──────────────────────────────────
        elif t == "MANIFEST_PUSH":
            # Peer is offering us their view of a shared folder.
            if not self._capability_allowed(peer_fp, FOLDER_SYNC):
                self._emit_capability_request(peer_fp, peer_sid, FOLDER_SYNC)
                return
            await self._handle_manifest_push(channel, msg, peer_fp)
        elif t == "MANIFEST_WANTS":
            # Peer is asking for specific blobs that they don't have.
            await self._handle_manifest_wants(channel, msg, peer_fp)
        elif t == "BLOB_OFFER":
            await self._handle_blob_offer(channel, msg, peer_fp)
        elif t == "BLOB_CHUNK":
            await self._handle_blob_chunk(channel, msg, peer_fp)

    # ─── CDC file-transfer helpers ─────────────────────────────────────
    def _chunk_cache_dir(self) -> Path:
        p = data_dir() / "file_chunks"
        p.mkdir(parents=True, exist_ok=True)
        return p

    def _chunk_cache_path(self, hash_hex: str) -> Path:
        return self._chunk_cache_dir() / hash_hex[:2] / hash_hex[2:]

    def _normalize_cdc_chunks(self, raw, *, declared_size: int | None = None) -> list[dict] | None:
        """Validate a peer-supplied CDC chunk index.

        Returns None on any malformed input. Caller treats None as "use the
        non-CDC streaming path" — the file still transfers, just without the
        dedup optimization.

        M3: a peer can advertise `chunks: list[dict]` of arbitrary length.
        At MIN_CHUNK_BYTES, a 1 GiB file produces ~64k chunks max; we accept
        the upper bound as `(declared_size // MIN_CHUNK_BYTES) + 16` (the
        +16 absorbs CDC's small-tail-chunk drift). Above that, a peer is
        either lying or trying to make us allocate huge structures.
        """
        if raw is None:
            return None
        if not isinstance(raw, list):
            return None
        if declared_size is not None and declared_size >= 0:
            max_chunks = max(1, declared_size // CDC_MIN_CHUNK_BYTES + 16)
        else:
            # Fallback: cap absolutely at the count for the largest file we
            # would ever accept on the wire.
            max_chunks = (MAX_INCOMING_FILE_BYTES // CDC_MIN_CHUNK_BYTES) + 16
        if len(raw) > max_chunks:
            log.warning(
                "rejecting FILE_OFFER chunks list: %d > %d (declared_size=%s)",
                len(raw), max_chunks, declared_size,
            )
            return None
        out = []
        running_end = 0
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                return None
            h = str(item.get("hash", ""))
            if not self._valid_blob_hex(h):
                return None
            start = int(item.get("start", 0))
            end = int(item.get("end", 0))
            size = int(item.get("size", end - start))
            if start < 0 or end < start or size != end - start:
                return None
            if size < 0 or size > CDC_MAX_CHUNK_BYTES * 2:
                # CDC's hard upper bound is MAX_CHUNK_BYTES; allow a small
                # multiplier to account for any future loosening, but reject
                # absurd sizes that would force a multi-MB single allocation.
                return None
            if declared_size is not None and end > declared_size:
                return None
            running_end = max(running_end, end)
            out.append({"index": i, "start": start, "end": end, "size": size, "hash": h})
        if declared_size is not None and running_end > declared_size:
            return None
        return out

    def _store_chunk_cache(self, chunk_hash: str, data: bytes) -> None:
        if blake3.blake3(data).hexdigest() != chunk_hash:
            raise RuntimeError("CDC chunk hash mismatch")
        dst = self._chunk_cache_path(chunk_hash)
        if dst.is_file():
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.parent / f".{os.getpid()}_{secrets.token_hex(8)}.tmp"
        tmp.write_bytes(data)
        os.replace(tmp, dst)

    def _read_chunk_cache(self, chunk_hash: str) -> bytes | None:
        p = self._chunk_cache_path(chunk_hash)
        if not p.is_file():
            return None
        with contextlib.suppress(OSError):
            os.utime(p, None)
        return p.read_bytes()

    def _cache_file_chunks(self, path: Path) -> None:
        try:
            chunks = chunk_path(path)
            with open(path, "rb") as fh:
                for c in chunks:
                    fh.seek(c.start)
                    self._store_chunk_cache(c.hash, fh.read(c.size))
        except Exception as e:
            log.debug("CDC cache fill skipped for %s: %s", path, e)

    def _chunk_cache_stats(self) -> dict:
        root = self._chunk_cache_dir()
        count = 0
        total = 0
        oldest_ms = None
        newest_ms = None
        for shard in root.iterdir():
            if not shard.is_dir():
                continue
            for p in shard.iterdir():
                if not p.is_file():
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                count += 1
                total += st.st_size
                mtime_ms = int(st.st_mtime * 1000)
                oldest_ms = mtime_ms if oldest_ms is None else min(oldest_ms, mtime_ms)
                newest_ms = mtime_ms if newest_ms is None else max(newest_ms, mtime_ms)
        return {
            "chunks": count,
            "bytes": total,
            "max_bytes": CDC_CACHE_MAX_BYTES,
            "oldest_mtime_ms": oldest_ms,
            "newest_mtime_ms": newest_ms,
        }

    def _prune_chunk_cache(self, max_bytes: int = CDC_CACHE_MAX_BYTES) -> dict:
        root = self._chunk_cache_dir()
        entries = []
        total = 0
        for shard in root.iterdir():
            if not shard.is_dir():
                continue
            for p in shard.iterdir():
                if not p.is_file():
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                entries.append((st.st_mtime, st.st_size, p))
                total += st.st_size
        removed = 0
        freed = 0
        for _mtime, size, p in sorted(entries):
            if total <= max_bytes:
                break
            with contextlib.suppress(OSError):
                p.unlink()
                removed += 1
                freed += size
                total -= size
                with contextlib.suppress(OSError):
                    p.parent.rmdir()
        return {"removed": removed, "freed_bytes": freed, "bytes": total}

    def _encode_payload(self, data: bytes) -> tuple[str, bytes]:
        if len(data) < COMPRESSION_MIN_BYTES:
            return "raw", data
        compressed = zlib.compress(data, level=1)
        if len(compressed) <= len(data) * (1.0 - COMPRESSION_MIN_SAVINGS):
            return "zlib", compressed
        return "raw", data

    def _decode_payload(self, encoding: str, data: bytes, *, max_bytes: int | None = None) -> bytes:
        """Decompress an inbound payload with a strict output bound.

        M4: previously the cap was MAX_INCOMING_FILE_BYTES (1 GiB) for every
        decompression call, so a zlib bomb of ~1 KB compressed → 1 GiB
        decompressed could happen before we raised. Callers now pass the
        *expected* upper bound for the specific message they are decoding —
        for CDC chunks, that's CDC_MAX_CHUNK_BYTES; for whole files, the
        declared size; etc.
        """
        if encoding == "raw" or not encoding:
            return data
        cap = max_bytes if max_bytes is not None else MAX_INCOMING_FILE_BYTES
        if cap <= 0:
            raise RuntimeError("max_bytes must be positive")
        # +1 lets us detect overflow without silently truncating valid data.
        if encoding == "zlib":
            dec = zlib.decompressobj()
            out = dec.decompress(data, cap + 1)
            if dec.unconsumed_tail or len(out) > cap:
                raise RuntimeError(
                    f"compressed payload exceeds maximum size ({cap} bytes)"
                )
            out += dec.flush()
            if len(out) > MAX_INCOMING_FILE_BYTES:
                raise RuntimeError("compressed payload exceeds maximum size")
            return out
        raise RuntimeError(f"unknown payload encoding: {encoding}")

    async def _handle_file_cdc_chunk(self, channel, msg, peer_fp, peer_sid) -> None:
        blob = str(msg.get("blob", ""))
        f = self._incoming_files.get(blob)
        if not f or f.cdc_chunks is None or f.cdc_missing is None:
            return
        idx = int(msg.get("index", -1))
        if idx < 0 or idx >= len(f.cdc_chunks) or idx not in f.cdc_missing:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(f"unexpected FILE_CDC_CHUNK index {idx}")
        expected = f.cdc_chunks[idx]
        # M4: bound decompression by the *expected* chunk size, not by the
        # whole-file cap. A zlib bomb is rejected at 1.5x the expected
        # chunk size (small slack for compressor framing variance).
        max_chunk_out = max(expected["size"] + 64, CDC_MAX_CHUNK_BYTES + 64)
        try:
            data = base64.b64decode(msg.get("data", ""), validate=True)
            data = self._decode_payload(
                str(msg.get("enc", "raw")), data, max_bytes=max_chunk_out,
            )
        except (binascii.Error, ValueError) as e:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(f"invalid FILE_CDC_CHUNK base64: {e}") from e
        if len(data) != expected["size"] or blake3.blake3(data).hexdigest() != expected["hash"]:
            self._abort_incoming_file(blob, f)
            raise RuntimeError("FILE_CDC_CHUNK integrity failure")
        self._store_chunk_cache(expected["hash"], data)
        f.cdc_parts[idx] = data
        f.cdc_missing.remove(idx)
        cached = len(f.cdc_chunks) - len(f.cdc_missing)
        done_bytes = sum(int(c["size"]) for c in f.cdc_chunks if int(c["index"]) not in f.cdc_missing)
        self._update_transfer(
            f.transfer_id,
            status="active",
            progress_bytes=done_bytes,
            total_bytes=f.size,
            chunks_done=cached,
            chunks_total=len(f.cdc_chunks),
            metadata={
                "mode": "cdc",
                "path": str(f.out_path),
                "missing_chunks": len(f.cdc_missing),
            },
        )
        await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        if not f.cdc_missing:
            await self._finish_cdc_file(blob, peer_fp, peer_sid, msg)

    async def _finish_cdc_file(self, blob: str, peer_fp: str, peer_sid: str, src_msg: dict) -> None:
        f = self._incoming_files.get(blob)
        if not f or f.cdc_chunks is None:
            return
        try:
            f.handle.seek(0)
            f.handle.truncate()
            h = blake3.blake3()
            written = 0
            for c in f.cdc_chunks:
                data = f.cdc_parts.get(c["index"]) if f.cdc_parts else None
                if data is None:
                    data = self._read_chunk_cache(c["hash"])
                if data is None:
                    return
                f.handle.write(data)
                h.update(data)
                self._store_chunk_cache(c["hash"], data)
                written += len(data)
            f.handle.close()
            ok = h.hexdigest() == blob and written == f.size
            done = {
                "t": "FILE_DONE", "id": src_msg["id"], "ts": src_msg["ts"],
                "from": src_msg["from"], "name": f.name, "size": f.size,
                "path": str(f.out_path), "blob": blob, "ok": ok,
                "cdc": True,
            }
            ev = self._persist(msg=done, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            self._incoming_files.pop(blob, None)
            if not ok:
                with contextlib.suppress(OSError):
                    f.out_path.unlink()
                self._update_transfer(f.transfer_id, status="failed")
            else:
                self._cache_file_chunks(f.out_path)
                self._update_transfer(
                    f.transfer_id,
                    status="complete",
                    progress_bytes=f.size,
                    total_bytes=f.size,
                    chunks_done=len(f.cdc_chunks),
                    chunks_total=len(f.cdc_chunks),
                )
        except Exception:
            self._update_transfer(f.transfer_id, status="failed")
            self._abort_incoming_file(blob, f)
            raise

    # ─── folder sync handlers ──────────────────────────────────────────
    def _is_pinned(self, peer_fp: str) -> bool:
        if self.state is None:
            return False
        rec = self.state.get_peer(peer_fp)
        return bool(rec and rec.trust == "pinned")

    def _sandbox_filter_manifest_entries(
        self, *, folder: dict, peer_fp: str, entries: list,
    ) -> list:
        """v0.7.2 sandbox: per-entry policy gate for incoming manifest
        rows. Each entry is either accepted (returned + audited as
        'write' or 'delete') or rejected (dropped + audited).

        Rejection reasons:
          - reject_pattern   — file_path matches an ignored glob
          - reject_size      — declared size > max_file_bytes
          - reject_traversal — file_path contains '..' or absolute root
        """
        if self.state is None:
            return entries
        folder_name = folder["name"]
        max_size = folder.get("max_file_bytes")
        patterns = folder.get("ignored_patterns") or []
        kept: list = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            file_path = str(e.get("file_path", "") or "")
            blob_hash = e.get("blob_hash")
            size = e.get("size")
            # Path-traversal guard: reject any entry whose path
            # would escape the sandbox root or look like an absolute
            # path. Existing code in foldersync also normalizes; this
            # is a belt-and-suspenders check at the policy layer with
            # an audited reject so the user can see attempts.
            norm = file_path.replace("\\", "/").lstrip("/")
            if (
                not norm
                or ".." in norm.split("/")
                or file_path.startswith("/")
                or (len(file_path) > 1 and file_path[1] == ":")
            ):
                with contextlib.suppress(Exception):
                    self.state.record_folder_audit_event(
                        folder_name=folder_name, peer_fp=peer_fp,
                        action="reject_traversal", file_path=file_path,
                        blob_hash=blob_hash if isinstance(blob_hash, str) else None,
                        size=int(size) if isinstance(size, int) else None,
                        note="path traversal or absolute path",
                    )
                continue
            # Pattern deny-list.
            if patterns and self.state.folder_path_matches_ignored(
                norm, patterns,
            ):
                with contextlib.suppress(Exception):
                    self.state.record_folder_audit_event(
                        folder_name=folder_name, peer_fp=peer_fp,
                        action="reject_pattern", file_path=norm,
                        blob_hash=blob_hash if isinstance(blob_hash, str) else None,
                        size=int(size) if isinstance(size, int) else None,
                    )
                continue
            # Size cap.
            if (
                max_size is not None
                and isinstance(size, int)
                and size > int(max_size)
            ):
                with contextlib.suppress(Exception):
                    self.state.record_folder_audit_event(
                        folder_name=folder_name, peer_fp=peer_fp,
                        action="reject_size", file_path=norm,
                        blob_hash=blob_hash if isinstance(blob_hash, str) else None,
                        size=int(size),
                        note=f"exceeds max_file_bytes={max_size}",
                    )
                continue
            # Accept. Audit as write/delete depending on whether
            # this is a tombstone.
            kept.append(e)
            with contextlib.suppress(Exception):
                self.state.record_folder_audit_event(
                    folder_name=folder_name, peer_fp=peer_fp,
                    action="delete" if blob_hash is None else "write",
                    file_path=norm,
                    blob_hash=blob_hash if isinstance(blob_hash, str) else None,
                    size=int(size) if isinstance(size, int) else None,
                )
        return kept

    async def _handle_manifest_push(self, channel, msg, peer_fp):
        if self.folder_engine is None or self.state is None:
            return
        # Only sync folders the peer is explicitly shared with AND is pinned.
        if not self._is_pinned(peer_fp):
            log.info("ignoring MANIFEST_PUSH from non-pinned peer %s", peer_fp[:8])
            return
        folder_name = msg.get("folder")
        if not folder_name:
            return
        f = self.state.get_folder(folder_name)
        if not f or peer_fp not in f["shared_with"]:
            log.info("MANIFEST_PUSH for folder we don't share with this peer")
            return
        if not self.state.folder_peer_allows(folder_name, peer_fp, "pull"):
            log.info("MANIFEST_PUSH denied by folder capability for %s", peer_fp[:8])
            return
        remote_root = msg.get("merkle_root")
        remote_count = msg.get("entry_count")
        local_root = self.folder_engine.manifest_root(folder_name)
        local_count = len(self.folder_engine.manifest_for(folder_name))
        # M7: a peer can claim "merkle_root matches yours" to make us skip
        # the merge and miss real updates. Only honour the early-exit when
        # *both* roots match AND the entry counts match. The root alone is
        # peer-supplied (can be lied about); the count check makes the
        # asymmetric attack (pretending to be in sync) require an actual
        # collision rather than just a guess.
        entries = msg.get("entries", []) or []
        if (
            remote_root and remote_root == local_root
            and isinstance(remote_count, int) and remote_count == local_count
            and not entries
        ):
            await channel.send(encode_msg(make_msg(
                "MANIFEST_WANTS", self.me.short_id,
                folder=folder_name, wants=[], merkle_root=local_root,
                already_in_sync=True,
            )))
            log.info(
                "MANIFEST_PUSH from %s: Merkle roots + counts match; in sync",
                peer_fp[:8],
            )
            return
        # v0.7.2 sandbox: filter remote entries against the folder's
        # capability policy (max_file_bytes, ignored_patterns, path
        # traversal). Each accept/reject decision is audited so the
        # user can review what the peer tried to do. The filtered
        # list is what the manifest engine actually merges.
        entries = self._sandbox_filter_manifest_entries(
            folder=f, peer_fp=peer_fp, entries=entries,
        )
        try:
            wants_data = self.folder_engine.receive_remote_manifest(
                folder_name=folder_name, entries=entries,
            )
        except Exception as e:
            log.warning("manifest merge failed: %s", e)
            return
        wants = [
            d["blob_hash"] for d in wants_data
            if d.get("blob_hash") and self._valid_blob_hex(d["blob_hash"])
        ]
        # M1: register the wanted set so subsequent BLOB_OFFER / BLOB_CHUNK
        # frames from this peer are gated to the blobs we asked for.
        if wants:
            self._expected_blob_pulls.setdefault(peer_fp, set()).update(wants)
        await channel.send(encode_msg(make_msg(
            "MANIFEST_WANTS", self.me.short_id,
            folder=folder_name, wants=wants,
            merkle_root=self.folder_engine.manifest_root(folder_name),
        )))
        log.info("MANIFEST_PUSH from %s: %d entries, %d wants",
                 peer_fp[:8], len(entries), len(wants))

    async def _handle_manifest_wants(self, channel, msg, peer_fp):
        if self.folder_engine is None or self.state is None:
            return
        if not self._is_pinned(peer_fp):
            return
        folder_name = msg.get("folder")
        wants = msg.get("wants", []) or []
        if not folder_name:
            return
        f = self.state.get_folder(folder_name)
        if not f or peer_fp not in f["shared_with"]:
            return
        if not self.state.folder_peer_allows(folder_name, peer_fp, "push"):
            return
        for blob_hex in wants:
            if not self._valid_blob_hex(blob_hex):
                continue
            if not self.blob_store or not self.blob_store.has(blob_hex):
                continue
            size = self.blob_store.size(blob_hex)
            await channel.send(encode_msg(make_msg(
                "BLOB_OFFER", self.me.short_id,
                blob=blob_hex, size=size,
            )))
            seq = 0
            try:
                with self.blob_store.open_read(blob_hex) as fh:
                    prev = fh.read(CHUNK_SIZE)
                    while prev:
                        cur = fh.read(CHUNK_SIZE)
                        eof = not cur
                        await channel.send(encode_msg(make_msg(
                            "BLOB_CHUNK", self.me.short_id,
                            blob=blob_hex, seq=seq,
                            data=base64.b64encode(prev).decode("ascii"),
                            eof=eof,
                        )))
                        seq += 1
                        prev = cur
            except OSError as e:
                log.warning("blob stream %s failed: %s", blob_hex[:8], e)

    async def _handle_blob_offer(self, channel, msg, peer_fp):
        if not self._is_pinned(peer_fp) or self.blob_store is None:
            return
        blob = msg.get("blob")
        size = msg.get("size", 0)
        if not self._valid_blob_hex(blob or ""):
            return
        if size < 0 or size > MAX_INCOMING_FILE_BYTES:
            return
        # M1: only accept blobs we explicitly requested from this peer via
        # MANIFEST_WANTS in the current sync cycle. A paired peer cannot use
        # the folder-sync wire as a write primitive into our blob store with
        # content we never asked for.
        expected = self._expected_blob_pulls.get(peer_fp)
        if expected is None or blob not in expected:
            log.info(
                "ignoring unsolicited BLOB_OFFER from %s for %s",
                peer_fp[:8], blob[:12] if blob else "?",
            )
            return
        # If we already have this blob, ignore the offer (peer wasted work).
        if self.blob_store.has(blob):
            return
        # Open a streaming writer.
        cm = self.blob_store.writer()
        writer, tmp_path = cm.__enter__()
        self._incoming_blobs[blob] = {
            "size": int(size),
            "received": 0,
            "next_seq": 0,
            "writer": writer,
            "cm": cm,
            "tmp_path": tmp_path,
        }

    async def _handle_blob_chunk(self, channel, msg, peer_fp):
        if not self._is_pinned(peer_fp) or self.blob_store is None:
            return
        blob = msg.get("blob")
        ctx = self._incoming_blobs.get(blob)
        if ctx is None:
            return
        # M1 (defense in depth): the offer was already gated, but if the
        # connection got reused after a different sync cycle this gate
        # ensures chunks for an unsolicited offer can't slip through.
        expected = self._expected_blob_pulls.get(peer_fp)
        if expected is None or blob not in expected:
            self._abort_blob(blob)
            return
        seq = msg.get("seq", -1)
        if seq != ctx["next_seq"]:
            log.warning("BLOB_CHUNK seq mismatch for %s (got %s, want %d)",
                        blob[:8], seq, ctx["next_seq"])
            self._abort_blob(blob)
            return
        try:
            data = base64.b64decode(msg.get("data", ""))
        except (binascii.Error, ValueError):
            self._abort_blob(blob)
            return
        ctx["received"] += len(data)
        ctx["next_seq"] += 1
        if ctx["received"] > ctx["size"] + (8 * 1024):
            self._abort_blob(blob)
            return
        try:
            ctx["writer"].write(data)
        except Exception:
            self._abort_blob(blob)
            return
        if msg.get("eof"):
            try:
                got_hash = ctx["writer"].commit()
            except Exception as e:
                log.warning("blob commit failed: %s", e)
                self._abort_blob(blob)
                return
            ctx["cm"].__exit__(None, None, None)
            self._incoming_blobs.pop(blob, None)
            if got_hash != blob:
                log.warning("blob hash mismatch: got %s, want %s",
                            got_hash[:12], blob[:12])
                # Hash didn't match; remove what we stored
                self.blob_store.remove(got_hash)
                return
            # Drop the satisfied entry from the expected-pull set.
            self._expected_blob_pulls.get(peer_fp, set()).discard(blob)
            self.blob_store.path(got_hash)  # confirms it lives
            try:
                self.state.record_blob(got_hash, ctx["received"])
            except Exception:
                pass
            n_files = self.folder_engine.materialize_after_blob_arrived(
                blob_hash=got_hash,
            )
            if self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "folder_synced",
                    "blob": got_hash,
                    "files": n_files,
                })
            log.info("blob received %s (%d files materialized)",
                     got_hash[:12], n_files)

    def _abort_blob(self, blob: str) -> None:
        ctx = self._incoming_blobs.pop(blob, None)
        if not ctx:
            return
        try:
            ctx["cm"].__exit__(None, None, None)
        except Exception:
            pass

    # ─── outbound to a peer ─────────────────────────────────────────────
    def _peer_fp_from_peer(self, peer: Peer) -> str | None:
        if not peer.ed_pub_hex:
            return None
        try:
            return fingerprint_of(bytes.fromhex(peer.ed_pub_hex))
        except ValueError:
            return None

    # ─── v0.5.1: rendezvous lifecycle + peer-endpoint resolution ───────
    async def _start_rendezvous(self, *, peer_port: int) -> None:
        """Start a RendezvousClient if URLs are configured. No-op
        otherwise. Failures are logged, not raised — the daemon must
        keep working LAN-only when rendezvous is unreachable.

        v0.5.4: First-run defaults — if no URLs are configured in
        state yet, harvest them from (in priority order):
          1. ONE_LINK_RDZ_DEFAULTS env var (comma-separated URLs)
          2. ~/.config/one-link/seeds.toml (or platform equivalent)
          3. The DEFAULT_RENDEZVOUS_URLS constant baked into the
             binary (empty by default; populated by distributors who
             want a zero-step out-of-box experience)
        These defaults are written to state.set_rendezvous_urls
        once on first run; user edits in Settings override.
        """
        if self.state is None:
            return
        self._rendezvous_peer_port = int(peer_port)
        try:
            urls = self.state.get_rendezvous_urls()
        except Exception as e:
            log.warning("could not read rendezvous URLs: %s", e)
            return
        if not urls:
            harvested = self._harvest_default_rendezvous_seeds()
            if harvested:
                try:
                    self.state.set_rendezvous_urls(harvested)
                    urls = self.state.get_rendezvous_urls()
                    log.info(
                        "first-run: adopted %d rendezvous default(s) %s",
                        len(urls), urls,
                    )
                except ValueError as e:
                    log.warning("default rendezvous seeds failed validation: %s", e)
        await self.update_rendezvous_urls(urls)

    def _maybe_inherit_rendezvous_from_mdns(self) -> None:
        """v0.5.4: opt-in household bootstrap from ambient LAN peers.

        If we currently have NO rendezvous URLs configured, harvest
        any URLs that LAN-discovered peers are advertising in their
        mDNS TXT records. Apply them via state.set_rendezvous_urls
        and trigger a live re-config.

        Guarded:
          - Disabled by default. Ambient mDNS is unauthenticated, so
            users must opt into this lower-trust bootstrap with
            `inherit_rendezvous_from_mdns=true`. Pinned CAPS inheritance
            remains the default zero-friction path for trusted peers.
          - Only runs when our list is empty. The user's first
            explicit `set_rendezvous_urls(...)` (UI save, API call,
            or a successful inherit) "claims" the slot and we stop
            doing this automatically.
          - Inheriting from mDNS is intentionally lower-trust than
            inheriting from a pinned peer's CAPS. We still validate
            URLs (http/https only) and cap by MAX_SHARED_RENDEZVOUS_URLS
            to defend against a malicious LAN actor flooding URLs.
          - Skipped entirely if `inherit_rendezvous` is set False.
        """
        if self.state is None or self.discovery is None:
            return
        try:
            mdns_v = self.state.get_setting("inherit_rendezvous_from_mdns")
            if mdns_v is None or mdns_v.lower() not in ("1", "true", "yes", "on"):
                return
            v = self.state.get_setting("inherit_rendezvous")
            if v is not None and v.lower() in ("0", "false", "no"):
                return
        except Exception:
            return
        try:
            existing = self.state.get_rendezvous_urls()
        except Exception:
            return
        if existing:
            return  # user has chosen — don't override

        candidates: set[str] = set()
        for p in self.discovery.registry.list():
            for u in (p.rendezvous_urls or []):
                u = u.strip().rstrip("/")
                if not (u.startswith("http://") or u.startswith("https://")):
                    continue
                candidates.add(u)
                if len(candidates) >= MAX_SHARED_RENDEZVOUS_URLS:
                    break
            if len(candidates) >= MAX_SHARED_RENDEZVOUS_URLS:
                break
        if not candidates:
            return
        urls = sorted(candidates)
        try:
            self.state.set_rendezvous_urls(urls)
        except ValueError:
            return
        log.info(
            "mDNS-inherited %d rendezvous url(s) from LAN peers: %s",
            len(urls), ", ".join(urls),
        )
        # Live re-config so we register with the inherited rendezvous
        # immediately; no daemon restart.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.update_rendezvous_urls(urls))
        except RuntimeError:
            pass
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "rendezvous_inherited",
                    "from_peer_fp": "lan-mdns",
                    "added": urls,
                })

    def _group_state_for(self, group_id: bytes):
        """Materialize a group's current signed event state from storage."""
        if self.state is None:
            return None
        try:
            from one_link import groups as gmod

            wire_events = self.state.list_group_events(group_id)
            if not wire_events:
                return None
            events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
            return gmod.reduce_events(events)
        except Exception as e:
            log.warning("could not reduce group %s: %s", group_id.hex()[:8], e)
            return None

    def _peer_is_current_group_member(self, group_id: bytes, peer_pub: bytes) -> bool:
        """True only when peer_pub is a member in the current group log."""
        gstate = self._group_state_for(group_id)
        return bool(gstate is not None and gstate.is_member(peer_pub))

    def _harvest_default_rendezvous_seeds(self) -> list[str]:
        """v0.5.4: Sources for first-run rendezvous URLs, in priority order.

        Tries env var first, then platform config seeds.toml, then a
        baked-in module constant. Returns a deduped list (possibly
        empty). Validation against http(s) prefix is left to
        state.set_rendezvous_urls.
        """
        out: list[str] = []
        seen: set[str] = set()

        def _add(u: str) -> None:
            u = u.strip().rstrip("/")
            if not u or u in seen:
                return
            seen.add(u)
            out.append(u)

        # 1. Env var.
        env = os.environ.get("ONE_LINK_RDZ_DEFAULTS", "")
        if env:
            for u in env.split(","):
                _add(u)

        # 2. seeds.toml in the data dir.
        seeds_path = data_dir() / "seeds.toml"
        if seeds_path.is_file():
            try:
                # Python 3.11+ has tomllib. Fall back gracefully if not.
                import tomllib  # type: ignore[import-not-found]
                with open(seeds_path, "rb") as fh:
                    doc = tomllib.load(fh)
                seeds = doc.get("rendezvous", {}).get("urls", [])
                if isinstance(seeds, list):
                    for u in seeds:
                        if isinstance(u, str):
                            _add(u)
            except Exception as e:
                log.warning("seeds.toml unreadable: %s", e)

        # 3. Baked-in defaults (empty by default; populated by builds
        #    that want zero-step out-of-the-box. See deploy/RENDEZVOUS_DEPLOY.md).
        from one_link import rendezvous_client as _rdz_client
        baked = getattr(_rdz_client, "DEFAULT_RENDEZVOUS_URLS", None)
        if isinstance(baked, list):
            for u in baked:
                if isinstance(u, str):
                    _add(u)

        return out

    def _inherit_rendezvous_urls_from(
        self, peer_fp: str, offered: list[str]
    ) -> None:
        """v0.5.4: Adopt rendezvous URLs that a pinned peer offered in
        their CAPS frame.

        Validation:
          - peer must be pinned (caller checks; defensive re-check)
          - URLs are sanitized via state.set_rendezvous_urls (rejects
            non-http(s), strips whitespace, dedupes)
          - the local `inherit_rendezvous` setting must not be False
            (default True; users can disable in settings)
          - capped at MAX_SHARED_RENDEZVOUS_URLS to defend against a
            malicious offered list
          - we mark the peer in `_inherited_rdz_from` so we don't
            spam-merge on every reconnect

        Side effect: if the merged URL set is different from what we
        had, schedule a live re-config of the rendezvous client (no
        restart needed) so the new URLs take effect immediately.
        """
        if self.state is None:
            return
        # Once-per-session guard: even if the caller forgot to check,
        # don't re-merge the same peer's offer twice.
        if peer_fp in self._inherited_rdz_from:
            return
        # User opt-out check.
        try:
            v = self.state.get_setting("inherit_rendezvous")
            if v is not None and v.lower() in ("0", "false", "no"):
                return
        except Exception:
            pass
        if not self._is_pinned(peer_fp):
            return

        # Merge.
        existing = set(self.state.get_rendezvous_urls())
        candidate = list(offered)[:MAX_SHARED_RENDEZVOUS_URLS]
        clean: set[str] = set(existing)
        added: list[str] = []
        for u in candidate:
            if not isinstance(u, str):
                continue
            u = u.strip().rstrip("/")
            if not (u.startswith("http://") or u.startswith("https://")):
                continue
            if u in clean:
                continue
            clean.add(u)
            added.append(u)

        self._inherited_rdz_from.add(peer_fp)
        if not added:
            return  # nothing new

        log.info(
            "inheriting %d rendezvous url(s) from peer %s: %s",
            len(added), peer_fp[:8], ", ".join(added),
        )
        try:
            self.state.set_rendezvous_urls(sorted(clean))
        except ValueError as e:
            log.warning("inherited urls failed validation: %s", e)
            return
        # Push the live re-config asynchronously so we don't block
        # the inbound peer-message handler — and so we don't try to
        # `await` from this sync helper.
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.update_rendezvous_urls(sorted(clean)))
        except RuntimeError:
            # Not in an event loop (shouldn't happen here, but be safe).
            pass
        # Tell the UI so the user sees "1 rendezvous URL adopted from <peer>".
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "rendezvous_inherited",
                    "from_peer_fp": peer_fp,
                    "added": added,
                })

    async def update_rendezvous_urls(self, urls: list[str]) -> None:
        """Live re-config — no daemon restart required.

        Stops any running rendezvous client (revoke + close), then
        starts a fresh one if `urls` is non-empty. Tolerant of partial
        failure: per-URL register issues are logged and the daemon
        keeps running. Empty list disables rendezvous entirely
        (LAN-only).

        v0.5.4: also re-broadcasts the new URL list via mDNS so other
        LAN daemons can auto-inherit. Honours the share_rendezvous
        opt-out.
        """
        # Tear down old client first.
        if self.rendezvous is not None:
            old = self.rendezvous
            self.rendezvous = None
            with contextlib.suppress(Exception):
                await old.stop()
        # v0.5.5: also tear down old relay listeners.
        for old_listener in list(self._relay_listener_clients):
            with contextlib.suppress(Exception):
                await old_listener.stop()
        self._relay_listener_clients.clear()

        # Update mDNS TXT to advertise (or stop advertising) these URLs.
        # The discovery instance might not be up yet during initial
        # _start_rendezvous; in that case its constructor receives the
        # URLs directly.
        if self.discovery is not None:
            share = True
            if self.state is not None:
                with contextlib.suppress(Exception):
                    v = self.state.get_setting("share_rendezvous")
                    share = v is None or v.lower() in ("1", "true", "yes")
            with contextlib.suppress(Exception):
                await self.discovery.update_rendezvous_urls(
                    urls if share else []
                )

        urls = [u for u in (urls or []) if u]
        if not urls:
            log.info("rendezvous: no URLs configured; LAN-only mode")
            return

        from one_link import rendezvous_client
        peer_port = getattr(self, "_rendezvous_peer_port", 0)
        try:
            advertise = rendezvous_client.discover_local_endpoints(peer_port=peer_port)
        except Exception as e:
            log.warning("rendezvous: failed to enumerate local endpoints: %s", e)
            advertise = []
        client = rendezvous_client.RendezvousClient(
            private_key=self.me.private,
            pubkey=self.me.public_bytes,
            rendezvous_urls=urls,
            advertise_endpoints=advertise,
            capabilities=list(CAPS_FEATURES),
        )
        try:
            await client.start()
        except Exception as e:
            log.warning("rendezvous: client.start failed: %s", e)
            return
        self.rendezvous = client
        log.info(
            "rendezvous: connected to %d endpoint(s); advertising %d local ip(s)",
            len(urls), len(advertise),
        )

        # v0.5.5: also fire up encrypted-relay listeners for each URL.
        # If the relay endpoint isn't enabled on a given rendezvous,
        # the listener client just retries-and-fails-quietly in its
        # own loop; no global breakage. Listeners are torn down by
        # the next call to update_rendezvous_urls or stop().
        from one_link.relay_client import RelayListenerClient
        for url in urls:
            listener = RelayListenerClient(
                rendezvous_url=url,
                private_key=self.me.private,
                pubkey=self.me.public_bytes,
                on_session=self._handle_relay_inbound_session,
            )
            try:
                await listener.start()
                self._relay_listener_clients.append(listener)
            except Exception as e:
                log.warning("relay listener for %s failed to start: %s", url, e)

        # Push a peers_changed notification so the UI re-fetches /api/rendezvous
        # status if it's open.
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({"type": "rendezvous_changed"})

    async def _handle_relay_inbound_session(
        self, reader, writer
    ) -> None:
        """v0.5.5: bridge a relay-tunneled inbound session into the
        existing peer-handler. The encrypted handshake +
        rate-limit + capability gates all run unchanged on top of
        the relay-streamed bytes — `_handle_peer` doesn't care
        whether the bytes came from a TCP socket or a WebSocket
        relay tunnel.

        v0.5.6: pass `regime="relay"` so the channel knows it came
        in over a relay tunnel; the regime is surfaced via /api/peers.
        """
        try:
            await self._handle_peer(reader, writer, regime="relay")
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def resolve_peer_endpoint(self, peer_fp: str) -> Peer | None:
        """Find a way to reach a paired peer. mDNS first (LAN), then
        the rendezvous (cross-internet). Returns None if no endpoint
        is currently known.

        The returned Peer is synthesized from the best-available data:
        if the peer is on mDNS we use that record; otherwise the
        rendezvous-observed public IP and port.
        """
        # mDNS path — current state already has the freshest LAN view.
        if self.discovery is not None:
            for p in self.discovery.registry.list():
                if not p.ed_pub_hex:
                    continue
                try:
                    if fingerprint_of(bytes.fromhex(p.ed_pub_hex)) == peer_fp:
                        return p
                except ValueError:
                    continue

        # Rendezvous fallback — only meaningful for paired peers since
        # we need their pubkey from the persistent DB.
        if self.rendezvous is None or self.state is None:
            return None
        rec = self.state.get_peer(peer_fp)
        if not rec or not rec.pubkey:
            return None
        try:
            ack = await self.rendezvous.lookup(rec.pubkey)
        except Exception as e:
            log.debug("rendezvous lookup for %s failed: %s", peer_fp[:8], e)
            return None
        if ack is None:
            return None

        # Pick the best endpoint to dial.
        #
        # Important correctness point: the rendezvous-observed `port`
        # is the source port of the peer's HTTP register request — NOT
        # the port their peer-server listens on. So `observed_endpoint`
        # gives us a reliable public *IP*, but its port is garbage for
        # establishing a peer connection. The peer's *advertised*
        # endpoints carry the real listening port.
        #
        # Strategy:
        #   1. Try advertised (LAN_IP, advertised_port) first — works if
        #      we share a network with the peer (rare for cross-internet,
        #      but free).
        #   2. Try (observed_public_IP, advertised_port) — this is the
        #      actual cross-internet candidate, valid as long as the
        #      peer's NAT preserves its outbound→inbound port mapping
        #      for the listener (true for most cone NATs, fails on
        #      symmetric NATs — the v0.5.3 relay path catches those).
        candidates: list[tuple[str, int]] = []
        observed_host: str | None = (
            ack.observed_endpoint.host if ack.observed_endpoint else None
        )
        for e in ack.advertised_endpoints:
            if e.port <= 0:
                continue
            candidates.append((e.host, e.port))
            if observed_host and observed_host != e.host:
                candidates.append((observed_host, e.port))
        if not candidates:
            return None
        host, port = candidates[0]
        return Peer(
            short_id=rec.short_id,
            hostname=rec.hostname or rec.short_id,
            address=host,
            port=int(port),
            ed_pub_hex=rec.pubkey.hex(),
        )

    # ─── v0.5.2: happy-eyeballs multi-endpoint dial ─────────────────
    HAPPY_EYEBALLS_TIMEOUT_S = 5.0
    HAPPY_EYEBALLS_STAGGER_S = 0.25  # delay between staggered starts

    async def _collect_dial_candidates(
        self, peer: Peer
    ) -> list[tuple[str, int]]:
        """All (host, port) pairs we'd consider dialing for this peer.

        Starts with the primary `peer.address:peer.port` (current LAN /
        mDNS view), then appends rendezvous-known endpoints if we have
        a rendezvous client and the peer's pubkey resolves there.
        Duplicates are removed in-order.
        """
        seen: set[tuple[str, int]] = set()
        out: list[tuple[str, int]] = []

        def _add(host: str | None, port: int | None) -> None:
            if not host or not port:
                return
            key = (host, int(port))
            if key in seen:
                return
            seen.add(key)
            out.append(key)

        _add(peer.address, peer.port)

        if self.rendezvous is None or not peer.ed_pub_hex:
            return out
        try:
            pub = bytes.fromhex(peer.ed_pub_hex)
        except ValueError:
            return out
        try:
            ack = await self.rendezvous.lookup(pub)
        except Exception:
            return out
        if ack is None:
            return out
        # See the priority note in `resolve_peer_endpoint`: the
        # observed_endpoint.port is garbage for dial — we only use
        # observed.host paired with each advertised.port.
        observed_host = (
            ack.observed_endpoint.host if ack.observed_endpoint else None
        )
        for e in ack.advertised_endpoints:
            if e.port <= 0:
                continue
            _add(e.host, e.port)
            if observed_host and observed_host != e.host:
                _add(observed_host, e.port)
        return out

    async def _dial_first_responsive(
        self,
        candidates: list[tuple[str, int]],
        *,
        timeout: float | None = None,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, tuple[str, int]]:
        """Open TCP connections to each candidate in parallel with a
        small stagger; return the first that succeeds + the
        (host, port) it connected to. Cancels and closes the rest.

        Raises OSError on full failure (mirrors asyncio.open_connection).
        """
        if not candidates:
            raise OSError("no candidates to dial")
        deadline = self.HAPPY_EYEBALLS_TIMEOUT_S if timeout is None else float(timeout)

        async def _attempt(host_port: tuple[str, int], delay: float):
            if delay > 0:
                await asyncio.sleep(delay)
            host, port = host_port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=deadline
            )
            return reader, writer, host_port

        tasks = [
            asyncio.create_task(_attempt(c, i * self.HAPPY_EYEBALLS_STAGGER_S))
            for i, c in enumerate(candidates)
        ]
        pending: set[asyncio.Task] = set(tasks)
        winner: tuple | None = None
        try:
            while pending and winner is None:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    if t.cancelled():
                        continue
                    if t.exception() is not None:
                        continue
                    if winner is None:
                        winner = t.result()
                    else:
                        # Two completed in the same iteration — close the
                        # extra successful connection.
                        _r, w, _hp = t.result()
                        w.close()
                        with contextlib.suppress(BaseException):
                            await w.wait_closed()
        finally:
            # Cancel anything still in-flight, drain. We don't await
            # the cancellation indefinitely: on Windows, an in-flight
            # `open_connection` against a non-listening port can take
            # multiple seconds to acknowledge a cancel because the
            # SYN retry runs in the OS network stack outside our
            # control. Best-effort drain with a short cap is fine —
            # the kernel will close the half-open sockets eventually.
            for t in pending:
                t.cancel()
            if pending:
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(
                        asyncio.gather(*pending, return_exceptions=True),
                        timeout=0.5,
                    )
            # Close any sockets from late-completing losers (those that
            # finished after `winner` was set but their task wasn't
            # observed in the same `done` set).
            winner_writer = winner[1] if winner is not None else None
            for t in tasks:
                if not t.done() or t.cancelled():
                    continue
                if t.exception() is not None:
                    continue
                _r, w, _hp = t.result()
                if w is winner_writer:
                    continue
                w.close()
                with contextlib.suppress(BaseException):
                    await w.wait_closed()
        if winner is None:
            raise OSError(f"all candidates failed: {candidates}")
        return winner

    async def _dial_peer(
        self, peer: Peer, *, timeout: float | None = None
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Connect to a peer; backwards-compat shim that drops regime."""
        reader, writer, _regime = await self._dial_peer_with_regime(
            peer, timeout=timeout
        )
        return reader, writer

    async def _dial_peer_with_regime(
        self, peer: Peer, *, timeout: float | None = None
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, str]:
        """Connect to a peer using all known endpoints in parallel,
        and report which transport regime won. Regime is one of:
          - "lan":      direct TCP to a private/loopback/link-local address
          - "internet": direct TCP to a public address
          - "relay":    encrypted relay fallback (v0.5.5)

        Falls back to relay when direct dial fails entirely AND a
        rendezvous client is configured AND the peer has an ed_pub_hex.
        """
        candidates = await self._collect_dial_candidates(peer)
        direct_err: BaseException | None = None
        if candidates:
            try:
                if len(candidates) == 1:
                    host, port = candidates[0]
                    reader, writer = await asyncio.open_connection(host, port)
                    return reader, writer, _classify_address_regime(host)
                reader, writer, winning = await self._dial_first_responsive(
                    candidates, timeout=timeout
                )
                return reader, writer, _classify_address_regime(winning[0])
            except (OSError, asyncio.TimeoutError) as e:
                direct_err = e

        # Fall through to relay if available.
        relay_triple = await self._dial_via_relay(peer)
        if relay_triple is not None:
            reader, writer, pump = relay_triple
            # Stash pump task on the writer so the OutboundSession
            # creator can attach it (see _get_outbound_session).
            setattr(writer, "_relay_pump_task", pump)
            return reader, writer, "relay"

        if direct_err is not None:
            raise direct_err
        raise OSError(f"peer {peer.short_id} has no dialable endpoints")

    async def _dial_via_relay(
        self, peer: Peer
    ) -> tuple[object, object, asyncio.Task] | None:
        """v0.5.5: open an encrypted-relay session targeting the
        peer's pubkey. Returns a (reader, writer, pump_task) triple,
        or None if no relay is available / peer can't be addressed
        via relay.

        Tries each configured rendezvous URL in order; the first
        whose listener slot for the peer's pubkey is occupied wins.

        Audit fix (v0.6.1+): the pump task that drains the relay
        WS into the reader is returned so the caller can attach it
        to the OutboundSession lifecycle. Without this the per-call
        aiohttp ClientSession leaks if the daemon stops before the
        pump's finally block runs to completion.
        """
        if not self._relay_listener_clients:
            return None
        if not peer.ed_pub_hex:
            return None
        try:
            dst_pubkey = bytes.fromhex(peer.ed_pub_hex)
        except ValueError:
            return None
        if len(dst_pubkey) != 32:
            return None
        from one_link.relay_client import open_relay_outbound

        # Route through the rendezvous client's daemon-lifetime aiohttp
        # session if available. Avoids per-dial session leaks under
        # cancellation races at test/daemon teardown.
        shared_session = (
            self.rendezvous.session
            if self.rendezvous is not None
            else None
        )

        for listener in list(self._relay_listener_clients):
            url = listener._rendezvous_url  # type: ignore[attr-defined]
            try:
                reader, writer, pump = await open_relay_outbound(
                    url, dst_pubkey, session=shared_session,
                )
                log.info(
                    "relay dial succeeded for %s via %s",
                    peer.short_id, url,
                )
                return reader, writer, pump
            except Exception as e:
                log.debug("relay dial via %s failed: %s", url, e)
                continue
        return None

    def _valid_blob_hex(self, blob: str) -> bool:
        if len(blob) != 64:
            return False
        try:
            int(blob, 16)
            return True
        except ValueError:
            return False

    def _abort_incoming_file(self, blob: str, f: IncomingFile) -> None:
        with contextlib.suppress(Exception):
            f.handle.close()
        self._incoming_files.pop(blob, None)
        with contextlib.suppress(OSError):
            f.out_path.unlink()
        self._update_transfer(f.transfer_id, status="failed")

    def _inbound_is_rejected(self, peer_fp: str) -> bool:
        """Returns True if the peer is on our local rejection list.

        The legacy name `_check_inbound_trust` was preserved as a thin alias
        for back-compat with any external callers; new code should use this
        explicitly-named version.
        """
        if self.state is None:
            return False
        rec = self.state.get_peer(peer_fp)
        return bool(rec and rec.trust == "rejected")

    # Back-compat alias. New call sites should use _inbound_is_rejected.
    _check_inbound_trust = _inbound_is_rejected

    def _verify_channel_peer(self, peer: Peer, channel: ch.Channel) -> str:
        actual_fp = fingerprint_of(channel.peer_ed_pub)
        if peer.ed_pub_hex:
            try:
                expected_pub = bytes.fromhex(peer.ed_pub_hex)
            except ValueError as e:
                raise RuntimeError(f"peer {peer.short_id} advertised invalid pubkey") from e
            expected_fp = fingerprint_of(expected_pub)
            if channel.peer_ed_pub != expected_pub:
                raise RuntimeError(
                    "peer identity mismatch: expected full fingerprint "
                    f"{expected_fp}, got {actual_fp}"
                )
            return actual_fp
        if channel.peer_short_id != peer.short_id:
            raise RuntimeError(
                f"peer fingerprint mismatch: expected short id {peer.short_id}, "
                f"got {channel.peer_short_id}"
            )
        return actual_fp

    def _check_outbound_trust(self, peer: Peer) -> str | None:
        """Returns None if outbound is allowed; otherwise an error string."""
        if self.state is None:
            return None
        fp = self._peer_fp_from_peer(peer)
        if not fp:
            return None
        rec = self.state.get_peer(fp)
        if rec and rec.trust == "rejected":
            return f"peer {peer.short_id} is marked as rejected; cannot send"
        return None

    def _capability_allowed(self, peer_fp: str, cap: str) -> bool:
        if self.state is None:
            return True
        policy = self.state.get_peer_capability_policy(peer_fp)
        return policy is None or cap in policy

    def _apply_default_capability_policy(self, peer_fp: str) -> None:
        """v0.7.3: at SAS-pair finalize, the per-peer policy default
        is driven by the `pair_default_allow_all` setting.

          - True (default in v0.7.3+): leave policy = None.
            policy=None means legacy allow-all — every advertised
            capability flows. Aligns with the user mental model
            "I just SAS-verified this device, of course I trust it."
          - False: install [CHAT] only (the v0.7.2 audit-finding-A
            deny-by-default for files/folders/groups).

        Either way, the user can still flip individual caps in the
        per-device drawer — this only sets the initial state."""
        if self.state is None:
            return
        existing = self.state.get_peer_capability_policy(peer_fp)
        if existing is not None:
            return
        try:
            v = self.state.get_setting("pair_default_allow_all")
            allow_all = v is None or v.lower() in ("1", "true", "yes")
        except Exception:
            allow_all = True
        if allow_all:
            return  # leave policy = None (legacy allow-all semantics)
        from one_link.capabilities import DEFAULT_ALLOW_AFTER_PAIRING
        with contextlib.suppress(Exception):
            self.state.set_peer_capability_policy(
                peer_fp,
                list(DEFAULT_ALLOW_AFTER_PAIRING),
                actor="pairing",
                note="deny-by-default on first pair",
            )

    def _emit_capability_request(
        self, peer_fp: str, peer_sid: str, cap: str,
    ) -> None:
        """v0.7.1: notify UI that a peer is asking for a capability
        the user hasn't granted. Rate-limited per (fp, cap) so a
        peer hammering offer-retries can't spam the UI. The user
        responds via POST /api/peers/{fp}/capabilities/grant."""
        if self.ui_server is None:
            return
        now = time.monotonic()
        key = (peer_fp, cap)
        last = self._capability_request_seen.get(key, 0.0)
        if now - last < CAPABILITY_REQUEST_DEDUP_S:
            return
        self._capability_request_seen[key] = now
        with contextlib.suppress(Exception):
            self.ui_server.broadcast({
                "type": "capability_request",
                "fingerprint": peer_fp,
                "short_id": peer_sid,
                "capability": cap,
                "ts_ms": int(time.time() * 1000),
            })

    def _session_stats(self) -> dict:
        now = time.time()
        return {
            "open": len(self._outbound_sessions),
            "idle_timeout_s": OUTBOUND_SESSION_IDLE_S,
            "sessions": [
                {
                    "peer": s.peer.short_id,
                    "peer_fp": s.peer_fp,
                    "idle_s": round(now - s.last_used, 3),
                    "messages_sent": s.messages_sent,
                }
                for s in self._outbound_sessions.values()
            ],
        }

    async def _drop_outbound_session(self, peer_fp: str) -> None:
        sess = self._outbound_sessions.pop(peer_fp, None)
        if sess is None:
            return
        with contextlib.suppress(Exception):
            await sess.channel.close()
        # Audit fix: if this was a relay-tunneled session, the inbound
        # pump task owns an aiohttp ClientSession that must flush+close
        # before the event loop tears down. Channel.close() triggers
        # the WS close cascade via _RelayStreamWriter._on_close, which
        # ends the pump's `async for msg in ws`. We give it a bounded
        # window to drain its finally block; if it doesn't, cancel.
        pump = sess.relay_pump_task
        if pump is not None and not pump.done():
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(pump, timeout=2.0)
            if not pump.done():
                pump.cancel()
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(pump, timeout=0.5)

    async def _probe_outbound_session(self, sess: OutboundSession) -> bool:
        """H4: send a PING and wait briefly for a PONG. Returns True if the
        session is still alive, False if it timed out or errored. Ignores
        any non-PONG frames that arrive in the meantime (e.g. CAPS), as the
        server may push them eagerly.

        v0.7.0: also stamps the round-trip latency into pair health so the
        UI can show "32ms" or whatever instead of guessing from regime."""
        try:
            async with sess.lock:
                ping_at = time.monotonic()
                await sess.channel.send(encode_msg(make_msg("PING", self.me.short_id)))
                deadline = ping_at + OUTBOUND_SESSION_PING_DEADLINE_S
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return False
                    plaintext = await asyncio.wait_for(
                        sess.channel.recv(), timeout=remaining
                    )
                    reply = decode_msg(plaintext)
                    rt = reply.get("t")
                    if rt == "PONG":
                        sess.last_used = time.time()
                        latency_ms = (time.monotonic() - ping_at) * 1000.0
                        self._stamp_pair_health(
                            sess.peer_fp, latency_ms=latency_ms,
                        )
                        return True
                    if rt == "CAPS":
                        features = list(normalize_caps(reply.get("features", [])))
                        sess.channel.peer_caps = {
                            "protocol": reply.get("protocol", "?"),
                            "features": features,
                            "from": reply.get("from"),
                            "app_version": reply.get("app_version"),
                        }
                        if self.state is not None:
                            with contextlib.suppress(Exception):
                                self.state.set_peer_capabilities(sess.peer_fp, features)
                        continue
                    # Anything else mid-probe is unexpected for an idle
                    # session — treat as dead to be safe.
                    return False
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return False
        except Exception:
            return False

    async def _get_outbound_session(self, peer: Peer) -> OutboundSession:
        peer_fp = self._peer_fp_from_peer(peer)
        if not peer_fp:
            raise RuntimeError("peer has no verifiable public key for persistent session")
        existing = self._outbound_sessions.get(peer_fp)
        now = time.time()
        if existing and now - existing.last_used <= OUTBOUND_SESSION_IDLE_S:
            idle = now - existing.last_used
            if idle <= OUTBOUND_SESSION_PING_AFTER_S:
                return existing
            if await self._probe_outbound_session(existing):
                return existing
            log.info(
                "outbound session probe failed for %s — reopening",
                peer.short_id,
            )
        await self._drop_outbound_session(peer_fp)

        reader, writer, regime = await self._dial_peer_with_regime(peer)
        # Audit fix: when the regime is "relay", _dial_peer_with_regime
        # stashes the inbound-pump task on the writer for cleanup.
        relay_pump = getattr(writer, "_relay_pump_task", None)
        try:
            try:
                channel = await asyncio.wait_for(
                    ch.initiate(reader, writer, self.me),
                    timeout=HANDSHAKE_DEADLINE_OUTBOUND_S,
                )
            except asyncio.TimeoutError as e:
                raise RuntimeError(
                    f"session open to {peer.short_id}: handshake timed out "
                    f"after {HANDSHAKE_DEADLINE_OUTBOUND_S}s — peer not responsive"
                ) from e
            actual_fp = self._verify_channel_peer(peer, channel)
            if actual_fp != peer_fp:
                raise RuntimeError("peer fingerprint changed while opening session")
            if self.state is not None:
                with contextlib.suppress(Exception):
                    self.state.upsert_peer(
                        fingerprint=peer_fp,
                        short_id=channel.peer_short_id,
                        pubkey=channel.peer_ed_pub,
                        hostname=peer.hostname,
                        address=peer.address,
                        port=peer.port,
                    )
            await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
            sess = OutboundSession(
                peer_fp=peer_fp,
                peer=peer,
                channel=channel,
                lock=asyncio.Lock(),
                last_used=now,
                regime=regime,
                relay_pump_task=relay_pump,
            )
            self._outbound_sessions[peer_fp] = sess
            # v0.7.1: a fresh session means the peer just came back
            # online (or we just dialed them for the first time
            # this session). Schedule any pending outbox messages
            # for delivery in the background — the caller doesn't
            # block on the flush.
            self._schedule_outbox_flush(peer_fp)
            return sess
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise

    async def send_to(self, peer: Peer, msgs: list[dict]) -> list[dict]:
        """Send chat/control messages over a reusable encrypted session."""
        block = self._check_outbound_trust(peer)
        if block:
            raise RuntimeError(block)
        peer_fp = self._peer_fp_from_peer(peer)
        if peer_fp and not self._capability_allowed(peer_fp, CHAT):
            raise RuntimeError(f"chat capability disabled for peer {peer.short_id}")
        sess = await self._get_outbound_session(peer)
        try:
            async with sess.lock:
                results: list[dict] = []
                for m in msgs:
                    await sess.channel.send(encode_msg(m))
                    while True:
                        ack = decode_msg(await sess.channel.recv())
                        if ack.get("t") == "CAPS":
                            features = list(normalize_caps(ack.get("features", [])))
                            sess.channel.peer_caps = {
                                "protocol": ack.get("protocol", "?"),
                                "features": features,
                                "from": ack.get("from"),
                                "app_version": ack.get("app_version"),
                            }
                            if self.state is not None:
                                with contextlib.suppress(Exception):
                                    self.state.set_peer_capabilities(sess.peer_fp, features)
                            continue
                        break
                    if ack.get("rejected"):
                        raise RuntimeError(str(ack.get("rejected")))
                    results.append(ack)
                    sess.messages_sent += 1
                    sess.last_used = time.time()
                    # v0.6.2: group-protocol frames (GROUP_*) are not chat
                    # messages — they're transport-layer envelopes carrying
                    # encrypted multi-recipient payloads. Skip the regular
                    # message-log persist + UI broadcast so they don't
                    # clutter the 1-on-1 chat history. The receiver-side
                    # _handle_group_msg persists the decrypted plaintext
                    # into the dedicated group_messages table.
                    if not m.get("t", "").startswith("GROUP_"):
                        ev = self._persist(
                            msg=m, direction="out", peer_fp=sess.peer_fp,
                            peer_short_id=peer.short_id,
                        )
                        self._broadcast_tail(ev)
                return results
        except Exception:
            await self._drop_outbound_session(sess.peer_fp)
            raise

    async def _send_control(self, peer: Peer, msg: dict) -> None:
        """Open a one-shot connection, send a single control msg, wait for
        ACK, close cleanly. Waiting for the ACK forces the receiver to fully
        process the message before our close — avoids Win10053 abort races."""
        reader, writer = await self._dial_peer(peer)
        try:
            channel = await ch.initiate(reader, writer, self.me)
            self._verify_channel_peer(peer, channel)
            try:
                await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
            except Exception:
                pass
            await channel.send(encode_msg(msg))
            # Wait for ACK (skipping any peer-CAPS that arrives interleaved)
            try:
                while True:
                    ack = decode_msg(await asyncio.wait_for(channel.recv(), timeout=5.0))
                    if ack.get("t") == "CAPS":
                        features = list(normalize_caps(ack.get("features", [])))
                        channel.peer_caps = {
                            "protocol": ack.get("protocol", "?"),
                            "features": features,
                            "from": ack.get("from"),
                            "app_version": ack.get("app_version"),
                        }
                        if self.state is not None:
                            with contextlib.suppress(Exception):
                                fp = self._peer_fp_from_peer(peer)
                                if fp:
                                    self.state.set_peer_capabilities(fp, features)
                        continue
                    if ack.get("t") == "ACK":
                        break
                    # Unknown response type — break, message was sent
                    break
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                # Peer didn't ACK in time; the message was still transmitted
                # but the peer may have closed early. Acceptable for control.
                pass
            await channel.close()
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise

    async def initiate_pair(self, peer: Peer) -> str:
        """Start pairing with peer. Returns the SAS to display in our UI."""
        peer_fp = self._peer_fp_from_peer(peer) or fingerprint_of(
            bytes.fromhex(peer.ed_pub_hex)
        )
        sas = compute_sas(
            self.me.public_bytes, bytes.fromhex(peer.ed_pub_hex)
        )
        existing = self.pairing.get(peer_fp)
        if existing is None or existing.state in (
            PairState.NONE, PairState.PAIRED, PairState.REJECTED
        ):
            self.pairing.begin(peer_fp=peer_fp, sas=sas, incoming=False)
        # Make sure the peer DB has a row so trust changes can attach later
        if self.state is not None:
            self.state.upsert_peer(
                fingerprint=peer_fp,
                short_id=peer.short_id,
                pubkey=bytes.fromhex(peer.ed_pub_hex),
                hostname=peer.hostname,
                address=peer.address,
                port=peer.port,
            )
        await self._send_control(
            peer, make_msg("PAIR_REQUEST", self.me.short_id),
        )
        return sas

    async def confirm_pair(self, peer: Peer) -> dict:
        """User confirms the SAS matched. Send PAIR_CONFIRM; if peer also
        confirmed already, both sides become paired now."""
        peer_fp = self._peer_fp_from_peer(peer) or fingerprint_of(
            bytes.fromhex(peer.ed_pub_hex)
        )
        # Be defensive: ensure peer exists in state DB so set_peer_trust works.
        if self.state is not None:
            try:
                self.state.upsert_peer(
                    fingerprint=peer_fp,
                    short_id=peer.short_id,
                    pubkey=bytes.fromhex(peer.ed_pub_hex),
                    hostname=peer.hostname,
                    address=peer.address,
                    port=peer.port,
                )
            except Exception:
                pass

        ctx = self.pairing.we_confirm(peer_fp)
        if ctx is None:
            # No ctx — could be the case where we receive PAIR_REQUEST after
            # we already pressed confirm. Begin one and mark we_confirmed.
            sas = compute_sas(
                self.me.public_bytes, bytes.fromhex(peer.ed_pub_hex)
            )
            ctx = self.pairing.begin(peer_fp=peer_fp, sas=sas, incoming=False)
            ctx = self.pairing.we_confirm(peer_fp)

        await self._send_control(
            peer, make_msg("PAIR_CONFIRM", self.me.short_id),
        )
        # Re-check after the await — they_confirmed might have flipped
        # while _send_control was running and yielding to the event loop.
        ctx = self.pairing.get(peer_fp) or ctx
        if ctx and ctx.both_confirmed and self.state is not None:
            self.state.set_peer_trust(peer_fp, "pinned", actor="pairing")
            self._apply_default_capability_policy(peer_fp)
            if self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "peer_trust", "fingerprint": peer_fp, "trust": "pinned",
                })
            log.info("paired with %s via confirm_pair", peer.short_id)
        else:
            log.info(
                "confirm_pair: still waiting for peer (we=%s they=%s)",
                ctx.we_confirmed if ctx else "?",
                ctx.they_confirmed if ctx else "?",
            )
        return {
            "state": ctx.state.value if ctx else "unknown",
            "both_confirmed": bool(ctx and ctx.both_confirmed),
        }

    # ─── groups (v0.6.2) ───────────────────────────────────────────

    # ─── v0.7.0: Linked Mesh ──────────────────────────────────────

    MAX_ENDPOINTS_PER_ANNOUNCEMENT = 8

    def _stamp_pair_health(
        self,
        peer_fp: str,
        *,
        latency_ms: float | None = None,
    ) -> None:
        """v0.7.0: record liveness for this peer. Latency is EWMA'd
        when provided (alpha=0.3 — fast enough to track real changes,
        slow enough to ignore single-packet jitter)."""
        if not peer_fp:
            return
        now_ms = int(time.time() * 1000)
        h = self._pair_health.get(peer_fp)
        if h is None:
            h = {"last_alive_ms": now_ms, "latency_ewma_ms": float("nan")}
            self._pair_health[peer_fp] = h
        else:
            h["last_alive_ms"] = now_ms
        if latency_ms is not None:
            prev = h.get("latency_ewma_ms")
            if prev is None or prev != prev:  # NaN check
                h["latency_ewma_ms"] = float(latency_ms)
            else:
                h["latency_ewma_ms"] = 0.7 * prev + 0.3 * float(latency_ms)

    def get_pair_health(self, peer_fp: str) -> dict | None:
        """Public read for /api/peers."""
        h = self._pair_health.get(peer_fp)
        if h is None:
            return None
        return dict(h)

    async def revoke_peer(
        self, peer_fp: str, *, actor: str = "ui", note: str = "",
    ) -> None:
        """v0.7.0: trust=rejected becomes a unified tear-down.

        Today, set_peer_trust(rejected) just flips the DB field — but
        the persistent session can keep running until idle timeout,
        in-flight transfers can complete, and group sender chains
        stay valid. That leaves a window where a "rejected" peer can
        still drive state into our daemon.

        This method does the full revocation in one transaction:
          1. Set trust = rejected (audited)
          2. Drop outbound session (cuts active channel)
          3. Mark any in-flight transfer to/from this peer as failed
          4. Clear group sender chains keyed by this peer's pubkey
          5. Broadcast peer_trust event so UI updates immediately

        Idempotent: safe to call on a peer that's already rejected.
        """
        if self.state is None:
            return
        rec = self.state.get_peer(peer_fp)
        if rec is None:
            return
        # Step 1.
        try:
            self.state.set_peer_trust(peer_fp, "rejected", actor=actor, note=note)
        except Exception as e:
            log.warning("revoke_peer set_peer_trust failed: %s", e)
        # Step 2.
        with contextlib.suppress(Exception):
            await self._drop_outbound_session(peer_fp)
        # Step 3.
        try:
            transfers = self.state.list_transfers(peer_fp=peer_fp, limit=200)
        except Exception:
            transfers = []
        for t in transfers:
            if t.status in ("offered", "active", "queued"):
                with contextlib.suppress(Exception):
                    self._update_transfer(
                        t.id,
                        status="failed",
                        metadata={
                            **t.metadata,
                            "error": "peer revoked",
                            "error_class": "PeerRevoked",
                        },
                    )
        # Step 4: clear group sender chains for this peer's pubkey.
        # The pubkey is on the peer record; chains are keyed by it.
        if rec.pubkey:
            try:
                with self.state._write_lock:
                    self.state._conn.execute(
                        "DELETE FROM group_sender_chains WHERE sender_pub = ?",
                        (rec.pubkey,),
                    )
            except Exception as e:
                log.debug("clearing group chains for revoked peer failed: %s", e)
        # v0.7.1: drop any queued outbox messages for the revoked
        # peer. We're not delivering messages to a peer the user
        # no longer trusts.
        try:
            self.state.clear_outbox_for_peer(peer_fp)
        except Exception as e:
            log.debug("clearing outbox for revoked peer failed: %s", e)
        # Step 5.
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "peer_trust",
                    "fingerprint": peer_fp,
                    "trust": "rejected",
                })
        log.info(
            "peer revoked: %s (%d transfers cancelled, group chains cleared)",
            peer_fp[:8],
            sum(1 for t in transfers if t.status in ("offered", "active", "queued")),
        )

    async def _handle_endpoint_update(
        self, channel: ch.Channel, msg: dict, peer_fp: str, peer_sid: str,
    ) -> None:
        """A pinned peer is telling us their current endpoint(s).

        v0.7.0: paired peers act as one — once we trust each other,
        endpoint changes (Wi-Fi roam, daemon restart, NAT remap) get
        pushed proactively over the existing encrypted channel. The
        receiver updates `state.peers.last_address/last_port` with the
        first reachable advertised endpoint, so the next outbound
        send_to has the freshest address — no failed-dial-then-retry
        dance.

        Trust gate: only pinned peers can update our peer record.
        AEAD already authenticates the sender (this frame rode an
        encrypted channel keyed to their pubkey), so we don't need a
        second signature layer here; rejection of unpinned suffices.
        """
        if not self._is_pinned(peer_fp):
            log.info(
                "ENDPOINT_UPDATE from non-pinned peer dropped: %s", peer_fp[:8]
            )
            return
        if self.state is None:
            return
        endpoints = msg.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            log.warning("ENDPOINT_UPDATE with empty endpoints from %s", peer_sid)
            return
        # Cap at MAX_ENDPOINTS_PER_ANNOUNCEMENT to defend against a
        # malicious peer flooding us with junk addresses.
        endpoints = endpoints[: self.MAX_ENDPOINTS_PER_ANNOUNCEMENT]
        cleaned: list[tuple[str, int]] = []
        for e in endpoints:
            if not isinstance(e, dict):
                continue
            host = e.get("host")
            port = e.get("port")
            if not isinstance(host, str) or not host:
                continue
            if not isinstance(port, int) or not (0 < port < 65536):
                continue
            cleaned.append((host, port))
        if not cleaned:
            return
        # Pick the most-likely-reachable endpoint:
        #   1) any non-LAN public IP if our connection is internet
        #   2) otherwise the first private one (LAN)
        # If we currently have a session over a private IP and the
        # peer announces a public one, prefer the LAN one — same Wi-Fi
        # is fastest. The send-path's happy-eyeballs falls through if
        # the picked one is wrong.
        for host, port in cleaned:
            task = asyncio.create_task(
                self._verify_and_promote_endpoint(peer_fp, peer_sid, host, port)
            )
            self._endpoint_verify_tasks.add(task)
            task.add_done_callback(self._endpoint_verify_tasks.discard)
        log.info(
            "ENDPOINT_UPDATE queued %d route verification(s) from %s",
            len(cleaned), peer_sid,
        )
        # ACK so the sender's send_to() succeeds.
        await channel.send(encode_msg(make_msg(
            "ACK", self.me.short_id, of=msg.get("id"),
        )))

    async def _verify_and_promote_endpoint(
        self, peer_fp: str, peer_sid: str, host: str, port: int,
    ) -> None:
        """Promote an announced endpoint only after key-confirmed dial."""
        if self.state is None or not self._is_pinned(peer_fp):
            return
        try:
            rec = self.state.get_peer(peer_fp)
        except Exception:
            rec = None
        if rec is None or not rec.pubkey:
            return
        writer = None
        channel = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            channel = await asyncio.wait_for(
                ch.initiate(reader, writer, self.me), timeout=3.0
            )
            got_fp = fingerprint_of(channel.peer_ed_pub)
            if got_fp != peer_fp:
                log.warning(
                    "ENDPOINT_UPDATE verification rejected %s:%d for %s: got %s",
                    host, port, peer_fp[:8], got_fp[:8],
                )
                return
            self.state.upsert_peer(
                fingerprint=peer_fp,
                short_id=rec.short_id,
                pubkey=rec.pubkey,
                hostname=rec.hostname,
                address=host,
                port=port,
            )
            log.info(
                "ENDPOINT_UPDATE promoted verified route for %s: %s:%d",
                peer_sid, host, port,
            )
        except Exception as e:
            log.debug(
                "ENDPOINT_UPDATE candidate failed verification for %s at %s:%d: %s",
                peer_fp[:8], host, port, e,
            )
        finally:
            if channel is not None:
                with contextlib.suppress(Exception):
                    await channel.close()
            elif writer is not None:
                with contextlib.suppress(Exception):
                    writer.close()
                    await writer.wait_closed()

    async def broadcast_endpoint_to_paired(self) -> int:
        """v0.7.0: tell every pinned peer where to find us right now.

        Called on daemon start (so peers learn our potentially-new
        port immediately) and live-on-changes (TODO: hook into Wi-Fi
        change events in v0.7.x). Best-effort — peers we can't
        currently reach are skipped; they'll learn on next
        re-pair-time inheritance or by mDNS / rendezvous when they
        come back online.

        Returns the count of peers we successfully reached.
        """
        if self.state is None:
            return 0
        try:
            peers = self.state.list_peers()
        except Exception:
            return 0
        # Build the announcement payload using whatever we know about
        # our local addresses. Prefer the daemon's actual peer-server
        # port; the rendezvous client already has the discover-local
        # logic, reuse it to avoid divergence.
        from one_link import rendezvous_client
        peer_port = getattr(self, "_rendezvous_peer_port", 0)
        if peer_port <= 0:
            return 0
        try:
            local_endpoints = rendezvous_client.discover_local_endpoints(
                peer_port=peer_port
            )
        except Exception as e:
            log.debug("could not enumerate local endpoints: %s", e)
            return 0
        if not local_endpoints:
            return 0
        endpoint_dicts = [
            {"host": e.host, "port": e.port}
            for e in local_endpoints[: self.MAX_ENDPOINTS_PER_ANNOUNCEMENT]
        ]
        delivered = 0
        for rec in peers:
            if rec.trust != "pinned":
                continue
            if rec.fingerprint == self.me.fingerprint:
                continue
            try:
                peer_obj = await self.resolve_for_send(rec.fingerprint)
                if peer_obj is None:
                    continue
                outer = make_msg(
                    "ENDPOINT_UPDATE", self.me.short_id,
                    endpoints=endpoint_dicts,
                )
                # Best-effort. resolve_for_send + send_to do the right
                # thing: open or reuse a session, send through it,
                # await the ACK with the same backoff/timeouts the
                # rest of the daemon uses.
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(
                        self.send_to(peer_obj, [outer]),
                        timeout=10.0,
                    )
                    delivered += 1
            except Exception as e:
                log.debug(
                    "endpoint announcement to %s failed: %s",
                    rec.fingerprint[:8], e,
                )
        if delivered:
            log.info(
                "endpoint announcements: delivered to %d/%d pinned peer(s)",
                delivered, sum(1 for r in peers if r.trust == "pinned"),
            )
        return delivered

    async def _handle_group_key_offer(
        self, channel: ch.Channel, msg: dict, peer_fp: str,
    ) -> None:
        """A pinned peer is sharing their sender chain for a group
        we both belong to. Validate + persist. Idempotent on retransmit
        (same group_id + sender + epoch overwrites only if newer
        chain_key — receiver's existing chain_key may have advanced
        past the offered one).
        """
        if not self._is_pinned(peer_fp):
            log.info("GROUP_KEY_OFFER from non-pinned peer dropped: %s", peer_fp[:8])
            return
        if self.state is None:
            return
        try:
            from one_link import groups_crypto as gc
            group_id = gc._b64d(msg["group_id_b64"])
            epoch = int(msg["epoch"])
            chain_key = gc._b64d(msg["chain_key_b64"])
        except Exception as e:
            log.warning("malformed GROUP_KEY_OFFER from %s: %s", peer_fp[:8], e)
            return
        if len(group_id) != 16 or len(chain_key) != 32 or epoch <= 0:
            log.warning("invalid GROUP_KEY_OFFER fields from %s", peer_fp[:8])
            return
        sender_pub = channel.peer_ed_pub  # 32 bytes
        if not self._peer_is_current_group_member(group_id, sender_pub):
            log.warning(
                "GROUP_KEY_OFFER from non-member dropped: group=%s sender=%s peer=%s",
                group_id.hex()[:8], sender_pub.hex()[:8], peer_fp[:8],
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="group_not_member",
            )))
            return
        # Don't overwrite an in-progress chain at the same epoch — the
        # offered key is the *initial* state of that epoch, but we may
        # have already received and decrypted a few messages, advancing
        # past it. Only accept if we have NO chain at this epoch yet.
        existing = self.state.get_sender_chain(
            group_id=group_id,
            sender_pub=sender_pub,
            direction="in",
            epoch=epoch,
        )
        if existing is not None:
            log.debug(
                "GROUP_KEY_OFFER for (%s, ep=%d) already known; ignoring",
                sender_pub.hex()[:8], epoch,
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
            )))
            return
        self.state.upsert_sender_chain(
            group_id=group_id,
            sender_pub=sender_pub,
            direction="in",
            epoch=epoch,
            chain_key=chain_key,
            counter=0,
        )
        log.info(
            "GROUP_KEY_OFFER accepted for group=%s sender=%s epoch=%d",
            group_id.hex()[:8], sender_pub.hex()[:8], epoch,
        )
        await channel.send(encode_msg(make_msg(
            "ACK", self.me.short_id, of=msg.get("id"),
        )))

    async def _handle_group_msg(
        self, channel: ch.Channel, msg: dict, peer_fp: str, peer_sid: str,
    ) -> None:
        """Decrypt + verify + persist a group message from a pinned peer.
        ACKs on success or with a `rejected` reason on failure."""
        if not self._is_pinned(peer_fp):
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="peer_not_pinned",
            )))
            return
        if self.state is None:
            return
        from one_link import groups_crypto as gc

        try:
            group_id = gc._b64d(msg["group_id_b64"])
            wire = msg["wire"]
            if not isinstance(wire, dict):
                raise ValueError("wire must be a dict")
        except Exception as e:
            log.warning("malformed GROUP_MSG from %s: %s", peer_fp[:8], e)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="malformed",
            )))
            return

        sender_pub = channel.peer_ed_pub
        if not self._peer_is_current_group_member(group_id, sender_pub):
            log.warning(
                "GROUP_MSG from non-member dropped: group=%s sender=%s peer=%s",
                group_id.hex()[:8], sender_pub.hex()[:8], peer_fp[:8],
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="group_not_member",
            )))
            return
        epoch = int(wire.get("epoch", -1))
        if epoch <= 0:
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="malformed",
            )))
            return

        chain_row = self.state.get_sender_chain(
            group_id=group_id,
            sender_pub=sender_pub,
            direction="in",
            epoch=epoch,
        )
        if chain_row is None:
            log.info(
                "GROUP_MSG with no chain for group=%s sender=%s epoch=%d",
                group_id.hex()[:8], sender_pub.hex()[:8], epoch,
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="no_chain_for_epoch",
            )))
            return

        receiving = gc.ReceivingChain(
            group_id=group_id,
            sender_pubkey=sender_pub,
            epoch=epoch,
            chain_key=chain_row["chain_key"],
            counter=int(chain_row["counter"]),
        )
        try:
            plaintext, advanced = gc.decrypt_message(wire=wire, chain=receiving)
        except ValueError as e:
            log.warning(
                "GROUP_MSG decrypt failed for sender=%s epoch=%d counter=%d: %s",
                sender_pub.hex()[:8], epoch, wire.get("counter"), e,
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="decrypt_failed",
            )))
            return

        # Persist new chain state + the decrypted message.
        self.state.upsert_sender_chain(
            group_id=group_id,
            sender_pub=sender_pub,
            direction="in",
            epoch=epoch,
            chain_key=advanced.chain_key,
            counter=advanced.counter,
        )
        msg_id = msg.get("id") or uuid.uuid4().hex
        self.state.insert_group_message(
            id=msg_id,
            group_id=group_id,
            sender_pub=sender_pub,
            epoch=epoch,
            counter=int(wire.get("counter", 0)),
            direction="in",
            body=plaintext.decode("utf-8", errors="replace"),
        )
        # Surface to UI subscribers.
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_msg",
                    "group_id_hex": group_id.hex(),
                    "sender_pub_hex": sender_pub.hex(),
                    "epoch": epoch,
                    "counter": int(wire.get("counter", 0)),
                    "body": plaintext.decode("utf-8", errors="replace"),
                    "ts_ms": int(time.time() * 1000),
                    "direction": "in",
                })
        await channel.send(encode_msg(make_msg(
            "ACK", self.me.short_id, of=msg.get("id"),
        )))

    async def send_group_message(
        self, *, group_id: bytes, body: str,
    ) -> dict:
        """v0.6.2: encrypt a message under our sender chain for the
        group, then fan out to every member via their 1-on-1 outbound
        session.

        Returns:
            {"recipients": int, "delivered": int, "failures": [...]}
        """
        if self.state is None:
            raise RuntimeError("state not available")
        from one_link import groups as gmod
        from one_link import groups_crypto as gc

        # Materialize current group state from the persisted event log.
        wire_events = self.state.list_group_events(group_id)
        if not wire_events:
            raise RuntimeError(f"unknown group {group_id.hex()[:8]}")
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        if gstate is None:
            raise RuntimeError(f"group {group_id.hex()[:8]} has no valid events")
        if not gstate.is_member(self.me.public_bytes):
            raise RuntimeError("we are not a member of this group")

        # Get or create our outbound chain for this group + epoch.
        # Epoch 1 is the initial epoch; rotation comes in v0.6.x later.
        epoch = 1
        chain_row = self.state.get_sender_chain(
            group_id=group_id,
            sender_pub=self.me.public_bytes,
            direction="out",
            epoch=epoch,
        )
        if chain_row is None:
            # Start a fresh outbound chain. We must distribute its
            # initial chain key to every other member as a
            # GROUP_KEY_OFFER before they can decrypt our messages.
            initial = gc.begin_new_epoch(
                group_id=group_id,
                sender_pubkey=self.me.public_bytes,
                new_epoch=epoch,
            )
            self.state.upsert_sender_chain(
                group_id=group_id,
                sender_pub=self.me.public_bytes,
                direction="out",
                epoch=epoch,
                chain_key=initial.chain_key,
                counter=0,
            )
            await self._broadcast_group_key_offer(
                group_id=group_id,
                epoch=epoch,
                initial_chain_key=initial.chain_key,
                members=gstate.members,
            )
            chain_row = self.state.get_sender_chain(
                group_id=group_id,
                sender_pub=self.me.public_bytes,
                direction="out",
                epoch=epoch,
            )

        sender_chain = gc.SenderChain(
            group_id=group_id,
            sender_pubkey=self.me.public_bytes,
            epoch=int(chain_row["epoch"]),
            chain_key=chain_row["chain_key"],
            counter=int(chain_row["counter"]),
        )
        body_bytes = body.encode("utf-8")
        wire, advanced = gc.encrypt_message(
            plaintext=body_bytes,
            chain=sender_chain,
            private_key=self.me.private,
        )
        # Persist advance immediately — even if some recipients fail,
        # the chain has moved on.
        self.state.upsert_sender_chain(
            group_id=group_id,
            sender_pub=self.me.public_bytes,
            direction="out",
            epoch=advanced.epoch,
            chain_key=advanced.chain_key,
            counter=advanced.counter,
        )
        # Save outbound message in our own store.
        msg_id = uuid.uuid4().hex
        self.state.insert_group_message(
            id=msg_id,
            group_id=group_id,
            sender_pub=self.me.public_bytes,
            epoch=sender_chain.epoch,
            counter=sender_chain.counter,
            direction="out",
            body=body,
        )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_msg",
                    "group_id_hex": group_id.hex(),
                    "sender_pub_hex": self.me.public_bytes.hex(),
                    "epoch": sender_chain.epoch,
                    "counter": sender_chain.counter,
                    "body": body,
                    "ts_ms": int(time.time() * 1000),
                    "direction": "out",
                })

        # Fan out to every other member.
        recipients = [
            pk for pk in gstate.members.keys()
            if pk != self.me.public_bytes
        ]
        delivered = 0
        failures: list[dict] = []
        outer = make_msg(
            "GROUP_MSG", self.me.short_id,
            group_id_b64=gc._b64(group_id),
            wire=wire,
        )
        for member_pub in recipients:
            try:
                member_fp = fingerprint_of(member_pub)
                peer = await self.resolve_for_send(member_fp)
                if peer is None:
                    failures.append({
                        "fingerprint": member_fp,
                        "error": "peer_unreachable",
                    })
                    continue
                await self.send_to(peer, [outer])
                delivered += 1
            except Exception as e:
                failures.append({
                    "fingerprint": fingerprint_of(member_pub),
                    "error": str(e),
                })
        return {
            "recipients": len(recipients),
            "delivered": delivered,
            "failures": failures,
            "msg_id": msg_id,
        }

    async def _broadcast_group_key_offer(
        self,
        *,
        group_id: bytes,
        epoch: int,
        initial_chain_key: bytes,
        members: dict,
    ) -> None:
        """Send GROUP_KEY_OFFER to every group member except self.
        Best-effort — failures are logged, not raised. Membership
        rotation in later versions will retry on reconnect."""
        from one_link import groups_crypto as gc
        outer = make_msg(
            "GROUP_KEY_OFFER", self.me.short_id,
            group_id_b64=gc._b64(group_id),
            epoch=epoch,
            chain_key_b64=gc._b64(initial_chain_key),
        )
        for member_pub in list(members.keys()):
            if member_pub == self.me.public_bytes:
                continue
            try:
                fp = fingerprint_of(member_pub)
                peer = await self.resolve_for_send(fp)
                if peer is None:
                    log.info(
                        "GROUP_KEY_OFFER: peer unreachable %s",
                        fp[:8],
                    )
                    continue
                await self.send_to(peer, [outer])
            except Exception as e:
                log.warning("GROUP_KEY_OFFER to %s failed: %s",
                            fingerprint_of(member_pub)[:8], e)

    async def reject_pair(self, peer: Peer) -> None:
        """User says SAS did NOT match — possible MITM. Block the peer."""
        peer_fp = self._peer_fp_from_peer(peer) or fingerprint_of(
            bytes.fromhex(peer.ed_pub_hex)
        )
        self.pairing.reject(peer_fp)
        if self.state is not None:
            try:
                # Ensure the peer exists in the DB so trust update sticks
                self.state.upsert_peer(
                    fingerprint=peer_fp,
                    short_id=peer.short_id,
                    pubkey=bytes.fromhex(peer.ed_pub_hex),
                    hostname=peer.hostname,
                    address=peer.address,
                    port=peer.port,
                )
            except Exception:
                pass
            self.state.set_peer_trust(peer_fp, "rejected", actor="pairing")
        try:
            await self._send_control(
                peer, make_msg("PAIR_REJECT", self.me.short_id),
            )
        except Exception:
            # Peer may already be unreachable; that's fine.
            pass

    async def send_text(self, peer: Peer, body: str) -> dict:
        m = make_msg("TEXT", self.me.short_id, body=body)
        acks = await self.send_to(peer, [m])
        return {"sent": m, "ack": acks[0] if acks else None}

    # ─── outbox / store-and-forward (v0.7.1) ──────────────────────────

    def enqueue_text_outbox(self, peer_fp: str, body: str) -> dict:
        """Queue a TEXT message for a paired peer that's currently
        offline. Returns {ok, outbox_id, msg}. The caller wrote the
        send-attempt; this is the durable fallback. Persists the
        wire-shape `make_msg` dict so the eventual send goes out
        with the same id/ts the user expects."""
        if self.state is None:
            raise RuntimeError("state not available")
        rec = self.state.get_peer(peer_fp)
        if rec is None or rec.trust != "pinned":
            raise RuntimeError(
                "outbox enqueue requires a pinned peer fingerprint"
            )
        m = make_msg("TEXT", self.me.short_id, body=body)
        entry_id = self.state.enqueue_outbox(
            peer_fp=peer_fp, msg_id=m["id"], msg_body=m, msg_kind="TEXT",
        )
        # Persist + broadcast so the UI can render a "queued" bubble
        # immediately. The matching deliver event will flip it to
        # "delivered" once the peer is reachable.
        with contextlib.suppress(Exception):
            ev = self._persist(
                msg=m, direction="out", peer_fp=peer_fp,
                peer_short_id=rec.short_id,
            )
            self._broadcast_tail(ev)
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "outbox_enqueued",
                    "fingerprint": peer_fp,
                    "outbox_id": entry_id,
                    "msg_id": m["id"],
                    "kind": "TEXT",
                    "ts_ms": int(time.time() * 1000),
                })
        return {"ok": True, "outbox_id": entry_id, "msg": m}

    def _outbox_lock_for(self, peer_fp: str) -> asyncio.Lock:
        lk = self._outbox_flush_locks.get(peer_fp)
        if lk is None:
            lk = asyncio.Lock()
            self._outbox_flush_locks[peer_fp] = lk
        return lk

    async def flush_outbox_for(self, peer_fp: str) -> dict:
        """Deliver every pending outbox row for `peer_fp` over the
        existing (or freshly opened) encrypted session. Idempotent
        per peer (per-peer asyncio lock). Returns counts.

        Errors during a single message attempt are stamped onto the
        row's last_error and the row stays pending — next session-up
        retries it. Only `capability_disabled` rejections are sticky
        terminal: the UI can either grant the cap (then re-flush) or
        cancel the row."""
        if self.state is None:
            return {"ok": False, "error": "state not available", "delivered": 0}
        rec = self.state.get_peer(peer_fp)
        if rec is None:
            return {"ok": False, "error": "unknown peer", "delivered": 0}
        if rec.trust != "pinned":
            return {"ok": False, "error": "peer not pinned", "delivered": 0}
        # Lazy peer construction (mDNS first, rendezvous fallback).
        peer = await self.resolve_for_send(peer_fp)
        if peer is None:
            return {"ok": False, "error": "peer offline", "delivered": 0}

        lock = self._outbox_lock_for(peer_fp)
        if lock.locked():
            # Another flush is already running. Skip — that flush
            # picks up any rows we'd have processed.
            return {"ok": True, "delivered": 0, "skipped_concurrent": True}

        async with lock:
            self._outbox_flush_inflight.add(peer_fp)
            delivered = 0
            errors = 0
            try:
                pending = self.state.list_outbox(
                    peer_fp=peer_fp, pending_only=True, limit=200,
                )
                for entry in pending:
                    try:
                        # We send the original wire dict directly so
                        # the persisted message's id/ts is what the
                        # peer ACKs against.
                        await self.send_to(peer, [entry.msg_body])
                        self.state.mark_outbox_delivered(entry.id)
                        delivered += 1
                        if self.ui_server is not None:
                            with contextlib.suppress(Exception):
                                self.ui_server.broadcast({
                                    "type": "outbox_delivered",
                                    "fingerprint": peer_fp,
                                    "outbox_id": entry.id,
                                    "msg_id": entry.msg_id,
                                    "ts_ms": int(time.time() * 1000),
                                })
                    except Exception as e:
                        errors += 1
                        err = str(e)[:500]
                        self.state.record_outbox_attempt(entry.id, error=err)
                        # capability_disabled is sticky: don't keep
                        # retrying every 60s. The UI surfaces the
                        # row + the deny reason; user must grant.
                        log.info(
                            "outbox flush deferred for %s msg=%s: %s",
                            peer_fp[:8], entry.msg_id, err,
                        )
                        # First error short-circuits: if a session
                        # broke mid-stream, the next attempts would
                        # also fail and we'd burn through the queue
                        # marking every row with the same error.
                        # Better to surface one error and resume on
                        # the next session-up.
                        break
            finally:
                self._outbox_flush_inflight.discard(peer_fp)
            return {
                "ok": True,
                "delivered": delivered,
                "errors": errors,
                "remaining": len(self.state.list_outbox(
                    peer_fp=peer_fp, pending_only=True, limit=1,
                )),
            }

    def _schedule_outbox_flush(self, peer_fp: str) -> None:
        """Fire-and-forget background flush. Called from the
        session-up hook. Idempotent: if a flush for this peer is
        already inflight, the new task no-ops."""
        if self.state is None or not peer_fp:
            return
        if peer_fp in self._outbox_flush_inflight:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._flush_outbox_swallow(peer_fp))

    async def _flush_outbox_swallow(self, peer_fp: str) -> None:
        try:
            await self.flush_outbox_for(peer_fp)
        except Exception as e:
            log.warning("outbox flush task errored for %s: %s", peer_fp[:8], e)

    # ─── folder sync orchestration ─────────────────────────────────────
    async def push_folder_to_peer(self, peer: Peer, folder_name: str) -> dict:
        """One-way folder push to peer. Single connection cycle:
            1. Open + handshake + caps
            2. Send our manifest for this folder
            3. Receive MANIFEST_WANTS
            4. Stream BLOB_OFFER + BLOB_CHUNKs for each wanted blob
            5. Close

        Reverse direction happens when peer initiates their own cycle.
        """
        block = self._check_outbound_trust(peer)
        if block:
            return {"ok": False, "error": block, "blobs_sent": 0}
        if self.folder_engine is None or self.state is None or self.blob_store is None:
            return {"ok": False, "error": "folder sync not initialized", "blobs_sent": 0}

        peer_fp = self._peer_fp_from_peer(peer)
        if not peer_fp or not self._is_pinned(peer_fp):
            return {"ok": False, "error": "peer not pinned", "blobs_sent": 0}
        if not self._capability_allowed(peer_fp, FOLDER_SYNC):
            return {"ok": False, "error": "folder_sync capability disabled", "blobs_sent": 0}

        f = self.state.get_folder(folder_name)
        if not f or peer_fp not in f["shared_with"]:
            return {"ok": False, "error": "folder not shared with peer", "blobs_sent": 0}
        if not self.state.folder_peer_allows(folder_name, peer_fp, "push"):
            return {"ok": False, "error": "folder capability forbids push", "blobs_sent": 0}

        entries = self.folder_engine.manifest_for(folder_name)
        merkle_root = self.folder_engine.manifest_root(folder_name)
        total_bytes = sum(int(e.get("size") or 0) for e in entries if e.get("blob_hash"))
        transfer_id = f"folder:{folder_name}:{peer_fp[:12]}:{uuid.uuid4().hex[:10]}"
        self._upsert_transfer(
            id=transfer_id,
            direction="out",
            peer_fp=peer_fp,
            kind="folder",
            name=folder_name,
            size=total_bytes,
            blob_hash=merkle_root,
            status="active",
            progress_bytes=0,
            total_bytes=total_bytes,
            chunks_done=0,
            chunks_total=len(entries),
            metadata={
                "folder": folder_name,
                "entries": len(entries),
                "merkle_root": merkle_root,
                "peer": peer.short_id,
            },
        )

        reader, writer = await self._dial_peer(peer)
        blobs_sent = 0
        bytes_sent = 0
        try:
            channel = await ch.initiate(reader, writer, self.me)
            if channel.peer_short_id != peer.short_id:
                raise RuntimeError(
                    f"fingerprint mismatch: expected {peer.short_id}"
                )
            try:
                await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
            except Exception:
                pass

            await channel.send(encode_msg(make_msg(
                "MANIFEST_PUSH", self.me.short_id,
                folder=folder_name, entries=entries, merkle_root=merkle_root,
                entry_count=len(entries),
            )))

            # Drain replies until MANIFEST_WANTS arrives (skipping CAPS).
            wants: list[str] = []
            try:
                while True:
                    reply = await asyncio.wait_for(channel.recv(), timeout=15.0)
                    m = decode_msg(reply)
                    if m.get("t") == "CAPS":
                        channel.peer_caps = {
                            "protocol": m.get("protocol", "?"),
                            "features": list(normalize_caps(m.get("features", []))),
                            "from": m.get("from"),
                            "app_version": m.get("app_version"),
                        }
                        if self.state is not None:
                            with contextlib.suppress(Exception):
                                fp = self._peer_fp_from_peer(peer)
                                if fp:
                                    self.state.set_peer_capabilities(fp, channel.peer_caps["features"])
                        continue
                    if m.get("t") == "MANIFEST_WANTS" and m.get("folder") == folder_name:
                        wants = list(m.get("wants", []) or [])
                        break
                    # Anything else: ignore and keep listening briefly.
            except asyncio.TimeoutError:
                wants = []

            for blob_hex in wants:
                if not self._valid_blob_hex(blob_hex):
                    continue
                if not self.blob_store.has(blob_hex):
                    continue
                size = self.blob_store.size(blob_hex)
                bytes_sent += int(size)
                await channel.send(encode_msg(make_msg(
                    "BLOB_OFFER", self.me.short_id,
                    blob=blob_hex, size=size,
                )))
                seq = 0
                with self.blob_store.open_read(blob_hex) as fh:
                    prev = fh.read(CHUNK_SIZE)
                    while prev:
                        cur = fh.read(CHUNK_SIZE)
                        eof = not cur
                        await channel.send(encode_msg(make_msg(
                            "BLOB_CHUNK", self.me.short_id,
                            blob=blob_hex, seq=seq,
                            data=base64.b64encode(prev).decode("ascii"),
                            eof=eof,
                        )))
                        seq += 1
                        prev = cur
                blobs_sent += 1
                self._update_transfer(
                    transfer_id,
                    status="active",
                    progress_bytes=bytes_sent,
                    total_bytes=max(total_bytes, bytes_sent),
                    chunks_done=blobs_sent,
                    chunks_total=max(len(wants), blobs_sent),
                    raw_bytes=bytes_sent,
                    wire_bytes=bytes_sent,
                    metadata={
                        "folder": folder_name,
                        "entries": len(entries),
                        "wanted_blobs": len(wants),
                        "merkle_root": merkle_root,
                        "peer": peer.short_id,
                    },
                )

            await channel.close()
            self._update_transfer(
                transfer_id,
                status="complete",
                progress_bytes=bytes_sent if wants else total_bytes,
                total_bytes=max(total_bytes, bytes_sent),
                chunks_done=len(wants),
                chunks_total=len(wants),
                raw_bytes=bytes_sent,
                wire_bytes=bytes_sent,
                metadata={
                    "folder": folder_name,
                    "entries": len(entries),
                    "wanted_blobs": len(wants),
                    "blobs_sent": blobs_sent,
                    "merkle_root": merkle_root,
                    "peer": peer.short_id,
                },
            )
            return {
                "ok": True,
                "wants": len(wants),
                "blobs_sent": blobs_sent,
                "merkle_root": merkle_root,
            }
        except Exception as e:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            self._update_transfer(
                transfer_id,
                status="failed",
                metadata={
                    "folder": folder_name,
                    "entries": len(entries),
                    "merkle_root": merkle_root,
                    "peer": peer.short_id,
                    "error": str(e),
                },
            )
            return {"ok": False, "error": str(e), "blobs_sent": blobs_sent}

    async def send_file(self, peer: Peer, path: Path) -> dict:
        block = self._check_outbound_trust(peer)
        if block:
            raise RuntimeError(block)
        peer_fp_for_policy = self._peer_fp_from_peer(peer)
        if peer_fp_for_policy and not self._capability_allowed(peer_fp_for_policy, FILES):
            raise RuntimeError(f"files capability disabled for peer {peer.short_id}")
        size = path.stat().st_size
        file_index = index_path(path)
        blob_hex = file_index.blob_hash
        cdc_chunks = file_index.chunks
        cdc_index = [
            {
                "index": c.index,
                "start": c.start,
                "end": c.end,
                "size": c.size,
                "hash": c.hash,
            }
            for c in cdc_chunks
        ]

        offer = make_msg(
            "FILE_OFFER",
            self.me.short_id,
            name=path.name,
            size=size,
            blob=blob_hex,
            chunks=cdc_index,
            mode="cdc",
        )

        # v0.6.3: create the transfer-ledger row BEFORE the dial so any
        # failure during dial / handshake / first ACK marks an actual row
        # as 'failed' rather than disappearing silently. The peer_fp at
        # this stage is the policy-side estimate (from peer.ed_pub_hex);
        # the post-handshake _verify_channel_peer corrects it on success.
        transfer_id = f"out:{blob_hex}:{uuid.uuid4().hex[:12]}"
        provisional_fp = peer_fp_for_policy or ""
        self._upsert_transfer(
            id=transfer_id,
            direction="out",
            peer_fp=provisional_fp,
            kind="file",
            name=path.name,
            size=size,
            blob_hash=blob_hex,
            status="queued",
            progress_bytes=0,
            total_bytes=size,
            chunks_done=0,
            chunks_total=len(cdc_chunks),
            metadata={"mode": "cdc", "path": str(path)},
        )

        # v0.7.0 Linked Mesh: reuse the persistent encrypted session
        # instead of opening a fresh TCP connection + handshake per
        # file send. The session was negotiated on the first chat /
        # send_to call and is kept alive (with idle PING probe) for
        # OUTBOUND_SESSION_IDLE_S. Skipping the per-send handshake is
        # the core "they act as one" win: lower latency on the small-
        # file case, no stale-endpoint dial races, no CAPS round-trip
        # on every drop. _get_outbound_session handles the dial-and-
        # handshake fall-back internally when no live session exists.
        try:
            sess = await self._get_outbound_session(peer)
        except asyncio.TimeoutError as e:
            self._update_transfer(
                transfer_id, status="failed",
                metadata={
                    "mode": "cdc",
                    "path": str(path),
                    "error": (
                        f"file send to {peer.short_id}: handshake "
                        f"timed out after {HANDSHAKE_DEADLINE_OUTBOUND_S}s "
                        f"— peer not responsive"
                    ),
                    "error_class": "TimeoutError",
                },
            )
            raise RuntimeError(
                f"file send to {peer.short_id}: handshake timed out "
                f"after {HANDSHAKE_DEADLINE_OUTBOUND_S}s — peer not responsive"
            ) from e
        except Exception as e:
            # _get_outbound_session already wraps its own handshake
            # timeout into RuntimeError("... handshake timed out ..."),
            # which the existing test_send_file_aborts_when_receiver…
            # robustness test pins. Surface the original message and
            # stamp the ledger row so the UI shows the reason.
            err_msg = str(e)
            err_class = type(e).__name__
            ledger_msg = (
                err_msg if "handshake timed out" in err_msg.lower()
                else f"dial failed: {err_msg}"
            )
            self._update_transfer(
                transfer_id, status="failed",
                metadata={
                    "mode": "cdc",
                    "path": str(path),
                    "error": ledger_msg[:500],
                    "error_class": err_class,
                },
            )
            if "handshake timed out" in err_msg.lower():
                # Preserve the canonical "handshake timed out" wording
                # for callers/tests matching on it.
                raise RuntimeError(
                    f"file send to {peer.short_id}: handshake timed out "
                    f"after {HANDSHAKE_DEADLINE_OUTBOUND_S}s — peer not responsive"
                ) from e
            raise

        peer_fp = sess.peer_fp  # cryptographically-verified fingerprint
        channel = sess.channel
        # Walk the ledger row from queued → offered. The provisional
        # peer_fp was set from peer.ed_pub_hex; _get_outbound_session's
        # _verify_channel_peer guarantees they match here (it raises
        # otherwise). One UPDATE keeps the ledger consistent.
        if peer_fp != provisional_fp:
            self._upsert_transfer(
                id=transfer_id,
                direction="out",
                peer_fp=peer_fp,
                kind="file",
                name=path.name,
                size=size,
                blob_hash=blob_hex,
                status="offered",
                progress_bytes=0,
                total_bytes=size,
                chunks_done=0,
                chunks_total=len(cdc_chunks),
                metadata={"mode": "cdc", "path": str(path)},
            )
        else:
            self._update_transfer(transfer_id, status="offered")

        async def _await_ack(ch_: ch.Channel) -> dict:
            # v0.6.3: bound each recv. Without this, a peer that
            # received our chunk but never ACKed (e.g., crashed,
            # NAT dropped, channel hung mid-flush) would freeze
            # the entire transfer indefinitely.
            deadline = FILE_ACK_DEADLINE_S
            while True:
                try:
                    plaintext = await asyncio.wait_for(
                        ch_.recv(), timeout=deadline,
                    )
                except asyncio.TimeoutError as e:
                    raise RuntimeError(
                        f"file send to {peer.short_id}: peer did not "
                        f"ACK within {deadline}s — transfer aborted"
                    ) from e
                m = decode_msg(plaintext)
                if m.get("t") == "CAPS":
                    features = list(normalize_caps(m.get("features", [])))
                    ch_.peer_caps = {
                        "protocol": m.get("protocol", "?"),
                        "features": features,
                        "from": m.get("from"),
                        "app_version": m.get("app_version"),
                    }
                    if self.state is not None:
                        with contextlib.suppress(Exception):
                            self.state.set_peer_capabilities(peer_fp, features)
                    continue
                return m

        try:
            # v0.7.0: serialize all I/O on the persistent session under
            # sess.lock so the file send doesn't interleave with chat
            # send_to() calls or session-keepalive PINGs. Same locking
            # discipline as send_to(); the rest of the application is
            # unaware they're sharing a TCP connection.
            async with sess.lock:
                await channel.send(encode_msg(offer))
                first_reply = await _await_ack(channel)
                ev = self._persist(
                    msg=offer, direction="out", peer_fp=peer_fp, peer_short_id=peer.short_id,
                )
                self._broadcast_tail(ev)

                chunks_sent = 0
                wire_bytes_sent = 0
                raw_bytes_sent = 0
                compressed_chunks = 0
                cdc_used = first_reply.get("t") == "FILE_WANTS"
                wanted_indexes = (
                    {int(i) for i in first_reply.get("wants", [])}
                    if cdc_used else set()
                )
                if cdc_used:
                    skipped_bytes = sum(
                        int(c.size) for c in cdc_chunks if c.index not in wanted_indexes
                    )
                    self._update_transfer(
                        transfer_id,
                        status="active",
                        progress_bytes=skipped_bytes,
                        total_bytes=size,
                        chunks_done=len(cdc_chunks) - len(wanted_indexes),
                        chunks_total=len(cdc_chunks),
                        metadata={
                            "mode": "cdc",
                            "path": str(path),
                            "skipped_chunks": len(cdc_chunks) - len(wanted_indexes),
                        },
                    )
                    with open(path, "rb") as f:
                        for c in cdc_chunks:
                            if c.index not in wanted_indexes:
                                continue
                            f.seek(c.start)
                            data = f.read(c.size)
                            enc, payload = self._encode_payload(data)
                            raw_bytes_sent += len(data)
                            wire_bytes_sent += len(payload)
                            if enc != "raw":
                                compressed_chunks += 1
                            chunk_msg = make_msg(
                                "FILE_CDC_CHUNK",
                                self.me.short_id,
                                blob=blob_hex,
                                index=c.index,
                                hash=c.hash,
                                enc=enc,
                                wire_size=len(payload),
                                data=base64.b64encode(payload).decode("ascii"),
                            )
                            await channel.send(encode_msg(chunk_msg))
                            await _await_ack(channel)
                            chunks_sent += 1
                            self._update_transfer(
                                transfer_id,
                                status="active",
                                progress_bytes=skipped_bytes + raw_bytes_sent,
                                total_bytes=size,
                                chunks_done=(len(cdc_chunks) - len(wanted_indexes)) + chunks_sent,
                                chunks_total=len(cdc_chunks),
                                raw_bytes=raw_bytes_sent,
                                wire_bytes=wire_bytes_sent,
                            )
                else:
                    with open(path, "rb") as f:
                        seq = 0
                        prev = f.read(CHUNK_SIZE)
                        total_stream_chunks = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
                        while prev:
                            cur = f.read(CHUNK_SIZE)
                            eof = not cur
                            chunk_msg = make_msg(
                                "FILE_CHUNK",
                                self.me.short_id,
                                blob=blob_hex,
                                seq=seq,
                                data=base64.b64encode(prev).decode("ascii"),
                                eof=eof,
                            )
                            await channel.send(encode_msg(chunk_msg))
                            await _await_ack(channel)
                            chunks_sent += 1
                            raw_bytes_sent += len(prev)
                            wire_bytes_sent += len(prev)
                            self._update_transfer(
                                transfer_id,
                                status="active",
                                progress_bytes=raw_bytes_sent,
                                total_bytes=size,
                                chunks_done=chunks_sent,
                                chunks_total=total_stream_chunks,
                                raw_bytes=raw_bytes_sent,
                                wire_bytes=wire_bytes_sent,
                            )
                            prev = cur
                            seq += 1

                    if chunks_sent == 0:
                        empty = make_msg(
                            "FILE_CHUNK",
                            self.me.short_id,
                            blob=blob_hex,
                            seq=0,
                            data="",
                            eof=True,
                        )
                        await channel.send(encode_msg(empty))
                        await _await_ack(channel)
                        chunks_sent = 1
                        self._update_transfer(
                            transfer_id,
                            status="active",
                            progress_bytes=0,
                            total_bytes=0,
                            chunks_done=1,
                            chunks_total=1,
                        )

                # v0.7.0: stamp session counters so the next idle-PING
                # probe doesn't fire prematurely. No channel.close() —
                # the persistent session is alive for the next send.
                sess.last_used = time.time()
                sess.messages_sent += 1
                self._stamp_pair_health(sess.peer_fp)

            self._update_transfer(
                transfer_id,
                status="complete",
                progress_bytes=size,
                total_bytes=size,
                chunks_done=len(cdc_chunks) if cdc_used else chunks_sent,
                chunks_total=len(cdc_chunks) if cdc_used else chunks_sent,
                raw_bytes=raw_bytes_sent,
                wire_bytes=wire_bytes_sent,
                metadata={
                    "mode": "cdc" if cdc_used else "stream",
                    "path": str(path),
                    "skipped_chunks": len(cdc_chunks) - chunks_sent if cdc_used else 0,
                    "compressed_chunks": compressed_chunks,
                },
            )
            return {
                "offer": offer,
                "chunks": chunks_sent,
                "total_chunks": len(cdc_chunks),
                "cdc": cdc_used,
                "cdc_skipped": len(cdc_chunks) - chunks_sent if cdc_used else 0,
                "raw_bytes_sent": raw_bytes_sent,
                "wire_bytes_sent": wire_bytes_sent,
                "compressed_chunks": compressed_chunks,
                "blob": blob_hex,
                "size": size,
                "transfer_id": transfer_id,
            }
        except Exception as e:
            # v0.6.3: stamp the human-readable reason on the ledger row
            # so the UI can show "timed out" / "peer unreachable" /
            # "decrypt_failed" instead of a silent spinner.
            self._update_transfer(
                transfer_id, status="failed",
                metadata={
                    "mode": "cdc",
                    "path": str(path),
                    "error": str(e)[:500],
                    "error_class": type(e).__name__,
                },
            )
            # v0.7.0: a mid-stream failure leaves the session in an
            # unknown state (we sent a partial frame, peer's read loop
            # could be poisoned). Drop it so the next send_to / send_file
            # opens a fresh handshake instead of inheriting the rot.
            with contextlib.suppress(Exception):
                await self._drop_outbound_session(sess.peer_fp)
            raise

    # ─── control plane (local CLI) ──────────────────────────────────────
    async def _handle_control(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            line = await reader.readline()
            if not line:
                return
            try:
                req = json.loads(line.decode("utf-8"))
            except Exception as e:
                await self._reply(writer, {"ok": False, "error": f"bad request: {e}"})
                return
            cmd = req.get("cmd")
            if cmd == "peers":
                peers = [
                    {
                        "short_id": p.short_id,
                        "hostname": p.hostname,
                        "address": p.address,
                        "port": p.port,
                    }
                    for p in (self.discovery.registry.list() if self.discovery else [])
                ]
                me = {
                    "short_id": self.me.short_id,
                    "hostname": self.me.hostname,
                }
                await self._reply(writer, {"ok": True, "me": me, "peers": peers})
            elif cmd == "send":
                peers = self._resolve_peer_candidates(req["peer"])
                # v0.5.1: rendezvous fallback for paired peers off-LAN.
                if not peers:
                    fallback = await self.resolve_for_send(req["peer"])
                    if fallback is not None:
                        peers = [fallback]
                if not peers:
                    await self._reply(
                        writer, {"ok": False, "error": f"no peer {req['peer']!r}"}
                    )
                    return
                last_error = None
                for peer in peers:
                    try:
                        result = await self.send_text(peer, req["body"])
                        await self._reply(writer, {"ok": True, "result": result})
                        return
                    except OSError as e:
                        last_error = e
                        if self.discovery:
                            self.discovery.registry.remove(peer.short_id)
                        continue
                await self._reply(writer, {"ok": False, "error": str(last_error)})
            elif cmd == "send_file":
                peers = self._resolve_peer_candidates(req["peer"])
                if not peers:
                    fallback = await self.resolve_for_send(req["peer"])
                    if fallback is not None:
                        peers = [fallback]
                if not peers:
                    await self._reply(
                        writer, {"ok": False, "error": f"no peer {req['peer']!r}"}
                    )
                    return
                p = Path(req["path"])
                if not p.is_file():
                    await self._reply(writer, {"ok": False, "error": f"no file: {p}"})
                    return
                last_error = None
                for peer in peers:
                    try:
                        result = await self.send_file(peer, p)
                        await self._reply(writer, {"ok": True, "result": result})
                        return
                    except OSError as e:
                        last_error = e
                        if self.discovery:
                            self.discovery.registry.remove(peer.short_id)
                        continue
                await self._reply(writer, {"ok": False, "error": str(last_error)})
            elif cmd == "tail":
                self._tail_subs.add(writer)
                await self._reply(writer, {"ok": True, "tailing": True})
                try:
                    while not writer.is_closing():
                        await asyncio.sleep(60)
                finally:
                    self._tail_subs.discard(writer)
                return  # stay open
            else:
                await self._reply(writer, {"ok": False, "error": f"unknown cmd: {cmd}"})
        except Exception as e:
            log.exception("control handler error: %s", e)
            with contextlib.suppress(Exception):
                await self._reply(writer, {"ok": False, "error": str(e)})
        finally:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()

    async def _reply(self, writer: asyncio.StreamWriter, obj: dict) -> None:
        writer.write((json.dumps(obj) + "\n").encode("utf-8"))
        await writer.drain()

    def _resolve_peer(self, needle: str) -> Peer | None:
        return self.discovery.registry.find(needle) if self.discovery else None

    def _resolve_peer_candidates(self, needle: str) -> list[Peer]:
        return self.discovery.registry.candidates(needle) if self.discovery else []

    async def resolve_for_send(self, needle: str) -> Peer | None:
        """v0.5.1: send-path peer resolution. mDNS first, rendezvous
        fallback for paired peers.

        `needle` may be a hostname, short_id prefix, or full fingerprint.
        Returns the best Peer record we can construct, or None.
        """
        # mDNS path — same as before.
        peer = self._resolve_peer(needle)
        if peer is not None:
            return peer

        # Fingerprint or short_id lookup against the persistent peer DB —
        # only for peers we've explicitly trusted (pinned).
        if self.state is None:
            return None
        rec = None
        # Full fingerprint?
        if len(needle) == 64:
            rec = self.state.get_peer(needle)
        # Short ID?
        if rec is None and len(needle) <= 16:
            rec = self.state.get_peer_by_short_id(needle)
        if rec is None or rec.trust != "pinned":
            return None

        # Rendezvous fallback — only if the daemon has a client running.
        return await self.resolve_peer_endpoint(rec.fingerprint)

    def _broadcast_tail(self, msg: dict) -> None:
        line = (json.dumps({"event": "msg", "msg": msg}) + "\n").encode("utf-8")
        dead: list[asyncio.StreamWriter] = []
        for w in list(self._tail_subs):
            try:
                w.write(line)
            except Exception:
                dead.append(w)
        for w in dead:
            self._tail_subs.discard(w)
        # Push to UI subscribers too
        if self.ui_server is not None:
            try:
                self.ui_server.broadcast({"type": "msg", "msg": msg})
            except Exception:
                pass


    # ─── lifecycle ──────────────────────────────────────────────────────
    async def start(self) -> None:
        self._acquire_instance_lock()
        # Persistent state (sqlite) — created early so peer/handshake hooks
        # can record into it.
        try:
            self.state = State()
            # Pin our own identity so it's a known peer.
            self.state.upsert_peer(
                fingerprint=self.me.fingerprint,
                short_id=self.me.short_id,
                pubkey=self.me.public_bytes,
                hostname=self.me.hostname,
                trust_default="pinned",
            )
            self.state.set_peer_trust(self.me.fingerprint, "pinned", actor="self")
        except Exception as e:
            log.warning("state init failed (continuing without persistence): %s", e)
            self.state = None

        self._peer_server = await asyncio.start_server(
            self._handle_peer, host="0.0.0.0", port=0
        )
        peer_port = self._peer_server.sockets[0].getsockname()[1]
        _peer_port_path().write_text(str(peer_port))

        self._control_server = await asyncio.start_server(
            self._handle_control, host="127.0.0.1", port=0
        )
        ctrl_port = self._control_server.sockets[0].getsockname()[1]
        _control_port_path().write_text(str(ctrl_port))

        # M6: mDNS hostname privacy — never leak socket.gethostname() onto
        # the LAN by default. Prefer the user-chosen display_name, otherwise
        # fall back to the short_id (derived from the public key, non-PII).
        # Operators who *want* the OS hostname can set display_name to it
        # explicitly via /api/me.
        advertised_name = self.me.short_id
        if self.state is not None:
            with contextlib.suppress(Exception):
                dn = self.state.get_setting("display_name")
                if dn:
                    advertised_name = dn

        # v0.5.4: advertise our rendezvous URLs in mDNS TXT so other
        # LAN daemons auto-discover them. Tied to the same
        # share_rendezvous toggle that controls pair-time inheritance.
        rdz_to_advertise: list[str] = []
        if self.state is not None:
            with contextlib.suppress(Exception):
                share = self.state.get_setting("share_rendezvous")
                if share is None or share.lower() in ("1", "true", "yes"):
                    rdz_to_advertise = self.state.get_rendezvous_urls()

        # v0.7.3: smart device-kind detection. Cached after first call.
        from one_link import device_info as _device_info
        try:
            di = _device_info.detect()
            kind_tag = di.compact()
            self._device_info = di
        except Exception:
            kind_tag = ""
            self._device_info = _device_info.DeviceInfo()

        self.discovery = Discovery(
            short_id=self.me.short_id,
            hostname=advertised_name,
            port=peer_port,
            ed_pub_hex=self.me.public_bytes.hex(),
            rendezvous_urls=rdz_to_advertise,
            device_kind=kind_tag,
        )
        await self.discovery.start()

        # v0.4: notify UI to re-query /api/peers rather than pushing
        # raw discovery state. The /api/peers handler is the single
        # source of truth for filter mode (paired-only by default,
        # ?include_unpaired=1 for the discovery modal). Pushing only a
        # signal avoids duplicating that policy here.
        # v0.5.4: also inherit any rendezvous URLs LAN peers are
        # advertising — but ONLY if we currently have none configured
        # (zero-step bootstrap for new household members). Once we have
        # any rendezvous URL, we stop auto-inheriting from mDNS to
        # respect user choice. Pair-time inheritance from pinned peers
        # is the higher-trust path and runs separately.
        def _on_peer_change():
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({"type": "peers_changed"})
            with contextlib.suppress(Exception):
                self._maybe_inherit_rendezvous_from_mdns()

        self.discovery.registry.on_change = _on_peer_change

        # Background prune of unreachable mDNS entries. mDNS records can
        # outlive the daemon that announced them (OS-level / router caches);
        # a periodic TCP-probe is the only reliable way to keep the peer
        # list honest.
        async def _prune_loop():
            # Initial settle: wait a bit for mDNS to fully populate, then
            # an aggressive first prune to clear ghosts.
            try:
                await asyncio.sleep(3.0)
                if self.discovery:
                    n = await self.discovery.prune_unreachable(timeout=0.4)
                    if n:
                        log.info("startup prune: removed %d unreachable peers", n)
                cache_prune = self._prune_chunk_cache()
                if cache_prune["removed"]:
                    log.info(
                        "startup CDC cache prune: removed %d chunks freed=%d",
                        cache_prune["removed"], cache_prune["freed_bytes"],
                    )
                # Then steady-state every 20 seconds.
                while True:
                    await asyncio.sleep(20.0)
                    if self.discovery:
                        try:
                            await self.discovery.prune_unreachable(timeout=0.4)
                        except Exception as e:
                            log.warning("prune cycle failed: %s", e)
                    with contextlib.suppress(Exception):
                        self._prune_chunk_cache()
                    # v0.6.3: transfer-ledger watchdog. Any transfer
                    # in 'offered' or 'active' that hasn't progressed
                    # in 5 minutes is forcibly failed so the UI never
                    # shows "sending..." indefinitely. Genuine
                    # large-file transfers update updated_ms on every
                    # chunk, so this only catches actually-stuck rows.
                    with contextlib.suppress(Exception):
                        self._reap_stuck_transfers()
            except asyncio.CancelledError:
                pass

        self._prune_task = asyncio.create_task(_prune_loop())

        # v0.7.0: kick off endpoint announcement to all pinned peers
        # shortly after startup. Detached task — failures don't
        # affect daemon liveness, just degrade send-path freshness
        # for any peer that didn't receive the announcement.
        async def _delayed_announcement() -> None:
            try:
                # Short settle for the rendezvous client + discovery
                # to finish their startup work; otherwise we'd
                # broadcast empty endpoints.
                await asyncio.sleep(2.0)
                await self.broadcast_endpoint_to_paired()
            except asyncio.CancelledError:
                pass
            except Exception as e:
                log.debug("endpoint announcement at startup failed: %s", e)

        with contextlib.suppress(Exception):
            asyncio.create_task(_delayed_announcement())

        # Folder sync: blob store + manifest engine. Both lazy: even if user
        # never adds a folder, these are cheap to construct.
        if self.state is not None:
            try:
                self.blob_store = blobstore.BlobStore(data_dir() / "blobs")
                self.folder_engine = foldersync.FolderEngine(
                    state=self.state,
                    blob_store=self.blob_store,
                    my_fingerprint=self.me.fingerprint,
                    loop=asyncio.get_running_loop(),
                    on_local_change=self._on_local_folder_change,
                )
                await self.folder_engine.start()
                self._folder_sync_task = asyncio.create_task(self._folder_sync_loop())
            except Exception as e:
                log.warning("folder sync init failed: %s", e)
                self.folder_engine = None
                self.blob_store = None

        # Start UI server if available
        if UIServer is not None:
            try:
                self.ui_server = UIServer(self)
                ui_port = await self.ui_server.start()
            except Exception as e:
                log.warning("UI server failed to start: %s", e)
                self.ui_server = None
                ui_port = 0
        else:
            ui_port = 0

        # v0.5.1: rendezvous client. Optional — only starts if URLs are
        # configured. The daemon stays fully functional on LAN-only when
        # rendezvous is disabled or unreachable.
        await self._start_rendezvous(peer_port=peer_port)

        log.info(
            "One Link daemon up — id=%s host=%s peer=:%d ctrl=:%d ui=:%d",
            self.me.short_id,
            self.me.hostname,
            peer_port,
            ctrl_port,
            ui_port,
        )

    async def _on_local_folder_change(self, folder_name: str, entry) -> None:
        """Called by the FolderEngine when a watched file is added / changed
        / deleted. Notify the UI so the folder status indicator updates;
        peer push happens on the next sync tick."""
        if self.ui_server is not None:
            try:
                self.ui_server.broadcast({
                    "type": "folder_change",
                    "folder": folder_name,
                    "file": entry.file_path,
                    "deleted": entry.blob_hash is None,
                })
            except Exception:
                pass

    async def _folder_sync_loop(self) -> None:
        """Periodically push our manifest for each shared folder to every
        pinned peer that's currently reachable. One-way per cycle; the
        reverse direction happens when the peer initiates."""
        # Initial settle delay so discovery + state are fully up.
        try:
            await asyncio.sleep(8.0)
            while True:
                await self._run_one_folder_sync_cycle()
                await asyncio.sleep(30.0)
        except asyncio.CancelledError:
            pass

    async def _run_one_folder_sync_cycle(self) -> None:
        if (
            self.folder_engine is None
            or self.state is None
            or self.discovery is None
        ):
            return
        folders = self.state.list_folders()
        if not folders:
            return
        for folder in folders:
            for peer_fp in folder["shared_with"]:
                if not self._is_pinned(peer_fp):
                    continue
                # Find the peer in discovery.
                peer = None
                for p in self.discovery.registry.list():
                    cand_fp = self._peer_fp_from_peer(p)
                    if cand_fp == peer_fp:
                        peer = p
                        break
                if peer is None:
                    continue
                try:
                    await self.push_folder_to_peer(peer, folder["name"])
                except Exception as e:
                    log.info("folder sync to %s failed: %s", peer.short_id, e)

    async def serve_forever(self) -> None:
        assert self._peer_server and self._control_server
        await asyncio.gather(
            self._peer_server.serve_forever(),
            self._control_server.serve_forever(),
        )

    async def stop(self) -> None:
        # v0.5.1: revoke rendezvous registration first so peers learn
        # we're going offline before we tear down anything else.
        if self.rendezvous is not None:
            try:
                await self.rendezvous.stop()
            except Exception:
                pass
            self.rendezvous = None
        # v0.5.5: stop relay listeners.
        for listener in list(self._relay_listener_clients):
            with contextlib.suppress(Exception):
                await listener.stop()
        self._relay_listener_clients.clear()
        for peer_fp in list(self._outbound_sessions):
            await self._drop_outbound_session(peer_fp)
        if self._folder_sync_task and not self._folder_sync_task.done():
            self._folder_sync_task.cancel()
            try:
                await self._folder_sync_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.folder_engine is not None:
            try:
                await self.folder_engine.stop()
            except Exception:
                pass
        if self._prune_task and not self._prune_task.done():
            self._prune_task.cancel()
            try:
                await self._prune_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.ui_server is not None:
            try:
                await self.ui_server.stop()
            except Exception:
                pass
        if self.discovery:
            await self.discovery.stop()
        if self._peer_server:
            self._peer_server.close()
            await self._peer_server.wait_closed()
        if self._control_server:
            self._control_server.close()
            await self._control_server.wait_closed()
        if self.state is not None:
            try:
                self.state.close()
            except Exception:
                pass
        self._release_instance_lock()


async def run() -> None:
    me = load_or_create()
    daemon = Daemon(me)
    await daemon.start()
    try:
        await daemon.serve_forever()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await daemon.stop()


def read_control_port() -> int:
    p = _control_port_path()
    if not p.exists():
        raise RuntimeError("daemon not running (no control.port file)")
    return int(p.read_text().strip())


def is_daemon_alive(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()
