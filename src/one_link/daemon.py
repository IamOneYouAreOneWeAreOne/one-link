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
import sys
import time
import uuid
import zlib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any, Optional, Protocol, TypedDict, cast

import blake3

if TYPE_CHECKING:
    from one_link import rendezvous_client
    from one_link.server import UIServer
    from one_link_native.prefetch import Predictor as _NativePredictor

from one_link import blobstore, channel as ch, foldersync
from one_link.capabilities import (
    CHAT,
    FILE_ACK_BATCH,
    FILE_BINARY_FRAME,
    FILE_CDC_BINARY_FRAME,
    FILES,
    FILE_SWARM,
    FOLDER_SYNC,
    LOCAL_CAPABILITIES,
    NATIVE_TRANSFER_V1,
    normalize_caps,
)
from one_link.cdc import (
    MAX_CHUNK_BYTES as CDC_MAX_CHUNK_BYTES,
    MIN_CHUNK_BYTES as CDC_MIN_CHUNK_BYTES,
    Chunk,
    FileIndex,
    fixed_index_path,
    hash_path,
    index_path,
)
from one_link.discovery import Discovery, Peer
from one_link.identity import Identity, fingerprint_of, load_or_create
from one_link.native_cdc import native_cdc_status
from one_link.pairing import PairingTracker, PairState, compute_sas
from one_link.paths import (
    data_dir,
    inbox_dir,
)
from one_link.state import State
from one_link.swarm_plan import plan_swarm_sources, source_from_hashes
from one_link.transfer_brain import (
    AdaptiveTransferScheduler,
    MeshNodeSignal,
    TransferPerformanceOracle,
    TransferRouteObservation,
    adapt_pipeline_profile,
    build_transfer_autopilot_plan,
    decision_from_observations,
    transfer_performance_summary,
    transfer_result_report,
    verification_priority_order,
)
from one_link.transfer_doctor import (
    RouteMemory,
    RouteObservation,
    diagnose_transfer,
    enrich_transfer_event,
)
from one_link.transfer_intent import (
    FileChunkManifest,
    FileManifest,
    plan_transfer_intent,
    plan_transfer_intent_for_manifest,
)
from one_link.transfer_safety import (
    TransferAdmissionContext,
    TransferAdmissionPolicy,
    classify_file_risk,
    evaluate_transfer_admission,
    known_bytes_from_chunks,
)
from one_link.wire import decode_msg, encode_msg, make_msg

log = logging.getLogger("one_link.daemon")


def _is_benign_windows_transport_reset(exc: BaseException | None) -> bool:
    return (
        os.name == "nt"
        and isinstance(exc, ConnectionResetError)
        and getattr(exc, "winerror", None) == 10054
    )


def _install_asyncio_exception_handler(loop: asyncio.AbstractEventLoop) -> None:
    """Suppress Windows Proactor teardown noise for already-closed sockets.

    Real peer/session errors are still handled and logged by the protocol
    paths. This only catches callback-level ``connection_lost`` resets that
    can happen after a successful transfer when the remote peer has already
    closed its side of the pipe.
    """
    previous_handler = loop.get_exception_handler()

    def _handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        if _is_benign_windows_transport_reset(exc):
            log.debug(
                "suppressed benign Windows transport reset: %s",
                context.get("message", ""),
            )
            return
        if previous_handler is not None:
            previous_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)

CONTROL_PORT_FILE = "control.port"
PEER_PORT_FILE = "peer.port"
DAEMON_LOCK_FILE = "daemon.lock"
CHUNK_SIZE = 256 * 1024  # 256 KiB plaintext per FILE_CHUNK
STREAM_MIN_CHUNK_SIZE = 256 * 1024
STREAM_MAX_CHUNK_SIZE = 4 * 1024 * 1024
STREAM_PIPELINE_TARGET_BYTES = 24 * 1024 * 1024
STREAM_PIPELINE_MAX_CHUNKS = 16
FILE_ACK_BATCH_MAX = 32
BINARY_FRAME_MAGIC = b"OLB1"
BINARY_FRAME_HEADER_MAX = 64 * 1024
MAX_INCOMING_FILE_BYTES = 1024 * 1024 * 1024  # match UI upload cap
MAX_DECLARED_FILE_OFFER_BYTES = 16 * 1024 * 1024 * 1024 * 1024
MAX_TRANSFER_FILE_NAME_BYTES = 240
MAX_CDC_MANIFEST_CHUNKS = 262_144
CDC_CACHE_MAX_BYTES = 512 * 1024 * 1024
CDC_AUTO_INDEX_MAX_BYTES = 128 * 1024 * 1024
FAST_FIXED_INDEX_MIN_BYTES = 16 * 1024 * 1024
FAST_FIXED_CHUNK_SIZE = 1024 * 1024
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
FILE_FINAL_ACK_MIN_GRACE_S = 120.0
FILE_FINAL_ACK_BYTES_PER_S = 2 * 1024 * 1024
TRANSFER_RETRY_BASE_S = 5.0
TRANSFER_RETRY_MAX_S = 5 * 60.0
SWARM_ASSIST_DEADLINE_S = 2.0
SWARM_QUERY_BATCH_HASHES = 2048
SWARM_QUERY_MAX_HASHES = 262_144
PRIOR_ASSIST_MAX_FILES = 96
PRIOR_ASSIST_MAX_SCAN_BYTES = 2 * 1024 * 1024 * 1024
PRIOR_ASSIST_MAX_MATCHES_PER_SCAN = 4096
PRIOR_INDEX_INTERVAL_S = 120.0
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
# v0.7.6: edit cooldown. Messages older than 5 minutes are
# locked — protects against confusing audit trails (peer claims
# "I never said that" when they did, but edited it last week).
EDIT_COOLDOWN_MS = 5 * 60 * 1000
# H3: handshake hardening
HANDSHAKE_DEADLINE_S = 8.0          # peer has 8s to complete handshake
HANDSHAKE_PER_IP_INFLIGHT_MAX = 32  # concurrent handshakes from one IP
HANDSHAKE_PER_IP_RATE_WINDOW_S = 60.0
HANDSHAKE_PER_IP_RATE_MAX = 240     # attempts per window per IP
# v0.20.7 (security audit H4): per-frame deadline on the post-handshake
# peer recv loop. Without this, a peer that completes the (cheap)
# handshake can hold the connection open indefinitely with no further
# bytes, pinning fds + memory. The keepalive uses 30s PING/PONG so 120s
# tolerates two missed PINGs before declaring the channel dead.
PEER_IDLE_S = 120.0
# v0.20.7 (security audit M8): global cap on concurrent inbound peer
# connections. Per-IP HANDSHAKE_PER_IP_INFLIGHT_MAX bounds one source,
# but a coordinated fan-in from N IPs (or one host with many NICs)
# can pin N×32 inflight handshakes plus N×∞ post-handshake idle
# channels (slowloris). 256 is a generous ceiling for friend-of-friend
# households; tune via env if needed.
MAX_TOTAL_PEER_CONNECTIONS = int(os.environ.get("ONE_LINK_MAX_PEERS", "256"))
# Per-fingerprint cap so one peer key can't open many parallel
# channels to wedge the global cap.
MAX_PEER_CONNECTIONS_PER_FP = int(os.environ.get("ONE_LINK_MAX_PEERS_PER_FP", "4"))
# Loopback gets a free pass — the test suite & the local UI talk to the
# daemon on 127.0.0.1 in tight bursts, and an attacker on loopback already
# owns the box.
HANDSHAKE_LOOPBACK_IPS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_transient_send_error(exc: BaseException) -> bool:
    """v0.7.4: classify send_file failures so the resume-on-reconnect
    path knows when to mark a transfer 'paused' (auto-retry on next
    fresh session) vs 'failed' (permanent, user must intervene).

    Transient — pause + retry:
      - OSError family (ConnectionAbortedError, ConnectionResetError,
        TimeoutError, BrokenPipeError, etc) — typically WinError 10053
        when the peer's TCP stack tore the link mid-stream.
      - asyncio.TimeoutError — handshake or per-chunk ACK deadline.
      - RuntimeError carrying our own "handshake timed out" / "did
        not ACK" / "peer not responsive" sentinels.

    Permanent — fail loudly:
      - Capability denial (peer's policy refused us).
      - Decrypt failure (wrong key / corrupt authenticated ciphertext).
      - Peer marked rejected.

    Ratchet header mismatch is session-bound and recoverable: drop the
    session, preserve the staged file, and retry after a fresh handshake.
    """
    if isinstance(exc, (OSError, ConnectionError, asyncio.TimeoutError)):
        return True
    msg = str(exc).lower()
    if "capability" in msg and "disabled" in msg:
        return False
    if "rejected" in msg:
        return False
    if "decrypt" in msg or "invalidtag" in msg:
        return False
    transient_markers = (
        "handshake timed out", "did not ack", "peer not responsive",
        "connection aborted", "connection reset", "broken pipe",
        "timed out", "winerror 10053", "winerror 10054",
        "peer offline", "peer unreachable",
        "unsupported ratchet header version", "ratchet header version",
        "ratchet frame too short", "header too short",
    )
    return any(m in msg for m in transient_markers)


class TransferPausedError(RuntimeError):
    """Raised when an outbound file send is safely resumable later.

    The transfer ledger already contains the durable status row when this
    exception is raised. HTTP callers use the transfer_id/path to return a
    202 instead of an opaque 500 and, for browser uploads, to keep the
    staged file available for automatic resume.
    """

    def __init__(self, message: str, *, transfer_id: str, path: Path):
        super().__init__(message)
        self.transfer_id = transfer_id
        self.path = path


def _should_build_cdc_offer(
    *,
    size: int,
    intent,
    existing_metadata: dict | None = None,
) -> tuple[bool, str]:
    """Decide whether a live send should pay CDC indexing cost.

    CDC is excellent when it skips enough bytes, but Python CDC is much slower
    than the fast stream path for first-time large media. Native CDC changes
    that tradeoff: large files can advertise chunk knowledge quickly, so the
    peer can skip anything it already has or source it from the trusted mesh.
    """

    if not getattr(intent, "can_offer_cdc", False):
        return False, "peer_does_not_support_cdc"
    md = existing_metadata or {}
    previous_mode = str(md.get("actual_method") or md.get("planned_wire_mode") or "")
    if previous_mode in {"file_cdc", "cdc", "swarm_cdc"}:
        return True, "resume_existing_cdc_transfer"
    if int(size) <= CDC_AUTO_INDEX_MAX_BYTES:
        return True, "small_enough_for_python_cdc"
    native = native_cdc_status()
    if native.available:
        return True, f"native_cdc_fast_lane:{native.engine}"
    return False, "large_file_fast_lane_until_native_cdc"


def _stream_transfer_profile(size: int) -> dict[str, int]:
    """Choose a safe high-throughput baseline stream profile.

    The goal is to fill modern Wi-Fi/Ethernet pipes without turning One Link
    into a RAM vacuum. Larger files get larger chunks and a bounded in-flight
    byte window; small files keep low latency and small allocations.
    """

    size = max(0, int(size))
    if size >= 2 * 1024 * 1024 * 1024:
        chunk_size = STREAM_MAX_CHUNK_SIZE
    elif size >= 512 * 1024 * 1024:
        chunk_size = 2 * 1024 * 1024
    elif size >= 64 * 1024 * 1024:
        chunk_size = 1024 * 1024
    else:
        chunk_size = STREAM_MIN_CHUNK_SIZE
    target = min(
        STREAM_PIPELINE_TARGET_BYTES,
        max(chunk_size, size if size > 0 else chunk_size),
    )
    window_chunks = max(1, min(STREAM_PIPELINE_MAX_CHUNKS, target // chunk_size))
    return {
        "chunk_size": int(chunk_size),
        "window_chunks": int(window_chunks),
        "window_bytes": int(window_chunks * chunk_size),
    }


def _final_stream_ack_deadline(size: int) -> float:
    """Grace period for old receivers that cache chunks before final ACK."""

    size = max(0, int(size))
    cache_grace = size / FILE_FINAL_ACK_BYTES_PER_S if size else 0.0
    return float(min(
        FILE_SEND_TOTAL_DEADLINE_S,
        max(FILE_ACK_DEADLINE_S, FILE_FINAL_ACK_MIN_GRACE_S, cache_grace),
    ))


def _version_at_least(version: str | None, major: int, minor: int, patch: int) -> bool:
    if not version:
        return False
    try:
        nums = []
        for part in str(version).strip().lstrip("v").split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            nums.append(int(digits or 0))
        while len(nums) < 3:
            nums.append(0)
        return tuple(nums[:3]) >= (major, minor, patch)
    except Exception:
        return False


def _fast_fixed_chunk_size_for_peer(
    peer_version: str | None,
    *,
    size: int = 0,
    peer_features: list[str] | tuple[str, ...] | set[str] | None = None,
) -> int:
    """Largest fixed-manifest chunk this peer can safely parse.

    v0.12.5 receivers accept up to STREAM_MAX_CHUNK_SIZE in FILE_OFFER
    manifests. Older receivers clamp CDC-ish offers around 512 KiB, so we use
    the classic 256 KiB chunk when version is unknown/older to preserve
    zero-chunk repeat sends instead of silently falling back to streaming.
    """

    features = set(normalize_caps(peer_features or ()))
    modern_peer = (
        _version_at_least(peer_version, 0, 12, 5)
        or FILE_CDC_BINARY_FRAME in features
        or FILE_SWARM in features
    )
    if modern_peer:
        size = max(0, int(size or 0))
        if size >= 2 * 1024 * 1024 * 1024:
            return STREAM_MAX_CHUNK_SIZE
        if size >= 512 * 1024 * 1024:
            return 2 * 1024 * 1024
        return FAST_FIXED_CHUNK_SIZE
    return CDC_MAX_CHUNK_BYTES


def _encode_binary_frame(header: dict, data: bytes) -> bytes:
    """Encrypted-channel plaintext for binary payload frames.

    The channel still encrypts/authenticates the whole bytestring. This
    format only removes JSON/base64 from the plaintext payload:

        b"OLB1" + header_len:u32be + compact_json_header + raw_bytes
    """

    head = encode_msg(header)
    if len(head) > BINARY_FRAME_HEADER_MAX:
        raise ValueError(f"binary frame header too large: {len(head)}")
    return BINARY_FRAME_MAGIC + len(head).to_bytes(4, "big") + head + data


def _decode_binary_frame(payload: bytes) -> dict:
    if not payload.startswith(BINARY_FRAME_MAGIC):
        raise ValueError("not a One Link binary frame")
    if len(payload) < len(BINARY_FRAME_MAGIC) + 4:
        raise ValueError("binary frame header truncated")
    pos = len(BINARY_FRAME_MAGIC)
    n = int.from_bytes(payload[pos:pos + 4], "big")
    if n <= 0 or n > BINARY_FRAME_HEADER_MAX:
        raise ValueError(f"invalid binary frame header length: {n}")
    start = pos + 4
    end = start + n
    if end > len(payload):
        raise ValueError("binary frame header exceeds payload")
    msg = decode_msg(payload[start:end])
    msg["_binary_data"] = payload[end:]
    return msg


def _delivery_backoff_ms(attempts: int) -> int:
    attempts = max(1, int(attempts))
    delay_s = min(TRANSFER_RETRY_MAX_S, TRANSFER_RETRY_BASE_S * (2 ** (attempts - 1)))
    return int(delay_s * 1000)

# Capabilities this build advertises in CAPS messages.
# v0.5.4 bumps to OL1.2: CAPS optionally includes `share_rdz` so paired
# devices auto-inherit each other's rendezvous URL list. Older OL1.1
# peers ignore the field — strict-forward-compat.
PROTOCOL_VERSION = "OL1.2"
CAPS_FEATURES: list[str] = [
    # v0.20.7 (security audit C4 + H14): advertise the full
    # LOCAL_CAPABILITIES set including `double_ratchet_v1`. The
    # activation path was implemented in v0.7.2 (channel.py
    # note_caps_sent / note_caps_received / maybe_activate_ratchet)
    # but the cap was filtered out of advertised CAPS, leaving every
    # channel on the static AEAD keys derived once at handshake — so
    # captured ciphertext from a stolen long-term key stayed
    # decryptable forever and "block = cryptographic cutoff" was
    # fiction. The v0.7.2 ratchet activation regression suite
    # (test_channel_ratchet_v082.py + test_double_ratchet_v072.py)
    # is green; advertising the cap lets both sides activate and
    # delivers the forward-secrecy + post-compromise-security
    # guarantees that SECURITY.md §T3 commits to.
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
PRESENCE_STATES = frozenset({"online", "away", "dnd", "invisible", "offline"})


def _build_caps(
    short_id: str,
    *,
    rendezvous_urls: list[str] | None = None,
    channel_bind: dict | None = None,
    presence: str | None = None,
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
    if presence:
        extra["presence"] = presence
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


def _daemon_lock_path() -> Path:
    return data_dir() / DAEMON_LOCK_FILE


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


def _read_lock_pid() -> int | None:
    try:
        raw = _daemon_lock_path().read_text(encoding="ascii", errors="ignore").strip()
        return int(raw) if raw else None
    except Exception:
        return None


def _runtime_port_paths() -> tuple[Path, ...]:
    """Files that describe a live daemon instance, not durable user data."""
    return (
        data_dir() / CONTROL_PORT_FILE,
        data_dir() / PEER_PORT_FILE,
        data_dir() / "server.port",
    )


def _clear_stale_runtime_files() -> None:
    """Remove dead daemon runtime hints without touching identity/state.

    These files are just pointers to a currently running process. If the
    process is gone, leaving them behind makes launchers and tests try a
    port that will never answer. That is exactly the class of "spins forever"
    failure a self-healing desktop app must not expose to users.
    """
    for p in (*_runtime_port_paths(), _daemon_lock_path()):
        with contextlib.suppress(OSError):
            p.unlink()


@dataclass
class IncomingFile:
    name: str
    size: int
    blob_hex: str
    out_path: Path
    # Writable binary file handle the receiver streams chunks into.
    # ``IO[bytes]`` covers both the builtins.open(...) result and any
    # custom binary writer we might inject in tests.
    handle: IO[bytes]
    # ``hasher`` is the blake3 Hasher instance running in parallel
    # with the write stream. blake3 doesn't ship PEP-561 stubs, so
    # the field is type-checked as ``_HasherProtocol`` (a small
    # nominal protocol the call sites need — update + hexdigest).
    # Required field — the construction site always supplies it.
    hasher: "_HasherProtocol"
    received: int = 0
    next_seq: int = 0
    cdc_chunks: list[dict] | None = None
    cdc_missing: set[int] | None = None
    cdc_parts: dict[int, bytes] | None = None
    transfer_id: str | None = None
    ack_batch_ids: list[str] = field(default_factory=list)


class _HasherProtocol(Protocol):
    """Minimal interface IncomingFile needs from a streaming hasher.

    blake3.blake3() returns an instance that satisfies this contract.
    Pinned as a Protocol so we don't depend on blake3 shipping stubs
    and tests can substitute a stub without subclassing."""

    def update(self, data: bytes) -> None: ...

    def hexdigest(self) -> str: ...


class _PairHealth(TypedDict, total=False):
    """Per-peer health snapshot kept in ``Daemon._pair_health``.
    Keys are populated incrementally as PING / ACK / chunk-arrival
    events fire, so ``total=False``."""

    last_alive_ms: int
    latency_ewma_ms: float
    bandwidth_bps: float
    reliability: float
    best_route: str


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
        # TYPE_CHECKING import keeps UIServer (and its aiohttp deps)
        # off the import graph for CLI / status paths — see start()
        # where it's imported on demand. The runtime contract: None
        # until start() succeeds; UIServer instance afterward.
        self.ui_server: Optional["UIServer"] = None
        self.state: State | None = None
        self.pairing = PairingTracker()
        # v0.12.0: bandwidth pacer + auto-accept rules cache. Both
        # consume settings; refresh_settings_cache() pulls the
        # latest values and is invoked from /api/settings POST so
        # changes apply live without a daemon restart.
        from one_link.pacing import BandwidthPacer
        self.bandwidth_pacer = BandwidthPacer(cap_kbps=0)
        self._auto_accept_max_size_bytes: int = 0  # 0 = no limit
        self._auto_accept_extensions: set[str] = set()  # empty = no filter
        # v0.20.7 (security audit M8): inbound-peer concurrency
        # accounting. Global counter for the absolute cap; per-fp
        # counter for the one-key-many-channels case.
        self._inbound_peer_count: int = 0
        self._inbound_per_fp: dict[str, int] = {}
        self._transfer_admission_policy = TransferAdmissionPolicy(
            max_declared_bytes=MAX_DECLARED_FILE_OFFER_BYTES,
        )
        # v0.12.3: typing-indicator state + privacy.
        # _peer_typing[fp] = wall-clock ms when the peer's "still
        # typing" expires. The WS broadcasts peer_typing events;
        # the UI shows "User is typing…" until the deadline.
        self._peer_typing: dict[str, int] = {}
        # _last_typing_sent_to[fp] = ts of last TYPING we sent to
        # this peer, used to debounce so a fast typer doesn't
        # flood the wire.
        self._last_typing_sent_to: dict[str, float] = {}
        self._prune_task: asyncio.Task | None = None
        self._dm_reaper_task: asyncio.Task | None = None
        self._prior_index_task: asyncio.Task | None = None
        # Opened in ``_acquire_pid_lock`` after start. ``IO[bytes]``
        # covers both the msvcrt + fcntl branches — both eventually
        # bind the same builtins.open(..., "wb+") result before
        # locking, so the underlying type unifies.
        self._lock_file: Optional[IO[bytes]] = None
        # Folder sync — populated in start() when state + blob store are up.
        self.folder_engine = None  # type: foldersync.FolderEngine | None
        self.blob_store = None     # type: blobstore.BlobStore | None
        self._folder_sync_task: asyncio.Task | None = None
        self._outbound_sessions: dict[str, OutboundSession] = {}
        # v0.20.7+ (Bundle 55): per-peer session-creation locks. Without
        # these, N concurrent send_to() calls to the same peer that
        # arrive before any session exists each see ``existing=None``,
        # each dial a new TCP connection + run a fresh handshake, and
        # the LAST one wins in the dict — leaving N-1 orphaned channels
        # whose follow-up ACK reads fail with EOF when the peer's
        # per-fp inbound cap kicks in. Hold this lock around the
        # check-or-create critical section so concurrent callers
        # collapse onto a single fresh session.
        self._outbound_session_create_locks: dict[str, asyncio.Lock] = {}
        # Bundle 56: signed-capability-grant store. Daemons accept
        # grants from peers (typically over the existing channel
        # frame format) and consult the store from
        # ``_capability_allowed``. Active grants override the binary
        # pinned/unpinned policy for the specific (capability, scope)
        # they cover; expired grants auto-drop.
        from one_link.cap_store import CapStore
        self._cap_store: CapStore = CapStore()
        # Phase C-3 (ADR-0021): macaroon dual-issue. The most recently
        # minted macaroon cap (wire bytes) is stashed here for the
        # peer-facing share endpoint to surface to advertise-capable
        # clients. `None` until the first share is minted or when the
        # native cap_migration module is unavailable.
        self._last_minted_macaroon: bytes | None = None
        # Phase D #3 (ADR-0033): per-daemon active inference prefetch
        # predictor. Built lazily on first observation so daemons without
        # the native crate installed don't pay the cost.
        # Type-resolved via the PEP-561 stubs in
        # ``stubs/one_link_native-stubs/prefetch.pyi`` so the daemon
        # actually verifies the .observe / .predict_top_n /
        # .storage_entries calls against the native ABI.
        self._prefetch_predictor: Optional["_NativePredictor"] = None
        self._prefetch_unavailable_logged: bool = False
        # Phase D #1 (ADR-0028): per-relay empirical metrics. Maps
        # relay URL → {rtt_ms, loss_rate, n_attempts, n_successes,
        # last_observed_ms}. EWMA-smoothed by `record_relay_observation`
        # so a one-off bad dial doesn't permanently demote a relay.
        # Consumed by `_pick_best_relay` via `_relay_metrics_for`.
        self._relay_metrics: dict[str, dict] = {}
        # Phase E coherence-field snapshot manager. Background-ticking
        # solver that every Phase E consumer (ratchet cadence, bandit
        # prior, prefetch scheduler, /api/metrics surface) reads from.
        # Constructed lazily on first start() so daemons that don't
        # have the native crate installed never instantiate it.
        # Typed as Any because the FieldSnapshotManager import is also
        # lazy (avoids hard-import dependencies on the native wheel at
        # daemon module load).
        self._field_snapshot: Any = None
        # Phase E topology feeder task — pushes peer-graph updates
        # to the snapshot manager every 5s once start() runs.
        self._field_topology_feeder_task: Optional[asyncio.Task] = None
        # Phase A2 dual-stack QUIC endpoint. Stays None when ol_quic
        # isn't installed; transport_choice_for_peer() then keeps
        # every peer on WebRTC. Lazy-built in start().
        self._quic_endpoint: Any = None
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
        # v0.10.4 peer presence cache. peer_fp -> 'online' | 'away'
        # | 'dnd' | 'offline'. 'invisible' is never observed on the
        # wire — invisible peers report 'offline'. NOT persisted —
        # presence is transient (resets when the peer disconnects).
        self._peer_presence: dict[str, str] = {}
        # v0.7.0: per-pairing health metrics. Updated on every
        # successful send / receive. Surfaced in /api/peers so the
        # UI can show real "last alive" + latency instead of guessing
        # from mDNS visibility.
        # peer_fp -> {"last_alive_ms": int, "latency_ewma_ms": float}
        # Per-peer pair-health snapshot keyed by fingerprint. See the
        # ``_PairHealth`` TypedDict above for the field set.
        self._pair_health: dict[str, _PairHealth] = {}
        # v0.10.8: live route memory. Transfer outcomes feed this so
        # swarm planning can prefer routes that actually work for this
        # peer instead of static guesses.
        self._route_memory: dict[str, RouteMemory] = {}
        # v0.14.x: local transfer engine calibration. The route memory
        # learns which peer path is good; this learns which local engine
        # is actually fast on this computer right now.
        self._transfer_perf = TransferPerformanceOracle()
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
        v0.10.4: also carries our presence ('invisible' goes out as
        'offline' so peers can't tell we're online).
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
            presence=self._presence_for_wire(self.get_my_presence()),
        )

    def _presence_for_wire(self, status: str) -> str:
        clean = (status or "online").lower()
        if clean == "invisible":
            return "offline"
        return clean if clean in {"online", "away", "dnd", "offline"} else "online"

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
            elif sys.platform != "win32":
                # ``sys.platform != "win32"`` is a guard mypy
                # understands as a platform narrow — fcntl is then
                # resolvable from its real stub set.
                import fcntl

                try:
                    fcntl.flock(
                        f.fileno(),
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
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
            elif sys.platform != "win32":
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
        # v0.7.5: reply_to is a first-class column, not metadata.
        reply_to = (
            msg.get("reply_to")
            if isinstance(msg.get("reply_to"), str) else None
        )
        # v0.10.2 disappearing messages: if the wire frame carries
        # ttl_ms, compute expires_at_ms once and persist it. Reaper
        # tombstones the row when due. Outbound: send_text already
        # set ttl_ms from the peer's dm_ttl_ms. Inbound: honor
        # whatever the sender chose (matches their TTL window).
        expires_at_ms: Optional[int] = None
        ts_ms = int(msg["ts"])
        ttl_ms_raw = msg.get("ttl_ms")
        if isinstance(ttl_ms_raw, int) and ttl_ms_raw > 0:
            expires_at_ms = ts_ms + ttl_ms_raw
        # Store everything-except-the-canonical fields as metadata so we
        # round-trip cleanly for tests and history reads.
        canonical = {"t", "id", "ts", "body", "reply_to", "ttl_ms"}
        metadata = {
            **{k: v for k, v in msg.items() if k not in canonical},
            "short_id": peer_short_id,
        }
        if self.state is not None:
            try:
                self.state.record_message(
                    id=msg["id"],
                    ts_ms=ts_ms,
                    direction=direction,
                    peer_fp=peer_fp,
                    msg_type=msg["t"],
                    body=body,
                    room_id=msg.get("room_id"),
                    metadata=metadata,
                    reply_to=reply_to,
                    expires_at_ms=expires_at_ms,
                )
            except Exception as e:
                log.warning("state.record_message failed: %s", e)
        out = {**msg, "dir": direction, "peer": peer_short_id, "peer_fp": peer_fp}
        if reply_to:
            out["reply_to"] = reply_to
        if expires_at_ms is not None:
            out["expires_at_ms"] = expires_at_ms
        return out

    def _transfer_event(self, rec) -> dict:
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
            "metadata": rec.metadata,
        }
        return enrich_transfer_event(event, now_ms=int(time.time() * 1000))

    def _broadcast_transfer(self, rec) -> None:
        if self.ui_server is None or rec is None:
            return
        with contextlib.suppress(Exception):
            self.ui_server.broadcast({"type": "transfer", "transfer": self._transfer_event(rec)})

    DM_REAPER_INTERVAL_S = 30

    async def _dm_reaper_loop(self) -> None:
        """v0.10.2: tombstone expired disappearing messages every
        30s + broadcast msg_delete WS events so open tabs flip the
        bubbles in real time. Failures don't kill the loop."""
        while True:
            try:
                await asyncio.sleep(self.DM_REAPER_INTERVAL_S)
                if self.state is None:
                    continue
                expired_ids = self.state.expire_due_messages()
                if not expired_ids:
                    continue
                log.info("dm reaper: expired %d message(s)", len(expired_ids))
                if self.ui_server is not None:
                    now_ms = int(time.time() * 1000)
                    for mid in expired_ids:
                        with contextlib.suppress(Exception):
                            self.ui_server.broadcast({
                                "type": "msg_delete",
                                "target": mid,
                                "deleted_at_ms": now_ms,
                                "reason": "expired",
                            })
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("dm reaper loop error: %s", e)

    # v0.10.4 presence helpers ─────────────────────────────────────
    PRESENCE_VALUES = ("online", "away", "dnd", "invisible")

    def get_my_presence(self) -> str:
        if self.state is None:
            return "online"
        try:
            v = (self.state.get_setting("presence") or "online").lower()
            if v in self.PRESENCE_VALUES:
                return v
        except Exception:
            pass
        return "online"

    async def set_my_presence(self, status: str) -> str:
        """Persist + propagate the user's status. Broadcasts a
        PRESENCE wire frame to every open outbound session so
        paired peers update in real time. Returns the canonical
        (lowercased) status."""
        s = (status or "online").lower()
        if s not in self.PRESENCE_VALUES:
            raise ValueError(
                f"presence must be one of {self.PRESENCE_VALUES}"
            )
        if self.state is not None:
            with contextlib.suppress(Exception):
                self.state.set_setting("presence", s)
        wire_value = "offline" if s == "invisible" else s
        for peer_fp, sess in list(self._outbound_sessions.items()):
            with contextlib.suppress(Exception):
                async with sess.lock:
                    # Phase A2: route through PeerTransport facade.
                    await self._send_via_transport(
                        peer_fp,
                        sess.channel,
                        encode_msg(make_msg(
                            "PRESENCE", self.me.short_id,
                            presence=wire_value,
                        )),
                    )
        return s

    def record_peer_presence(
        self, peer_fp: str, presence: Optional[str],
    ) -> None:
        """Cache a peer's reported presence + broadcast peer_presence
        WS event so the UI updates the avatar dot. ``presence=None`` is
        treated as ``"online"`` so wire frames with a missing field
        fall through to the default."""
        if not peer_fp:
            return
        s = (presence or "online").lower()
        if s not in ("online", "away", "dnd", "offline"):
            return
        old = self._peer_presence.get(peer_fp)
        self._peer_presence[peer_fp] = s
        if old == s:
            return
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "peer_presence",
                    "fingerprint": peer_fp,
                    "presence": s,
                })

    def _apply_settings_at_boot(self) -> None:
        """v0.10.0: read settings that affect global daemon state +
        apply them once at startup. Lets the user keep their
        download_folder + log_level preferences across restarts.

        Each setting is wrapped in its own try so a malformed value
        from an older build doesn't take down the boot."""
        if self.state is None:
            return
        # Custom download folder. Re-validate at boot since the path
        # on disk may have moved / been deleted since the user set it.
        # On failure, fall back to default + log.
        with contextlib.suppress(Exception):
            from one_link.paths import set_inbox_override
            saved = self.state.get_setting("download_folder")
            if saved:
                from pathlib import Path as _Path
                p = _Path(saved)
                if p.is_dir() and os.access(p, os.W_OK):
                    set_inbox_override(p.resolve())
                    log.info("download folder override active: %s", p)
                else:
                    log.warning(
                        "download_folder setting %r is not a "
                        "writable directory; using default inbox",
                        saved,
                    )
        # Persisted log level.
        with contextlib.suppress(Exception):
            level = (self.state.get_setting("log_level") or "").lower()
            if level in ("error", "warn", "info", "debug"):
                import logging as _logging
                level_map = {
                    "error": _logging.ERROR, "warn": _logging.WARNING,
                    "info":  _logging.INFO,  "debug": _logging.DEBUG,
                }
                _logging.getLogger("one_link").setLevel(level_map[level])
        # v0.12.0: bandwidth + auto-accept cache.
        self.refresh_runtime_settings()

    def refresh_runtime_settings(self) -> None:
        """v0.12.0: re-read settings that the daemon caches in
        memory for hot-path use. Called at boot AND from
        UIServer.api_set_settings after the user saves, so changes
        apply live without a restart.

        Currently caches:
          - bandwidth_cap_kbps  (drives self.bandwidth_pacer)
          - auto_accept_max_size_mb
          - auto_accept_extensions
        """
        if self.state is None:
            return
        with contextlib.suppress(Exception):
            raw = self.state.get_setting("bandwidth_cap_kbps")
            cap = 0
            if raw:
                try:
                    cap = int(raw)
                except (TypeError, ValueError):
                    cap = 0
            self.bandwidth_pacer.set_cap(max(0, cap))
        with contextlib.suppress(Exception):
            raw = self.state.get_setting("auto_accept_max_size_mb")
            mb = 0
            if raw:
                try:
                    mb = int(raw)
                except (TypeError, ValueError):
                    mb = 0
            self._auto_accept_max_size_bytes = max(0, mb) * 1024 * 1024
        with contextlib.suppress(Exception):
            raw = self.state.get_setting("auto_accept_extensions") or ""
            self._auto_accept_extensions = {
                e.strip().lstrip(".").lower()
                for e in raw.split(",") if e.strip()
            }
        with contextlib.suppress(Exception):
            max_tb = self.state.get_setting("safety_max_file_tb")
            reserve_mb = self.state.get_setting("safety_min_free_mb")
            peer_active = self.state.get_setting("safety_peer_active_transfers")
            peer_bytes_gb = self.state.get_setting("safety_peer_active_gb")
            self._transfer_admission_policy = TransferAdmissionPolicy(
                max_declared_bytes=(
                    max(1, int(max_tb)) * 1024 * 1024 * 1024 * 1024
                    if max_tb else MAX_DECLARED_FILE_OFFER_BYTES
                ),
                min_free_reserve_bytes=(
                    max(256, int(reserve_mb)) * 1024 * 1024
                    if reserve_mb else TransferAdmissionPolicy().min_free_reserve_bytes
                ),
                max_active_inbound_transfers_per_peer=(
                    max(1, int(peer_active))
                    if peer_active
                    else TransferAdmissionPolicy().max_active_inbound_transfers_per_peer
                ),
                max_active_inbound_bytes_per_peer=(
                    max(1, int(peer_bytes_gb)) * 1024 * 1024 * 1024
                    if peer_bytes_gb
                    else TransferAdmissionPolicy().max_active_inbound_bytes_per_peer
                ),
            )

    def _file_passes_auto_accept(self, *, name: str, size: int) -> tuple[bool, str]:
        """v0.12.0: check the inbound file against the user's
        auto-accept rules. Returns (ok, reason). ok=False blocks
        the offer with the reason surfaced to the sender."""
        if self._auto_accept_max_size_bytes > 0 and size > self._auto_accept_max_size_bytes:
            return False, "exceeds_max_size"
        if self._auto_accept_extensions:
            ext = ""
            if "." in name:
                ext = name.rsplit(".", 1)[1].lower()
            if ext not in self._auto_accept_extensions:
                return False, "extension_blocked"
        return True, ""

    def _active_inbound_load_for_peer(self, peer_fp: str) -> tuple[int, int]:
        if self.state is None:
            return 0, 0
        count = 0
        total = 0
        with contextlib.suppress(Exception):
            for r in self.state.list_transfers(peer_fp=peer_fp, limit=500):
                if r.direction != "in" or r.status not in ("offered", "active", "queued"):
                    continue
                count += 1
                remaining = max(0, int(r.total_bytes or r.size or 0) - int(r.progress_bytes or 0))
                total += remaining
        return count, total

    def _transfer_admission_context(
        self,
        *,
        peer_fp: str,
        already_known_bytes: int = 0,
    ) -> TransferAdmissionContext:
        active_count, active_bytes = self._active_inbound_load_for_peer(peer_fp)
        return TransferAdmissionContext(
            incoming_dir=inbox_dir(),
            active_inbound_count_for_peer=active_count,
            active_inbound_bytes_for_peer=active_bytes,
            already_known_bytes=already_known_bytes,
        )

    async def _reject_file_offer(
        self,
        channel,
        msg: dict,
        *,
        peer_fp: str,
        name: str,
        size: int,
        blob: str | None,
        reason: str,
        user_message: str = "",
        metadata: dict | None = None,
    ) -> None:
        transfer_id = f"in:{blob}" if blob and self._valid_blob_hex(blob) else f"in:rejected:{uuid.uuid4().hex[:12]}"
        self._upsert_transfer(
            id=transfer_id,
            direction="in",
            peer_fp=peer_fp,
            kind="file",
            name=name,
            size=max(0, int(size or 0)),
            blob_hash=blob if blob and self._valid_blob_hex(blob) else None,
            status="failed",
            progress_bytes=0,
            total_bytes=max(0, int(size or 0)),
            chunks_done=0,
            chunks_total=0,
            metadata={
                "mode": "rejected",
                "delivery_state": "blocked",
                "error": reason,
                "error_class": "TransferAdmissionDenied",
                "user_message": user_message
                or "One Link blocked this file before any bytes were received.",
                "admission": metadata or {},
            },
        )
        await channel.send(encode_msg(make_msg(
            "ACK",
            self.me.short_id,
            of=msg.get("id"),
            rejected=f"admission_{reason}",
        )))

    def _on_folder_conflict(self, folder_name: str, conflict_id: int) -> None:
        """v0.8.9: invoked from foldersync.FolderEngine when a CRDT-
        detected divergent-edit conflict has just been logged. Reads
        the row out of state + broadcasts so the UI raises the
        Conflicts banner without waiting for a poll."""
        if self.ui_server is None or self.state is None:
            return
        with contextlib.suppress(Exception):
            row = self.state.get_manifest_conflict(conflict_id)
            if row is None:
                return
            self.ui_server.broadcast({
                "type": "folder_conflict_detected",
                "folder_name": folder_name,
                "conflict": row,
            })

    def _broadcast_key_change_if_present(self, peer_rec) -> None:
        """v0.7.8: if `state.upsert_peer` just detected a hostname-pubkey
        rotation, the returned PeerRecord has `_pending_key_change_event_id`
        attached. Broadcast a `key_change_detected` event so the UI raises
        the red banner without waiting for a poll."""
        if self.ui_server is None or peer_rec is None:
            return
        event_id = getattr(peer_rec, "_pending_key_change_event_id", None)
        if event_id is None:
            return
        if self.state is None:
            return
        with contextlib.suppress(Exception):
            events = self.state.list_key_change_events(limit=1)
            event = next((e for e in events if e["id"] == event_id), None)
            if event is None:
                return
            self.ui_server.broadcast({
                "type": "key_change_detected",
                "fingerprint": peer_rec.fingerprint,
                "event": event,
            })
            # Also nudge a peers_changed so /api/peers re-fetches with
            # the fresh `key_change_unacked` count.
            self.ui_server.broadcast({"type": "peers_changed"})

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

    def _mark_transfer_waiting(
        self,
        transfer_id: str,
        *,
        path: Path,
        error: str,
        error_class: str,
        base_metadata: dict | None = None,
    ):
        now_ms = int(time.time() * 1000)
        current = self.state.get_transfer(transfer_id) if self.state else None
        metadata = {
            **(base_metadata or {}),
            **((current.metadata if current else {}) or {}),
        }
        attempts = int(metadata.get("attempts") or 0) + 1
        metadata.update({
            "path": str(path),
            "error": str(error)[:500],
            "error_class": str(error_class)[:120],
            "transient": True,
            "paused_at_ms": now_ms,
            "last_attempt_ms": now_ms,
            "attempts": attempts,
            "next_retry_ms": now_ms + _delivery_backoff_ms(attempts),
            "delivery_state": "waiting_for_device",
        })
        diagnosis = diagnose_transfer({
            "status": "paused",
            "direction": "out",
            "metadata": metadata,
        }, now_ms=now_ms).to_dict()
        metadata.update({
            "doctor": diagnosis,
            "auto_action": diagnosis["action"],
            "user_message": diagnosis["user_message"],
        })
        return self._update_transfer(
            transfer_id,
            status="paused",
            metadata=metadata,
        )

    def queue_file_transfer(
        self,
        *,
        peer_fp: str,
        path: Path,
        reason: str = "peer offline",
    ):
        """Create the durable transfer intent before any live route exists."""
        if self.state is None:
            raise RuntimeError("state not available")
        rec = self.state.get_peer(peer_fp)
        if rec is None or rec.trust != "pinned":
            raise RuntimeError("file queue requires a pinned peer")
        path = Path(path)
        size = path.stat().st_size
        file_index = index_path(path)
        transfer_id = f"out:{file_index.blob_hash}:{uuid.uuid4().hex[:12]}"
        now_ms = int(time.time() * 1000)
        queued = self._upsert_transfer(
            id=transfer_id,
            direction="out",
            peer_fp=peer_fp,
            kind="file",
            name=path.name,
            size=size,
            blob_hash=file_index.blob_hash,
            status="paused",
            progress_bytes=0,
            total_bytes=size,
            chunks_done=0,
            chunks_total=len(file_index.chunks),
            metadata={
                "mode": "cdc",
                "path": str(path),
                "queued_at_ms": now_ms,
                "paused_at_ms": now_ms,
                "attempts": 0,
                "next_retry_ms": now_ms,
                "transient": True,
                "delivery_state": "waiting_for_device",
                "error": reason,
                "error_class": "PeerOffline",
            },
        )
        if queued is not None:
            diag = diagnose_transfer(queued, now_ms=now_ms).to_dict()
            self._update_transfer(
                queued.id,
                metadata={
                    **(queued.metadata or {}),
                    "doctor": diag,
                    "auto_action": diag["action"],
                    "user_message": diag["user_message"],
                },
            )
        self._schedule_resume_paused(peer_fp)
        return queued

    def _mark_due_transfers_waiting_for_peer(
        self,
        peer_fp: str,
        *,
        reason: str,
        error_class: str,
    ) -> int:
        """Back off due outbound intents for a peer that is not sendable.

        This keeps the background queue quiet: an offline peer should not
        trigger scary errors or tight retry loops; the durable rows remain
        Waiting and the next backoff window/session-up will try again.
        """
        if self.state is None:
            return 0
        now_ms = int(time.time() * 1000)
        try:
            rows = self.state.list_transfers(peer_fp=peer_fp, limit=200)
        except Exception:
            return 0
        marked = 0
        for r in rows:
            if r.direction != "out" or r.status not in ("paused", "queued"):
                continue
            meta = r.metadata or {}
            if int(meta.get("next_retry_ms") or 0) > now_ms:
                continue
            self._mark_transfer_waiting(
                r.id,
                path=Path(meta.get("path") or r.name),
                error=reason,
                error_class=error_class,
                base_metadata=meta,
            )
            marked += 1
        return marked

    # v0.6.3: transfer-ledger watchdog.
    STUCK_TRANSFER_DEADLINE_MS = 5 * 60 * 1000  # 5 min without progress
    STUCK_TRANSFER_PLANNING_DEADLINE_MS = 2 * 60 * 1000

    def _reap_stuck_transfers(self) -> int:
        """Mark any stale active transfer as paused/retryable if it
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
            meta = t.metadata or {}
            if t.status == "queued" and meta.get("mode") == "planning":
                planning_cutoff = now_ms - self.STUCK_TRANSFER_PLANNING_DEADLINE_MS
                if t.updated_ms > planning_cutoff:
                    continue
                src_path = Path(meta.get("path") or t.name)
                if not src_path.is_file():
                    self._update_transfer(
                        t.id,
                        status="failed",
                        metadata={
                            **meta,
                            "error": f"source file no longer exists: {src_path}",
                            "error_class": "FileNotFoundError",
                            "transient": False,
                            "delivery_state": "needs_attention",
                            "reaped": True,
                            "reaped_reason": "planning_source_missing",
                            "reaped_at_ms": now_ms,
                        },
                    )
                    reaped += 1
                    continue
                self._mark_transfer_waiting(
                    t.id,
                    path=src_path,
                    error="send was interrupted before transfer started; resuming automatically",
                    error_class="PlanningInterrupted",
                    base_metadata={
                        **meta,
                        "reaped": True,
                        "reaped_reason": "stale_planning_row",
                        "reaped_at_ms": now_ms,
                    },
                )
                reaped += 1
                continue
            if t.status not in ("offered", "active"):
                continue
            if t.updated_ms > cutoff:
                continue
            try:
                self._mark_transfer_waiting(
                    t.id,
                    path=Path(meta.get("path") or t.name),
                    error="transfer stalled; waiting to resume automatically",
                    error_class="StalledTransfer",
                    base_metadata={
                        **meta,
                        "reaped": True,
                        "reaped_reason": "no_progress_within_deadline",
                        "reaped_at_ms": now_ms,
                    },
                )
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
        # v0.20.7 (security audit M8): refuse fast at the global
        # concurrent-peer ceiling. Counter-based; asyncio is single-
        # threaded so check-then-increment is atomic. The counter
        # increments only after the cap check passes, so the limit
        # is observed even under burst arrival.
        if self._inbound_peer_count >= MAX_TOTAL_PEER_CONNECTIONS:
            log.warning(
                "peer connection refused: global cap %d reached",
                MAX_TOTAL_PEER_CONNECTIONS,
            )
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            return
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
            except asyncio.IncompleteReadError as e:
                if not e.partial:
                    log.debug("empty pre-handshake disconnect from %s", addr)
                else:
                    log.warning("handshake failed from %s: %s", addr, e)
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
        # v0.20.7 (security audit M8): per-fp cap. Defends against a
        # single peer key opening many parallel inbound channels to
        # crowd the global cap. Strict cap; refuse fast.
        existing_for_fp = self._inbound_per_fp.get(peer_fp, 0)
        if existing_for_fp >= MAX_PEER_CONNECTIONS_PER_FP:
            log.warning(
                "peer %s already has %d inbound channels (cap %d); refusing",
                peer_fp[:8], existing_for_fp, MAX_PEER_CONNECTIONS_PER_FP,
            )
            await channel.close()
            return
        # v0.20.7 (security audit M8): increment counters AFTER all
        # the early-return paths. The recv-loop's finally decrements
        # both. Handshake-failure paths above don't touch counters,
        # which means a flood of handshake-failures still doesn't
        # leak counter slots.
        self._inbound_peer_count += 1
        self._inbound_per_fp[peer_fp] = existing_for_fp + 1
        if self.state is not None:
            try:
                hostname: str | None = None
                if self.discovery:
                    pinfo = self.discovery.registry.find(channel.peer_short_id)
                    if pinfo:
                        hostname = pinfo.hostname
                rec = self.state.upsert_peer(
                    fingerprint=peer_fp,
                    short_id=channel.peer_short_id,
                    pubkey=channel.peer_ed_pub,
                    hostname=hostname,
                    address=addr[0] if addr else None,
                    port=addr[1] if addr else None,
                )
                # v0.7.8: if upsert_peer just detected a hostname-pubkey
                # rotation, the returned record carries the new event id
                # as a runtime attribute. Broadcast it live so every
                # open tab raises the red banner without waiting for
                # the next /api/peers poll.
                self._broadcast_key_change_if_present(rec)
            except Exception as e:
                log.warning("upsert_peer failed: %s", e)

        # Send our capabilities eagerly (no ACK expected).
        try:
            await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
            # v0.8.2: ratchet-activation half-step. Once we've also
            # received the peer's CAPS we'll flip both directions.
            channel.note_caps_sent()
            channel.maybe_activate_ratchet()
        except Exception as e:
            log.warning("CAPS send failed: %s", e)

        try:
            while True:
                try:
                    # v0.20.7 (security audit H4): bounded read deadline.
                    # A peer that holds the channel open with no further
                    # bytes after handshake exits the loop here instead
                    # of pinning fds forever.
                    plaintext = await asyncio.wait_for(
                        channel.recv(), timeout=PEER_IDLE_S
                    )
                except asyncio.IncompleteReadError:
                    break
                except asyncio.TimeoutError:
                    log.info(
                        "peer %s idle for %.0fs, closing channel",
                        channel.peer_short_id, PEER_IDLE_S,
                    )
                    break
                if plaintext.startswith(BINARY_FRAME_MAGIC):
                    msg = _decode_binary_frame(plaintext)
                else:
                    msg = decode_msg(plaintext)
                await self._on_peer_message(channel, msg)
        except Exception as e:
            log.warning("peer loop error (%s): %s", channel.peer_short_id, e)
        finally:
            await channel.close()
            log.info("peer disconnected: %s", channel.peer_short_id)
            # v0.20.7 (security audit M8): decrement counters that
            # were incremented after the rejected-check above. Both
            # decrements are guarded against the (impossible-in-
            # practice) negative-counter case to keep the daemon
            # resilient against any future ordering bug.
            if self._inbound_peer_count > 0:
                self._inbound_peer_count -= 1
            current_fp_count = self._inbound_per_fp.get(peer_fp, 0)
            if current_fp_count <= 1:
                self._inbound_per_fp.pop(peer_fp, None)
            else:
                self._inbound_per_fp[peer_fp] = current_fp_count - 1

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
        if t == "PRESENCE":
            self.record_peer_presence(peer_fp, msg.get("presence"))
            return
        if t == "CAPS":
            # v0.20.7 (security audit M18): intersect peer-claimed
            # features with our LOCAL_CAPABILITIES so an attacker
            # can't poison state with arbitrary feature strings
            # (e.g. claim "admin" / "grant_files" / "root_share")
            # that future code might key off. We only persist
            # features WE recognize. Backward-compat: peers
            # advertising a future capability we haven't shipped
            # yet are silently ignored — they'll keep working
            # against the subset of caps that are common.
            raw_features = list(normalize_caps(msg.get("features", [])))
            features = [
                f for f in raw_features
                if f in LOCAL_CAPABILITIES or f in CAPS_FEATURES
            ]
            bind = msg.get("channel_bind")
            # v0.20.7 (security audit H1): channel_bind is REQUIRED.
            # The v0.7.0 audit fix #10 added a transcript-bound CAPS
            # claim to defeat channel-splicing / cross-session glue
            # attacks. The receiver previously verified the claim only
            # if present (`if isinstance(bind, dict)`), so a malicious
            # peer could omit it and silently land on the pre-fix-#10
            # acceptance path. Pre-v0.7.0 peers (which last shipped
            # ~6+ months ago) must upgrade to communicate with a v0.20.7
            # daemon. This is a deliberate compat break for security.
            if not isinstance(bind, dict):
                raise RuntimeError(
                    f"CAPS missing channel_bind from {peer_fp[:8]} "
                    f"(peer must upgrade to v0.7.0+)"
                )
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
                # v0.20.7: bind is now guaranteed-dict (checked above).
                "channel_bind": bind,
                "app_version": msg.get("app_version"),
                "presence": msg.get("presence"),
            }
            self.record_peer_presence(peer_fp, msg.get("presence"))
            # v0.8.2: ratchet-activation half-step. Once we've also
            # SENT our CAPS we'll flip both directions to ratchet.
            with contextlib.suppress(Exception):
                channel.note_caps_received(features)
                if channel.maybe_activate_ratchet():
                    log.info(
                        "ratchet activated on inbound channel from %s",
                        peer_fp[:8],
                    )
            # v0.10.4: peer's reported presence drives the UI dot.
            if msg.get("presence"):
                self.record_peer_presence(peer_fp, msg.get("presence"))
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
        if t == "PRESENCE":
            # v0.10.4: peer reported a status change. No ACK needed.
            self.record_peer_presence(peer_fp, str(msg.get("presence") or ""))
            return
        if t == "CAPABILITY_GRANT":
            # Bundle 58: peer ships a signed capability grant over the
            # established channel. Receiver verifies + accepts into
            # _cap_store; subsequent _capability_allowed checks
            # consult the store. The grant authorizes the SENDER (us)
            # to perform actions against the SENDING peer's resources.
            #
            # Wire shape: { "t": "CAPABILITY_GRANT", "id": <id>,
            #               "grant_b64": "<base64 caps_grants record>" }
            # NB: do NOT use a local ``import base64`` here — base64 is
            # already imported at module level and shadowing it would
            # cause UnboundLocalError on FILE_CHUNK handling later in
            # the same function (Python's local-name analysis).
            try:
                grant_b64 = msg.get("grant_b64", "")
                if not isinstance(grant_b64, str) or not grant_b64:
                    raise ValueError("grant_b64 missing or wrong type")
                # Local-name distinct from the FILE_OFFER ``blob``
                # below so mypy's type inference for the outer scope
                # doesn't collide.
                grant_blob = base64.urlsafe_b64decode(
                    grant_b64 + "=" * (-len(grant_b64) % 4)
                )
                self._cap_store.accept(
                    grant_blob,
                    expected_subject_pub=self.me.public_bytes,
                    expected_granter_pub=channel.peer_ed_pub,
                )
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"), ok=True,
                )))
                log.info(
                    "accepted capability grant from %s (active grants: %d)",
                    peer_fp[:8], len(self._cap_store),
                )
            except Exception as e:
                log.warning(
                    "rejected capability grant from %s: %s",
                    peer_fp[:8], e,
                )
                with contextlib.suppress(Exception):
                    await channel.send(encode_msg(make_msg(
                        "ACK", self.me.short_id, of=msg.get("id"),
                        rejected=f"grant_rejected: {e}",
                    )))
            return
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
            blob = str(msg.get("blob") or "")
            if not self._valid_blob_hex(blob):
                await self._reject_file_offer(
                    channel,
                    msg,
                    peer_fp=peer_fp,
                    name=self._safe_transfer_name(msg.get("name")),
                    size=0,
                    blob=None,
                    reason="invalid_blob",
                    user_message="One Link blocked a file offer with an invalid file fingerprint.",
                )
                return
            size = self._safe_transfer_size(msg.get("size"))
            name = self._safe_transfer_name(msg.get("name"))
            if size is None:
                await self._reject_file_offer(
                    channel,
                    msg,
                    peer_fp=peer_fp,
                    name=name,
                    size=0,
                    blob=blob,
                    reason="invalid_size",
                    user_message="One Link blocked a file offer with an invalid size.",
                )
                return
            # v0.12.0: auto-accept rules. If the user has configured
            # a max size or extension allowlist and this file fails
            # them, ACK with the rejection reason and don't open a
            # write handle. The sender sees the rejection and the
            # user can loosen their filter to retry.
            passed, reason = self._file_passes_auto_accept(name=name, size=size)
            if not passed:
                log.info(
                    "auto-accept reject: %s (%d bytes) reason=%s",
                    name, size, reason,
                )
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg["id"],
                    rejected=f"auto_accept_{reason}",
                )))
                return
            raw_chunks = msg.get("chunks")
            chunks_were_advertised = raw_chunks is not None
            cdc_chunks = self._normalize_cdc_chunks(raw_chunks, declared_size=size)
            if chunks_were_advertised and cdc_chunks is None:
                await self._reject_file_offer(
                    channel,
                    msg,
                    peer_fp=peer_fp,
                    name=name,
                    size=size,
                    blob=blob,
                    reason="invalid_chunk_map",
                    user_message="One Link blocked a file offer with an invalid resumable chunk map.",
                )
                return
            missing = None
            swarm_assist: dict = {"pulled": 0, "sources": {}}
            known_hashes: set[str] = set()
            already_known_bytes = 0
            if cdc_chunks:
                known_hashes = set(self._available_chunk_hashes(
                    [str(c["hash"]) for c in cdc_chunks],
                    hydrate=False,
                    limit=len(cdc_chunks),
                ))
                already_known_bytes = known_bytes_from_chunks(cdc_chunks, known_hashes)
                missing = {
                    int(c["index"]) for c in cdc_chunks
                    if str(c["hash"]) not in known_hashes
                }
            admission = evaluate_transfer_admission(
                name=name,
                size=size,
                peer_fp=peer_fp,
                policy=self._transfer_admission_policy,
                context=self._transfer_admission_context(
                    peer_fp=peer_fp,
                    already_known_bytes=already_known_bytes,
                ),
            )
            if not admission.ok:
                await self._reject_file_offer(
                    channel,
                    msg,
                    peer_fp=peer_fp,
                    name=name,
                    size=size,
                    blob=blob,
                    reason=admission.wire_reason(),
                    user_message=admission.user_message,
                    metadata=admission.to_metadata(),
                )
                return
            if size > MAX_INCOMING_FILE_BYTES and not cdc_chunks:
                await self._reject_file_offer(
                    channel,
                    msg,
                    peer_fp=peer_fp,
                    name=name,
                    size=size,
                    blob=blob,
                    reason="stream_offer_too_large",
                    user_message=(
                        "One Link needs a resumable chunk map before accepting a file this large."
                    ),
                )
                return
            # v0.20.7 (security audit H16): open with exclusive-create
            # against a uniquified path so a name + blob-prefix
            # collision can't truncate an existing inbox file.
            out_path = self._unique_inbox_path(blob, name)
            handle = open(out_path, "xb")
            if cdc_chunks:
                if missing:
                    missing, swarm_assist = await self._swarm_assist_file_offer(
                        sender_fp=peer_fp,
                        name=name,
                        size=size,
                        blob=blob,
                        cdc_chunks=cdc_chunks,
                        missing=missing,
                    )
            transfer_id = f"in:{blob}"
            self._incoming_files[blob] = IncomingFile(
                name=name,
                size=size,
                blob_hex=blob,
                out_path=out_path,
                handle=handle,
                # blake3 lacks PEP-561 stubs; the runtime hasher
                # exposes update/hexdigest exactly per _HasherProtocol.
                # ``cast`` documents the contract for the type
                # checker without bypassing it.
                hasher=cast(_HasherProtocol, blake3.blake3()),
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
                    "swarm_assist": swarm_assist,
                    "admission": admission.to_metadata(),
                    "file_risk": classify_file_risk(name),
                },
            )
            log.info(
                "file offer: %s (%d bytes) blob=%s from %s",
                name, msg["size"], blob[:8], peer_sid,
            )
            ev = self._persist(msg=msg, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            if cdc_chunks is not None:
                # Phase B Bloom-init honor mode: when ONE_LINK_BLOOM_HONOR=1
                # AND peer advertises BLOOM_INIT_V1 AND native crate is
                # available, drop the FILE_WANTS list and rely on the
                # accompanying BLOOM_INIT_FILTER for chunk dispatch. The
                # sender + receiver still run an integrity-check-and-
                # recover round at transfer end to catch the rare
                # false-positive-induced miss. When the env flag is off
                # (the default), both messages fly and FILE_WANTS stays
                # canonical.
                use_bloom_only = self._bloom_only_for_peer(peer_fp)
                if not use_bloom_only:
                    await channel.send(encode_msg(make_msg(
                        "FILE_WANTS", self.me.short_id,
                        of=msg["id"], blob=blob, wants=sorted(missing or []),
                    )))
                await self._maybe_send_bloom_init_advisory(
                    channel, msg_id=msg["id"], blob=blob, peer_fp=peer_fp
                )
                if not missing:
                    self._schedule_finish_cdc_file(blob, peer_fp, peer_sid, msg)
            else:
                await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "FILE_CHUNK":
            blob = str(msg["blob"])
            f = self._incoming_files.get(blob)
            if not f:
                log.warning("FILE_CHUNK with no offer: %s", blob[:8])
                return
            # v0.20.7 (security audit H15 / H17): re-check pinned +
            # files capability on every chunk, not just at FILE_OFFER.
            # Without this, a user revoking files mid-transfer leaves
            # the IncomingFile entry intact and chunks keep landing
            # on disk; the rejection becomes effective only on the
            # next FILE_OFFER.
            if not self._capability_allowed(peer_fp, FILES):
                self._abort_incoming_file(blob, f)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="capability_revoked_mid_stream",
                )))
                return
            try:
                seq = int(msg.get("seq", -1))
            except (TypeError, ValueError, OverflowError):
                self._abort_incoming_file(blob, f)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"), rejected="bad_file_chunk_sequence",
                )))
                return
            if seq != f.next_seq:
                self._abort_incoming_file(blob, f)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"), rejected="file_chunk_sequence_mismatch",
                )))
                return
            try:
                data = base64.b64decode(msg["data"], validate=True)
            except (binascii.Error, ValueError) as e:
                self._abort_incoming_file(blob, f)
                log.warning("invalid FILE_CHUNK base64 from %s: %s", peer_sid, e)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"), rejected="bad_file_chunk_data",
                )))
                return
            if f.received + len(data) > f.size:
                self._abort_incoming_file(blob, f)
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"), rejected="file_chunk_size_overrun",
                )))
                return
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
                    "file_risk": classify_file_risk(f.name),
                }
                ev = self._persist(msg=done, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
                self._broadcast_tail(ev)
                self._incoming_files.pop(blob, None)
                if not ok:
                    with contextlib.suppress(OSError):
                        f.out_path.unlink()
                    self._update_transfer(f.transfer_id, status="failed")
                else:
                    self._update_transfer(
                        f.transfer_id,
                        status="complete",
                        progress_bytes=f.size,
                        total_bytes=f.size,
                    )
                log.info("file done: %s ok=%s -> %s", f.name, ok, f.out_path)
                await self._ack_file_chunk(channel, msg, f, force_individual=True)
                if ok:
                    self._cache_file_chunks(f.out_path)
                    # Phase D #3: observe successful receive in prefetch
                    # predictor so the warm-cache model sees both ends
                    # of every transfer.
                    self._observe_prefetch(peer_fp, f.blob_hex)
                return
            await self._ack_file_chunk(channel, msg, f)
        elif t == "FILE_BIN_CHUNK":
            await self._handle_file_binary_chunk(channel, msg, peer_fp, peer_sid)
        elif t == "FILE_NATIVE_CHUNK":
            # Phase C-3 (ADR-0026): native chunk-store transport.
            await self._handle_file_native_chunk(channel, msg, peer_fp, peer_sid)
        elif t == "FILE_CDC_CHUNK":
            await self._handle_file_cdc_chunk(channel, msg, peer_fp, peer_sid)
        elif t == "CHUNK_QUERY":
            await self._handle_chunk_query(channel, msg, peer_fp)
        elif t == "CHUNK_PULL":
            await self._handle_chunk_pull(channel, msg, peer_fp)
        elif t == "GROUP_EVENT":
            # v0.8.0: peer is sending us a CRDT GroupEvent (create,
            # add_member, remove_member, change_role, rename, leave).
            # We persist via state.upsert_group_event after signature
            # verification; reduce_events runs lazily on next state
            # materialization. UI broadcasts a `group_event` so it
            # can refresh the groups list / conversation membership.
            if not self._is_pinned(peer_fp):
                return
            event_wire = msg.get("event")
            if not isinstance(event_wire, dict):
                return
            try:
                from one_link import groups as gmod
                group_ev = gmod.GroupEvent.from_wire(event_wire)
            except Exception as e:
                log.warning("malformed GROUP_EVENT from %s: %s", peer_fp[:8], e)
                return
            # Verify signature. group_ev.verify() raises ValueError on
            # bad signature; treat any exception as untrusted.
            try:
                group_ev.verify()
            except Exception as e:
                log.warning(
                    "GROUP_EVENT signature failed: from=%s peer=%s: %s",
                    group_ev.author_pubkey.hex()[:8], peer_fp[:8], e,
                )
                return
            if self.state is not None:
                with contextlib.suppress(Exception):
                    self.state.upsert_group_event(
                        group_id=group_ev.group_id,
                        event_id=group_ev.event_id,
                        timestamp_ms=group_ev.timestamp_ms,
                        wire_dict=group_ev.to_wire(),
                    )
                # Bump the cached group_meta name so the sidebar
                # reflects the latest reduce result without forcing
                # the UI to recompute.
                with contextlib.suppress(Exception):
                    gstate = self._group_state_for(group_ev.group_id)
                    if gstate is not None:
                        self.state.upsert_group_meta(
                            group_id=group_ev.group_id,
                            name=gstate.name or "",
                            created_ms=int(time.time() * 1000),
                            state_hash="",
                        )
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "group_event",
                        "group_id": group_ev.group_id.hex(),
                        "event_kind": group_ev.kind,
                    })
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
            )))
        elif t == "GROUP_KEY_OFFER":
            await self._handle_group_key_offer(channel, msg, peer_fp)
        elif t == "GROUP_MSG":
            await self._handle_group_msg(channel, msg, peer_fp, peer_sid)
        elif t == "ENDPOINT_UPDATE":
            await self._handle_endpoint_update(channel, msg, peer_fp, peer_sid)
        elif t == "BLOOM_INIT_FILTER":
            # Phase B advisory: receiver advertised its locally-held
            # chunk set as a Bloom. Sender logs the savings potential
            # for telemetry. The canonical chunk dispatch still flows
            # through FILE_WANTS (which arrived alongside this frame).
            # Future cutover: flip to honor the Bloom and drop the
            # FILE_WANTS list from BLOOM_INIT_V1 peers.
            await self._handle_bloom_init_advisory(channel, msg, peer_fp)
        elif t == "REACTION":
            # v0.7.5: emoji reaction frame. {target, emoji, op}.
            # Only pinned peers can react against our messages, since
            # accepting reactions from strangers would surface their
            # short_id in our UI without prior trust.
            if not self._is_pinned(peer_fp):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="not_pinned",
                )))
                return
            target = str(msg.get("target") or "")
            emoji = str(msg.get("emoji") or "")
            op = str(msg.get("op") or "add")
            if not target or not emoji or op not in ("add", "remove"):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="bad_reaction",
                )))
                return
            if self.state is not None:
                try:
                    if op == "add":
                        self.state.record_reaction(
                            target_msg_id=target, peer_fp=peer_fp, emoji=emoji,
                        )
                    else:
                        self.state.remove_reaction(
                            target_msg_id=target, peer_fp=peer_fp, emoji=emoji,
                        )
                except Exception as e:
                    log.warning("record_reaction failed: %s", e)
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "reaction",
                        "target": target, "peer_fp": peer_fp,
                        "emoji": emoji, "op": op,
                    })
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
            )))
        elif t == "EDIT_MSG":
            # v0.7.6: peer is editing one of THEIR previously-sent messages.
            # We only honour edits from pinned peers. Server-side EDIT_COOLDOWN_S
            # bound is enforced; older edits are dropped.
            if not self._is_pinned(peer_fp):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="not_pinned",
                )))
                return
            target = str(msg.get("target") or "")
            new_body = msg.get("body")
            edited_at = int(msg.get("edited_at_ms") or 0) or int(time.time() * 1000)
            if not target or not isinstance(new_body, str):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="bad_edit",
                )))
                return
            # Cooldown: only allow edit within 5 minutes of original ts.
            if self.state is not None:
                tgt = self.state.get_message(target)
                if tgt is None:
                    await channel.send(encode_msg(make_msg(
                        "ACK", self.me.short_id, of=msg.get("id"),
                        rejected="unknown_target",
                    )))
                    return
                if tgt.peer_fp != peer_fp:
                    # Peers can only edit their own messages.
                    await channel.send(encode_msg(make_msg(
                        "ACK", self.me.short_id, of=msg.get("id"),
                        rejected="not_author",
                    )))
                    return
                if edited_at - tgt.ts_ms > EDIT_COOLDOWN_MS:
                    await channel.send(encode_msg(make_msg(
                        "ACK", self.me.short_id, of=msg.get("id"),
                        rejected="cooldown",
                    )))
                    return
                with contextlib.suppress(Exception):
                    self.state.edit_message(
                        id=target, new_body=new_body, edited_at_ms=edited_at,
                    )
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "msg_edit",
                        "target": target,
                        "body": new_body,
                        "edited_at_ms": edited_at,
                    })
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
            )))
        elif t == "DELETE_MSG":
            if not self._is_pinned(peer_fp):
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="not_pinned",
                )))
                return
            target = str(msg.get("target") or "")
            deleted_at = int(msg.get("deleted_at_ms") or 0) or int(time.time() * 1000)
            if not target:
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg.get("id"),
                    rejected="bad_delete",
                )))
                return
            if self.state is not None:
                tgt = self.state.get_message(target)
                if tgt is None or tgt.peer_fp != peer_fp:
                    await channel.send(encode_msg(make_msg(
                        "ACK", self.me.short_id, of=msg.get("id"),
                        rejected="not_author",
                    )))
                    return
                with contextlib.suppress(Exception):
                    self.state.delete_message(
                        id=target, deleted_at_ms=deleted_at,
                    )
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "msg_delete",
                        "target": target,
                        "deleted_at_ms": deleted_at,
                    })
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
            )))
        elif t == "TYPING":
            # v0.12.3: ephemeral "peer is typing" indicator.
            # Pinned-only — strangers can't poke our UI.
            # Capped expiry at 10s (the wire claims 5s; we cap to
            # avoid a malicious peer setting expires_in_ms = MAX
            # to lock the indicator on forever).
            if not self._is_pinned(peer_fp):
                return
            # Honor the local display privacy toggle: if off, we
            # silently drop the WS broadcast so the UI never shows
            # the indicator. We still cache the deadline so other
            # internal consumers (notification suppression, etc.)
            # can read it later.
            display_on = True
            if self.state is not None:
                with contextlib.suppress(Exception):
                    v = self.state.get_setting("display_typing_indicators")
                    if v is not None and v != "true":
                        display_on = False
            try:
                expires_in_ms = int(msg.get("expires_in_ms") or 5000)
            except (TypeError, ValueError):
                expires_in_ms = 5000
            expires_in_ms = max(0, min(10_000, expires_in_ms))
            now_ms = int(time.time() * 1000)
            self._peer_typing[peer_fp] = now_ms + expires_in_ms
            if display_on and self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "peer_typing",
                        "peer_fp": peer_fp,
                        "expires_at_ms": now_ms + expires_in_ms,
                    })
        elif t == "READ_MARKER":
            # v0.7.6: peer reports they've read up to ts X.
            # Pinned-only — receipts from strangers leak nothing
            # useful to us and could be a flood vector otherwise.
            if not self._is_pinned(peer_fp):
                return
            up_to = int(msg.get("up_to_ts_ms") or 0)
            if up_to <= 0:
                return
            # We track THEIR read marker so the UI can render
            # ✓✓ next to OUR messages with ts ≤ up_to.
            # Stored in the same peer_read_markers table keyed
            # by peer_fp; flips role here intentionally.
            if self.state is not None:
                with contextlib.suppress(Exception):
                    self.state.record_read_marker(peer_fp, up_to)
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "read_marker",
                        "peer_fp": peer_fp,
                        "up_to_ts_ms": up_to,
                    })
        elif t == "PING":
            await channel.send(encode_msg(make_msg("PONG", self.me.short_id)))
        elif t == "PAIR_REQUEST":
            # Peer wants to pair with us. Compute the SAS bound to the
            # channel's transcript_hash (audit fix H11) and store as
            # incoming, surface to UI for the user to verify.
            transcript = getattr(channel, "transcript_hash", None)
            sas = compute_sas(
                self.me.public_bytes,
                channel.peer_ed_pub,
                transcript_hash=transcript,
            )
            # v0.20.7 (security audit M20): if we previously rejected
            # this peer, set the previously_rejected flag so the UI
            # surfaces a "previously blocked" warning before the user
            # clicks Match.
            previously_rejected = False
            if self.state is not None:
                try:
                    rec = self.state.get_peer(peer_fp)
                    previously_rejected = bool(rec and rec.trust == "rejected")
                except Exception:
                    previously_rejected = False
            ctx = self.pairing.get(peer_fp)
            # v0.20.7 (security audit H12): treat an expired ctx as
            # absent so a stale "Match" prompt that the user ignored
            # earlier doesn't carry over and bypass the fresh ceremony.
            if (
                ctx is None
                or ctx.state in (PairState.NONE, PairState.PAIRED, PairState.REJECTED)
                or ctx.is_expired()
            ):
                ctx = self.pairing.begin(
                    peer_fp=peer_fp, sas=sas, incoming=True,
                    previously_rejected=previously_rejected,
                )
            if self.ui_server is not None:
                self.ui_server.broadcast({
                    "type": "pair_request",
                    "peer_fp": peer_fp,
                    "peer_short_id": peer_sid,
                    "sas": sas,
                    "previously_rejected": previously_rejected,
                })
            log.info("PAIR_REQUEST from %s sas=%s ctx.state=%s",
                     peer_sid, sas, ctx.state.value)
            # ACK so the sender can close the connection cleanly.
            await channel.send(encode_msg(make_msg("ACK", self.me.short_id, of=msg["id"])))
        elif t == "PAIR_CONFIRM":
            # Peer says SAS matched on their side.
            ctx = self.pairing.they_confirm(peer_fp)
            if ctx is None or (ctx is not None and ctx.is_expired()):
                # v0.20.7 (security audit H11 + H12): no live ctx (or
                # the ctx is past its TTL). The legacy fallback used
                # to silently fabricate a v1 SAS and begin a new ctx
                # with they_confirmed=True; with v2 SAS bound to the
                # transcript_hash, that fallback would display a
                # different code than what the peer's side computed
                # and the user would (correctly) see a mismatch.
                # Refuse instead so the user retries pair from
                # scratch with a fresh ceremony.
                log.warning(
                    "PAIR_CONFIRM refused: no live pair context for %s",
                    peer_sid,
                )
                await channel.send(encode_msg(make_msg(
                    "ACK", self.me.short_id, of=msg["id"],
                    rejected="no_live_pair_context",
                )))
                return
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

    def _safe_transfer_size(self, value) -> int | None:
        try:
            size = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return size if size >= 0 else None

    # v0.20.7 (security audit H16): Windows treats these as device
    # paths, opening "CON", "NUL", or "COM1" yields the console /
    # null / serial port instead of a real file. Reject by
    # case-folded stem.
    _WINDOWS_RESERVED_BASENAMES: frozenset[str] = frozenset({
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
        "LPT6", "LPT7", "LPT8", "LPT9",
    })

    def _safe_transfer_name(self, value) -> str:
        name = Path(str(value or "")).name
        if not name or name in (".", ".."):
            return "unnamed.bin"
        # v0.20.7 (security audit H16):
        #   - Reject NUL + control chars (0x00-0x1f, 0x7f).
        #   - Reject trailing dots and spaces (Windows silently strips
        #     them, so "report.pdf." collides with "report.pdf").
        #   - Reject Windows reserved device names (CON, NUL, COM1-9,
        #     LPT1-9, AUX, PRN). Match by stem so "CON.txt" is also
        #     rejected — Windows treats the device-name stem as the
        #     reserved meaning even with an extension.
        clean = name.replace("\x00", "").rstrip(". ")
        if not clean:
            return "unnamed.bin"
        if any(0 <= ord(c) <= 0x1f or ord(c) == 0x7f for c in clean):
            clean = "".join(
                c for c in clean
                if not (0 <= ord(c) <= 0x1f or ord(c) == 0x7f)
            )
            if not clean:
                return "unnamed.bin"
        stem = Path(clean).stem
        if stem.upper() in self._WINDOWS_RESERVED_BASENAMES:
            clean = "_" + clean
        encoded = clean.encode("utf-8", errors="ignore")
        if len(encoded) <= MAX_TRANSFER_FILE_NAME_BYTES:
            return clean
        # Preserve the extension when clipping by total byte length so
        # a long-prefix attacker can't collide on the trimmed name.
        suffix = Path(clean).suffix.encode("utf-8", errors="ignore")
        if 0 < len(suffix) < MAX_TRANSFER_FILE_NAME_BYTES // 2:
            stem_budget = MAX_TRANSFER_FILE_NAME_BYTES - len(suffix)
            stem_bytes = encoded[:stem_budget]
            clipped = (
                stem_bytes.decode("utf-8", errors="ignore").rstrip()
                + suffix.decode("utf-8", errors="ignore")
            )
        else:
            clipped = encoded[:MAX_TRANSFER_FILE_NAME_BYTES].decode(
                "utf-8", errors="ignore"
            ).strip()
        return clipped or "unnamed.bin"

    def _unique_inbox_path(self, blob: str, name: str) -> Path:
        """v0.20.7 (security audit H16): allocate a write-only inbox
        path that does not overwrite an existing file.

        The previous implementation opened ``inbox / f"{blob[:8]}_{name}"``
        with ``"wb"`` (truncate). Two distinct file offers whose 8-char
        blob prefix collided AND whose names matched silently overwrote.
        With 32 bits of prefix entropy, a targeted attacker who can
        choose the file name (a malicious paired peer) can grind blob
        contents until the prefix matches an existing inbox file and
        truncate it. We now open with ``"xb"`` (exclusive create) and
        on collision append a numeric suffix until we find a free name.
        """
        base = inbox_dir()
        candidate = base / f"{blob[:8]}_{name}"
        if not candidate.exists():
            return candidate
        # On collision, insert "(N)" before the extension.
        stem = Path(candidate.name).stem
        suffix = Path(candidate.name).suffix
        for n in range(1, 1000):
            alt = base / f"{stem} ({n}){suffix}"
            if not alt.exists():
                return alt
        # Fallback: random suffix to guarantee uniqueness even at
        # extreme collision counts.
        return base / f"{stem}.{secrets.token_hex(4)}{suffix}"

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
            max_chunks = min(
                MAX_CDC_MANIFEST_CHUNKS,
                max(1, declared_size // CDC_MIN_CHUNK_BYTES + 16),
            )
        else:
            # Fallback: cap absolutely at the count for the largest file we
            # would ever accept on the wire.
            max_chunks = min(
                MAX_CDC_MANIFEST_CHUNKS,
                (MAX_INCOMING_FILE_BYTES // CDC_MIN_CHUNK_BYTES) + 16,
            )
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
            try:
                start = int(item.get("start", 0))
                end = int(item.get("end", 0))
                size = int(item.get("size", end - start))
            except (TypeError, ValueError, OverflowError):
                return None
            if start < 0 or end < start or size != end - start:
                return None
            if size < 0 or size > STREAM_MAX_CHUNK_SIZE:
                # CDC's natural hard upper bound is MAX_CHUNK_BYTES. v0.12.5
                # fixed-block manifests can use larger chunks to reduce ACK
                # pressure, but still clamp to the stream max so a malicious
                # offer cannot force arbitrary multi-MB allocations.
                return None
            if declared_size is not None and end > declared_size:
                return None
            running_end = max(running_end, end)
            out.append({"index": i, "start": start, "end": end, "size": size, "hash": h})
        if declared_size is not None and running_end > declared_size:
            return None
        return out

    def _store_chunk_cache(
        self,
        chunk_hash: str,
        data: bytes,
        *,
        blob_hash: str | None = None,
        chunk_index: int | None = None,
    ) -> None:
        if blake3.blake3(data).hexdigest() != chunk_hash:
            raise RuntimeError("CDC chunk hash mismatch")
        dst = self._chunk_cache_path(chunk_hash)
        if not dst.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.parent / f".{os.getpid()}_{secrets.token_hex(8)}.tmp"
            tmp.write_bytes(data)
            os.replace(tmp, dst)
        if self.state is not None:
            with contextlib.suppress(Exception):
                self.state.record_chunk_available(
                    chunk_hash,
                    len(data),
                    blob_hash=blob_hash,
                    chunk_index=chunk_index,
                    source="local",
                )

    def _read_chunk_cache(self, chunk_hash: str) -> bytes | None:
        p = self._chunk_cache_path(chunk_hash)
        if not p.is_file():
            return self._read_chunk_from_prior_source(chunk_hash)
        with contextlib.suppress(OSError):
            os.utime(p, None)
        data = p.read_bytes()
        # v0.20.7 (security audit H18): re-verify the stored bytes
        # actually hash to the address they're stored under. Without
        # this check, any process or cross-app actor that modifies a
        # file under <data>/file_chunks (no FS sandbox enforcement;
        # only user-account isolation) causes the daemon to ship
        # wrong bytes to remote peers AND incorporate them into
        # locally-assembled output. The CDC-finish path catches
        # whole-file mismatch via the trailing blake3 check, but
        # peers receiving a poisoned chunk via _handle_chunk_pull
        # had no defense. Re-hashing on read is O(chunk_size) and
        # the chunks are bounded; cost is acceptable for the
        # integrity guarantee. On mismatch we unlink the corrupted
        # cache entry and fall through to the prior-source path so
        # a transient disk fault doesn't permanently kill the chunk.
        if blake3.blake3(data).hexdigest() != chunk_hash:
            log.warning(
                "chunk-cache integrity mismatch for %s; unlinking",
                chunk_hash[:8],
            )
            with contextlib.suppress(OSError):
                p.unlink()
            return self._read_chunk_from_prior_source(chunk_hash)
        return data

    def _read_chunk_from_prior_source(self, chunk_hash: str) -> bytes | None:
        if self.state is None:
            return None
        try:
            sources = self.state.get_chunk_sources(chunk_hash, limit=8)
        except Exception:
            return None
        for src in sources:
            try:
                p = Path(str(src["path"])).expanduser()
                st = p.stat()
                if int(st.st_size) != int(src["file_size"]):
                    continue
                mtime_ms = int(st.st_mtime * 1000)
                if abs(mtime_ms - int(src["mtime_ms"])) > 1000:
                    continue
                start = int(src["start"])
                size = int(src["size"])
                if start < 0 or size <= 0 or start + size > st.st_size:
                    continue
                with open(p, "rb") as fh:
                    fh.seek(start)
                    data = fh.read(size)
                if len(data) != size:
                    continue
                if blake3.blake3(data).hexdigest() != chunk_hash:
                    continue
                self._store_chunk_cache(chunk_hash, data)
                return data
            except Exception as e:
                log.debug("prior chunk source skipped for %s: %s", chunk_hash[:8], e)
        return None

    def _cache_file_chunks(self, path: Path) -> None:
        try:
            file_index = index_path(path)
            self._record_file_index_cache(
                path,
                file_index,
                index_kind="cdc",
            )
            chunks = file_index.chunks
            with open(path, "rb") as fh:
                for c in chunks:
                    fh.seek(c.start)
                    self._store_chunk_cache(
                        c.hash,
                        fh.read(c.size),
                        blob_hash=file_index.blob_hash,
                        chunk_index=c.index,
                    )
        except Exception as e:
            log.debug("CDC cache fill skipped for %s: %s", path, e)

    def _file_cache_signature(self, path: Path) -> dict:
        p = Path(path).expanduser().resolve()
        st = p.stat()
        return {
            "path": str(p),
            "size": int(st.st_size),
            "mtime_ns": int(st.st_mtime_ns),
            "ctime_ns": int(st.st_ctime_ns),
        }

    def _cached_file_index(self, sig: dict) -> tuple[FileIndex, str] | None:
        if self.state is None:
            return None
        try:
            row = self.state.get_file_index_cache(**sig)
        except Exception as e:
            log.debug("file index cache lookup skipped for %s: %s", sig.get("path"), e)
            return None
        if not row:
            return None
        try:
            chunks = tuple(
                Chunk(
                    index=int(c["index"]),
                    start=int(c["start"]),
                    end=int(c["end"]),
                    hash=str(c["hash"]),
                )
                for c in (row.get("chunks") or [])
            )
            return (
                FileIndex(
                    blob_hash=str(row["blob_hash"]),
                    size=int(row["size"]),
                    chunks=chunks,
                ),
                str(row.get("index_kind") or "unknown"),
            )
        except Exception as e:
            log.debug("file index cache decode skipped for %s: %s", sig.get("path"), e)
            return None

    def _record_file_index_cache(
        self,
        path: Path,
        file_index: FileIndex,
        *,
        index_kind: str,
    ) -> None:
        if self.state is None:
            return
        try:
            sig = self._file_cache_signature(path)
            chunk_rows = [
                {
                    "index": c.index,
                    "start": c.start,
                    "end": c.end,
                    "size": c.size,
                    "hash": c.hash,
                }
                for c in file_index.chunks
            ]
            self.state.record_file_index_cache(
                **sig,
                blob_hash=file_index.blob_hash,
                index_kind=index_kind,
                chunks=chunk_rows,
            )
            if chunk_rows:
                self.state.record_chunk_sources_for_file(
                    path=sig["path"],
                    file_size=int(sig["size"]),
                    mtime_ms=int(Path(sig["path"]).stat().st_mtime * 1000),
                    chunks=chunk_rows,
                    source=f"file_index:{index_kind}",
                )
        except Exception as e:
            log.debug("file index cache write skipped for %s: %s", path, e)

    def _record_prior_file_sources(self, path: Path) -> dict:
        if self.state is None:
            return {"chunks": 0, "bytes": 0, "skipped": True}
        try:
            p = Path(path).expanduser().resolve()
            st = p.stat()
            idx = index_path(p)
        except Exception as e:
            log.debug("prior source index skipped for %s: %s", path, e)
            return {"chunks": 0, "bytes": 0, "skipped": True}
        mtime_ms = int(st.st_mtime * 1000)
        for c in idx.chunks:
            with contextlib.suppress(Exception):
                self.state.record_chunk_source(
                    c.hash,
                    path=str(p),
                    start=c.start,
                    size=c.size,
                    mtime_ms=mtime_ms,
                    file_size=int(st.st_size),
                    source="prior",
                )
        return {"chunks": len(idx.chunks), "bytes": idx.size, "skipped": False}

    def _prior_assist_roots(self) -> list[Path]:
        roots: list[Path] = []
        with contextlib.suppress(Exception):
            roots.append(inbox_dir())
        if self.state is not None:
            with contextlib.suppress(Exception):
                for f in self.state.list_folders():
                    p = Path(str(f.get("local_path") or "")).expanduser()
                    if p:
                        roots.append(p)
        out: list[Path] = []
        seen: set[str] = set()
        for root in roots:
            with contextlib.suppress(OSError, RuntimeError):
                r = root.resolve()
                key = str(r).lower()
                if r.is_dir() and key not in seen:
                    seen.add(key)
                    out.append(r)
        return out

    def _iter_prior_assist_files(self) -> tuple[list[Path], dict]:
        candidates: list[tuple[float, Path]] = []
        scanned_bytes = 0
        skipped = 0
        cache_root = self._chunk_cache_dir().resolve()
        for root in self._prior_assist_roots():
            if len(candidates) >= PRIOR_ASSIST_MAX_FILES:
                break
            try:
                walker = os.walk(root)
            except OSError:
                continue
            for dirpath, dirnames, filenames in walker:
                dirnames[:] = [
                    d for d in dirnames
                    if d not in {".chunk_cache", "file_chunks", "__pycache__"}
                    and not d.startswith(".")
                ]
                for name in filenames:
                    if len(candidates) >= PRIOR_ASSIST_MAX_FILES:
                        break
                    p = Path(dirpath) / name
                    try:
                        rp = p.resolve()
                        if cache_root in rp.parents:
                            continue
                        st = rp.stat()
                        if not st.st_size:
                            continue
                        if scanned_bytes + st.st_size > PRIOR_ASSIST_MAX_SCAN_BYTES:
                            skipped += 1
                            continue
                    except OSError:
                        skipped += 1
                        continue
                    candidates.append((float(st.st_mtime), rp))
                    scanned_bytes += int(st.st_size)
                if len(candidates) >= PRIOR_ASSIST_MAX_FILES:
                    break
        files = [p for _mtime, p in sorted(candidates, reverse=True)]
        return files, {
            "candidate_files": len(files),
            "candidate_bytes": scanned_bytes,
            "skipped": skipped,
        }

    def _hydrate_chunks_from_local_prior(
        self,
        wanted_hashes: set[str],
        *,
        blob_hash: str | None = None,
        target_chunks: dict[str, dict] | None = None,
    ) -> dict:
        wanted = {
            str(h) for h in wanted_hashes
            if self._valid_blob_hex(str(h)) and not self._chunk_cache_path(str(h)).is_file()
        }
        stats = {
            "enabled": True,
            "matched": 0,
            "matched_bytes": 0,
            "scanned_files": 0,
            "scanned_bytes": 0,
            "candidate_files": 0,
            "candidate_bytes": 0,
            "skipped": 0,
        }
        if not wanted:
            return stats
        files, file_stats = self._iter_prior_assist_files()
        stats.update(file_stats)
        for path in files:
            if not wanted or stats["matched"] >= PRIOR_ASSIST_MAX_MATCHES_PER_SCAN:
                break
            source_stats = self._record_prior_file_sources(path)
            if source_stats.get("skipped"):
                stats["skipped"] += 1
                continue
            try:
                idx = index_path(path)
            except Exception:
                stats["skipped"] += 1
                continue
            stats["scanned_files"] += 1
            stats["scanned_bytes"] += idx.size
            for c in [c for c in idx.chunks if c.hash in wanted]:
                data = self._read_chunk_cache(c.hash)
                if data is None:
                    continue
                target = (target_chunks or {}).get(c.hash) or {}
                if blob_hash or target.get("index") is not None:
                    self._store_chunk_cache(
                        c.hash,
                        data,
                        blob_hash=blob_hash,
                        chunk_index=target.get("index"),
                    )
                wanted.discard(c.hash)
                stats["matched"] += 1
                stats["matched_bytes"] += len(data)
        return stats

    def _index_local_prior_sources_once(self) -> dict:
        files, file_stats = self._iter_prior_assist_files()
        stats = {
            **file_stats,
            "indexed_files": 0,
            "indexed_chunks": 0,
            "indexed_bytes": 0,
        }
        for path in files:
            source_stats = self._record_prior_file_sources(path)
            if source_stats.get("skipped"):
                stats["skipped"] += 1
                continue
            stats["indexed_files"] += 1
            stats["indexed_chunks"] += int(source_stats.get("chunks") or 0)
            stats["indexed_bytes"] += int(source_stats.get("bytes") or 0)
        return stats

    async def _prior_index_loop(self) -> None:
        try:
            await asyncio.sleep(5.0)
            while True:
                stats = await asyncio.to_thread(self._index_local_prior_sources_once)
                if stats.get("indexed_chunks"):
                    log.info(
                        "prior index: files=%d chunks=%d bytes=%d",
                        stats["indexed_files"],
                        stats["indexed_chunks"],
                        stats["indexed_bytes"],
                    )
                await asyncio.sleep(PRIOR_INDEX_INTERVAL_S)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.warning("prior index loop stopped: %s", e)

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

    def _transfer_autopilot_stats(self) -> dict:
        """Live transfer brain status for /api/status.

        This is intentionally compact and user-safe: no file paths, no peer
        names, just whether the local engines and learned routes are getting
        faster or need repair.
        """
        routes = []
        for peer_fp, mem in sorted(self._route_memory.items()):
            best = mem.best_route()
            candidates = mem.candidates()
            top = candidates[0] if candidates else None
            routes.append({
                "peer": peer_fp[:8],
                "best_route": best,
                "score": round(float(top.score), 6) if top is not None else 0.0,
                "latency_ms": top.latency_ms if top is not None else None,
                "bandwidth_bps": top.bandwidth_bps if top is not None else None,
                "attempts": top.attempts if top is not None else 0,
                "successes": top.successes if top is not None else 0,
            })
        return {
            "engines": self._transfer_perf.snapshot(),
            "routes": routes[:12],
            "route_count": len(routes),
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

    def _available_chunk_hashes(
        self,
        hashes: list[str],
        *,
        hydrate: bool = True,
        limit: int = 2048,
    ) -> list[str]:
        requested = []
        seen = set()
        max_items = max(0, int(limit))
        for h in hashes[:max_items]:
            h = str(h)
            if h in seen or not self._valid_blob_hex(h):
                continue
            seen.add(h)
            requested.append(h)
        missing = {h for h in requested if not self._chunk_cache_path(h).is_file()}
        if hydrate and missing:
            self._hydrate_chunks_from_local_prior(missing)
        sourced: set[str] = set()
        if self.state is not None and missing:
            with contextlib.suppress(Exception):
                sourced = set(self.state.chunks_sourced(missing))
                if hydrate:
                    for h in sourced:
                        self._read_chunk_cache(h)
        clean = []
        for h in requested:
            if self._chunk_cache_path(h).is_file() or h in sourced:
                clean.append(h)
        if self.state is not None and clean:
            with contextlib.suppress(Exception):
                indexed = set(self.state.chunks_available(clean))
                clean = [h for h in clean if h in indexed or self._chunk_cache_path(h).is_file()]
        return clean

    async def _handle_chunk_query(self, channel, msg, peer_fp) -> None:
        if not self._is_pinned(peer_fp) or not self._capability_allowed(peer_fp, FILES):
            await channel.send(encode_msg(make_msg(
                "CHUNK_HAVE", self.me.short_id, of=msg.get("id"), hashes=[],
                rejected="not_authorized",
            )))
            return
        raw = msg.get("hashes") or []
        if not isinstance(raw, list):
            raw = []
        have = self._available_chunk_hashes(raw)
        await channel.send(encode_msg(make_msg(
            "CHUNK_HAVE", self.me.short_id, of=msg.get("id"), hashes=have,
        )))

    async def _handle_chunk_pull(self, channel, msg, peer_fp) -> None:
        if not self._is_pinned(peer_fp) or not self._capability_allowed(peer_fp, FILES):
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="not_authorized",
            )))
            return
        h = str(msg.get("hash", ""))
        if not self._valid_blob_hex(h):
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="bad_hash",
            )))
            return
        data = self._read_chunk_cache(h)
        if data is None:
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="missing_chunk",
            )))
            return
        enc, payload = self._encode_payload(data)
        await channel.send(encode_msg(make_msg(
            "CHUNK_DATA",
            self.me.short_id,
            of=msg.get("id"),
            hash=h,
            enc=enc,
            wire_size=len(payload),
            size=len(data),
            data=base64.b64encode(payload).decode("ascii"),
        )))

    async def query_peer_chunks(self, peer: Peer, hashes: list[str]) -> dict:
        block = self._check_outbound_trust(peer)
        if block:
            raise RuntimeError(block)
        peer_fp = self._peer_fp_from_peer(peer) or ""
        if peer_fp and not self._capability_allowed(peer_fp, FILES):
            raise RuntimeError(f"files capability disabled for peer {peer.short_id}")
        clean = [h for h in hashes[:2048] if self._valid_blob_hex(str(h))]
        sess = await self._get_outbound_session(peer)
        async with sess.lock:
            q = make_msg("CHUNK_QUERY", self.me.short_id, hashes=clean)
            # Phase A2: routed through PeerTransport facade (CHUNK_QUERY
            # is the third message-type migration after PING + send_to).
            await self._send_via_transport(
                sess.peer_fp, sess.channel, encode_msg(q)
            )
            while True:
                reply = await self._recv_chunk_protocol_reply(
                    sess=sess,
                    request_id=str(q.get("id")),
                    expected_types={"CHUNK_HAVE"},
                    timeout_s=FILE_ACK_DEADLINE_S,
                )
                have = [
                    str(h) for h in (reply.get("hashes") or [])
                    if self._valid_blob_hex(str(h))
                ]
                return {
                    "ok": not reply.get("rejected"),
                    "hashes": have,
                    "rejected": reply.get("rejected"),
                }

    async def pull_peer_chunk(self, peer: Peer, chunk_hash: str) -> dict:
        block = self._check_outbound_trust(peer)
        if block:
            raise RuntimeError(block)
        peer_fp = self._peer_fp_from_peer(peer) or ""
        if peer_fp and not self._capability_allowed(peer_fp, FILES):
            raise RuntimeError(f"files capability disabled for peer {peer.short_id}")
        if not self._valid_blob_hex(str(chunk_hash)):
            raise RuntimeError("bad chunk hash")
        sess = await self._get_outbound_session(peer)
        async with sess.lock:
            q = make_msg("CHUNK_PULL", self.me.short_id, hash=str(chunk_hash))
            # Phase A2: routed through PeerTransport facade.
            await self._send_via_transport(
                sess.peer_fp, sess.channel, encode_msg(q)
            )
            while True:
                reply = await self._recv_chunk_protocol_reply(
                    sess=sess,
                    request_id=str(q.get("id")),
                    expected_types={"CHUNK_DATA"},
                    timeout_s=FILE_ACK_DEADLINE_S,
                    accept_rejected_ack=True,
                )
                if reply.get("t") == "ACK" and reply.get("rejected"):
                    return {"ok": False, "rejected": reply.get("rejected")}
                data = base64.b64decode(reply.get("data", ""), validate=True)
                data = self._decode_payload(
                    str(reply.get("enc", "raw")),
                    data,
                    max_bytes=CDC_MAX_CHUNK_BYTES + 64,
                )
                if blake3.blake3(data).hexdigest() != chunk_hash:
                    raise RuntimeError("CHUNK_DATA integrity failure")
                self._store_chunk_cache(chunk_hash, data)
                return {
                    "ok": True,
                    "hash": chunk_hash,
                    "size": len(data),
                    "wire_size": int(reply.get("wire_size") or len(data)),
                }

    async def _recv_chunk_protocol_reply(
        self,
        *,
        sess: OutboundSession,
        request_id: str,
        expected_types: set[str],
        timeout_s: float,
        accept_rejected_ack: bool = False,
    ) -> dict:
        """Receive the matching chunk-protocol reply on a shared peer channel.

        Swarm chunk query/pull rides the same encrypted channel as chat,
        presence, grants, and file-control traffic. Production peers can send
        those frames while a chunk request is in flight, so treating the next
        frame as "the reply" makes large transfers flaky. This helper waits
        for the response with a matching ``of`` id, tolerates legacy responses
        that omit ``of``, and lets ordinary out-of-band frames continue through
        the normal peer-message handler.
        """
        deadline = time.monotonic() + max(0.001, float(timeout_s))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise asyncio.TimeoutError(
                    f"timed out waiting for {sorted(expected_types)} reply"
                )
            reply = decode_msg(await asyncio.wait_for(
                sess.channel.recv(), timeout=remaining,
            ))
            t = str(reply.get("t") or "")
            if t == "CAPS":
                continue
            of = reply.get("of")
            if of not in (None, request_id):
                log.debug(
                    "ignored stale chunk-protocol frame %s of=%s while waiting for %s",
                    t, of, request_id,
                )
                continue
            if t in expected_types:
                return reply
            if accept_rejected_ack and t == "ACK" and reply.get("rejected"):
                return reply
            if t.startswith("CHUNK_") or t == "ACK":
                log.debug(
                    "ignored unrelated chunk-protocol frame %s while waiting for %s",
                    t, sorted(expected_types),
                )
                continue
            try:
                await self._on_peer_message(sess.channel, reply)
            except Exception as e:
                log.debug(
                    "out-of-band peer frame %s failed during chunk wait: %s",
                    t, e,
                )

    def _swarm_trust_score(self, peer_fp: str) -> float:
        if self.state is None:
            return 0.0
        rec = self.state.get_peer(peer_fp)
        if rec is None:
            return 0.0
        score = 1.0 if rec.trust == "pinned" else 0.0
        if rec.is_verified:
            score += 1.0
        return score

    async def query_swarm_chunk_sources(
        self,
        peers: list[Peer],
        hashes: list[str],
        *,
        concurrency: int = 4,
    ) -> dict[str, set[str]]:
        clean = []
        seen = set()
        for h in hashes[:SWARM_QUERY_MAX_HASHES]:
            h = str(h)
            if h not in seen and self._valid_blob_hex(h):
                seen.add(h)
                clean.append(h)
        sem = asyncio.Semaphore(max(1, int(concurrency)))
        claims: dict[str, set[str]] = {}
        batches = [
            clean[i:i + SWARM_QUERY_BATCH_HASHES]
            for i in range(0, len(clean), SWARM_QUERY_BATCH_HASHES)
        ]

        async def _query(peer: Peer) -> None:
            peer_fp = self._peer_fp_from_peer(peer)
            if not peer_fp:
                return
            async with sem:
                have: set[str] = set()
                for batch in batches:
                    try:
                        res = await self.query_peer_chunks(peer, batch)
                    except Exception as e:
                        log.debug("swarm chunk query skipped %s: %s", peer.short_id, e)
                        return
                    if not res.get("ok"):
                        return
                    have.update(
                        str(h) for h in (res.get("hashes") or [])
                        if self._valid_blob_hex(str(h))
                    )
            if have:
                claims[peer_fp] = have

        await asyncio.gather(*(_query(p) for p in peers))
        return claims

    async def pull_swarm_missing_chunks(
        self,
        *,
        peers: list[Peer],
        manifest: FileManifest,
        needed_indexes: list[int] | None = None,
        concurrency: int = 3,
    ) -> dict:
        needed = set(needed_indexes) if needed_indexes is not None else {
            c.index for c in manifest.chunks
        }
        needed_hashes = [
            c.hash for c in manifest.chunks
            if c.index in needed and not self._chunk_cache_path(c.hash).is_file()
        ]
        if not needed_hashes:
            return {
                "ok": True,
                "pulled": 0,
                "missing_indexes": [],
                "sources": {},
            }
        claims = await self.query_swarm_chunk_sources(
            peers,
            needed_hashes,
            concurrency=concurrency,
        )
        health_latency = {}
        health_bandwidth = {}
        health_reliability = {}
        peer_by_fp = {}
        for p in peers:
            fp = self._peer_fp_from_peer(p)
            if not fp:
                continue
            peer_by_fp[fp] = p
            health = self.get_pair_health(fp) or {}
            latency = health.get("latency_ewma_ms")
            if isinstance(latency, (int, float)) and not (latency != latency):
                health_latency[fp] = float(latency)
            bandwidth = health.get("bandwidth_bps") or health.get("throughput_bps")
            if isinstance(bandwidth, (int, float)) and bandwidth > 0:
                health_bandwidth[fp] = float(bandwidth)
            reliability = health.get("reliability")
            if isinstance(reliability, (int, float)):
                health_reliability[fp] = max(0.0, min(1.0, float(reliability)))
        source_objects = [
            source_from_hashes(
                fp,
                hashes,
                trust_score=self._swarm_trust_score(fp),
                latency_ms=health_latency.get(fp),
                bandwidth_bps=health_bandwidth.get(fp),
                reliability=health_reliability.get(fp, 1.0),
            )
            for fp, hashes in claims.items()
        ]
        candidate_fps_by_hash: dict[str, list[str]] = {}
        for chunk_hash in needed_hashes:
            candidates = [
                s for s in source_objects
                if chunk_hash in s.chunk_hashes and s.peer_fp in peer_by_fp
            ]
            candidates.sort(
                key=lambda s: (*s.route_score_without_tiebreaker(), s.peer_fp),
                reverse=True,
            )
            candidate_fps_by_hash[chunk_hash] = [s.peer_fp for s in candidates]
        chunk_by_index = {c.index: c for c in manifest.chunks}
        plan = plan_swarm_sources(
            manifest=manifest,
            needed_indexes=needed,
            sources=source_objects,
        )
        sem = asyncio.Semaphore(max(1, int(concurrency)))
        pulled = 0
        retried = 0
        healed = 0
        failed: set[int] = set()
        succeeded: set[int] = set()

        async def _pull_from(index: int, fp: str, chunk_hash: str) -> bool:
            nonlocal pulled
            if self._chunk_cache_path(chunk_hash).is_file():
                succeeded.add(index)
                return True
            peer = peer_by_fp.get(fp)
            if peer is None:
                return False
            async with sem:
                try:
                    res = await self.pull_peer_chunk(peer, chunk_hash)
                except Exception as e:
                    log.debug("swarm chunk pull failed %s from %s: %s", chunk_hash[:8], fp[:8], e)
                    return False
            if res.get("ok"):
                pulled += 1
                succeeded.add(index)
                return True
            return False

        async def _pull(index: int, fp: str, chunk_hash: str) -> None:
            if not await _pull_from(index, fp, chunk_hash):
                failed.add(index)

        pulls = [
            _pull(a.index, str(a.source_peer_fp), a.chunk_hash)
            for a in plan.assignments
            if a.status == "assigned" and a.source_peer_fp
        ]
        if pulls:
            await asyncio.gather(*pulls)

        if failed:
            retry_indexes = sorted(failed)
            failed.clear()

            async def _retry(index: int) -> None:
                nonlocal retried, healed
                chunk = chunk_by_index.get(index)
                if chunk is None:
                    failed.add(index)
                    return
                primary = next(
                    (
                        a.source_peer_fp for a in plan.assignments
                        if a.index == index
                    ),
                    None,
                )
                for fp in candidate_fps_by_hash.get(chunk.hash, []):
                    if fp == primary:
                        continue
                    retried += 1
                    if await _pull_from(index, fp, chunk.hash):
                        healed += 1
                        return
                if index not in succeeded:
                    failed.add(index)

            await asyncio.gather(*(_retry(i) for i in retry_indexes))
        missing = sorted(set(plan.missing_indexes) | failed)
        return {
            "ok": not missing,
            "pulled": pulled,
            "retried": retried,
            "healed": healed,
            "missing_indexes": missing,
            "sources": plan.per_source_counts(),
            "source_bytes": plan.per_source_bytes(),
            "assigned_bytes": plan.assigned_bytes,
            "missing_bytes": plan.missing_bytes,
            "schedule": list(plan.rarest_first_indexes),
            "candidate_sources": {
                h: fps for h, fps in candidate_fps_by_hash.items() if len(fps) > 1
            },
        }

    def _trusted_chunk_source_peers(self, *, exclude_fp: str) -> list[Peer]:
        """Build direct peer candidates for swarm chunk assistance."""
        if self.state is None:
            return []
        try:
            records = self.state.list_peers()
        except Exception:
            return []
        out: list[Peer] = []
        for rec in records:
            if rec.fingerprint in (exclude_fp, self.me.fingerprint):
                continue
            if rec.trust != "pinned" or not rec.last_address or not rec.last_port:
                continue
            if not rec.pubkey:
                continue
            out.append(Peer(
                short_id=rec.short_id,
                hostname=rec.hostname or rec.short_id,
                address=rec.last_address,
                port=int(rec.last_port),
                ed_pub_hex=rec.pubkey.hex(),
            ))
        return out[:8]

    async def _swarm_assist_file_offer(
        self,
        *,
        sender_fp: str,
        name: str,
        size: int,
        blob: str,
        cdc_chunks: list[dict],
        missing: set[int],
    ) -> tuple[set[int], dict]:
        """Try to satisfy inbound missing chunks from other trusted devices."""
        missing_before = sorted(int(i) for i in missing)
        if not missing:
            return missing, {
                "pulled": 0,
                "sources": {},
                "source_count": 0,
                "missing_before": [],
                "missing_after": [],
                "strategy": "already_local",
            }
        peers = self._trusted_chunk_source_peers(exclude_fp=sender_fp)
        if not peers:
            return missing, {
                "pulled": 0,
                "sources": {},
                "source_count": 0,
                "missing_before": missing_before,
                "missing_after": missing_before,
                "strategy": "sender_only",
            }
        manifest = FileManifest(
            name=name,
            size=size,
            blob_hash=blob,
            chunks=tuple(
                FileChunkManifest(
                    index=int(c["index"]),
                    start=int(c["start"]),
                    end=int(c["end"]),
                    size=int(c["size"]),
                    hash=str(c["hash"]),
                )
                for c in cdc_chunks
            ),
        )
        try:
            result = await asyncio.wait_for(
                self.pull_swarm_missing_chunks(
                    peers=peers,
                    manifest=manifest,
                    needed_indexes=sorted(missing),
                ),
                timeout=SWARM_ASSIST_DEADLINE_S,
            )
        except Exception as e:
            log.debug("swarm assist skipped for %s: %s", blob[:8], e)
            return missing, {
                "pulled": 0,
                "sources": {},
                "source_count": 0,
                "missing_before": missing_before,
                "missing_after": missing_before,
                "strategy": "swarm_probe_failed",
                "error": str(e)[:200],
            }
        remaining = {
            int(c["index"])
            for c in cdc_chunks
            if int(c["index"]) in missing
            and not self._chunk_cache_path(str(c["hash"])).is_file()
        }
        sources = dict(result.get("sources") or {})
        source_bytes = dict(result.get("source_bytes") or {})
        pulled = int(result.get("pulled") or 0)
        missing_after = sorted(remaining)
        source_count = len([fp for fp, count in sources.items() if int(count or 0) > 0])
        saved_bytes = sum(
            int(c["size"])
            for c in cdc_chunks
            if int(c["index"]) in set(missing_before) - set(missing_after)
        )
        return remaining, {
            "pulled": pulled,
            "retried": int(result.get("retried") or 0),
            "healed": int(result.get("healed") or 0),
            "sources": sources,
            "source_count": source_count,
            "source_bytes": source_bytes,
            "assisted_bytes": saved_bytes,
            "assigned_bytes": int(result.get("assigned_bytes") or 0),
            "missing_bytes": int(result.get("missing_bytes") or 0),
            "candidate_sources": dict(result.get("candidate_sources") or {}),
            "missing_before": missing_before,
            "missing_after": missing_after,
            "strategy": "multi_source_chunk_pull" if pulled else "sender_only",
            "user_message": (
                f"Pulled {pulled} missing chunk{'s' if pulled != 1 else ''} "
                f"from {source_count} trusted device"
                f"{'s' if source_count != 1 else ''}."
                if pulled
                else "No trusted device had the missing chunks yet."
            ),
        }

    def _encode_payload(self, data: bytes, *, allow_compress: bool = True) -> tuple[str, bytes]:
        if not allow_compress or len(data) < COMPRESSION_MIN_BYTES:
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
            # v0.20.7 (security audit M6): re-check the per-call cap
            # after dec.flush(), not just MAX_INCOMING_FILE_BYTES.
            # flush() can emit additional bytes from the decoder's
            # internal buffer that the bounded decompress() call did
            # not return. Without this re-check, the per-chunk cap
            # was leaky and a stream of small over-cap chunks could
            # compound into noticeable extra allocation.
            if len(out) > cap:
                raise RuntimeError(
                    f"compressed payload exceeds maximum size after flush "
                    f"({len(out)} > {cap})"
                )
            if len(out) > MAX_INCOMING_FILE_BYTES:
                raise RuntimeError("compressed payload exceeds maximum size")
            return out
        raise RuntimeError(f"unknown payload encoding: {encoding}")

    async def _handle_file_native_chunk(self, channel, msg, peer_fp, peer_sid) -> None:
        """Phase C-3 (ADR-0026) — receive a FILE_NATIVE_CHUNK message.

        Wire shape::

            {
              "t": "FILE_NATIVE_CHUNK",
              "id": ..., "ts": ..., "from": ...,
              "blob": <hex>,
              "seq": <int>,
              "chunk_id": <hex 32B BLAKE3>,
              "plaintext_len": <int>,
              "data": <base64 of native ciphertext>,
              "eof": <bool>,
            }

        Decryption flows through ``channel.get_or_create_native_transfer_session()``;
        the AEAD tag binds chunk_id as AAD so any swap/tamper raises
        before plaintext is exposed. The receiver's native session
        is matched to the sender's by the shared derive_native_transfer
        secret, so chunks decrypt in lockstep without any per-chunk
        key exchange.
        """
        from one_link import native_transfer as _nt

        blob = str(msg.get("blob", ""))
        f = self._incoming_files.get(blob)
        if not f:
            log.warning("FILE_NATIVE_CHUNK with no offer: %s", blob[:8])
            return
        # Mid-stream capability re-check (matches FILE_BIN_CHUNK pattern).
        if not self._capability_allowed(peer_fp, FILES):
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="capability_revoked_mid_stream",
            )))
            return
        seq = int(msg.get("seq", -1))
        if seq != f.next_seq:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(
                f"FILE_NATIVE_CHUNK sequence mismatch for {blob[:8]}: "
                f"expected {f.next_seq}, got {seq}"
            )
        try:
            chunk_id_hex = str(msg["chunk_id"])
            chunk_id = bytes.fromhex(chunk_id_hex)
            if len(chunk_id) != 32:
                raise ValueError(f"chunk_id must be 32 bytes, got {len(chunk_id)}")
            plaintext_len = int(msg["plaintext_len"])
            ciphertext = base64.b64decode(msg["data"], validate=True)
        except (KeyError, ValueError, binascii.Error) as exc:
            self._abort_incoming_file(blob, f)
            log.warning("FILE_NATIVE_CHUNK decode error from %s: %s", peer_sid, exc)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="bad_native_chunk_envelope",
            )))
            return
        # Build the session lazily on first chunk. After this it's
        # reused for the rest of the channel's lifetime — both peers
        # cache matched instances independently.
        try:
            session = channel.get_or_create_native_transfer_session()
        except Exception as exc:
            self._abort_incoming_file(blob, f)
            log.warning("native transfer session unavailable: %s", exc)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="native_transfer_unavailable",
            )))
            return
        record = _nt.NativeChunkRecord(
            chunk_id=chunk_id,
            chunk_index=seq,
            plaintext_len=plaintext_len,
            ciphertext=ciphertext,
        )
        try:
            data = session.decrypt_chunk(record)
        except Exception as exc:
            # AEAD tag failure means the chunk was tampered, the
            # session secret diverged, or the chunk_id was swapped.
            # Any of those is fatal for the transfer.
            self._abort_incoming_file(blob, f)
            log.warning(
                "FILE_NATIVE_CHUNK decrypt failure for %s (seq=%d): %s",
                blob[:8], seq, exc,
            )
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="native_chunk_decrypt_failed",
            )))
            return
        if f.received + len(data) > f.size:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(
                f"FILE_NATIVE_CHUNK exceeds declared size for {blob[:8]}: "
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
                "file_risk": classify_file_risk(f.name),
            }
            ev = self._persist(msg=done, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            self._incoming_files.pop(blob, None)
            if not ok:
                with contextlib.suppress(OSError):
                    f.out_path.unlink()
                self._update_transfer(f.transfer_id, status="failed")
            else:
                self._update_transfer(
                    f.transfer_id,
                    status="complete",
                    progress_bytes=f.size,
                    total_bytes=f.size,
                )
            log.info("native file done: %s ok=%s -> %s", f.name, ok, f.out_path)
            await self._ack_file_chunk(channel, msg, f, force_individual=True)
            if ok:
                self._cache_file_chunks(f.out_path)
            return
        await self._ack_file_chunk(channel, msg, f)

    async def _handle_file_binary_chunk(self, channel, msg, peer_fp, peer_sid) -> None:
        """Receive one raw binary file chunk carried inside the encrypted channel."""

        blob = str(msg.get("blob", ""))
        f = self._incoming_files.get(blob)
        if not f:
            log.warning("FILE_BIN_CHUNK with no offer: %s", blob[:8])
            return
        # v0.20.7 (security audit H15 / H17): re-check pinned + files
        # capability on every chunk so a mid-transfer revoke takes
        # effect immediately. See the FILE_CHUNK comment for the full
        # rationale.
        if not self._capability_allowed(peer_fp, FILES):
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="capability_revoked_mid_stream",
            )))
            return
        seq = int(msg.get("seq", -1))
        if seq != f.next_seq:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(
                f"FILE_BIN_CHUNK sequence mismatch for {blob[:8]}: "
                f"expected {f.next_seq}, got {seq}"
            )
        data = msg.get("_binary_data")
        if not isinstance(data, (bytes, bytearray)):
            self._abort_incoming_file(blob, f)
            raise RuntimeError("FILE_BIN_CHUNK missing binary payload")
        data = bytes(data)
        if f.received + len(data) > f.size:
            self._abort_incoming_file(blob, f)
            raise RuntimeError(
                f"FILE_BIN_CHUNK exceeds declared size for {blob[:8]}: "
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
            self._incoming_files.pop(blob, None)
            if not ok:
                # v0.20.7 (security audit M23): same quarantine
                # discipline as _finish_cdc_file. See note there.
                quarantine_target: Optional[Path] = None
                try:
                    quarantine_target = f.out_path.with_name(
                        f.out_path.name + ".failed." + secrets.token_hex(4)
                    )
                    f.out_path.rename(quarantine_target)
                except OSError:
                    quarantine_target = None
                if quarantine_target is not None:
                    with contextlib.suppress(OSError):
                        quarantine_target.unlink()
                else:
                    with contextlib.suppress(OSError):
                        f.out_path.unlink()
                done["path"] = ""
                ev = self._persist(
                    msg=done, direction="in",
                    peer_fp=peer_fp, peer_short_id=peer_sid,
                )
                self._broadcast_tail(ev)
                self._update_transfer(f.transfer_id, status="failed")
            else:
                ev = self._persist(
                    msg=done, direction="in",
                    peer_fp=peer_fp, peer_short_id=peer_sid,
                )
                self._broadcast_tail(ev)
                self._update_transfer(
                    f.transfer_id,
                    status="complete",
                    progress_bytes=f.size,
                    total_bytes=f.size,
                )
            log.info("binary file done: %s ok=%s -> %s", f.name, ok, f.out_path)
            await self._ack_file_chunk(channel, msg, f, force_individual=True)
            if ok:
                self._cache_file_chunks(f.out_path)
            return
        await self._ack_file_chunk(channel, msg, f)

    async def _handle_file_cdc_chunk(self, channel, msg, peer_fp, peer_sid) -> None:
        blob = str(msg.get("blob", ""))
        f = self._incoming_files.get(blob)
        if not f or f.cdc_chunks is None or f.cdc_missing is None:
            return
        # v0.20.7 (security audit H15 / H17): re-check pinned + files
        # capability on every chunk so a mid-transfer revoke takes
        # effect immediately. The CDC path additionally writes to the
        # global chunk cache (which other peers can pull from), so
        # leaking chunks past a revoke is doubly-bad without this gate.
        if not self._capability_allowed(peer_fp, FILES):
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"),
                rejected="capability_revoked_mid_stream",
            )))
            return
        try:
            idx = int(msg.get("index", -1))
        except (TypeError, ValueError, OverflowError):
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="bad_cdc_chunk_index",
            )))
            return
        if idx < 0 or idx >= len(f.cdc_chunks) or idx not in f.cdc_missing:
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="unexpected_cdc_chunk",
            )))
            return
        expected = f.cdc_chunks[idx]
        # M4: bound decompression by the *expected* chunk size, not by the
        # whole-file cap. A zlib bomb is rejected at 1.5x the expected
        # chunk size (small slack for compressor framing variance).
        max_chunk_out = max(expected["size"] + 64, CDC_MAX_CHUNK_BYTES + 64)
        try:
            payload = msg.get("_binary_data")
            if isinstance(payload, (bytes, bytearray)):
                data = bytes(payload)
            else:
                data = base64.b64decode(msg.get("data", ""), validate=True)
            data = self._decode_payload(
                str(msg.get("enc", "raw")), data, max_bytes=max_chunk_out,
            )
        except (binascii.Error, ValueError) as e:
            self._abort_incoming_file(blob, f)
            log.warning("invalid FILE_CDC_CHUNK payload from %s: %s", peer_sid, e)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="bad_cdc_chunk_data",
            )))
            return
        if len(data) != expected["size"] or blake3.blake3(data).hexdigest() != expected["hash"]:
            self._abort_incoming_file(blob, f)
            await channel.send(encode_msg(make_msg(
                "ACK", self.me.short_id, of=msg.get("id"), rejected="cdc_chunk_integrity_failure",
            )))
            return
        self._store_chunk_cache(
            expected["hash"],
            data,
            blob_hash=f.blob_hex,
            chunk_index=idx,
        )
        assert f.cdc_parts is not None
        assert f.cdc_missing is not None
        assert f.cdc_chunks is not None
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
                "file_risk": classify_file_risk(f.name),
            },
        )
        if not f.cdc_missing:
            await self._ack_file_chunk(channel, msg, f, force_individual=True)
            self._schedule_finish_cdc_file(blob, peer_fp, peer_sid, msg)
        else:
            await self._ack_file_chunk(channel, msg, f)

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
                written += len(data)
            f.handle.close()
            ok = h.hexdigest() == blob and written == f.size
            done = {
                "t": "FILE_DONE", "id": src_msg["id"], "ts": src_msg["ts"],
                "from": src_msg["from"], "name": f.name, "size": f.size,
                "path": str(f.out_path), "blob": blob, "ok": ok,
                "cdc": True,
                "file_risk": classify_file_risk(f.name),
            }
            self._incoming_files.pop(blob, None)
            if not ok:
                # v0.20.7 (security audit M23): the prior implementation
                # ran ``contextlib.suppress(OSError): unlink`` and
                # broadcast the ``path`` field regardless. On Windows
                # an antivirus / search-indexer transient handle on
                # the just-closed file frequently makes the unlink
                # fail; the corrupt file then sits in the user's
                # inbox indistinguishable (by name) from a legitimate
                # one, and the FILE_DONE WS event surfaces a path
                # pointing at it. Move-aside-then-retry-unlink ensures
                # the visible inbox state never has a path the user
                # would mistake for a clean download.
                quarantine_target: Optional[Path] = None
                try:
                    quarantine_target = f.out_path.with_name(
                        f.out_path.name + ".failed." + secrets.token_hex(4)
                    )
                    f.out_path.rename(quarantine_target)
                except OSError:
                    quarantine_target = None
                if quarantine_target is not None:
                    with contextlib.suppress(OSError):
                        quarantine_target.unlink()
                else:
                    with contextlib.suppress(OSError):
                        f.out_path.unlink()
                # Strip the path field from the broadcast so any UI
                # subscriber doesn't surface the corrupt path.
                done["path"] = ""
                ev = self._persist(
                    msg=done, direction="in",
                    peer_fp=peer_fp, peer_short_id=peer_sid,
                )
                self._broadcast_tail(ev)
                self._update_transfer(f.transfer_id, status="failed")
                return
            ev = self._persist(msg=done, direction="in", peer_fp=peer_fp, peer_short_id=peer_sid)
            self._broadcast_tail(ev)
            self._record_finished_cdc_sources(f.out_path, f)
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

    def _record_finished_cdc_sources(self, path: Path, f: IncomingFile) -> None:
        """Record chunk source rows for a just-assembled CDC receive.

        The finish path already has the verified manifest. Re-indexing the
        whole output file here makes repeated large-file sends feel stuck even
        though no network bytes are needed. Keep the fast content-addressed
        evidence without paying a second full-file scan.
        """
        if self.state is None or not f.cdc_chunks:
            return
        try:
            st = path.stat()
            self.state.record_chunk_sources_for_file(
                path=str(path),
                file_size=int(st.st_size),
                mtime_ms=int(st.st_mtime * 1000),
                chunks=[
                    {
                        "index": int(c["index"]),
                        "start": int(c["start"]),
                        "end": int(c["end"]),
                        "size": int(c["size"]),
                        "hash": str(c["hash"]),
                    }
                    for c in f.cdc_chunks
                ],
                source="received_cdc",
            )
        except Exception as e:
            log.debug("finished CDC source recording skipped for %s: %s", path, e)

    def _schedule_finish_cdc_file(
        self, blob: str, peer_fp: str, peer_sid: str, src_msg: dict,
    ) -> None:
        """Finish a fully deduped receive after the FILE_WANTS response flushes.

        If the sender needs zero chunks, the important wire response is
        FILE_WANTS(wants=[]). Rebuilding the duplicate inbox file can touch tens
        or hundreds of MiB of local disk, so it must not sit in front of the
        sender's no-byte completion path.
        """

        async def _runner() -> None:
            try:
                await self._finish_cdc_file(blob, peer_fp, peer_sid, src_msg)
            except Exception as e:
                log.warning("background CDC finish failed for %s: %s", blob[:8], e)

        asyncio.create_task(_runner())

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
            #
            # v0.20.7 (security audit M21): broader rejection set.
            # The original guard caught `..` / leading `/` /
            # `X:` Windows drive-letter starts, but missed:
            #   - NUL + control characters (POSIX silently truncates
            #     paths at NUL; Windows rejects but logs; either way
            #     a control char in a filename is suspicious).
            #   - UNC paths (``\\server\share\...``) — even after the
            #     `\` → `/` flip these aren't local paths.
            #   - Windows reserved device basenames (CON, NUL, COM1
            #     etc., even with extensions) — opening one yields
            #     the device, not a real file.
            #   - Trailing dot / space — Windows silently strips
            #     them, collapsing distinct names onto one on-disk
            #     entry which an attacker can use for collision.
            norm = file_path.replace("\\", "/").lstrip("/")
            has_control = any(
                ord(c) < 0x20 or ord(c) == 0x7f for c in file_path
            )
            looks_unc = (
                file_path.startswith("\\\\")
                or file_path.startswith("//")
                or "\\\\?\\" in file_path
            )
            from pathlib import PurePosixPath
            try:
                parts = PurePosixPath(norm).parts if norm else ()
            except Exception:
                parts = ()
            reserved_windows = frozenset({
                "CON", "PRN", "AUX", "NUL",
                "COM1", "COM2", "COM3", "COM4", "COM5",
                "COM6", "COM7", "COM8", "COM9",
                "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
                "LPT6", "LPT7", "LPT8", "LPT9",
            })
            has_reserved = any(
                part.split(".")[0].upper() in reserved_windows
                for part in parts
            )
            has_trailing_dot_or_space = any(
                part != part.rstrip(". ") for part in parts
            )
            if (
                not norm
                or ".." in norm.split("/")
                or file_path.startswith("/")
                or (len(file_path) > 1 and file_path[1] == ":")
                or has_control
                or looks_unc
                or has_reserved
                or has_trailing_dot_or_space
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
                peer_fp=peer_fp,  # v0.8.9: attribute conflicts to source
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
            # State + folder_engine are both initialised inside
            # ``start()`` before any chunk can land here; the wider
            # nullable typing is for the boot window.
            assert self.state is not None
            assert self.folder_engine is not None
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
        for endpoint in ack.advertised_endpoints:
            if endpoint.port <= 0:
                continue
            candidates.append((endpoint.host, endpoint.port))
            if observed_host and observed_host != endpoint.host:
                candidates.append((observed_host, endpoint.port))
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
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=(
                            self.HAPPY_EYEBALLS_TIMEOUT_S
                            if timeout is None else float(timeout)
                        ),
                    )
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
    ) -> tuple[Any, Any, asyncio.Task] | None:
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

        # Phase D #1 (ADR-0028): when multiple relays are available
        # AND ol_routing is installed AND we have per-relay
        # RTT/loss telemetry, sort by τ_c-weighted cost. Currently
        # this is a no-op pass-through (metrics surface comes in a
        # follow-up commit); future-proofing means we add the
        # selector at the dial site now so the wire is ready.
        listeners = self._pick_best_relay(list(self._relay_listener_clients))
        for listener in listeners:
            url = listener._rendezvous_url  # type: ignore[attr-defined]
            dial_start = time.perf_counter()
            try:
                reader, writer, pump = await open_relay_outbound(
                    url, dst_pubkey, session=shared_session,
                )
                dial_ms = (time.perf_counter() - dial_start) * 1000.0
                # Phase D #1: record successful dial RTT + success
                # so the next call to _pick_best_relay has fresh data.
                self.record_relay_observation(url, rtt_ms=dial_ms, success=True)
                log.info(
                    "relay dial succeeded for %s via %s",
                    peer.short_id, url,
                )
                return reader, writer, pump
            except Exception as e:
                # Record the failure so future _pick_best_relay calls
                # demote this URL.
                self.record_relay_observation(url, rtt_ms=None, success=False)
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

    # ─── Phase D #3 prefetch hook (ADR-0033) ──────────────────────────
    def _observe_prefetch(self, peer_fp: str, blob_hex: str) -> None:
        """Record a (peer, file_id, t_ms) tuple in the native prefetch
        predictor. Pure observer — failures (native crate missing,
        bad input) are swallowed so they never affect a successful
        transfer. Daemon callers invoke this on every send_file /
        file-receive success so the predictor builds a model of
        peer-pair demand over time."""
        try:
            from one_link import prefetch_native

            if not prefetch_native.HAS_NATIVE:
                if not self._prefetch_unavailable_logged:
                    log.debug(
                        "prefetch_native unavailable — predictor disabled"
                    )
                    self._prefetch_unavailable_logged = True
                return
            if self._prefetch_predictor is None:
                self._prefetch_predictor = prefetch_native.predictor()
            # Map (peer_fp hex string, blob_hex string) -> 32B keys.
            try:
                peer_bytes = bytes.fromhex(peer_fp)[:32]
                file_bytes = bytes.fromhex(blob_hex)[:32]
            except (ValueError, AttributeError):
                return
            if len(peer_bytes) != 32 or len(file_bytes) != 32:
                return
            t_ms = int(time.time() * 1000)
            self._prefetch_predictor.observe(peer_bytes, file_bytes, t_ms)
        except Exception as exc:  # pragma: no cover — defensive
            log.debug("prefetch observe failed (%s)", exc)

    def predict_next_files_for_peer(self, peer_fp: str, n: int = 3):
        """Operator-facing helper: return the predictor's top-N next-
        likely file_ids for ``peer_fp``. Empty list if the predictor
        isn't initialized or the peer has no observations yet."""
        if self._prefetch_predictor is None:
            return []
        try:
            peer_bytes = bytes.fromhex(peer_fp)[:32]
            if len(peer_bytes) != 32:
                return []
            return self._prefetch_predictor.predict_top_n(peer_bytes, n)
        except Exception:
            return []

    def native_diagnostics(self) -> dict:
        """Phase D operator diagnostics — current state of the native
        primitives wired into this daemon.

        Returns a dict with:
          - prefetch.available: bool, prefetch.storage_entries: int
          - routing.available: bool, routing.aead_kind_default: str
            (when the native pipeline is loaded)
          - native_transfer_v1.advertised: bool (whether THIS daemon
            ships NATIVE_TRANSFER_V1 in its CAPS frame)
          - macaroon_dual_issue.last_minted: bool (whether any
            macaroon has been minted since startup)

        Returns the keys for any unavailable subsystem with
        ``available=False`` so the operator sees the full surface."""
        out: dict = {
            "prefetch": {
                "available": False,
                "storage_entries": 0,
            },
            "routing": {
                "available": False,
            },
            "homology": {
                "available": False,
            },
            "coherence_field": {
                "available": False,
                "calibration": None,
            },
            "bloom_init": {
                "available": False,
                "advertised": False,
            },
            "quic_transport": {
                "available": False,
                "advertised": False,
                "endpoint_up": False,
            },
            "native_transfer_v1": {
                "advertised": False,
            },
            "macaroon_dual_issue": {
                "last_minted": False,
                "last_minted_len": 0,
            },
        }
        try:
            from one_link import prefetch_native as _pf

            if _pf.HAS_NATIVE:
                out["prefetch"]["available"] = True
                if self._prefetch_predictor is not None:
                    try:
                        out["prefetch"]["storage_entries"] = (
                            self._prefetch_predictor.storage_entries()
                        )
                    except Exception:  # pragma: no cover
                        pass
        except ImportError:
            pass
        try:
            from one_link import routing_native as _rt

            if _rt.HAS_NATIVE:
                out["routing"]["available"] = True
        except ImportError:
            pass
        try:
            from one_link import homology_native as _hm

            if _hm.HAS_NATIVE:
                out["homology"]["available"] = True
        except ImportError:
            pass
        try:
            from one_link import coherence_field_native as _cf

            if _cf.HAS_NATIVE:
                out["coherence_field"]["available"] = True
                # Surface the One Link calibration so operators can
                # eyeball g_A / ell_screen without dropping into Python.
                try:
                    cal = _cf.one_link_calibration()
                    out["coherence_field"]["calibration"] = {
                        "d": cal["d"],
                        "gamma": cal["gamma"],
                        "screening_length": cal["screening_length"],
                        "apparent_horizon_anchor": cal["apparent_horizon_anchor"],
                    }
                except Exception:  # pragma: no cover
                    pass
                # Field-snapshot live metrics: solve count, failure count,
                # most-recent snapshot age. -1ms age means "no snapshot
                # yet" (manager started but tick hasn't completed).
                try:
                    out["coherence_field"]["snapshot_metrics"] = (
                        self.field_snapshot_metrics()
                    )
                except Exception:  # pragma: no cover
                    pass
        except ImportError:
            pass
        # Phase B Bloom-init availability + advertisement + telemetry.
        try:
            from one_link import bloom_init as _bi
            from one_link.capabilities import BLOOM_INIT_V1, LOCAL_CAPABILITIES

            out["bloom_init"]["available"] = _bi.HAS_NATIVE
            out["bloom_init"]["advertised"] = BLOOM_INIT_V1 in LOCAL_CAPABILITIES
            stats = getattr(self, "_bloom_init_stats", None)
            if stats:
                out["bloom_init"]["advisories_received"] = stats.get(
                    "advisories_received", 0
                )
                out["bloom_init"]["advisories_decode_failed"] = stats.get(
                    "advisories_decode_failed", 0
                )
                out["bloom_init"]["total_bloom_bytes"] = stats.get(
                    "total_bloom_bytes", 0
                )
                out["bloom_init"]["estimated_savings_bytes"] = stats.get(
                    "estimated_savings_vs_explicit_list_bytes", 0
                )
                out["bloom_init"]["bloom_honored_chunks"] = stats.get(
                    "bloom_honored_chunks", 0
                )
                out["bloom_init"]["bloom_vs_file_wants_disagreements"] = (
                    stats.get("bloom_vs_file_wants_disagreements", 0)
                )
        except ImportError:
            pass
        # Phase A2 QUIC transport availability + endpoint status.
        try:
            from one_link import peer_quic as _pq
            from one_link.capabilities import LOCAL_CAPABILITIES, QUIC_TRANSPORT_V1

            out["quic_transport"]["available"] = _pq.HAS_NATIVE
            out["quic_transport"]["advertised"] = (
                QUIC_TRANSPORT_V1 in LOCAL_CAPABILITIES
            )
            out["quic_transport"]["endpoint_up"] = (
                getattr(self, "_quic_endpoint", None) is not None
            )
        except ImportError:
            pass
        # NATIVE_TRANSFER_V1 is advertised whenever it's in
        # LOCAL_CAPABILITIES — see capabilities.py for the source.
        try:
            from one_link.capabilities import LOCAL_CAPABILITIES

            out["native_transfer_v1"]["advertised"] = (
                NATIVE_TRANSFER_V1 in LOCAL_CAPABILITIES
            )
        except Exception:  # pragma: no cover
            pass
        if self._last_minted_macaroon is not None:
            out["macaroon_dual_issue"]["last_minted"] = True
            out["macaroon_dual_issue"]["last_minted_len"] = len(
                self._last_minted_macaroon
            )
        return out

    async def _field_topology_feeder_loop(self) -> None:
        """Background loop that pushes the daemon's live peer-graph
        into the :class:`FieldSnapshotManager` on a 5-second cadence.

        Without this loop the manager has zero topology and skips
        every tick (per the ``min_peers=3`` gate). With it, every
        peer the daemon currently knows about becomes a node, every
        relay metric becomes an edge weight, and the field solver
        produces the snapshots downstream consumers read.

        Cancellation-safe: the loop exits cleanly on daemon.stop.
        Errors are swallowed per-tick so a single transient failure
        doesn't kill the feeder."""
        try:
            while True:
                await asyncio.sleep(5.0)
                mgr = getattr(self, "_field_snapshot", None)
                if mgr is None:
                    continue
                try:
                    self._push_topology_to_field_snapshot(mgr)
                except Exception as exc:  # pragma: no cover
                    log.debug("field topology feeder tick failed: %s", exc)
        except asyncio.CancelledError:
            pass

    def _push_topology_to_field_snapshot(self, mgr) -> None:
        """Single-tick of the topology feed. Builds the (peer, peer,
        weight) edge list from the discovery registry + relay metrics
        and pushes it into the manager. Per-peer source contributions
        (density, flux) are derived from the relay-metrics table:
        density ∝ recent successful dials, flux ∝ inverse RTT."""
        if self.discovery is None:
            return
        peers = list(self.discovery.registry.list())
        if len(peers) < 2:
            return
        # Edge weights: when relay metrics exist for a peer, weight
        # ~= (1 − loss). Fully-meshed star from self.me; real swarm
        # topology evolves once gossip / capability ads encode it.
        edges: list[tuple[str, str, float]] = []
        for a in peers:
            for b in peers:
                if a.short_id >= b.short_id:
                    continue
                edges.append((a.short_id, b.short_id, 1.0))
        mgr.update_topology(edges)
        # Per-peer source contributions.
        metrics = getattr(self, "_relay_metrics", {}) or {}
        for peer in peers:
            url = getattr(peer, "rendezvous_url", None) or peer.short_id
            m = metrics.get(url)
            if m:
                rtt = max(float(m.get("rtt_ms", 100.0)), 1.0)
                loss = float(m.get("loss_rate", 0.0))
                density = 1.0 - min(loss, 1.0)
                flux = 1000.0 / rtt
            else:
                density = 1.0
                flux = 0.5
            mgr.update_peer_source(
                peer.short_id, density=density, flux=flux
            )

    async def _send_via_transport(
        self,
        peer_fp: str,
        channel,
        payload: bytes,
    ) -> None:
        """Send ``payload`` via the per-peer transport facade.

        Selects WebRTC or QUIC based on ``transport_choice_for_peer``
        (when caps + endpoint allow). Falls through to
        ``channel.send`` directly if the facade isn't built for this
        peer (no-op compat path for code that hasn't migrated yet).

        Per-peer transport facades cache lazily inside
        ``_outbound_sessions[peer_fp]._transport``. The first send
        builds; subsequent sends reuse.

        Returns when the underlying transport accepts the bytes.
        Raises whatever the underlying transport raised (after
        bumping stats). The caller's existing error handling
        applies unchanged.
        """
        sess = self._outbound_sessions.get(peer_fp)
        # No session → fall back to direct channel.send. This is the
        # "we don't own this peer yet" path; rare on the production
        # hot path but possible during pairing handshake.
        if sess is None:
            await channel.send(payload)
            return
        # Cached facade or lazy-build.
        facade = getattr(sess, "_transport", None)
        if facade is None:
            from one_link.peer_transport import make_transport_for_peer

            peer = getattr(sess, "peer", None)
            kind = "webrtc"
            if peer is not None:
                try:
                    kind = self.transport_choice_for_peer(peer)
                except Exception:
                    kind = "webrtc"
            if kind == "quic":
                quic_sess = getattr(sess, "_quic_session", None)
                if quic_sess is not None:
                    facade = make_transport_for_peer(
                        "quic", quic_session=quic_sess
                    )
                else:
                    # Daemon's QUIC track flag is set but no live QUIC
                    # session for this peer yet — fall back to WebRTC.
                    facade = make_transport_for_peer(
                        "webrtc", channel=channel
                    )
            else:
                facade = make_transport_for_peer("webrtc", channel=channel)
            sess._transport = facade  # type: ignore[attr-defined]
        try:
            await facade.send_bytes_async(payload)
        except Exception:
            # Drop the facade so the next send rebuilds (e.g. after
            # transport-level reconnect). Re-raise so the existing
            # error path is intact.
            try:
                sess._transport = None  # type: ignore[attr-defined]
            except Exception:
                pass
            raise

    # ── Phase A2 QUIC dual-stack transport wiring ──────────────────

    def _ensure_quic_endpoint(self):
        """Lazily build the local QUIC endpoint. Returns ``None``
        when the native crate isn't installed; daemon then keeps
        using WebRTC for every peer. Idempotent."""
        existing = getattr(self, "_quic_endpoint", None)
        if existing is not None:
            return existing
        try:
            from one_link import peer_quic

            ep = peer_quic.make_endpoint()
            self._quic_endpoint = ep
            return ep
        except Exception as e:  # pragma: no cover
            log.warning("QUIC endpoint init failed (%s); WebRTC-only", e)
            self._quic_endpoint = None
            return None

    def transport_choice_for_peer(self, peer) -> str:
        """Decide which transport to use for ``peer`` based on
        capability advertisement. Returns ``"quic"`` or ``"webrtc"``.

        Per [PHASE_A2_QUIC_CUTOVER_PLAN.md](../../docs/PHASE_A2_QUIC_CUTOVER_PLAN.md):
        QUIC requires (a) both peers advertise ``QUIC_TRANSPORT_V1``,
        (b) the local endpoint is up, (c) the peer has a dial-able
        address. Browser peers always get WebRTC; v0.20.x peers
        always get WebRTC (no cap → no QUIC). New v0.22+ daemons
        will negotiate QUIC when both ends advertise the cap.
        """
        try:
            from one_link import peer_quic
            from one_link.capabilities import (
                LOCAL_CAPABILITIES,
                QUIC_TRANSPORT_V1,
            )
        except ImportError:  # pragma: no cover
            return "webrtc"
        if not peer_quic.HAS_NATIVE:
            return "webrtc"
        if self._ensure_quic_endpoint() is None:
            return "webrtc"
        peer_caps = getattr(peer, "capabilities", None) or getattr(
            peer, "advertised_caps", None
        )
        if peer_caps is None:
            return "webrtc"
        if peer_quic.should_prefer_quic_for_peer(
            tuple(LOCAL_CAPABILITIES), tuple(peer_caps)
        ):
            return "quic"
        return "webrtc"

    def _bloom_only_for_peer(self, peer_fp: str) -> bool:
        """Predicate: should this peer's offer-ack drop the FILE_WANTS
        list and rely on BLOOM_INIT_FILTER alone?

        All four must hold:
        1. ``ONE_LINK_BLOOM_HONOR=1`` env flag set.
        2. Peer advertises ``BLOOM_INIT_V1`` capability.
        3. The native ``ol_bloom`` crate is installed.
        4. The receiver has some chunks to advertise (empty Bloom means
           "send everything" — keep FILE_WANTS as the clear signal).

        Returns False on any failure → caller falls back to the
        legacy FILE_WANTS path. This preserves correctness for every
        peer that doesn't meet all four conditions.
        """
        try:
            from one_link import bloom_init

            if not bloom_init.HAS_NATIVE:
                return False
            if not bloom_init.bloom_honor_enabled():
                return False
        except ImportError:
            return False
        from one_link.capabilities import BLOOM_INIT_V1

        if BLOOM_INIT_V1 not in self._peer_advertised_caps(peer_fp):
            return False
        # Empty receiver inventory → no advantage to Bloom-only.
        # Falling back to FILE_WANTS preserves the explicit "send
        # everything" semantics.
        return bool(self._locally_held_chunk_ids_for_blob(""))

    async def _maybe_send_bloom_init_advisory(
        self, channel, *, msg_id: str, blob: str, peer_fp: str
    ) -> None:
        """Send a BLOOM_INIT_FILTER advisory frame to the sender,
        listing the receiver's locally-held chunk IDs as a Bloom.

        No-op when:
        - The peer doesn't advertise BLOOM_INIT_V1.
        - The native bloom crate isn't installed.
        - The receiver has no chunks to report.

        Pure telemetry today — the sender currently uses the
        accompanying FILE_WANTS list as the canonical source. The
        advisory exists so operators can compare wire-byte costs
        (FILE_WANTS list vs Bloom) in `/api/metrics` before the
        Phase B cutover commits to Bloom as primary.
        """
        from one_link.capabilities import BLOOM_INIT_V1

        # Peer capability gate.
        if BLOOM_INIT_V1 not in self._peer_advertised_caps(peer_fp):
            return
        # Native availability gate.
        try:
            from one_link import bloom_init

            if not bloom_init.HAS_NATIVE:
                return
        except ImportError:
            return
        # Build the Bloom over chunks the receiver actually has.
        known_ids = self._locally_held_chunk_ids_for_blob(blob)
        if not known_ids:
            return
        try:
            advertisement = bloom_init.build_receiver_bloom(known_ids)
        except Exception:  # pragma: no cover
            return
        import base64

        await channel.send(encode_msg(make_msg(
            "BLOOM_INIT_FILTER", self.me.short_id,
            of=msg_id, blob=blob,
            bloom=base64.b64encode(advertisement).decode("ascii"),
            n_known=len(known_ids),
        )))

    def _peer_advertised_caps(self, peer_fp: str) -> frozenset[str]:
        """Best-effort lookup of which capabilities `peer_fp` advertised
        during pairing. Returns an empty set when the peer is unknown
        or never advertised."""
        sess = self._outbound_sessions.get(peer_fp)
        if sess is None:
            return frozenset()
        chan = getattr(sess, "channel", None)
        if chan is None:
            return frozenset()
        peer_caps = getattr(chan, "peer_caps", None) or {}
        feats = peer_caps.get("features") if isinstance(peer_caps, dict) else None
        if feats is None:
            return frozenset()
        if isinstance(feats, (list, tuple, set, frozenset)):
            return frozenset(str(f) for f in feats)
        return frozenset()

    def _locally_held_chunk_ids_for_blob(self, _blob: str) -> list[bytes]:
        """Return the set of chunk_ids this daemon already holds that
        are relevant to the manifest of `blob`. Default implementation
        returns the empty list (manifests aren't kept on the receiver
        side until after the transfer completes). Sub-classes /
        production extensions override.

        Hook for future Bloom-init wiring once a manifest-cache
        surface exists. Empty list is safe — receiver advertises no
        prior knowledge → sender ships everything (correctness
        preserved)."""
        return []

    async def _handle_bloom_init_advisory(self, channel, msg, peer_fp: str) -> None:
        """Sender-side handler for BLOOM_INIT_FILTER messages.

        Phase B canonical-honor path: decodes the Bloom and caches it
        keyed by ``(peer_fp, blob)``. The transfer's chunk-dispatch
        loop consults the cache via :meth:`bloom_decision_for_chunk`
        as the canonical "does the receiver have this chunk?" answer.

        The FILE_WANTS list that arrived alongside stays as a cross-
        check + a fallback for transfers initiated before the
        advisory landed (race window) or for blobs the receiver
        hasn't sent a Bloom for.

        Telemetry counters:
        - ``advisories_received`` — wire frames seen.
        - ``advisories_decode_failed`` — wire frames we couldn't decode.
        - ``total_bloom_bytes`` — sum of advisory body sizes.
        - ``estimated_savings_vs_explicit_list_bytes`` — what a
          FILE_WANTS list of the same n_known would have cost.
        - ``bloom_honored_chunks`` — chunks whose dispatch decision
          consulted the cached Bloom.
        - ``bloom_vs_file_wants_disagreements`` — Bloom said "have it"
          but FILE_WANTS said "send it." Expected at ~5% of the
          receiver's known-chunk count (the Bloom false-positive rate).
        """
        import base64

        blob = str(msg.get("blob") or "")
        bloom_b64 = msg.get("bloom") or ""
        n_known = msg.get("n_known")
        if not blob or not bloom_b64:
            return
        try:
            wire = base64.b64decode(bloom_b64, validate=True)
        except (binascii.Error, ValueError):
            log.debug("BLOOM_INIT_FILTER from %s: bad base64", peer_fp[:8])
            return
        # Decode + cache the Bloom keyed by (peer_fp, blob). The
        # transfer's chunk-dispatch loop reads this via
        # bloom_decision_for_chunk on each chunk decision.
        bloom_obj = None
        try:
            from one_link import bloom_init

            if bloom_init.HAS_NATIVE:
                bloom_obj = bloom_init.decode_receiver_bloom(wire)
        except Exception as e:  # pragma: no cover
            log.debug("BLOOM_INIT_FILTER decode failed (%s)", e)
        if bloom_obj is not None:
            cache = getattr(self, "_bloom_init_cache", None)
            if cache is None:
                cache = {}
                self._bloom_init_cache = cache
            cache[(peer_fp, blob)] = bloom_obj

        # Telemetry: always bump (failure path is its own counter).
        stats = getattr(self, "_bloom_init_stats", None)
        if stats is None:
            stats = {
                "advisories_received": 0,
                "advisories_decode_failed": 0,
                "total_bloom_bytes": 0,
                "estimated_savings_vs_explicit_list_bytes": 0,
                "bloom_honored_chunks": 0,
                "bloom_vs_file_wants_disagreements": 0,
            }
            self._bloom_init_stats = stats
        stats["advisories_received"] += 1
        stats["total_bloom_bytes"] += len(wire)
        if bloom_obj is None:
            stats["advisories_decode_failed"] = (
                stats.get("advisories_decode_failed", 0) + 1
            )
        try:
            n_known_int = int(n_known) if n_known is not None else 0
            explicit_cost = n_known_int * 32
            stats["estimated_savings_vs_explicit_list_bytes"] += max(
                explicit_cost - len(wire), 0
            )
        except (TypeError, ValueError):
            pass

    def bloom_decision_for_chunk(
        self, peer_fp: str, blob: str, chunk_id: bytes
    ) -> bool | None:
        """Phase B canonical honor query: "does ``peer_fp`` already
        have ``chunk_id`` for ``blob`` per their advertised Bloom?"

        Returns:
        - ``True`` — Bloom says receiver has it; sender may skip (modulo
          ~5% false-positive rate which an out-of-band ACK-retry
          corrects).
        - ``False`` — Bloom says missing; sender must ship.
        - ``None`` — no cached Bloom for this peer/blob; caller must
          fall back to FILE_WANTS or send-everything.

        The honored-chunks counter is bumped on every consult so the
        ``/api/metrics`` surface shows operational adoption.
        """
        cache = getattr(self, "_bloom_init_cache", None)
        if cache is None:
            return None
        bf = cache.get((peer_fp, blob))
        if bf is None:
            return None
        try:
            in_receiver = bf.contains(chunk_id)
        except Exception:
            return None
        stats = getattr(self, "_bloom_init_stats", None)
        if stats is not None:
            stats["bloom_honored_chunks"] = (
                stats.get("bloom_honored_chunks", 0) + 1
            )
        return in_receiver

    def bloom_cross_check_with_file_wants(
        self,
        peer_fp: str,
        blob: str,
        file_wants_list: list[str],
        full_manifest: list[bytes],
    ) -> None:
        """Cross-check accounting. For each manifest chunk the Bloom
        claims the receiver has BUT the FILE_WANTS list says is
        missing, bump a disagreement counter. Operators watch this in
        production; large values mean the Bloom is mis-sized or the
        receiver lied about its inventory.
        """
        cache = getattr(self, "_bloom_init_cache", None)
        if cache is None:
            return
        bf = cache.get((peer_fp, blob))
        if bf is None:
            return
        wants_set = set(file_wants_list or [])
        stats = getattr(self, "_bloom_init_stats", None)
        if stats is None:
            return
        for chunk_id in full_manifest:
            try:
                in_bloom = bf.contains(chunk_id)
            except Exception:
                continue
            hex_id = (
                chunk_id.hex() if isinstance(chunk_id, (bytes, bytearray))
                else str(chunk_id)
            )
            in_wants = hex_id in wants_set
            if in_bloom and in_wants:
                stats["bloom_vs_file_wants_disagreements"] = (
                    stats.get("bloom_vs_file_wants_disagreements", 0) + 1
                )

    # ── Phase B Bloom-init handshake wiring ────────────────────────

    def build_local_bloom_advertisement(
        self, known_chunk_ids: list[bytes]
    ) -> bytes | None:
        """Build the receiver-side Bloom filter advertising which
        chunks this daemon already holds. Returned as the wire-encoded
        bytes ready to send in a BLOOM_INIT frame.

        Returns ``None`` when the native bloom crate isn't installed —
        callers fall back to full manifest exchange.
        """
        try:
            from one_link import bloom_init

            if not bloom_init.HAS_NATIVE:
                return None
            return bloom_init.build_receiver_bloom(known_chunk_ids)
        except Exception as e:  # pragma: no cover
            log.debug("Bloom-init advertisement failed (%s)", e)
            return None

    def filter_manifest_with_receiver_bloom(
        self,
        manifest_chunk_ids: list[bytes],
        receiver_bloom_wire: bytes,
    ) -> list[bytes] | None:
        """Decode the receiver's Bloom advertisement and return the
        manifest subset the receiver appears to be missing. Returns
        ``None`` on decode error or native-crate absence — callers
        then ship the full manifest."""
        try:
            from one_link import bloom_init

            if not bloom_init.HAS_NATIVE:
                return None
            bf = bloom_init.decode_receiver_bloom(receiver_bloom_wire)
            return bloom_init.filter_manifest_against_bloom(
                manifest_chunk_ids, bf
            )
        except Exception as e:  # pragma: no cover
            log.debug("Bloom-init receiver-bloom decode failed (%s)", e)
            return None

    # ── Phase E field-snapshot manager wiring ──────────────────────

    def _ensure_field_snapshot(self):
        """Lazily build + start the FieldSnapshotManager on first
        access. Safe to call repeatedly; idempotent."""
        if self._field_snapshot is not None:
            return self._field_snapshot
        try:
            from one_link.field_snapshot import FieldSnapshotManager

            self._field_snapshot = FieldSnapshotManager()
            self._field_snapshot.start()
        except Exception as e:  # pragma: no cover
            log.warning("field-snapshot manager unavailable: %s", e)
            self._field_snapshot = None
        return self._field_snapshot

    def field_snapshot_metrics(self) -> dict:
        """Operator-facing metrics from the field-snapshot manager.
        Returns the safe-default zero block if Phase E isn't running."""
        snap_mgr = getattr(self, "_field_snapshot", None)
        if snap_mgr is None:
            return {
                "field_solve_count": 0,
                "field_solve_failures": 0,
                "field_snapshot_age_ms": -1.0,
                "field_topology_edge_count": 0,
            }
        try:
            return snap_mgr.metrics()
        except Exception:  # pragma: no cover
            return {}

    def cadence_for_peer(self, peer_short_id: str) -> int | None:
        """Field-driven bytes-between-rotations advisory for the named
        peer. Returns ``None`` when no snapshot exists or the peer is
        absent from the latest snapshot — callers fall back to the
        baseline cadence."""
        snap_mgr = getattr(self, "_field_snapshot", None)
        if snap_mgr is None:
            return None
        try:
            return snap_mgr.cadence_for_peer(peer_short_id)
        except Exception:  # pragma: no cover
            return None

    def field_score_for_peer(self, peer_short_id: str) -> float | None:
        """Normalised field score (0, 1] at the named peer. Consumed
        by the bandit-prior shaper and the prefetch scheduler."""
        snap_mgr = getattr(self, "_field_snapshot", None)
        if snap_mgr is None:
            return None
        try:
            return snap_mgr.field_score_for_peer(peer_short_id)
        except Exception:  # pragma: no cover
            return None

    def _pick_best_relay(self, available_relays: list) -> list:
        """Phase D #1 (ADR-0028) + Phase E (FILE_ENGINE_V2_PLAN.md) —
        sort relay candidates by τ_c-weighted cost when ol_routing is
        available + we have empirical RTT/loss metrics for the relay
        set. Falls back to the input order otherwise. Pure helper:
        never raises, never drops a relay (just reorders).

        The cost model uses per-relay τ_c = max(1ms, 1.0 / max(rtt_ms,
        1.0)) and loss_rate from the relay's recent ACK record. Without
        empirical metrics, every relay defaults to the same cost so
        the input order is preserved.

        Phase E upgrade: when ``ol_coherence_field`` is available the
        heuristic ``loss_penalty = 1/(1-loss)^2`` is replaced with the
        BE-RAR interpolation ``nu(y) = 1/(1 - exp(-sqrt(y)))``. α = 1/2
        is forced by Bose statistics rather than fit, and the same
        function drives galaxy rotation-curve fitting in the S_One
        canonical theorem stack — see ``coherence_field_native``."""
        if len(available_relays) <= 1:
            return list(available_relays)
        try:
            from one_link import routing_native as _rt

            if not _rt.HAS_NATIVE:
                return list(available_relays)
        except ImportError:
            return list(available_relays)
        # Without per-relay RTT/loss telemetry in this daemon (yet),
        # the routing-aware sort is currently a no-op pass-through.
        # When peer_rtc / relay_client start recording per-relay
        # metrics, this picks them up via _relay_metrics_for(url).
        # Bind through the unbound class form so the helper works on
        # both real Daemon instances and lightweight stubs that supply
        # ``_relay_metrics`` directly without rebinding the method.
        metrics_for = getattr(
            self, "_relay_metrics_for", None
        ) or (lambda u: Daemon._relay_metrics_for(self, u))
        # Phase E upgrade: when ol_coherence_field is available, replace
        # the heuristic `loss_penalty = 1/(1-loss)^2` with the BE-RAR
        # interpolation `nu(y) = 1/(1 - exp(-sqrt(y)))` (alpha = 1/2
        # forced by Bose statistics — not a free knob). y = loss / (1 -
        # loss) is the loss-deficit ratio, the network analog of the
        # gravitational potential the BE-RAR was originally derived for.
        # When the crate isn't installed, fall back to the Phase D
        # routing-native cost.
        use_be_rar = False
        try:
            from one_link import coherence_field_native as _cf

            use_be_rar = _cf.HAS_NATIVE
        except ImportError:
            _cf = None  # type: ignore[assignment]
        scored: list[tuple[float, object]] = []
        for relay in available_relays:
            url = getattr(relay, "_rendezvous_url", str(relay))
            metrics = metrics_for(url)
            if metrics is None:
                # No empirical metrics → arbitrary stable cost.
                scored.append((1.0, relay))
                continue
            rtt_ms = max(1.0, float(metrics.get("rtt_ms", 100.0)))
            loss = min(0.99, max(0.0, float(metrics.get("loss_rate", 0.0))))
            tau_c_s = max(1.0e-3, 1.0 / rtt_ms)
            if use_be_rar:
                # BE-RAR-weighted edge cost: edge_weight × nu(y_quality).
                #
                # Cosmological BE-RAR shape: nu(y) is monotonically
                # DECREASING from ∞ at y=0 to 1 at y=∞. In the galaxy
                # mapping, y = a_bar²/a_0² (gravitational pull relative
                # to anchor): outer regions (low y) have huge nu boost
                # (deep MOND), inner regions (high y) have nu = 1
                # (Newtonian).
                #
                # Network analog: define y = (1 - loss)/loss as the
                # "quality ratio." At loss = 0 (perfect) → y = ∞ →
                # nu = 1 (baseline cost, no penalty). At loss → 1 →
                # y → 0 → nu → ∞ (huge penalty multiplier). This is
                # the physically-correct mapping; the earlier wiring
                # (y = loss/(1 - loss)) was inverted.
                #
                # alpha = 1/2 is forced by Bose statistics — not a
                # free knob — and the same nu(y) drives galaxy
                # rotation-curve fitting in the S_One canonical stack.
                edge_w = _rt.edge_weight(tau_c_s, 100.0)
                # Loss clamped to (1e-6, 1−1e-6) so y is finite and
                # be_rar() gets a positive input.
                clamped_loss = min(max(loss, 1e-6), 1.0 - 1e-6)
                y_quality = (1.0 - clamped_loss) / clamped_loss
                penalty = _cf.be_rar(y_quality)
                cost = edge_w * penalty
            else:
                cost = _rt.edge_cost(tau_c_s, 100.0, loss)
            scored.append((cost, relay))
        scored.sort(key=lambda x: x[0])
        return [r for _, r in scored]

    def _relay_metrics_for(self, url: str) -> dict | None:
        """Per-relay empirical metrics (``rtt_ms``, ``loss_rate``).
        Returns ``None`` for relays we haven't observed yet so
        :meth:`_pick_best_relay` falls back to input order; otherwise
        returns the EWMA-smoothed dict recorded by
        :meth:`record_relay_observation`. Tolerates a missing
        ``_relay_metrics`` field (returns ``None``) so the helper is
        safe to call on stubs / partially-initialized daemons."""
        store = getattr(self, "_relay_metrics", None)
        if store is None:
            return None
        return store.get(url)

    def record_relay_observation(
        self, url: str, *, rtt_ms: float | None, success: bool
    ) -> None:
        """Record one relay dial outcome. EWMA-smooths rtt_ms with
        alpha=0.2; loss_rate is the fraction of failed attempts in a
        moving window via the same EWMA. Call from every
        :func:`open_relay_outbound` success/failure site so
        :meth:`_pick_best_relay` has fresh data to sort on.

        Idempotent + thread-safe: dict-level updates are atomic in
        CPython under the GIL; the EWMA math is read-modify-write of a
        single key. The metrics surface tolerates a benign race that
        loses one update — never crashes."""
        alpha = 0.2
        now_ms = int(time.time() * 1000)
        cur = self._relay_metrics.get(url) or {
            "rtt_ms": 100.0,
            "loss_rate": 0.0,
            "n_attempts": 0,
            "n_successes": 0,
            "last_observed_ms": now_ms,
        }
        cur["n_attempts"] = int(cur.get("n_attempts", 0)) + 1
        if success:
            cur["n_successes"] = int(cur.get("n_successes", 0)) + 1
            if rtt_ms is not None and rtt_ms > 0:
                prev = float(cur.get("rtt_ms", rtt_ms))
                cur["rtt_ms"] = (1.0 - alpha) * prev + alpha * float(rtt_ms)
        # Loss-rate EWMA: 0 for success, 1 for failure.
        prev_loss = float(cur.get("loss_rate", 0.0))
        obs_loss = 0.0 if success else 1.0
        cur["loss_rate"] = (1.0 - alpha) * prev_loss + alpha * obs_loss
        cur["last_observed_ms"] = now_ms
        self._relay_metrics[url] = cur

    def _abort_incoming_file(self, blob: str, f: IncomingFile) -> None:
        with contextlib.suppress(Exception):
            f.handle.close()
        self._incoming_files.pop(blob, None)
        with contextlib.suppress(OSError):
            f.out_path.unlink()
        self._update_transfer(f.transfer_id, status="failed")

    def _ack_batch_size_from_chunk(self, msg: dict) -> int:
        try:
            requested = int(msg.get("ack_batch") or 1)
        except (TypeError, ValueError, OverflowError):
            requested = 1
        return max(1, min(FILE_ACK_BATCH_MAX, requested))

    async def _flush_file_ack_batch(self, channel, f: IncomingFile) -> None:
        if not f.ack_batch_ids:
            return
        ids = [str(v) for v in f.ack_batch_ids if v]
        f.ack_batch_ids.clear()
        if not ids:
            return
        await channel.send(encode_msg(make_msg(
            "FILE_ACK_BATCH",
            self.me.short_id,
            blob=f.blob_hex,
            ofs=ids,
            count=len(ids),
        )))

    async def _ack_file_chunk(
        self,
        channel,
        msg: dict,
        f: IncomingFile,
        *,
        force_individual: bool = False,
    ) -> None:
        msg_id = str(msg.get("id") or "")
        if not msg_id:
            return
        batch_size = self._ack_batch_size_from_chunk(msg)
        if force_individual or batch_size <= 1:
            await self._flush_file_ack_batch(channel, f)
            await channel.send(encode_msg(make_msg(
                "ACK",
                self.me.short_id,
                of=msg_id,
            )))
            return
        f.ack_batch_ids.append(msg_id)
        if len(f.ack_batch_ids) >= batch_size:
            await self._flush_file_ack_batch(channel, f)

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
        # Bundle 56: a peer with a valid signed capability grant
        # (Bundle 44) for this exact (cap) is allowed regardless of
        # the binary pinned-policy state. Useful for one-shot
        # delegation flows (e.g. a colleague granted "files:read"
        # for the next hour) without forcing them through the full
        # SAS pair flow. The grant's signature attests authority;
        # CapStore enforces auto-expiry + replay.
        if self._cap_store is not None and self.state is not None:
            try:
                peer_pub = self._peer_pub_for_fp(peer_fp)
                # Local granter pubkey == this device's identity. A
                # future bundle adds delegation chains where another
                # paired peer can act as granter; for now self-grant
                # is the only authority recognized.
                if peer_pub is not None and self._cap_store.has_capability(
                    granter_pub=self.me.public_bytes,
                    subject_pub=peer_pub,
                    capability=cap,
                ):
                    return True
            except Exception:
                pass
        if self.state is None:
            return True
        policy = self.state.get_peer_capability_policy(peer_fp)
        return policy is None or cap in policy

    async def issue_capability_grant(
        self,
        peer_fp: str,
        *,
        capabilities: list[str],
        scope: bytes = b"",
        duration_ms: int = 60 * 60 * 1000,
    ) -> bytes:
        """Bundle 58: mint a signed capability grant authorizing the
        named peer to take ``capabilities`` against this daemon's
        resources, store the grant in our local cap_store (which
        ``_capability_allowed`` consults), and ship a notification
        to the peer over the established channel.

        Returns the grant blob. The peer's ACK (success / failure)
        is logged; failure to ship doesn't roll back our local
        store, since the grant is locally authoritative."""
        import time as _time

        from one_link import caps_grants as _caps_grants

        peer_pub = self._peer_pub_for_fp(peer_fp)
        if peer_pub is None:
            raise RuntimeError(
                f"no pubkey on file for peer {peer_fp[:16]}; cannot grant"
            )
        now = int(_time.time() * 1000)
        priv_seed = self.me.private.private_bytes_raw()
        grant_blob = _caps_grants.encode_grant(
            granter_priv_seed=priv_seed,
            granter_pub=self.me.public_bytes,
            subject_pub=peer_pub,
            capabilities=capabilities,
            not_before_ms=now,
            not_after_ms=now + duration_ms,
            scope=scope,
        )
        # Phase C-3 daemon migration (ADR-0021): dual-issue a
        # macaroon-style capability alongside the legacy Ed25519 grant.
        # The legacy blob remains authoritative on the wire so old
        # peers stay compatible; the macaroon is stashed in the cap
        # store for clients that advertise the new path. When all
        # paired peers advertise macaroon support, the legacy issue
        # collapses to the macaroon-only branch in a follow-up
        # release.
        try:
            from one_link import cap_migration as _cap_migration

            macaroon = _cap_migration.mint_share_capability(
                granter_priv_seed=priv_seed,
                granter_pub=self.me.public_bytes,
                subject_pub=peer_pub,
                capabilities=capabilities,
                not_after_ms=now + duration_ms,
                scope=scope if isinstance(scope, (bytes, bytearray)) else bytes(scope or b""),
            )
            self._last_minted_macaroon = macaroon.encode()
        except Exception as exc:  # native module missing or transient failure
            self._last_minted_macaroon = None
            log.debug("macaroon dual-issue skipped: %s", exc)
        # Local-authoritative: store in OUR cap_store first, so
        # _capability_allowed picks it up immediately even if the
        # wire ship fails.
        self._cap_store.accept(
            grant_blob,
            expected_subject_pub=peer_pub,
            expected_granter_pub=self.me.public_bytes,
        )
        # Ship to the peer for their UI / audit. Module-level base64
        # is already in scope; do NOT shadow it with a local import.
        peer = self._peer_from_fp(peer_fp)
        if peer is not None:
            grant_b64 = base64.urlsafe_b64encode(grant_blob).rstrip(
                b"=",
            ).decode("ascii")
            # Phase C-3 (ADR-0027): if a macaroon was dual-issued
            # alongside this Ed25519 grant, advertise it on the
            # CAPABILITY_GRANT wire frame as `macaroon_b64`. Receivers
            # that understand the new format can verify the macaroon
            # path; legacy receivers ignore unknown keys. The wire
            # is forward-compatible: this field is purely additive.
            grant_fields = {"grant_b64": grant_b64}
            if self._last_minted_macaroon is not None:
                try:
                    grant_fields["macaroon_b64"] = base64.urlsafe_b64encode(
                        self._last_minted_macaroon
                    ).rstrip(b"=").decode("ascii")
                except Exception as exc:  # pragma: no cover - defensive
                    log.debug("macaroon advertisement skipped: %s", exc)
            with contextlib.suppress(Exception):
                await self.send_to(peer, [make_msg(
                    "CAPABILITY_GRANT",
                    self.me.short_id,
                    **grant_fields,
                )])
        return grant_blob

    def _peer_from_fp(self, peer_fp: str) -> Optional[Peer]:
        """Resolve a peer_fp to a discovery.Peer if present in
        the registry, else None."""
        if self.discovery is None or self.discovery.registry is None:
            return None
        for p in self.discovery.registry.list():
            if fingerprint_of(bytes.fromhex(p.ed_pub_hex)) == peer_fp:
                return p
        return None

    def _peer_pub_for_fp(self, peer_fp: str) -> Optional[bytes]:
        """Resolve a hex fingerprint back to the 32-byte raw pubkey
        from the peer registry, when known. Used by Bundle 56's
        grant lookup; returns None if we don't have a pub on file
        (in which case grant-based authority is unavailable for
        this peer)."""
        if self.state is None:
            return None
        rec = self.state.get_peer(peer_fp)
        if rec is None or not rec.pubkey:
            return None
        return rec.pubkey

    def _apply_default_capability_policy(self, peer_fp: str) -> None:
        """v0.20.7 (security audit C3): at SAS-pair finalize, the per-peer
        policy default is driven by the `pair_default_allow_all` setting.

        v0.7.3 silently reversed the v0.7.2 audit-finding-A deny-by-default
        ground (a None setting was treated as allow-all). The audit doc
        and capabilities.py STILL document deny-by-default; runtime
        contradicted both. v0.20.7 restores the deny-by-default ground:
        a None or unset setting is treated as DENY, not allow.

          - True: leave policy = None.
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
            # v0.20.7: deny-by-default. Only an explicit truthy setting
            # opts in to legacy allow-all; None / unset / empty / falsy
            # all resolve to deny (policy=[]).
            allow_all = (
                v is not None
                and isinstance(v, str)
                and v.lower() in ("1", "true", "yes")
            )
        except Exception:
            allow_all = False
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
                # Route PING through the PeerTransport facade — the
                # first message-type to migrate from raw channel.send.
                # Pure facade path for WebRTC peers (no behavior change);
                # routes through QuicTransport for peers on the QUIC
                # track once that cap negotiates true. See
                # PHASE_A2_QUIC_CUTOVER_PLAN.md.
                ping_bytes = encode_msg(make_msg("PING", self.me.short_id))
                await self._send_via_transport(
                    sess.peer_fp, sess.channel, ping_bytes
                )
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
                        # v0.8.2: ratchet activation on probe-time CAPS.
                        # In practice the session was already CAPS-
                        # exchanged at construction — this is a
                        # defence in depth for any session that
                        # somehow missed it.
                        with contextlib.suppress(Exception):
                            sess.channel.note_caps_received(features)
                            sess.channel.maybe_activate_ratchet()
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

    async def _get_outbound_session(
        self,
        peer: Peer,
        *,
        resume_pending: bool = True,
    ) -> OutboundSession:
        peer_fp = self._peer_fp_from_peer(peer)
        if not peer_fp:
            raise RuntimeError("peer has no verifiable public key for persistent session")
        # v0.20.7+ (Bundle 55): serialize the check-or-create critical
        # section so N concurrent send_to() calls to the same peer
        # collapse onto a single fresh session. Without this, each
        # caller dials its own TCP connection while the others are
        # mid-handshake; the last to store wins and the rest race to
        # be torn down by the peer's per-fp cap.
        create_lock = self._outbound_session_create_locks.get(peer_fp)
        if create_lock is None:
            create_lock = asyncio.Lock()
            self._outbound_session_create_locks[peer_fp] = create_lock
        async with create_lock:
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
            return await self._create_outbound_session_locked(
                peer, peer_fp, resume_pending=resume_pending,
            )

    async def _create_outbound_session_locked(
        self,
        peer: Peer,
        peer_fp: str,
        *,
        resume_pending: bool = True,
    ) -> OutboundSession:
        """Caller holds ``self._outbound_session_create_locks[peer_fp]``.
        Performs the dial + handshake + dict-store under the lock so a
        racing caller arriving on the same peer_fp finds the session
        already in the dict by the time it gets to the check."""
        now = time.time()

        reader, writer, regime = await self._dial_peer_with_regime(peer)
        # Audit fix: when the regime is "relay", _dial_peer_with_regime
        # stashes the inbound-pump task on the writer for cleanup.
        relay_pump = getattr(writer, "_relay_pump_task", None)
        try:
            try:
                # v0.20.7 (M1): bind expected responder pubkey into the
                # HELLO sig so an attacker re-routing our HELLO can't
                # silently land us at a different paired peer.
                channel = await asyncio.wait_for(
                    ch.initiate(
                        reader, writer, self.me,
                        expected_responder_ed_pub=bytes.fromhex(peer.ed_pub_hex),
                    ),
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
            # v0.8.2: half-step toward ratchet activation. The
            # peer's CAPS will arrive on the first recv inside the
            # session-using path (send_to / send_file / probe). At
            # that point note_caps_received fires and the channel
            # flips to ratchet mode for both directions.
            with contextlib.suppress(Exception):
                channel.note_caps_sent()
                channel.maybe_activate_ratchet()
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
            # v0.7.4: same trigger for paused outbound transfers.
            # The resume task acquires its own per-peer lock so two
            # session-up events can't fire duplicate sends. Fresh
            # send_file() calls disable this while their just-created
            # "planning" row is still moving into offered/active; otherwise
            # the resume worker can race and recursively resend the same row.
            if resume_pending:
                self._schedule_resume_paused(peer_fp)
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
                    send_started = time.monotonic()
                    # Phase A2: route through the PeerTransport facade
                    # — the second message-type migration after PING.
                    # send_to handles text + control messages, the
                    # next-highest-traffic path after PING. WebRTC
                    # behavior unchanged; QUIC peers (when capability
                    # negotiation flips true) route through QuicTransport
                    # via _send_via_transport.
                    await self._send_via_transport(
                        sess.peer_fp, sess.channel, encode_msg(m)
                    )
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
                            # v0.8.2: half-step toward ratchet
                            # activation. If we already sent CAPS
                            # right after handshake, this completes
                            # the negotiation and flips the channel.
                            with contextlib.suppress(Exception):
                                sess.channel.note_caps_received(features)
                                if sess.channel.maybe_activate_ratchet():
                                    log.info(
                                        "ratchet activated on outbound "
                                        "session for %s",
                                        sess.peer_fp[:8],
                                    )
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
                    self._stamp_pair_health(
                        sess.peer_fp,
                        latency_ms=(time.monotonic() - send_started) * 1000.0,
                        best_route=sess.regime,
                    )
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

    async def _send_control(self, peer: Peer, msg: dict) -> Optional[bytes]:
        """Open a one-shot connection, send a single control msg, wait for
        ACK, close cleanly. Waiting for the ACK forces the receiver to fully
        process the message before our close — avoids Win10053 abort races.

        v0.20.7 (security audit H11): returns the channel's
        transcript_hash so callers (notably the pair flow) can bind
        per-session derivations to it. Returns None on dial / handshake
        failure so existing callers that ignore the return value
        continue to work unchanged.
        """
        reader, writer = await self._dial_peer(peer)
        try:
            # v0.20.7 (M1): bind expected responder pubkey to defeat UKS.
            channel = await ch.initiate(
                reader, writer, self.me,
                expected_responder_ed_pub=bytes.fromhex(peer.ed_pub_hex),
            )
            self._verify_channel_peer(peer, channel)
            transcript = getattr(channel, "transcript_hash", None)
            try:
                await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
                # v0.8.2: half-step. This is _send_control — a
                # short-lived dial that sends one msg + waits for
                # ACK. If the peer's CAPS arrives + we've already
                # sent ours, the recv loop below picks up the
                # peer's CAPS and the channel flips automatically.
                with contextlib.suppress(Exception):
                    channel.note_caps_sent()
                    channel.maybe_activate_ratchet()
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
            return transcript
        except Exception:
            with contextlib.suppress(Exception):
                writer.close()
                await writer.wait_closed()
            raise

    async def initiate_pair(self, peer: Peer) -> str:
        """Start pairing with peer. Returns the SAS to display in our UI.

        v0.20.7 (security audit H11): the SAS is computed AFTER the
        encrypted channel opens, so it can be bound to the channel's
        transcript_hash. Without that binding, an attacker grinding
        Ed25519 keypairs can pre-compute a colliding SAS offline.
        With the transcript bound in, the attacker has to grind during
        the live pair window against a fresh per-session value.
        """
        peer_fp = self._peer_fp_from_peer(peer) or fingerprint_of(
            bytes.fromhex(peer.ed_pub_hex)
        )
        # Make sure the peer DB has a row so trust changes can attach later
        # AND so we can read the previously-rejected flag below.
        if self.state is not None:
            self.state.upsert_peer(
                fingerprint=peer_fp,
                short_id=peer.short_id,
                pubkey=bytes.fromhex(peer.ed_pub_hex),
                hostname=peer.hostname,
                address=peer.address,
                port=peer.port,
            )
        # v0.20.7 (security audit M20): surface previously-rejected
        # state so the UI can show a "this peer was previously
        # blocked" warning before the user clicks Match.
        previously_rejected = False
        if self.state is not None:
            try:
                rec = self.state.get_peer(peer_fp)
                previously_rejected = bool(rec and rec.trust == "rejected")
            except Exception:
                previously_rejected = False
        # Send PAIR_REQUEST first so we have the channel's
        # transcript_hash; SAS is bound to it.
        transcript = await self._send_control(
            peer, make_msg("PAIR_REQUEST", self.me.short_id),
        )
        sas = compute_sas(
            self.me.public_bytes,
            bytes.fromhex(peer.ed_pub_hex),
            transcript_hash=transcript,
        )
        existing = self.pairing.get(peer_fp)
        if (
            existing is None
            or existing.state in (
                PairState.NONE, PairState.PAIRED, PairState.REJECTED,
            )
            or existing.is_expired()
        ):
            self.pairing.begin(
                peer_fp=peer_fp, sas=sas, incoming=False,
                previously_rejected=previously_rejected,
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
        if ctx is None or ctx.is_expired():
            # v0.20.7 (security audit H12): no live ctx (or stale).
            # Old behavior re-derived a v1 SAS from pubkeys-only and
            # quietly continued; with v2 SAS that fallback would
            # display a different code than what the peer sees and
            # the user would (correctly) see a mismatch on the next
            # exchange. Cleaner to refuse here and force a fresh
            # ceremony from initiate_pair where the SAS gets bound
            # to a real transcript.
            log.warning(
                "confirm_pair refused: no live pair context for %s",
                peer.short_id,
            )
            return {
                "ok": False,
                "reason": "no_live_pair_context",
                "user_message": (
                    "Pair session expired. Click Pair again to restart."
                ),
            }

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
        bandwidth_bps: float | None = None,
        reliability: float | None = None,
        best_route: str | None = None,
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
        if bandwidth_bps is not None and bandwidth_bps > 0:
            prev_bw = h.get("bandwidth_bps")
            if prev_bw is None or prev_bw <= 0:
                h["bandwidth_bps"] = float(bandwidth_bps)
            else:
                h["bandwidth_bps"] = 0.7 * prev_bw + 0.3 * float(bandwidth_bps)
        if reliability is not None:
            h["reliability"] = max(0.0, min(1.0, float(reliability)))
        if best_route:
            h["best_route"] = str(best_route)

    def _route_memory_for(self, peer_fp: str) -> RouteMemory:
        mem = self._route_memory.get(peer_fp)
        if mem is None:
            mem = RouteMemory()
            self._route_memory[peer_fp] = mem
        return mem

    def _persist_route_memory(self, peer_fp: str, mem: RouteMemory) -> None:
        if self.state is None or not peer_fp:
            return
        for c in mem.candidates():
            with contextlib.suppress(Exception):
                self.state.upsert_route_memory(
                    peer_fp=peer_fp,
                    route=c.route,
                    attempts=c.attempts,
                    successes=c.successes,
                    failures=c.failures,
                    score=c.score,
                    latency_ms=c.latency_ms,
                    bandwidth_bps=c.bandwidth_bps,
                    metadata={"source": "transfer_runtime"},
                )

    def _load_persisted_route_memory(self) -> None:
        if self.state is None:
            return
        try:
            rows = self.state.list_route_memory()
        except Exception as e:
            log.debug("route memory load skipped: %s", e)
            return
        rebuilt: dict[str, RouteMemory] = {}
        now_ms = int(time.time() * 1000)
        for row in rows:
            peer_fp = str(row.get("peer_fp") or "")
            route = str(row.get("route") or "")
            if not peer_fp or not route:
                continue
            mem = rebuilt.setdefault(peer_fp, RouteMemory())
            successes = max(0, int(row.get("successes") or 0))
            failures = max(0, int(row.get("failures") or 0))
            latency_ms = row.get("latency_ms")
            bandwidth_bps = row.get("bandwidth_bps")
            for _ in range(successes):
                mem.observe(RouteObservation(
                    route=route,
                    ok=True,
                    latency_ms=latency_ms,
                    bandwidth_bps=bandwidth_bps,
                    at_ms=now_ms,
                ))
            for _ in range(failures):
                mem.observe(RouteObservation(
                    route=route,
                    ok=False,
                    error_code="persisted_failure",
                    at_ms=now_ms,
                ))
        self._route_memory.update(rebuilt)
        for peer_fp, mem in rebuilt.items():
            ranked = mem.candidates()
            best = ranked[0] if ranked else None
            if best is not None:
                self._stamp_pair_health(
                    peer_fp,
                    latency_ms=best.latency_ms,
                    bandwidth_bps=best.bandwidth_bps,
                    reliability=best.successes / max(1, best.attempts),
                    best_route=best.route,
                )

    def _record_route_observation(
        self,
        peer_fp: str,
        *,
        route: str = "lan",
        ok: bool,
        latency_ms: float | None = None,
        bandwidth_bps: float | None = None,
        error_code: str | None = None,
    ) -> None:
        if not peer_fp:
            return
        mem = self._route_memory_for(peer_fp)
        mem.observe(RouteObservation(
            route=route or "unknown",
            ok=bool(ok),
            latency_ms=latency_ms,
            bandwidth_bps=bandwidth_bps,
            error_code=error_code,
            at_ms=int(time.time() * 1000),
        ))
        ranked = mem.candidates()
        best = ranked[0] if ranked else None
        if best is not None:
            self._stamp_pair_health(
                peer_fp,
                latency_ms=best.latency_ms,
                bandwidth_bps=best.bandwidth_bps,
                reliability=best.successes / max(1, best.attempts),
                best_route=best.route,
            )
        self._persist_route_memory(peer_fp, mem)

    def get_pair_health(self, peer_fp: str) -> dict | None:
        """Public read for /api/peers."""
        h = self._pair_health.get(peer_fp)
        if h is None:
            return None
        # Cast through dict[str, Any] so we can mix in non-_PairHealth
        # fields (route_scores) for the /api/peers UI surface — the
        # public diagnostic shape is broader than the internal one.
        out: dict[str, Any] = dict(h)
        mem = self._route_memory.get(peer_fp)
        if mem is not None:
            out["route_scores"] = [c.__dict__ for c in mem.candidates()]
            out["best_route"] = mem.best_route(
                str(out.get("best_route") or "lan")
            )
        return out

    def _transfer_route_observations(
        self, peer_fp: str,
    ) -> tuple[TransferRouteObservation, ...]:
        mem = self._route_memory.get(peer_fp)
        if mem is None:
            return ()
        out: list[TransferRouteObservation] = []
        for c in mem.candidates():
            attempts = max(1, int(c.attempts))
            for _ in range(max(0, int(c.successes))):
                out.append(TransferRouteObservation(
                    route=c.route,
                    ok=True,
                    latency_ms=c.latency_ms,
                    bandwidth_bps=c.bandwidth_bps,
                ))
            for _ in range(max(0, attempts - int(c.successes))):
                out.append(TransferRouteObservation(route=c.route, ok=False))
        return tuple(out)

    def _mesh_node_signals(
        self,
        peer_fp: str,
        *,
        chunk_hit_rate: float = 0.0,
    ) -> tuple[MeshNodeSignal, ...]:
        nodes: list[MeshNodeSignal] = []
        health = self.get_pair_health(peer_fp) or {}
        if health:
            nodes.append(MeshNodeSignal(
                peer_fp=peer_fp,
                trust_score=self._swarm_trust_score(peer_fp),
                reliability=float(health.get("reliability") or 0.5),
                latency_ms=health.get("latency_ewma_ms"),
                bandwidth_bps=health.get("bandwidth_bps"),
                chunk_hit_rate=chunk_hit_rate,
                route_kind=str(health.get("best_route") or "lan"),
            ))
        if self.state is not None:
            with contextlib.suppress(Exception):
                for rec in self.state.list_peers():
                    fp = str(getattr(rec, "fingerprint", "") or "")
                    if not fp or fp == peer_fp or getattr(rec, "trust", "") != "pinned":
                        continue
                    h = self.get_pair_health(fp) or {}
                    nodes.append(MeshNodeSignal(
                        peer_fp=fp,
                        trust_score=self._swarm_trust_score(fp),
                        reliability=float(h.get("reliability") or 0.5),
                        latency_ms=h.get("latency_ewma_ms"),
                        bandwidth_bps=h.get("bandwidth_bps"),
                        chunk_hit_rate=0.0,
                        route_kind=str(h.get("best_route") or "mesh"),
                    ))
        return tuple(nodes)

    def _estimate_prior_hit_rate(
        self,
        *,
        metadata: dict,
        cdc_chunks: tuple[Chunk, ...],
        cached_hit: bool,
    ) -> float:
        chunks_total = int(metadata.get("chunks_total") or 0)
        skipped = int(metadata.get("skipped_chunks") or 0)
        if chunks_total > 0 and skipped > 0:
            return min(1.0, max(0.0, skipped / chunks_total))
        if cached_hit and cdc_chunks:
            return 0.18
        if cdc_chunks:
            return 0.04
        return 0.0

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
        # v0.20.7 (security audit L11): delete on-disk partial files
        # for in-flight inbound transfers. Pre-fix the partial bytes
        # remained in the inbox after revoke — combined with the
        # FILE_DONE quarantine path's broadcast skipping, the user
        # could be left with a partly-written file under a
        # legitimate-looking name. Iterate _incoming_files for this
        # peer and unlink + abort + drop the IncomingFile entry.
        partials_to_drop: list[str] = []
        for blob, f in list(self._incoming_files.items()):
            try:
                if getattr(f, "peer_fp", "") == peer_fp:
                    partials_to_drop.append(blob)
            except Exception:
                continue
        for blob in partials_to_drop:
            partial = self._incoming_files.get(blob)
            if partial is None:
                continue
            with contextlib.suppress(Exception):
                self._abort_incoming_file(blob, partial)
            with contextlib.suppress(OSError):
                partial.out_path.unlink()
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
            # v0.20.7 (M1): rec.pubkey is the canonical pubkey we
            # already trust for this peer; bind it into HELLO.
            channel = await asyncio.wait_for(
                ch.initiate(
                    reader, writer, self.me,
                    expected_responder_ed_pub=rec.pubkey,
                ),
                timeout=3.0,
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
        plain_text = plaintext.decode("utf-8", errors="replace")
        group_body = plain_text
        group_reply_to = None
        group_kind = "text"
        group_target = None
        group_emoji = None
        group_op = None
        group_at_ms = int(time.time() * 1000)
        with contextlib.suppress(Exception):
            env = json.loads(plain_text)
            if isinstance(env, dict) and env.get("ol_group_msg") == 1:
                group_kind = str(env.get("kind") or "text")
                if isinstance(env.get("body"), str):
                    group_body = env["body"]
                if isinstance(env.get("reply_to"), str) and env.get("reply_to"):
                    group_reply_to = env["reply_to"]
                if isinstance(env.get("target"), str):
                    group_target = env["target"]
                if isinstance(env.get("emoji"), str):
                    group_emoji = env["emoji"]
                if isinstance(env.get("op"), str):
                    group_op = env["op"]
                with contextlib.suppress(Exception):
                    group_at_ms = int(env.get("at_ms") or group_at_ms)

        if group_kind in ("text", "message"):
            self.state.insert_group_message(
                id=msg_id,
                group_id=group_id,
                sender_pub=sender_pub,
                epoch=epoch,
                counter=int(wire.get("counter", 0)),
                direction="in",
                body=group_body,
                reply_to=group_reply_to,
            )
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "group_msg",
                        "group_id_hex": group_id.hex(),
                        "sender_pub_hex": sender_pub.hex(),
                        "id": msg_id,
                        "epoch": epoch,
                        "counter": int(wire.get("counter", 0)),
                        "body": group_body,
                        "reply_to": group_reply_to,
                        "ts_ms": group_at_ms,
                        "direction": "in",
                    })
        elif group_kind == "reaction" and group_target and group_emoji:
            op = "remove" if group_op == "remove" else "add"
            sender_fp = fingerprint_of(sender_pub)
            if op == "add":
                self.state.record_reaction(
                    target_msg_id=group_target,
                    peer_fp=sender_fp,
                    emoji=group_emoji,
                )
            else:
                self.state.remove_reaction(
                    target_msg_id=group_target,
                    peer_fp=sender_fp,
                    emoji=group_emoji,
                )
            if self.ui_server is not None:
                with contextlib.suppress(Exception):
                    self.ui_server.broadcast({
                        "type": "group_reaction",
                        "group_id_hex": group_id.hex(),
                        "target": group_target,
                        "peer_fp": sender_fp,
                        "emoji": group_emoji,
                        "op": op,
                    })
        elif group_kind == "edit" and group_target and isinstance(group_body, str):
            existing_msg = self.state.get_group_message(group_target)
            if existing_msg and existing_msg.get("sender_pub") == sender_pub:
                self.state.edit_group_message(
                    id=group_target,
                    new_body=group_body,
                    edited_at_ms=group_at_ms,
                )
                if self.ui_server is not None:
                    with contextlib.suppress(Exception):
                        self.ui_server.broadcast({
                            "type": "group_msg_edit",
                            "group_id_hex": group_id.hex(),
                            "target": group_target,
                            "body": group_body,
                            "edited_at_ms": group_at_ms,
                        })
        elif group_kind == "delete" and group_target:
            existing_msg = self.state.get_group_message(group_target)
            if existing_msg and existing_msg.get("sender_pub") == sender_pub:
                self.state.delete_group_message(
                    id=group_target,
                    deleted_at_ms=group_at_ms,
                )
                if self.ui_server is not None:
                    with contextlib.suppress(Exception):
                        self.ui_server.broadcast({
                            "type": "group_msg_delete",
                            "group_id_hex": group_id.hex(),
                            "target": group_target,
                            "deleted_at_ms": group_at_ms,
                        })
        else:
            log.warning(
                "unknown GROUP_MSG action from %s: %s",
                peer_fp[:8], group_kind,
            )
        await channel.send(encode_msg(make_msg(
            "ACK", self.me.short_id, of=msg.get("id"),
        )))

    async def _broadcast_group_event(
        self, group_id: bytes, event_wire: dict, recipients: list[bytes],
    ) -> dict:
        """v0.8.0: fan out a single CRDT event to every recipient by
        Ed25519 pubkey. Uses send_to which reuses the persistent
        encrypted session with each peer. Best-effort — peers we
        can't reach now will catch up on next reconnect via outbox-
        style distribution (TODO v0.8.1 — for now, missed events
        require a fresh send when peer is online)."""
        if self.state is None:
            return {"delivered": 0, "failures": []}
        delivered = 0
        failures: list[str] = []
        for pub in recipients:
            if pub == self.me.public_bytes:
                continue
            fp = fingerprint_of(pub)
            peer_obj = await self.resolve_for_send(fp)
            if peer_obj is None:
                failures.append(f"{fp[:8]}: offline")
                continue
            try:
                await self.send_to(peer_obj, [
                    make_msg("GROUP_EVENT", self.me.short_id, event=event_wire),
                ])
                delivered += 1
            except Exception as e:
                log.info(
                    "GROUP_EVENT fan-out to %s failed: %s", fp[:8], e,
                )
                failures.append(f"{fp[:8]}: {e}")
        return {"delivered": delivered, "failures": failures}

    async def create_group(
        self, *, name: str, member_pubkeys: list[bytes],
    ) -> dict:
        """v0.8.0: issue a fresh group + add every member, persist
        the events locally, fan out to all recipients. Returns the
        new group id (hex) and reduce result."""
        if self.state is None:
            raise RuntimeError("state not available")
        from one_link import groups as gmod
        # 1. Sign genesis CREATE.
        create_ev = gmod.sign_create_group(
            private_key=self.me.private,
            pubkey=self.me.public_bytes,
            name=name,
        )
        gid = create_ev.group_id
        # 2. Persist locally.
        self.state.upsert_group_event(
            group_id=gid, event_id=create_ev.event_id,
            timestamp_ms=create_ev.timestamp_ms,
            wire_dict=create_ev.to_wire(),
        )
        events_to_fan_out = [create_ev]
        # 3. Sign ADD_MEMBER for each invited peer.
        for pub in member_pubkeys:
            if pub == self.me.public_bytes:
                continue
            if len(pub) != 32:
                continue
            add_ev = gmod.sign_add_member(
                private_key=self.me.private,
                pubkey=self.me.public_bytes,
                group_id=gid,
                member_pubkey=pub,
            )
            self.state.upsert_group_event(
                group_id=gid, event_id=add_ev.event_id,
                timestamp_ms=add_ev.timestamp_ms,
                wire_dict=add_ev.to_wire(),
            )
            events_to_fan_out.append(add_ev)
        # 4. Materialize state, cache name.
        wire_events = self.state.list_group_events(gid)
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        if gstate is None:
            raise RuntimeError("reduce failed on freshly-created group")
        self.state.upsert_group_meta(
            group_id=gid, name=gstate.name or name,
            created_ms=int(time.time() * 1000), state_hash="",
        )
        # 5. Fan out every event to every member (including the
        # CREATE so they can verify provenance).
        all_recipients = list(member_pubkeys)
        fanout_results = []
        for ev in events_to_fan_out:
            r = await self._broadcast_group_event(
                gid, ev.to_wire(), all_recipients,
            )
            fanout_results.append(r)
        # 6. UI notify.
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_created",
                    "group_id": gid.hex(),
                    "name": gstate.name,
                })
        return {
            "group_id": gid.hex(),
            "name": gstate.name,
            "member_count": len(gstate.members),
            "fanout": fanout_results,
        }

    async def add_group_member(
        self, *, group_id: bytes, member_pubkey: bytes,
        role: str = "member",
    ) -> dict:
        """v0.8.0: sign + persist + distribute an ADD_MEMBER event."""
        if self.state is None:
            raise RuntimeError("state not available")
        from one_link import groups as gmod
        ev = gmod.sign_add_member(
            private_key=self.me.private,
            pubkey=self.me.public_bytes,
            group_id=group_id,
            member_pubkey=member_pubkey,
            role=role,
        )
        self.state.upsert_group_event(
            group_id=group_id, event_id=ev.event_id,
            timestamp_ms=ev.timestamp_ms,
            wire_dict=ev.to_wire(),
        )
        # Re-materialize membership so we know who to fan out to.
        wire_events = self.state.list_group_events(group_id)
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        if gstate is None:
            raise RuntimeError("group state unreadable")
        recipients = list(gstate.members)
        result = await self._broadcast_group_event(
            group_id, ev.to_wire(), recipients,
        )
        return {"event_id": ev.event_id, **result}

    async def change_group_member_role(
        self, *, group_id: bytes, member_pubkey: bytes, new_role: str,
    ) -> dict:
        """v0.11.3: sign + persist + distribute a CHANGE_ROLE event.

        Authority: only owners can change roles (enforced in the
        reducer). The caller is expected to be an owner — the
        endpoint surfaces the reducer-rejection as a 400 if not."""
        if self.state is None:
            raise RuntimeError("state not available")
        from one_link import groups as gmod
        ev = gmod.sign_change_role(
            private_key=self.me.private,
            pubkey=self.me.public_bytes,
            group_id=group_id,
            member_pubkey=member_pubkey,
            new_role=new_role,
        )
        self.state.upsert_group_event(
            group_id=group_id, event_id=ev.event_id,
            timestamp_ms=ev.timestamp_ms,
            wire_dict=ev.to_wire(),
        )
        wire_events = self.state.list_group_events(group_id)
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        if gstate is None:
            raise RuntimeError("group state unreadable")
        recipients = list(gstate.members)
        result = await self._broadcast_group_event(
            group_id, ev.to_wire(), recipients,
        )
        return {"event_id": ev.event_id, **result}

    async def remove_group_member(
        self, *, group_id: bytes, member_pubkey: bytes,
    ) -> dict:
        if self.state is None:
            raise RuntimeError("state not available")
        from one_link import groups as gmod
        ev = gmod.sign_remove_member(
            private_key=self.me.private,
            pubkey=self.me.public_bytes,
            group_id=group_id,
            member_pubkey=member_pubkey,
        )
        self.state.upsert_group_event(
            group_id=group_id, event_id=ev.event_id,
            timestamp_ms=ev.timestamp_ms,
            wire_dict=ev.to_wire(),
        )
        wire_events = self.state.list_group_events(group_id)
        events = [gmod.GroupEvent.from_wire(w) for w in wire_events]
        gstate = gmod.reduce_events(events)
        # Fan out to the OLD member set (so the now-removed peer
        # also sees the remove event and stops trying to participate).
        recipients = list(gstate.members) if gstate else []
        recipients.append(member_pubkey)
        result = await self._broadcast_group_event(
            group_id, ev.to_wire(), recipients,
        )
        return {"event_id": ev.event_id, **result}

    async def _send_group_envelope(self, *, group_id: bytes, payload: dict) -> dict:
        """Encrypt one typed group action and fan it to every member."""
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

        assert chain_row is not None, "sender chain missing after upsert"
        sender_chain = gc.SenderChain(
            group_id=group_id,
            sender_pubkey=self.me.public_bytes,
            epoch=int(chain_row["epoch"]),
            chain_key=chain_row["chain_key"],
            counter=int(chain_row["counter"]),
        )
        payload = {
            "ol_group_msg": 1,
            "at_ms": int(time.time() * 1000),
            **payload,
        }
        body_bytes = json.dumps(
            payload, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
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
            "epoch": sender_chain.epoch,
            "counter": sender_chain.counter,
            "at_ms": payload["at_ms"],
        }

    async def send_group_message(
        self, *, group_id: bytes, body: str, reply_to: str | None = None,
    ) -> dict:
        """v0.6.2: encrypt a group text message under our sender chain."""
        if self.state is None:
            raise RuntimeError("state not available")
        msg_id = uuid.uuid4().hex
        payload = {"kind": "text", "body": body}
        if reply_to:
            payload["reply_to"] = reply_to
        fanout = await self._send_group_envelope(group_id=group_id, payload=payload)
        self.state.insert_group_message(
            id=msg_id,
            group_id=group_id,
            sender_pub=self.me.public_bytes,
            epoch=int(fanout["epoch"]),
            counter=int(fanout["counter"]),
            direction="out",
            body=body,
            reply_to=reply_to,
            ts_ms=int(fanout["at_ms"]),
        )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_msg",
                    "group_id_hex": group_id.hex(),
                    "sender_pub_hex": self.me.public_bytes.hex(),
                    "id": msg_id,
                    "epoch": int(fanout["epoch"]),
                    "counter": int(fanout["counter"]),
                    "body": body,
                    "reply_to": reply_to,
                    "ts_ms": int(fanout["at_ms"]),
                    "direction": "out",
                })
        return {**fanout, "msg_id": msg_id}

    async def send_group_reaction(
        self, *, group_id: bytes, target_msg_id: str, emoji: str, op: str,
    ) -> dict:
        if self.state is None:
            raise RuntimeError("state not available")
        op = "remove" if op == "remove" else "add"
        if op == "add":
            self.state.record_reaction(
                target_msg_id=target_msg_id,
                peer_fp=self.me.fingerprint,
                emoji=emoji,
            )
        else:
            self.state.remove_reaction(
                target_msg_id=target_msg_id,
                peer_fp=self.me.fingerprint,
                emoji=emoji,
            )
        fanout = await self._send_group_envelope(
            group_id=group_id,
            payload={
                "kind": "reaction",
                "target": target_msg_id,
                "emoji": emoji,
                "op": op,
            },
        )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_reaction",
                    "group_id_hex": group_id.hex(),
                    "target": target_msg_id,
                    "peer_fp": self.me.fingerprint,
                    "emoji": emoji,
                    "op": op,
                })
        return fanout

    async def send_group_edit(
        self, *, group_id: bytes, target_msg_id: str, new_body: str,
    ) -> dict:
        if self.state is None:
            raise RuntimeError("state not available")
        rec = self.state.get_group_message(target_msg_id)
        if rec is None:
            raise RuntimeError("message not found")
        if rec.get("direction") != "out":
            raise RuntimeError("can only edit your own outbound messages")
        if rec.get("deleted_at_ms"):
            raise RuntimeError("cannot edit a deleted message")
        edited_at_ms = int(time.time() * 1000)
        self.state.edit_group_message(
            id=target_msg_id,
            new_body=new_body,
            edited_at_ms=edited_at_ms,
        )
        fanout = await self._send_group_envelope(
            group_id=group_id,
            payload={
                "kind": "edit",
                "target": target_msg_id,
                "body": new_body,
                "at_ms": edited_at_ms,
            },
        )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_msg_edit",
                    "group_id_hex": group_id.hex(),
                    "target": target_msg_id,
                    "body": new_body,
                    "edited_at_ms": edited_at_ms,
                })
        return fanout

    async def send_group_delete(
        self, *, group_id: bytes, target_msg_id: str,
    ) -> dict:
        if self.state is None:
            raise RuntimeError("state not available")
        rec = self.state.get_group_message(target_msg_id)
        if rec is None:
            raise RuntimeError("message not found")
        if rec.get("direction") != "out":
            raise RuntimeError("can only delete your own outbound messages")
        deleted_at_ms = int(time.time() * 1000)
        self.state.delete_group_message(
            id=target_msg_id,
            deleted_at_ms=deleted_at_ms,
        )
        fanout = await self._send_group_envelope(
            group_id=group_id,
            payload={
                "kind": "delete",
                "target": target_msg_id,
                "at_ms": deleted_at_ms,
            },
        )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "group_msg_delete",
                    "group_id_hex": group_id.hex(),
                    "target": target_msg_id,
                    "deleted_at_ms": deleted_at_ms,
                })
        return fanout

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

    async def send_text(
        self, peer: Peer, body: str, *, reply_to: str | None = None,
    ) -> dict:
        # v0.7.5: optional reply_to threads this TEXT under a parent
        # message. The receiver renders an inline quote chip.
        kwargs: dict = {"body": body}
        if reply_to:
            kwargs["reply_to"] = str(reply_to)
        # v0.10.2 disappearing messages — attach the peer's TTL so
        # both sides compute the same expires_at_ms = ts_ms + ttl.
        peer_fp = self._peer_fp_from_peer(peer)
        if peer_fp and self.state is not None:
            with contextlib.suppress(Exception):
                ttl = self.state.get_peer_dm_ttl(peer_fp)
                if ttl:
                    kwargs["ttl_ms"] = int(ttl)
        m = make_msg("TEXT", self.me.short_id, **kwargs)
        acks = await self.send_to(peer, [m])
        return {"sent": m, "ack": acks[0] if acks else None}

    async def send_edit(
        self, peer: Peer, *, target_msg_id: str, new_body: str,
    ) -> dict:
        """v0.7.6: edit one of our previously-sent messages. The
        sender enforces the cooldown locally (so the UI doesn't
        even attempt to send) and the receiver enforces it again
        on receive."""
        if self.state is not None:
            tgt = self.state.get_message(str(target_msg_id))
            if tgt is None:
                raise RuntimeError("message not found")
            if tgt.is_deleted:
                raise RuntimeError("message is deleted")
            now = int(time.time() * 1000)
            if now - tgt.ts_ms > EDIT_COOLDOWN_MS:
                raise RuntimeError(
                    f"edit cooldown exceeded ({EDIT_COOLDOWN_MS // 60000}min)"
                )
        edited_at = int(time.time() * 1000)
        m = make_msg(
            "EDIT_MSG", self.me.short_id,
            target=str(target_msg_id),
            body=str(new_body),
            edited_at_ms=edited_at,
        )
        acks = await self.send_to(peer, [m])
        # Apply to our own state too so the sender's UI shows
        # the edit immediately.
        if self.state is not None:
            with contextlib.suppress(Exception):
                self.state.edit_message(
                    id=str(target_msg_id),
                    new_body=str(new_body),
                    edited_at_ms=edited_at,
                )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "msg_edit",
                    "target": str(target_msg_id),
                    "body": str(new_body),
                    "edited_at_ms": edited_at,
                })
        return {"sent": m, "ack": acks[0] if acks else None}

    async def send_delete(
        self, peer: Peer, *, target_msg_id: str,
    ) -> dict:
        """v0.7.6: delete one of our previously-sent messages.
        Soft-delete on both ends — body cleared, deleted_at_ms set."""
        deleted_at = int(time.time() * 1000)
        m = make_msg(
            "DELETE_MSG", self.me.short_id,
            target=str(target_msg_id),
            deleted_at_ms=deleted_at,
        )
        acks = await self.send_to(peer, [m])
        if self.state is not None:
            with contextlib.suppress(Exception):
                self.state.delete_message(
                    id=str(target_msg_id), deleted_at_ms=deleted_at,
                )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "msg_delete",
                    "target": str(target_msg_id),
                    "deleted_at_ms": deleted_at,
                })
        return {"sent": m, "ack": acks[0] if acks else None}

    async def send_read_marker(
        self, peer: Peer, *, up_to_ts_ms: int,
    ) -> dict:
        """v0.7.6: tell `peer` we've read all their messages with
        ts ≤ `up_to_ts_ms`. Best-effort — peer-side persistence
        is the source of truth, but errors don't block the UI.

        v0.12.2: gated by send_read_receipts privacy setting. When
        off, returns immediately without dialing the peer. The UI
        still updates its own local state.peer_read_markers so
        unread counts are accurate even if peers don't get told."""
        if self.state is not None:
            with contextlib.suppress(Exception):
                v = self.state.get_setting("send_read_receipts")
                if v is not None and v != "true":
                    return {"sent": None, "skipped": "privacy"}
        m = make_msg(
            "READ_MARKER", self.me.short_id,
            up_to_ts_ms=int(up_to_ts_ms),
        )
        try:
            acks = await self.send_to(peer, [m])
            return {"sent": m, "ack": acks[0] if acks else None}
        except Exception as e:
            log.debug("send_read_marker best-effort failed: %s", e)
            return {"sent": m, "error": str(e)}

    async def send_typing(self, peer: Peer) -> dict:
        """v0.12.3: ephemeral 'I'm typing' indicator.

        Debounced to once per 2.5s per peer to avoid wire flood
        on a fast typer. The wire frame carries an `expires_in_ms`
        (5000) so the receiver knows when to time out the
        indicator without coordination clocks.

        Gated by send_typing_indicators privacy setting; off →
        return immediately, peer never learns we're typing.
        Best-effort — failures are debug-logged, never bubble up
        to the UI."""
        if self.state is not None:
            with contextlib.suppress(Exception):
                v = self.state.get_setting("send_typing_indicators")
                if v is not None and v != "true":
                    return {"sent": None, "skipped": "privacy"}
        peer_fp = self._peer_fp_from_peer(peer)
        if peer_fp:
            now = time.monotonic()
            last = self._last_typing_sent_to.get(peer_fp, 0.0)
            if now - last < 2.5:
                return {"sent": None, "skipped": "debounced"}
            self._last_typing_sent_to[peer_fp] = now
        m = make_msg(
            "TYPING", self.me.short_id,
            expires_in_ms=5000,
        )
        try:
            await self.send_to(peer, [m])
            return {"sent": m}
        except Exception as e:
            log.debug("send_typing best-effort failed: %s", e)
            return {"sent": m, "error": str(e)}

    async def send_reaction(
        self, peer: Peer, *, target_msg_id: str, emoji: str, op: str = "add",
    ) -> dict:
        """v0.7.5: emit a REACTION frame to the peer for one of
        their messages. `op` is 'add' or 'remove' — the receiver
        applies idempotently. Persisted on both sides."""
        if op not in ("add", "remove"):
            raise ValueError("op must be 'add' or 'remove'")
        m = make_msg(
            "REACTION", self.me.short_id,
            target=str(target_msg_id),
            emoji=str(emoji),
            op=op,
        )
        acks = await self.send_to(peer, [m])
        # Persist on the local side too (the sending peer's reaction
        # against the target message). _on_peer_message handles the
        # receiver-side persist.
        if self.state is not None and self.me.fingerprint:
            with contextlib.suppress(Exception):
                if op == "add":
                    self.state.record_reaction(
                        target_msg_id=str(target_msg_id),
                        peer_fp=self.me.fingerprint,
                        emoji=str(emoji),
                    )
                else:
                    self.state.remove_reaction(
                        target_msg_id=str(target_msg_id),
                        peer_fp=self.me.fingerprint,
                        emoji=str(emoji),
                    )
        if self.ui_server is not None:
            with contextlib.suppress(Exception):
                self.ui_server.broadcast({
                    "type": "reaction",
                    "target": str(target_msg_id),
                    "peer_fp": self.me.fingerprint,
                    "emoji": str(emoji),
                    "op": op,
                })
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

    # ─── resume-on-reconnect (v0.7.4) ─────────────────────────────────

    def _get_resume_lock(self, peer_fp: str) -> asyncio.Lock:
        # Lazy per-peer lock dict, created on first use to avoid
        # touching __init__ across versions.
        if not hasattr(self, "_resume_lock_dict"):
            self._resume_lock_dict: dict[str, asyncio.Lock] = {}
        lk = self._resume_lock_dict.get(peer_fp)
        if lk is None:
            lk = asyncio.Lock()
            self._resume_lock_dict[peer_fp] = lk
        return lk

    async def resume_paused_transfers_for(self, peer_fp: str) -> dict:
        """v0.7.4: re-run send_file for every transfer this daemon
        paused mid-stream against `peer_fp`. The CDC FILE_OFFER /
        FILE_WANTS protocol is naturally idempotent — receiver replies
        with ONLY the chunks it doesn't already have cached, so a
        resume only ships the gap.

        Per-peer asyncio lock prevents two simultaneous session-up
        events from firing duplicate resumes. Returns counts."""
        if self.state is None:
            return {"ok": False, "error": "state not available", "resumed": 0}
        rec = self.state.get_peer(peer_fp)
        if rec is None or rec.trust != "pinned":
            return {"ok": False, "error": "peer not pinned", "resumed": 0}
        peer = await self.resolve_for_send(peer_fp)
        if peer is None:
            self._mark_due_transfers_waiting_for_peer(
                peer_fp,
                reason="waiting for device",
                error_class="PeerOffline",
            )
            return {"ok": False, "error": "peer offline", "resumed": 0}
        lock = self._get_resume_lock(peer_fp)
        if lock.locked():
            return {"ok": True, "resumed": 0, "skipped_concurrent": True}
        async with lock:
            try:
                rows = self.state.list_transfers(peer_fp=peer_fp, limit=200)
            except Exception:
                rows = []
            now_ms = int(time.time() * 1000)
            paused = [
                r for r in rows
                if r.status in ("paused", "queued")
                and r.direction == "out"
                and int((r.metadata or {}).get("next_retry_ms") or 0) <= now_ms
                and not (
                    r.status == "queued"
                    and (r.metadata or {}).get("mode") == "planning"
                )
            ]
            resumed = 0
            errors = 0
            for r in paused:
                path_str = (r.metadata or {}).get("path")
                if not path_str:
                    log.info(
                        "resume skipped %s: no source path on ledger row",
                        r.id,
                    )
                    continue
                from pathlib import Path as _P
                src = _P(path_str)
                if not src.is_file():
                    log.info(
                        "resume skipped %s: source file gone (%s)",
                        r.id, path_str,
                    )
                    self._update_transfer(
                        r.id, status="failed",
                        metadata={
                            **(r.metadata or {}),
                            "error": f"source file no longer exists: {path_str}",
                            "error_class": "FileNotFoundError",
                        },
                    )
                    errors += 1
                    continue
                try:
                    self._update_transfer(
                        r.id,
                        status="paused",
                        metadata={
                            **(r.metadata or {}),
                            "delivery_state": "resuming",
                        },
                    )
                    await self.send_file(peer, src, transfer_id=r.id)
                    resumed += 1
                except Exception as e:
                    errors += 1
                    log.info(
                        "resume of %s deferred for %s: %s",
                        r.id, peer_fp[:8], e,
                    )
                    # send_file's own except path stamped a fresh
                    # paused/failed row; we don't double-write.
                    # First failure short-circuits — same logic as
                    # outbox flush. Next session-up retries.
                    break
            return {
                "ok": True, "resumed": resumed, "errors": errors,
                "remaining": sum(
                    1 for r in self.state.list_transfers(
                        peer_fp=peer_fp, limit=200,
                    ) if r.status == "paused" and r.direction == "out"
                ),
            }

    def _schedule_resume_paused(self, peer_fp: str) -> None:
        """Fire-and-forget background resume. Called from the same
        session-up hook as the outbox flush."""
        if self.state is None or not peer_fp:
            return
        if self.discovery is not None:
            live = False
            for p in self.discovery.registry.list():
                if self._peer_fp_from_peer(p) == peer_fp:
                    live = True
                    break
            if not live:
                return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self._resume_paused_swallow(peer_fp))

    async def _resume_paused_swallow(self, peer_fp: str) -> None:
        try:
            await self.resume_paused_transfers_for(peer_fp)
        except Exception as e:
            log.warning("resume task errored for %s: %s", peer_fp[:8], e)

    def _schedule_due_transfer_retries(self) -> int:
        """Background transfer queue pump.

        Scans durable outbound transfer intents whose backoff window has
        elapsed and schedules one resume task per peer. It is intentionally
        quiet when peers are offline; the row stays as Waiting and the next
        pump/session-up will try again.
        """
        if self.state is None:
            return 0
        now_ms = int(time.time() * 1000)
        try:
            rows = self.state.list_transfers(limit=500)
        except Exception:
            return 0
        peers: set[str] = set()
        for r in rows:
            if r.direction != "out" or r.status not in ("paused", "queued"):
                continue
            meta = r.metadata or {}
            if r.status == "queued" and meta.get("mode") == "planning":
                continue
            if not meta.get("path"):
                continue
            if int(meta.get("next_retry_ms") or 0) > now_ms:
                continue
            if self.discovery is not None:
                live = False
                for p in self.discovery.registry.list():
                    if self._peer_fp_from_peer(p) == r.peer_fp:
                        live = True
                        break
                if not live:
                    continue
            peers.add(r.peer_fp)
        for fp in peers:
            self._schedule_resume_paused(fp)
        return len(peers)

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
            # v0.20.7 (M1): bind expected responder pubkey to defeat UKS.
            channel = await ch.initiate(
                reader, writer, self.me,
                expected_responder_ed_pub=bytes.fromhex(peer.ed_pub_hex),
            )
            if channel.peer_short_id != peer.short_id:
                raise RuntimeError(
                    f"fingerprint mismatch: expected {peer.short_id}"
                )
            try:
                await channel.send(encode_msg(self._build_my_caps_for_channel(channel)))
                # v0.8.2: ratchet half-step.
                with contextlib.suppress(Exception):
                    channel.note_caps_sent()
                    channel.maybe_activate_ratchet()
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
                        feats = list(normalize_caps(m.get("features", [])))
                        channel.peer_caps = {
                            "protocol": m.get("protocol", "?"),
                            "features": feats,
                            "from": m.get("from"),
                            "app_version": m.get("app_version"),
                        }
                        # v0.8.2: ratchet half-step.
                        with contextlib.suppress(Exception):
                            channel.note_caps_received(feats)
                            channel.maybe_activate_ratchet()
                        if self.state is not None:
                            with contextlib.suppress(Exception):
                                fp = self._peer_fp_from_peer(peer)
                                if fp:
                                    self.state.set_peer_capabilities(fp, feats)
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

    async def send_file(
        self,
        peer: Peer,
        path: Path,
        *,
        transfer_id: str | None = None,
    ) -> dict:
        block = self._check_outbound_trust(peer)
        if block:
            raise RuntimeError(block)
        peer_fp_for_policy = self._peer_fp_from_peer(peer)
        if peer_fp_for_policy and not self._capability_allowed(peer_fp_for_policy, FILES):
            raise RuntimeError(f"files capability disabled for peer {peer.short_id}")
        file_sig = self._file_cache_signature(path)
        size = int(file_sig["size"])
        cached_file_index: FileIndex | None = None
        cached_index_kind = "miss"
        cached = self._cached_file_index(file_sig)
        if cached is not None:
            cached_file_index, cached_index_kind = cached
            blob_hex = cached_file_index.blob_hash
        else:
            blob_hex = hash_path(path)
            self._record_file_index_cache(
                path,
                FileIndex(blob_hash=blob_hex, size=size, chunks=()),
                index_kind="hash_only",
            )
        cdc_chunks: tuple[Chunk, ...] = ()
        cdc_index: list[dict] = []
        stream_chunks_total = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)

        # v0.6.3: create the transfer-ledger row BEFORE the dial so any
        # failure during dial / handshake / first ACK marks an actual row
        # as 'failed' rather than disappearing silently. The peer_fp at
        # this stage is the policy-side estimate (from peer.ed_pub_hex);
        # the post-handshake _verify_channel_peer corrects it on success.
        transfer_id = transfer_id or f"out:{blob_hex}:{uuid.uuid4().hex[:12]}"
        provisional_fp = peer_fp_for_policy or ""
        existing = self.state.get_transfer(transfer_id) if self.state else None
        existing_progress_bytes = int(
            getattr(existing, "progress_bytes", 0) or 0
        ) if existing is not None else 0
        existing_chunks_done = int(
            getattr(existing, "chunks_done", 0) or 0
        ) if existing is not None else 0
        existing_chunks_total = int(
            getattr(existing, "chunks_total", 0) or 0
        ) if existing is not None else 0
        base_metadata = {
            **((existing.metadata if existing else {}) or {}),
            "mode": "planning",
            "path": str(path),
            "delivery_state": "queued",
        }
        self._upsert_transfer(
            id=transfer_id,
            direction="out",
            peer_fp=provisional_fp,
            kind="file",
            name=path.name,
            size=size,
            blob_hash=blob_hex,
            status="queued",
            progress_bytes=existing_progress_bytes,
            total_bytes=size,
            chunks_done=existing_chunks_done,
            chunks_total=max(stream_chunks_total, existing_chunks_total),
            metadata=base_metadata,
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
            sess = await self._get_outbound_session(peer, resume_pending=False)
        except asyncio.TimeoutError as e:
            self._mark_transfer_waiting(
                transfer_id,
                path=path,
                error=(
                    f"file send to {peer.short_id}: handshake "
                    f"timed out after {HANDSHAKE_DEADLINE_OUTBOUND_S}s "
                    f"- peer not responsive"
                ),
                error_class="TimeoutError",
                base_metadata=base_metadata,
            )
            raise TransferPausedError(
                "file send paused: handshake timed out",
                transfer_id=transfer_id,
                path=path,
            ) from e
        except Exception as e:
            # _get_outbound_session already wraps its own handshake
            # timeout into RuntimeError("... handshake timed out ..."),
            # which the existing send-file timeout tests pin.
            # robustness test pins. Surface the original message and
            # stamp the ledger row so the UI shows the reason.
            err_msg = str(e)
            err_class = type(e).__name__
            ledger_msg = (
                err_msg if "handshake timed out" in err_msg.lower()
                else f"dial failed: {err_msg}"
            )
            transient = _is_transient_send_error(e)
            if transient:
                self._mark_transfer_waiting(
                    transfer_id,
                    path=path,
                    error=ledger_msg,
                    error_class=err_class,
                    base_metadata=base_metadata,
                )
            else:
                self._update_transfer(
                    transfer_id, status="failed",
                    metadata={
                        **base_metadata,
                        "error": ledger_msg[:500],
                        "error_class": err_class,
                        "transient": False,
                        "delivery_state": "needs_attention",
                    },
                )
            if transient:
                raise TransferPausedError(
                    ledger_msg, transfer_id=transfer_id, path=path,
                ) from e
            raise

        peer_fp = sess.peer_fp  # cryptographically-verified fingerprint
        channel = sess.channel
        peer_caps_frame = getattr(channel, "peer_caps", None) or {}
        peer_features = list(peer_caps_frame.get("features") or [])
        if not peer_features and self.state is not None:
            with contextlib.suppress(Exception):
                peer_features = self.state.get_peer_capabilities(peer_fp)
        peer_version = peer_caps_frame.get("app_version")
        local_version: Optional[str]
        try:
            from one_link import __version__ as local_version  # type: ignore[no-redef]
        except Exception:
            local_version = None
        fixed_chunk_size = _fast_fixed_chunk_size_for_peer(
            peer_version,
            size=size,
            peer_features=peer_features,
        )
        if (
            cached_file_index is not None
            and cached_file_index.chunks
        ):
            cached_max_chunk = max((c.size for c in cached_file_index.chunks), default=0)
            cached_fixed_too_large = cached_max_chunk > fixed_chunk_size
            cached_fixed_too_small = (
                cached_index_kind == "fixed"
                and size >= FAST_FIXED_INDEX_MIN_BYTES
                and cached_max_chunk < fixed_chunk_size
            )
            if cached_fixed_too_large or cached_fixed_too_small:
                cached_file_index = None
                cached_index_kind = (
                    "fixed_chunk_upgrade"
                    if cached_fixed_too_small else "incompatible"
                )

        thin_manifest = FileManifest(
            name=path.name,
            size=size,
            blob_hash=blob_hex,
            chunks=(),
        )
        intent = plan_transfer_intent_for_manifest(
            manifest=thin_manifest,
            path=path,
            peer_fp=peer_fp,
            local_version=local_version,
            peer_version=peer_version,
            peer_capabilities=peer_features,
            intent_id=transfer_id,
        )
        can_offer_cdc, cdc_decision_reason = _should_build_cdc_offer(
            size=size,
            intent=intent,
            existing_metadata=base_metadata,
        )
        if can_offer_cdc:
            if cached_file_index is not None and cached_file_index.chunks:
                file_index = cached_file_index
                index_kind = cached_index_kind
                self._record_file_index_cache(
                    path,
                    file_index,
                    index_kind=index_kind,
                )
            elif size >= FAST_FIXED_INDEX_MIN_BYTES:
                file_index = fixed_index_path(path, chunk_size=fixed_chunk_size)
                index_kind = "fixed"
                self._record_file_index_cache(
                    path,
                    file_index,
                    index_kind=index_kind,
                )
            else:
                file_index = index_path(path)
                index_kind = "cdc"
                self._record_file_index_cache(
                    path,
                    file_index,
                    index_kind=index_kind,
                )
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
            intent = plan_transfer_intent(
                path=path,
                peer_fp=peer_fp,
                local_version=local_version,
                peer_version=peer_version,
                peer_capabilities=peer_features,
                intent_id=transfer_id,
                file_index=file_index,
            )
        planned_wire_mode = "cdc" if can_offer_cdc else "stream"
        planned_chunks_total = (
            len(cdc_chunks)
            if can_offer_cdc
            else stream_chunks_total
        )
        prior_hit_rate = self._estimate_prior_hit_rate(
            metadata=base_metadata,
            cdc_chunks=tuple(cdc_chunks),
            cached_hit=cached is not None,
        )
        verification_head = tuple(
            t.index for t in verification_priority_order(
                tuple(FileChunkManifest.from_chunk(c) for c in cdc_chunks),
                max_items=8,
            )
        ) if cdc_chunks else ()
        route_observations = self._transfer_route_observations(peer_fp)
        route_names = tuple(
            c.route for c in self._route_memory_for(peer_fp).candidates()
        ) or (getattr(sess, "regime", None) or "lan",)
        native_status = native_cdc_status()
        engine_speeds = self._transfer_perf.speeds(
            native_cdc=bool(native_status.available),
        )
        transfer_brain_decision = decision_from_observations(
            size_bytes=size,
            supports_cdc=can_offer_cdc,
            supports_swarm=FILE_SWARM in set(normalize_caps(peer_features)),
            prior_hit_rate=prior_hit_rate,
            observations=route_observations,
            routes=route_names,
            mesh_nodes=self._mesh_node_signals(
                peer_fp,
                chunk_hit_rate=prior_hit_rate,
            ),
            verification_head=verification_head,
            speeds=engine_speeds,
        ).to_dict()
        autopilot_profile = adapt_pipeline_profile(
            _stream_transfer_profile(size),
            transfer_brain_decision,
        )
        autopilot_plan = build_transfer_autopilot_plan(
            decision=transfer_brain_decision,
            profile=autopilot_profile,
            size_bytes=size,
            peer_features=peer_features,
            prior_hit_rate=prior_hit_rate,
            cdc_binary_feature=FILE_CDC_BINARY_FRAME,
            stream_binary_feature=FILE_BINARY_FRAME,
        ).to_dict()
        now_ms = int(time.time() * 1000)
        base_metadata = {
            **base_metadata,
            **intent.metadata(),
            "mode": planned_wire_mode,
            "delivery_state": "queued",
            "file_index_cache": "hit" if cached is not None else "miss",
            "file_index_kind": (
                index_kind if can_offer_cdc else cached_index_kind
            ),
            "cdc_decision_reason": cdc_decision_reason,
            "cdc_auto_index_max_bytes": CDC_AUTO_INDEX_MAX_BYTES,
            "fast_fixed_index_min_bytes": FAST_FIXED_INDEX_MIN_BYTES,
            "fixed_chunk_size": fixed_chunk_size,
            "cdc_engine_status": {
                "available": bool(native_status.available),
                "engine": str(native_status.engine),
                "reason": str(native_status.reason),
                "library": str(native_status.library),
            },
            "transfer_engine_speeds": engine_speeds,
            "transfer_engine_oracle": self._transfer_perf.snapshot(),
            "prior_hit_rate_estimate": prior_hit_rate,
            "transfer_brain": transfer_brain_decision,
            "autopilot_plan": autopilot_plan,
            "verification_head": list(verification_head),
            "peer_app_version": peer_version,
            "peer_features": list(peer_features),
            "planned_wire_mode": planned_wire_mode,
            "protocol_attempts": [
                {
                    "method": intent.preferred_method,
                    "at_ms": now_ms,
                    "state": "selected",
                },
            ],
        }
        offer_fields = {
            "name": path.name,
            "size": size,
            "blob": blob_hex,
            "mode": planned_wire_mode,
            "compat": {
                "preferred_method": intent.preferred_method,
                "fallback_order": list(intent.methods),
                "transfer_mode": intent.compatibility.transfer_mode,
            },
        }
        if can_offer_cdc:
            offer_fields["chunks"] = cdc_index
        offer = make_msg("FILE_OFFER", self.me.short_id, **offer_fields)
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
                progress_bytes=existing_progress_bytes,
                total_bytes=size,
                chunks_done=existing_chunks_done,
                chunks_total=max(planned_chunks_total, existing_chunks_total),
                metadata={
                    **base_metadata,
                    "delivery_state": "sending",
                    "last_attempt_ms": now_ms,
                },
            )
        else:
            self._update_transfer(
                transfer_id,
                status="offered",
                metadata={
                    **base_metadata,
                    "delivery_state": "sending",
                    "last_attempt_ms": now_ms,
                },
            )

        batched_acks: set[str] = set()

        async def _await_ack(
            ch_: ch.Channel,
            *,
            request_id: str | None = None,
            expected_types: set[str] | None = None,
            deadline: float | None = None,
        ) -> dict:
            # v0.6.3: bound each recv. Without this, a peer that
            # received our chunk but never ACKed (e.g., crashed,
            # NAT dropped, channel hung mid-flush) would freeze
            # the entire transfer indefinitely.
            deadline = FILE_ACK_DEADLINE_S if deadline is None else float(deadline)
            expected = expected_types or {"ACK"}
            while True:
                if request_id is not None and request_id in batched_acks:
                    batched_acks.remove(request_id)
                    return {
                        "t": "ACK",
                        "from": peer.short_id,
                        "of": request_id,
                        "batched": True,
                    }
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
                t = str(m.get("t") or "")
                if t == "CAPS":
                    features = list(normalize_caps(m.get("features", [])))
                    ch_.peer_caps = {
                        "protocol": m.get("protocol", "?"),
                        "features": features,
                        "from": m.get("from"),
                        "app_version": m.get("app_version"),
                    }
                    # v0.8.2: ratchet half-step on file-send recv loop.
                    with contextlib.suppress(Exception):
                        ch_.note_caps_received(features)
                        ch_.maybe_activate_ratchet()
                    if self.state is not None:
                        with contextlib.suppress(Exception):
                            self.state.set_peer_capabilities(peer_fp, features)
                    continue
                if t == "PRESENCE":
                    self.record_peer_presence(peer_fp, str(m.get("presence") or ""))
                    continue
                if t == "FILE_ACK_BATCH":
                    acked = {
                        str(v) for v in (m.get("ofs") or m.get("acks") or [])
                        if v is not None and str(v)
                    }
                    if request_id is not None and request_id in acked:
                        acked.remove(request_id)
                        batched_acks.update(acked)
                        return {
                            "t": "ACK",
                            "from": m.get("from", peer.short_id),
                            "of": request_id,
                            "batched": True,
                            "batch_count": int(m.get("count") or (len(acked) + 1)),
                        }
                    batched_acks.update(acked)
                    continue
                of = m.get("of")
                if request_id is not None and of not in (None, request_id):
                    log.debug(
                        "ignored stale file-transfer reply %s of=%s while waiting for %s",
                        t, of, request_id,
                    )
                    continue
                if t in expected:
                    return m
                if t == "ACK" and m.get("rejected"):
                    return m
                log.debug(
                    "ignored out-of-band file-transfer frame %s while waiting for %s",
                    t, sorted(expected),
                )

        adaptive_scheduler: AdaptiveTransferScheduler | None = None
        try:
            # v0.7.0: serialize all I/O on the persistent session under
            # sess.lock so the file send doesn't interleave with chat
            # send_to() calls or session-keepalive PINGs. Same locking
            # discipline as send_to(); the rest of the application is
            # unaware they're sharing a TCP connection.
            async with sess.lock:
                await channel.send(encode_msg(offer))
                first_reply = await _await_ack(
                    channel,
                    request_id=str(offer.get("id")),
                    expected_types={"ACK", "FILE_WANTS"},
                )
                ev = self._persist(
                    msg=offer, direction="out", peer_fp=peer_fp, peer_short_id=peer.short_id,
                )
                self._broadcast_tail(ev)

                chunks_sent = 0
                wire_bytes_sent = 0
                raw_bytes_sent = 0
                compressed_chunks = 0
                skipped_bytes = 0
                adaptive_scheduler_snapshot = None
                peer_feature_set = set(normalize_caps(
                    (getattr(channel, "peer_caps", None) or {}).get("features", peer_features)
                ))
                ack_batch_raw = (
                    autopilot_plan.get("ack_batch", 1)
                    if isinstance(autopilot_plan, dict) else 1
                )
                try:
                    ack_batch_requested = int(cast(Any, ack_batch_raw))
                except (TypeError, ValueError, OverflowError):
                    ack_batch_requested = 1
                negotiated_ack_batch = (
                    max(1, min(
                        FILE_ACK_BATCH_MAX,
                        ack_batch_requested,
                    ))
                    if FILE_ACK_BATCH in peer_feature_set else 1
                )
                if first_reply.get("rejected"):
                    raise RuntimeError(
                        f"peer rejected file offer: {first_reply.get('rejected')}"
                    )

                async def _queue_or_send(ch_: ch.Channel, payload: bytes) -> bool:
                    queued = getattr(ch_, "queue_send", None)
                    if queued is None:
                        await ch_.send(payload)
                        return False
                    await queued(payload)
                    return True

                async def _flush_if_queued(ch_: ch.Channel, queued: bool) -> None:
                    if not queued:
                        return
                    flush = getattr(ch_, "flush", None)
                    if flush is not None:
                        await flush()

                cdc_used = can_offer_cdc and first_reply.get("t") == "FILE_WANTS"
                wanted_indexes = (
                    {int(i) for i in first_reply.get("wants", [])}
                    if cdc_used else set()
                )
                actual_method = (
                    "file_cdc"
                    if cdc_used
                    else "file_baseline"
                )
                if cdc_used:
                    cdc_binary_used = FILE_CDC_BINARY_FRAME in peer_feature_set
                    actual_prior_hit_rate = (
                        1.0 - (len(wanted_indexes) / max(1, len(cdc_chunks)))
                    )
                    skipped_bytes = sum(
                        int(c.size) for c in cdc_chunks if c.index not in wanted_indexes
                    )
                    cdc_profile = adapt_pipeline_profile(
                        _stream_transfer_profile(size),
                        {
                            **transfer_brain_decision,
                            "coherence_score": max(
                                float(transfer_brain_decision.get("coherence_score") or 0.0),
                                actual_prior_hit_rate,
                            ),
                        },
                    )
                    if actual_prior_hit_rate < 0.25:
                        safe_window = 4 if size >= 64 * 1024 * 1024 else 8
                        current_window = max(1, int(cdc_profile.get("window_chunks") or 1))
                        if current_window > safe_window:
                            chunk_size_for_window = max(
                                1,
                                int(cdc_profile.get("chunk_size") or CHUNK_SIZE),
                            )
                            cdc_profile = {
                                **cdc_profile,
                                "window_chunks": safe_window,
                                "window_bytes": safe_window * chunk_size_for_window,
                                "reason": (
                                    f"{cdc_profile.get('reason', 'adaptive')}"
                                    "_fresh_content_warm_start"
                                ),
                            }
                    cdc_scheduler = AdaptiveTransferScheduler(
                        cdc_profile,
                        max_window_chunks=max(1, int(cdc_profile["window_chunks"]) * 2),
                    )
                    adaptive_scheduler = cdc_scheduler
                    cdc_window_chunks = int(cdc_scheduler.window_chunks)
                    cdc_window_bytes = int(cdc_scheduler.window_bytes)
                    base_metadata = {
                        **base_metadata,
                        "cdc_engine": (
                            f"native_{native_status.engine}_pipelined_chunks_v3"
                            if native_status.available
                            else "pipelined_chunks_v2"
                        ),
                        "cdc_window_chunks": cdc_window_chunks,
                        "cdc_window_bytes": cdc_window_bytes,
                        "pipeline_tuning": cdc_profile,
                        "prior_hit_rate_actual": actual_prior_hit_rate,
                        "skipped_bytes": skipped_bytes,
                        "skipped_ratio": round(
                            skipped_bytes / max(1, size), 6,
                        ),
                        "binary_frame": cdc_binary_used,
                        "ack_batch": negotiated_ack_batch,
                    }
                    self._update_transfer(
                        transfer_id,
                        status="active",
                        progress_bytes=skipped_bytes,
                        total_bytes=size,
                        chunks_done=len(cdc_chunks) - len(wanted_indexes),
                        chunks_total=len(cdc_chunks),
                        metadata={
                            **base_metadata,
                            "delivery_state": "sending",
                            "actual_method": actual_method,
                            "skipped_chunks": len(cdc_chunks) - len(wanted_indexes),
                        },
                    )
                    with open(path, "rb") as f:
                        pending_cdc_sizes: deque[tuple[str, int, int, float]] = deque()
                        compression_enabled = True
                        compression_trials = 0
                        compression_misses = 0

                        async def _settle_one_cdc_ack() -> None:
                            nonlocal chunks_sent, raw_bytes_sent, wire_bytes_sent
                            msg_id, raw_size, wire_size, sent_at = pending_cdc_sizes[0]
                            await _await_ack(channel, request_id=msg_id)
                            ack_done = time.perf_counter()
                            pending_cdc_sizes.popleft()
                            cdc_scheduler.observe_ack(
                                ack_ms=(ack_done - sent_at) * 1000.0,
                                raw_bytes=raw_size,
                                wire_bytes=wire_size,
                                in_flight_chunks=len(pending_cdc_sizes),
                            )
                            chunks_sent += 1
                            raw_bytes_sent += raw_size
                            wire_bytes_sent += wire_size
                            self._update_transfer(
                                transfer_id,
                                status="active",
                                progress_bytes=skipped_bytes + raw_bytes_sent,
                                total_bytes=size,
                                chunks_done=(len(cdc_chunks) - len(wanted_indexes)) + chunks_sent,
                                chunks_total=len(cdc_chunks),
                                raw_bytes=raw_bytes_sent,
                                wire_bytes=wire_bytes_sent,
                                metadata={
                                    **base_metadata,
                                    "delivery_state": "sending",
                                    "actual_method": actual_method,
                                    "in_flight_chunks": len(pending_cdc_sizes),
                                    "adaptive_scheduler": cdc_scheduler.snapshot(),
                                },
                            )

                        wanted_total = len(wanted_indexes)
                        wanted_sent_index = 0
                        for c in cdc_chunks:
                            if c.index not in wanted_indexes:
                                continue
                            wanted_sent_index += 1
                            f.seek(c.start)
                            data = f.read(c.size)
                            if len(data) != c.size or blake3.blake3(data).hexdigest() != c.hash:
                                raise RuntimeError("source file changed during transfer")
                            enc, payload = self._encode_payload(
                                data,
                                allow_compress=compression_enabled,
                            )
                            if enc != "raw":
                                compressed_chunks += 1
                                compression_misses = 0
                            elif len(data) >= COMPRESSION_MIN_BYTES:
                                compression_misses += 1
                            if len(data) >= COMPRESSION_MIN_BYTES:
                                compression_trials += 1
                                if compression_trials >= 3 and compression_misses >= 3:
                                    compression_enabled = False
                            chunk_msg = make_msg(
                                "FILE_CDC_CHUNK",
                                self.me.short_id,
                                blob=blob_hex,
                                index=c.index,
                                hash=c.hash,
                                enc=enc,
                                wire_size=len(payload),
                            )
                            remaining_wanted = max(1, wanted_total - wanted_sent_index + 1)
                            chunk_ack_batch = min(
                                negotiated_ack_batch,
                                max(1, int(cdc_scheduler.window_chunks)),
                                remaining_wanted,
                            )
                            if chunk_ack_batch > 1:
                                chunk_msg["ack_batch"] = chunk_ack_batch
                            if cdc_binary_used:
                                wire_payload = _encode_binary_frame(chunk_msg, payload)
                            else:
                                chunk_msg["data"] = base64.b64encode(payload).decode("ascii")
                                wire_payload = encode_msg(chunk_msg)
                            queued_write = await _queue_or_send(
                                channel,
                                wire_payload,
                            )
                            pending_cdc_sizes.append((
                                str(chunk_msg.get("id")),
                                len(data),
                                len(payload),
                                time.perf_counter(),
                            ))
                            while not cdc_scheduler.can_send(len(pending_cdc_sizes)):
                                await _flush_if_queued(channel, queued_write)
                                queued_write = False
                                await _settle_one_cdc_ack()
                        while pending_cdc_sizes:
                            await _flush_if_queued(channel, True)
                            await _settle_one_cdc_ack()
                    adaptive_scheduler_snapshot = cdc_scheduler.snapshot()
                else:
                    binary_stream_used = FILE_BINARY_FRAME in peer_feature_set
                    # Phase C-3 (ADR-0026 + follow-up): native chunk-store
                    # transport is now DEFAULT-ON when the peer advertises
                    # NATIVE_TRANSFER_V1. Operators can disable explicitly
                    # via ``ONE_LINK_NATIVE_TRANSFER=0`` (e.g. for rolling
                    # back during a production incident). When the peer
                    # lacks the cap, sender falls through to FILE_BIN_CHUNK
                    # / FILE_CHUNK transparently.
                    _native_env = os.environ.get("ONE_LINK_NATIVE_TRANSFER", "1")
                    native_transfer_used = (
                        NATIVE_TRANSFER_V1 in peer_feature_set
                        and _native_env != "0"
                    )
                    native_session = None
                    if native_transfer_used:
                        try:
                            native_session = channel.get_or_create_native_transfer_session()
                        except Exception as exc:
                            log.warning(
                                "native transfer requested but unavailable (%s) — "
                                "falling back to %s",
                                exc,
                                "FILE_BIN_CHUNK" if binary_stream_used else "FILE_CHUNK",
                            )
                            native_transfer_used = False
                    if can_offer_cdc:
                        attempts = list(base_metadata.get("protocol_attempts") or [])
                        attempts.append({
                            "method": "file_binary_frame" if binary_stream_used else "file_baseline",
                            "at_ms": int(time.time() * 1000),
                            "state": "fallback",
                            "reason": "peer_acknowledged_stream",
                        })
                        base_metadata = {
                            **base_metadata,
                            "mode": "stream",
                            "actual_method": "file_binary_frame" if binary_stream_used else actual_method,
                            "protocol_attempts": attempts,
                        }
                    stream_profile = adapt_pipeline_profile(
                        _stream_transfer_profile(size),
                        transfer_brain_decision,
                    )
                    stream_chunk_size = int(stream_profile["chunk_size"])
                    stream_scheduler = AdaptiveTransferScheduler(
                        stream_profile,
                        max_window_chunks=max(1, int(stream_profile["window_chunks"]) * 2),
                    )
                    adaptive_scheduler = stream_scheduler
                    stream_window_chunks = int(stream_scheduler.window_chunks)
                    stream_window_bytes = int(stream_scheduler.window_bytes)
                    base_metadata = {
                        **base_metadata,
                        "stream_engine": (
                            "pipelined_binary_v1" if binary_stream_used
                            else "pipelined_json_v1"
                        ),
                        "stream_chunk_size": stream_chunk_size,
                        "stream_window_chunks": stream_window_chunks,
                        "stream_window_bytes": stream_window_bytes,
                        "pipeline_tuning": stream_profile,
                        "binary_frame": binary_stream_used,
                        "ack_batch": negotiated_ack_batch,
                    }
                    with open(path, "rb") as f:
                        seq = 0
                        pending_sizes: deque[tuple[str, int, float]] = deque()
                        total_stream_chunks = max(
                            1, (size + stream_chunk_size - 1) // stream_chunk_size,
                        )

                        async def _settle_one_stream_ack(
                            *, deadline: float | None = None,
                        ) -> None:
                            nonlocal chunks_sent, raw_bytes_sent, wire_bytes_sent
                            msg_id, acked_size, sent_at = pending_sizes[0]
                            await _await_ack(
                                channel,
                                request_id=msg_id,
                                deadline=deadline,
                            )
                            ack_done = time.perf_counter()
                            pending_sizes.popleft()
                            stream_scheduler.observe_ack(
                                ack_ms=(ack_done - sent_at) * 1000.0,
                                raw_bytes=acked_size,
                                wire_bytes=acked_size,
                                in_flight_chunks=len(pending_sizes),
                            )
                            chunks_sent += 1
                            raw_bytes_sent += acked_size
                            wire_bytes_sent += acked_size
                            self._update_transfer(
                                transfer_id,
                                status="active",
                                progress_bytes=raw_bytes_sent,
                                total_bytes=size,
                                chunks_done=chunks_sent,
                                chunks_total=total_stream_chunks,
                                raw_bytes=raw_bytes_sent,
                                wire_bytes=wire_bytes_sent,
                                metadata={
                                    **base_metadata,
                                    "delivery_state": "sending",
                                    "actual_method": (
                                        "file_binary_frame" if binary_stream_used
                                        else actual_method
                                    ),
                                    "in_flight_chunks": len(pending_sizes),
                                    "adaptive_scheduler": stream_scheduler.snapshot(),
                                },
                            )

                        while True:
                            data = f.read(stream_chunk_size)
                            if not data:
                                break
                            eof = f.tell() >= size
                            # v0.12.0: pace before send. No-op when
                            # the user hasn't set a bandwidth cap.
                            await self.bandwidth_pacer.pace(len(data))
                            remaining_stream_chunks = max(1, total_stream_chunks - seq)
                            chunk_ack_batch = min(
                                negotiated_ack_batch,
                                max(1, int(stream_scheduler.window_chunks)),
                                remaining_stream_chunks,
                            )
                            if native_transfer_used and native_session is not None:
                                # ADR-0026: encrypt plaintext via the
                                # cached native session; ship encrypted
                                # bytes + chunk_id + plaintext_len. The
                                # receiver's matched session decrypts
                                # in lockstep (same derivation, same
                                # ratchet position).
                                record = native_session.encrypt_chunk_bytes(data)
                                chunk_msg = make_msg(
                                    "FILE_NATIVE_CHUNK",
                                    self.me.short_id,
                                    blob=blob_hex,
                                    seq=seq,
                                    chunk_id=record.chunk_id.hex(),
                                    plaintext_len=record.plaintext_len,
                                    data=base64.b64encode(record.ciphertext).decode("ascii"),
                                    eof=eof,
                                )
                                if chunk_ack_batch > 1 and not eof:
                                    chunk_msg["ack_batch"] = chunk_ack_batch
                                queued_write = await _queue_or_send(
                                    channel,
                                    encode_msg(chunk_msg),
                                )
                            elif binary_stream_used:
                                chunk_msg = make_msg(
                                    "FILE_BIN_CHUNK",
                                    self.me.short_id,
                                    blob=blob_hex,
                                    seq=seq,
                                    eof=eof,
                                )
                                if chunk_ack_batch > 1 and not eof:
                                    chunk_msg["ack_batch"] = chunk_ack_batch
                                queued_write = await _queue_or_send(
                                    channel,
                                    _encode_binary_frame(chunk_msg, data),
                                )
                            else:
                                chunk_msg = make_msg(
                                    "FILE_CHUNK",
                                    self.me.short_id,
                                    blob=blob_hex,
                                    seq=seq,
                                    data=base64.b64encode(data).decode("ascii"),
                                    eof=eof,
                                )
                                if chunk_ack_batch > 1 and not eof:
                                    chunk_msg["ack_batch"] = chunk_ack_batch
                                queued_write = await _queue_or_send(
                                    channel,
                                    encode_msg(chunk_msg),
                                )
                            pending_sizes.append((
                                str(chunk_msg.get("id")),
                                len(data),
                                time.perf_counter(),
                            ))
                            while not stream_scheduler.can_send(len(pending_sizes)):
                                await _flush_if_queued(channel, queued_write)
                                queued_write = False
                                await _settle_one_stream_ack()
                            seq += 1

                        while pending_sizes:
                            await _flush_if_queued(channel, True)
                            final_deadline = (
                                _final_stream_ack_deadline(size)
                                if len(pending_sizes) == 1 else None
                            )
                            await _settle_one_stream_ack(deadline=final_deadline)
                    adaptive_scheduler_snapshot = stream_scheduler.snapshot()

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
                        await _await_ack(channel, request_id=str(empty.get("id")))
                        chunks_sent = 1
                        self._update_transfer(
                            transfer_id,
                            status="active",
                            progress_bytes=0,
                            total_bytes=0,
                            chunks_done=1,
                            chunks_total=1,
                            metadata={
                                **base_metadata,
                                "delivery_state": "sending",
                                "actual_method": actual_method,
                            },
                        )

                # v0.7.0: stamp session counters so the next idle-PING
                # probe doesn't fire prematurely. No channel.close() —
                # the persistent session is alive for the next send.
                sess.last_used = time.time()
                sess.messages_sent += 1
                # Phase D #3 (ADR-0033): record the successful transfer
                # in the prefetch predictor so future warm-cache +
                # next-file prediction sees the access pattern.
                self._observe_prefetch(peer_fp, blob_hex)
                done_ms = int(time.time() * 1000)
                started_ms = int(base_metadata.get("last_attempt_ms") or now_ms)
                elapsed_s = max(0.001, (done_ms - started_ms) / 1000.0)
                transfer_report = transfer_result_report(
                    raw_bytes=raw_bytes_sent,
                    wire_bytes=wire_bytes_sent,
                    elapsed_s=elapsed_s,
                    skipped_bytes=skipped_bytes,
                )
                performance_summary = transfer_performance_summary(
                    report=transfer_report,
                    plan=base_metadata.get("autopilot_plan") or autopilot_plan,
                    elapsed_s=elapsed_s,
                )
                throughput_bps = (
                    (raw_bytes_sent * 8.0) / elapsed_s
                    if raw_bytes_sent > 0 else None
                )
                self._record_route_observation(
                    sess.peer_fp,
                    route=getattr(sess, "regime", None) or "lan",
                    ok=True,
                    bandwidth_bps=throughput_bps,
                )
                self._transfer_perf.observe(
                    method=(
                        "file_cdc" if cdc_used
                        else "file_binary_frame"
                        if base_metadata.get("binary_frame")
                        else "file_baseline"
                    ),
                    report=transfer_report,
                    ok=True,
                )

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
                    **base_metadata,
                    "mode": "cdc" if cdc_used else "stream",
                    "delivery_state": "done",
                    "actual_method": (
                        "file_cdc" if cdc_used
                        else "file_binary_frame"
                        if base_metadata.get("binary_frame")
                        else "file_baseline"
                    ),
                    "skipped_chunks": len(cdc_chunks) - chunks_sent if cdc_used else 0,
                    "compressed_chunks": compressed_chunks,
                    "completed_at_ms": int(time.time() * 1000),
                    "elapsed_ms": int(round(elapsed_s * 1000.0)),
                    "transfer_report": transfer_report,
                    "performance_summary": performance_summary,
                    "adaptive_scheduler": adaptive_scheduler_snapshot,
                    "error": None,
                    "transient": False,
                },
            )
            # A completed send is stronger evidence than the background
            # timer: the peer, route, session, and receiver are healthy
            # right now. Use that signal to quietly drain any older durable
            # file intents for the same peer instead of waiting for the next
            # retry window/prune tick. If this send itself is running inside
            # resume_paused_transfers_for(), that per-peer lock makes the
            # scheduled task no-op, avoiding recursive duplicate resumes.
            self._schedule_resume_paused(sess.peer_fp)
            return {
                "offer": offer,
                "chunks": chunks_sent,
                "total_chunks": len(cdc_chunks) if cdc_used else chunks_sent,
                "cdc": cdc_used,
                "cdc_skipped": len(cdc_chunks) - chunks_sent if cdc_used else 0,
                "raw_bytes_sent": raw_bytes_sent,
                "wire_bytes_sent": wire_bytes_sent,
                "compressed_chunks": compressed_chunks,
                "transfer_report": transfer_report,
                "performance_summary": performance_summary,
                "transfer_engine_oracle": self._transfer_perf.snapshot(),
                "blob": blob_hex,
                "size": size,
                "transfer_id": transfer_id,
            }
        except Exception as e:
            # v0.7.4: distinguish transient errors (network drop,
            # WinError 10053, handshake timeout, peer offline) from
            # permanent ones (capability_disabled, decrypt fail,
            # peer_rejected). Transient → status='paused' so the
            # next session-up auto-resumes via the CDC chunk-cache
            # protocol (FILE_OFFER replies with FILE_WANTS=missing,
            # which is empty for already-delivered chunks). Permanent
            # → status='failed' as before.
            err_str = str(e)
            err_class = type(e).__name__
            transient = _is_transient_send_error(e)
            if adaptive_scheduler is not None:
                with contextlib.suppress(Exception):
                    adaptive_scheduler.observe_retry(
                        reason=err_class,
                        in_flight_chunks=0,
                    )
                    base_metadata = {
                        **base_metadata,
                        "adaptive_scheduler": adaptive_scheduler.snapshot(),
                    }
            with contextlib.suppress(Exception):
                self._transfer_perf.observe_failure(
                    method=str(base_metadata.get("actual_method") or actual_method),
                )
            if transient:
                self._mark_transfer_waiting(
                    transfer_id,
                    path=path,
                    error=err_str,
                    error_class=err_class,
                    base_metadata=base_metadata,
                )
            else:
                self._update_transfer(
                    transfer_id,
                    status="failed",
                    metadata={
                        **base_metadata,
                        "error": err_str[:500],
                        "error_class": err_class,
                        "transient": False,
                        "delivery_state": "needs_attention",
                    },
                )
            # v0.7.0: a mid-stream failure leaves the session in an
            # unknown state (we sent a partial frame, peer's read loop
            # could be poisoned). Drop it so the next send_to / send_file
            # opens a fresh handshake instead of inheriting the rot.
            with contextlib.suppress(Exception):
                await self._drop_outbound_session(sess.peer_fp)
            diag = diagnose_transfer({
                "status": "paused" if transient else "failed",
                "direction": "out",
                "metadata": {
                    **base_metadata,
                    "error": err_str,
                    "error_class": err_class,
                    "transient": transient,
                },
            }).to_dict()
            self._record_route_observation(
                sess.peer_fp,
                route=getattr(sess, "regime", None) or "lan",
                ok=False,
                error_code=diag["code"],
            )
            if transient:
                raise TransferPausedError(
                    err_str, transfer_id=transfer_id, path=path,
                ) from e
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
            if cmd == "status":
                await self._reply(writer, self._control_status())
            elif cmd == "shutdown":
                await self._reply(writer, {"ok": True, "stopping": True})
                asyncio.create_task(self._control_shutdown())
            elif cmd == "peers":
                peer_rows = [
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
                await self._reply(writer, {"ok": True, "me": me, "peers": peer_rows})
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
                    except Exception as e:
                        if not _is_transient_send_error(e):
                            raise
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
                    except Exception as e:
                        if not _is_transient_send_error(e):
                            raise
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

    def _control_status(self) -> dict:
        try:
            from one_link import __version__ as app_version
        except Exception:
            app_version = "?"
        schema_version = 0
        if self.state is not None:
            with contextlib.suppress(Exception):
                schema_version = self.state.schema_version()
        return {
            "ok": True,
            "pid": os.getpid(),
            "app_version": app_version,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": schema_version,
            "python": sys.executable,
            "home": str(data_dir()),
            "ui_server_port": (
                getattr(self.ui_server, "port", None)
                if self.ui_server is not None else None
            ),
            "ui_https_port": (
                getattr(self.ui_server, "https_port", None)
                if self.ui_server is not None else None
            ),
            "me": {
                "short_id": self.me.short_id,
                "fingerprint": self.me.fingerprint,
                "hostname": self.me.hostname,
            },
            # Surface the full native-subsystem availability matrix so
            # operators + integration tests can verify Phase E is
            # wired through the live daemon process, not just inside
            # the harness.
            "native_status": self.native_diagnostics(),
        }

    async def _control_shutdown(self) -> None:
        await asyncio.sleep(0.05)
        if self._peer_server is not None:
            self._peer_server.close()
        if self._control_server is not None:
            self._control_server.close()

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

        # Discovery is opportunistic. A trusted device we have talked to before
        # should remain dialable through its last observed LAN endpoint while
        # mDNS catches up, so "send" does not fail right after daemon restart.
        if rec.last_address and rec.last_port:
            with contextlib.suppress(Exception):
                port = int(rec.last_port)
                if port > 0:
                    return Peer(
                        short_id=rec.short_id,
                        hostname=rec.hostname or rec.short_id,
                        address=rec.last_address,
                        port=port,
                        ed_pub_hex=rec.pubkey.hex(),
                    )

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
            # v0.20.7 (security audit H21 + M29 + partial C5):
            # acquire a LockBox unconditionally so chain_keys and
            # the UI token get AES-GCM-wrapped at rest. The lockbox
            # picks the strongest key it can without prompting:
            #   - ONE_LINK_PASSPHRASE set ⇒ scrypt-derived key
            #     (resists attackers with same-user OS access).
            #   - Otherwise silent DRK from acquire_or_create_silent_drk:
            #     DPAPI-wrapped per-user on Windows; raw 32 random
            #     bytes with 0o600 perms on POSIX.
            # The point: every install gets at-rest encryption by
            # default, no UX friction. A user who steals the laptop
            # without the login password cannot DPAPI-unwrap the
            # DRK, so wrapped sqlite values stay opaque.
            try:
                from one_link.lockbox import acquire_lockbox
                from one_link.paths import data_dir
                lb = acquire_lockbox(data_dir())
                self.state.set_lockbox(lb)
                log.info(
                    "lockbox: at-rest wrap active for chain_keys + UI token"
                )
            except Exception as e:
                log.warning(
                    "lockbox: failed to initialize (%s); proceeding "
                    "with cleartext at-rest storage",
                    e,
                )
            # v0.20.7 (security audit M30): attach the path-PII
            # encryptor when the master seed is available. Same-path-
            # → same-ciphertext (AES-SIV deterministic AEAD), so the
            # chunk_sources / file_index_cache indexes still work; a
            # T4 attacker sees opaque ciphertext instead of the user's
            # full home-dir layout. Daemons without a master seed
            # (legacy installs that haven't run `backup init`) keep
            # cleartext paths — there's no recoverable secret to
            # derive a key from anyway, so the gain would be illusory.
            try:
                from one_link import master_seed as _ms
                from one_link.path_pii import PathPIIEncryptor
                from one_link.paths import data_dir as _data_dir
                _seed = _ms.load_seed(_data_dir())
                if _seed is not None:
                    self.state.set_path_pii_encryptor(PathPIIEncryptor(_seed))
                    log.info(
                        "path-pii: AES-SIV deterministic encryption "
                        "active for chunk_sources / file_index_cache "
                        "path columns (audit M30)"
                    )
            except Exception as e:
                log.warning(
                    "path-pii: failed to initialize (%s); paths in "
                    "chunk_sources / file_index_cache stay cleartext",
                    e,
                )
            # Pin our own identity so it's a known peer.
            self.state.upsert_peer(
                fingerprint=self.me.fingerprint,
                short_id=self.me.short_id,
                pubkey=self.me.public_bytes,
                hostname=self.me.hostname,
                trust_default="pinned",
            )
            self.state.set_peer_trust(self.me.fingerprint, "pinned", actor="self")
            # v0.10.0: apply persisted settings that affect global
            # daemon behavior (custom download folder, log level).
            self._apply_settings_at_boot()
            self._load_persisted_route_memory()
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
        # v0.20.7 (security audit L1): refuse mDNS-driven pub-hex
        # swaps for short_ids whose existing pubkey is already pinned
        # via SAS pair. Defends against a LAN attacker advertising a
        # victim's short_id with a different pub. The channel
        # handshake already pins identity for impersonation defense;
        # this closes the discovery-display side so the UI never
        # surfaces an attacker-supplied pub for a paired short_id.
        def _is_pub_hex_pinned(pub_hex: str) -> bool:
            if self.state is None:
                return False
            try:
                pub_bytes = bytes.fromhex(pub_hex)
            except ValueError:
                return False
            try:
                fp = fingerprint_of(pub_bytes)
                rec = self.state.get_peer(fp)
            except Exception:
                return False
            return bool(rec and rec.trust == "pinned")
        self.discovery.registry.is_pinned_pubkey = _is_pub_hex_pinned

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
                    with contextlib.suppress(Exception):
                        self._schedule_due_transfer_retries()
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

        with contextlib.suppress(Exception):
            self._schedule_due_transfer_retries()

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
                # v0.8.9: hook divergent-edit conflict detection so the
                # UI raises a banner the moment a conflict is logged.
                # FolderEngine now declares the field as
                # ``Optional[Callable[[str, int], None]]`` so the
                # assignment is fully type-checked.
                self.folder_engine._on_conflict_recorded = self._on_folder_conflict
                await self.folder_engine.start()
                self._folder_sync_task = asyncio.create_task(self._folder_sync_loop())
            except Exception as e:
                log.warning("folder sync init failed: %s", e)
                self.folder_engine = None
                self.blob_store = None

        # v0.10.2: disappearing-message reaper. Polls every 30s for
        # rows whose expires_at_ms has passed; tombstones them and
        # broadcasts msg_delete WS events.
        self._dm_reaper_task = asyncio.create_task(self._dm_reaper_loop())
        self._prior_index_task = asyncio.create_task(self._prior_index_loop())

        # Phase E: spin up the coherence-field snapshot manager. The
        # manager idles harmlessly when no peers / no native crate; it
        # only does work when both are present.
        self._ensure_field_snapshot()
        # Phase E: feed the manager its topology from the daemon's
        # live peer registry every 5s. Without this hook the manager
        # spins idle (no topology → no solve → no field).
        self._field_topology_feeder_task = asyncio.create_task(
            self._field_topology_feeder_loop()
        )

        # Phase A2: bring up the local QUIC endpoint (no-op if the
        # native crate isn't installed). Dual-stack with WebRTC; the
        # daemon's transport_choice_for_peer() selects per-peer.
        self._ensure_quic_endpoint()

        # Start UI server if available. Import lazily so CLI/status paths do
        # not pay aiohttp's Windows platform/WMI import cost before the daemon
        # has even published its control socket.
        try:
            from one_link.server import UIServer

            self.ui_server = UIServer(self)
            ui_port = await self.ui_server.start()
        except Exception as e:
            log.warning("UI server failed to start: %s", e)
            self.ui_server = None
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
        try:
            await asyncio.gather(
                self._peer_server.serve_forever(),
                self._control_server.serve_forever(),
            )
        except RuntimeError as e:
            if "is closed" not in str(e):
                raise

    async def stop(self) -> None:
        # Phase E: stop the field-snapshot topology feeder + the
        # snapshot manager itself. Feeder first so it doesn't observe
        # a half-torn-down peer table mid-tick.
        feeder = getattr(self, "_field_topology_feeder_task", None)
        if feeder is not None and not feeder.done():
            feeder.cancel()
            try:
                await feeder
            except (asyncio.CancelledError, Exception):
                pass
        if self._field_snapshot is not None:
            try:
                self._field_snapshot.stop(join_timeout=2.0)
            except Exception:  # pragma: no cover
                pass
        # Phase A2: close the local QUIC endpoint. Active QUIC peer
        # connections close as part of their own session teardown.
        quic_ep = getattr(self, "_quic_endpoint", None)
        if quic_ep is not None:
            try:
                quic_ep.close()
            except Exception:  # pragma: no cover
                pass
            self._quic_endpoint = None
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
        if self._dm_reaper_task and not self._dm_reaper_task.done():
            self._dm_reaper_task.cancel()
            try:
                await self._dm_reaper_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._prior_index_task and not self._prior_index_task.done():
            self._prior_index_task.cancel()
            try:
                await self._prior_index_task
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
    _install_asyncio_exception_handler(asyncio.get_running_loop())
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
    try:
        port = int(p.read_text().strip())
    except Exception as e:
        _clear_stale_runtime_files()
        raise RuntimeError("daemon not running (bad control.port file)") from e
    if is_daemon_alive(port):
        return port
    lock_pid = _read_lock_pid()
    if lock_pid is None or not _pid_is_alive(lock_pid):
        _clear_stale_runtime_files()
    raise RuntimeError(f"daemon not running (stale control.port {port})")


def is_daemon_alive(port: int, *, timeout: float = 0.5) -> bool:
    """Return True only when the local One Link control protocol answers.

    A bare TCP connect is not enough: a stale port can be reused by an
    unrelated process, and a wedged daemon can accept sockets without ever
    replying. The launcher and CLI need the stronger signal.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b'{"cmd":"status"}\n')
        buf = b""
        while not buf.endswith(b"\n") and len(buf) < 65536:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        if not buf:
            return False
        msg = json.loads(buf.decode("utf-8").strip() or "{}")
        return msg.get("ok") is True and bool(msg.get("pid"))
    except Exception:
        return False
    finally:
        s.close()
