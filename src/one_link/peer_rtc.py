"""v0.20.0 — Browser-as-peer ↔ daemon WebRTC transport.

Lets a browser running /peer (the v0.16-v0.19.2 architecture)
connect directly to the desktop daemon over a WebRTC DataChannel.
DTLS-SRTP at the transport layer + DataChannel framing at the
app layer. Same wire kinds the daemon already speaks ride this
new transport unchanged once `v0.20.2` bridges the two layers.

Design principles
=================

- **Hidden by default.** Users never see SDP, ICE candidates,
  or signaling URLs. Browser scans a QR (v0.20.1) or
  rendezvous-discovers; signaling is over a WebSocket the
  daemon already serves. No manual paste.

- **Trust via certified device enrollment.** A setup-device invite and
  operator-confirmed SAS create a root-signed, revocable self-mesh device row.
  The short-lived pairing token is only a one-device WebRTC handoff; possession
  of the bearer alone never creates owner authority.

- **Roster-bound returning peers.** Every connection resolves the signed-offer
  key against a live, root-certified self-mesh row. Every DataChannel message
  rechecks trust, revoke, safety state, and Guardian epoch. Reconnects also
  prove possession of the enrolled key on the current control channel.

- **Persistent authority, single-process liveness.** `State` is the authority
  source; `BrowserPeerManager` owns only active connections, device-bound
  handoffs, replay caches, and immutable certificate-verification cache data.

Wire format
===========

Signaling (WebSocket text frames):

  Browser → daemon:
    {"v":"OL-PEER-RTC-1", "t":"offer",
     "sdp":"<full SDP offer>",
     "pubkey_b64u":"<browser Ed25519 pubkey>",
     "pair_token":"<optional pairing token>",
     "fingerprint":"<algo>:<hex>",
     "ts":<ms>,
     "signature":"<Ed25519 over canonical(envelope minus signature)>"}

  Daemon → browser:
    {"v":"OL-PEER-RTC-1", "t":"answer",
     "sdp":"<full SDP answer>",
     "daemon_pubkey_b64u":"<daemon's Ed25519 pubkey>",
     "ts":<ms>}

  Either direction (during ICE):
    {"v":"OL-PEER-RTC-1", "t":"ice",
     "candidate":{"candidate":..., "sdpMid":..., "sdpMLineIndex":...}}

  Either direction (errors):
    {"v":"OL-PEER-RTC-1", "t":"error",
     "code":"<short>", "message":"<human>"}

DataChannel (post-connection, JSON text frames):

  {"v":"OL-PEER-1", "t":"ping", "ts":<ms>}
  {"v":"OL-PEER-1", "t":"pong", "ts":<ms>}

  v0.20.2 layers chat / file / peer-roster wire kinds on top.

Pairing-token contract
======================

  Daemon mints a 32-byte base64url token via api_mint_pairing.
  Token is stored in `BrowserPeerManager._pending_pairings` keyed
  by token → {created_ms, ttl_ms, fp_hint, root_pub, device_pub,
  guardian_epoch}. TTL default 90 seconds. Redemption is atomic,
  requires the same signed-offer key and the same still-live roster epoch,
  and consumes the token exactly once. No process-local paired-key authority
  exists.

  The QR encoded for the user has a deep-link to /peer with the
  token embedded as `?pair=<token>` (v0.20.1 wires this).

Security model
==============

  - Pair token leaked → it remains unusable without the certified browser
    private key. Fingerprint mismatch does not burn the legitimate handoff;
    revoke/safety/epoch transition invalidates it immediately.
  - DTLS-SRTP fingerprint pinning (browser ↔ daemon) handled
    by aiortc + browser WebRTC stacks.
  - Ed25519 signature on the offer envelope binds the SDP
    to the browser's claimed pubkey. A malicious signaling
    relay cannot forge an offer for a different pubkey because
    they'd have to break Ed25519.
  - A fresh nonce, challenge id, peer fingerprint, daemon fingerprint,
    connection session id, issuance/expiry window, and exact schema are signed
    again on the current control DataChannel. Accepted challenges are replay
    cached, and any wrong signer/session/channel/schema closes the peer.
  - Daemon's signaling endpoint is unauthenticated by HTTP
    standards (no Bearer token) because the browser is signing
    its own claim. Auth happens at the WebRTC peer-pubkey layer,
    not at the WS-route layer.
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
import time
import threading
import hashlib
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from one_link.fault_observability import report_best_effort_failure

log = logging.getLogger(__name__)


# ── protocol constants ────────────────────────────────────────────────

PEER_RTC_PROTOCOL_VERSION = "OL-PEER-RTC-1"
PEER_DC_PROTOCOL_VERSION = "OL-PEER-1"

# DataChannel labels — browser-side createDataChannel uses the same.
# v0.18.0's /peer page defines WEBRTC_CONTROL_LABEL = "one-link-control-v1"
# but for browser-↔-daemon we use a distinct label so a browser-↔-browser
# connection's DC isn't confused with a browser-↔-daemon DC by any
# bridging logic in v0.20.2+.
DAEMON_CONTROL_LABEL = "one-link-daemon-control-v1"
DAEMON_BULK_LABEL = "one-link-daemon-bulk-v1"

# Pairing-token TTL. External audit 2026-05-18 ES-30 (P2): the old
# 5-minute default was generous to the point of giving a shoulder-
# surfer / screen-share-leaker plenty of window. Real-time pairing
# is the whole point of the QR; 90 seconds is enough to pick up the
# phone, open the camera, and scan, while keeping the leaked-QR
# attack window short. If a slow user fails the scan, the UI shows
# the timer and they can mint a fresh QR with one click — better
# UX than a long-lived token waiting to be stolen.
PAIRING_TOKEN_TTL_MS = 90 * 1000
PAIRING_TOKEN_BYTES = 32
# External audit 2026-05-18 ES-46 (P3): bump the cap so a multi-user
# laptop pairing many family devices in succession doesn't sweep out
# tokens before the user finishes the last one. Sweep is opportunistic
# and bounded by TTL, so a higher cap is harmless.
MAX_PENDING_PAIRING_TOKENS_DEFAULT = 256

# Signature freshness window — accept offer envelopes with a
# timestamp within this many ms of "now". Prevents trivial replay
# of a stale captured offer. WebRTC SDP itself isn't sensitive
# (it's network-routing info), but we still bind freshness so a
# stolen signed offer can't be re-played weeks later.
OFFER_REPLAY_WINDOW_MS = 60 * 1000
OFFER_REPLAY_CACHE_TTL_MS = OFFER_REPLAY_WINDOW_MS + 5_000
OFFER_REPLAY_CACHE_MAX_ENTRIES = 16_384
MAX_SIGNALING_TEXT_BYTES = 256 * 1024
MAX_SDP_BYTES = 128 * 1024
MAX_DC_TEXT_BYTES = 256 * 1024
MAX_PENDING_PAIRING_TOKENS = MAX_PENDING_PAIRING_TOKENS_DEFAULT
MAX_COVER_PACKET_BYTES = 192 * 1024
_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_OFFER_REQUIRED_FIELDS = frozenset({
    "v", "t", "sdp", "pubkey_b64u", "fingerprint", "ts", "signature",
})
_OFFER_OPTIONAL_FIELDS = frozenset({"pair_token"})
_MAX_TIMESTAMP_MS = (1 << 63) - 1

# Audit H8/H9 May 2026 — per-peer rate-limit caps for the two
# control-DC frame types that drive expensive native work. Tuned so
# legitimate burst handshakes (a few attestations on reconnect, the
# scheduled cover-traffic cadence) pass without throttling while
# unauthenticated floods get capped.
ATTEST_CHALLENGE_WINDOW_SECS = 10
ATTEST_CHALLENGE_MAX_PER_WINDOW = 3
COVER_PACKET_WINDOW_SECS = 1
COVER_PACKET_MAX_PER_WINDOW = 20

# Browser-feasible identity-possession proof.  This is deliberately not named
# "attestation": a Web browser can prove possession of its enrolled Ed25519
# device key on one exact DataChannel, but it cannot make a hardware-backed or
# post-quantum platform-attestation claim.
BROWSER_IDENTITY_POSSESSION_SCHEMA = "OL-BROWSER-IDENTITY-POSSESSION-1"
BROWSER_IDENTITY_CHALLENGE_BYTES = 32
BROWSER_IDENTITY_CHALLENGE_ID_BYTES = 16
BROWSER_IDENTITY_SESSION_ID_BYTES = 16
BROWSER_IDENTITY_CHALLENGE_TTL_MS = 15_000
BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS = 5_000
BROWSER_IDENTITY_REPLAY_CACHE_MAX_ENTRIES = 16_384
BROWSER_IDENTITY_REPLAY_CACHE_TTL_MS = 5 * 60 * 1000
BROWSER_AUTH_CERT_CACHE_MAX_ENTRIES = 4_096
_BROWSER_IDENTITY_CHALLENGE_FIELDS = frozenset({
    "v", "t", "schema", "challenge_id", "nonce", "session_id",
    "peer_fingerprint", "daemon_fingerprint", "issued_ms", "expires_ms",
})
_BROWSER_IDENTITY_RESPONSE_FIELDS = frozenset({
    "v", "t", "schema", "challenge_id", "session_id",
    "peer_fingerprint", "signature",
})
_BROWSER_IDENTITY_SIGNING_DOMAIN = b"one-link/browser-identity-possession/v1\0"


# ── helpers (b64url no padding, canonical JSON) ──────────────────────

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64ud(
    s: str,
    *,
    expected_size: int | None = None,
    max_size: int = 128,
) -> bytes:
    if (
        not isinstance(s, str)
        or not s
        or "=" in s
        or any(c not in _B64URL_ALPHABET for c in s)
    ):
        raise ValueError("invalid base64url")
    size_bound = expected_size if expected_size is not None else max_size
    max_chars = (size_bound * 8 + 5) // 6
    if len(s) > max_chars or (
        expected_size is not None and len(s) != (expected_size * 8 + 5) // 6
    ):
        raise ValueError("invalid base64url length")
    pad = b"=" * ((4 - len(s) % 4) % 4)
    try:
        decoded = base64.b64decode(
            s.encode("ascii") + pad,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, UnicodeEncodeError, ValueError) as e:
        raise ValueError("invalid base64url") from e
    if (
        len(decoded) > max_size
        or (expected_size is not None and len(decoded) != expected_size)
        or _b64u(decoded) != s
    ):
        raise ValueError("invalid base64url")
    return decoded


def _b64std_exact(
    value: object,
    *,
    label: str,
    expected_size: int | None = None,
    max_size: int = MAX_COVER_PACKET_BYTES,
) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be base64 text")
    size_bound = expected_size if expected_size is not None else max_size
    max_chars = 4 * ((size_bound + 2) // 3)
    if len(value) > max_chars or (
        expected_size is not None and len(value) != 4 * ((expected_size + 2) // 3)
    ):
        raise ValueError(f"{label} has invalid encoded length")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} is not canonical base64") from exc
    if (
        len(decoded) > max_size
        or (expected_size is not None and len(decoded) != expected_size)
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        raise ValueError(f"{label} is not canonical base64")
    return decoded


def _extract_dtls_fingerprint(sdp: str) -> str:
    """v0.20.7 (security audit C1): extract the DTLS-SRTP fingerprint
    from an SDP blob. The fingerprint line is per-RFC 8122:
        a=fingerprint:<algo> <colon-separated hex bytes>
    Returns "<algo>:<UPPERCASE-HEX>" (e.g. "sha-256:AB:CD:..."), or
    "" if no a=fingerprint line is present. Both endpoints can call
    this on their local + remote SDPs to verify the cryptographic
    identity bound into the DataChannel transport.

    Used in the signed answer envelope so the browser can cross-
    check the SDP it received against the value the daemon
    cryptographically committed to. A MITM rewriting the SDP
    a=fingerprint to point at the attacker's DTLS cert would
    invalidate the cross-check and the browser would refuse the
    DataChannel.
    """
    if not isinstance(sdp, str):
        return ""
    import re
    m = re.search(
        r"^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]+)",
        sdp,
        re.MULTILINE,
    )
    if not m:
        return ""
    algo = m.group(1).strip().lower()
    fp = m.group(2).strip().upper()
    return f"{algo}:{fp}"


def _canonical(payload: dict) -> bytes:
    """JSON canonicalization matching the browser's _canonicalJson:
    sorted keys, no whitespace, ASCII-only (\\uXXXX escapes for
    non-ASCII), exclude the 'signature' field."""
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _canonical_sha256_fingerprint(value: object) -> str | None:
    """Return a canonical browser-peer fingerprint or ``None``.

    Pairing-token identity hints cross an authentication boundary, so an
    arbitrary label (or a differently-cased spelling) must never be treated as
    equivalent to the SHA-256 fingerprint derived from the signed offer key.
    """

    if not isinstance(value, str) or len(value) != len("sha256:") + 64:
        return None
    if not value.startswith("sha256:"):
        return None
    digest = value[len("sha256:"):]
    if any(char not in "0123456789abcdef" for char in digest):
        return None
    return value


def _fingerprint_for_device_pub(device_pub: bytes) -> str:
    if not isinstance(device_pub, bytes) or len(device_pub) != 32:
        raise ValueError("device_pub must be exactly 32 bytes")
    return "sha256:" + hashlib.sha256(device_pub).hexdigest()


def _identity_possession_signing_bytes(challenge: dict[str, Any]) -> bytes:
    """Return the exact bytes an enrolled browser device must sign."""

    if set(challenge) != _BROWSER_IDENTITY_CHALLENGE_FIELDS:
        raise ValueError("identity-possession challenge fields are invalid")
    return _BROWSER_IDENTITY_SIGNING_DOMAIN + _canonical(challenge)


# ── pairing-token store ──────────────────────────────────────────────


@dataclass
class PendingPair:
    token: str
    created_ms: int
    ttl_ms: int = PAIRING_TOKEN_TTL_MS
    # Every token is bound to one already-enrolled, currently-authorized device
    # row.  A bearer alone can never create owner authority.
    fp_hint: Optional[str] = None
    root_pub: Optional[bytes] = None
    device_pub: Optional[bytes] = None
    guardian_epoch: int = 0

    def expired(self, now_ms: Optional[int] = None) -> bool:
        current_ms = _now_ms() if now_ms is None else int(now_ms)
        return current_ms >= self.created_ms + self.ttl_ms


# ── connected browser-peer record ────────────────────────────────────


@dataclass
class BrowserPeer:
    """Live state for a single browser-as-peer connection."""
    fingerprint: str          # sha256:<hex>
    pubkey_bytes: bytes       # 32 bytes raw
    pc: Any = None            # aiortc.RTCPeerConnection
    control_dc: Any = None    # aiortc.RTCDataChannel — the post-connect
                              # control channel we receive from the
                              # browser (or open ourselves if initiator)
    bulk_dc: Any = None       # aiortc.RTCDataChannel
    connected_ms: int = field(default_factory=_now_ms)
    last_activity_ms: int = field(default_factory=_now_ms)
    paired_ms: Optional[int] = None  # set once pairing token redeemed
                                     # OR pubkey already in roster
    closed: bool = False
    # Authoritative self-mesh roster binding captured at connection admission.
    # It is rechecked before every DataChannel dispatch, and Guardian epoch
    # changes force a fresh connection rather than silently retaining owner
    # authority across a safety transition.
    authorized_root_pub: Optional[bytes] = None
    authorized_device_pub: Optional[bytes] = None
    authorized_guardian_epoch: int = 0
    # Browser identity-possession proof, bound to this exact control channel.
    identity_session_id: str = field(
        default_factory=lambda: _b64u(
            secrets.token_bytes(BROWSER_IDENTITY_SESSION_ID_BYTES)
        )
    )
    identity_challenge: Optional[dict[str, Any]] = None
    identity_challenge_dc_id: Optional[int] = None
    identity_verified_ms: Optional[int] = None
    identity_verified_dc_id: Optional[int] = None
    identity_timeout_handle: Optional[asyncio.TimerHandle] = field(
        default=None,
        repr=False,
    )
    # Row 10 — peer-handshake attestation state.
    # `attestation_challenge`: 32-byte nonce we sent the peer.
    #   Populated when we initiate; checked when their response arrives.
    # `attested_ms`: monotonic timestamp when verification passed.
    #   None until the peer's attest_response has verified.
    # `peer_master_vk`: 1984-byte hybrid VK extracted from a verified
    #   attestation doc. None until attested. Pin this to detect
    #   master-key rotation across reconnects.
    attestation_challenge: Optional[bytes] = None
    # Audit M9 May 2026: bind the in-flight challenge to the
    # specific control DC instance it was sent on (the `id()` of the
    # DC object at issue time). A peer reconnecting mid-handshake
    # creates a NEW DC instance; binding to it prevents the new DC
    # from accidentally accepting a response signed against the old
    # DC's challenge (cross-DC confusion).
    attestation_challenge_dc_id: Optional[int] = None
    attested_ms: Optional[int] = None
    peer_master_vk: Optional[bytes] = None
    # Wall-clock unix seconds when the accepted attestation doc
    # expires. Stored so the gate can re-check freshness on every
    # dispatched message — without this, an attacker who succeeds
    # ONCE within the 30s window can ride that "attested" state
    # indefinitely (audit H7 May 2026).
    attestation_deadline_unix: Optional[int] = None
    # Per-peer rate-limit state for expensive control-DC frames
    # (audit H9 May 2026: attest_challenge invokes the hybrid
    # signing path which holds a process-wide GIL/native lock; an
    # unauthenticated peer flooding challenges can stall every
    # legitimate sign). Tracks (window_start_sec, count_in_window).
    _attest_challenge_window_start: int = 0
    _attest_challenge_count: int = 0
    # H8 May 2026: cover_packet handler runs Sphinx peel (~100µs
    # per packet); flood-protect on the same model.
    _cover_packet_window_start: int = 0
    _cover_packet_count: int = 0
    # Dispatch tasks are owned by the live authority.  Revocation closes the
    # channels and cancels any request handlers that yielded before finishing,
    # preventing a previously-authorized phone from completing queued work
    # after its Guardian epoch changed.
    _dispatch_tasks: set[asyncio.Task[Any]] = field(
        default_factory=set,
        repr=False,
    )
    # Row 6/7 — peer's Sphinx onion public key (Ristretto255 32-byte
    # compressed point). Each peer publishes theirs on DC-open via
    # the `onion_pubkey` envelope; we record the other side's so
    # cover-traffic emission can build real Sphinx packets bound
    # for them (instead of looping back to self).
    onion_pubkey: Optional[bytes] = None
    onion_pubkey_received_ms: Optional[int] = None
    # Audit L7 May 2026: timestamp (unix seconds) of the last
    # protocol-skew log we emitted for this peer. Rate-limits log
    # spam if a peer floods bad-version frames.
    _last_protocol_skew_log_s: int = 0


# ── manager ──────────────────────────────────────────────────────────


class BrowserPeerManager:
    """Single-process registry of active browser-as-peer connections
    + the pairing-token store. Wraps aiortc imports lazily so a daemon
    that doesn't ship aiortc still imports `peer_rtc` for the constants
    + helpers."""

    def __init__(self, daemon: Any):
        self.daemon = daemon
        self._peers: dict[str, BrowserPeer] = {}    # fingerprint → BrowserPeer
        self._pending_pairings: dict[str, PendingPair] = {}
        self._pairing_lock = threading.Lock()
        # A timestamp window alone does not make an envelope single-use: a
        # captured, correctly signed offer could otherwise be replayed for 60
        # seconds and replace a known peer's live connection. Cache a
        # domain-separated signature id after verification. Ordered eviction
        # bounds attacker-controlled memory, and the lock keeps check+insert
        # atomic under free-threaded Python or mixed API/event-loop callers.
        self._seen_offer_ids: OrderedDict[bytes, int] = OrderedDict()
        self._offer_replay_lock = threading.Lock()
        self._dc_listeners: list[
            Callable[[BrowserPeer, str, str, dict], Awaitable[None]]
        ] = []
        # Browser authority comes exclusively from the persistent self-mesh
        # roster.  The former process-local `_paired_pubkeys` set survived a
        # device revoke until daemon restart and therefore acted as an
        # unrevocable owner credential.  No parallel authority cache exists.
        self._consumed_identity_challenges: OrderedDict[str, int] = OrderedDict()
        self._identity_replay_lock = threading.Lock()
        # Certificate signatures are immutable and comparatively expensive to
        # re-verify on every high-rate DataChannel frame. Cache only the
        # cryptographic certificate binding; trust/revoke/safety/Guardian epoch
        # still come from SQLite on every authorization check, so this cache is
        # never an authority cache and cannot delay revocation.
        self._verified_device_cert_cache: OrderedDict[
            bytes, tuple[bytes, bytes, str, int]
        ] = OrderedDict()
        self._device_cert_cache_lock = threading.Lock()
        # Audit C1 defense-in-depth: track the DTLS-SRTP fingerprint
        # extracted from each peer's most-recent SDP offer. The
        # envelope signature already binds the SDP to the peer's
        # Ed25519 pubkey, so any silent change here would itself
        # carry the same Ed25519 sig. The check is belt-and-suspenders
        # — log + record on first observation; warn (but don't refuse)
        # on subsequent changes since legitimate cert rotations DO
        # happen on browser restart. Hard rejection lives upstream
        # at the envelope-signature + pubkey-roster gates.
        self._dtls_fingerprints: dict[str, str] = {}
        # Audit I4 May 2026 — explicit replay cache for accepted
        # attestation docs. Keyed by BLAKE3(master_sig) — collisions
        # are vanishingly unlikely (2^-256). Each entry stores the
        # acceptance wall-clock-ms so the cache self-prunes against
        # ``ATTESTATION_REPLAY_CACHE_TTL_MS``. Without this, the sole
        # defense against in-flight replay was the per-peer
        # `attestation_challenge = None` clear (peer_rtc.py:807) —
        # if a future refactor forgot that line, the 30-second
        # challenge window would re-open silently. The cache is
        # belt-and-suspenders.
        self._seen_doc_ids: "dict[bytes, int]" = {}
        # Audit I6 May 2026 — per-master-vk monotonic-issued-unix
        # fork detection. A legitimate single-daemon issuer's docs
        # produce non-decreasing `issued_unix` (modulo small clock
        # skew). Two daemons claiming the same master_vk (a fork or
        # cloned identity) will eventually produce a doc with an
        # `issued_unix` that regresses below what we've already
        # observed for that vk. Rejecting on regression detects
        # forks without a wire-format change. Tolerates up to
        # MAX_CLOCK_SKEW_SECS (5s, matches the I3 issuer-skew
        # bound) of natural NTP wobble before flagging.
        #
        # External audit 2026-05-18 ES-44: persisted to disk so the
        # check survives daemon restart. Without persistence, an
        # attacker with the stolen SDP signing key could wait out a
        # daemon restart and present an earlier-issued doc.
        self._master_vk_last_issued_unix: "dict[bytes, int]" = (
            self._load_master_vk_hwm()
        )

    # Audit I4 May 2026 — replay-cache TTL (ms). Comfortably exceeds
    # the 30s ATTESTATION_FRESHNESS_WINDOW_SECS so the cache strictly
    # outlives the validity window of any doc it remembers.
    ATTESTATION_REPLAY_CACHE_TTL_MS: int = 5 * 60 * 1000
    # Hard cap on cache size — flood-defense companion to the TTL
    # sweep. Drops oldest-first when exceeded.
    ATTESTATION_REPLAY_CACHE_MAX_ENTRIES: int = 16_384
    MASTER_VK_HWM_MAX_ENTRIES: int = 2_048
    MASTER_VK_HWM_MAX_BYTES: int = 12 * 1024 * 1024
    MASTER_VK_BYTES: int = 1_984
    # Audit I6 May 2026 — tolerance for natural NTP wobble in the
    # monotonic-issued-unix fork-detection check. Matches the I3
    # issuer-clock-skew bound exactly so the two checks share a
    # consistent tolerance.
    ATTESTATION_FORK_MAX_BACKWARDS_SECS: int = 5

    def _attestation_doc_id(self, master_sig: bytes) -> bytes:
        """Audit I4 — SHA-256 over a domain-tagged copy of
        ``master_sig``. Used purely as an internal map key; the
        security property is collision-resistance (so distinct sigs
        can't collide) + preimage-resistance (so cache contents
        don't directly leak sigs). SHA-256 is stdlib so the cache
        works even when the native module is absent."""
        import hashlib
        return hashlib.sha256(
            b"ol-attest-replay-cache-v1" + master_sig
        ).digest()

    def _attestation_replay_check_and_record(self, master_sig: bytes) -> bool:
        """Returns True iff this doc has NOT been seen before.

        Side-effect: on a fresh doc, records the id with the current
        wall-clock; on a repeat, leaves the cache untouched. Sweeps
        expired entries opportunistically (no background timer)."""
        doc_id = self._attestation_doc_id(master_sig)
        now_ms = _now_ms()
        # Sweep expired entries first (bounded work: at most one
        # full traversal every ATTESTATION_REPLAY_CACHE_TTL_MS).
        if self._seen_doc_ids:
            cutoff = now_ms - self.ATTESTATION_REPLAY_CACHE_TTL_MS
            dead = [k for k, t in self._seen_doc_ids.items() if t < cutoff]
            for k in dead:
                self._seen_doc_ids.pop(k, None)
        if doc_id in self._seen_doc_ids:
            return False
        # Bound the cache size with oldest-first eviction (matches
        # the M11 OrderedDict pattern in cap_store; here we use a
        # plain dict ordered by insertion since Python 3.7+ preserves
        # it).
        if len(self._seen_doc_ids) >= self.ATTESTATION_REPLAY_CACHE_MAX_ENTRIES:
            drop_n = self.ATTESTATION_REPLAY_CACHE_MAX_ENTRIES // 10
            for k in list(self._seen_doc_ids.keys())[:drop_n]:
                self._seen_doc_ids.pop(k, None)
        self._seen_doc_ids[doc_id] = now_ms
        return True

    # ── pairing tokens ──────────────────────────────────────────────

    def _authorization_row_is_live(self, row: object) -> bool:
        if not isinstance(row, dict):
            return False
        if bool(row.get("revoked")) or not bool(row.get("trusted")):
            return False
        if str(row.get("safety_state") or "trusted") != "trusted":
            return False
        root_pub = row.get("root_pub")
        device_pub = row.get("device_pub")
        cert = row.get("cert")
        if (
            not isinstance(root_pub, (bytes, bytearray, memoryview))
            or len(bytes(root_pub)) != 32
            or not isinstance(device_pub, (bytes, bytearray, memoryview))
            or len(bytes(device_pub)) != 32
            or not isinstance(cert, (bytes, bytearray, memoryview))
            or not bytes(cert)
        ):
            return False
        root_bytes = bytes(root_pub)
        device_bytes = bytes(device_pub)
        cert_bytes = bytes(cert)
        device_kind = str(row.get("device_kind") or "")
        cache_id = hashlib.sha256(
            b"OL/browser-auth-device-cert-cache/v1\0" + cert_bytes
        ).digest()
        now_ms = _now_ms()
        with self._device_cert_cache_lock:
            cached = self._verified_device_cert_cache.get(cache_id)
            if cached is not None:
                cached_root, cached_device, cached_kind, expires_ms = cached
                if expires_ms == 0 or now_ms <= expires_ms:
                    self._verified_device_cert_cache.move_to_end(cache_id)
                    return (
                        secrets.compare_digest(cached_root, root_bytes)
                        and secrets.compare_digest(cached_device, device_bytes)
                        and cached_kind == device_kind
                    )
                self._verified_device_cert_cache.pop(cache_id, None)
        try:
            from one_link.identity_dag import verify_device_cert

            parsed = verify_device_cert(
                cert_bytes,
                expected_root_pub=root_bytes,
                now_ms=now_ms,
            )
        except (TypeError, ValueError):
            return False
        valid = (
            parsed is not None
            and secrets.compare_digest(parsed.device_pub, device_bytes)
            and parsed.device_kind == device_kind
        )
        if not valid:
            return False
        with self._device_cert_cache_lock:
            self._verified_device_cert_cache[cache_id] = (
                root_bytes,
                device_bytes,
                device_kind,
                int(parsed.expires_ms),
            )
            self._verified_device_cert_cache.move_to_end(cache_id)
            while (
                len(self._verified_device_cert_cache)
                > BROWSER_AUTH_CERT_CACHE_MAX_ENTRIES
            ):
                self._verified_device_cert_cache.popitem(last=False)
        return True

    def authorization_for_pubkey(self, device_pub: bytes) -> Optional[dict[str, Any]]:
        """Resolve one live owner-device authorization from persistent state.

        This is intentionally a state read, not a process-local cache: revoke,
        delete, freeze, quarantine, and maybe-lost transitions must take effect
        without restarting the daemon.
        """

        try:
            device_pub = bytes(device_pub)
        except (TypeError, ValueError):
            return None
        if len(device_pub) != 32:
            return None
        state = getattr(self.daemon, "state", None)
        if state is None:
            return None
        try:
            rows = state.list_self_mesh_devices(include_revoked=True)
        except Exception as exc:
            log.warning("peer-rtc: browser authorization lookup failed: %s", exc)
            return None
        matches: list[dict[str, Any]] = []
        for row in rows:
            candidate = row.get("device_pub") if isinstance(row, dict) else None
            if not isinstance(candidate, (bytes, bytearray, memoryview)):
                continue
            candidate_bytes = bytes(candidate)
            if len(candidate_bytes) != 32 or not secrets.compare_digest(
                candidate_bytes, device_pub,
            ):
                continue
            if self._authorization_row_is_live(row):
                matches.append(dict(row))
        # A key enrolled under two live roots is an ambiguous principal.  It
        # must be repaired in the roster rather than letting database ordering
        # choose which root owns a browser session or bearer.
        if len(matches) != 1:
            if len(matches) > 1:
                log.warning(
                    "peer-rtc: refusing ambiguous browser key enrolled under "
                    "%d live roots",
                    len(matches),
                )
            return None
        return matches[0]

    def peer_authorization_is_live(self, peer: BrowserPeer) -> bool:
        root_pub = peer.authorized_root_pub
        device_pub = peer.authorized_device_pub
        state = getattr(self.daemon, "state", None)
        if state is None or root_pub is None or device_pub is None:
            return False
        try:
            peer_pub = bytes(peer.pubkey_bytes)
            bound_device_pub = bytes(device_pub)
            bound_root_pub = bytes(root_pub)
            expected_fingerprint = _fingerprint_for_device_pub(peer_pub)
        except (TypeError, ValueError):
            return False
        canonical_fingerprint = _canonical_sha256_fingerprint(peer.fingerprint)
        if (
            len(bound_root_pub) != 32
            or len(bound_device_pub) != 32
            or canonical_fingerprint is None
            or not secrets.compare_digest(bound_device_pub, peer_pub)
            or not secrets.compare_digest(
                canonical_fingerprint, expected_fingerprint,
            )
        ):
            return False
        try:
            row = state.get_self_mesh_device(
                root_pub=bound_root_pub,
                device_pub=bound_device_pub,
            )
        except Exception as exc:
            log.warning("peer-rtc: live browser authorization check failed: %s", exc)
            return False
        if not self._authorization_row_is_live(row):
            return False
        return int(row.get("guardian_epoch") or 0) == int(
            peer.authorized_guardian_epoch
        )

    def mint_pairing_token(
        self,
        *,
        device_pub: bytes,
        fp_hint: Optional[str] = None,
    ) -> PendingPair:
        """Mint a single-use token for one already-authorized roster device.

        The setup ceremony persists a signed device certificate before this
        handoff is minted.  Generic callers must supply the same enrolled
        public key; an unbound bearer token is never an owner credential.
        """

        device_pub = bytes(device_pub)
        expected_fp = _fingerprint_for_device_pub(device_pub)
        if fp_hint is not None:
            canonical_hint = _canonical_sha256_fingerprint(fp_hint)
            if canonical_hint is None or not secrets.compare_digest(
                canonical_hint, expected_fp,
            ):
                raise ValueError("fp_hint must match the enrolled device public key")
        authorization = self.authorization_for_pubkey(device_pub)
        if authorization is None:
            raise PermissionError("browser device is not currently authorized")
        root_pub = bytes(authorization["root_pub"])
        token = _b64u(secrets.token_bytes(PAIRING_TOKEN_BYTES))
        pp = PendingPair(
            token=token,
            created_ms=_now_ms(),
            fp_hint=expected_fp,
            root_pub=root_pub,
            device_pub=device_pub,
            guardian_epoch=int(authorization.get("guardian_epoch") or 0),
        )
        with self._pairing_lock:
            # Sweep expired tokens opportunistically — keeps memory bounded
            # without a background sweeper task.
            self._sweep_expired_pairings_locked(_now_ms())
            self._pending_pairings[token] = pp
            if len(self._pending_pairings) > MAX_PENDING_PAIRING_TOKENS:
                oldest = sorted(
                    self._pending_pairings.items(),
                    key=lambda item: item[1].created_ms,
                )
                overflow = len(self._pending_pairings) - MAX_PENDING_PAIRING_TOKENS
                for old_token, _old in oldest[:overflow]:
                    self._pending_pairings.pop(old_token, None)
        log.info("peer-rtc: minted pairing token (ttl=%dms)", pp.ttl_ms)
        return pp

    def _sweep_expired_pairings_locked(self, now: int) -> int:
        expired = [t for t, pp in self._pending_pairings.items() if pp.expired(now)]
        for token in expired:
            self._pending_pairings.pop(token, None)
        return len(expired)

    def _sweep_expired_pairings(self) -> int:
        with self._pairing_lock:
            return self._sweep_expired_pairings_locked(_now_ms())

    def redeem_pairing_token(
        self,
        token: object,
        *,
        fingerprint: str | None = None,
    ) -> Optional[PendingPair]:
        """Try to redeem a pairing token. Returns the PendingPair on
        success (consuming it) or None if missing, expired, or bound to a
        different browser key.

        A fingerprint mismatch deliberately does *not* consume a bound token.
        Someone who learns the bearer but does not hold the certified device
        key must not be able to burn the legitimate device's handoff.
        """
        if (
            not isinstance(token, str)
            or len(token) != 43
            or any(
                char not in (
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"
                    "0123456789-_"
                )
                for char in token
            )
        ):
            return None
        with self._pairing_lock:
            pp = self._pending_pairings.get(token)
            if pp is None:
                return None
            if pp.expired():
                self._pending_pairings.pop(token, None)
                return None
            canonical_fp = _canonical_sha256_fingerprint(fingerprint)
            if (
                pp.fp_hint is None
                or pp.device_pub is None
                or pp.root_pub is None
                or canonical_fp is None
                or not secrets.compare_digest(pp.fp_hint, canonical_fp)
            ):
                return None
            authorization = self.authorization_for_pubkey(pp.device_pub)
            if (
                authorization is None
                or not secrets.compare_digest(
                    bytes(authorization["root_pub"]), bytes(pp.root_pub)
                )
                or int(authorization.get("guardian_epoch") or 0)
                != int(pp.guardian_epoch)
            ):
                # An authority transition invalidates every outstanding bearer.
                self._pending_pairings.pop(token, None)
                return None
            self._pending_pairings.pop(token, None)
            return pp

    # ── peer registry ───────────────────────────────────────────────

    def register_peer(self, peer: BrowserPeer) -> None:
        if peer.closed:
            raise PermissionError("cannot register a closed browser peer")
        if not self.peer_authorization_is_live(peer):
            raise PermissionError("browser peer is not currently authorized")
        existing = self._peers.get(peer.fingerprint)
        if existing is not None and existing is not peer:
            # Newest connection wins. Tear down the old one.
            log.info(
                "peer-rtc: replacing existing connection for %s",
                peer.fingerprint,
            )
            self._close_peer(existing)
        self._peers[peer.fingerprint] = peer

    def is_paired(self, fingerprint: str, *, pubkey_bytes: bytes) -> bool:
        expected = _fingerprint_for_device_pub(bytes(pubkey_bytes))
        canonical = _canonical_sha256_fingerprint(fingerprint)
        return (
            canonical is not None
            and secrets.compare_digest(canonical, expected)
            and self.authorization_for_pubkey(bytes(pubkey_bytes)) is not None
        )

    def revoke_device(self, *, root_pub: bytes, device_pub: bytes) -> dict[str, int]:
        """Invalidate pending handoffs and evict the live device immediately."""

        root_pub = bytes(root_pub)
        device_pub = bytes(device_pub)
        if len(root_pub) != 32 or len(device_pub) != 32:
            raise ValueError("root_pub and device_pub must be exactly 32 bytes")
        fingerprint = _fingerprint_for_device_pub(device_pub)
        invalidated = 0
        with self._pairing_lock:
            for token, pending in list(self._pending_pairings.items()):
                if (
                    pending.device_pub is not None
                    and pending.root_pub is not None
                    and secrets.compare_digest(bytes(pending.device_pub), device_pub)
                    and secrets.compare_digest(bytes(pending.root_pub), root_pub)
                ):
                    self._pending_pairings.pop(token, None)
                    invalidated += 1
        peer = self._peers.get(fingerprint)
        evicted = 0
        if (
            peer is not None
            and peer.authorized_root_pub is not None
            and peer.authorized_device_pub is not None
            and secrets.compare_digest(bytes(peer.authorized_root_pub), root_pub)
            and secrets.compare_digest(bytes(peer.authorized_device_pub), device_pub)
        ):
            self._close_peer(peer)
            evicted = 1
        return {"pending_tokens": invalidated, "active_peers": evicted}

    def get_peer(self, fingerprint: str) -> Optional[BrowserPeer]:
        return self._peers.get(fingerprint)

    def list_peers(self) -> list[BrowserPeer]:
        return list(self._peers.values())

    # External audit 2026-05-18 ES-44: load + persist the master-VK
    # high-water marks across daemon restarts. JSON file in data_dir
    # because it's small (peer count × ~80 bytes) and we don't need
    # transactional updates. Atomic write via temp + rename so a
    # crash mid-write doesn't truncate.
    def _master_vk_hwm_path(self):
        from one_link.paths import data_dir
        return data_dir() / "peer_rtc_master_vk_hwm.json"
    def _load_master_vk_hwm(self) -> "dict[bytes, int]":
        try:
            p = self._master_vk_hwm_path()
            if not p.exists():
                return {}
            if p.stat().st_size > self.MASTER_VK_HWM_MAX_BYTES:
                raise ValueError("master-vk HWM file exceeds size limit")
            raw = p.read_text(encoding="utf-8")
            data = json.loads(raw)
            out: dict[bytes, int] = {}
            if isinstance(data, dict):
                for hex_key, ts in data.items():
                    if len(out) >= self.MASTER_VK_HWM_MAX_ENTRIES:
                        break
                    if (
                        not isinstance(hex_key, str)
                        or len(hex_key) != self.MASTER_VK_BYTES * 2
                        or any(ch not in "0123456789abcdef" for ch in hex_key)
                        or not isinstance(ts, int)
                        or isinstance(ts, bool)
                        or not 0 <= ts <= _MAX_TIMESTAMP_MS
                    ):
                        continue
                    try:
                        key = bytes.fromhex(hex_key)
                    except ValueError:
                        continue
                    if len(key) == self.MASTER_VK_BYTES:
                        out[key] = ts
            return out
        except (OSError, json.JSONDecodeError, ValueError) as e:
            log.warning(
                "peer-rtc: failed to load master-vk HWM (%s); fork detection "
                "for known peers will start fresh until next attestation",
                e,
            )
            return {}
    def _persist_master_vk_hwm(self, master_vk: bytes, issued_unix: int) -> None:
        try:
            if (
                not isinstance(master_vk, bytes)
                or len(master_vk) != self.MASTER_VK_BYTES
                or not isinstance(issued_unix, int)
                or isinstance(issued_unix, bool)
                or not 0 <= issued_unix <= _MAX_TIMESTAMP_MS
            ):
                raise ValueError("invalid master-vk HWM entry")
            p = self._master_vk_hwm_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            data = {
                vk.hex(): ts for vk, ts in self._master_vk_last_issued_unix.items()
            }
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
            os.replace(tmp, p)
        except (OSError, ValueError) as e:
            log.warning(
                "peer-rtc: failed to persist master-vk HWM (%s); fork "
                "detection across restart may regress for this master_vk",
                e,
            )

    def _close_peer(self, peer: BrowserPeer) -> None:
        if peer.closed:
            return
        peer.closed = True
        current_task: asyncio.Task[Any] | None = None
        with contextlib.suppress(RuntimeError):
            current_task = asyncio.current_task()
        if peer.identity_timeout_handle is not None:
            peer.identity_timeout_handle.cancel()
            peer.identity_timeout_handle = None
        for dispatch_task in tuple(peer._dispatch_tasks):
            if dispatch_task is not current_task and not dispatch_task.done():
                dispatch_task.cancel()
        # Stop application authority synchronously. aiortc's PC close is
        # asynchronous, but DataChannel.close() marks each channel closing
        # immediately; dispatch also refuses every frame after `closed` flips.
        for dc in (peer.control_dc, peer.bulk_dc):
            if dc is not None:
                with contextlib.suppress(Exception):
                    dc.close()
        pc = peer.pc
        if pc is not None:
            try:
                # aiortc's pc.close is async; schedule it.
                # 2026-05-22 audit Batch Y: track close tasks in
                # ``self._pc_close_tasks`` so ``shutdown()`` can await
                # them with a bounded timeout. Without tracking, the
                # daemon-shutdown cancellation can interrupt aiortc
                # mid-ICE-teardown; any attached MediaStream tracks
                # then leak their underlying socket handles + worker
                # threads (visible on call paths).
                loop = asyncio.get_event_loop()
                if not hasattr(self, "_pc_close_tasks"):
                    self._pc_close_tasks: set[asyncio.Task] = set()
                close_task = loop.create_task(pc.close())
                self._pc_close_tasks.add(close_task)
                close_task.add_done_callback(self._pc_close_tasks.discard)
            except Exception as e:
                log.debug("peer-rtc: pc.close error for %s: %s", peer.fingerprint, e)
        # A staged connection can fail while an older, healthy connection for
        # the same enrolled key remains authoritative. Teardown of that
        # unregistered object (or a delayed callback from a replaced PC) must
        # never evict the registry's different live object.
        if self._peers.get(peer.fingerprint) is peer:
            self._peers.pop(peer.fingerprint, None)

    # ── DataChannel listener registry ──────────────────────────────

    def add_dc_listener(
        self,
        cb: Callable[[BrowserPeer, str, str, dict], Awaitable[None]],
    ) -> None:
        """Register a callback invoked when a DataChannel message
        arrives from any browser peer. Signature:
            cb(peer, channel_kind, msg_t, payload_dict)
        Channel kind is "control" or "bulk". Payload is the parsed
        JSON envelope minus the version + type."""
        self._dc_listeners.append(cb)

    # ── Gate helpers (audit H7/H8/H9 May 2026) ─────────────────────

    def _requires_browser_identity_possession(self) -> bool:
        return bool(
            getattr(self.daemon, "require_browser_identity_possession", False)
            or getattr(self.daemon, "require_attested_peers", False)
        )

    def _gate_app_or_attested(
        self, peer: BrowserPeer, msg_t: str
    ) -> bool:
        """Gate browser app traffic on channel-bound key possession.

        The legacy method name remains for compatibility. This is explicitly
        not hardware or platform attestation: the browser proves possession of
        its enrolled Ed25519 device key on this exact DataChannel. The older
        hybrid-attestation state is still expired below for optional native
        experiments, but does not satisfy browser owner authorization.
        """
        # H7 — even when require_attested_peers is OFF, expire stale
        # attestation state so onion/cover-packet handlers don't
        # ride a long-dead doc.
        now_unix = int(time.time())
        dl = peer.attestation_deadline_unix
        if peer.attested_ms is not None and dl is not None and now_unix > dl:
            log.info(
                "peer-rtc: attestation for %s expired (deadline=%d, "
                "now=%d); clearing attested state",
                peer.fingerprint, dl, now_unix,
            )
            peer.attested_ms = None
            peer.attestation_deadline_unix = None
            # peer_master_vk stays pinned (audit C2 TOFU); a
            # re-attestation must match it.
        if self._requires_browser_identity_possession():
            control_dc_id = id(peer.control_dc) if peer.control_dc is not None else None
            identity_verified = (
                peer.identity_verified_ms is not None
                and peer.identity_verified_dc_id is not None
                and peer.identity_verified_dc_id == control_dc_id
            )
            if not identity_verified:
                # Audit L8 May 2026: take the daemon's telemetry
                # lock to serialize the read-modify-write across
                # asyncio + cover background thread.
                lock = getattr(self.daemon, "_telemetry_lock", None)
                if lock is not None:
                    with lock:
                        cnt = getattr(self.daemon, "_gate_drop_count", 0)
                        try:
                            self.daemon._gate_drop_count = cnt + 1
                        except Exception as exc:
                            report_best_effort_failure(
                                log,
                                "rtc_gate_drop_counter_locked",
                                exc,
                                level=logging.DEBUG,
                            )
                else:
                    cnt = getattr(self.daemon, "_gate_drop_count", 0)
                    try:
                        self.daemon._gate_drop_count = cnt + 1
                    except Exception as exc:
                        report_best_effort_failure(
                            log,
                            "rtc_gate_drop_counter",
                            exc,
                            level=logging.DEBUG,
                        )
                log.info(
                    "peer-rtc: dropped %r from browser peer %s without "
                    "channel-bound identity possession (required, drops=%d)",
                    msg_t, peer.fingerprint,
                    getattr(self.daemon, "_gate_drop_count", 0),
                )
                return False
        return True

    def _allow_attest_challenge(self, peer: BrowserPeer) -> bool:
        """H9 May 2026: per-peer rate-limit on attest_challenge so a
        flood can't pin the native signing lock."""
        now = int(time.time())
        if now - peer._attest_challenge_window_start >= ATTEST_CHALLENGE_WINDOW_SECS:
            peer._attest_challenge_window_start = now
            peer._attest_challenge_count = 0
        peer._attest_challenge_count += 1
        return peer._attest_challenge_count <= ATTEST_CHALLENGE_MAX_PER_WINDOW

    def _allow_cover_packet(self, peer: BrowserPeer) -> bool:
        """H8 May 2026: per-peer rate-limit on cover_packet so a
        flood can't saturate Sphinx-peel CPU."""
        now = int(time.time())
        if now - peer._cover_packet_window_start >= COVER_PACKET_WINDOW_SECS:
            peer._cover_packet_window_start = now
            peer._cover_packet_count = 0
        peer._cover_packet_count += 1
        return peer._cover_packet_count <= COVER_PACKET_MAX_PER_WINDOW

    async def _dispatch_dc(
        self, peer: BrowserPeer, channel_kind: str, raw: Any
    ) -> None:
        if peer.closed:
            return
        if not self.peer_authorization_is_live(peer):
            log.warning(
                "peer-rtc: evicting browser peer %s after authority loss",
                peer.fingerprint,
            )
            self._close_peer(peer)
            return
        try:
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            if isinstance(raw, str) and len(raw.encode("utf-8", errors="ignore")) > MAX_DC_TEXT_BYTES:
                log.warning("peer-rtc: oversized DC frame from %s", peer.fingerprint)
                return
            envelope = json.loads(raw) if isinstance(raw, str) else None
        except Exception as e:
            log.debug("peer-rtc: bad DC frame from %s: %s", peer.fingerprint, e)
            return
        if not isinstance(envelope, dict):
            return
        wire_v = envelope.get("v")
        if wire_v != PEER_DC_PROTOCOL_VERSION:
            # Audit L7 May 2026: surface protocol-skew rather than
            # silently drop. A future-version peer (v=OL-PEER-2)
            # otherwise vanishes from the operator's view. Per-peer
            # rate-limited log so a hostile flood of bad-version
            # frames can't flood the log either.
            now = int(time.time())
            last = getattr(peer, "_last_protocol_skew_log_s", 0)
            if now - last >= 60:
                log.info(
                    "peer-rtc: dropping DC frame from %s with "
                    "unsupported protocol version %r (we speak %s); "
                    "peer may need an upgrade or downgrade",
                    peer.fingerprint, wire_v, PEER_DC_PROTOCOL_VERSION,
                )
                peer._last_protocol_skew_log_s = now
            return
        msg_t = str(envelope.get("t") or "")
        if not msg_t:
            return
        peer.last_activity_ms = _now_ms()
        if msg_t == "identity_possession_response":
            await self._handle_identity_possession_response(
                peer, channel_kind, envelope,
            )
            return
        # Built-in ping/pong. Always handled; tests for liveness.
        if msg_t == "ping":
            self.send_dc(peer, "control", {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "pong",
                "ts": _now_ms(),
                "echo_ts": envelope.get("ts"),
            })
            return
        # Row 10 — peer-handshake attestation.
        # The other side sends `attest_challenge` (their nonce); we
        # respond with `attest_response` (our doc bound to their
        # nonce). They send `attest_response` for OUR nonce; we
        # verify + mark them attested.
        #
        # H9 (audit May 2026): attest_challenge invokes the hybrid
        # signing path (Ed25519 + ML-DSA-65, ~1–5 ms wall) under a
        # process-wide native lock. An unauthenticated peer flooding
        # challenges stalls every legit signer in the daemon. Apply a
        # per-peer token bucket: ATTEST_CHALLENGE_MAX_PER_WINDOW per
        # ATTEST_CHALLENGE_WINDOW_SECS, drop the rest.
        if msg_t == "attest_challenge":
            if not self._allow_attest_challenge(peer):
                log.info(
                    "peer-rtc: rate-limited attest_challenge from %s",
                    peer.fingerprint,
                )
                return
            await self._handle_attest_challenge(peer, envelope)
            return
        if msg_t == "attest_response":
            await self._handle_attest_response(peer, envelope)
            return
        # H8 + H10 (audit May 2026): onion_pubkey + cover_packet are
        # NOT control-plane bootstrap — they are part of the running
        # mesh state. Require attestation before accepting either,
        # AND rate-limit cover_packet (Sphinx peel is ~100 µs/packet,
        # an unauthenticated flood saturates a core).
        if msg_t == "onion_pubkey":
            if not self._gate_app_or_attested(peer, msg_t):
                return
            await self._handle_onion_pubkey(peer, envelope)
            return
        if msg_t == "cover_packet":
            if not self._gate_app_or_attested(peer, msg_t):
                return
            if not self._allow_cover_packet(peer):
                log.info(
                    "peer-rtc: rate-limited cover_packet from %s",
                    peer.fingerprint,
                )
                return
            await self._handle_cover_packet(peer, envelope)
            return
        # Browser owner gate. In strict mode, app-layer messages from peers
        # that have not completed the channel-bound enrolled-key proof are
        # dropped. Ping and the optional native hybrid-attestation experiment
        # already returned above, so the gate sees only app traffic.
        if not self._gate_app_or_attested(peer, msg_t):
            return
        # Fan out to registered listeners (chat, files, etc. wire in
        # v0.20.2+).
        for cb in list(self._dc_listeners):
            try:
                await cb(peer, channel_kind, msg_t, envelope)
            except Exception as e:
                log.warning("peer-rtc: dc listener raised: %s", e)

    # ── Browser identity possession (not platform attestation) ──────

    def init_identity_possession(self, peer: BrowserPeer) -> bool:
        """Challenge the enrolled browser key on this exact control DC."""

        if peer.closed or not self.peer_authorization_is_live(peer):
            return False
        if peer.control_dc is None:
            return False
        now = _now_ms()
        challenge = {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "identity_possession_challenge",
            "schema": BROWSER_IDENTITY_POSSESSION_SCHEMA,
            "challenge_id": _b64u(
                secrets.token_bytes(BROWSER_IDENTITY_CHALLENGE_ID_BYTES)
            ),
            "nonce": _b64u(
                secrets.token_bytes(BROWSER_IDENTITY_CHALLENGE_BYTES)
            ),
            "session_id": peer.identity_session_id,
            "peer_fingerprint": peer.fingerprint,
            "daemon_fingerprint": str(self.daemon.me.wire_fingerprint),
            "issued_ms": now,
            "expires_ms": now + BROWSER_IDENTITY_CHALLENGE_TTL_MS,
        }
        # Self-check the encoder at the trust boundary. A future accidental
        # field addition cannot silently split browser/server canonicalization.
        _identity_possession_signing_bytes(challenge)
        control_dc_id = id(peer.control_dc)
        peer.identity_challenge = challenge
        peer.identity_challenge_dc_id = control_dc_id
        peer.identity_verified_ms = None
        peer.identity_verified_dc_id = None
        if peer.identity_timeout_handle is not None:
            peer.identity_timeout_handle.cancel()
            peer.identity_timeout_handle = None
        if self.send_dc(peer, "control", challenge):
            if self._requires_browser_identity_possession():
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    # Strict mode without a running lifecycle loop cannot
                    # enforce expiry, so fail closed instead of leaving an
                    # unverified connection resident forever.
                    peer.identity_challenge = None
                    peer.identity_challenge_dc_id = None
                    self._close_peer(peer)
                    return False
                peer.identity_timeout_handle = loop.call_later(
                    BROWSER_IDENTITY_CHALLENGE_TTL_MS / 1000,
                    self._expire_identity_challenge,
                    peer,
                    str(challenge["challenge_id"]),
                    control_dc_id,
                )
            return True
        peer.identity_challenge = None
        peer.identity_challenge_dc_id = None
        return False

    def _expire_identity_challenge(
        self,
        peer: BrowserPeer,
        challenge_id: str,
        control_dc_id: int,
    ) -> None:
        """Evict a strict-mode peer that never completed its live proof."""

        peer.identity_timeout_handle = None
        challenge = peer.identity_challenge
        if (
            peer.closed
            or peer.identity_verified_ms is not None
            or challenge is None
            or challenge.get("challenge_id") != challenge_id
            or peer.identity_challenge_dc_id != control_dc_id
            or peer.control_dc is None
            or id(peer.control_dc) != control_dc_id
        ):
            return
        log.warning(
            "peer-rtc: browser identity-possession proof timed out for %s",
            peer.fingerprint,
        )
        peer.identity_challenge = None
        peer.identity_challenge_dc_id = None
        self._close_peer(peer)

    def _identity_challenge_replayed(self, challenge_id: str, *, record: bool) -> bool:
        now = _now_ms()
        cutoff = now - BROWSER_IDENTITY_REPLAY_CACHE_TTL_MS
        with self._identity_replay_lock:
            while self._consumed_identity_challenges:
                _old_id, old_ms = next(
                    iter(self._consumed_identity_challenges.items())
                )
                if old_ms >= cutoff:
                    break
                self._consumed_identity_challenges.popitem(last=False)
            if challenge_id in self._consumed_identity_challenges:
                return True
            if record:
                while (
                    len(self._consumed_identity_challenges)
                    >= BROWSER_IDENTITY_REPLAY_CACHE_MAX_ENTRIES
                ):
                    self._consumed_identity_challenges.popitem(last=False)
                self._consumed_identity_challenges[challenge_id] = now
        return False

    async def _handle_identity_possession_response(
        self,
        peer: BrowserPeer,
        channel_kind: str,
        envelope: dict[str, Any],
    ) -> None:
        """Verify one exact, fresh, session-bound browser key proof."""

        try:
            if channel_kind != "control":
                raise ValueError("identity response must use the control channel")
            if set(envelope) != _BROWSER_IDENTITY_RESPONSE_FIELDS:
                raise ValueError("identity response fields are invalid")
            if (
                envelope.get("v") != PEER_DC_PROTOCOL_VERSION
                or envelope.get("t") != "identity_possession_response"
                or envelope.get("schema") != BROWSER_IDENTITY_POSSESSION_SCHEMA
            ):
                raise ValueError("identity response protocol is invalid")
            challenge_id = envelope.get("challenge_id")
            session_id = envelope.get("session_id")
            fingerprint = _canonical_sha256_fingerprint(
                envelope.get("peer_fingerprint")
            )
            if not isinstance(challenge_id, str):
                raise ValueError("identity challenge id is invalid")
            _b64ud(
                challenge_id,
                expected_size=BROWSER_IDENTITY_CHALLENGE_ID_BYTES,
            )
            if not isinstance(session_id, str):
                raise ValueError("identity session id is invalid")
            _b64ud(
                session_id,
                expected_size=BROWSER_IDENTITY_SESSION_ID_BYTES,
            )
            signature_text = envelope.get("signature")
            if not isinstance(signature_text, str):
                raise ValueError("identity signature is invalid")
            signature = _b64ud(signature_text, expected_size=64)
            challenge = peer.identity_challenge
            if challenge is None:
                raise ValueError("no identity challenge is active")
            if (
                peer.identity_challenge_dc_id is None
                or peer.control_dc is None
                or peer.identity_challenge_dc_id != id(peer.control_dc)
            ):
                raise ValueError("identity challenge belongs to another channel")
            if (
                challenge_id != challenge["challenge_id"]
                or session_id != challenge["session_id"]
                or session_id != peer.identity_session_id
                or fingerprint is None
                or not secrets.compare_digest(fingerprint, peer.fingerprint)
            ):
                raise ValueError("identity response binding does not match")
            now = _now_ms()
            issued_ms = challenge.get("issued_ms")
            expires_ms = challenge.get("expires_ms")
            if (
                not isinstance(issued_ms, int)
                or isinstance(issued_ms, bool)
                or not isinstance(expires_ms, int)
                or isinstance(expires_ms, bool)
                or expires_ms - issued_ms != BROWSER_IDENTITY_CHALLENGE_TTL_MS
                or now < issued_ms - BROWSER_IDENTITY_MAX_CLOCK_SKEW_MS
                or now >= expires_ms
            ):
                raise ValueError("identity challenge expired or malformed")
            if self._identity_challenge_replayed(challenge_id, record=False):
                raise ValueError("identity challenge was already consumed")
            Ed25519PublicKey.from_public_bytes(peer.pubkey_bytes).verify(
                signature,
                _identity_possession_signing_bytes(challenge),
            )
            if self._identity_challenge_replayed(challenge_id, record=True):
                raise ValueError("identity challenge was already consumed")
        except (InvalidSignature, ValueError, TypeError) as exc:
            log.warning(
                "peer-rtc: browser identity-possession proof rejected for %s: %s",
                peer.fingerprint,
                exc,
            )
            peer.identity_challenge = None
            peer.identity_challenge_dc_id = None
            self._close_peer(peer)
            return

        verified_ms = _now_ms()
        if peer.identity_timeout_handle is not None:
            peer.identity_timeout_handle.cancel()
            peer.identity_timeout_handle = None
        peer.identity_challenge = None
        peer.identity_challenge_dc_id = None
        peer.identity_verified_ms = verified_ms
        peer.identity_verified_dc_id = id(peer.control_dc)
        self.send_dc(peer, "control", {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "identity_possession_verified",
            "schema": BROWSER_IDENTITY_POSSESSION_SCHEMA,
            "challenge_id": challenge_id,
            "session_id": session_id,
            "verified_ms": verified_ms,
        })

    # ── Optional hybrid daemon attestation ───────────────────────────

    def init_attestation(self, peer: BrowserPeer) -> bool:
        """Generate a fresh challenge nonce + send it to the peer.
        Callers invoke this once the DC is open. Returns ``True`` if
        the challenge was sent, ``False`` if the daemon can't attest
        (no sealed master or native ext not built). Safe to call
        multiple times — overwrites the previous challenge so a
        stale one doesn't cause cross-flow confusion."""
        try:
            from one_link.handshake_attestation import fresh_challenge_for_peer
            import base64
        except ImportError:
            return False
        try:
            nonce = fresh_challenge_for_peer()
        except Exception as e:
            log.info("peer-rtc: init_attestation skipped (%s)", e)
            return False
        peer.attestation_challenge = nonce
        # Audit M9 May 2026: record which DC instance the challenge
        # was issued on so a response on a NEW DC (e.g. after
        # reconnect) is treated as cross-flow and rejected.
        peer.attestation_challenge_dc_id = (
            id(peer.control_dc) if peer.control_dc is not None else None
        )
        sent = self.send_dc(peer, "control", {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "attest_challenge",
            "ts": _now_ms(),
            "challenge_b64": base64.b64encode(nonce).decode("ascii"),
        })
        if not sent:
            # Do not leave a nonce that was never put on the wire. A later,
            # unrelated response could otherwise be compared against phantom
            # state while callers believe attestation successfully started.
            peer.attestation_challenge = None
            peer.attestation_challenge_dc_id = None
            log.warning(
                "peer-rtc: attestation challenge was not queued for %s",
                peer.fingerprint,
            )
            return False
        return True

    async def _handle_attest_challenge(
        self, peer: BrowserPeer, envelope: dict
    ) -> None:
        """Peer sent us their challenge; we respond with our doc
        bound to their nonce AND to our own SDP-layer Ed25519 pubkey
        (audit C1)."""
        try:
            from one_link.handshake_attestation import (
                AttestationWire,
                issue_for_challenge,
            )
        except ImportError:
            return
        sealed = getattr(self.daemon, "sealed_master", None)
        if sealed is None:
            log.info(
                "peer-rtc: attest_challenge from %s but no sealed_master; "
                "skipping response",
                peer.fingerprint,
            )
            return
        # Our SDP pubkey is the identity that signs the WebRTC offer/answer
        # envelope on this channel. Peer pins this against our channel ID.
        try:
            my_sdp_pubkey = bytes(self.daemon.me.public_bytes)
        except Exception:
            log.info(
                "peer-rtc: attest_challenge from %s but daemon.me.public_bytes "
                "unavailable; skipping response",
                peer.fingerprint,
            )
            return
        if len(my_sdp_pubkey) != 32:
            log.warning(
                "peer-rtc: attest_challenge from %s — our SDP pubkey is %d bytes "
                "(expected 32); cannot bind attestation",
                peer.fingerprint, len(my_sdp_pubkey),
            )
            return
        try:
            challenge = _b64std_exact(
                envelope.get("challenge_b64"),
                label="challenge_b64",
                expected_size=32,
            )
        except ValueError:
            return
        try:
            doc = issue_for_challenge(sealed, challenge, my_sdp_pubkey)
            wire = AttestationWire.from_doc(doc).to_wire_dict()
        except Exception as e:
            log.info("peer-rtc: issue attestation failed: %s", e)
            return
        if not self.send_dc(peer, "control", {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "attest_response",
            "ts": _now_ms(),
            "doc": wire,
        }):
            log.warning(
                "peer-rtc: attestation response was not queued for %s",
                peer.fingerprint,
            )

    async def _handle_attest_response(
        self, peer: BrowserPeer, envelope: dict
    ) -> None:
        """Peer sent us their attestation doc bound to OUR challenge
        and their SDP pubkey (audit C1). Verify and update peer state
        on success. TOFU-pins peer.peer_master_vk on first attest;
        rejects rotation on subsequent attests (audit C2)."""
        try:
            from one_link.handshake_attestation import (
                AttestationWire,
                verify_doc,
            )
        except ImportError:
            return
        challenge = peer.attestation_challenge
        if challenge is None:
            log.info(
                "peer-rtc: attest_response from %s without prior "
                "init_attestation; ignoring",
                peer.fingerprint,
            )
            return
        # Audit M9 May 2026: reject the response if the DC the
        # response arrived on is NOT the same DC instance the
        # challenge was issued on. Covers the reconnect race where
        # an old DC's response could be accepted on a fresh DC.
        challenge_dc_id = getattr(peer, "attestation_challenge_dc_id", None)
        current_dc_id = id(peer.control_dc) if peer.control_dc is not None else None
        if challenge_dc_id is not None and challenge_dc_id != current_dc_id:
            log.info(
                "peer-rtc: dropping attest_response from %s — challenge "
                "was issued on a different DC instance (reconnect race)",
                peer.fingerprint,
            )
            peer.attestation_challenge = None
            peer.attestation_challenge_dc_id = None
            return
        # The peer's SDP-layer pubkey is the identity that signed the
        # WebRTC offer envelope on this channel. The attestation doc
        # MUST commit to this pubkey.
        peer_sdp_pubkey = bytes(peer.pubkey_bytes)
        if len(peer_sdp_pubkey) != 32:
            log.warning(
                "peer-rtc: attest_response from %s — peer SDP pubkey is %d bytes "
                "(expected 32); rejecting",
                peer.fingerprint, len(peer_sdp_pubkey),
            )
            return
        wire_d = envelope.get("doc")
        if not isinstance(wire_d, dict):
            return
        try:
            wire = AttestationWire.from_wire_dict(wire_d)
            doc = wire.to_doc()
            verify_doc(doc, challenge, peer_sdp_pubkey)
        except Exception as e:
            log.warning(
                "peer-rtc: attestation from %s failed verify: %s",
                peer.fingerprint, e,
            )
            return
        # Audit I4 May 2026 — explicit replay-cache check. A doc that
        # already passed verify in the recent past is rejected here
        # before we update any peer state. The per-peer
        # `attestation_challenge = None` clear (below) still removes
        # the primary replay window; this is belt-and-suspenders so a
        # future refactor that drops that clear doesn't open a 30s
        # replay vector.
        if not self._attestation_replay_check_and_record(doc.master_sig):
            log.warning(
                "peer-rtc: attestation from %s rejected — doc replay "
                "(BLAKE3(master_sig) already seen in recent cache window)",
                peer.fingerprint,
            )
            return
        # Audit I6 May 2026 — per-master-vk fork detection. If we've
        # previously seen ANY doc from this master_vk (across any
        # peer fingerprint), require the new doc's `issued_unix` to
        # be NOT meaningfully earlier than the previous one. A
        # cloned-identity attacker on a second host that produces an
        # earlier-issued doc with the same master_vk gets caught
        # here. Tolerates ATTESTATION_FORK_MAX_BACKWARDS_SECS of
        # natural clock wobble before flagging.
        prev_issued_unix = self._master_vk_last_issued_unix.get(doc.master_vk)
        if (
            prev_issued_unix is not None
            and doc.issued_unix + self.ATTESTATION_FORK_MAX_BACKWARDS_SECS
            < prev_issued_unix
        ):
            log.warning(
                "peer-rtc: SECURITY ALERT — peer %s presented attestation "
                "with master_vk=%s and issued_unix=%d, but previously "
                "observed issued_unix=%d for the same master_vk. Possible "
                "fork / cloned identity. Refusing.",
                peer.fingerprint,
                doc.master_vk[:8].hex(),
                doc.issued_unix,
                prev_issued_unix,
            )
            with contextlib.suppress(Exception):
                self._close_peer(peer)
            return
        if (
            prev_issued_unix is None
            and len(self._master_vk_last_issued_unix) >= self.MASTER_VK_HWM_MAX_ENTRIES
        ):
            # Fork-detection state is security-relevant, so never evict an
            # older key silently to admit attacker-controlled cardinality.
            log.error(
                "peer-rtc: master-vk HWM capacity reached; refusing new "
                "attestation for %s",
                peer.fingerprint,
            )
            peer.attestation_challenge = None
            peer.attestation_challenge_dc_id = None
            with contextlib.suppress(Exception):
                self._close_peer(peer)
            return
        # Record the high-water-mark for this master_vk.
        self._master_vk_last_issued_unix[doc.master_vk] = max(
            prev_issued_unix if prev_issued_unix is not None else 0,
            doc.issued_unix,
        )
        # External audit 2026-05-18 ES-44: persist the HWM to disk so
        # the fork-detection check survives a daemon restart. The
        # previous in-memory-only behaviour let an attacker with the
        # stolen SDP signing key wait out a daemon restart, then
        # present an earlier-issued doc with the same master_vk and
        # bypass fork detection. Best-effort write — failures don't
        # abort the live request because the in-memory check still
        # holds for the rest of this session.
        self._persist_master_vk_hwm(doc.master_vk, doc.issued_unix)
        # Audit C2 (May 14 2026): TOFU-pin peer_master_vk. If we
        # previously pinned a different master VK against this peer
        # fingerprint, refuse the new doc and tear the peer down.
        # An attacker who stole the SDP signing key but cannot
        # recover the original master seed would silently roll
        # forward to a fresh master without this check.
        prior_vk = peer.peer_master_vk
        if prior_vk is not None and prior_vk != doc.master_vk:
            log.warning(
                "peer-rtc: SECURITY ALERT — peer %s presented master_vk "
                "%s but previously pinned %s. Refusing and tearing down.",
                peer.fingerprint,
                doc.master_vk[:8].hex(),
                prior_vk[:8].hex(),
            )
            peer.attestation_challenge = None
            peer.attestation_challenge_dc_id = None
            with contextlib.suppress(Exception):
                self._close_peer(peer)
            return
        # Pin the peer's master VK + mark attested.
        peer.peer_master_vk = doc.master_vk
        peer.attested_ms = _now_ms()
        # Record the doc's deadline so the gate can re-check freshness
        # on every dispatched frame (audit H7 May 2026). Without this,
        # a single successful 30 s round-trip grants the peer an
        # indefinitely-attested state.
        peer.attestation_deadline_unix = int(doc.deadline_unix)
        # Clear the challenge so a stale response doesn't get accepted.
        peer.attestation_challenge = None
        peer.attestation_challenge_dc_id = None
        log.info(
            "peer-rtc: peer %s attested (provider_tag=%d, vk_len=%d, "
            "deadline_unix=%d)",
            peer.fingerprint, doc.provider_tag, len(doc.master_vk),
            peer.attestation_deadline_unix,
        )

    def init_onion_announce(self, peer: BrowserPeer) -> bool:
        """Announce this daemon's Sphinx onion pubkey to a browser peer."""
        pk = getattr(self.daemon, "_cover_relay_pk", None)
        if not pk:
            return False
        try:
            self.send_dc(peer, "control", {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "onion_pubkey",
                "ts": _now_ms(),
                "pubkey_b64": base64.b64encode(pk).decode("ascii"),
            })
            return True
        except Exception as e:
            log.info("peer-rtc: onion pubkey announce failed: %s", e)
            return False

    async def _handle_onion_pubkey(
        self,
        peer: BrowserPeer,
        envelope: dict,
    ) -> None:
        try:
            pk = _b64std_exact(
                envelope.get("pubkey_b64"),
                label="pubkey_b64",
                expected_size=32,
            )
        except ValueError:
            return
        # Audit H10 May 2026 — TOFU pin onion_pubkey. Without this,
        # a peer that has already announced K1 can later send K2 and
        # silently redirect our cover-traffic emitter (which picks
        # the first peer with onion_pubkey + open DC) to a key the
        # attacker holds. The attacker would then have a free
        # decryption oracle for our cover packets — including the
        # COVER_SENTINEL plaintext as a known-plaintext crib against
        # the channel.
        if peer.onion_pubkey is not None and peer.onion_pubkey != pk:
            log.warning(
                "peer-rtc: SECURITY ALERT — peer %s rotated onion_pubkey "
                "(prior=%s, new=%s); refusing.",
                peer.fingerprint,
                peer.onion_pubkey[:8].hex(),
                pk[:8].hex(),
            )
            return
        peer.onion_pubkey = pk
        peer.onion_pubkey_received_ms = _now_ms()
        log.info("peer-rtc: recorded onion pubkey for %s", peer.fingerprint)

    async def _handle_cover_packet(
        self,
        peer: BrowserPeer,
        envelope: dict,
    ) -> None:
        """Audit M8 May 2026 — constant-time response across the
        success / failure split.

        The pre-M8 implementation emitted distinguishing debug log
        lines for ``failed to peel`` vs ``non-deliver`` vs ``lacks
        cover sentinel`` — three different code paths that an
        adversary with DC access could probe (by varying the inbound
        bytes and watching which log shape they produced indirectly
        via timing or controlled log scrape). Combined with the M4
        plaintext sentinel, this was a format-reverse-engineering
        oracle.

        New shape:
          - All non-success peel outcomes collapse to a single
            silent-drop branch with NO log emission (debug or
            otherwise).
          - Success is identified by the M4 authenticated peel
            returning kind=="cover" (the destination's per-circuit
            shared key has verified the trailer MAC). Plaintext
            sentinel inspection is no longer involved.
          - The telemetry counter increment is the ONLY observable
            side effect of success, and it lives in private daemon
            state never echoed to any peer.
        """
        relay_sk = getattr(self.daemon, "_cover_relay_sk", None)
        if relay_sk is None:
            return
        try:
            from one_link_native import sphinx as _native_sphinx
        except ImportError:
            return
        # Decode + peel are wrapped in a single try; any failure
        # silently drops with NO log emission so adversarial probing
        # cannot distinguish failure modes from outside.
        try:
            packet = _b64std_exact(
                envelope.get("packet_b64"),
                label="packet_b64",
                max_size=MAX_COVER_PACKET_BYTES,
            )
            kind, _next_hop, _payload = _native_sphinx.peel_sphinx(
                relay_sk,
                packet,
            )
        except Exception:
            return
        # Audit M4: the authenticated peel returns kind=="cover" iff
        # the trailer MAC verifies under the destination's per-
        # circuit shared key. We do NOT fall back to inspecting the
        # plaintext sentinel — that path is forgeable and was the
        # M8 oracle. kind=="deliver" with a cover-shaped payload but
        # an invalid MAC is treated as a REAL packet (delivered
        # normally elsewhere), not a cover-drop here.
        if kind != "cover":
            return
        # Audit L8 May 2026: lock the read-modify-write so the cover
        # background thread's increment of _cover_emit_count and this
        # path's increment of _cover_recv_count don't tear under
        # concurrent access.
        lock = getattr(self.daemon, "_telemetry_lock", None)
        try:
            if lock is not None:
                with lock:
                    self.daemon._cover_recv_count = (
                        getattr(self.daemon, "_cover_recv_count", 0) + 1
                    )
            else:
                self.daemon._cover_recv_count = (
                    getattr(self.daemon, "_cover_recv_count", 0) + 1
                )
        except Exception as exc:
            report_best_effort_failure(
                log,
                "rtc_cover_receive_counter",
                exc,
                level=logging.DEBUG,
            )

    def send_dc(
        self, peer: BrowserPeer, channel_kind: str, envelope: dict
    ) -> bool:
        """Send a JSON envelope down the peer's DataChannel. Non-async;
        aiortc's send is synchronous (queues into the channel's send
        buffer). Returns whether the frame was successfully queued."""
        if peer.closed:
            log.debug("peer-rtc: refusing send to closed peer %s", peer.fingerprint)
            return False
        # Inbound dispatch rechecks the roster before every request. Outbound
        # notifications and delayed replies need the same guarantee or a
        # device revoked between request admission and response emission could
        # still receive owner data. Pre-registration handshake sends are
        # checked by their initiating methods; this branch applies to the
        # manager's current live registry object.
        if (
            self._peers.get(peer.fingerprint) is peer
            and not self.peer_authorization_is_live(peer)
        ):
            log.warning(
                "peer-rtc: refusing outbound frame and evicting %s after "
                "authority loss",
                peer.fingerprint,
            )
            self._close_peer(peer)
            return False
        dc = peer.control_dc if channel_kind == "control" else peer.bulk_dc
        if dc is None:
            log.debug(
                "peer-rtc: no %s channel for %s", channel_kind, peer.fingerprint,
            )
            return False
        try:
            dc.send(json.dumps(envelope))
        except Exception as e:
            log.warning(
                "peer-rtc: send on %s failed for %s: %s",
                channel_kind, peer.fingerprint, e,
            )
            return False
        return True

    # ── envelope verification ──────────────────────────────────────

    def accept_verified_offer_once(self, envelope: dict) -> bool:
        """Atomically accept one already-verified signed offer.

        Returns ``False`` for a malformed signature field or for an exact
        replay inside the freshness window. Call only after
        :meth:`verify_offer_envelope`; this method deliberately does not repeat
        public-key verification.
        """
        signature_text = envelope.get("signature")
        if not isinstance(signature_text, str) or len(signature_text) > 128:
            return False
        try:
            signature = _b64ud(signature_text, expected_size=64)
        except ValueError:
            return False
        import hashlib
        offer_id = hashlib.sha256(
            b"OL/peer-rtc/offer-replay/v1\0" + signature
        ).digest()
        now = _now_ms()
        cutoff = now - OFFER_REPLAY_CACHE_TTL_MS
        with self._offer_replay_lock:
            while self._seen_offer_ids:
                _oldest_id, oldest_ms = next(iter(self._seen_offer_ids.items()))
                if oldest_ms >= cutoff:
                    break
                self._seen_offer_ids.popitem(last=False)
            if offer_id in self._seen_offer_ids:
                return False
            while len(self._seen_offer_ids) >= OFFER_REPLAY_CACHE_MAX_ENTRIES:
                self._seen_offer_ids.popitem(last=False)
            self._seen_offer_ids[offer_id] = now
        return True

    @staticmethod
    def verify_offer_envelope(envelope: dict) -> tuple[bytes, str]:
        """Validate the signed offer envelope. Returns
        (pubkey_bytes, fingerprint) on success; raises ValueError
        on any failure. Drops timestamps outside the replay window."""
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be an object")
        fields = set(envelope)
        missing = _OFFER_REQUIRED_FIELDS - fields
        unknown = fields - _OFFER_REQUIRED_FIELDS - _OFFER_OPTIONAL_FIELDS
        if missing or unknown:
            raise ValueError(
                "offer envelope fields invalid "
                f"(missing={sorted(missing, key=repr)}, "
                f"unknown={sorted(unknown, key=repr)})"
            )
        if envelope.get("v") != PEER_RTC_PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {envelope.get('v')!r}")
        if envelope.get("t") != "offer":
            raise ValueError(f"unexpected envelope type: {envelope.get('t')!r}")
        pubkey_b64u = envelope.get("pubkey_b64u")
        if not isinstance(pubkey_b64u, str):
            raise ValueError("pubkey_b64u required")
        try:
            pubkey = _b64ud(pubkey_b64u, expected_size=32)
        except ValueError as exc:
            raise ValueError("pubkey invalid base64url; must encode 32 bytes") from exc
        fingerprint = envelope.get("fingerprint")
        if not isinstance(fingerprint, str) or ":" not in fingerprint:
            raise ValueError("fingerprint required (algo:hex)")
        if len(fingerprint) > 128:
            raise ValueError("fingerprint too large")
        sig_b64u = envelope.get("signature")
        if not isinstance(sig_b64u, str):
            raise ValueError("signature required")
        if len(sig_b64u) > 128:
            raise ValueError("signature too large")
        try:
            sig = _b64ud(sig_b64u, expected_size=64)
        except ValueError as exc:
            raise ValueError("signature must be canonical base64url for 64 bytes") from exc
        sdp = envelope.get("sdp")
        if not isinstance(sdp, str) or not sdp:
            raise ValueError("sdp required")
        try:
            sdp_bytes = sdp.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("sdp is not valid UTF-8 text") from exc
        if len(sdp_bytes) > MAX_SDP_BYTES:
            raise ValueError("sdp too large")
        if "\x00" in sdp or not (sdp.startswith("v=0\r\n") or sdp.startswith("v=0\n")):
            raise ValueError("sdp has invalid structure")
        ts = envelope.get("ts")
        if (
            not isinstance(ts, int)
            or isinstance(ts, bool)
            or not 0 <= ts <= _MAX_TIMESTAMP_MS
        ):
            raise ValueError("ts required (int ms)")
        if "pair_token" in envelope:
            token = envelope["pair_token"]
            if not isinstance(token, str):
                raise ValueError("pair_token must be a string")
            _b64ud(token, expected_size=PAIRING_TOKEN_BYTES)
        now = _now_ms()
        if abs(now - ts) > OFFER_REPLAY_WINDOW_MS:
            raise ValueError("offer envelope timestamp out of replay window")
        try:
            Ed25519PublicKey.from_public_bytes(pubkey).verify(
                sig, _canonical(envelope),
            )
        except InvalidSignature as e:
            raise ValueError("offer signature does not verify") from e
        # Don't trust the browser's claimed fingerprint without
        # checking it against a re-derivation. We re-derive the
        # sha256-tagged form ourselves and require equality.
        # Only algorithms implemented here may cross the trust boundary. An
        # unknown tag cannot be accepted as an opaque identifier: after one QR
        # redemption, a second key could claim the same arbitrary identifier
        # and inherit the first key's paired status.
        algo, _, claimed_hex = fingerprint.partition(":")
        if algo != "sha256":
            raise ValueError("unsupported fingerprint algorithm")
        if len(claimed_hex) != 64 or any(
            char not in "0123456789abcdef" for char in claimed_hex
        ):
            raise ValueError("fingerprint must use canonical lowercase sha256")
        import hashlib
        expected = "sha256:" + hashlib.sha256(pubkey).hexdigest()
        if not secrets.compare_digest(expected, fingerprint):
            raise ValueError("fingerprint does not match pubkey (sha256)")
        return pubkey, fingerprint

    # ── DTLS fingerprint cross-check (audit C1 defense-in-depth) ──

    def record_dtls_fingerprint(
        self,
        *,
        pubkey: bytes,
        sdp: str,
    ) -> tuple[str, bool]:
        """Extract the SDP's DTLS-SRTP fingerprint, store it against
        this peer's Ed25519 pubkey, and check it against the
        previously-observed value.

        Returns ``(current_dtls_fp, matches_or_first_seen)``.
        - ``("", True)`` if the SDP has no a=fingerprint line (no
          cross-check possible).
        - ``(fp, True)`` on first observation or matching observation.
        - ``(fp, False)`` if the fingerprint changed — recorded as a
          structured WARNING in the daemon log. Not a hard reject;
          the envelope-signature path already does that.
        """
        dtls_fp = _extract_dtls_fingerprint(sdp)
        if not dtls_fp:
            return "", True
        pubkey_hex = pubkey.hex()
        previous = self._dtls_fingerprints.get(pubkey_hex)
        if previous is not None and previous != dtls_fp:
            log.warning(
                "peer-rtc: DTLS fingerprint changed for browser peer "
                "(pubkey=%s...): %s -> %s",
                pubkey_hex[:16],
                previous[:24] + "...",
                dtls_fp[:24] + "...",
            )
            self._dtls_fingerprints[pubkey_hex] = dtls_fp
            return dtls_fp, False
        self._dtls_fingerprints[pubkey_hex] = dtls_fp
        return dtls_fp, True

    def get_recorded_dtls_fingerprint(self, pubkey: bytes) -> Optional[str]:
        """For tests + diagnostics: read the recorded DTLS
        fingerprint for a pubkey (or None if never observed)."""
        return self._dtls_fingerprints.get(pubkey.hex())
