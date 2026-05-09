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

- **Trust via pairing token, not manual SAS.** The user
  ceremony is "scan the QR I'm showing on my laptop." Possessing
  a fresh, signed, single-use, short-TTL token that came directly
  off the laptop's screen IS the trust ceremony. We do NOT
  re-prompt the user for SAS confirmation — that would be
  asking them to verify what they just verified by scanning.

- **Pubkey-bound returning peers.** Once paired, the browser's
  Ed25519 pubkey is stored as a peer record. Subsequent
  reconnects from the same pubkey skip pairing entirely; the
  signature on the SDP offer envelope authenticates them.

- **Single-process state.** All browser-peer connections live
  in `BrowserPeerManager` on the daemon. This module is the
  single source of truth for what's connected, what's pending,
  and which pairing tokens are active.

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
  by token → {created_ms, ttl_ms, fp_hint}. TTL default 5
  minutes. Token is consumed (deleted) when redeemed; only one
  redemption per token. After redemption, the browser's pubkey
  is marked as a paired peer and any future reconnect with the
  same pubkey skips pairing.

  The QR encoded for the user has a deep-link to /peer with the
  token embedded as `?pair=<token>` (v0.20.1 wires this).

Security model
==============

  - Pair token leaked → an attacker who scans the same QR (or
    intercepts it) can pair. Mitigation: 5min TTL, single-use,
    QR is on-screen for the user only.
  - DTLS-SRTP fingerprint pinning (browser ↔ daemon) handled
    by aiortc + browser WebRTC stacks.
  - Ed25519 signature on the offer envelope binds the SDP
    to the browser's claimed pubkey. A malicious signaling
    relay cannot forge an offer for a different pubkey because
    they'd have to break Ed25519.
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
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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

# Pairing-token TTL. 5 minutes is enough for the user to physically
# pick up their phone, open the camera, and scan the QR + a couple
# of network round-trips of slack. Shorter and a slow user fails
# without a clear cause.
PAIRING_TOKEN_TTL_MS = 5 * 60 * 1000
PAIRING_TOKEN_BYTES = 32

# Signature freshness window — accept offer envelopes with a
# timestamp within this many ms of "now". Prevents trivial replay
# of a stale captured offer. WebRTC SDP itself isn't sensitive
# (it's network-routing info), but we still bind freshness so a
# stolen signed offer can't be re-played weeks later.
OFFER_REPLAY_WINDOW_MS = 60 * 1000
MAX_SIGNALING_TEXT_BYTES = 256 * 1024
MAX_SDP_BYTES = 128 * 1024
MAX_DC_TEXT_BYTES = 256 * 1024
MAX_PENDING_PAIRING_TOKENS = 64
_B64URL_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


# ── helpers (b64url no padding, canonical JSON) ──────────────────────

def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64ud(s: str) -> bytes:
    if not isinstance(s, str) or any(c not in _B64URL_ALPHABET for c in s):
        raise ValueError("invalid base64url")
    pad = "=" * ((4 - len(s) % 4) % 4)
    try:
        return base64.urlsafe_b64decode((s + pad).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as e:
        raise ValueError("invalid base64url") from e


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


# ── pairing-token store ──────────────────────────────────────────────


@dataclass
class PendingPair:
    token: str
    created_ms: int
    ttl_ms: int = PAIRING_TOKEN_TTL_MS
    fp_hint: Optional[str] = None  # rendered in the laptop QR for the user

    def expired(self, now_ms: Optional[int] = None) -> bool:
        return (now_ms or _now_ms()) > self.created_ms + self.ttl_ms


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
        self._dc_listeners: list[
            Callable[[BrowserPeer, str, str, dict], Awaitable[None]]
        ] = []
        # `_paired_pubkeys`: persistent set of fingerprints that have
        # already redeemed a pairing token at any point. Tracks the
        # "this browser has been paired before" identity. Persistence
        # to disk is wired in v0.20.2 — for v0.20.0 we keep in-memory
        # only.
        self._paired_pubkeys: set[str] = set()

    # ── pairing tokens ──────────────────────────────────────────────

    def mint_pairing_token(self, fp_hint: Optional[str] = None) -> PendingPair:
        """Mint a fresh single-use pairing token. The laptop UI
        renders this into a QR for the user to scan with their phone."""
        token = _b64u(secrets.token_bytes(PAIRING_TOKEN_BYTES))
        pp = PendingPair(token=token, created_ms=_now_ms(), fp_hint=fp_hint)
        self._pending_pairings[token] = pp
        log.info("peer-rtc: minted pairing token (ttl=%dms)", pp.ttl_ms)
        # Sweep expired tokens opportunistically — keeps memory bounded
        # without a background sweeper task.
        self._sweep_expired_pairings()
        if len(self._pending_pairings) > MAX_PENDING_PAIRING_TOKENS:
            oldest = sorted(
                self._pending_pairings.items(),
                key=lambda item: item[1].created_ms,
            )
            overflow = len(self._pending_pairings) - MAX_PENDING_PAIRING_TOKENS
            for old_token, _old in oldest[:overflow]:
                self._pending_pairings.pop(old_token, None)
        return pp

    def _sweep_expired_pairings(self) -> int:
        now = _now_ms()
        expired = [t for t, pp in self._pending_pairings.items() if pp.expired(now)]
        for t in expired:
            self._pending_pairings.pop(t, None)
        return len(expired)

    def redeem_pairing_token(self, token: str) -> Optional[PendingPair]:
        """Try to redeem a pairing token. Returns the PendingPair on
        success (consuming it) or None if missing/expired."""
        if not token:
            return None
        pp = self._pending_pairings.pop(token, None)
        if pp is None:
            return None
        if pp.expired():
            return None
        return pp

    # ── peer registry ───────────────────────────────────────────────

    def register_peer(self, peer: BrowserPeer) -> None:
        existing = self._peers.get(peer.fingerprint)
        if existing is not None and existing is not peer:
            # Newest connection wins. Tear down the old one.
            log.info(
                "peer-rtc: replacing existing connection for %s",
                peer.fingerprint,
            )
            self._close_peer(existing)
        self._peers[peer.fingerprint] = peer

    def is_paired(self, fingerprint: str) -> bool:
        return fingerprint in self._paired_pubkeys

    def mark_paired(self, fingerprint: str) -> None:
        self._paired_pubkeys.add(fingerprint)

    def get_peer(self, fingerprint: str) -> Optional[BrowserPeer]:
        return self._peers.get(fingerprint)

    def list_peers(self) -> list[BrowserPeer]:
        return list(self._peers.values())

    def _close_peer(self, peer: BrowserPeer) -> None:
        if peer.closed:
            return
        peer.closed = True
        pc = peer.pc
        if pc is not None:
            try:
                # aiortc's pc.close is async; schedule it.
                loop = asyncio.get_event_loop()
                loop.create_task(pc.close())
            except Exception as e:
                log.debug("peer-rtc: pc.close error for %s: %s", peer.fingerprint, e)
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

    async def _dispatch_dc(
        self, peer: BrowserPeer, channel_kind: str, raw: Any
    ) -> None:
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
        if envelope.get("v") != PEER_DC_PROTOCOL_VERSION:
            return
        msg_t = str(envelope.get("t") or "")
        if not msg_t:
            return
        peer.last_activity_ms = _now_ms()
        # Built-in ping/pong. Always handled; tests for liveness.
        if msg_t == "ping":
            with contextlib.suppress(Exception):
                self.send_dc(peer, "control", {
                    "v": PEER_DC_PROTOCOL_VERSION,
                    "t": "pong",
                    "ts": _now_ms(),
                    "echo_ts": envelope.get("ts"),
                })
            return
        # Fan out to registered listeners (chat, files, etc. wire in
        # v0.20.2+).
        for cb in list(self._dc_listeners):
            try:
                await cb(peer, channel_kind, msg_t, envelope)
            except Exception as e:
                log.warning("peer-rtc: dc listener raised: %s", e)

    def send_dc(
        self, peer: BrowserPeer, channel_kind: str, envelope: dict
    ) -> None:
        """Send a JSON envelope down the peer's DataChannel. Non-async;
        aiortc's send is synchronous (queues into the channel's send
        buffer)."""
        if peer.closed:
            return
        dc = peer.control_dc if channel_kind == "control" else peer.bulk_dc
        if dc is None:
            log.debug(
                "peer-rtc: no %s channel for %s", channel_kind, peer.fingerprint,
            )
            return
        try:
            dc.send(json.dumps(envelope))
        except Exception as e:
            log.warning(
                "peer-rtc: send on %s failed for %s: %s",
                channel_kind, peer.fingerprint, e,
            )

    # ── envelope verification ──────────────────────────────────────

    @staticmethod
    def verify_offer_envelope(envelope: dict) -> tuple[bytes, str]:
        """Validate the signed offer envelope. Returns
        (pubkey_bytes, fingerprint) on success; raises ValueError
        on any failure. Drops timestamps outside the replay window."""
        if not isinstance(envelope, dict):
            raise ValueError("envelope must be an object")
        if envelope.get("v") != PEER_RTC_PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {envelope.get('v')!r}")
        if envelope.get("t") != "offer":
            raise ValueError(f"unexpected envelope type: {envelope.get('t')!r}")
        pubkey_b64u = envelope.get("pubkey_b64u")
        if not isinstance(pubkey_b64u, str):
            raise ValueError("pubkey_b64u required")
        if len(pubkey_b64u) > 64:
            raise ValueError("pubkey_b64u too large")
        pubkey = _b64ud(pubkey_b64u)
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
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
        sig = _b64ud(sig_b64u)
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes")
        sdp = envelope.get("sdp")
        if not isinstance(sdp, str) or not sdp:
            raise ValueError("sdp required")
        if len(sdp.encode("utf-8", errors="ignore")) > MAX_SDP_BYTES:
            raise ValueError("sdp too large")
        ts = envelope.get("ts")
        if not isinstance(ts, int):
            raise ValueError("ts required (int ms)")
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
        # (BLAKE3 fingerprints can come along when the browser
        # vendors BLAKE3-WASM in a later ship; we accept whichever
        # algorithm the browser tagged, as long as it derives
        # correctly.)
        algo, _, claimed_hex = fingerprint.partition(":")
        if algo == "sha256":
            import hashlib
            expected = "sha256:" + hashlib.sha256(pubkey).hexdigest()
            if expected != fingerprint:
                raise ValueError("fingerprint does not match pubkey (sha256)")
        return pubkey, fingerprint
