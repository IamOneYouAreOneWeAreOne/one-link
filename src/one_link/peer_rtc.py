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

# Audit H8/H9 May 2026 — per-peer rate-limit caps for the two
# control-DC frame types that drive expensive native work. Tuned so
# legitimate burst handshakes (a few attestations on reconnect, the
# scheduled cover-traffic cadence) pass without throttling while
# unauthenticated floods get capped.
ATTEST_CHALLENGE_WINDOW_SECS = 10
ATTEST_CHALLENGE_MAX_PER_WINDOW = 3
COVER_PACKET_WINDOW_SECS = 1
COVER_PACKET_MAX_PER_WINDOW = 20


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
    # Row 10 — peer-handshake attestation state.
    # `attestation_challenge`: 32-byte nonce we sent the peer.
    #   Populated when we initiate; checked when their response arrives.
    # `attested_ms`: monotonic timestamp when verification passed.
    #   None until the peer's attest_response has verified.
    # `peer_master_vk`: 1984-byte hybrid VK extracted from a verified
    #   attestation doc. None until attested. Pin this to detect
    #   master-key rotation across reconnects.
    attestation_challenge: Optional[bytes] = None
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
    # Row 6/7 — peer's Sphinx onion public key (Ristretto255 32-byte
    # compressed point). Each peer publishes theirs on DC-open via
    # the `onion_pubkey` envelope; we record the other side's so
    # cover-traffic emission can build real Sphinx packets bound
    # for them (instead of looping back to self).
    onion_pubkey: Optional[bytes] = None
    onion_pubkey_received_ms: Optional[int] = None


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

    # ── Gate helpers (audit H7/H8/H9 May 2026) ─────────────────────

    def _gate_app_or_attested(
        self, peer: BrowserPeer, msg_t: str
    ) -> bool:
        """Audit H7 + the attestation gate. Returns True if the
        message should be processed, False if it must be dropped.

        Two combined checks:
        - If ``require_attested_peers=True`` and peer hasn't yet
          attested, drop.
        - If peer HAS attested but the stored
          ``attestation_deadline_unix`` has passed, drop AND clear
          the attested state so a fresh attestation is required.

        H7 closes the gap where a peer that attested once within
        the 30 s freshness window could ride that "attested" state
        forever. The 30 s window from the attestation doc is the
        peer's freshness promise; treating it as a one-shot opens
        a forever-impersonation window after a single capture of
        an attestation round.
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
        if getattr(self.daemon, "require_attested_peers", False):
            if peer.attested_ms is None:
                cnt = getattr(self.daemon, "_gate_drop_count", 0)
                try:
                    self.daemon._gate_drop_count = cnt + 1
                except Exception:
                    pass
                log.info(
                    "peer-rtc: dropped %r from un-attested peer %s "
                    "(require_attested_peers=on, drops=%d)",
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
        # Row 10 — attestation gate. When the daemon requires
        # attested peers, app-layer messages from peers that haven't
        # completed the handshake are dropped. Control-plane
        # messages (ping/pong, attest_challenge, attest_response)
        # already returned above so the gate only sees app traffic.
        if not self._gate_app_or_attested(peer, msg_t):
            return
        # Fan out to registered listeners (chat, files, etc. wire in
        # v0.20.2+).
        for cb in list(self._dc_listeners):
            try:
                await cb(peer, channel_kind, msg_t, envelope)
            except Exception as e:
                log.warning("peer-rtc: dc listener raised: %s", e)

    # ── Row 10 attestation ───────────────────────────────────────────

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
        with contextlib.suppress(Exception):
            self.send_dc(peer, "control", {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "attest_challenge",
                "ts": _now_ms(),
                "challenge_b64": base64.b64encode(nonce).decode("ascii"),
            })
        return True

    async def _handle_attest_challenge(
        self, peer: BrowserPeer, envelope: dict
    ) -> None:
        """Peer sent us their challenge; we respond with our doc
        bound to their nonce AND to our own SDP-layer Ed25519 pubkey
        (audit C1)."""
        try:
            import base64
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
        challenge_b64 = str(envelope.get("challenge_b64") or "")
        try:
            challenge = base64.b64decode(challenge_b64)
        except Exception:
            return
        if len(challenge) != 32:
            return
        try:
            doc = issue_for_challenge(sealed, challenge, my_sdp_pubkey)
            wire = AttestationWire.from_doc(doc).to_wire_dict()
        except Exception as e:
            log.info("peer-rtc: issue attestation failed: %s", e)
            return
        with contextlib.suppress(Exception):
            self.send_dc(peer, "control", {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": "attest_response",
                "ts": _now_ms(),
                "doc": wire,
            })

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
            pk = base64.b64decode(
                str(envelope.get("pubkey_b64") or ""),
                validate=True,
            )
        except Exception:
            return
        if len(pk) != 32:
            log.info(
                "peer-rtc: %s sent onion_pubkey of wrong length %d",
                peer.fingerprint, len(pk),
            )
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
        relay_sk = getattr(self.daemon, "_cover_relay_sk", None)
        if relay_sk is None:
            return
        try:
            from one_link_native import sphinx as _native_sphinx
        except ImportError:
            return
        try:
            packet = base64.b64decode(
                str(envelope.get("packet_b64") or ""),
                validate=True,
            )
        except Exception:
            return
        try:
            kind, _next_hop, payload = _native_sphinx.peel_sphinx(
                relay_sk,
                packet,
            )
        except Exception as e:
            log.debug(
                "peer-rtc: cover_packet from %s failed to peel: %s",
                peer.fingerprint, e,
            )
            return
        if kind != "deliver":
            log.debug(
                "peer-rtc: cover_packet from %s peeled to non-deliver "
                "(kind=%r); dropping",
                peer.fingerprint, kind,
            )
            return
        if not _native_sphinx.is_cover_payload(payload):
            log.debug(
                "peer-rtc: peeled packet from %s lacks cover sentinel; "
                "dropping",
                peer.fingerprint,
            )
            return
        try:
            self.daemon._cover_recv_count = (
                getattr(self.daemon, "_cover_recv_count", 0) + 1
            )
        except Exception:
            pass

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
