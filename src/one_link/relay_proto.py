"""Encrypted relay protocol — sealed-sender byte forwarding over WebSocket.

Design summary
==============

When two One Link daemons can't connect directly (symmetric NAT, no
port forward, hostile network), they meet inside an encrypted relay
session hosted on a rendezvous they both trust.

Two WebSocket endpoints on the rendezvous server:

    WS  /api/v1/relay/listen
        Destination opens this, signs a freshness-bound challenge, and
        keeps the WS alive. The relay holds a `dst_pubkey -> listener
        ws` slot. Multiple concurrent sessions can be multiplexed
        through this one listener (each tagged with a session_id).

    WS  /api/v1/relay/connect/{dst_pubkey_b64}
        Source opens this. The relay finds the listener for the
        destination, allocates a session_id, signals both sides, and
        forwards binary frames blindly between them.

Sealed-sender posture
---------------------

  - The relay sees `dst_pubkey` (it has to, to route).
  - The relay does NOT see `src_pubkey`. The connector's authentication
    is anonymous-by-design (the rendezvous can't link a connector to
    a real device identity).
  - All payload bytes are end-to-end encrypted by the existing One
    Link channel (`channel.py`). The relay forwards opaque bytes; it
    cannot read content, signing keys, or session secrets.

What the relay can attack
-------------------------

  - DoS by dropping or refusing to forward — users notice immediately.
  - Refuse listen registrations (limit availability of their own
    rendezvous; users can switch operators).
  - Observe traffic *patterns* (timing, byte counts) per dst_pubkey.
    Sealed sender hides who is talking to whom but not the destination.
  - The relay CANNOT impersonate any device, decrypt any payload,
    forge a session, or connect a source to a destination they don't
    actually want to talk to.

Wire frames
-----------

All inner-protocol messages are JSON; the relay's own framing is
WebSocket binary frames. Inside each binary frame the wire bytes are:

    [1-byte type][8-byte session_id][optional payload bytes]

Frame types:

    0x01 (DATA)         payload is opaque encrypted bytes from one
                        side to the other; relay forwards verbatim.
    0x02 (CLOSE)        terminate this session_id. Forwarded as-is.

The listener also receives small JSON control messages (no
session_id) over text frames:

    {"t": "incoming", "session_id": <8-byte hex>}
    {"t": "session_closed", "session_id": <8-byte hex>}

The connector receives a `{"t": "ready", "session_id": <8-byte hex>}`
text frame once paired with the listener.

Replay defense
--------------

The listen-side authentication binds a signed `(pubkey, ts_ms,
nonce)` blob via the same Ed25519 signature primitive the rendezvous
already uses for register/revoke. Replay window is the same
REPLAY_WINDOW_MS (60 s).

Limits
------

  - LISTEN_AUTH_MAX_BYTES (1 KB) — listen-side auth blob.
  - DATA_FRAME_MAX_BYTES (1 MB) — single relay data frame. Larger
    payloads are chunked at the channel layer above us.
  - SESSION_ID_BYTES (8) — random, server-allocated.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "OL-RELAY-1"
REPLAY_WINDOW_MS = 60_000

LISTEN_AUTH_MAX_BYTES = 1 * 1024
DATA_FRAME_MAX_BYTES = 1 * 1024 * 1024
CONTROL_FRAME_MAX_BYTES = 4 * 1024  # text frames: incoming/ready/closed
SESSION_ID_BYTES = 8

# Wire frame types (binary frames)
FRAME_DATA = 0x01
FRAME_CLOSE = 0x02


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def now_ms() -> int:
    return int(time.time() * 1000)


def new_session_id() -> bytes:
    """Server-side session_id. Random — the listener doesn't choose
    or learn the source's identity from this value."""
    return secrets.token_bytes(SESSION_ID_BYTES)


# ─── listen-side auth ──────────────────────────────────────────────

@dataclass
class ListenAuth:
    """Destination proves it controls a pubkey to claim that pubkey's
    listener slot. Signed Ed25519 blob bound to a freshness token so
    a captured auth message can't be replayed past the window."""

    pubkey: bytes              # the pubkey the destination is claiming
    timestamp_ms: int
    nonce: bytes               # 16 bytes of entropy, freshness binder
    signature: bytes = b""

    def to_signing_dict(self) -> dict:
        return {
            "v": PROTOCOL_VERSION,
            "t": "listen_auth",
            "pubkey_b64": _b64(self.pubkey),
            "timestamp_ms": int(self.timestamp_ms),
            "nonce_b64": _b64(self.nonce),
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(self.signature)
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "ListenAuth":
        if not isinstance(d, dict):
            raise ValueError("listen_auth must be an object")
        if d.get("v") != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {d.get('v')!r}")
        if d.get("t") != "listen_auth":
            raise ValueError(f"unexpected type: {d.get('t')!r}")
        pubkey = _b64d(_require_str(d.get("pubkey_b64"), "pubkey_b64"))
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        nonce = _b64d(_require_str(d.get("nonce_b64"), "nonce_b64"))
        if len(nonce) != 16:
            raise ValueError("nonce must be 16 bytes")
        sig = _b64d(_require_str(d.get("signature"), "signature"))
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_require_int(d.get("timestamp_ms"), "timestamp_ms"),
            nonce=nonce,
            signature=sig,
        )

    def verify(self) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                self.signature,
                _canonical_bytes(self.to_signing_dict()),
            )
        except InvalidSignature:
            raise ValueError("listen_auth signature does not verify")


def sign_listen_auth(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    timestamp_ms: int | None = None,
    nonce: bytes | None = None,
) -> ListenAuth:
    auth = ListenAuth(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
        nonce=nonce if nonce is not None else os.urandom(16),
    )
    auth.signature = private_key.sign(_canonical_bytes(auth.to_signing_dict()))
    return auth


# ─── binary frame helpers ──────────────────────────────────────────

def encode_data_frame(session_id: bytes, payload: bytes) -> bytes:
    if len(session_id) != SESSION_ID_BYTES:
        raise ValueError("session_id must be 8 bytes")
    if len(payload) > DATA_FRAME_MAX_BYTES:
        raise ValueError(
            f"data frame too large: {len(payload)} > {DATA_FRAME_MAX_BYTES}"
        )
    return bytes([FRAME_DATA]) + session_id + payload


def encode_close_frame(session_id: bytes) -> bytes:
    if len(session_id) != SESSION_ID_BYTES:
        raise ValueError("session_id must be 8 bytes")
    return bytes([FRAME_CLOSE]) + session_id


@dataclass
class ParsedFrame:
    type: int
    session_id: bytes
    payload: bytes


def decode_frame(buf: bytes) -> ParsedFrame:
    """Parse a binary relay frame.

    Raises ValueError on malformed input. The caller (relay server or
    client) is responsible for size-bound enforcement at the WebSocket
    transport level — but we re-check DATA_FRAME_MAX_BYTES here as
    defense-in-depth.
    """
    if not isinstance(buf, (bytes, bytearray, memoryview)):
        raise ValueError("frame must be bytes")
    if len(buf) < 1 + SESSION_ID_BYTES:
        raise ValueError(f"frame too short: {len(buf)}")
    t = buf[0]
    if t not in (FRAME_DATA, FRAME_CLOSE):
        raise ValueError(f"unknown frame type: {t:#04x}")
    session_id = bytes(buf[1:1 + SESSION_ID_BYTES])
    payload = bytes(buf[1 + SESSION_ID_BYTES:])
    if t == FRAME_CLOSE and payload:
        raise ValueError("close frame must not carry payload")
    if t == FRAME_DATA and len(payload) > DATA_FRAME_MAX_BYTES:
        raise ValueError(
            f"data frame payload too large: {len(payload)} > {DATA_FRAME_MAX_BYTES}"
        )
    return ParsedFrame(type=t, session_id=session_id, payload=payload)


# ─── control frames (JSON over text WS) ────────────────────────────

def make_incoming_msg(session_id: bytes) -> dict:
    return {"t": "incoming", "session_id": session_id.hex()}


def make_session_closed_msg(session_id: bytes) -> dict:
    return {"t": "session_closed", "session_id": session_id.hex()}


def make_ready_msg(session_id: bytes) -> dict:
    return {"t": "ready", "session_id": session_id.hex()}


def parse_session_id_from_msg(msg: dict) -> bytes:
    sid_hex = msg.get("session_id")
    if not isinstance(sid_hex, str) or len(sid_hex) != SESSION_ID_BYTES * 2:
        raise ValueError(f"invalid session_id field: {sid_hex!r}")
    try:
        sid = bytes.fromhex(sid_hex)
    except ValueError as e:
        raise ValueError(f"session_id not hex: {e}")
    if len(sid) != SESSION_ID_BYTES:
        raise ValueError("session_id wrong length")
    return sid


# ─── replay window ─────────────────────────────────────────────────

def timestamp_within_replay_window(
    timestamp_ms: int,
    *,
    server_now_ms: int | None = None,
    window_ms: int = REPLAY_WINDOW_MS,
) -> bool:
    now = server_now_ms if server_now_ms is not None else now_ms()
    return abs(int(now) - int(timestamp_ms)) <= window_ms


# ─── canonical signing form (shared with rendezvous_proto) ─────────

def _canonical_bytes(payload: dict) -> bytes:
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


# ─── input validation helpers ──────────────────────────────────────

def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v
