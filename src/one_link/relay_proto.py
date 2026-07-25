"""Encrypted relay protocol — sealed-sender byte forwarding over WebSocket.

Design summary
==============

When two One Link daemons can't connect directly (symmetric NAT, no
port forward, hostile network), they meet inside an encrypted relay
session hosted on a rendezvous they both trust.

Two WebSocket endpoints on the rendezvous server:

    WS  /api/v2/relay/listen
        Production listeners register rotating pairwise route tags and
        epoch-scoped verification keys. Tags are self-certified from those
        keys, so a vacant observed tag cannot be claimed with new authority.
        No identity public key is sent.

    WS  /api/v2/relay/connect/{route_tag_b64}
        A paired source proves possession of the epoch route authority.
        The relay finds that opaque tag, allocates a session_id, signals
        both sides, and forwards binary frames blindly between them.

The v1 public-key routes implemented in this module remain available to
operators for an explicit mixed-version migration. The daemon does not
register or dial them unless the legacy override is enabled.

Sealed-sender posture
---------------------

  - The v2 relay sees neither participant's identity public key on its
    protocol wire. It routes by an epoch-scoped pairwise tag, and the
    channel's otherwise identity-bearing HELLO/REPLY flights are sealed to
    their already-paired recipients before becoming relay DATA.
  - The relay still sees both socket addresses, timing, byte counts, and
    tag activity. When the same operator also handles signed presence, it may
    correlate relay sockets with presence identities using IP address and
    timing even though no identity key occurs in the relay protocol. This is
    recipient-identifier blinding, not anonymity.
  - A later compromise of a recipient identity seed can open recorded sealed
    first flights. The inner channel has its own forward/PQ security posture;
    the sealed metadata envelope itself does not claim forward secrecy.
  - All payload bytes are end-to-end encrypted by the existing One
    Link channel (`channel.py`). The relay forwards opaque bytes; it
    cannot read content, signing keys, or session secrets.

What the relay can attack
-------------------------

  - DoS by dropping or refusing to forward — users notice immediately.
  - Refuse listen registrations (limit availability of their own
    rendezvous; users can switch operators).
  - Observe traffic *patterns* (timing, byte counts) per rotating tag and
    correlate sockets at this relay.
  - The relay CANNOT complete an authenticated channel as a device or decrypt
    a payload. A malicious operator can still drop, replay, delay, duplicate,
    or misroute bytes; peer identity checks and transcript binding make those
    attempts fail closed rather than making the relay trustworthy.

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

The v2 listen and connect proofs are signed by an epoch key derived from the
paired identities' shared secret. Both bind a timestamp and one-use nonce;
the server enforces the same 60-second replay window. Legacy v1 listen auth
continues to bind `(pubkey, ts_ms, nonce)` for migration clients.

Limits
------

  - LISTEN_AUTH_MAX_BYTES (1 KB) — listen-side auth blob.
  - DATA_FRAME_MAX_BYTES (1 MB) — single relay data frame. Larger
    payloads are chunked at the channel layer above us.
  - SESSION_ID_BYTES (8) — random, server-allocated.
"""
from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from dataclasses import dataclass

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
MAX_TIMESTAMP_MS = (1 << 63) - 1
RELAY_JSON_MAX_NESTING = 64

_LISTEN_AUTH_KEYS = frozenset({
    "v", "t", "pubkey_b64", "timestamp_ms", "nonce_b64", "signature",
})
_CONTROL_TYPES = frozenset({"incoming", "ready", "session_closed"})
_CONTROL_KEYS = frozenset({"t", "session_id"})

# Wire frame types (binary frames)
FRAME_DATA = 0x01
FRAME_CLOSE = 0x02


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str, *, expected_size: int, name: str) -> bytes:
    """Decode canonical unpadded base64url with a pre-decode size bound."""
    if not isinstance(s, str):
        raise ValueError(f"{name} must be a string")
    expected_chars = (expected_size * 8 + 5) // 6
    if len(s) != expected_chars or "=" in s:
        raise ValueError(f"{name} has invalid encoded length")
    try:
        raw_ascii = s.encode("ascii")
        pad = b"=" * ((4 - len(raw_ascii) % 4) % 4)
        decoded = base64.b64decode(raw_ascii + pad, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} is not canonical base64url") from exc
    if len(decoded) != expected_size or _b64(decoded) != s:
        raise ValueError(f"{name} is not canonical base64url")
    return decoded


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
        pubkey = _require_bytes_exact(self.pubkey, 32, "pubkey")
        timestamp_ms = _validate_timestamp(self.timestamp_ms, "timestamp_ms")
        nonce = _require_bytes_exact(self.nonce, 16, "nonce")
        return {
            "v": PROTOCOL_VERSION,
            "t": "listen_auth",
            "pubkey_b64": _b64(pubkey),
            "timestamp_ms": timestamp_ms,
            "nonce_b64": _b64(nonce),
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(_require_bytes_exact(self.signature, 64, "signature"))
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "ListenAuth":
        d = _require_exact_keys(d, _LISTEN_AUTH_KEYS, "listen_auth")
        if d["v"] != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {d['v']!r}")
        if d["t"] != "listen_auth":
            raise ValueError(f"unexpected type: {d['t']!r}")
        pubkey = _b64d(d["pubkey_b64"], expected_size=32, name="pubkey_b64")
        nonce = _b64d(d["nonce_b64"], expected_size=16, name="nonce_b64")
        sig = _b64d(d["signature"], expected_size=64, name="signature")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_validate_timestamp(d["timestamp_ms"], "timestamp_ms"),
            nonce=nonce,
            signature=sig,
        )

    def verify(self) -> None:
        signing_dict = self.to_signing_dict()
        signature = _require_bytes_exact(self.signature, 64, "signature")
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                signature,
                _canonical_bytes(signing_dict),
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
    _require_matching_public_key(private_key, pubkey)
    auth = ListenAuth(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
        nonce=nonce if nonce is not None else secrets.token_bytes(16),
    )
    signing_dict = auth.to_signing_dict()
    auth.signature = private_key.sign(_canonical_bytes(signing_dict))
    return auth


# ─── binary frame helpers ──────────────────────────────────────────

def encode_data_frame(session_id: bytes, payload: bytes) -> bytes:
    sid = _require_bytes_exact(session_id, SESSION_ID_BYTES, "session_id")
    if not isinstance(payload, bytes):
        raise ValueError("payload must be bytes")
    if len(payload) > DATA_FRAME_MAX_BYTES:
        raise ValueError(
            f"data frame too large: {len(payload)} > {DATA_FRAME_MAX_BYTES}"
        )
    return bytes([FRAME_DATA]) + sid + payload


def encode_close_frame(session_id: bytes) -> bytes:
    sid = _require_bytes_exact(session_id, SESSION_ID_BYTES, "session_id")
    return bytes([FRAME_CLOSE]) + sid


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
    frame_len = len(buf)
    if frame_len < 1 + SESSION_ID_BYTES:
        raise ValueError(f"frame too short: {len(buf)}")
    if frame_len > 1 + SESSION_ID_BYTES + DATA_FRAME_MAX_BYTES:
        raise ValueError(
            f"relay frame too large: {frame_len} > "
            f"{1 + SESSION_ID_BYTES + DATA_FRAME_MAX_BYTES}"
        )
    frame = bytes(buf)
    t = frame[0]
    if t not in (FRAME_DATA, FRAME_CLOSE):
        raise ValueError(f"unknown frame type: {t:#04x}")
    session_id = frame[1:1 + SESSION_ID_BYTES]
    payload = frame[1 + SESSION_ID_BYTES:]
    if t == FRAME_CLOSE and payload:
        raise ValueError("close frame must not carry payload")
    if t == FRAME_DATA and len(payload) > DATA_FRAME_MAX_BYTES:
        raise ValueError(
            f"data frame payload too large: {len(payload)} > {DATA_FRAME_MAX_BYTES}"
        )
    return ParsedFrame(type=t, session_id=session_id, payload=payload)


# ─── control frames (JSON over text WS) ────────────────────────────

def make_incoming_msg(session_id: bytes) -> dict:
    return {"t": "incoming", "session_id": _session_id_hex(session_id)}


def make_session_closed_msg(session_id: bytes) -> dict:
    return {"t": "session_closed", "session_id": _session_id_hex(session_id)}


def make_ready_msg(session_id: bytes) -> dict:
    return {"t": "ready", "session_id": _session_id_hex(session_id)}


def parse_session_id_from_msg(msg: dict) -> bytes:
    msg = _require_exact_keys(msg, _CONTROL_KEYS, "relay control message")
    control_type = msg["t"]
    if not isinstance(control_type, str) or control_type not in _CONTROL_TYPES:
        raise ValueError(f"invalid relay control type: {control_type!r}")
    sid_hex = msg["session_id"]
    if not isinstance(sid_hex, str) or len(sid_hex) != SESSION_ID_BYTES * 2:
        raise ValueError(f"invalid session_id field: {sid_hex!r}")
    try:
        sid = bytes.fromhex(sid_hex)
    except ValueError as e:
        raise ValueError(f"session_id not hex: {e}")
    if len(sid) != SESSION_ID_BYTES:
        raise ValueError("session_id wrong length")
    if sid.hex() != sid_hex:
        raise ValueError("session_id must be canonical lowercase hex")
    return sid


# ─── replay window ─────────────────────────────────────────────────

def timestamp_within_replay_window(
    timestamp_ms: int,
    *,
    server_now_ms: int | None = None,
    window_ms: int = REPLAY_WINDOW_MS,
) -> bool:
    now = server_now_ms if server_now_ms is not None else now_ms()
    if (
        not _is_valid_timestamp(timestamp_ms)
        or not _is_valid_timestamp(now)
        or not isinstance(window_ms, int)
        or isinstance(window_ms, bool)
        or window_ms < 0
        or window_ms > MAX_TIMESTAMP_MS
    ):
        return False
    return abs(now - timestamp_ms) <= window_ms


# ─── canonical signing form (shared with rendezvous_proto) ─────────

def bounded_json_loads(raw: str | bytes) -> object:
    """Decode protocol JSON without duplicate, non-finite, or depth ambiguity."""

    if isinstance(raw, bytes):
        text = raw.decode("utf-8", "strict")
    elif isinstance(raw, str):
        text = raw
    else:
        raise ValueError("JSON input must be text or bytes")

    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if in_string:
            if char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > RELAY_JSON_MAX_NESTING:
                raise ValueError(
                    f"JSON nesting exceeds {RELAY_JSON_MAX_NESTING}-level bound"
                )
        elif char in "]}":
            depth = max(0, depth - 1)

    def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON field: {key}")
            value[key] = item
        return value

    def _reject_nonfinite(constant: str) -> object:
        raise ValueError(f"non-finite JSON number is not permitted: {constant}")

    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds parser recursion bound") from exc


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


def _require_exact_keys(d: object, expected: frozenset[str], name: str) -> dict:
    if not isinstance(d, dict):
        raise ValueError(f"{name} must be an object")
    actual = set(d)
    if actual != expected:
        missing = sorted(expected - actual, key=repr)
        unknown = sorted(actual - expected, key=repr)
        raise ValueError(f"{name} fields invalid (missing={missing}, unknown={unknown})")
    return d


def _require_bytes_exact(value: object, expected: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes")
    return value


def _validate_timestamp(value: object, name: str) -> int:
    timestamp = _require_int(value, name)
    if not 0 <= timestamp <= MAX_TIMESTAMP_MS:
        raise ValueError(f"{name} out of range")
    return timestamp


def _is_valid_timestamp(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_TIMESTAMP_MS
    )


def _require_matching_public_key(
    private_key: Ed25519PrivateKey,
    pubkey: object,
) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("private_key must be an Ed25519 private key")
    claimed = _require_bytes_exact(pubkey, 32, "pubkey")
    if private_key.public_key().public_bytes_raw() != claimed:
        raise ValueError("pubkey does not match private_key")
    return claimed


def _session_id_hex(session_id: object) -> str:
    return _require_bytes_exact(session_id, SESSION_ID_BYTES, "session_id").hex()
