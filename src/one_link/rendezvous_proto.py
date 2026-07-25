"""Rendezvous wire protocol — signed JSON over HTTP.

The rendezvous is a small federated service (or self-hosted box) that
holds, in memory, a mapping of `pubkey -> last-known-endpoint` so two
One Link devices on different networks can find each other to attempt
direct connection (NAT hole-punch in v0.5.1, relay fallback in v0.5.2).

Three guarantees the protocol provides:

 1. **Authenticity.** Every register / revoke is signed by the
    device's Ed25519 key. The rendezvous can't impersonate anyone
    because it doesn't hold private keys.

 2. **Privacy from the rendezvous.** The rendezvous learns *who is
    online* (pubkey + IP), never *who is talking to whom* — that
    information lives only in the (encrypted) channel between the
    two devices once they connect.

 3. **No plaintext data.** The rendezvous never carries chat / file
    bytes in v0.5.0. (Relay fallback in v0.5.2 will carry encrypted
    bytes and still cannot read them — sealed-sender envelope.)

Wire shape — three endpoints:

  POST  /api/v1/register
        body:  RegisterReq (signed)
        reply: RegisterAck
  GET   /api/v1/lookup/{pubkey_b64}
        reply: LookupAck or 404
  POST  /api/v1/revoke
        body:  RevokeReq (signed)
        reply: 200 OK or 404

All payloads are JSON; signatures cover a deterministic canonical-form
serialization of the message minus the signature field itself.

Replay defense:
  - `timestamp_ms` must be within ± REPLAY_WINDOW_MS of server time
  - on register: the server stamps `expires_at_ms = min(now+ttl_s,
    now+MAX_REGISTRATION_TTL_S)` and stores it; lookups past expiry
    return 404.

Forward-compat:
  - `protocol_version` field; rendezvous rejects requests it doesn't
    know how to verify
  - each protocol version has a closed schema. Extensions therefore
    require a new version instead of creating signed/parsed ambiguity.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PROTOCOL_VERSION = "OL-RDZ-1"

# Replays older than this are rejected. 60s tolerates clock skew + WAN
# latency without leaving meaningful replay surface.
REPLAY_WINDOW_MS = 60_000

# Hard cap on how long a single register can claim the slot. Forces
# devices to refresh and gives the rendezvous bounded memory.
MAX_REGISTRATION_TTL_S = 24 * 60 * 60  # 24 hours

# Endpoints the client *advertises* it can be reached at (LAN IPs,
# IPv6 globals, etc.). The server independently records the IP it
# observed the request from.
MAX_ADVERTISED_ENDPOINTS = 8

# Opaque payload size sanity (kilobytes, not megabytes).
MAX_REQUEST_BYTES = 8 * 1024

# Every variable-length field is bounded before expensive parsing or
# allocation. These limits comfortably cover the current capability set
# while keeping a hostile rendezvous response cheap to reject.
MAX_HOST_LENGTH = 253
MAX_CAPABILITIES = 128
MAX_CAPABILITY_LENGTH = 128
MAX_TIMESTAMP_MS = (1 << 63) - 1

_NAT_TYPES = frozenset({"open", "restricted", "symmetric", "unknown"})
_CAPABILITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_REGISTER_KEYS = frozenset({
    "v", "type", "pubkey_b64", "timestamp_ms", "ttl_s",
    "advertised_endpoints", "nat_type", "capabilities", "signature",
})
_REGISTER_ACK_KEYS = frozenset({
    "v", "type", "observed_host", "observed_port", "server_time_ms",
    "expires_at_ms",
})
_LOOKUP_ACK_KEYS = frozenset({
    "v", "type", "pubkey_b64", "observed_endpoint",
    "advertised_endpoints", "nat_type", "capabilities", "expires_at_ms",
    "server_time_ms",
})
_REVOKE_KEYS = frozenset({"v", "type", "pubkey_b64", "timestamp_ms", "signature"})
_ENDPOINT_KEYS = frozenset({"host", "port"})


# ─── helpers ────────────────────────────────────────────────────────

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


def _canonical_bytes(payload: dict) -> bytes:
    """Deterministic serialization for signing.

    Sort keys, no whitespace, ASCII only. Every party computes this
    the same way so the signature verifies. We exclude the
    `signature` field itself — that's what we're signing.
    """
    body = {k: v for k, v in payload.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def now_ms() -> int:
    return int(time.time() * 1000)


def _require_exact_keys(d: object, expected: frozenset[str], name: str) -> dict:
    if not isinstance(d, dict):
        raise ValueError(f"{name} must be an object")
    actual = set(d)
    if actual != expected:
        missing = sorted(expected - actual, key=repr)
        unknown = sorted(actual - expected, key=repr)
        raise ValueError(f"{name} fields invalid (missing={missing}, unknown={unknown})")
    return d


def _validate_timestamp(value: object, name: str) -> int:
    ts = _require_int(value, name)
    if not 0 <= ts <= MAX_TIMESTAMP_MS:
        raise ValueError(f"{name} out of range")
    return ts


def _validate_host(value: object, name: str = "host") -> str:
    host = _require_str(value, name)
    if not host or len(host) > MAX_HOST_LENGTH or host != host.strip():
        raise ValueError(f"{name} is invalid")
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be ASCII") from exc
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in host):
        raise ValueError(f"{name} contains invalid characters")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        # A colon is only valid in a syntactically valid IPv6 literal.
        if ":" in host:
            raise ValueError(f"{name} is not a valid IP address")
        if all(ch.isdigit() or ch == "." for ch in host):
            raise ValueError(f"{name} is not a valid IPv4 address")
    if host.endswith("."):
        host = host[:-1]
    labels = host.split(".")
    if not host or any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise ValueError(f"{name} is not a valid DNS name")
    return host


def _validate_capabilities(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise ValueError(f"capabilities must be a list of length <= {MAX_CAPABILITIES}")
    result: list[str] = []
    for cap in value:
        if (
            not isinstance(cap, str)
            or len(cap) > MAX_CAPABILITY_LENGTH
            or _CAPABILITY_RE.fullmatch(cap) is None
        ):
            raise ValueError("capabilities contains an invalid token")
        result.append(cap)
    return result


def _validate_nat_type(value: object) -> str:
    nat_type = _require_str(value, "nat_type")
    if nat_type not in _NAT_TYPES:
        raise ValueError(f"invalid nat_type: {nat_type!r}")
    return nat_type


# ─── frame types ────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """A single (host, port) the device advertises it can be reached at.

    `host` may be an IPv4 dotted-quad, an IPv6 string, or a DNS name.
    The rendezvous does not validate reachability; it stores what
    the device claims and lets the connecting peer's daemon dial."""
    host: str
    port: int

    def __post_init__(self) -> None:
        self.host = _validate_host(self.host, "endpoint.host")
        self.port = _require_int(self.port, "endpoint.port")
        if not 0 < self.port < 65536:
            raise ValueError("endpoint.port must be 1..65535")

    def to_json(self) -> dict:
        # Revalidate because dataclass fields are intentionally mutable.
        host = _validate_host(self.host, "endpoint.host")
        port = _require_int(self.port, "endpoint.port")
        if not 0 < port < 65536:
            raise ValueError("endpoint.port must be 1..65535")
        return {"host": host, "port": port}

    @classmethod
    def from_json(cls, d: dict) -> "Endpoint":
        d = _require_exact_keys(d, _ENDPOINT_KEYS, "endpoint")
        host = _validate_host(d["host"], "endpoint.host")
        port = _require_int(d["port"], "endpoint.port")
        if not 0 < port < 65536:
            raise ValueError("endpoint.port must be 1..65535")
        return cls(host=host, port=port)


@dataclass
class RegisterReq:
    """Device claims its current presence. Signed by the device's
    Ed25519 key. The rendezvous stores `(pubkey -> RegisterReq)` keyed
    on pubkey; subsequent registers from the same pubkey overwrite."""
    pubkey: bytes                         # Ed25519 public key (32 B)
    timestamp_ms: int                     # client wall-clock at sign time
    ttl_s: int                            # how long this registration should remain valid
    advertised_endpoints: list[Endpoint]  # what the device thinks its addresses are
    nat_type: str = "unknown"             # informational: open / restricted / symmetric / unknown
    capabilities: list[str] = field(default_factory=list)
    signature: bytes = b""

    def to_signing_dict(self) -> dict:
        pubkey = _require_bytes_exact(self.pubkey, 32, "pubkey")
        timestamp_ms = _validate_timestamp(self.timestamp_ms, "timestamp_ms")
        ttl_s = _require_int(self.ttl_s, "ttl_s")
        if not 0 < ttl_s <= MAX_REGISTRATION_TTL_S:
            raise ValueError(f"ttl_s out of range: {ttl_s}")
        endpoints = _validate_endpoints(self.advertised_endpoints)
        nat_type = _validate_nat_type(self.nat_type)
        capabilities = _validate_capabilities(self.capabilities)
        return {
            "v": PROTOCOL_VERSION,
            "type": "register",
            "pubkey_b64": _b64(pubkey),
            "timestamp_ms": timestamp_ms,
            "ttl_s": ttl_s,
            "advertised_endpoints": [e.to_json() for e in endpoints],
            "nat_type": nat_type,
            "capabilities": capabilities,
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(_require_bytes_exact(self.signature, 64, "signature"))
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "RegisterReq":
        d = _require_exact_keys(d, _REGISTER_KEYS, "register")
        if d["v"] != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {d['v']!r}")
        if d["type"] != "register":
            raise ValueError(f"unexpected type: {d['type']!r}")
        pubkey = _b64d(d["pubkey_b64"], expected_size=32, name="pubkey_b64")
        ttl_s = _require_int(d["ttl_s"], "ttl_s")
        if ttl_s <= 0 or ttl_s > MAX_REGISTRATION_TTL_S:
            raise ValueError(f"ttl_s out of range: {ttl_s}")
        eps_raw = d["advertised_endpoints"]
        if not isinstance(eps_raw, list) or len(eps_raw) > MAX_ADVERTISED_ENDPOINTS:
            raise ValueError("advertised_endpoints must be a list of length <= "
                             f"{MAX_ADVERTISED_ENDPOINTS}")
        eps = [Endpoint.from_json(e) for e in eps_raw]
        nat_type = _validate_nat_type(d["nat_type"])
        caps = _validate_capabilities(d["capabilities"])
        sig = _b64d(d["signature"], expected_size=64, name="signature")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_validate_timestamp(d["timestamp_ms"], "timestamp_ms"),
            ttl_s=ttl_s,
            advertised_endpoints=eps,
            nat_type=nat_type,
            capabilities=caps,
            signature=sig,
        )

    def verify(self) -> None:
        """Verify the signature; raises ValueError if invalid."""
        signing_dict = self.to_signing_dict()
        signature = _require_bytes_exact(self.signature, 64, "signature")
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                signature, _canonical_bytes(signing_dict)
            )
        except InvalidSignature:
            raise ValueError("register signature does not verify")


def sign_register(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    ttl_s: int,
    advertised_endpoints: list[Endpoint],
    nat_type: str = "unknown",
    capabilities: list[str] | None = None,
    timestamp_ms: int | None = None,
) -> RegisterReq:
    _require_matching_public_key(private_key, pubkey)
    req = RegisterReq(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
        ttl_s=ttl_s,
        advertised_endpoints=list(advertised_endpoints),
        nat_type=nat_type,
        capabilities=list(capabilities) if capabilities is not None else [],
    )
    signing_dict = req.to_signing_dict()
    sig = private_key.sign(_canonical_bytes(signing_dict))
    req.signature = sig
    return req


@dataclass
class RegisterAck:
    """Server's reply to a successful register. Tells the client the
    public IP:port the rendezvous observed (useful for the client's
    own NAT-type detection)."""
    observed_host: str
    observed_port: int
    server_time_ms: int
    expires_at_ms: int

    def to_wire(self) -> dict:
        host = _validate_host(self.observed_host, "observed_host")
        port = _require_port(self.observed_port, "observed_port")
        server_time_ms = _validate_timestamp(self.server_time_ms, "server_time_ms")
        expires_at_ms = _validate_timestamp(self.expires_at_ms, "expires_at_ms")
        if expires_at_ms < server_time_ms:
            raise ValueError("expires_at_ms must not precede server_time_ms")
        return {
            "v": PROTOCOL_VERSION,
            "type": "register_ack",
            "observed_host": host,
            "observed_port": port,
            "server_time_ms": server_time_ms,
            "expires_at_ms": expires_at_ms,
        }

    @classmethod
    def from_wire(cls, d: dict) -> "RegisterAck":
        d = _require_exact_keys(d, _REGISTER_ACK_KEYS, "register_ack")
        if d["v"] != PROTOCOL_VERSION or d["type"] != "register_ack":
            raise ValueError("not a register_ack")
        server_time_ms = _validate_timestamp(d["server_time_ms"], "server_time_ms")
        expires_at_ms = _validate_timestamp(d["expires_at_ms"], "expires_at_ms")
        if expires_at_ms < server_time_ms:
            raise ValueError("expires_at_ms must not precede server_time_ms")
        return cls(
            observed_host=_validate_host(d["observed_host"], "observed_host"),
            observed_port=_require_port(d["observed_port"], "observed_port"),
            server_time_ms=server_time_ms,
            expires_at_ms=expires_at_ms,
        )


@dataclass
class LookupAck:
    """Server's reply to a lookup. The looked-up pubkey's last-known
    presence, with both the rendezvous-observed endpoint and the
    self-advertised set the device wants peers to try."""
    pubkey: bytes
    observed_endpoint: Optional[Endpoint]
    advertised_endpoints: list[Endpoint]
    nat_type: str
    capabilities: list[str]
    expires_at_ms: int
    server_time_ms: int

    def to_wire(self) -> dict:
        pubkey = _require_bytes_exact(self.pubkey, 32, "pubkey")
        endpoints = _validate_endpoints(self.advertised_endpoints)
        observed = self.observed_endpoint
        if observed is not None and not isinstance(observed, Endpoint):
            raise ValueError("observed_endpoint must be an Endpoint or null")
        nat_type = _validate_nat_type(self.nat_type)
        capabilities = _validate_capabilities(self.capabilities)
        expires_at_ms = _validate_timestamp(self.expires_at_ms, "expires_at_ms")
        server_time_ms = _validate_timestamp(self.server_time_ms, "server_time_ms")
        return {
            "v": PROTOCOL_VERSION,
            "type": "lookup_ack",
            "pubkey_b64": _b64(pubkey),
            "observed_endpoint": (
                observed.to_json()
                if observed is not None
                else None
            ),
            "advertised_endpoints": [e.to_json() for e in endpoints],
            "nat_type": nat_type,
            "capabilities": capabilities,
            "expires_at_ms": expires_at_ms,
            "server_time_ms": server_time_ms,
        }

    @classmethod
    def from_wire(cls, d: dict) -> "LookupAck":
        d = _require_exact_keys(d, _LOOKUP_ACK_KEYS, "lookup_ack")
        if d["v"] != PROTOCOL_VERSION or d["type"] != "lookup_ack":
            raise ValueError("not a lookup_ack")
        pubkey = _b64d(d["pubkey_b64"], expected_size=32, name="pubkey_b64")
        oe = d["observed_endpoint"]
        observed = Endpoint.from_json(oe) if oe is not None else None
        adv_raw = d["advertised_endpoints"]
        if not isinstance(adv_raw, list) or len(adv_raw) > MAX_ADVERTISED_ENDPOINTS:
            raise ValueError(
                "advertised_endpoints must be a list of length <= "
                f"{MAX_ADVERTISED_ENDPOINTS}"
            )
        adv = [Endpoint.from_json(e) for e in adv_raw]
        caps = _validate_capabilities(d["capabilities"])
        return cls(
            pubkey=pubkey,
            observed_endpoint=observed,
            advertised_endpoints=adv,
            nat_type=_validate_nat_type(d["nat_type"]),
            capabilities=caps,
            expires_at_ms=_validate_timestamp(d["expires_at_ms"], "expires_at_ms"),
            server_time_ms=_validate_timestamp(d["server_time_ms"], "server_time_ms"),
        )


@dataclass
class RevokeReq:
    """Signed self-deletion."""
    pubkey: bytes
    timestamp_ms: int
    signature: bytes = b""

    def to_signing_dict(self) -> dict:
        pubkey = _require_bytes_exact(self.pubkey, 32, "pubkey")
        timestamp_ms = _validate_timestamp(self.timestamp_ms, "timestamp_ms")
        return {
            "v": PROTOCOL_VERSION,
            "type": "revoke",
            "pubkey_b64": _b64(pubkey),
            "timestamp_ms": timestamp_ms,
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(_require_bytes_exact(self.signature, 64, "signature"))
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "RevokeReq":
        d = _require_exact_keys(d, _REVOKE_KEYS, "revoke")
        if d["v"] != PROTOCOL_VERSION or d["type"] != "revoke":
            raise ValueError("not a revoke request")
        pubkey = _b64d(d["pubkey_b64"], expected_size=32, name="pubkey_b64")
        sig = _b64d(d["signature"], expected_size=64, name="signature")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_validate_timestamp(d["timestamp_ms"], "timestamp_ms"),
            signature=sig,
        )

    def verify(self) -> None:
        signing_dict = self.to_signing_dict()
        signature = _require_bytes_exact(self.signature, 64, "signature")
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                signature, _canonical_bytes(signing_dict)
            )
        except InvalidSignature:
            raise ValueError("revoke signature does not verify")


def sign_revoke(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    timestamp_ms: int | None = None,
) -> RevokeReq:
    _require_matching_public_key(private_key, pubkey)
    req = RevokeReq(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
    )
    signing_dict = req.to_signing_dict()
    req.signature = private_key.sign(_canonical_bytes(signing_dict))
    return req


# ─── replay window helper ───────────────────────────────────────────

def timestamp_within_replay_window(
    timestamp_ms: int,
    *,
    server_now_ms: int | None = None,
    window_ms: int = REPLAY_WINDOW_MS,
) -> bool:
    """Return True if the client-supplied timestamp is within the
    replay window relative to server time. The window is symmetric
    so honest clock skew in either direction is tolerated."""
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


# ─── input validation helpers ───────────────────────────────────────

def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v


def _require_bytes_exact(value: object, expected: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes")
    return value


def _require_port(value: object, name: str) -> int:
    port = _require_int(value, name)
    if not 0 < port < 65536:
        raise ValueError(f"{name} must be 1..65535")
    return port


def _validate_endpoints(value: object) -> list[Endpoint]:
    if not isinstance(value, list) or len(value) > MAX_ADVERTISED_ENDPOINTS:
        raise ValueError(
            "advertised_endpoints must be a list of length <= "
            f"{MAX_ADVERTISED_ENDPOINTS}"
        )
    endpoints: list[Endpoint] = []
    for endpoint in value:
        if not isinstance(endpoint, Endpoint):
            raise ValueError("advertised_endpoints must contain Endpoint values")
        # Validate mutated instances without reusing or coercing wire input.
        endpoint.to_json()
        endpoints.append(endpoint)
    return endpoints


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


def _is_valid_timestamp(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_TIMESTAMP_MS
    )
