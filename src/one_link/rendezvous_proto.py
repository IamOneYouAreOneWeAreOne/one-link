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
  - unknown JSON fields are tolerated on the rendezvous (ignored)
    but the signature covers only the fields explicitly named below
"""
from __future__ import annotations

import base64
import json
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


# ─── helpers ────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


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


# ─── frame types ────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """A single (host, port) the device advertises it can be reached at.

    `host` may be an IPv4 dotted-quad, an IPv6 string, or a DNS name.
    The rendezvous does not validate reachability; it stores what
    the device claims and lets the connecting peer's daemon dial."""
    host: str
    port: int

    def to_json(self) -> dict:
        return {"host": str(self.host), "port": int(self.port)}

    @classmethod
    def from_json(cls, d: dict) -> "Endpoint":
        if not isinstance(d, dict):
            raise ValueError("endpoint must be an object")
        host = d.get("host")
        port = d.get("port")
        if not isinstance(host, str) or not host:
            raise ValueError("endpoint.host required")
        if not isinstance(port, int) or not (0 < port < 65536):
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
        return {
            "v": PROTOCOL_VERSION,
            "type": "register",
            "pubkey_b64": _b64(self.pubkey),
            "timestamp_ms": int(self.timestamp_ms),
            "ttl_s": int(self.ttl_s),
            "advertised_endpoints": [e.to_json() for e in self.advertised_endpoints],
            "nat_type": str(self.nat_type),
            "capabilities": list(self.capabilities),
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(self.signature)
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "RegisterReq":
        _require_str(d.get("v"), "v")
        if d.get("v") != PROTOCOL_VERSION:
            raise ValueError(f"unsupported protocol version: {d.get('v')!r}")
        if d.get("type") != "register":
            raise ValueError(f"unexpected type: {d.get('type')!r}")
        pubkey = _b64d(_require_str(d.get("pubkey_b64"), "pubkey_b64"))
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        ttl_s = _require_int(d.get("ttl_s"), "ttl_s")
        if ttl_s <= 0 or ttl_s > MAX_REGISTRATION_TTL_S:
            raise ValueError(f"ttl_s out of range: {ttl_s}")
        eps_raw = d.get("advertised_endpoints") or []
        if not isinstance(eps_raw, list) or len(eps_raw) > MAX_ADVERTISED_ENDPOINTS:
            raise ValueError("advertised_endpoints must be a list of length <= "
                             f"{MAX_ADVERTISED_ENDPOINTS}")
        eps = [Endpoint.from_json(e) for e in eps_raw]
        nat_type = str(d.get("nat_type") or "unknown")
        if nat_type not in ("open", "restricted", "symmetric", "unknown"):
            raise ValueError(f"invalid nat_type: {nat_type!r}")
        caps = d.get("capabilities") or []
        if not isinstance(caps, list) or any(not isinstance(c, str) for c in caps):
            raise ValueError("capabilities must be a list of strings")
        sig = _b64d(_require_str(d.get("signature"), "signature"))
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_require_int(d.get("timestamp_ms"), "timestamp_ms"),
            ttl_s=ttl_s,
            advertised_endpoints=eps,
            nat_type=nat_type,
            capabilities=[str(c) for c in caps],
            signature=sig,
        )

    def verify(self) -> None:
        """Verify the signature; raises ValueError if invalid."""
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                self.signature, _canonical_bytes(self.to_signing_dict())
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
    req = RegisterReq(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
        ttl_s=ttl_s,
        advertised_endpoints=list(advertised_endpoints),
        nat_type=nat_type,
        capabilities=list(capabilities or []),
    )
    sig = private_key.sign(_canonical_bytes(req.to_signing_dict()))
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
        return {
            "v": PROTOCOL_VERSION,
            "type": "register_ack",
            "observed_host": self.observed_host,
            "observed_port": int(self.observed_port),
            "server_time_ms": int(self.server_time_ms),
            "expires_at_ms": int(self.expires_at_ms),
        }

    @classmethod
    def from_wire(cls, d: dict) -> "RegisterAck":
        if d.get("v") != PROTOCOL_VERSION or d.get("type") != "register_ack":
            raise ValueError("not a register_ack")
        return cls(
            observed_host=_require_str(d.get("observed_host"), "observed_host"),
            observed_port=_require_int(d.get("observed_port"), "observed_port"),
            server_time_ms=_require_int(d.get("server_time_ms"), "server_time_ms"),
            expires_at_ms=_require_int(d.get("expires_at_ms"), "expires_at_ms"),
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
        return {
            "v": PROTOCOL_VERSION,
            "type": "lookup_ack",
            "pubkey_b64": _b64(self.pubkey),
            "observed_endpoint": (
                self.observed_endpoint.to_json()
                if self.observed_endpoint is not None
                else None
            ),
            "advertised_endpoints": [e.to_json() for e in self.advertised_endpoints],
            "nat_type": self.nat_type,
            "capabilities": list(self.capabilities),
            "expires_at_ms": int(self.expires_at_ms),
            "server_time_ms": int(self.server_time_ms),
        }

    @classmethod
    def from_wire(cls, d: dict) -> "LookupAck":
        if d.get("v") != PROTOCOL_VERSION or d.get("type") != "lookup_ack":
            raise ValueError("not a lookup_ack")
        pubkey = _b64d(_require_str(d.get("pubkey_b64"), "pubkey_b64"))
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        oe = d.get("observed_endpoint")
        observed = Endpoint.from_json(oe) if oe is not None else None
        adv_raw = d.get("advertised_endpoints") or []
        if not isinstance(adv_raw, list):
            raise ValueError("advertised_endpoints must be a list")
        adv = [Endpoint.from_json(e) for e in adv_raw]
        caps = d.get("capabilities") or []
        if not isinstance(caps, list):
            raise ValueError("capabilities must be a list")
        return cls(
            pubkey=pubkey,
            observed_endpoint=observed,
            advertised_endpoints=adv,
            nat_type=str(d.get("nat_type") or "unknown"),
            capabilities=[str(c) for c in caps],
            expires_at_ms=_require_int(d.get("expires_at_ms"), "expires_at_ms"),
            server_time_ms=_require_int(d.get("server_time_ms"), "server_time_ms"),
        )


@dataclass
class RevokeReq:
    """Signed self-deletion."""
    pubkey: bytes
    timestamp_ms: int
    signature: bytes = b""

    def to_signing_dict(self) -> dict:
        return {
            "v": PROTOCOL_VERSION,
            "type": "revoke",
            "pubkey_b64": _b64(self.pubkey),
            "timestamp_ms": int(self.timestamp_ms),
        }

    def to_wire(self) -> dict:
        d = self.to_signing_dict()
        d["signature"] = _b64(self.signature)
        return d

    @classmethod
    def from_wire(cls, d: dict) -> "RevokeReq":
        if d.get("v") != PROTOCOL_VERSION or d.get("type") != "revoke":
            raise ValueError("not a revoke request")
        pubkey = _b64d(_require_str(d.get("pubkey_b64"), "pubkey_b64"))
        if len(pubkey) != 32:
            raise ValueError("pubkey must be 32 bytes")
        sig = _b64d(_require_str(d.get("signature"), "signature"))
        if len(sig) != 64:
            raise ValueError("signature must be 64 bytes")
        return cls(
            pubkey=pubkey,
            timestamp_ms=_require_int(d.get("timestamp_ms"), "timestamp_ms"),
            signature=sig,
        )

    def verify(self) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self.pubkey).verify(
                self.signature, _canonical_bytes(self.to_signing_dict())
            )
        except InvalidSignature:
            raise ValueError("revoke signature does not verify")


def sign_revoke(
    *,
    private_key: Ed25519PrivateKey,
    pubkey: bytes,
    timestamp_ms: int | None = None,
) -> RevokeReq:
    req = RevokeReq(
        pubkey=pubkey,
        timestamp_ms=timestamp_ms if timestamp_ms is not None else now_ms(),
    )
    req.signature = private_key.sign(_canonical_bytes(req.to_signing_dict()))
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
    return abs(int(now) - int(timestamp_ms)) <= window_ms


# ─── input validation helpers ───────────────────────────────────────

def _require_str(v, name: str) -> str:
    if not isinstance(v, str):
        raise ValueError(f"{name} must be a string")
    return v


def _require_int(v, name: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise ValueError(f"{name} must be an integer")
    return v
