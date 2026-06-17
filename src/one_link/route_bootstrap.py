"""Signed route bootstrap payloads for QR/audio/BLE control paths.

Slow paths should not carry files; they should carry tiny, authenticated route
hints that let two trusted devices create or repair a better path. This module
defines the compact payload used by QR codes, audio chirps, BLE adverts, and
future out-of-band transports.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import time
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from one_link._coerce import to_int

import blake3

from .identity import Identity, fingerprint_of, verify


BOOTSTRAP_MAGIC = "OLRB"
BOOTSTRAP_COMPRESSED_MAGIC = "OLRZ"
BOOTSTRAP_VERSION = 1
MAX_ENDPOINTS = 8
MAX_CAPABILITIES = 64
MAX_ENCODED_BYTES = 4096
MAX_TTL_S = 15 * 60
MAX_ADDRESS_BYTES = 256
MAX_KIND_BYTES = 32
MAX_ROUTE_BYTES = 32
MAX_TRANSPORT_BYTES = 32

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_CONTROL_ONLY_ROUTES = {"qr", "qr_control", "audio", "audio_control", "ble", "ble_control"}
_LOOPBACK_ROUTES = {"loopback"}
_LOCAL_ROUTES = {"lan", "wifi_direct", "private_hotspot", "ethernet", "peer_server"}
_INTERNET_ROUTES = {"webrtc", "relay", "sealed_relay", "internet"}
_OFFLINE_ROUTES = {"courier", "storage_courier"}
_EXPERIMENTAL_ROUTES = {"onefield", "lora", "sdr", "rf"}


@dataclass(frozen=True)
class RouteEndpointHint:
    kind: str
    address: str
    port: int | None = None
    priority: int = 100
    route: str = "lan"
    transport: str = "tcp"
    expires_ms: int | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        if not self.kind or not self.address:
            raise ValueError("endpoint kind and address are required")
        if self.port is not None and not (0 < int(self.port) <= 65535):
            raise ValueError("endpoint port must be 1..65535")
        kind = _clean_token(self.kind, "endpoint kind", max_len=MAX_KIND_BYTES)
        route = _clean_token(self.route or "lan", "endpoint route", max_len=MAX_ROUTE_BYTES)
        transport = _clean_token(
            self.transport or "tcp",
            "endpoint transport",
            max_len=MAX_TRANSPORT_BYTES,
        )
        address = _clean_address(self.address)
        _validate_endpoint_target(
            kind=kind,
            address=address,
            port=self.port,
            route=route,
            transport=transport,
        )
        out: dict[str, object] = {
            "kind": kind,
            "address": address,
            "priority": max(0, min(10_000, int(self.priority))),
            "route": route,
            "transport": transport,
        }
        if self.port is not None:
            out["port"] = int(self.port)
        if self.expires_ms is not None:
            out["expires_ms"] = max(0, int(self.expires_ms))
        clean_meta = _clean_mapping(self.metadata, max_items=16)
        if clean_meta:
            out["metadata"] = clean_meta
        return out


@dataclass(frozen=True)
class SignedRouteBootstrap:
    body: Mapping[str, object]
    signature_hex: str

    def to_dict(self) -> dict[str, object]:
        return {"body": dict(self.body), "signature": self.signature_hex}

    @property
    def issuer_pub_hex(self) -> str:
        return str(self.body.get("issuer_pub_hex") or "")

    @property
    def issuer_fp(self) -> str:
        return str(self.body.get("issuer_fp") or "")

    @property
    def expires_ms(self) -> int:
        return to_int(self.body.get("expires_ms") or 0)

    @property
    def endpoints(self) -> tuple[dict[str, object], ...]:
        raw = self.body.get("endpoints") or []
        if not isinstance(raw, list):
            return ()
        return tuple(e for e in raw if isinstance(e, dict))

    def verify(self, *, now_ms: int | None = None, expected_issuer_fp: str | None = None) -> None:
        verify_bootstrap(self, now_ms=now_ms, expected_issuer_fp=expected_issuer_fp)


def make_route_bootstrap(
    *,
    identity: Identity,
    endpoints: Iterable[RouteEndpointHint | Mapping[str, object]],
    capabilities: Iterable[str] = (),
    route_truth: Mapping[str, object] | None = None,
    ttl_s: int = 180,
    now_ms: int | None = None,
    nonce_hex: str | None = None,
) -> SignedRouteBootstrap:
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    ttl_s = max(5, min(MAX_TTL_S, int(ttl_s)))
    endpoint_dicts = [_endpoint_to_dict(e) for e in endpoints]
    if not endpoint_dicts:
        raise ValueError("at least one endpoint hint is required")
    if len(endpoint_dicts) > MAX_ENDPOINTS:
        raise ValueError(f"too many endpoint hints; max {MAX_ENDPOINTS}")
    caps = sorted({str(c)[:80] for c in capabilities if str(c).strip()})
    if len(caps) > MAX_CAPABILITIES:
        raise ValueError(f"too many capabilities; max {MAX_CAPABILITIES}")
    body: dict[str, object] = {
        "magic": BOOTSTRAP_MAGIC,
        "version": BOOTSTRAP_VERSION,
        "issued_ms": now_ms,
        "expires_ms": now_ms + ttl_s * 1000,
        "nonce": nonce_hex or secrets.token_hex(16),
        "issuer_pub_hex": identity.public_bytes.hex(),
        "issuer_fp": identity.fingerprint,
        "endpoints": endpoint_dicts,
        "capabilities": caps,
    }
    if route_truth:
        body["route_truth"] = _clean_mapping(route_truth, max_items=24)
    body["body_hash"] = blake3.blake3(_canonical_bytes({
        k: v for k, v in body.items() if k != "body_hash"
    })).hexdigest()
    signature = identity.sign(_signing_bytes(body)).hex()
    signed = SignedRouteBootstrap(body=body, signature_hex=signature)
    signed.verify(now_ms=now_ms)
    return signed


def encode_bootstrap(payload: SignedRouteBootstrap) -> str:
    raw = _canonical_bytes(payload.to_dict())
    if len(raw) > MAX_ENCODED_BYTES:
        raise ValueError(f"bootstrap payload too large: {len(raw)} bytes")
    return BOOTSTRAP_MAGIC + "1." + _b64u(raw)


def encode_bootstrap_compact(payload: SignedRouteBootstrap) -> str:
    """Compact token for QR/audio control paths.

    The signed payload is compressed after signing. Verification still checks
    the original canonical body hash and Ed25519 signature after decoding.
    """

    raw = _canonical_bytes(payload.to_dict())
    if len(raw) > MAX_ENCODED_BYTES:
        raise ValueError(f"bootstrap payload too large: {len(raw)} bytes")
    compressed = zlib.compress(raw, level=9)
    if len(compressed) >= len(raw):
        return encode_bootstrap(payload)
    return BOOTSTRAP_COMPRESSED_MAGIC + "1." + _b64u(compressed)


def decode_bootstrap(token: str, *, now_ms: int | None = None) -> SignedRouteBootstrap:
    compressed = False
    if token.startswith(BOOTSTRAP_MAGIC + "1."):
        encoded = token.split(".", 1)[1]
    elif token.startswith(BOOTSTRAP_COMPRESSED_MAGIC + "1."):
        compressed = True
        encoded = token.split(".", 1)[1]
    else:
        raise ValueError("not a One Link route bootstrap token")
    raw = _b64u_decode(encoded)
    if compressed:
        try:
            decomp = zlib.decompressobj()
            raw = decomp.decompress(raw, MAX_ENCODED_BYTES + 1)
            if decomp.unconsumed_tail or decomp.unused_data or len(raw) > MAX_ENCODED_BYTES:
                raise ValueError("compressed bootstrap payload too large")
        except Exception as exc:
            raise ValueError("invalid compressed bootstrap payload") from exc
    if len(raw) > MAX_ENCODED_BYTES:
        raise ValueError("bootstrap payload too large")
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError("invalid bootstrap JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("bootstrap payload must be an object")
    body = obj.get("body")
    signature = obj.get("signature")
    if not isinstance(body, dict) or not isinstance(signature, str):
        raise ValueError("bootstrap payload missing body/signature")
    payload = SignedRouteBootstrap(body=body, signature_hex=signature)
    payload.verify(now_ms=now_ms)
    return payload


def verify_bootstrap(
    payload: SignedRouteBootstrap,
    *,
    now_ms: int | None = None,
    expected_issuer_fp: str | None = None,
) -> None:
    body = dict(payload.body)
    if body.get("magic") != BOOTSTRAP_MAGIC:
        raise ValueError("bad bootstrap magic")
    if to_int(body.get("version") or 0) != BOOTSTRAP_VERSION:
        raise ValueError("unsupported bootstrap version")
    issuer_pub_hex = str(body.get("issuer_pub_hex") or "")
    try:
        issuer_pub = bytes.fromhex(issuer_pub_hex)
    except ValueError as exc:
        raise ValueError("issuer public key is not hex") from exc
    if len(issuer_pub) != 32:
        raise ValueError("issuer public key must be 32 bytes")
    issuer_fp = fingerprint_of(issuer_pub)
    if str(body.get("issuer_fp") or "") != issuer_fp:
        raise ValueError("issuer fingerprint mismatch")
    if expected_issuer_fp and issuer_fp != expected_issuer_fp:
        raise ValueError("unexpected bootstrap issuer")
    issued_ms = to_int(body.get("issued_ms") or 0)
    expires_ms = to_int(body.get("expires_ms") or 0)
    now_ms = int(now_ms if now_ms is not None else time.time() * 1000)
    if issued_ms <= 0 or expires_ms <= issued_ms:
        raise ValueError("invalid bootstrap time bounds")
    if expires_ms - issued_ms > MAX_TTL_S * 1000:
        raise ValueError("bootstrap TTL exceeds maximum")
    if now_ms > expires_ms:
        raise ValueError("bootstrap expired")
    if issued_ms - now_ms > 60_000:
        raise ValueError("bootstrap issued too far in the future")
    endpoints = body.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("bootstrap needs endpoint hints")
    if len(endpoints) > MAX_ENDPOINTS:
        raise ValueError("too many endpoint hints")
    for endpoint in endpoints:
        _validate_endpoint_dict(endpoint)
    caps = body.get("capabilities", [])
    if not isinstance(caps, list) or len(caps) > MAX_CAPABILITIES:
        raise ValueError("invalid capability list")
    claimed_hash = str(body.get("body_hash") or "")
    actual_hash = blake3.blake3(_canonical_bytes({
        k: v for k, v in body.items() if k != "body_hash"
    })).hexdigest()
    if claimed_hash != actual_hash:
        raise ValueError("bootstrap body hash mismatch")
    try:
        sig = bytes.fromhex(payload.signature_hex)
    except ValueError as exc:
        raise ValueError("bootstrap signature is not hex") from exc
    if len(sig) != 64:
        raise ValueError("bootstrap signature must be 64 bytes")
    if not verify(issuer_pub, sig, _signing_bytes(body)):
        raise ValueError("bootstrap signature invalid")


def _endpoint_to_dict(endpoint: RouteEndpointHint | Mapping[str, object]) -> dict[str, object]:
    if isinstance(endpoint, RouteEndpointHint):
        return endpoint.to_dict()
    return RouteEndpointHint(
        kind=str(endpoint.get("kind") or ""),
        address=str(endpoint.get("address") or ""),
        port=to_int(endpoint["port"]) if endpoint.get("port") is not None else None,
        priority=to_int(endpoint.get("priority") or 100),
        route=str(endpoint.get("route") or "lan"),
        transport=str(endpoint.get("transport") or "tcp"),
        expires_ms=(
            to_int(endpoint["expires_ms"]) if endpoint.get("expires_ms") is not None else None
        ),
        metadata=_md if isinstance((_md := endpoint.get("metadata")), Mapping) else {},
    ).to_dict()


def _validate_endpoint_dict(endpoint: object) -> None:
    if not isinstance(endpoint, dict):
        raise ValueError("endpoint hint must be an object")
    RouteEndpointHint(
        kind=str(endpoint.get("kind") or ""),
        address=str(endpoint.get("address") or ""),
        port=to_int(endpoint["port"]) if endpoint.get("port") is not None else None,
        priority=to_int(endpoint.get("priority") or 100),
        route=str(endpoint.get("route") or "lan"),
        transport=str(endpoint.get("transport") or "tcp"),
        expires_ms=(
            to_int(endpoint["expires_ms"]) if endpoint.get("expires_ms") is not None else None
        ),
        metadata=_md if isinstance((_md := endpoint.get("metadata")), Mapping) else {},
    ).to_dict()


def _clean_token(value: object, label: str, *, max_len: int) -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text.encode("utf-8")) > max_len:
        raise ValueError(f"{label} is too long")
    if not re.fullmatch(r"[a-z0-9_.-]+", text):
        raise ValueError(f"{label} contains unsafe characters")
    return text


def _clean_address(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("endpoint address is required")
    if len(text.encode("utf-8")) > MAX_ADDRESS_BYTES:
        raise ValueError("endpoint address is too long")
    if any(ch in text for ch in "\r\n\t /\\@#?"):
        raise ValueError("endpoint address contains unsafe characters")
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return text


def _validate_endpoint_target(
    *,
    kind: str,
    address: str,
    port: int | None,
    route: str,
    transport: str,
) -> None:
    route_family = route if route else kind
    if route_family in _CONTROL_ONLY_ROUTES:
        if port is not None:
            raise ValueError("control-only endpoint must not carry a TCP/UDP port")
        return
    if route_family in _OFFLINE_ROUTES:
        if port is not None:
            raise ValueError("offline courier endpoint must not carry a network port")
        return
    if route_family not in (
        _LOOPBACK_ROUTES | _LOCAL_ROUTES | _INTERNET_ROUTES | _EXPERIMENTAL_ROUTES
    ):
        raise ValueError(f"unsupported endpoint route: {route_family}")
    if transport not in {"tcp", "udp", "quic", "webrtc", "relay", "http3", "rf"}:
        raise ValueError(f"unsupported endpoint transport: {transport}")
    if port is None and transport in {"tcp", "udp", "quic", "http3"}:
        raise ValueError("network endpoint needs a port")
    parsed_ip = _parse_ip(address)
    if parsed_ip is not None:
        if route_family in _LOOPBACK_ROUTES:
            if not parsed_ip.is_loopback:
                raise ValueError("loopback route must use a loopback address")
            return
        if (
            parsed_ip.is_unspecified
            or parsed_ip.is_multicast
            or parsed_ip.is_reserved
            or parsed_ip.is_loopback
        ):
            raise ValueError("endpoint IP is not a safe routable target")
        if route_family in _LOCAL_ROUTES and not (
            parsed_ip.is_private or parsed_ip.is_link_local
        ):
            raise ValueError("local route must use a private or link-local address")
        if route_family in _INTERNET_ROUTES and parsed_ip.is_private:
            raise ValueError("internet route must not advertise private IPs")
        return
    if not _HOSTNAME_RE.fullmatch(address):
        raise ValueError("endpoint address is not a valid host name or IP")
    if route_family in _LOOPBACK_ROUTES:
        if address.rstrip(".").lower() != "localhost":
            raise ValueError("loopback route hostnames must be localhost")
        return
    if route_family in _LOCAL_ROUTES and not (
        address.endswith(".local") or "." not in address
    ):
        raise ValueError("local route hostnames must be local-only names")


def _parse_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(address)
    except ValueError:
        return None


def _clean_mapping(value: Mapping[str, object], *, max_items: int) -> dict[str, object]:
    out: dict[str, object] = {}
    for i, (k, v) in enumerate(sorted(value.items(), key=lambda kv: str(kv[0]))):
        if i >= max_items:
            break
        key = str(k)[:64]
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = str(v)[:512] if isinstance(v, str) else v
        elif isinstance(v, Mapping):
            out[key] = _clean_mapping(v, max_items=8)
        elif isinstance(v, (list, tuple)):
            out[key] = [
                item if isinstance(item, (int, float, bool)) or item is None else str(item)[:128]
                for item in list(v)[:16]
            ]
        else:
            out[key] = str(v)[:128]
    return out


def _signing_bytes(body: Mapping[str, object]) -> bytes:
    return b"OL1|ROUTE_BOOTSTRAP|v1|" + _canonical_bytes(body)


def _canonical_bytes(obj: Mapping[str, object]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))
