"""Signed route bootstrap payloads for QR/audio/BLE control paths.

Slow paths should not carry files; they should carry tiny, authenticated route
hints that let two trusted devices create or repair a better path. This module
defines the compact payload used by QR codes, audio chirps, BLE adverts, and
future out-of-band transports.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import secrets
import time
import zlib
from dataclasses import dataclass, field
from typing import Iterable, Mapping

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
MAX_CAPABILITY_BYTES = 80
MAX_TIMESTAMP_MS = (1 << 63) - 1
MAX_TOKEN_CHARS = (MAX_ENCODED_BYTES * 8 + 5) // 6

_OUTER_KEYS = frozenset({"body", "signature"})
_BODY_REQUIRED_KEYS = frozenset({
    "magic", "version", "issued_ms", "expires_ms", "nonce",
    "issuer_pub_hex", "issuer_fp", "endpoints", "capabilities", "body_hash",
})
_BODY_OPTIONAL_KEYS = frozenset({"route_truth"})
_ENDPOINT_REQUIRED_KEYS = frozenset({
    "kind", "address", "priority", "route", "transport",
})
_ENDPOINT_OPTIONAL_KEYS = frozenset({"port", "expires_ms", "metadata"})
_CAPABILITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")

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
        if self.port is not None:
            _require_int_range(self.port, "endpoint port", minimum=1, maximum=65535)
        kind = _clean_token(self.kind, "endpoint kind", max_len=MAX_KIND_BYTES)
        route = _clean_token(self.route, "endpoint route", max_len=MAX_ROUTE_BYTES)
        transport = _clean_token(
            self.transport,
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
            "priority": _require_int_range(
                self.priority, "endpoint priority", minimum=0, maximum=10_000
            ),
            "route": route,
            "transport": transport,
        }
        if self.port is not None:
            out["port"] = self.port
        if self.expires_ms is not None:
            out["expires_ms"] = _require_int_range(
                self.expires_ms,
                "endpoint expires_ms",
                minimum=0,
                maximum=MAX_TIMESTAMP_MS,
            )
        clean_meta = _clean_mapping(self.metadata, max_items=16, label="endpoint metadata")
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
        value = self.body.get("expires_ms")
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

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
    issued_ms = _require_int_range(
        now_ms if now_ms is not None else int(time.time() * 1000),
        "now_ms",
        minimum=1,
        maximum=MAX_TIMESTAMP_MS,
    )
    ttl_s = _require_int_range(ttl_s, "ttl_s", minimum=5, maximum=MAX_TTL_S)
    if issued_ms > MAX_TIMESTAMP_MS - ttl_s * 1000:
        raise ValueError("bootstrap expiry overflows timestamp range")
    endpoint_dicts = [_endpoint_to_dict(e) for e in endpoints]
    if not endpoint_dicts:
        raise ValueError("at least one endpoint hint is required")
    if len(endpoint_dicts) > MAX_ENDPOINTS:
        raise ValueError(f"too many endpoint hints; max {MAX_ENDPOINTS}")
    cap_values = list(capabilities)
    caps = sorted(set(_validate_capabilities(cap_values)))
    if len(caps) > MAX_CAPABILITIES:
        raise ValueError(f"too many capabilities; max {MAX_CAPABILITIES}")
    body: dict[str, object] = {
        "magic": BOOTSTRAP_MAGIC,
        "version": BOOTSTRAP_VERSION,
        "issued_ms": issued_ms,
        "expires_ms": issued_ms + ttl_s * 1000,
        "nonce": _validate_hex(
            nonce_hex if nonce_hex is not None else secrets.token_hex(16),
            expected_chars=32,
            label="nonce",
        ),
        "issuer_pub_hex": identity.public_bytes.hex(),
        "issuer_fp": identity.fingerprint,
        "endpoints": endpoint_dicts,
        "capabilities": caps,
    }
    if route_truth:
        body["route_truth"] = _clean_mapping(
            route_truth, max_items=24, label="route_truth"
        )
    body["body_hash"] = blake3.blake3(_canonical_bytes({
        k: v for k, v in body.items() if k != "body_hash"
    })).hexdigest()
    signature = identity.sign(_signing_bytes(body)).hex()
    signed = SignedRouteBootstrap(body=body, signature_hex=signature)
    signed.verify(now_ms=issued_ms)
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
    if not isinstance(token, str) or len(token) > MAX_TOKEN_CHARS + 6:
        raise ValueError("bootstrap token is invalid or too large")
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
            if (
                decomp.unconsumed_tail
                or decomp.unused_data
                or not decomp.eof
                or len(raw) > MAX_ENCODED_BYTES
            ):
                raise ValueError("compressed bootstrap payload too large")
        except (ValueError, zlib.error) as exc:
            raise ValueError("invalid compressed bootstrap payload") from exc
    if len(raw) > MAX_ENCODED_BYTES:
        raise ValueError("bootstrap payload too large")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid bootstrap JSON") from exc
    obj = _require_exact_keys(obj, _OUTER_KEYS, frozenset(), "bootstrap payload")
    if _canonical_bytes(obj) != raw:
        raise ValueError("bootstrap JSON must use canonical encoding")
    body = obj["body"]
    signature = obj["signature"]
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
    if not isinstance(payload, SignedRouteBootstrap):
        raise ValueError("bootstrap payload has invalid type")
    body = dict(payload.body)
    _require_exact_keys(body, _BODY_REQUIRED_KEYS, _BODY_OPTIONAL_KEYS, "bootstrap body")
    if body["magic"] != BOOTSTRAP_MAGIC:
        raise ValueError("bad bootstrap magic")
    if _require_int(body["version"], "version") != BOOTSTRAP_VERSION:
        raise ValueError("unsupported bootstrap version")
    issuer_pub_hex = _validate_hex(
        body["issuer_pub_hex"], expected_chars=64, label="issuer public key"
    )
    issuer_pub = bytes.fromhex(issuer_pub_hex)
    issuer_fp = fingerprint_of(issuer_pub)
    claimed_issuer_fp = _validate_hex(
        body["issuer_fp"], expected_chars=64, label="issuer fingerprint"
    )
    if claimed_issuer_fp != issuer_fp:
        raise ValueError("issuer fingerprint mismatch")
    if expected_issuer_fp is not None:
        expected_issuer_fp = _validate_hex(
            expected_issuer_fp,
            expected_chars=64,
            label="expected issuer fingerprint",
        )
    if expected_issuer_fp is not None and issuer_fp != expected_issuer_fp:
        raise ValueError("unexpected bootstrap issuer")
    issued_ms = _require_int_range(
        body["issued_ms"], "issued_ms", minimum=1, maximum=MAX_TIMESTAMP_MS
    )
    expires_ms = _require_int_range(
        body["expires_ms"], "expires_ms", minimum=1, maximum=MAX_TIMESTAMP_MS
    )
    current_ms = _require_int_range(
        now_ms if now_ms is not None else int(time.time() * 1000),
        "now_ms",
        minimum=0,
        maximum=MAX_TIMESTAMP_MS,
    )
    if issued_ms <= 0 or expires_ms <= issued_ms:
        raise ValueError("invalid bootstrap time bounds")
    if expires_ms - issued_ms > MAX_TTL_S * 1000:
        raise ValueError("bootstrap TTL exceeds maximum")
    if current_ms > expires_ms:
        raise ValueError("bootstrap expired")
    if issued_ms - current_ms > 60_000:
        raise ValueError("bootstrap issued too far in the future")
    _validate_hex(body["nonce"], expected_chars=32, label="nonce")
    endpoints = body["endpoints"]
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("bootstrap needs endpoint hints")
    if len(endpoints) > MAX_ENDPOINTS:
        raise ValueError("too many endpoint hints")
    for endpoint in endpoints:
        _validate_endpoint_dict(endpoint)
    caps = _validate_capabilities(body["capabilities"])
    if caps != sorted(set(caps)):
        raise ValueError("capability list must be sorted and unique")
    if "route_truth" in body:
        route_truth = body["route_truth"]
        if not isinstance(route_truth, Mapping):
            raise ValueError("route_truth must be an object")
        if _clean_mapping(route_truth, max_items=24, label="route_truth") != route_truth:
            raise ValueError("route_truth is not canonical")
    claimed_hash = _validate_hex(
        body["body_hash"], expected_chars=64, label="body_hash"
    )
    actual_hash = blake3.blake3(_canonical_bytes({
        k: v for k, v in body.items() if k != "body_hash"
    })).hexdigest()
    if claimed_hash != actual_hash:
        raise ValueError("bootstrap body hash mismatch")
    signature_hex = _validate_hex(
        payload.signature_hex,
        expected_chars=128,
        label="bootstrap signature",
    )
    sig = bytes.fromhex(signature_hex)
    if not verify(issuer_pub, sig, _signing_bytes(body)):
        raise ValueError("bootstrap signature invalid")


def _endpoint_to_dict(endpoint: RouteEndpointHint | Mapping[str, object]) -> dict[str, object]:
    if isinstance(endpoint, RouteEndpointHint):
        return endpoint.to_dict()
    if not isinstance(endpoint, Mapping):
        raise ValueError("endpoint hint must be an object")
    return RouteEndpointHint(
        kind=endpoint.get("kind"),  # type: ignore[arg-type]
        address=endpoint.get("address"),  # type: ignore[arg-type]
        port=endpoint["port"] if endpoint.get("port") is not None else None,  # type: ignore[arg-type]
        priority=endpoint.get("priority", 100),  # type: ignore[arg-type]
        route=endpoint.get("route", "lan"),  # type: ignore[arg-type]
        transport=endpoint.get("transport", "tcp"),  # type: ignore[arg-type]
        expires_ms=(
            endpoint["expires_ms"] if endpoint.get("expires_ms") is not None else None  # type: ignore[arg-type]
        ),
        metadata=(
            endpoint["metadata"]
            if "metadata" in endpoint and isinstance(endpoint["metadata"], Mapping)
            else {}
        ),
    ).to_dict()


def _validate_endpoint_dict(endpoint: object) -> None:
    if not isinstance(endpoint, dict):
        raise ValueError("endpoint hint must be an object")
    _require_exact_keys(
        endpoint,
        _ENDPOINT_REQUIRED_KEYS,
        _ENDPOINT_OPTIONAL_KEYS,
        "endpoint hint",
    )
    normalized = RouteEndpointHint(
        kind=endpoint["kind"],  # type: ignore[arg-type]
        address=endpoint["address"],  # type: ignore[arg-type]
        port=endpoint.get("port"),  # type: ignore[arg-type]
        priority=endpoint["priority"],  # type: ignore[arg-type]
        route=endpoint["route"],  # type: ignore[arg-type]
        transport=endpoint["transport"],  # type: ignore[arg-type]
        expires_ms=(
            endpoint["expires_ms"] if endpoint.get("expires_ms") is not None else None  # type: ignore[arg-type]
        ),
        metadata=(
            endpoint["metadata"]
            if "metadata" in endpoint and isinstance(endpoint["metadata"], Mapping)
            else {}
        ),
    ).to_dict()
    if normalized != endpoint:
        raise ValueError("endpoint hint is not canonical")


def _clean_token(value: object, label: str, *, max_len: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value
    if not text:
        raise ValueError(f"{label} is required")
    if len(text.encode("utf-8")) > max_len:
        raise ValueError(f"{label} is too long")
    if not re.fullmatch(r"[a-z0-9_.-]+", text):
        raise ValueError(f"{label} contains unsafe characters")
    return text


def _clean_address(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("endpoint address must be a string")
    text = value
    if not text:
        raise ValueError("endpoint address is required")
    if len(text.encode("utf-8")) > MAX_ADDRESS_BYTES:
        raise ValueError("endpoint address is too long")
    if any(ch in text for ch in "\r\n\t /\\@#?"):
        raise ValueError("endpoint address contains unsafe characters")
    if text != text.strip():
        raise ValueError("endpoint address must not contain surrounding whitespace")
    if text.startswith("[") or text.endswith("]"):
        raise ValueError("endpoint address must not use bracketed IPv6 form")
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


def _clean_mapping(
    value: Mapping[str, object],
    *,
    max_items: int,
    label: str,
    depth: int = 0,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    if len(value) > max_items:
        raise ValueError(f"{label} has too many fields")
    if depth > 3:
        raise ValueError(f"{label} nesting is too deep")
    out: dict[str, object] = {}
    for key, v in sorted(value.items(), key=lambda kv: repr(kv[0])):
        if not isinstance(key, str) or not key or len(key.encode("utf-8")) > 64:
            raise ValueError(f"{label} contains an invalid key")
        if any(ord(ch) < 0x20 for ch in key):
            raise ValueError(f"{label} contains an invalid key")
        if isinstance(v, str):
            if len(v.encode("utf-8")) > 512 or any(ord(ch) < 0x20 for ch in v):
                raise ValueError(f"{label}.{key} string is invalid or too long")
            out[key] = v
        elif isinstance(v, bool) or v is None:
            out[key] = v
        elif isinstance(v, int):
            if not -(1 << 63) <= v <= MAX_TIMESTAMP_MS:
                raise ValueError(f"{label}.{key} integer is out of range")
            out[key] = v
        elif isinstance(v, float):
            if not math.isfinite(v):
                raise ValueError(f"{label}.{key} number must be finite")
            out[key] = v
        elif isinstance(v, Mapping):
            out[key] = _clean_mapping(
                v,
                max_items=24,
                label=f"{label}.{key}",
                depth=depth + 1,
            )
        elif isinstance(v, (list, tuple)):
            if len(v) > 16:
                raise ValueError(f"{label}.{key} list is too long")
            normalized: list[object] = []
            for item in v:
                if isinstance(item, str):
                    if len(item.encode("utf-8")) > 128 or any(
                        ord(ch) < 0x20 for ch in item
                    ):
                        raise ValueError(f"{label}.{key} contains an invalid string")
                    normalized.append(item)
                elif isinstance(item, bool) or item is None:
                    normalized.append(item)
                elif isinstance(item, int):
                    if not -(1 << 63) <= item <= MAX_TIMESTAMP_MS:
                        raise ValueError(f"{label}.{key} integer is out of range")
                    normalized.append(item)
                elif isinstance(item, float) and math.isfinite(item):
                    normalized.append(item)
                else:
                    raise ValueError(f"{label}.{key} contains an unsupported value")
            out[key] = normalized
        else:
            raise ValueError(f"{label}.{key} contains an unsupported value")
    return out


def _signing_bytes(body: Mapping[str, object]) -> bytes:
    return b"OL1|ROUTE_BOOTSTRAP|v1|" + _canonical_bytes(body)


def _canonical_bytes(obj: Mapping[str, object]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(data: str) -> bytes:
    if not isinstance(data, str) or not data or len(data) > MAX_TOKEN_CHARS or "=" in data:
        raise ValueError("bootstrap token has invalid base64url length")
    try:
        encoded = data.encode("ascii")
        pad = b"=" * (-len(encoded) % 4)
        decoded = base64.b64decode(encoded + pad, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("bootstrap token is not canonical base64url") from exc
    if _b64u(decoded) != data:
        raise ValueError("bootstrap token is not canonical base64url")
    return decoded


def _require_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{label} must be an integer")
    return value


def _require_int_range(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    integer = _require_int(value, label)
    if not minimum <= integer <= maximum:
        raise ValueError(f"{label} out of range")
    return integer


def _validate_hex(value: object, *, expected_chars: int, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != expected_chars
        or re.fullmatch(r"[0-9a-f]+", value) is None
    ):
        raise ValueError(f"{label} must be {expected_chars} lowercase hex characters")
    return value


def _validate_capabilities(value: object) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_CAPABILITIES:
        raise ValueError("invalid capability list")
    result: list[str] = []
    for capability in value:
        if (
            not isinstance(capability, str)
            or len(capability.encode("utf-8")) > MAX_CAPABILITY_BYTES
            or _CAPABILITY_RE.fullmatch(capability) is None
        ):
            raise ValueError("capability list contains an invalid token")
        result.append(capability)
    return result


def _require_exact_keys(
    value: object,
    required: frozenset[str],
    optional: frozenset[str],
    label: str,
) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        raise ValueError(
            f"{label} fields invalid "
            f"(missing={sorted(missing, key=repr)}, unknown={sorted(unknown, key=repr)})"
        )
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result
