"""Pairwise-blinded rendezvous routing for the live WebSocket relay.

The legacy relay route is a recipient Ed25519 public key embedded in the URL.
That is sufficient for delivery, but it gives the relay operator a stable,
public recipient identifier.  This module replaces that address with a
short-lived value derived from a static X25519 agreement between two *already
paired* Ed25519 identities.

The relay sees only:

* a random-looking, epoch-scoped routing tag;
* a deterministic epoch-scoped Ed25519 verification key; and
* freshness nonces, expiry times, and opaque encrypted channel bytes.

It never receives either participant's identity public key in the v2 routing
protocol.  Each tag is self-certified from its epoch verification key, and
both registration and connection are signed by the corresponding private key.
A party that has merely observed a route tag therefore cannot claim it while
vacant, consume listener capacity, replay a captured connector proof, or
replace the listener.

This is recipient-*identifier* blinding, not global anonymity.  A relay still
observes socket addresses, timing, byte counts, and the fact that two relay
sockets exchanged traffic.  Tags rotate, but a persistent listener socket and
its atomic refresh sets let the same relay correlate that listener's tags
within and across epochs; route-set cardinality also reveals an approximate
paired-peer count.  Independent multi-hop relays and traffic-analysis
resistance are separate properties.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


ROUTING_PROTOCOL_VERSION = "OL-RELAY-ROUTE-1"
ROUTING_EPOCH_MS = 10 * 60 * 1000
ROUTING_GRACE_MS = 2 * 60 * 1000
ROUTING_REPLAY_WINDOW_MS = 60 * 1000

ROUTE_TAG_BYTES = 32
ROUTE_AUTH_PUBLIC_BYTES = 32
ROUTE_NONCE_BYTES = 16
ROUTE_SIGNATURE_BYTES = 64
ROUTE_SET_DIGEST_BYTES = 32

# The daemon itself admits at most 256 live peer connections.  One listener
# advertises current + next routes and, during the short rotation grace, the
# immediately previous route for each paired peer.
MAX_PAIRED_ROUTE_PEERS = 256
MAX_ROUTE_ENTRIES = MAX_PAIRED_ROUTE_PEERS * 3
ROUTE_AUTH_MAX_BYTES = 512 * 1024
MAX_TIMESTAMP_MS = (1 << 63) - 1

_ROOT_INFO = b"OL/relay-rendezvous/root/v1\x00"
_TAG_INFO = b"OL/relay-rendezvous/tag/v1\x00"
_AUTH_INFO = b"OL/relay-rendezvous/auth/v1\x00"
_SET_INFO = b"OL/relay-rendezvous/route-set/v1\x00"

_LISTEN_KEYS = frozenset(
    {"v", "t", "timestamp_ms", "nonce_b64", "routes_digest_b64", "routes"}
)
_ROUTE_KEYS = frozenset(
    {
        "epoch",
        "route_tag_b64",
        "auth_pub_b64",
        "expires_at_ms",
        "signature_b64",
    }
)
_CONNECT_KEYS = frozenset(
    {
        "v",
        "t",
        "route_tag_b64",
        "epoch",
        "timestamp_ms",
        "nonce_b64",
        "signature_b64",
    }
)


def now_ms() -> int:
    return int(time.time() * 1000)


def epoch_for_timestamp(timestamp_ms: int) -> int:
    timestamp = _timestamp(timestamp_ms, "timestamp_ms")
    return timestamp // ROUTING_EPOCH_MS


def route_expiry_ms(epoch: int) -> int:
    epoch_value = _nonnegative_int(epoch, "epoch")
    expiry = (epoch_value + 1) * ROUTING_EPOCH_MS + ROUTING_GRACE_MS
    if expiry > MAX_TIMESTAMP_MS:
        raise ValueError("route expiry exceeds protocol timestamp range")
    return expiry


def route_tag_for_authority(*, auth_public: bytes, epoch: int) -> bytes:
    """Return the self-certifying route tag for one epoch authority.

    The relay can verify this public relation without learning either paired
    identity. An observer cannot claim a vacant tag with a new signing key:
    changing the verification key necessarily changes the tag, while keeping
    the genuine key requires forging its Ed25519 signature.
    """

    authority = _bytes_exact(auth_public, ROUTE_AUTH_PUBLIC_BYTES, "auth_public")
    epoch_value = _nonnegative_int(epoch, "epoch")
    if epoch_value > (1 << 64) - 1:
        raise ValueError("epoch exceeds protocol u64 range")
    return hashlib.sha256(
        _TAG_INFO + struct.pack(">Q", epoch_value) + authority
    ).digest()


@dataclass(frozen=True)
class DerivedRoute:
    """One direction-specific, epoch-scoped pairwise relay route."""

    epoch: int
    route_tag: bytes
    auth_private: Ed25519PrivateKey
    auth_public: bytes
    expires_at_ms: int


@dataclass(frozen=True)
class RouteRegistration:
    epoch: int
    route_tag: bytes
    auth_public: bytes
    expires_at_ms: int
    signature: bytes

    def unsigned_wire(self) -> dict[str, object]:
        return {
            "epoch": _nonnegative_int(self.epoch, "epoch"),
            "route_tag_b64": _b64(_bytes_exact(self.route_tag, ROUTE_TAG_BYTES, "route_tag")),
            "auth_pub_b64": _b64(
                _bytes_exact(self.auth_public, ROUTE_AUTH_PUBLIC_BYTES, "auth_public")
            ),
            "expires_at_ms": _timestamp(self.expires_at_ms, "expires_at_ms"),
        }

    def to_wire(self) -> dict[str, object]:
        value = self.unsigned_wire()
        value["signature_b64"] = _b64(
            _bytes_exact(self.signature, ROUTE_SIGNATURE_BYTES, "signature")
        )
        return value

    @classmethod
    def from_wire(cls, value: object) -> "RouteRegistration":
        doc = _exact_dict(value, _ROUTE_KEYS, "route registration")
        return cls(
            epoch=_nonnegative_int(doc["epoch"], "epoch"),
            route_tag=_b64d(
                doc["route_tag_b64"], expected_size=ROUTE_TAG_BYTES, name="route_tag_b64"
            ),
            auth_public=_b64d(
                doc["auth_pub_b64"],
                expected_size=ROUTE_AUTH_PUBLIC_BYTES,
                name="auth_pub_b64",
            ),
            expires_at_ms=_timestamp(doc["expires_at_ms"], "expires_at_ms"),
            signature=_b64d(
                doc["signature_b64"],
                expected_size=ROUTE_SIGNATURE_BYTES,
                name="signature_b64",
            ),
        )


@dataclass(frozen=True)
class RouteListenAuth:
    timestamp_ms: int
    nonce: bytes
    routes_digest: bytes
    routes: tuple[RouteRegistration, ...]

    def to_wire(self) -> dict[str, object]:
        doc: dict[str, object] = {
            "v": ROUTING_PROTOCOL_VERSION,
            "t": "route_listen_auth",
            "timestamp_ms": _timestamp(self.timestamp_ms, "timestamp_ms"),
            "nonce_b64": _b64(_bytes_exact(self.nonce, ROUTE_NONCE_BYTES, "nonce")),
            "routes_digest_b64": _b64(
                _bytes_exact(self.routes_digest, ROUTE_SET_DIGEST_BYTES, "routes_digest")
            ),
            "routes": [route.to_wire() for route in self.routes],
        }
        encoded = _canonical(doc)
        if len(encoded) > ROUTE_AUTH_MAX_BYTES:
            raise ValueError(
                f"route listen auth exceeds {ROUTE_AUTH_MAX_BYTES} byte wire limit"
            )
        return doc

    @classmethod
    def from_wire(cls, value: object) -> "RouteListenAuth":
        doc = _exact_dict(value, _LISTEN_KEYS, "route listen auth")
        if doc["v"] != ROUTING_PROTOCOL_VERSION:
            raise ValueError("unsupported blinded relay routing version")
        if doc["t"] not in {"route_listen_auth", "route_refresh"}:
            raise ValueError("unexpected blinded relay listen auth type")
        raw_routes = doc["routes"]
        if not isinstance(raw_routes, list):
            raise ValueError("routes must be an array")
        if not 1 <= len(raw_routes) <= MAX_ROUTE_ENTRIES:
            raise ValueError(
                f"routes must contain 1 through {MAX_ROUTE_ENTRIES} entries"
            )
        routes = tuple(RouteRegistration.from_wire(route) for route in raw_routes)
        auth = cls(
            timestamp_ms=_timestamp(doc["timestamp_ms"], "timestamp_ms"),
            nonce=_b64d(
                doc["nonce_b64"], expected_size=ROUTE_NONCE_BYTES, name="nonce_b64"
            ),
            routes_digest=_b64d(
                doc["routes_digest_b64"],
                expected_size=ROUTE_SET_DIGEST_BYTES,
                name="routes_digest_b64",
            ),
            routes=routes,
        )
        # Re-encoding is also the exact bounded-size check after parsing.
        auth.to_wire()
        return auth

    def verify(self, *, server_now_ms: int | None = None) -> None:
        current = now_ms() if server_now_ms is None else _timestamp(server_now_ms, "server_now_ms")
        if abs(current - self.timestamp_ms) > ROUTING_REPLAY_WINDOW_MS:
            raise ValueError("route listen auth timestamp outside replay window")
        expected_digest = _routes_digest(self.routes)
        if not secrets.compare_digest(expected_digest, self.routes_digest):
            raise ValueError("route set digest does not match route entries")

        current_epoch = epoch_for_timestamp(current)
        seen_tags: set[bytes] = set()
        for route in self.routes:
            if route.route_tag in seen_tags:
                raise ValueError("duplicate routing tag in listen auth")
            seen_tags.add(route.route_tag)
            if route.epoch not in {current_epoch - 1, current_epoch, current_epoch + 1}:
                raise ValueError("route epoch outside accepted rotation window")
            if route.expires_at_ms != route_expiry_ms(route.epoch):
                raise ValueError("route expiry is not canonical for its epoch")
            if route.expires_at_ms <= current:
                raise ValueError("route registration has expired")
            expected_tag = route_tag_for_authority(
                auth_public=route.auth_public,
                epoch=route.epoch,
            )
            if not secrets.compare_digest(route.route_tag, expected_tag):
                raise ValueError("routing tag is not self-certified by epoch authority")
            signed = _route_registration_signing_bytes(
                timestamp_ms=self.timestamp_ms,
                nonce=self.nonce,
                routes_digest=self.routes_digest,
                route=route,
            )
            try:
                Ed25519PublicKey.from_public_bytes(route.auth_public).verify(
                    route.signature, signed
                )
            except InvalidSignature:
                raise ValueError("route registration signature does not verify") from None


@dataclass(frozen=True)
class RouteConnectAuth:
    route_tag: bytes
    epoch: int
    timestamp_ms: int
    nonce: bytes
    signature: bytes

    def unsigned_wire(self) -> dict[str, object]:
        return {
            "v": ROUTING_PROTOCOL_VERSION,
            "t": "route_connect_auth",
            "route_tag_b64": _b64(
                _bytes_exact(self.route_tag, ROUTE_TAG_BYTES, "route_tag")
            ),
            "epoch": _nonnegative_int(self.epoch, "epoch"),
            "timestamp_ms": _timestamp(self.timestamp_ms, "timestamp_ms"),
            "nonce_b64": _b64(_bytes_exact(self.nonce, ROUTE_NONCE_BYTES, "nonce")),
        }

    def to_wire(self) -> dict[str, object]:
        doc = self.unsigned_wire()
        doc["signature_b64"] = _b64(
            _bytes_exact(self.signature, ROUTE_SIGNATURE_BYTES, "signature")
        )
        return doc

    @classmethod
    def from_wire(cls, value: object) -> "RouteConnectAuth":
        doc = _exact_dict(value, _CONNECT_KEYS, "route connect auth")
        if doc["v"] != ROUTING_PROTOCOL_VERSION:
            raise ValueError("unsupported blinded relay routing version")
        if doc["t"] != "route_connect_auth":
            raise ValueError("unexpected blinded relay connect auth type")
        return cls(
            route_tag=_b64d(
                doc["route_tag_b64"], expected_size=ROUTE_TAG_BYTES, name="route_tag_b64"
            ),
            epoch=_nonnegative_int(doc["epoch"], "epoch"),
            timestamp_ms=_timestamp(doc["timestamp_ms"], "timestamp_ms"),
            nonce=_b64d(
                doc["nonce_b64"], expected_size=ROUTE_NONCE_BYTES, name="nonce_b64"
            ),
            signature=_b64d(
                doc["signature_b64"],
                expected_size=ROUTE_SIGNATURE_BYTES,
                name="signature_b64",
            ),
        )

    def verify(
        self,
        *,
        expected_route_tag: bytes,
        expected_auth_public: bytes,
        expires_at_ms: int,
        server_now_ms: int | None = None,
    ) -> None:
        current = now_ms() if server_now_ms is None else _timestamp(server_now_ms, "server_now_ms")
        expected_tag = _bytes_exact(expected_route_tag, ROUTE_TAG_BYTES, "expected_route_tag")
        if not secrets.compare_digest(self.route_tag, expected_tag):
            raise ValueError("connector proof routing tag mismatch")
        expiry = _timestamp(expires_at_ms, "expires_at_ms")
        if current >= expiry:
            raise ValueError("connector route has expired")
        if route_expiry_ms(self.epoch) != expiry:
            raise ValueError("connector epoch does not match registered route")
        if abs(current - self.timestamp_ms) > ROUTING_REPLAY_WINDOW_MS:
            raise ValueError("route connector timestamp outside replay window")
        auth_public = _bytes_exact(
            expected_auth_public, ROUTE_AUTH_PUBLIC_BYTES, "expected_auth_public"
        )
        certified_tag = route_tag_for_authority(
            auth_public=auth_public,
            epoch=self.epoch,
        )
        if not secrets.compare_digest(expected_tag, certified_tag):
            raise ValueError("connector route is not self-certified by epoch authority")
        try:
            Ed25519PublicKey.from_public_bytes(auth_public).verify(
                self.signature, _canonical(self.unsigned_wire())
            )
        except InvalidSignature:
            raise ValueError("route connector signature does not verify") from None


def derive_route(
    *,
    local_private_key: Ed25519PrivateKey,
    local_public_key: bytes,
    peer_public_key: bytes,
    recipient_public_key: bytes,
    epoch: int,
) -> DerivedRoute:
    """Derive the same directional route at both ends of a paired link."""

    local_public, peer_public, root = _derive_pairwise_route_root(
        local_private_key=local_private_key,
        local_public_key=local_public_key,
        peer_public_key=peer_public_key,
    )
    recipient_public = _bytes_exact(recipient_public_key, 32, "recipient_public_key")
    if recipient_public not in {local_public, peer_public}:
        raise ValueError("recipient_public_key must be one of the paired identities")
    return _derive_route_from_root(
        root=root,
        recipient_public_key=recipient_public,
        epoch=epoch,
    )


def _derive_pairwise_route_root(
    *,
    local_private_key: Ed25519PrivateKey,
    local_public_key: bytes,
    peer_public_key: bytes,
) -> tuple[bytes, bytes, bytes]:
    local_public = _matching_identity(local_private_key, local_public_key)
    peer_public = _bytes_exact(peer_public_key, 32, "peer_public_key")
    if local_public == peer_public:
        raise ValueError("relay route requires two distinct paired identities")
    shared = _pairwise_ecdh(local_private_key.private_bytes_raw(), peer_public)
    first, second = sorted((local_public, peer_public))
    root = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(_ROOT_INFO + first + second).digest(),
        info=_ROOT_INFO + first + second,
    ).derive(shared)
    return local_public, peer_public, root


def _derive_route_from_root(
    *,
    root: bytes,
    recipient_public_key: bytes,
    epoch: int,
) -> DerivedRoute:
    root_value = _bytes_exact(root, 32, "pairwise route root")
    recipient_public = _bytes_exact(
        recipient_public_key, 32, "recipient_public_key"
    )
    epoch_value = _nonnegative_int(epoch, "epoch")
    expires_at_ms = route_expiry_ms(epoch_value)
    epoch_bytes = struct.pack(">Q", epoch_value)
    auth_seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_AUTH_INFO + epoch_bytes + recipient_public,
    ).derive(root_value)
    auth_private = Ed25519PrivateKey.from_private_bytes(auth_seed)
    auth_public = auth_private.public_key().public_bytes_raw()
    route_tag = route_tag_for_authority(
        auth_public=auth_public,
        epoch=epoch_value,
    )
    return DerivedRoute(
        epoch=epoch_value,
        route_tag=route_tag,
        auth_private=auth_private,
        auth_public=auth_public,
        expires_at_ms=expires_at_ms,
    )


def listener_route_epochs(*, at_ms: int | None = None) -> tuple[int, ...]:
    """Return canonical listener epochs: current, next, and grace previous."""

    current_time = now_ms() if at_ms is None else _timestamp(at_ms, "at_ms")
    current = epoch_for_timestamp(current_time)
    epochs = [current, current + 1]
    if current > 0 and current_time < route_expiry_ms(current - 1):
        epochs.append(current - 1)
    return tuple(epochs)


def dial_route_epochs(*, at_ms: int | None = None) -> tuple[int, ...]:
    """Current-first candidates tolerating one epoch of peer clock skew."""

    current_time = now_ms() if at_ms is None else _timestamp(at_ms, "at_ms")
    current = epoch_for_timestamp(current_time)
    epochs = [current]
    if current > 0:
        epochs.append(current - 1)
    epochs.append(current + 1)
    return tuple(epochs)


def build_route_listen_auth(
    *,
    local_private_key: Ed25519PrivateKey,
    local_public_key: bytes,
    paired_peer_public_keys: Iterable[bytes],
    timestamp_ms: int | None = None,
    nonce: bytes | None = None,
) -> RouteListenAuth:
    timestamp = now_ms() if timestamp_ms is None else _timestamp(timestamp_ms, "timestamp_ms")
    local_public = _matching_identity(local_private_key, local_public_key)
    unique_peers: list[bytes] = []
    seen: set[bytes] = set()
    for value in paired_peer_public_keys:
        peer = _bytes_exact(value, 32, "paired peer public key")
        if peer == local_public or peer in seen:
            continue
        seen.add(peer)
        unique_peers.append(peer)
    unique_peers.sort()
    if not unique_peers:
        raise ValueError("blinded relay listener requires at least one paired peer")
    if len(unique_peers) > MAX_PAIRED_ROUTE_PEERS:
        raise ValueError(
            f"paired relay route count exceeds {MAX_PAIRED_ROUTE_PEERS} peer bound"
        )

    nonce_value = secrets.token_bytes(ROUTE_NONCE_BYTES) if nonce is None else _bytes_exact(
        nonce, ROUTE_NONCE_BYTES, "nonce"
    )
    route_epochs = listener_route_epochs(at_ms=timestamp)
    derived: list[DerivedRoute] = []
    for peer in unique_peers:
        _local, _peer, root = _derive_pairwise_route_root(
            local_private_key=local_private_key,
            local_public_key=local_public,
            peer_public_key=peer,
        )
        derived.extend(
            _derive_route_from_root(
                root=root,
                recipient_public_key=local_public,
                epoch=epoch,
            )
            for epoch in route_epochs
        )
    unsigned = tuple(
        RouteRegistration(
            epoch=route.epoch,
            route_tag=route.route_tag,
            auth_public=route.auth_public,
            expires_at_ms=route.expires_at_ms,
            signature=b"\x00" * ROUTE_SIGNATURE_BYTES,
        )
        for route in sorted(derived, key=lambda item: item.route_tag)
    )
    routes_digest = _routes_digest(unsigned)
    signed_routes: list[RouteRegistration] = []
    private_by_tag = {route.route_tag: route.auth_private for route in derived}
    for route in unsigned:
        signature = private_by_tag[route.route_tag].sign(
            _route_registration_signing_bytes(
                timestamp_ms=timestamp,
                nonce=nonce_value,
                routes_digest=routes_digest,
                route=route,
            )
        )
        signed_routes.append(
            RouteRegistration(
                epoch=route.epoch,
                route_tag=route.route_tag,
                auth_public=route.auth_public,
                expires_at_ms=route.expires_at_ms,
                signature=signature,
            )
        )
    auth = RouteListenAuth(
        timestamp_ms=timestamp,
        nonce=nonce_value,
        routes_digest=routes_digest,
        routes=tuple(signed_routes),
    )
    return auth


def route_listen_wire(auth: RouteListenAuth, *, refresh: bool = False) -> dict[str, object]:
    wire = auth.to_wire()
    if refresh:
        wire["t"] = "route_refresh"
    return wire


def derive_dial_routes(
    *,
    local_private_key: Ed25519PrivateKey,
    local_public_key: bytes,
    recipient_public_key: bytes,
    timestamp_ms: int | None = None,
) -> tuple[DerivedRoute, ...]:
    timestamp = now_ms() if timestamp_ms is None else _timestamp(timestamp_ms, "timestamp_ms")
    _local, recipient, root = _derive_pairwise_route_root(
        local_private_key=local_private_key,
        local_public_key=local_public_key,
        peer_public_key=recipient_public_key,
    )
    return tuple(
        _derive_route_from_root(
            root=root,
            recipient_public_key=recipient,
            epoch=epoch,
        )
        for epoch in dial_route_epochs(at_ms=timestamp)
    )


def sign_route_connect_auth(
    route: DerivedRoute,
    *,
    timestamp_ms: int | None = None,
    nonce: bytes | None = None,
) -> RouteConnectAuth:
    timestamp = now_ms() if timestamp_ms is None else _timestamp(timestamp_ms, "timestamp_ms")
    nonce_value = secrets.token_bytes(ROUTE_NONCE_BYTES) if nonce is None else _bytes_exact(
        nonce, ROUTE_NONCE_BYTES, "nonce"
    )
    unsigned = RouteConnectAuth(
        route_tag=_bytes_exact(route.route_tag, ROUTE_TAG_BYTES, "route.route_tag"),
        epoch=_nonnegative_int(route.epoch, "route.epoch"),
        timestamp_ms=timestamp,
        nonce=nonce_value,
        signature=b"\x00" * ROUTE_SIGNATURE_BYTES,
    )
    signature = route.auth_private.sign(_canonical(unsigned.unsigned_wire()))
    return RouteConnectAuth(
        route_tag=unsigned.route_tag,
        epoch=unsigned.epoch,
        timestamp_ms=unsigned.timestamp_ms,
        nonce=unsigned.nonce,
        signature=signature,
    )


def route_set_identity(auth: RouteListenAuth) -> bytes:
    """Stable comparison key used by a listener's refresh loop."""

    return _bytes_exact(auth.routes_digest, ROUTE_SET_DIGEST_BYTES, "routes_digest")


def _pairwise_ecdh(local_ed_seed: bytes, peer_ed_public: bytes) -> bytes:
    seed = _bytes_exact(local_ed_seed, 32, "local Ed25519 seed")
    peer = _bytes_exact(peer_ed_public, 32, "peer Ed25519 public key")
    digest = bytearray(hashlib.sha512(seed).digest()[:32])
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64

    modulus = 2**255 - 19
    y = int.from_bytes(peer, "little") & ((1 << 255) - 1)
    denominator = (1 - y) % modulus
    if denominator == 0:
        raise ValueError("peer Ed25519 public key cannot map to X25519")
    u = ((1 + y) * pow(denominator, -1, modulus)) % modulus
    try:
        shared = X25519PrivateKey.from_private_bytes(bytes(digest)).exchange(
            X25519PublicKey.from_public_bytes(u.to_bytes(32, "little"))
        )
    except ValueError as exc:
        raise ValueError("peer Ed25519 public key is not a valid pairwise route key") from exc
    if secrets.compare_digest(shared, b"\x00" * 32):
        raise ValueError("pairwise route ECDH produced the all-zero secret")
    return shared


def _routes_digest(routes: Iterable[RouteRegistration]) -> bytes:
    entries = [route.unsigned_wire() for route in routes]
    entries.sort(key=lambda item: str(item["route_tag_b64"]))
    return hashlib.sha256(_SET_INFO + _canonical(entries)).digest()


def _route_registration_signing_bytes(
    *,
    timestamp_ms: int,
    nonce: bytes,
    routes_digest: bytes,
    route: RouteRegistration,
) -> bytes:
    return _canonical(
        {
            "v": ROUTING_PROTOCOL_VERSION,
            "t": "route_registration",
            "timestamp_ms": _timestamp(timestamp_ms, "timestamp_ms"),
            "nonce_b64": _b64(_bytes_exact(nonce, ROUTE_NONCE_BYTES, "nonce")),
            "routes_digest_b64": _b64(
                _bytes_exact(routes_digest, ROUTE_SET_DIGEST_BYTES, "routes_digest")
            ),
            "route": route.unsigned_wire(),
        }
    )


def _matching_identity(private_key: Ed25519PrivateKey, public_key: bytes) -> bytes:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("local_private_key must be an Ed25519 private key")
    claimed = _bytes_exact(public_key, 32, "local_public_key")
    if not secrets.compare_digest(private_key.public_key().public_bytes_raw(), claimed):
        raise ValueError("local public key does not match local private key")
    return claimed


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64d(value: object, *, expected_size: int, name: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise ValueError(f"{name} must be canonical unpadded base64url")
    expected_chars = (expected_size * 8 + 5) // 6
    if len(value) != expected_chars:
        raise ValueError(f"{name} has invalid encoded length")
    try:
        encoded = value.encode("ascii")
        padding = b"=" * ((4 - len(encoded) % 4) % 4)
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"{name} is not valid base64url") from exc
    if len(decoded) != expected_size or _b64(decoded) != value:
        raise ValueError(f"{name} is not canonical base64url")
    return decoded


def _exact_dict(value: object, keys: frozenset[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    if set(value) != keys:
        raise ValueError(
            f"{name} fields invalid (missing={sorted(keys - set(value))}, "
            f"unknown={sorted(set(value) - keys, key=repr)})"
        )
    return value


def _bytes_exact(value: object, size: int, name: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError(f"{name} must be exactly {size} bytes")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _timestamp(value: object, name: str) -> int:
    result = _nonnegative_int(value, name)
    if result > MAX_TIMESTAMP_MS:
        raise ValueError(f"{name} exceeds protocol timestamp range")
    return result
