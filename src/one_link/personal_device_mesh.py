"""Personal Device Mesh planning and remote-instruct commands.

This module is the first live Python slice of Coherence Mesh Phase F5:
one person can own several One Link devices that are "one contact" to
friends, while remaining separately addressable to the owner.

The code here is deliberately transport-agnostic. It answers two
production questions the daemon/UI can share:

* which of my devices should receive a self-mesh delivery right now?
* is this remote-instruct command genuinely signed by one of my devices?

It composes with :mod:`identity_dag`: root identity certs establish that
each device belongs to the same owner; this module handles presence,
revocation-aware routing, and one-shot signed commands.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from one_link.identity import fingerprint_of
from one_link.identity_dag import verify_device_cert


PRESENCE_STATES = frozenset({"awake", "asleep", "dormant", "offline"})
NETWORK_CLASSES = frozenset({
    "ethernet",
    "wifi",
    "cellular",
    "bluetooth",
    "offline",
    "unknown",
})
SELF_TRAFFIC_ROUTE = "self_mesh_direct"
REMOTE_INSTRUCT_VERSION = 1
MAX_SCOPE_BYTES = 4096
MAX_REMOTE_INSTRUCT_TTL_MS = 15 * 60 * 1000


def _now_ms() -> int:
    return int(time.time() * 1000)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode((text + pad).encode("ascii"))


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _stable_command_id(body: Mapping[str, Any], signature: bytes) -> str:
    h = hashlib.sha256()
    h.update(b"OL/self-mesh/command-id|v1|")
    h.update(_canonical_json(body))
    h.update(signature)
    return h.hexdigest()


@dataclass(frozen=True)
class MeshDevice:
    """A separately addressable device under one root identity."""

    root_pub: bytes
    device_pub: bytes
    device_kind: str
    label: str = ""
    cert: bytes | None = None
    local: bool = False
    trusted: bool = True
    revoked: bool = False

    def __post_init__(self) -> None:
        if len(self.root_pub) != 32:
            raise ValueError("root_pub must be 32 bytes")
        if len(self.device_pub) != 32:
            raise ValueError("device_pub must be 32 bytes")
        if not self.device_kind:
            raise ValueError("device_kind must not be empty")
        if self.cert is not None:
            parsed = verify_device_cert(self.cert, expected_root_pub=self.root_pub)
            if parsed.device_pub != self.device_pub:
                raise ValueError("cert device_pub does not match MeshDevice")

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.device_pub)

    @property
    def display_name(self) -> str:
        return self.label or self.device_kind or self.fingerprint[:8]


@dataclass(frozen=True)
class DevicePresence:
    """LWW presence fact for one self-mesh device."""

    device_pub: bytes
    state: str
    updated_ms: int
    sequence: int = 0
    battery_pct: int | None = None
    network: str = "unknown"
    free_bytes: int | None = None
    route: str | None = None
    latency_ms: float | None = None
    bandwidth_bps: float | None = None

    def __post_init__(self) -> None:
        if len(self.device_pub) != 32:
            raise ValueError("device_pub must be 32 bytes")
        if self.state not in PRESENCE_STATES:
            raise ValueError(f"unsupported presence state {self.state!r}")
        if self.network not in NETWORK_CLASSES:
            raise ValueError(f"unsupported network class {self.network!r}")
        if self.updated_ms < 0:
            raise ValueError("updated_ms must be non-negative")
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if self.battery_pct is not None and not (0 <= self.battery_pct <= 100):
            raise ValueError("battery_pct must be 0..100")
        if self.free_bytes is not None and self.free_bytes < 0:
            raise ValueError("free_bytes must be non-negative")

    def dominates(self, other: "DevicePresence") -> bool:
        if self.device_pub != other.device_pub:
            raise ValueError("cannot compare presence for different devices")
        return (self.sequence, self.updated_ms) >= (other.sequence, other.updated_ms)


@dataclass(frozen=True)
class DeliveryIntent:
    """What the owner wants the self mesh to do."""

    kind: str
    size_bytes: int = 0
    target_device_pub: bytes | None = None
    require_awake: bool = False
    min_free_bytes: int = 0

    def __post_init__(self) -> None:
        if not self.kind:
            raise ValueError("kind must not be empty")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")
        if self.min_free_bytes < 0:
            raise ValueError("min_free_bytes must be non-negative")
        if self.target_device_pub is not None and len(self.target_device_pub) != 32:
            raise ValueError("target_device_pub must be 32 bytes")


@dataclass(frozen=True)
class MeshDecision:
    status: str
    target: MeshDevice | None
    route: str
    score: float
    facts: tuple[str, ...] = field(default_factory=tuple)
    rejected: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @property
    def ready(self) -> bool:
        return self.status == "ready" and self.target is not None

    def to_dict(self) -> dict[str, Any]:
        target = None
        if self.target is not None:
            target = {
                "fingerprint": self.target.fingerprint,
                "device_pub_b64": _b64u(self.target.device_pub),
                "device_kind": self.target.device_kind,
                "label": self.target.display_name,
                "local": self.target.local,
            }
        return {
            "status": self.status,
            "target": target,
            "route": self.route,
            "score": round(self.score, 6),
            "facts": list(self.facts),
            "rejected": list(self.rejected),
        }


class PresenceBook:
    """Small deterministic CRDT-style presence book.

    For each device, the highest (sequence, updated_ms) fact wins. This
    gives repeatable convergence across devices without requiring wall
    clocks to be perfectly synchronized.
    """

    def __init__(self, entries: Iterable[DevicePresence] = ()):
        self._by_pub: dict[bytes, DevicePresence] = {}
        for entry in entries:
            self.merge(entry)

    def merge(self, entry: DevicePresence) -> None:
        old = self._by_pub.get(entry.device_pub)
        if old is None or entry.dominates(old):
            self._by_pub[entry.device_pub] = entry

    def get(self, device_pub: bytes) -> DevicePresence | None:
        return self._by_pub.get(device_pub)

    def values(self) -> tuple[DevicePresence, ...]:
        return tuple(
            self._by_pub[k]
            for k in sorted(self._by_pub.keys())
        )


def choose_self_mesh_target(
    devices: Iterable[MeshDevice],
    presence: PresenceBook | Iterable[DevicePresence],
    intent: DeliveryIntent,
    *,
    now_ms: int | None = None,
) -> MeshDecision:
    """Pick the best owner-device for a self-mesh delivery."""

    if now_ms is None:
        now_ms = _now_ms()
    book = presence if isinstance(presence, PresenceBook) else PresenceBook(presence)
    rejected: list[dict[str, Any]] = []
    scored: list[tuple[float, MeshDevice, DevicePresence, tuple[str, ...]]] = []

    for device in devices:
        fact = book.get(device.device_pub)
        reason = _device_rejection_reason(device, fact, intent)
        if reason is not None:
            rejected.append({
                "fingerprint": device.fingerprint,
                "label": device.display_name,
                "reason": reason,
            })
            continue
        assert fact is not None
        score, facts = _score_device(device, fact, intent, now_ms=now_ms)
        scored.append((score, device, fact, facts))

    if not scored:
        return MeshDecision(
            status="waiting_for_device",
            target=None,
            route=SELF_TRAFFIC_ROUTE,
            score=0.0,
            facts=("No eligible self-mesh device is ready yet.",),
            rejected=tuple(rejected),
        )

    scored.sort(
        key=lambda row: (
            row[0],
            row[2].updated_ms,
            row[1].fingerprint,
        ),
        reverse=True,
    )
    score, device, fact, facts = scored[0]
    route = fact.route or SELF_TRAFFIC_ROUTE
    return MeshDecision(
        status="ready",
        target=device,
        route=route,
        score=score,
        facts=facts,
        rejected=tuple(rejected),
    )


def _device_rejection_reason(
    device: MeshDevice,
    fact: DevicePresence | None,
    intent: DeliveryIntent,
) -> str | None:
    if not device.trusted:
        return "untrusted"
    if device.revoked:
        return "revoked"
    if intent.target_device_pub is not None and not hmac.compare_digest(
        device.device_pub,
        intent.target_device_pub,
    ):
        return "not_requested_target"
    if fact is None:
        return "no_presence"
    if fact.state == "offline":
        return "offline"
    if intent.require_awake and fact.state != "awake":
        return "not_awake"
    needed = max(intent.min_free_bytes, intent.size_bytes)
    if needed and fact.free_bytes is not None and fact.free_bytes < needed:
        return "insufficient_storage"
    return None


def _score_device(
    device: MeshDevice,
    fact: DevicePresence,
    intent: DeliveryIntent,
    *,
    now_ms: int,
) -> tuple[float, tuple[str, ...]]:
    score = 0.0
    facts: list[str] = []

    state_score = {
        "awake": 100.0,
        "asleep": 45.0,
        "dormant": 15.0,
        "offline": -1000.0,
    }[fact.state]
    score += state_score
    facts.append(f"{device.display_name} is {fact.state}.")

    network_score = {
        "ethernet": 30.0,
        "wifi": 24.0,
        "cellular": 13.0,
        "bluetooth": 5.0,
        "unknown": 0.0,
        "offline": -100.0,
    }[fact.network]
    score += network_score
    if fact.network != "unknown":
        facts.append(f"Network is {fact.network}.")

    if fact.battery_pct is not None:
        if fact.battery_pct < 10:
            score -= 25.0
            facts.append("Battery is critically low.")
        elif fact.battery_pct < 20:
            score -= 10.0
            facts.append("Battery is low.")
        else:
            score += min(12.0, fact.battery_pct / 10.0)

    needed = max(intent.size_bytes, intent.min_free_bytes)
    if needed and fact.free_bytes is not None:
        headroom = max(0, fact.free_bytes - needed)
        score += min(18.0, headroom / max(needed, 1) * 6.0)
        facts.append("Storage headroom is sufficient.")

    if fact.bandwidth_bps:
        score += min(18.0, fact.bandwidth_bps / 100_000_000.0)
    if fact.latency_ms is not None:
        score -= min(20.0, fact.latency_ms / 25.0)

    age_ms = max(0, now_ms - fact.updated_ms)
    score -= min(20.0, age_ms / 60_000.0)
    if age_ms <= 30_000:
        facts.append("Presence is fresh.")

    if device.local:
        score += 2.0

    return score, tuple(facts)


@dataclass(frozen=True)
class RemoteInstruction:
    """Signed command from one owner-device to another."""

    command_id: str
    root_pub: bytes
    controller_cert: bytes
    controller_device_pub: bytes
    target_device_pub: bytes
    action: str
    scope: dict[str, Any]
    created_ms: int
    expires_ms: int
    nonce: bytes
    signature: bytes
    encoded: bytes

    def to_wire(self) -> dict[str, Any]:
        return json.loads(self.encoded.decode("utf-8"))


def sign_remote_instruction(
    *,
    controller_device_seed: bytes,
    controller_cert: bytes,
    target_device_pub: bytes,
    action: str,
    scope: Mapping[str, Any],
    created_ms: int | None = None,
    expires_ms: int | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Create a one-shot remote-instruct command.

    Example actions are ``send_file_from_device`` and
    ``pull_file_manifest``. ``scope`` must be narrow: one file, one
    blob hash, one peer, one transfer id, etc. The verifier enforces
    expiry and signature; callers enforce action-specific policy.
    """

    if len(controller_device_seed) != 32:
        raise ValueError("controller_device_seed must be 32 bytes")
    if len(target_device_pub) != 32:
        raise ValueError("target_device_pub must be 32 bytes")
    if not action:
        raise ValueError("action must not be empty")
    if created_ms is None:
        created_ms = _now_ms()
    if expires_ms is None:
        expires_ms = created_ms + MAX_REMOTE_INSTRUCT_TTL_MS
    if expires_ms <= created_ms:
        raise ValueError("expires_ms must be after created_ms")
    if expires_ms - created_ms > MAX_REMOTE_INSTRUCT_TTL_MS:
        raise ValueError("remote instruction TTL is too long")
    if nonce is None:
        nonce = secrets.token_bytes(16)
    if len(nonce) < 16:
        raise ValueError("nonce must be at least 16 bytes")

    cert = verify_device_cert(controller_cert)
    scope_obj = dict(scope)
    scope_bytes = _canonical_json(scope_obj)
    if len(scope_bytes) > MAX_SCOPE_BYTES:
        raise ValueError("scope is too large")

    body: dict[str, Any] = {
        "v": REMOTE_INSTRUCT_VERSION,
        "type": "self_mesh_remote_instruction",
        "root_pub_b64": _b64u(cert.root_pub),
        "controller_cert_b64": _b64u(controller_cert),
        "controller_device_pub_b64": _b64u(cert.device_pub),
        "target_device_pub_b64": _b64u(target_device_pub),
        "action": action,
        "scope": scope_obj,
        "created_ms": int(created_ms),
        "expires_ms": int(expires_ms),
        "nonce_b64": _b64u(nonce),
    }
    signed = _remote_instruction_signed_bytes(body)
    sig = Ed25519PrivateKey.from_private_bytes(controller_device_seed).sign(signed)
    body["signature_b64"] = _b64u(sig)
    body["command_id"] = _stable_command_id(
        {k: v for k, v in body.items() if k not in {"signature_b64", "command_id"}},
        sig,
    )
    return _canonical_json(body)


def verify_remote_instruction(
    wire: bytes | str | Mapping[str, Any],
    *,
    expected_root_pub: bytes,
    expected_target_device_pub: bytes | None = None,
    now_ms: int | None = None,
    seen_command_ids: set[str] | None = None,
) -> RemoteInstruction:
    """Verify root binding, cert, signature, expiry, target and replay."""

    if now_ms is None:
        now_ms = _now_ms()
    body = _load_remote_instruction(wire)
    if body.get("v") != REMOTE_INSTRUCT_VERSION:
        raise ValueError("unsupported remote instruction version")
    if body.get("type") != "self_mesh_remote_instruction":
        raise ValueError("not a self-mesh remote instruction")

    root_pub = _b64u_decode(str(body.get("root_pub_b64", "")))
    if not hmac.compare_digest(root_pub, expected_root_pub):
        raise ValueError("remote instruction root does not match")

    controller_cert = _b64u_decode(str(body.get("controller_cert_b64", "")))
    cert = verify_device_cert(controller_cert, expected_root_pub=expected_root_pub)
    controller_pub = _b64u_decode(str(body.get("controller_device_pub_b64", "")))
    if not hmac.compare_digest(controller_pub, cert.device_pub):
        raise ValueError("controller device pub does not match cert")

    target_pub = _b64u_decode(str(body.get("target_device_pub_b64", "")))
    if len(target_pub) != 32:
        raise ValueError("target_device_pub must be 32 bytes")
    if expected_target_device_pub is not None and not hmac.compare_digest(
        target_pub,
        expected_target_device_pub,
    ):
        raise ValueError("remote instruction target does not match this device")

    created_ms = int(body.get("created_ms", -1))
    expires_ms = int(body.get("expires_ms", -1))
    if created_ms < 0 or expires_ms <= created_ms:
        raise ValueError("invalid remote instruction time bounds")
    if expires_ms - created_ms > MAX_REMOTE_INSTRUCT_TTL_MS:
        raise ValueError("remote instruction TTL exceeds maximum")
    if now_ms > expires_ms:
        raise ValueError("remote instruction expired")
    if created_ms - now_ms > 60_000:
        raise ValueError("remote instruction is from the future")

    action = str(body.get("action", ""))
    if not action:
        raise ValueError("remote instruction action missing")
    scope = body.get("scope")
    if not isinstance(scope, dict):
        raise ValueError("remote instruction scope must be an object")
    if len(_canonical_json(scope)) > MAX_SCOPE_BYTES:
        raise ValueError("remote instruction scope too large")
    nonce = _b64u_decode(str(body.get("nonce_b64", "")))
    if len(nonce) < 16:
        raise ValueError("remote instruction nonce too short")
    signature = _b64u_decode(str(body.get("signature_b64", "")))
    if len(signature) != 64:
        raise ValueError("remote instruction signature must be 64 bytes")

    unsigned = {k: v for k, v in body.items() if k not in {"signature_b64", "command_id"}}
    expected_id = _stable_command_id(unsigned, signature)
    command_id = str(body.get("command_id", ""))
    if not hmac.compare_digest(command_id, expected_id):
        raise ValueError("remote instruction command_id mismatch")
    if seen_command_ids is not None:
        if command_id in seen_command_ids:
            raise ValueError("remote instruction replayed")
        seen_command_ids.add(command_id)

    try:
        Ed25519PublicKey.from_public_bytes(cert.device_pub).verify(
            signature,
            _remote_instruction_signed_bytes(unsigned),
        )
    except InvalidSignature:
        raise ValueError("remote instruction signature invalid") from None

    return RemoteInstruction(
        command_id=command_id,
        root_pub=root_pub,
        controller_cert=controller_cert,
        controller_device_pub=cert.device_pub,
        target_device_pub=target_pub,
        action=action,
        scope=dict(scope),
        created_ms=created_ms,
        expires_ms=expires_ms,
        nonce=nonce,
        signature=signature,
        encoded=_canonical_json(body),
    )


def _load_remote_instruction(wire: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(wire, Mapping):
        body = dict(wire)
    else:
        if isinstance(wire, bytes):
            raw = wire
        else:
            raw = wire.encode("utf-8")
        body = json.loads(raw.decode("utf-8"))
    if not isinstance(body, dict):
        raise ValueError("remote instruction must be a JSON object")
    return body


def _remote_instruction_signed_bytes(body: Mapping[str, Any]) -> bytes:
    return (
        b"OL/self-mesh/remote-instruction|v1|"
        + _canonical_json(body)
    )


__all__ = [
    "DeliveryIntent",
    "DevicePresence",
    "MeshDecision",
    "MeshDevice",
    "PresenceBook",
    "RemoteInstruction",
    "choose_self_mesh_target",
    "sign_remote_instruction",
    "verify_remote_instruction",
]
