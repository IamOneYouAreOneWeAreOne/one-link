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
import binascii
import hashlib
import hmac
import json
import math
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from one_link.device_guardian import (
    SAFETY_STATES,
    safety_blocks_routing,
    safety_score_penalty,
)
from one_link.identity import fingerprint_of
from one_link.identity_dag import verify_device_cert


PRESENCE_STATES = frozenset({"awake", "asleep", "dormant", "offline"})
NETWORK_CLASSES = frozenset(
    {
        "ethernet",
        "wifi",
        "cellular",
        "bluetooth",
        "offline",
        "unknown",
    }
)
SELF_TRAFFIC_ROUTE = "self_mesh_direct"
REMOTE_INSTRUCT_VERSION = 1
MAX_SCOPE_BYTES = 4096
MAX_REMOTE_INSTRUCT_TTL_MS = 15 * 60 * 1000
MAX_REMOTE_INSTRUCTION_BYTES = 8192
MAX_REMOTE_INSTRUCTION_CERT_BYTES = 256
MAX_REMOTE_INSTRUCTION_ACTION_BYTES = 80
MAX_REMOTE_INSTRUCTION_NONCE_BYTES = 16
MAX_IN_MEMORY_REPLAY_IDS = 65_536
MAX_MESH_DEVICES = 256
MAX_PRESENCE_INPUT_FACTS = 1024
MAX_PRESENCE_FUTURE_SKEW_MS = 60_000
MAX_PRESENCE_AGE_MS = 24 * 60 * 60 * 1000
MAX_I64 = 2**63 - 1
MAX_SCOPE_DEPTH = 12
MAX_SCOPE_NODES = 512
MAX_SCOPE_CONTAINER_ITEMS = 128
MAX_SCOPE_KEY_BYTES = 128
MAX_SCOPE_STRING_BYTES = 2048

_REMOTE_INSTRUCTION_FIELDS = frozenset(
    {
        "v",
        "type",
        "root_pub_b64",
        "controller_cert_b64",
        "controller_device_pub_b64",
        "target_device_pub_b64",
        "action",
        "scope",
        "created_ms",
        "expires_ms",
        "nonce_b64",
        "signature_b64",
        "command_id",
    }
)
_B64U_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
_LOWER_HEX = frozenset("0123456789abcdef")


def _now_ms() -> int:
    return int(time.time() * 1000)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(
    text: object,
    *,
    field_name: str,
    exact_bytes: int | None = None,
    max_bytes: int | None = None,
) -> bytes:
    """Decode exactly the canonical unpadded base64url representation.

    ``urlsafe_b64decode`` is deliberately permissive: it ignores several
    non-alphabet characters and accepts padded aliases.  Signed protocol
    fields need a single wire spelling, and allocation must be bounded before
    decoding attacker-controlled text.
    """

    if not isinstance(text, str):
        raise ValueError(f"{field_name} must be text")
    if exact_bytes is not None:
        if exact_bytes < 0:
            raise ValueError("exact_bytes must be non-negative")
        size_limit = exact_bytes
    elif max_bytes is not None:
        if max_bytes < 0:
            raise ValueError("max_bytes must be non-negative")
        size_limit = max_bytes
    else:  # Every credential decode site must declare its allocation bound.
        raise ValueError("base64url decode requires a size bound")
    max_chars = ((size_limit + 2) // 3) * 4
    if len(text) > max_chars:
        raise ValueError(f"{field_name} exceeds size limit")
    if "=" in text or any(ch not in _B64U_ALPHABET for ch in text):
        raise ValueError(f"{field_name} is not canonical base64url")
    pad = "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(
            (text + pad).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{field_name} is invalid base64url") from exc
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ValueError(f"{field_name} must decode to {exact_bytes} bytes")
    if max_bytes is not None and len(decoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds size limit")
    if not hmac.compare_digest(_b64u(decoded), text):
        raise ValueError(f"{field_name} is not canonical base64url")
    return decoded


def _canonical_json(obj: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise ValueError("value is not canonical JSON data") from exc


def _require_i64(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    if not (0 <= value <= MAX_I64):
        raise ValueError(f"{field_name} out of range")
    return value


def _require_exact_bytes(value: object, field_name: str, length: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{field_name} must be {length} bytes")
    return value


def _validate_bounded_text(
    value: object,
    field_name: str,
    *,
    max_chars: int,
    max_bytes: int,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be text")
    if not value and not allow_empty:
        raise ValueError(f"{field_name} must not be empty")
    if len(value) > max_chars:
        raise ValueError(f"{field_name} exceeds character limit")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} is not valid Unicode") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds byte limit")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError(f"{field_name} contains a control character")
    return value


def _validate_action(value: object) -> str:
    action = _validate_bounded_text(
        value,
        "action",
        max_chars=MAX_REMOTE_INSTRUCTION_ACTION_BYTES,
        max_bytes=MAX_REMOTE_INSTRUCTION_ACTION_BYTES,
    )
    if not action[0].islower() or not action[0].isascii():
        raise ValueError("action must start with a lowercase ASCII letter")
    if any(not (ch.isascii() and (ch.islower() or ch.isdigit() or ch == "_")) for ch in action):
        raise ValueError("action must be a lowercase ASCII token")
    return action


def _snapshot_scope(scope: object) -> dict[str, Any]:
    """Validate and detach the deterministic JSON subset used by commands.

    Floats are excluded because cross-runtime JSON spellings and non-finite
    values are not a sound signature contract.  Bounded depth, fan-out, node
    count, key size, and value size prevent small wire frames from triggering
    pathological parser or canonicalizer work.
    """

    budget = [0]

    def copy_value(value: object, depth: int) -> Any:
        if depth > MAX_SCOPE_DEPTH:
            raise ValueError("scope exceeds maximum nesting depth")
        budget[0] += 1
        if budget[0] > MAX_SCOPE_NODES:
            raise ValueError("scope contains too many values")
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            if not (-MAX_I64 - 1 <= value <= MAX_I64):
                raise ValueError("scope integer out of range")
            return value
        if isinstance(value, float):
            raise ValueError("scope floating-point values are not supported")
        if isinstance(value, str):
            return _validate_bounded_text(
                value,
                "scope string",
                max_chars=MAX_SCOPE_STRING_BYTES,
                max_bytes=MAX_SCOPE_STRING_BYTES,
                allow_empty=True,
            )
        if isinstance(value, list):
            if len(value) > MAX_SCOPE_CONTAINER_ITEMS:
                raise ValueError("scope list contains too many values")
            return [copy_value(item, depth + 1) for item in value]
        if isinstance(value, Mapping):
            if len(value) > MAX_SCOPE_CONTAINER_ITEMS:
                raise ValueError("scope object contains too many fields")
            copied: dict[str, Any] = {}
            for key, item in value.items():
                safe_key = _validate_bounded_text(
                    key,
                    "scope key",
                    max_chars=MAX_SCOPE_KEY_BYTES,
                    max_bytes=MAX_SCOPE_KEY_BYTES,
                )
                if safe_key in copied:
                    raise ValueError("scope contains a duplicate field")
                copied[safe_key] = copy_value(item, depth + 1)
            return copied
        raise ValueError(f"scope contains unsupported value type {type(value).__name__}")

    if not isinstance(scope, Mapping):
        raise ValueError("remote instruction scope must be an object")
    copied = copy_value(scope, 0)
    assert isinstance(copied, dict)
    encoded = _canonical_json(copied)
    if len(encoded) > MAX_SCOPE_BYTES:
        raise ValueError("remote instruction scope too large")
    return copied


def _json_object_without_duplicate_keys(raw: bytes) -> dict[str, Any]:
    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_hook)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("remote instruction is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("remote instruction must be a JSON object")
    return value


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
    safety_state: str = "trusted"

    def __post_init__(self) -> None:
        _require_exact_bytes(self.root_pub, "root_pub", 32)
        _require_exact_bytes(self.device_pub, "device_pub", 32)
        if hmac.compare_digest(self.root_pub, self.device_pub):
            raise ValueError("root_pub and device_pub must differ")
        _validate_bounded_text(
            self.device_kind,
            "device_kind",
            max_chars=64,
            max_bytes=64,
        )
        _validate_bounded_text(
            self.label,
            "label",
            max_chars=120,
            max_bytes=480,
            allow_empty=True,
        )
        for name in ("local", "trusted", "revoked"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        if not isinstance(self.safety_state, str) or self.safety_state not in SAFETY_STATES:
            raise ValueError(f"unsupported safety_state {self.safety_state!r}")
        if self.cert is not None:
            if not isinstance(self.cert, bytes):
                raise ValueError("cert must be bytes")
            if len(self.cert) > MAX_REMOTE_INSTRUCTION_CERT_BYTES:
                raise ValueError("cert exceeds size limit")
            parsed = verify_device_cert(self.cert, expected_root_pub=self.root_pub)
            if not hmac.compare_digest(parsed.device_pub, self.device_pub):
                raise ValueError("cert device_pub does not match MeshDevice")
            if parsed.device_kind != self.device_kind:
                raise ValueError("cert device_kind does not match MeshDevice")

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
        _require_exact_bytes(self.device_pub, "device_pub", 32)
        if not isinstance(self.state, str):
            raise ValueError("state must be text")
        if self.state not in PRESENCE_STATES:
            raise ValueError(f"unsupported presence state {self.state!r}")
        if not isinstance(self.network, str):
            raise ValueError("network must be text")
        if self.network not in NETWORK_CLASSES:
            raise ValueError(f"unsupported network class {self.network!r}")
        _require_i64(self.updated_ms, "updated_ms")
        _require_i64(self.sequence, "sequence")
        if self.battery_pct is not None:
            if isinstance(self.battery_pct, bool) or not isinstance(
                self.battery_pct,
                int,
            ):
                raise ValueError("battery_pct must be an integer")
            if not (0 <= self.battery_pct <= 100):
                raise ValueError("battery_pct must be 0..100")
        if self.free_bytes is not None:
            _require_i64(self.free_bytes, "free_bytes")
        if self.route is not None:
            _validate_bounded_text(
                self.route,
                "route",
                max_chars=80,
                max_bytes=240,
            )
        for name in ("latency_ms", "bandwidth_bps"):
            value = getattr(self, name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite number")
            if value < 0 or value > MAX_I64 or not math.isfinite(value):
                raise ValueError(f"{name} must be finite, non-negative, and bounded")

    def dominates(self, other: "DevicePresence") -> bool:
        if not isinstance(other, DevicePresence):
            raise ValueError("other must be a DevicePresence")
        if self.device_pub != other.device_pub:
            raise ValueError("cannot compare presence for different devices")
        return self._order_key() >= other._order_key()

    def _order_key(self) -> tuple[int, int, bytes]:
        """Total order, including deterministic resolution of exact LWW ties."""

        body = {
            "state": self.state,
            "battery_pct": self.battery_pct,
            "network": self.network,
            "free_bytes": self.free_bytes,
            "route": self.route,
            "latency_ms": self.latency_ms,
            "bandwidth_bps": self.bandwidth_bps,
        }
        return (
            self.sequence,
            self.updated_ms,
            _canonical_json(body),
        )


@dataclass(frozen=True)
class DeliveryIntent:
    """What the owner wants the self mesh to do."""

    kind: str
    size_bytes: int = 0
    target_device_pub: bytes | None = None
    require_awake: bool = False
    min_free_bytes: int = 0

    def __post_init__(self) -> None:
        _validate_bounded_text(
            self.kind,
            "kind",
            max_chars=80,
            max_bytes=80,
        )
        _require_i64(self.size_bytes, "size_bytes")
        _require_i64(self.min_free_bytes, "min_free_bytes")
        if not isinstance(self.require_awake, bool):
            raise ValueError("require_awake must be a boolean")
        if self.target_device_pub is not None:
            _require_exact_bytes(
                self.target_device_pub,
                "target_device_pub",
                32,
            )


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
                "safety_state": self.target.safety_state,
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
        for index, entry in enumerate(entries):
            if index >= MAX_PRESENCE_INPUT_FACTS:
                raise ValueError("presence input exceeds resource limit")
            self.merge(entry)

    def merge(self, entry: DevicePresence) -> None:
        if not isinstance(entry, DevicePresence):
            raise ValueError("presence entry must be a DevicePresence")
        old = self._by_pub.get(entry.device_pub)
        if old is None and len(self._by_pub) >= MAX_MESH_DEVICES:
            raise ValueError("presence book exceeds device limit")
        if old is None or entry.dominates(old):
            self._by_pub[entry.device_pub] = entry

    def get(self, device_pub: bytes) -> DevicePresence | None:
        _require_exact_bytes(device_pub, "device_pub", 32)
        return self._by_pub.get(device_pub)

    def values(self) -> tuple[DevicePresence, ...]:
        return tuple(self._by_pub[k] for k in sorted(self._by_pub.keys()))


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
    now_ms = _require_i64(now_ms, "now_ms")
    if not isinstance(intent, DeliveryIntent):
        raise ValueError("intent must be a DeliveryIntent")
    book = presence if isinstance(presence, PresenceBook) else PresenceBook(presence)
    rejected: list[dict[str, Any]] = []
    scored: list[tuple[float, MeshDevice, DevicePresence, tuple[str, ...]]] = []
    root_pub: bytes | None = None
    seen_devices: set[bytes] = set()

    for index, device in enumerate(devices):
        if index >= MAX_MESH_DEVICES:
            raise ValueError("device input exceeds resource limit")
        if not isinstance(device, MeshDevice):
            raise ValueError("device entry must be a MeshDevice")
        if root_pub is None:
            root_pub = device.root_pub
        elif not hmac.compare_digest(root_pub, device.root_pub):
            raise ValueError("self-mesh routing cannot mix identity roots")
        if device.device_pub in seen_devices:
            raise ValueError("self-mesh routing contains a duplicate device")
        seen_devices.add(device.device_pub)
        fact = book.get(device.device_pub)
        reason = _device_rejection_reason(
            device,
            fact,
            intent,
            now_ms=now_ms,
        )
        if reason is not None:
            rejected.append(
                {
                    "fingerprint": device.fingerprint,
                    "label": device.display_name,
                    "reason": reason,
                }
            )
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
    *,
    now_ms: int,
) -> str | None:
    if not device.trusted:
        return "untrusted"
    if device.revoked:
        return "revoked"
    if safety_blocks_routing(device.safety_state):
        return f"guardian_{device.safety_state}"
    if intent.target_device_pub is not None and not hmac.compare_digest(
        device.device_pub,
        intent.target_device_pub,
    ):
        return "not_requested_target"
    if fact is None:
        return "no_presence"
    if fact.updated_ms > now_ms + MAX_PRESENCE_FUTURE_SKEW_MS:
        return "presence_from_future"
    if now_ms > fact.updated_ms + MAX_PRESENCE_AGE_MS:
        return "presence_stale"
    if fact.state == "offline":
        return "offline"
    if fact.network == "offline":
        return "network_offline"
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
    penalty = safety_score_penalty(device.safety_state)
    if penalty:
        score -= penalty
        facts.append(f"Guardian state is {device.safety_state}.")

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
        return _load_remote_instruction(self.encoded)


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

    controller_device_seed = _require_exact_bytes(
        controller_device_seed,
        "controller_device_seed",
        32,
    )
    target_device_pub = _require_exact_bytes(
        target_device_pub,
        "target_device_pub",
        32,
    )
    if not isinstance(controller_cert, bytes):
        raise ValueError("controller_cert must be bytes")
    if not controller_cert or len(controller_cert) > MAX_REMOTE_INSTRUCTION_CERT_BYTES:
        raise ValueError("controller_cert exceeds size limit")
    action = _validate_action(action)
    if created_ms is None:
        created_ms = _now_ms()
    created_ms = _require_i64(created_ms, "created_ms")
    if expires_ms is None:
        expires_ms = created_ms + MAX_REMOTE_INSTRUCT_TTL_MS
    expires_ms = _require_i64(expires_ms, "expires_ms")
    if expires_ms <= created_ms:
        raise ValueError("expires_ms must be after created_ms")
    if expires_ms - created_ms > MAX_REMOTE_INSTRUCT_TTL_MS:
        raise ValueError("remote instruction TTL is too long")
    if nonce is None:
        nonce = secrets.token_bytes(MAX_REMOTE_INSTRUCTION_NONCE_BYTES)
    nonce = _require_exact_bytes(
        nonce,
        "nonce",
        MAX_REMOTE_INSTRUCTION_NONCE_BYTES,
    )

    cert = verify_device_cert(controller_cert)
    if cert.added_ms > _now_ms() + MAX_PRESENCE_FUTURE_SKEW_MS:
        raise ValueError("controller cert is from the future")
    if created_ms < cert.added_ms:
        raise ValueError("remote instruction predates controller cert")
    if cert.expires_ms != 0 and expires_ms > cert.expires_ms:
        raise ValueError("remote instruction outlives controller cert")
    derived_controller_pub = (
        Ed25519PrivateKey.from_private_bytes(
            controller_device_seed,
        )
        .public_key()
        .public_bytes_raw()
    )
    if not hmac.compare_digest(derived_controller_pub, cert.device_pub):
        raise ValueError("controller_device_seed does not match controller_cert")
    scope_obj = _snapshot_scope(scope)

    body: dict[str, Any] = {
        "v": REMOTE_INSTRUCT_VERSION,
        "type": "self_mesh_remote_instruction",
        "root_pub_b64": _b64u(cert.root_pub),
        "controller_cert_b64": _b64u(controller_cert),
        "controller_device_pub_b64": _b64u(cert.device_pub),
        "target_device_pub_b64": _b64u(target_device_pub),
        "action": action,
        "scope": scope_obj,
        "created_ms": created_ms,
        "expires_ms": expires_ms,
        "nonce_b64": _b64u(nonce),
    }
    signed = _remote_instruction_signed_bytes(body)
    sig = Ed25519PrivateKey.from_private_bytes(controller_device_seed).sign(signed)
    body["signature_b64"] = _b64u(sig)
    body["command_id"] = _stable_command_id(
        {k: v for k, v in body.items() if k not in {"signature_b64", "command_id"}},
        sig,
    )
    encoded = _canonical_json(body)
    if len(encoded) > MAX_REMOTE_INSTRUCTION_BYTES:  # pragma: no cover - constants
        raise ValueError("remote instruction exceeds wire size limit")
    return encoded


def verify_remote_instruction(
    wire: bytes | str | Mapping[str, Any],
    *,
    expected_root_pub: bytes,
    expected_target_device_pub: bytes | None = None,
    now_ms: int | None = None,
    seen_command_ids: set[str] | None = None,
) -> RemoteInstruction:
    """Verify root binding, cert, signature, expiry, target and replay."""

    expected_root_pub = _require_exact_bytes(
        expected_root_pub,
        "expected_root_pub",
        32,
    )
    if expected_target_device_pub is not None:
        expected_target_device_pub = _require_exact_bytes(
            expected_target_device_pub,
            "expected_target_device_pub",
            32,
        )
    if now_ms is None:
        now_ms = _now_ms()
    now_ms = _require_i64(now_ms, "now_ms")
    if seen_command_ids is not None and not isinstance(seen_command_ids, set):
        raise ValueError("seen_command_ids must be a set")
    body = _load_remote_instruction(wire)
    version = body["v"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise ValueError("remote instruction version must be an integer")
    if version != REMOTE_INSTRUCT_VERSION:
        raise ValueError("unsupported remote instruction version")
    if body["type"] != "self_mesh_remote_instruction":
        raise ValueError("not a self-mesh remote instruction")

    root_pub = _b64u_decode(
        body["root_pub_b64"],
        field_name="root_pub_b64",
        exact_bytes=32,
    )
    if not hmac.compare_digest(root_pub, expected_root_pub):
        raise ValueError("remote instruction root does not match")

    controller_cert = _b64u_decode(
        body["controller_cert_b64"],
        field_name="controller_cert_b64",
        max_bytes=MAX_REMOTE_INSTRUCTION_CERT_BYTES,
    )
    cert = verify_device_cert(
        controller_cert,
        expected_root_pub=expected_root_pub,
        now_ms=now_ms,
    )
    if cert.expires_ms != 0 and now_ms >= cert.expires_ms:
        raise ValueError("controller cert expired")
    if cert.added_ms > now_ms + MAX_PRESENCE_FUTURE_SKEW_MS:
        raise ValueError("controller cert is from the future")
    controller_pub = _b64u_decode(
        body["controller_device_pub_b64"],
        field_name="controller_device_pub_b64",
        exact_bytes=32,
    )
    if not hmac.compare_digest(controller_pub, cert.device_pub):
        raise ValueError("controller device pub does not match cert")

    target_pub = _b64u_decode(
        body["target_device_pub_b64"],
        field_name="target_device_pub_b64",
        exact_bytes=32,
    )
    if expected_target_device_pub is not None and not hmac.compare_digest(
        target_pub,
        expected_target_device_pub,
    ):
        raise ValueError("remote instruction target does not match this device")

    created_ms = _require_i64(body["created_ms"], "created_ms")
    expires_ms = _require_i64(body["expires_ms"], "expires_ms")
    if expires_ms <= created_ms:
        raise ValueError("invalid remote instruction time bounds")
    if expires_ms - created_ms > MAX_REMOTE_INSTRUCT_TTL_MS:
        raise ValueError("remote instruction TTL exceeds maximum")
    if now_ms >= expires_ms:
        raise ValueError("remote instruction expired")
    if created_ms > now_ms + MAX_PRESENCE_FUTURE_SKEW_MS:
        raise ValueError("remote instruction is from the future")
    if created_ms < cert.added_ms:
        raise ValueError("remote instruction predates controller cert")
    if cert.expires_ms != 0 and expires_ms > cert.expires_ms:
        raise ValueError("remote instruction outlives controller cert")

    action = _validate_action(body["action"])
    scope = _snapshot_scope(body["scope"])
    nonce = _b64u_decode(
        body["nonce_b64"],
        field_name="nonce_b64",
        exact_bytes=MAX_REMOTE_INSTRUCTION_NONCE_BYTES,
    )
    signature = _b64u_decode(
        body["signature_b64"],
        field_name="signature_b64",
        exact_bytes=64,
    )

    unsigned = {k: v for k, v in body.items() if k not in {"signature_b64", "command_id"}}
    expected_id = _stable_command_id(unsigned, signature)
    command_id = body["command_id"]
    if (
        not isinstance(command_id, str)
        or len(command_id) != 64
        or any(ch not in _LOWER_HEX for ch in command_id)
    ):
        raise ValueError("remote instruction command_id must be lowercase SHA-256 hex")
    if not hmac.compare_digest(command_id, expected_id):
        raise ValueError("remote instruction command_id mismatch")

    try:
        Ed25519PublicKey.from_public_bytes(cert.device_pub).verify(
            signature,
            _remote_instruction_signed_bytes(unsigned),
        )
    except InvalidSignature:
        raise ValueError("remote instruction signature invalid") from None

    # Never let an unauthenticated envelope consume or poison replay state.
    if seen_command_ids is not None:
        if command_id in seen_command_ids:
            raise ValueError("remote instruction replayed")
        if len(seen_command_ids) >= MAX_IN_MEMORY_REPLAY_IDS:
            raise ValueError("remote instruction replay cache is full")
        seen_command_ids.add(command_id)

    return RemoteInstruction(
        command_id=command_id,
        root_pub=root_pub,
        controller_cert=controller_cert,
        controller_device_pub=cert.device_pub,
        target_device_pub=target_pub,
        action=action,
        scope=scope,
        created_ms=created_ms,
        expires_ms=expires_ms,
        nonce=nonce,
        signature=signature,
        encoded=_canonical_json(body),
    )


def _load_remote_instruction(wire: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(wire, Mapping):
        if len(wire) != len(_REMOTE_INSTRUCTION_FIELDS):
            raise ValueError("remote instruction has an invalid field count")
        body = dict(wire)
    else:
        if isinstance(wire, bytes):
            raw = wire
        elif isinstance(wire, str):
            try:
                raw = wire.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("remote instruction is not valid Unicode") from exc
        else:
            raise ValueError("remote instruction must be bytes, text, or a mapping")
        if not raw:
            raise ValueError("remote instruction must not be empty")
        if len(raw) > MAX_REMOTE_INSTRUCTION_BYTES:
            raise ValueError("remote instruction exceeds wire size limit")
        body = _json_object_without_duplicate_keys(raw)
        if _canonical_json(body) != raw:
            raise ValueError("remote instruction JSON is not canonical")
    fields = set(body)
    if fields != _REMOTE_INSTRUCTION_FIELDS:
        missing = sorted(_REMOTE_INSTRUCTION_FIELDS - fields)
        extra = sorted(str(key) for key in fields - _REMOTE_INSTRUCTION_FIELDS)
        detail = []
        if missing:
            detail.append(f"missing={','.join(missing)}")
        if extra:
            detail.append(f"unsupported={','.join(extra)}")
        raise ValueError(
            "remote instruction schema mismatch" + (f" ({'; '.join(detail)})" if detail else "")
        )
    return body


def _remote_instruction_signed_bytes(body: Mapping[str, Any]) -> bytes:
    return b"OL/self-mesh/remote-instruction|v1|" + _canonical_json(body)


__all__ = [
    "DeliveryIntent",
    "DevicePresence",
    "MAX_PRESENCE_FUTURE_SKEW_MS",
    "MAX_REMOTE_INSTRUCTION_BYTES",
    "MeshDecision",
    "MeshDevice",
    "NETWORK_CLASSES",
    "PRESENCE_STATES",
    "PresenceBook",
    "RemoteInstruction",
    "choose_self_mesh_target",
    "sign_remote_instruction",
    "verify_remote_instruction",
]
