"""Personal Device Mesh enrollment helpers.

These functions keep the ceremony deterministic and small enough for
the daemon, API, and tests to share: create/import a root identity,
mint device certificates, and derive safe public summaries.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.identity_dag import encode_device_cert, verify_device_cert


MAX_B64U_TEXT_CHARS = 64 * 1024
MAX_ENROLLMENT_INVITE_CHARS = 4096
MAX_ENROLLMENT_INVITE_JSON_BYTES = 3072
MAX_ENROLLMENT_CERT_BYTES = 256
MAX_ENROLLMENT_LABEL_CHARS = 120
_B64U_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str, *, max_bytes: int = 65535) -> bytes:
    """Decode canonical, unpadded base64url with explicit size limits.

    ``urlsafe_b64decode`` is intentionally permissive and can silently accept
    non-alphabet characters. Enrollment material is a credential boundary, so
    accept exactly the representation emitted by :func:`b64u` and no aliases.
    """
    if not isinstance(text, str):
        raise ValueError("base64url value must be text")
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    max_chars = min(MAX_B64U_TEXT_CHARS, ((max_bytes + 2) // 3) * 4)
    if len(text) > max_chars:
        raise ValueError("base64url value exceeds size limit")
    if "=" in text or any(ch not in _B64U_ALPHABET for ch in text):
        raise ValueError("base64url value is not canonical")
    pad = "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(
            (text + pad).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64url value is invalid") from exc
    if len(decoded) > max_bytes or b64u(decoded) != text:
        raise ValueError("base64url value is not canonical")
    return decoded


def _bounded_label(value: object, *, fallback: str) -> str:
    if not isinstance(value, str):
        raise ValueError("label must be text")
    label = value or fallback
    if len(label) > MAX_ENROLLMENT_LABEL_CHARS:
        raise ValueError("label exceeds size limit")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in label):
        raise ValueError("label contains a control character")
    return label


def _json_object_without_duplicates(raw: bytes) -> dict[str, Any]:
    def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate invite field: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("enrollment invite is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("enrollment invite must be an object")
    return value


@dataclass(frozen=True)
class MeshRoot:
    root_seed: bytes
    root_pub: bytes

    def __post_init__(self) -> None:
        if len(self.root_seed) != 32:
            raise ValueError("root_seed must be 32 bytes")
        if len(self.root_pub) != 32:
            raise ValueError("root_pub must be 32 bytes")

    @classmethod
    def create(cls) -> "MeshRoot":
        seed = secrets.token_bytes(32)
        pub = Ed25519PrivateKey.from_private_bytes(
            seed
        ).public_key().public_bytes_raw()
        return cls(root_seed=seed, root_pub=pub)

    @classmethod
    def from_seed(cls, seed: bytes) -> "MeshRoot":
        if len(seed) != 32:
            raise ValueError("root_seed must be 32 bytes")
        pub = Ed25519PrivateKey.from_private_bytes(
            seed
        ).public_key().public_bytes_raw()
        return cls(root_seed=seed, root_pub=pub)


def mint_device_cert(
    *,
    root_seed: bytes,
    root_pub: bytes,
    device_pub: bytes,
    device_kind: str,
    expires_ms: int = 0,
) -> bytes:
    return encode_device_cert(
        root_priv_seed=root_seed,
        root_pub=root_pub,
        device_pub=device_pub,
        device_kind=device_kind,
        added_ms=int(time.time() * 1000),
        expires_ms=expires_ms,
    )


def verify_enrollment_cert(
    cert: bytes,
    *,
    expected_root_pub: bytes | None = None,
) -> dict[str, Any]:
    parsed = verify_device_cert(cert, expected_root_pub=expected_root_pub)
    return {
        "root_pub": parsed.root_pub,
        "device_pub": parsed.device_pub,
        "device_kind": parsed.device_kind,
        "added_ms": parsed.added_ms,
        "expires_ms": parsed.expires_ms,
    }


def build_enrollment_invite(
    *,
    cert: bytes,
    label: str = "",
    created_ms: int | None = None,
) -> dict[str, Any]:
    parsed = verify_enrollment_cert(cert)
    if created_ms is None:
        created_ms = int(time.time() * 1000)
    if isinstance(created_ms, bool) or not isinstance(created_ms, int):
        raise ValueError("created_ms must be an integer")
    if not (0 <= created_ms <= 2**63 - 1):
        raise ValueError("created_ms out of range")
    safe_label = _bounded_label(label, fallback=parsed["device_kind"])
    body = {
        "v": 1,
        "type": "one_link_self_mesh_enrollment",
        "root_pub_b64": b64u(parsed["root_pub"]),
        "device_pub_b64": b64u(parsed["device_pub"]),
        "cert_b64": b64u(cert),
        "device_kind": parsed["device_kind"],
        "label": safe_label,
        "created_ms": created_ms,
    }
    token = b64u(json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))
    return {
        **body,
        "token": token,
        "deep_link": f"one-link://self-mesh/enroll?token={token}",
    }


def parse_enrollment_invite(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token:
        raise ValueError("enrollment invite token is required")
    if len(token) > MAX_ENROLLMENT_INVITE_CHARS:
        raise ValueError("enrollment invite exceeds size limit")
    raw = b64u_decode(token, max_bytes=MAX_ENROLLMENT_INVITE_JSON_BYTES)
    body = _json_object_without_duplicates(raw)
    allowed = {
        "v",
        "type",
        "root_pub_b64",
        "device_pub_b64",
        "cert_b64",
        "device_kind",
        "label",
        "created_ms",
    }
    if set(body) - allowed:
        raise ValueError("enrollment invite contains unsupported fields")
    if body.get("v") != 1 or body.get("type") != "one_link_self_mesh_enrollment":
        raise ValueError("not a self-mesh enrollment invite")
    for field in ("root_pub_b64", "device_pub_b64", "cert_b64", "device_kind"):
        if not isinstance(body.get(field), str) or not body[field]:
            raise ValueError(f"{field} must be non-empty text")
    cert = b64u_decode(
        body["cert_b64"],
        max_bytes=MAX_ENROLLMENT_CERT_BYTES,
    )
    parsed = verify_enrollment_cert(cert)
    root_pub = b64u_decode(body["root_pub_b64"], max_bytes=32)
    device_pub = b64u_decode(body["device_pub_b64"], max_bytes=32)
    if len(root_pub) != 32 or len(device_pub) != 32:
        raise ValueError("invite public keys must be 32 bytes")
    if parsed["root_pub"] != root_pub or parsed["device_pub"] != device_pub:
        raise ValueError("invite cert does not match public keys")
    if body["device_kind"] != parsed["device_kind"]:
        raise ValueError("invite cert does not match device kind")
    created_ms = body.get("created_ms")
    if isinstance(created_ms, bool) or not isinstance(created_ms, int):
        raise ValueError("created_ms must be an integer")
    if not (0 <= created_ms <= 2**63 - 1):
        raise ValueError("created_ms out of range")
    safe_label = _bounded_label(
        body.get("label", parsed["device_kind"]),
        fallback=parsed["device_kind"],
    )
    # Return one canonical object. In particular, security-relevant identity
    # fields come from the verified certificate, never mutable outer JSON.
    return {
        "v": 1,
        "type": "one_link_self_mesh_enrollment",
        "root_pub_b64": b64u(parsed["root_pub"]),
        "device_pub_b64": b64u(parsed["device_pub"]),
        "cert_b64": b64u(cert),
        "device_kind": parsed["device_kind"],
        "label": safe_label,
        "created_ms": created_ms,
    }


__all__ = [
    "MeshRoot",
    "b64u",
    "b64u_decode",
    "mint_device_cert",
    "build_enrollment_invite",
    "parse_enrollment_invite",
    "verify_enrollment_cert",
]
