"""Replay-safe challenges for certificate-authenticated device relogin.

The device certificate is public authorization material.  It is therefore not
enough for a relogin client to sign a nonce of its own choosing: the complete
``{certificate, nonce, signature}`` request can be captured and replayed to
mint fresh WebRTC pairing credentials.  This module provides a small,
process-local challenge store whose proofs are:

* chosen by the daemon and consumed exactly once;
* bound to the daemon, mesh root, and device public keys;
* expired against a monotonic clock; and
* globally and per-device bounded under one lock.

Challenges intentionally do not survive daemon restart.  A restart invalidates
every outstanding proof and the returning device can request a fresh one.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import secrets
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable


RELOGIN_CHALLENGE_VERSION = 1
RELOGIN_CHALLENGE_TTL_MS = 60_000
RELOGIN_CHALLENGE_ID_BYTES = 24
RELOGIN_CHALLENGE_NONCE_BYTES = 32
RELOGIN_CHALLENGE_MAX_ENTRIES = 1_024
RELOGIN_CHALLENGE_MAX_PER_DEVICE = 4
RELOGIN_PROOF_DOMAIN = b"OL/device-relogin/challenge/v1\0"

# Device certs are currently at most 217 bytes (64-byte device-kind cap), but
# leave a small versioning margin while rejecting attacker-sized request data
# before any asymmetric verification or database access.
RELOGIN_CERT_MAX_BYTES = 256
RELOGIN_SIGNATURE_BYTES = 64

_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class DeviceReloginChallengeError(ValueError):
    """Base class for invalid, missing, expired, or mismatched challenges."""


class DeviceReloginChallengeCapacityError(DeviceReloginChallengeError):
    """The bounded challenge store has no safe admission capacity."""


def encode_b64u(raw: bytes) -> str:
    """Return canonical unpadded base64url."""

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_b64u_strict(
    value: object,
    *,
    field: str,
    exact_bytes: int | None = None,
    min_bytes: int = 1,
    max_bytes: int,
) -> bytes:
    """Decode one canonical, unpadded base64url field with hard bounds.

    ``urlsafe_b64decode`` is deliberately permissive: it can ignore invalid
    characters and accept multiple spellings of the same bytes.  Public auth
    endpoints should instead have a single wire representation and reject
    oversized values before allocating or doing cryptographic work.
    """

    if not isinstance(value, str):
        raise DeviceReloginChallengeError(f"{field} must be text")
    if not value or "=" in value or any(ch not in _B64URL_ALPHABET for ch in value):
        raise DeviceReloginChallengeError(
            f"{field} must be canonical unpadded base64url"
        )
    if exact_bytes is not None:
        min_bytes = exact_bytes
        max_bytes = exact_bytes
    if min_bytes < 0 or max_bytes < min_bytes:
        raise ValueError("invalid decoded-size bounds")
    # ceil(n * 8 / 6), with no padding.  Reject before decoding so a huge
    # attacker string cannot allocate a correspondingly huge temporary buffer.
    max_chars = (max_bytes * 8 + 5) // 6
    if len(value) > max_chars:
        raise DeviceReloginChallengeError(f"{field} is too large")
    padded = value + ("=" * (-len(value) % 4))
    try:
        decoded = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error, UnicodeEncodeError) as exc:
        raise DeviceReloginChallengeError(f"{field} is not valid base64url") from exc
    if not (min_bytes <= len(decoded) <= max_bytes):
        if exact_bytes is not None:
            raise DeviceReloginChallengeError(
                f"{field} must decode to exactly {exact_bytes} bytes"
            )
        raise DeviceReloginChallengeError(
            f"{field} decoded length is outside the allowed range"
        )
    if not hmac.compare_digest(encode_b64u(decoded), value):
        raise DeviceReloginChallengeError(f"{field} is not canonical base64url")
    return decoded


def _public_key(value: object, field: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise DeviceReloginChallengeError(f"{field} must be bytes")
    raw = bytes(value)
    if len(raw) != 32:
        raise DeviceReloginChallengeError(f"{field} must be exactly 32 bytes")
    return raw


@dataclass(frozen=True)
class DeviceReloginChallenge:
    challenge_id: str
    challenge_id_bytes: bytes
    nonce: bytes
    device_pub: bytes
    root_pub: bytes
    daemon_pub: bytes
    issued_unix_ms: int
    expires_unix_ms: int
    issued_monotonic_ms: int
    expires_monotonic_ms: int
    proof: bytes


class DeviceReloginChallengeStore:
    """Thread-safe, bounded, one-time relogin challenge registry."""

    def __init__(
        self,
        *,
        ttl_ms: int = RELOGIN_CHALLENGE_TTL_MS,
        max_entries: int = RELOGIN_CHALLENGE_MAX_ENTRIES,
        max_per_device: int = RELOGIN_CHALLENGE_MAX_PER_DEVICE,
        monotonic_ms: Callable[[], int] | None = None,
        unix_ms: Callable[[], int] | None = None,
        random_bytes: Callable[[int], bytes] | None = None,
    ) -> None:
        if ttl_ms <= 0:
            raise ValueError("ttl_ms must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if max_per_device <= 0 or max_per_device > max_entries:
            raise ValueError("max_per_device must be in [1, max_entries]")
        self._ttl_ms = int(ttl_ms)
        self._max_entries = int(max_entries)
        self._max_per_device = int(max_per_device)
        self._monotonic_ms = monotonic_ms or (
            lambda: time.monotonic_ns() // 1_000_000
        )
        self._unix_ms = unix_ms or (lambda: time.time_ns() // 1_000_000)
        self._random_bytes = random_bytes or secrets.token_bytes
        self._records: OrderedDict[str, DeviceReloginChallenge] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def ttl_ms(self) -> int:
        return self._ttl_ms

    def _prune_expired_locked(self, now_monotonic_ms: int) -> int:
        removed = 0
        # OrderedDict is insertion ordered and all records use the same TTL, so
        # the first live record proves every later record is live as well.
        while self._records:
            _challenge_id, record = next(iter(self._records.items()))
            if now_monotonic_ms < record.expires_monotonic_ms:
                break
            self._records.popitem(last=False)
            removed += 1
        return removed

    @staticmethod
    def _build_proof(
        *,
        challenge_id_bytes: bytes,
        nonce: bytes,
        device_pub: bytes,
        root_pub: bytes,
        daemon_pub: bytes,
        issued_unix_ms: int,
        expires_unix_ms: int,
    ) -> bytes:
        return b"".join(
            (
                RELOGIN_PROOF_DOMAIN,
                bytes([RELOGIN_CHALLENGE_VERSION]),
                daemon_pub,
                root_pub,
                device_pub,
                challenge_id_bytes,
                nonce,
                struct.pack(">QQ", issued_unix_ms, expires_unix_ms),
            )
        )

    def issue(
        self,
        *,
        device_pub: bytes,
        root_pub: bytes,
        daemon_pub: bytes,
    ) -> DeviceReloginChallenge:
        device = _public_key(device_pub, "device_pub")
        root = _public_key(root_pub, "root_pub")
        daemon = _public_key(daemon_pub, "daemon_pub")
        now_monotonic = int(self._monotonic_ms())
        now_unix = int(self._unix_ms())
        if now_monotonic < 0 or now_unix < 0:
            raise DeviceReloginChallengeError("challenge clock returned a negative time")

        with self._lock:
            self._prune_expired_locked(now_monotonic)
            if len(self._records) >= self._max_entries:
                raise DeviceReloginChallengeCapacityError(
                    "relogin challenge capacity is temporarily exhausted"
                )
            device_count = sum(
                1
                for record in self._records.values()
                if hmac.compare_digest(record.device_pub, device)
            )
            if device_count >= self._max_per_device:
                raise DeviceReloginChallengeCapacityError(
                    "too many outstanding relogin challenges for this device"
                )

            challenge_id_bytes = b""
            challenge_id = ""
            for _attempt in range(8):
                challenge_id_bytes = bytes(
                    self._random_bytes(RELOGIN_CHALLENGE_ID_BYTES)
                )
                if len(challenge_id_bytes) != RELOGIN_CHALLENGE_ID_BYTES:
                    raise DeviceReloginChallengeError(
                        "challenge entropy source returned the wrong length"
                    )
                challenge_id = encode_b64u(challenge_id_bytes)
                if challenge_id not in self._records:
                    break
            else:  # pragma: no cover - requires a malicious/broken RNG
                raise DeviceReloginChallengeError(
                    "could not allocate a unique relogin challenge"
                )
            nonce = bytes(self._random_bytes(RELOGIN_CHALLENGE_NONCE_BYTES))
            if len(nonce) != RELOGIN_CHALLENGE_NONCE_BYTES:
                raise DeviceReloginChallengeError(
                    "challenge entropy source returned the wrong length"
                )
            expires_unix = now_unix + self._ttl_ms
            expires_monotonic = now_monotonic + self._ttl_ms
            proof = self._build_proof(
                challenge_id_bytes=challenge_id_bytes,
                nonce=nonce,
                device_pub=device,
                root_pub=root,
                daemon_pub=daemon,
                issued_unix_ms=now_unix,
                expires_unix_ms=expires_unix,
            )
            record = DeviceReloginChallenge(
                challenge_id=challenge_id,
                challenge_id_bytes=challenge_id_bytes,
                nonce=nonce,
                device_pub=device,
                root_pub=root,
                daemon_pub=daemon,
                issued_unix_ms=now_unix,
                expires_unix_ms=expires_unix,
                issued_monotonic_ms=now_monotonic,
                expires_monotonic_ms=expires_monotonic,
                proof=proof,
            )
            self._records[challenge_id] = record
            return record

    def consume(
        self,
        challenge_id: object,
        *,
        device_pub: bytes,
        root_pub: bytes,
        daemon_pub: bytes,
    ) -> DeviceReloginChallenge:
        """Atomically remove and return a matching, live challenge.

        A syntactically valid known id is consumed before binding checks.  This
        prevents repeated oracle attempts against the same proof and guarantees
        that concurrent submissions can have at most one winner.
        """

        device = _public_key(device_pub, "device_pub")
        root = _public_key(root_pub, "root_pub")
        daemon = _public_key(daemon_pub, "daemon_pub")
        challenge_id_bytes = decode_b64u_strict(
            challenge_id,
            field="challenge_id",
            exact_bytes=RELOGIN_CHALLENGE_ID_BYTES,
            max_bytes=RELOGIN_CHALLENGE_ID_BYTES,
        )
        canonical_id = encode_b64u(challenge_id_bytes)
        now_monotonic = int(self._monotonic_ms())
        with self._lock:
            self._prune_expired_locked(now_monotonic)
            record = self._records.pop(canonical_id, None)
        if record is None:
            raise DeviceReloginChallengeError(
                "relogin challenge is missing, expired, or already used"
            )
        if now_monotonic >= record.expires_monotonic_ms:
            raise DeviceReloginChallengeError("relogin challenge expired")
        if not (
            hmac.compare_digest(record.device_pub, device)
            and hmac.compare_digest(record.root_pub, root)
            and hmac.compare_digest(record.daemon_pub, daemon)
        ):
            raise DeviceReloginChallengeError(
                "relogin challenge does not match this device"
            )
        return record

    def pending_count(self) -> int:
        """Return the number of live records (primarily for diagnostics/tests)."""

        now_monotonic = int(self._monotonic_ms())
        with self._lock:
            self._prune_expired_locked(now_monotonic)
            return len(self._records)


__all__ = [
    "DeviceReloginChallenge",
    "DeviceReloginChallengeCapacityError",
    "DeviceReloginChallengeError",
    "DeviceReloginChallengeStore",
    "RELOGIN_CERT_MAX_BYTES",
    "RELOGIN_CHALLENGE_ID_BYTES",
    "RELOGIN_CHALLENGE_MAX_ENTRIES",
    "RELOGIN_CHALLENGE_MAX_PER_DEVICE",
    "RELOGIN_CHALLENGE_NONCE_BYTES",
    "RELOGIN_CHALLENGE_TTL_MS",
    "RELOGIN_PROOF_DOMAIN",
    "RELOGIN_SIGNATURE_BYTES",
    "decode_b64u_strict",
    "encode_b64u",
]
