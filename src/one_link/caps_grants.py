"""Signed capability grants — fine-grained authority with auto-expiry.

Today's capability system (capabilities.py) is binary: either a
peer is paired (full access to whatever capabilities both sides
advertise) or not paired (denied). Three real-world flows aren't
served by that:

  1. **One-shot delegation**: "let my colleague pull these files
     for the next hour while I'm asleep, then auto-revoke."

  2. **Bounded scope**: "this peer can read folder /shared but
     not /private, files under 100 MB, no chat."

  3. **Offline-resilient revocation**: a peer that's currently
     offline can't issue a revoke. A grant that auto-expires
     bounds the worst-case exposure window without needing the
     granter to come online.

Bundle 44 ships a signed-capability-grant primitive. The granter
mints a Ed25519-signed token bearing:

  - granter_pub        (32 bytes — who issued)
  - subject_pub        (32 bytes — who is granted to)
  - capabilities       (set of strings — what's allowed)
  - resource_scope     (bytes — opaque scope, e.g. folder root_id)
  - not_before_ms      (epoch when grant activates)
  - not_after_ms       (epoch when grant auto-expires)
  - nonce              (16 bytes — replay defense per grant)

The receiver verifies on every use:
  - Signature is valid under granter_pub
  - now ∈ [not_before_ms, not_after_ms]
  - nonce hasn't been replayed (caller maintains a seen-set)
  - subject_pub matches the presenting peer

Combined with the existing pair-flow + capability-policy code,
this lets a granter say "this device is paired AND can do these
specific actions until time T". After T, the grant is dead even
if the granter is offline. After explicit revoke (a tombstone the
granter pre-commits or broadcasts), it's also dead.

Wire format
-----------

  [magic: b"OLCAP1"] (6 bytes)
  [version: 1 byte]
  [granter_pub: 32 bytes]
  [subject_pub: 32 bytes]
  [not_before_ms: 8 bytes BE]
  [not_after_ms: 8 bytes BE]
  [nonce: 16 bytes]
  [u16 caps_len]
  [caps: caps_len bytes — UTF-8 sorted comma-separated capability tags]
  [u16 scope_len]
  [scope: scope_len bytes — opaque caller-defined]
  [signature: 64 bytes]

The signature covers everything from magic to scope (i.e. the
whole record except the trailing 64 bytes).

Capability tag namespace:
  - "files:read" / "files:write"
  - "folder:read:<root_id_hex>" / "folder:write:<root_id_hex>"
  - "chat:send" / "chat:read"
  - "groups:join" / "groups:speak"
  - "rdz:lookup"
The tags are caller-defined; this module is opaque to the names.
"""
from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


GRANT_MAGIC = b"OLCAP1"
GRANT_VERSION = 1
NONCE_LEN = 16
SIG_LEN = 64
ED_PUB_LEN = 32
HEADER_FIXED_LEN = (
    len(GRANT_MAGIC) + 1
    + ED_PUB_LEN + ED_PUB_LEN
    + 8 + 8 + NONCE_LEN
)
MAX_CAPS_LEN = 4096
MAX_SCOPE_LEN = 4096


def _normalize_caps(capabilities: Iterable[str]) -> bytes:
    """Caps are stored sorted + comma-joined for canonical
    serialization. A grant with caps {"a", "b"} encodes the same
    bytes as one with {"b", "a"}, so the signature is stable."""
    seen = set()
    for c in capabilities:
        if not isinstance(c, str):
            raise TypeError(f"capability must be a string, got {type(c)}")
        if not c:
            raise ValueError("capability strings must not be empty")
        if "," in c:
            raise ValueError(
                f"capability {c!r} contains comma (delimiter); "
                "use a non-comma name"
            )
        seen.add(c)
    encoded = ",".join(sorted(seen)).encode("utf-8")
    if len(encoded) > MAX_CAPS_LEN:
        raise ValueError(
            f"caps too long: {len(encoded)} > {MAX_CAPS_LEN}"
        )
    return encoded


def _decode_caps(encoded: bytes) -> set[str]:
    if not encoded:
        return set()
    s = encoded.decode("utf-8")
    return set(part for part in s.split(",") if part)


@dataclass(frozen=True)
class CapabilityGrant:
    granter_pub: bytes
    subject_pub: bytes
    not_before_ms: int
    not_after_ms: int
    nonce: bytes
    capabilities: frozenset[str]
    scope: bytes
    signature: bytes
    encoded: bytes


def encode_grant(
    *,
    granter_priv_seed: bytes,
    granter_pub: bytes,
    subject_pub: bytes,
    capabilities: Iterable[str],
    not_before_ms: int,
    not_after_ms: int,
    nonce: bytes | None = None,
    scope: bytes = b"",
) -> bytes:
    """Mint + sign a capability grant. ``not_before_ms`` and
    ``not_after_ms`` are wall-clock epochs in milliseconds. Caller
    is responsible for picking sensible values; we enforce only
    that ``not_before <= not_after`` and both fit in u64."""
    if len(granter_priv_seed) != 32:
        raise ValueError("granter_priv_seed must be 32 bytes")
    if len(granter_pub) != ED_PUB_LEN:
        raise ValueError(f"granter_pub must be {ED_PUB_LEN} bytes")
    if len(subject_pub) != ED_PUB_LEN:
        raise ValueError(f"subject_pub must be {ED_PUB_LEN} bytes")
    if not (0 <= not_before_ms <= 2**63 - 1):
        raise ValueError("not_before_ms out of range")
    if not (0 <= not_after_ms <= 2**63 - 1):
        raise ValueError("not_after_ms out of range")
    if not_before_ms > not_after_ms:
        raise ValueError(
            f"not_before_ms {not_before_ms} > not_after_ms {not_after_ms}"
        )
    if nonce is None:
        nonce = secrets.token_bytes(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes")
    if len(scope) > MAX_SCOPE_LEN:
        raise ValueError(f"scope too long: {len(scope)} > {MAX_SCOPE_LEN}")

    caps_bytes = _normalize_caps(capabilities)
    body = (
        GRANT_MAGIC + bytes([GRANT_VERSION])
        + granter_pub + subject_pub
        + struct.pack(">QQ", not_before_ms, not_after_ms)
        + nonce
        + struct.pack(">H", len(caps_bytes)) + caps_bytes
        + struct.pack(">H", len(scope)) + bytes(scope)
    )
    sig = Ed25519PrivateKey.from_private_bytes(granter_priv_seed).sign(body)
    return body + sig


def parse_grant(blob: bytes) -> CapabilityGrant:
    if len(blob) < HEADER_FIXED_LEN + 2 + 2 + SIG_LEN:
        raise ValueError(
            f"grant too short ({len(blob)} bytes); minimum is "
            f"{HEADER_FIXED_LEN + 2 + 2 + SIG_LEN}"
        )
    if blob[:6] != GRANT_MAGIC:
        raise ValueError("not a One Link capability grant (bad magic)")
    if blob[6] != GRANT_VERSION:
        raise ValueError(f"unsupported grant version {blob[6]}")
    off = 7
    granter_pub = blob[off:off + ED_PUB_LEN]; off += ED_PUB_LEN
    subject_pub = blob[off:off + ED_PUB_LEN]; off += ED_PUB_LEN
    not_before_ms, not_after_ms = struct.unpack(">QQ", blob[off:off + 16])
    off += 16
    nonce = blob[off:off + NONCE_LEN]; off += NONCE_LEN
    if off + 2 > len(blob):
        raise ValueError("grant truncated at caps_len")
    caps_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if caps_len > MAX_CAPS_LEN:
        raise ValueError(f"caps_len exceeds cap: {caps_len}")
    if off + caps_len > len(blob):
        raise ValueError("grant truncated at caps body")
    caps_bytes = blob[off:off + caps_len]
    off += caps_len
    if off + 2 > len(blob):
        raise ValueError("grant truncated at scope_len")
    scope_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if scope_len > MAX_SCOPE_LEN:
        raise ValueError(f"scope_len exceeds cap: {scope_len}")
    if off + scope_len + SIG_LEN != len(blob):
        raise ValueError(
            f"grant length mismatch: header says caps={caps_len} "
            f"scope={scope_len} but blob is {len(blob)} bytes"
        )
    scope = blob[off:off + scope_len]
    off += scope_len
    signature = blob[off:off + SIG_LEN]
    return CapabilityGrant(
        granter_pub=granter_pub,
        subject_pub=subject_pub,
        not_before_ms=not_before_ms,
        not_after_ms=not_after_ms,
        nonce=nonce,
        capabilities=frozenset(_decode_caps(caps_bytes)),
        scope=scope,
        signature=signature,
        encoded=blob,
    )


def verify_grant(
    blob: bytes,
    *,
    expected_granter_pub: bytes | None = None,
    expected_subject_pub: bytes | None = None,
    now_ms: int | None = None,
    seen_nonces: set[bytes] | None = None,
) -> CapabilityGrant:
    """Verify a grant's signature + temporal validity + (optional)
    granter/subject identity binding + (optional) replay defense.

    Raises ValueError on any failure; returns the parsed grant on
    success."""
    parsed = parse_grant(blob)
    body = blob[:-SIG_LEN]
    try:
        Ed25519PublicKey.from_public_bytes(parsed.granter_pub).verify(
            parsed.signature, body,
        )
    except InvalidSignature:
        raise ValueError("grant signature invalid") from None
    if expected_granter_pub is not None:
        if parsed.granter_pub != expected_granter_pub:
            raise ValueError(
                f"grant granter_pub doesn't match expected "
                f"{expected_granter_pub.hex()[:16]}…"
            )
    if expected_subject_pub is not None:
        if parsed.subject_pub != expected_subject_pub:
            raise ValueError(
                f"grant subject_pub doesn't match presenter "
                f"{expected_subject_pub.hex()[:16]}…"
            )
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if now_ms < parsed.not_before_ms:
        raise ValueError(
            f"grant not yet valid: now_ms {now_ms} < "
            f"not_before {parsed.not_before_ms}"
        )
    # Audit L9 May 2026: tightened to `>=` so a grant expires AT
    # not_after_ms, not one ms past. Matches the ExpiresAt caveat
    # semantics in ol_capability::Caveat::check.
    if now_ms >= parsed.not_after_ms:
        raise ValueError(
            f"grant expired: now_ms {now_ms} >= "
            f"not_after {parsed.not_after_ms}"
        )
    if seen_nonces is not None:
        if parsed.nonce in seen_nonces:
            raise ValueError(
                f"grant nonce replayed: {parsed.nonce.hex()[:16]}…"
            )
        # Audit M11 May 2026: CapStore upgraded `seen_nonces` from
        # `set` to `OrderedDict` so eviction-on-overflow drops the
        # OLDEST nonce, not a random one. Accept both container
        # shapes — sets via .add(), OrderedDicts via __setitem__.
        adder = getattr(seen_nonces, "add", None)
        if adder is not None:
            adder(parsed.nonce)
        else:
            seen_nonces[parsed.nonce] = None  # type: ignore[index]
    return parsed
