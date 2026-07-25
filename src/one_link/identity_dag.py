"""Identity DAG — multi-device identity without sharing the master key.

Today One Link identity = one Ed25519 keypair = one device. A user
with phone + laptop + tablet either juggles three separate
identities (terrible UX) or shares one private key across devices
(terrible security: a single device compromise reveals every
device's private key, and revoking one device requires rotating
all of them).

Bundle 45 ships a DAG-shaped identity model:

  - **Root keypair** (Ed25519): the master identity. Typically
    derived from the user's master seed (Bundle 23) so it survives
    the social-recovery flow (Bundle 35).
  - **Device certs** (signed by root): each device gets its own
    Ed25519 keypair and a cert binding (root_pub, device_pub,
    device_kind, added_ms, expires_ms) under the root signature.
    The device's PRIVATE key never leaves the device.
  - **Session attestations**: when a device proves "I am a device
    of identity I" to a peer P, it sends (cert, signature_by_device
    over (P's challenge_nonce + transcript)). Two signatures: cert
    proves root authorized the device; attestation proves the
    device's holder is the one signing right now.

Properties:

  - **One device compromise = ONE device revoked.** The root key
    stays cold (or in a hardware token, or only-on-the-device-with-
    the-user's-paper-backup). Revoking a phone means publishing
    a revocation bound to that device_pub; the laptop's cert
    stays valid.
  - **Multi-device discovery**: a peer learning about identity I
    can be told "I has these N device pubkeys, here are N certs."
    Any one of those devices can sign for I.
  - **Recovery composability**: Bundle 35 social recovery on the
    root seed brings back the root keypair on a fresh device.
    From there, the user mints new device certs for their
    remaining devices (or revokes the lost ones).

Wire format
-----------

Device cert (variable length):

  [magic: b"OLIDC1"] (6 bytes)
  [version: 1 byte]
  [root_pub: 32 bytes]
  [device_pub: 32 bytes]
  [added_ms: 8 bytes BE]
  [expires_ms: 8 bytes BE]              # 0 means never expires
  [u16 device_kind_len][device_kind]    # e.g. "phone-ios"
  [signature: 64 bytes]                 # root sig over above

Session attestation (variable, wraps a cert):

  [u16 cert_len][cert]
  [u16 challenge_len][challenge]
  [u16 transcript_len][transcript]
  [signature: 64 bytes]                 # device sig over
                                          (challenge || transcript)

The verifier supplies the challenge (a fresh nonce per session)
and the transcript hash from the channel handshake. The signature
binds the device to THIS session, so a captured attestation can't
be replayed against a different verifier.
"""
from __future__ import annotations

import secrets
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)


CERT_MAGIC = b"OLIDC1"
CERT_VERSION = 1
ED_PUB_LEN = 32
SIG_LEN = 64
MAX_DEVICE_KIND_LEN = 64
MAX_CHALLENGE_LEN = 256
MAX_TRANSCRIPT_LEN = 256
MAX_CERT_FUTURE_SKEW_MS = 60_000
MAX_I64 = 2**63 - 1
CERT_HEADER_FIXED_LEN = (
    len(CERT_MAGIC) + 1
    + ED_PUB_LEN + ED_PUB_LEN
    + 8 + 8
)
ATT_CERT_PREFIX_LEN = 2
ATT_CHALLENGE_PREFIX_LEN = 2
ATT_TRANSCRIPT_PREFIX_LEN = 2


# ── DeviceCert ────────────────────────────────────────────────────


@dataclass(frozen=True)
class DeviceCert:
    root_pub: bytes
    device_pub: bytes
    added_ms: int
    expires_ms: int
    device_kind: str
    signature: bytes
    encoded: bytes


def encode_device_cert(
    *,
    root_priv_seed: bytes,
    root_pub: bytes,
    device_pub: bytes,
    device_kind: str,
    added_ms: int | None = None,
    expires_ms: int = 0,
) -> bytes:
    """Mint + sign a device cert with the root's Ed25519 priv."""
    if not isinstance(root_priv_seed, bytes) or len(root_priv_seed) != 32:
        raise ValueError("root_priv_seed must be 32 bytes")
    if not isinstance(root_pub, bytes) or len(root_pub) != ED_PUB_LEN:
        raise ValueError(f"root_pub must be {ED_PUB_LEN} bytes")
    if not isinstance(device_pub, bytes) or len(device_pub) != ED_PUB_LEN:
        raise ValueError(f"device_pub must be {ED_PUB_LEN} bytes")
    if root_pub == device_pub:
        raise ValueError("root_pub and device_pub must differ")
    if not isinstance(device_kind, str):
        raise ValueError("device_kind must be text")
    kind_bytes = device_kind.encode("utf-8")
    if len(kind_bytes) == 0:
        raise ValueError("device_kind must not be empty")
    if len(kind_bytes) > MAX_DEVICE_KIND_LEN:
        raise ValueError(
            f"device_kind too long: {len(kind_bytes)} > {MAX_DEVICE_KIND_LEN}"
        )
    if added_ms is None:
        added_ms = int(time.time() * 1000)
    if isinstance(added_ms, bool) or not isinstance(added_ms, int):
        raise ValueError("added_ms must be an integer")
    if isinstance(expires_ms, bool) or not isinstance(expires_ms, int):
        raise ValueError("expires_ms must be an integer")
    if not (0 <= added_ms <= MAX_I64):
        raise ValueError("added_ms out of range")
    if not (0 <= expires_ms <= MAX_I64):
        raise ValueError("expires_ms out of range")
    if expires_ms != 0 and expires_ms < added_ms:
        raise ValueError(
            f"expires_ms {expires_ms} < added_ms {added_ms}"
        )
    body = (
        CERT_MAGIC + bytes([CERT_VERSION])
        + root_pub + device_pub
        + struct.pack(">QQ", added_ms, expires_ms)
        + struct.pack(">H", len(kind_bytes)) + kind_bytes
    )
    sig = Ed25519PrivateKey.from_private_bytes(root_priv_seed).sign(body)
    return body + sig


def parse_device_cert(blob: bytes) -> DeviceCert:
    if not isinstance(blob, bytes):
        raise ValueError("cert must be bytes")
    if len(blob) < CERT_HEADER_FIXED_LEN + 2 + SIG_LEN:
        raise ValueError("cert too short")
    if blob[:6] != CERT_MAGIC:
        raise ValueError("not a One Link device cert (bad magic)")
    if blob[6] != CERT_VERSION:
        raise ValueError(f"unsupported cert version {blob[6]}")
    off = 7
    root_pub = blob[off:off + ED_PUB_LEN]; off += ED_PUB_LEN
    device_pub = blob[off:off + ED_PUB_LEN]; off += ED_PUB_LEN
    added_ms, expires_ms = struct.unpack(">QQ", blob[off:off + 16])
    off += 16
    if off + 2 > len(blob):
        raise ValueError("cert truncated at device_kind length")
    kind_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if kind_len > MAX_DEVICE_KIND_LEN:
        raise ValueError(f"device_kind_len exceeds cap: {kind_len}")
    if off + kind_len + SIG_LEN != len(blob):
        raise ValueError("cert length mismatch")
    kind = blob[off:off + kind_len].decode("utf-8")
    off += kind_len
    sig = blob[off:off + SIG_LEN]
    return DeviceCert(
        root_pub=root_pub, device_pub=device_pub,
        added_ms=added_ms, expires_ms=expires_ms,
        device_kind=kind, signature=sig, encoded=blob,
    )


def verify_device_cert(
    blob: bytes,
    *,
    expected_root_pub: bytes | None = None,
    now_ms: int | None = None,
) -> DeviceCert:
    """Verify a device cert's signature + (optional) root binding +
    expiry. Raises ValueError on any failure."""
    parsed = parse_device_cert(blob)
    body = blob[:-SIG_LEN]
    try:
        Ed25519PublicKey.from_public_bytes(parsed.root_pub).verify(
            parsed.signature, body,
        )
    except InvalidSignature:
        raise ValueError("device-cert signature invalid") from None
    if parsed.root_pub == parsed.device_pub:
        raise ValueError("device-cert root_pub and device_pub must differ")
    if not parsed.device_kind:
        raise ValueError("device-cert device_kind must not be empty")
    if parsed.added_ms > MAX_I64 or parsed.expires_ms > MAX_I64:
        raise ValueError("device-cert timestamp out of range")
    if parsed.expires_ms != 0 and parsed.expires_ms < parsed.added_ms:
        raise ValueError("device-cert expiry precedes issuance")
    if expected_root_pub is not None:
        if parsed.root_pub != expected_root_pub:
            raise ValueError(
                f"cert root_pub doesn't match expected "
                f"{expected_root_pub.hex()[:16]}…"
            )
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    if isinstance(now_ms, bool) or not isinstance(now_ms, int):
        raise ValueError("now_ms must be an integer")
    if not (0 <= now_ms <= MAX_I64):
        raise ValueError("now_ms out of range")
    if parsed.added_ms > now_ms + MAX_CERT_FUTURE_SKEW_MS:
        raise ValueError("device cert issuance is in the future")
    if parsed.expires_ms != 0 and now_ms > parsed.expires_ms:
        raise ValueError(
            f"device cert expired: now {now_ms} > "
            f"expires {parsed.expires_ms}"
        )
    return parsed


# ── Session attestation ───────────────────────────────────────────


@dataclass(frozen=True)
class SessionAttestation:
    cert: DeviceCert
    challenge: bytes
    transcript: bytes
    signature: bytes
    encoded: bytes


def encode_attestation(
    *,
    device_priv_seed: bytes,
    cert: bytes,
    challenge: bytes,
    transcript: bytes,
) -> bytes:
    """Device proves "I'm a current device of identity I" by signing
    the verifier's challenge + the channel transcript."""
    if len(device_priv_seed) != 32:
        raise ValueError("device_priv_seed must be 32 bytes")
    if len(cert) > 65535:
        raise ValueError("cert too large for u16 length prefix")
    if len(challenge) == 0 or len(challenge) > MAX_CHALLENGE_LEN:
        raise ValueError(
            f"challenge must be 1..{MAX_CHALLENGE_LEN} bytes"
        )
    if len(transcript) > MAX_TRANSCRIPT_LEN:
        raise ValueError(
            f"transcript exceeds {MAX_TRANSCRIPT_LEN} bytes"
        )
    sig_input = (
        b"OL/identity-dag/attestation|v1|"
        + struct.pack(">H", len(challenge)) + challenge
        + struct.pack(">H", len(transcript)) + transcript
    )
    sig = Ed25519PrivateKey.from_private_bytes(device_priv_seed).sign(sig_input)
    return (
        struct.pack(">H", len(cert)) + cert
        + struct.pack(">H", len(challenge)) + challenge
        + struct.pack(">H", len(transcript)) + transcript
        + sig
    )


def parse_attestation(blob: bytes) -> SessionAttestation:
    if len(blob) < 6 + SIG_LEN:
        raise ValueError("attestation too short")
    off = 0
    cert_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if off + cert_len > len(blob):
        raise ValueError("attestation truncated at cert")
    cert_blob = blob[off:off + cert_len]
    off += cert_len
    if off + 2 > len(blob):
        raise ValueError("attestation truncated at challenge len")
    challenge_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if challenge_len == 0 or challenge_len > MAX_CHALLENGE_LEN:
        raise ValueError(
            f"challenge_len {challenge_len} out of bounds"
        )
    if off + challenge_len > len(blob):
        raise ValueError("attestation truncated at challenge")
    challenge = blob[off:off + challenge_len]
    off += challenge_len
    if off + 2 > len(blob):
        raise ValueError("attestation truncated at transcript len")
    transcript_len = struct.unpack(">H", blob[off:off + 2])[0]
    off += 2
    if transcript_len > MAX_TRANSCRIPT_LEN:
        raise ValueError(
            f"transcript_len {transcript_len} exceeds cap"
        )
    if off + transcript_len + SIG_LEN != len(blob):
        raise ValueError("attestation length mismatch")
    transcript = blob[off:off + transcript_len]
    off += transcript_len
    signature = blob[off:off + SIG_LEN]
    cert = parse_device_cert(cert_blob)
    return SessionAttestation(
        cert=cert, challenge=challenge, transcript=transcript,
        signature=signature, encoded=blob,
    )


def verify_attestation(
    blob: bytes,
    *,
    expected_root_pub: bytes | None = None,
    expected_challenge: bytes | None = None,
    expected_transcript: bytes | None = None,
    now_ms: int | None = None,
) -> SessionAttestation:
    """The full verification flow: parse the attestation, verify the
    embedded device cert under the root's signature, verify the
    fresh device signature over (challenge || transcript), and
    enforce caller-supplied bindings on root / challenge / transcript.

    Raises ValueError on any failure; returns the parsed attestation
    on success."""
    parsed = parse_attestation(blob)
    # Verify the cert.
    cert = verify_device_cert(
        parsed.cert.encoded,
        expected_root_pub=expected_root_pub,
        now_ms=now_ms,
    )
    # Verify the fresh attestation signature under cert.device_pub.
    sig_input = (
        b"OL/identity-dag/attestation|v1|"
        + struct.pack(">H", len(parsed.challenge)) + parsed.challenge
        + struct.pack(">H", len(parsed.transcript)) + parsed.transcript
    )
    try:
        Ed25519PublicKey.from_public_bytes(cert.device_pub).verify(
            parsed.signature, sig_input,
        )
    except InvalidSignature:
        raise ValueError("attestation signature invalid") from None
    if expected_challenge is not None:
        if parsed.challenge != expected_challenge:
            raise ValueError(
                "attestation challenge doesn't match expected — "
                "possibly a replayed attestation from a different session"
            )
    if expected_transcript is not None:
        if parsed.transcript != expected_transcript:
            raise ValueError(
                "attestation transcript doesn't match channel transcript"
            )
    return parsed


def fresh_challenge() -> bytes:
    """Mint a 32-byte fresh challenge nonce. Verifiers send this to
    the attesting peer in a session-init frame; the peer signs it
    + their channel transcript to prove they're alive + bound."""
    return secrets.token_bytes(32)
