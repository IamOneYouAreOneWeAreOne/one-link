"""Cryptographic Reality Engine — frame-level provenance attestation.

Every media segment One Link emits carries a verifiable provenance
tag that attests:

    - Which device produced it (device_id, 8 hex chars of sender fingerprint)
    - Whether it is real / repaired / predicted / reconstructed / blank
    - Path class the engines chose (Local / LAN / Direct / Relay / Onion / Mesh)
    - Recording state (none / local / remote / mutual)
    - Timestamp + producer confidence
    - Sender's Ed25519 signature over a canonical encoding of all fields

The receiver verifies the signature against the sender's master public
key (the same long-lived Ed25519 identity key the rest of One Link uses
for SDP signing, capability minting, and pairing transcripts).

This module is intentionally pure: no I/O, no daemon imports, no UI
concerns. The daemon ([daemon.py]) attaches a FrameProvenance to each
FILE_OFFER / FILE_NATIVE_CHUNK / future media frame it emits. The
receiver verifies and forwards the rendered Reality dot state to the
UI over the existing ``/api/events`` WebSocket.

Wire format: each FrameProvenance is encoded as a small JSON dict (see
``to_wire_dict`` / ``from_wire_dict``) carried alongside its associated
media envelope. For v0.9.2 voice messages, one provenance per file
(per blob hash) is sufficient — the file as a whole is the "segment."
Later tiers (per-chunk, per-RTP-frame) reuse the same primitive with
finer-grained segment hashes.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.5
            docs/DOCTRINE_OF_INVISIBILITY.md §4.c, §4.d
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# Schema version for the canonical-encoding layout. Bump when the
# byte-level layout of the signed fields changes. Receivers that don't
# recognise a schema version refuse the signature and treat the frame
# as unverified.
SCHEMA_V1 = 1

# Canonical sizes (bytes) — used by both Python here and any future
# Rust crate that codegens against this schema.
SEGMENT_HASH_LEN = 32
DEVICE_ID_LEN = 8
ED25519_SIG_LEN = 64


class FrameKind(IntEnum):
    """What kind of media this frame contains. The user sees this in
    plain language on the Reality dot."""

    REAL          = 0   # captured live from the physical sensor
    REPAIRED      = 1   # missing samples filled by codec PLC
    PREDICTED     = 2   # rendered ahead by Predictive Continuity
    RECONSTRUCTED = 3   # rendered from semantic delta + shared model
    BLANK         = 4   # placeholder (camera off, silence, etc.)


class PathClass(IntEnum):
    """Network path the sender chose for this frame."""

    LOCAL  = 0   # same device (multi-device body internal)
    LAN    = 1   # local network
    DIRECT = 2   # P2P direct via WAN
    RELAY  = 3   # via federated relay
    ONION  = 4   # via onion circuit
    MESH   = 5   # OneField radio mesh (future)


class RecordingState(IntEnum):
    """Recording state at the moment this frame was produced."""

    NOT_RECORDING    = 0
    RECORDING_LOCAL  = 1   # only sender side is recording
    RECORDING_REMOTE = 2   # only receiver side is recording (consent required)
    RECORDING_MUTUAL = 3   # both sides agreed


# ---------------------------------------------------------------------------
# The provenance tag itself
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FrameProvenance:
    """Per-frame attestation. All fields are signed except ``signature``.

    Construct via :func:`sign_provenance` rather than directly; that
    helper guarantees the signature covers the canonical encoding.

    Hashable + immutable so the Immune System can cache decisions
    keyed on the provenance hash for soak-replay determinism.
    """

    schema_version: int
    segment_hash: bytes          # BLAKE3-256 of the media segment, 32 bytes
    device_id: str               # 8-hex-char sender device id
    frame_kind: FrameKind
    path_class: PathClass
    recording_state: RecordingState
    timestamp_us: int            # microseconds since Unix epoch
    produce_confidence: float    # 0.0..1.0 — for Body crossfade selection
    signature: bytes             # Ed25519 sig (64 bytes) over canonical fields


# ---------------------------------------------------------------------------
# Canonical encoding
# ---------------------------------------------------------------------------

def _canonical_bytes(p: FrameProvenance) -> bytes:
    """Return the byte string that gets signed.

    Layout (big-endian, fixed-width — deterministic across platforms):

        offset  size  field
        ------  ----  -----------------------------
            0     1   schema_version (u8)
            1    32   segment_hash (BLAKE3-256)
           33     8   device_id (ASCII hex, lower)
           41     1   frame_kind (u8)
           42     1   path_class (u8)
           43     1   recording_state (u8)
           44     8   timestamp_us (u64 big-endian)
           52     2   produce_confidence (u16 big-endian, 0..65535
                       scaled from 0.0..1.0)
        ------------
           54   total

    The signature field is intentionally NOT part of the canonical
    encoding (signing it would require the signature before it's
    produced; that's how schemes fail).
    """
    if not (0 <= p.schema_version <= 255):
        raise ValueError(
            f"schema_version out of range: {p.schema_version}"
        )
    if len(p.segment_hash) != SEGMENT_HASH_LEN:
        raise ValueError(
            f"segment_hash must be {SEGMENT_HASH_LEN} bytes, "
            f"got {len(p.segment_hash)}"
        )
    if len(p.device_id) != DEVICE_ID_LEN:
        raise ValueError(
            f"device_id must be {DEVICE_ID_LEN} hex chars, "
            f"got {len(p.device_id)!r}"
        )
    if not all(c in "0123456789abcdef" for c in p.device_id):
        raise ValueError(
            f"device_id must be lowercase hex, got {p.device_id!r}"
        )
    if not (0 <= p.timestamp_us < 2**64):
        raise ValueError(
            f"timestamp_us out of range: {p.timestamp_us}"
        )
    if not (0.0 <= p.produce_confidence <= 1.0):
        raise ValueError(
            f"produce_confidence must be in [0.0, 1.0], "
            f"got {p.produce_confidence}"
        )
    confidence_int = round(p.produce_confidence * 65535)
    confidence_int = max(0, min(65535, confidence_int))

    out = bytearray(54)
    out[0] = p.schema_version & 0xff
    out[1:33] = p.segment_hash
    out[33:41] = p.device_id.encode("ascii")
    out[41] = int(p.frame_kind) & 0xff
    out[42] = int(p.path_class) & 0xff
    out[43] = int(p.recording_state) & 0xff
    out[44:52] = p.timestamp_us.to_bytes(8, "big")
    out[52:54] = confidence_int.to_bytes(2, "big")
    return bytes(out)


# ---------------------------------------------------------------------------
# Mint + verify
# ---------------------------------------------------------------------------

def sign_provenance(
    *,
    segment_hash: bytes,
    device_id: str,
    frame_kind: FrameKind,
    path_class: PathClass,
    recording_state: RecordingState,
    timestamp_us: int,
    produce_confidence: float,
    signing_key: Ed25519PrivateKey,
    schema_version: int = SCHEMA_V1,
) -> FrameProvenance:
    """Mint a fresh FrameProvenance and attach the sender's signature.

    The signing key is the sender's Identity.private (the long-lived
    Ed25519 device identity). The receiver verifies against the
    sender's master public key — the same one pinned during pairing.
    """
    unsigned = FrameProvenance(
        schema_version=schema_version,
        segment_hash=segment_hash,
        device_id=device_id,
        frame_kind=frame_kind,
        path_class=path_class,
        recording_state=recording_state,
        timestamp_us=timestamp_us,
        produce_confidence=produce_confidence,
        signature=b"",
    )
    canonical = _canonical_bytes(unsigned)
    sig = signing_key.sign(canonical)
    if len(sig) != ED25519_SIG_LEN:
        # Defensive: cryptography library should always produce 64
        # bytes for Ed25519, but if a future swap changes that the
        # canonical layout assumption breaks here, fail loud.
        raise RuntimeError(
            f"unexpected signature length {len(sig)}, expected "
            f"{ED25519_SIG_LEN}"
        )
    return FrameProvenance(
        schema_version=schema_version,
        segment_hash=segment_hash,
        device_id=device_id,
        frame_kind=frame_kind,
        path_class=path_class,
        recording_state=recording_state,
        timestamp_us=timestamp_us,
        produce_confidence=produce_confidence,
        signature=sig,
    )


def verify_provenance(
    p: FrameProvenance,
    sender_public_bytes: bytes,
) -> bool:
    """Return True iff the signature verifies against the sender's
    public key. Any exception (bad signature, wrong key, malformed
    fields, etc.) returns False — never raise."""
    try:
        if len(p.signature) != ED25519_SIG_LEN:
            return False
        if p.schema_version != SCHEMA_V1:
            # Unknown schema — refuse rather than silently accept.
            return False
        canonical = _canonical_bytes(p)
        pub = Ed25519PublicKey.from_public_bytes(sender_public_bytes)
        pub.verify(p.signature, canonical)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


# ---------------------------------------------------------------------------
# Hashes + helpers
# ---------------------------------------------------------------------------

def make_segment_hash(data: bytes) -> bytes:
    """Compute the canonical BLAKE3-256 hash of a media segment.

    For voice messages v0.9.2, this is the BLAKE3 of the entire opus
    blob. Future tiers (per-RTP-frame) will use this on each frame's
    raw bytes.
    """
    return blake3.blake3(data).digest()


def now_us() -> int:
    """Microseconds since Unix epoch. Helper so callers don't reach
    for ``time.time()`` and round-trip through floats."""
    import time
    return int(time.time() * 1_000_000)


# ---------------------------------------------------------------------------
# Wire format (JSON-on-the-wire)
# ---------------------------------------------------------------------------

# Field-name abbreviations keep the wire frame compact. The canonical
# encoding above is independent of this — the wire dict is reassembled
# into a FrameProvenance before verification.
_WIRE_FIELDS = ("v", "seg", "did", "fk", "pc", "rs", "ts", "pcf", "sig")


def to_wire_dict(p: FrameProvenance) -> dict[str, Any]:
    """Encode for the One Link wire envelope (JSON-in-AEAD-in-frame)."""
    return {
        "v":   p.schema_version,
        "seg": p.segment_hash.hex(),
        "did": p.device_id,
        "fk":  int(p.frame_kind),
        "pc":  int(p.path_class),
        "rs":  int(p.recording_state),
        "ts":  p.timestamp_us,
        "pcf": p.produce_confidence,
        "sig": p.signature.hex(),
    }


def from_wire_dict(d: dict[str, Any]) -> FrameProvenance:
    """Decode from the One Link wire envelope.

    Raises ValueError on missing/malformed fields. The caller is
    responsible for verifying the signature afterwards with
    :func:`verify_provenance`.
    """
    for field in _WIRE_FIELDS:
        if field not in d:
            raise ValueError(f"missing field in provenance wire dict: {field}")
    try:
        return FrameProvenance(
            schema_version=int(d["v"]),
            segment_hash=bytes.fromhex(d["seg"]),
            device_id=str(d["did"]),
            frame_kind=FrameKind(int(d["fk"])),
            path_class=PathClass(int(d["pc"])),
            recording_state=RecordingState(int(d["rs"])),
            timestamp_us=int(d["ts"]),
            produce_confidence=float(d["pcf"]),
            signature=bytes.fromhex(d["sig"]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"malformed provenance wire dict: {exc}") from exc


# ---------------------------------------------------------------------------
# UI-facing language
# ---------------------------------------------------------------------------

# Per the Doctrine of Invisibility §3.9.a + §3.6.c, no fingerprint hex
# or network-technology jargon surfaces to the user. The functions
# below map enum values to plain-language tokens for the Reality dot
# detail pane. The web UI calls into these via the /api/events
# WebSocket event so all language is centralised here.

def frame_kind_label(k: FrameKind) -> str:
    return {
        FrameKind.REAL:          "Real",
        FrameKind.REPAIRED:      "Repaired",
        FrameKind.PREDICTED:     "Predicted",
        FrameKind.RECONSTRUCTED: "Reconstructed",
        FrameKind.BLANK:         "Blank",
    }[k]


def path_class_label(pc: PathClass) -> str:
    return {
        PathClass.LOCAL:  "Same device",
        PathClass.LAN:    "Local network",
        PathClass.DIRECT: "Direct",
        PathClass.RELAY:  "Via relay",
        PathClass.ONION:  "Through onion",
        PathClass.MESH:   "Mesh radio",
    }[pc]


def recording_state_label(rs: RecordingState) -> str:
    return {
        RecordingState.NOT_RECORDING:    "Not recording",
        RecordingState.RECORDING_LOCAL:  "You are recording",
        RecordingState.RECORDING_REMOTE: "They are recording",
        RecordingState.RECORDING_MUTUAL: "Recording (both)",
    }[rs]


def to_ui_dict(p: FrameProvenance, *, verified: bool) -> dict[str, Any]:
    """Render a FrameProvenance into plain-language fields the UI shows.

    Never includes raw hex (fingerprints, signatures) — those are
    forbidden by Doctrine §3.9.a from the user surface. The
    "Show technical details" affordance in the Reality detail pane
    (§5.i of the Doctrine) is the only place hex would be exposed,
    and that uses to_wire_dict instead.
    """
    return {
        "kind":           frame_kind_label(p.frame_kind),
        "path":           path_class_label(p.path_class),
        "recording":      recording_state_label(p.recording_state),
        "verified":       verified,
        "produced_at_us": p.timestamp_us,
    }
