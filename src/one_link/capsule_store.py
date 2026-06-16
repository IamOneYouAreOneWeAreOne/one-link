"""Capsule store — serialize, seal, persist, recover.

Wraps the at-rest encryption layer (:mod:`capsule_at_rest`) around
the AsyncCapsule serializer. The daemon's CallManager finalizes a
capsule on async-conversion; this module persists it to disk in
sealed form. Playback re-opens it with the same key.

Wire format inside the seal:
  - Header dict (JSON) with all the capsule scalar fields
  - 4-byte length prefix
  - Audio payload bytes
  - 4-byte length prefix
  - Provenance chain encoded as a JSON array of wire dicts

The whole sequence is fed to ``seal_to_path`` so an attacker with
the device can't read header / audio / provenance without the key.

Pure module: no daemon imports. The daemon's call_manager bridge
calls ``save_sealed_capsule`` on finalization + ``load_sealed_capsule``
on playback.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md Part 14.1 (C5),
           src/one_link/capsule_at_rest.py
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

from one_link.async_capsule import AsyncCapsule, CapsuleKind
from one_link.capsule_at_rest import open_from_path, seal_to_path
from one_link.frame_provenance import (
    from_wire_dict,
    to_wire_dict,
)


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def serialize_capsule(capsule: AsyncCapsule) -> bytes:
    """Pack an AsyncCapsule into its sealed-plaintext form. Inverse of
    :func:`deserialize_capsule`."""
    header = {
        "capsule_id": capsule.capsule_id,
        "call_id": capsule.call_id,
        "kind": int(capsule.kind),
        "sender_master_vk_hex": capsule.sender_master_vk_hex,
        "recipient_master_vk_hex": capsule.recipient_master_vk_hex,
        "started_at_ms": capsule.started_at_ms,
        "finalized_at_ms": capsule.finalized_at_ms,
        "duration_ms": capsule.duration_ms,
        "audio_codec": capsule.audio_codec,
        "sample_rate_hz": capsule.sample_rate_hz,
        "recording_state_at_conversion": int(capsule.recording_state_at_conversion),
        "resumable_until_ms": capsule.resumable_until_ms,
        "payload_hash": capsule.payload_hash,
    }
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    prov_list = [to_wire_dict(p) for p in capsule.provenance_chain]
    prov_bytes = json.dumps(prov_list, separators=(",", ":")).encode("utf-8")
    return (
        struct.pack("!I", len(header_bytes))
        + header_bytes
        + struct.pack("!I", len(capsule.audio_payload))
        + capsule.audio_payload
        + struct.pack("!I", len(prov_bytes))
        + prov_bytes
    )


def deserialize_capsule(data: bytes) -> AsyncCapsule:
    """Unpack a sealed-plaintext capsule blob back into the
    dataclass. Raises ValueError on malformed input."""
    pos = 0
    if len(data) < 4:
        raise ValueError("capsule blob truncated at header length")
    (header_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if pos + header_len > len(data):
        raise ValueError("capsule blob truncated at header body")
    header = json.loads(data[pos:pos + header_len].decode("utf-8"))
    pos += header_len

    if pos + 4 > len(data):
        raise ValueError("capsule blob truncated at audio length")
    (audio_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if pos + audio_len > len(data):
        raise ValueError("capsule blob truncated at audio body")
    audio = data[pos:pos + audio_len]
    pos += audio_len

    if pos + 4 > len(data):
        raise ValueError("capsule blob truncated at provenance length")
    (prov_len,) = struct.unpack("!I", data[pos:pos + 4])
    pos += 4
    if pos + prov_len > len(data):
        raise ValueError("capsule blob truncated at provenance body")
    prov_list = json.loads(data[pos:pos + prov_len].decode("utf-8"))
    pos += prov_len

    if pos != len(data):
        raise ValueError(
            f"capsule blob has {len(data) - pos} trailing bytes",
        )

    from one_link.frame_provenance import RecordingState
    return AsyncCapsule(
        capsule_id=header["capsule_id"],
        call_id=header["call_id"],
        kind=CapsuleKind(header["kind"]),
        sender_master_vk_hex=header["sender_master_vk_hex"],
        recipient_master_vk_hex=header["recipient_master_vk_hex"],
        started_at_ms=header["started_at_ms"],
        finalized_at_ms=header["finalized_at_ms"],
        duration_ms=header["duration_ms"],
        audio_payload=audio,
        audio_codec=header["audio_codec"],
        sample_rate_hz=header["sample_rate_hz"],
        provenance_chain=tuple(from_wire_dict(d) for d in prov_list),
        recording_state_at_conversion=RecordingState(
            header["recording_state_at_conversion"]
        ),
        resumable_until_ms=header["resumable_until_ms"],
        payload_hash=header["payload_hash"],
    )


# ---------------------------------------------------------------------------
# Sealed save / load
# ---------------------------------------------------------------------------

def save_sealed_capsule(
    *,
    capsule: AsyncCapsule,
    out_path: Path,
    master_seed: bytes,
) -> None:
    """Serialize + seal + atomically write to disk. The seal binds
    to ``capsule.call_id`` and ``capsule.finalized_at_ms`` so even
    on the same device a different call's seal can't be replayed."""
    plaintext = serialize_capsule(capsule)
    seal_to_path(
        plaintext=plaintext, out_path=out_path,
        master_seed=master_seed,
        call_id=capsule.call_id,
        finalized_at_ms=capsule.finalized_at_ms,
    )


def load_sealed_capsule(
    *,
    sealed_path: Path,
    master_seed: bytes,
    call_id: str,
    finalized_at_ms: int,
) -> AsyncCapsule:
    """Decrypt + deserialize. The caller must supply ``call_id`` and
    ``finalized_at_ms`` separately (they're in the sealed plaintext,
    but also serve as the AAD — so the caller needs them out-of-band
    to derive the key in the first place).

    The daemon's capsule index stores (call_id, finalized_at_ms) in
    plain SQLite next to the sealed-path reference; the sealed body
    holds the actual capsule content.
    """
    plaintext = open_from_path(
        sealed_path=sealed_path,
        master_seed=master_seed,
        call_id=call_id,
        finalized_at_ms=finalized_at_ms,
    )
    return deserialize_capsule(plaintext)


# ---------------------------------------------------------------------------
# Index helpers — what the daemon stores out-of-band
# ---------------------------------------------------------------------------

def capsule_index_entry(capsule: AsyncCapsule, sealed_path: Path) -> dict:
    """The plaintext metadata the daemon stores in its capsule index
    so it can find + decrypt a capsule later. No secrets here; an
    attacker who steals the index alone still cannot read capsule
    audio / provenance without the master_seed.

    Doctrine §3.2.e — the surface labels stay positive: ``label``
    holds the human-friendly text the chat list will show."""
    from one_link.async_capsule import capsule_label
    return {
        "capsule_id": capsule.capsule_id,
        "call_id": capsule.call_id,
        "finalized_at_ms": capsule.finalized_at_ms,
        "duration_ms": capsule.duration_ms,
        "size_bytes": capsule.size_bytes(),
        "kind": int(capsule.kind),
        "sealed_path": str(sealed_path),
        "label": capsule_label(capsule.kind),
        "resumable_until_ms": capsule.resumable_until_ms,
    }
