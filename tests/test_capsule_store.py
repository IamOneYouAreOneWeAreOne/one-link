"""Tests for the at-rest capsule store.

Properties:
  - serialize → deserialize round-trip yields byte-equal AsyncCapsule
  - save_sealed → load_sealed yields equivalent capsule
  - Wrong key fails decryption (no plaintext leak)
  - Index entry contains no secrets
"""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.async_capsule import AsyncCapsule, CapsuleKind
from one_link.capsule_store import (
    capsule_index_entry,
    deserialize_capsule,
    load_sealed_capsule,
    save_sealed_capsule,
    serialize_capsule,
)
from one_link.frame_provenance import (
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    make_segment_hash,
    sign_provenance,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_capsule(n_segments: int = 3) -> AsyncCapsule:
    sk = Ed25519PrivateKey.generate()
    device_id = "deadbeef"
    prov_chain = []
    audio_chunks = []
    for i in range(n_segments):
        chunk = f"audio-segment-{i}".encode() * 10
        audio_chunks.append(chunk)
        prov_chain.append(sign_provenance(
            segment_hash=make_segment_hash(chunk),
            device_id=device_id,
            frame_kind=FrameKind.REAL,
            path_class=PathClass.LAN,
            recording_state=RecordingState.NOT_RECORDING,
            timestamp_us=1_700_000_000_000_000 + i * 20_000,
            produce_confidence=1.0,
            signing_key=sk,
        ))
    audio = b"".join(audio_chunks)
    return AsyncCapsule(
        capsule_id="capsule-test-1",
        call_id="call-xyz-9",
        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
        sender_master_vk_hex="a" * 64,
        recipient_master_vk_hex="b" * 64,
        started_at_ms=1_700,
        finalized_at_ms=2_700,
        duration_ms=1_000,
        audio_payload=audio,
        audio_codec="opus",
        sample_rate_hz=48_000,
        provenance_chain=tuple(prov_chain),
        recording_state_at_conversion=RecordingState.NOT_RECORDING,
        resumable_until_ms=1_000_000,
        payload_hash=hashlib.sha256(audio).hexdigest(),
    )


# ---------------------------------------------------------------------------
# Serialization round-trip
# ---------------------------------------------------------------------------

def test_serialize_deserialize_round_trip_3_segments() -> None:
    cap = _make_capsule(n_segments=3)
    blob = serialize_capsule(cap)
    out = deserialize_capsule(blob)
    assert out.capsule_id == cap.capsule_id
    assert out.audio_payload == cap.audio_payload
    assert len(out.provenance_chain) == 3
    # Sigs survive byte-for-byte
    for orig, back in zip(cap.provenance_chain, out.provenance_chain):
        assert orig.signature == back.signature
        assert orig.segment_hash == back.segment_hash


def test_serialize_deserialize_round_trip_empty_provenance() -> None:
    cap = _make_capsule(n_segments=0)
    cap_zero = AsyncCapsule(**{**cap.__dict__, "provenance_chain": ()})
    blob = serialize_capsule(cap_zero)
    out = deserialize_capsule(blob)
    assert out.provenance_chain == ()


def test_deserialize_rejects_truncated_blob() -> None:
    cap = _make_capsule()
    blob = serialize_capsule(cap)
    with pytest.raises(ValueError, match="truncated"):
        deserialize_capsule(blob[:-10])


def test_deserialize_rejects_trailing_garbage() -> None:
    cap = _make_capsule()
    blob = serialize_capsule(cap) + b"extra-bytes"
    with pytest.raises(ValueError, match="trailing"):
        deserialize_capsule(blob)


# ---------------------------------------------------------------------------
# Sealed save / load
# ---------------------------------------------------------------------------

def test_save_sealed_then_load_round_trip(tmp_path: Path) -> None:
    cap = _make_capsule()
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.sealed"
    save_sealed_capsule(capsule=cap, out_path=p, master_seed=seed)
    out = load_sealed_capsule(
        sealed_path=p, master_seed=seed,
        call_id=cap.call_id, finalized_at_ms=cap.finalized_at_ms,
    )
    assert out.audio_payload == cap.audio_payload
    assert out.capsule_id == cap.capsule_id


def test_save_sealed_then_load_with_wrong_seed_fails(tmp_path: Path) -> None:
    cap = _make_capsule()
    p = tmp_path / "capsule.sealed"
    save_sealed_capsule(
        capsule=cap, out_path=p, master_seed=secrets.token_bytes(32),
    )
    with pytest.raises(Exception):
        load_sealed_capsule(
            sealed_path=p, master_seed=secrets.token_bytes(32),
            call_id=cap.call_id, finalized_at_ms=cap.finalized_at_ms,
        )


def test_save_sealed_then_load_with_wrong_call_id_fails(tmp_path: Path) -> None:
    cap = _make_capsule()
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.sealed"
    save_sealed_capsule(capsule=cap, out_path=p, master_seed=seed)
    with pytest.raises(Exception):
        load_sealed_capsule(
            sealed_path=p, master_seed=seed,
            call_id="different-call-id",
            finalized_at_ms=cap.finalized_at_ms,
        )


# ---------------------------------------------------------------------------
# Sealed file does NOT leak metadata
# ---------------------------------------------------------------------------

def test_sealed_file_does_not_contain_capsule_id_or_audio(tmp_path: Path) -> None:
    """The sealed file body should be opaque ciphertext — none of
    the capsule's distinguishing fields should appear in plaintext."""
    cap = _make_capsule()
    seed = secrets.token_bytes(32)
    p = tmp_path / "capsule.sealed"
    save_sealed_capsule(capsule=cap, out_path=p, master_seed=seed)
    raw = p.read_bytes()
    # capsule_id should NOT be present in plaintext
    assert cap.capsule_id.encode() not in raw
    # call_id should NOT be present (it IS used as AAD but not echoed
    # into the ciphertext as plaintext)
    assert cap.call_id.encode() not in raw
    # audio_payload should NOT be present
    assert cap.audio_payload not in raw


# ---------------------------------------------------------------------------
# Index entry
# ---------------------------------------------------------------------------

def test_capsule_index_entry_contains_no_audio() -> None:
    cap = _make_capsule()
    entry = capsule_index_entry(cap, Path("/path/to/capsule.sealed"))
    assert "audio_payload" not in entry
    assert "provenance_chain" not in entry
    # but it does have everything the chat-list needs.
    assert entry["capsule_id"] == cap.capsule_id
    assert entry["call_id"] == cap.call_id
    assert entry["duration_ms"] == cap.duration_ms
    assert entry["label"]  # plain-language label


def test_capsule_index_entry_label_is_doctrine_compliant() -> None:
    """Doctrine §3.2.e: capsule labels are positive artifacts, not
    failure descriptions. No 'failed', 'missed', or error words."""
    cap = _make_capsule()
    entry = capsule_index_entry(cap, Path("p"))
    label = entry["label"].lower()
    for forbidden in ("failed", "missed", "error", "lost", "dead"):
        assert forbidden not in label, f"index label contains '{forbidden}': {entry['label']}"
