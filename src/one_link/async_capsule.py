"""Async capsule format.

When a call converts to async (Immune System triggered, peer
offline, invite timed out, peer declined), the in-flight media
buffer + conversation context become an :class:`AsyncCapsule` that
lives in the chat surface and can be picked up later within the
resume window.

This module defines:

  - :class:`AsyncCapsule` — the persistent wire format
  - :class:`CapsuleBuilder` — accumulates partial frames into a
    final capsule blob
  - Serialisation helpers for the existing chat-persistence path
    (the daemon's chat surface stores capsules as a new message kind
    that renders inline)

Doctrine compliance:

  - No "failed call" labels. The capsule's user-facing rendering
    is "Voice note from Mom" / "You left this for Mom" — never
    referencing the underlying call failure.
  - The capsule carries the original call's FrameProvenance roots
    so the receiver can still verify the captured frames after
    delivery. Recording without consent is never possible: the
    capsule of an active recording carries
    ``recording_state=RECORDING_MUTUAL`` only when consent was
    granted before async conversion.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.2 (rung 7) + §6.6 + §6.7
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from one_link.frame_provenance import (
    FrameKind,
    FrameProvenance,
    RecordingState,
    make_segment_hash,
)


# ---------------------------------------------------------------------------
# Capsule kinds (what the receiver renders)
# ---------------------------------------------------------------------------

class CapsuleKind(IntEnum):
    """What kind of capsule this is. The chat surface renders each
    differently."""

    VOICE_NOTE_OUTGOING       = 0  # we left it for peer (call → async)
    VOICE_NOTE_INCOMING       = 1  # peer left it for us
    SHARED_CALL_RECORDING     = 2  # both sides recorded; mutual artifact


# ---------------------------------------------------------------------------
# Capsule schema
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AsyncCapsule:
    """The on-wire / on-disk capsule. Immutable after finalization.

    The ``audio_payload`` is opus-encoded (or whatever codec the
    Compiler was using when the call converted). The
    ``provenance_chain`` is a tuple of per-segment FrameProvenance
    tags covering the entire capsule duration — the receiver
    verifies each tag against the sender's pinned master_vk.

    ``resumable_until_ms`` is the resume-window close time; after
    this the capsule remains in chat as a voice note but no live
    resume affordance is shown.
    """

    capsule_id: str             # ULID
    call_id: str                # call this capsule was captured during
    kind: CapsuleKind
    sender_master_vk_hex: str
    recipient_master_vk_hex: str
    started_at_ms: int
    finalized_at_ms: int
    duration_ms: int
    audio_payload: bytes        # opus blob
    audio_codec: str            # "opus"
    sample_rate_hz: int
    provenance_chain: tuple[FrameProvenance, ...]
    recording_state_at_conversion: RecordingState
    resumable_until_ms: int
    payload_hash: str           # BLAKE3(audio_payload) hex

    # ── Read helpers ──────────────────────────────────────────

    def is_resumable_at(self, now_ms: int) -> bool:
        return now_ms < self.resumable_until_ms

    def size_bytes(self) -> int:
        return len(self.audio_payload)

    def all_frames_verified_by(self, sender_public_bytes: bytes) -> bool:
        """Every FrameProvenance in the chain must verify against
        the sender's pinned key. Returns True only if all do."""
        from one_link.frame_provenance import verify_provenance
        return all(
            verify_provenance(p, sender_public_bytes)
            for p in self.provenance_chain
        )


# ---------------------------------------------------------------------------
# Builder — accumulates capsule content during the ASYNC_CAPTURE phase
# ---------------------------------------------------------------------------

@dataclass
class CapsuleBuilder:
    """Stateful builder. Used by the daemon during the lifecycle
    ASYNC_CAPTURE phase to accumulate the in-flight buffer + new
    user input."""

    capsule_id: str
    call_id: str
    sender_master_vk_hex: str
    recipient_master_vk_hex: str
    kind: CapsuleKind
    started_at_ms: int
    recording_state_at_conversion: RecordingState = RecordingState.NOT_RECORDING
    sample_rate_hz: int = 48_000
    audio_codec: str = "opus"

    # Mutable accumulators
    _audio_chunks: list[bytes] = field(default_factory=list)
    _provenance_chain: list[FrameProvenance] = field(default_factory=list)
    _last_segment_ms: int = 0

    def append_audio(
        self,
        *,
        chunk: bytes,
        provenance: FrameProvenance,
        timestamp_ms: int,
    ) -> None:
        """Append one audio segment + its signed FrameProvenance.

        The daemon calls this for each opus packet during async
        capture. Validation of the provenance signature is the
        caller's job — by the time we're appending, the sender
        already signed (sender-side capture) or we've verified
        (receiver-side ingest)."""
        if not chunk:
            return
        self._audio_chunks.append(chunk)
        self._provenance_chain.append(provenance)
        self._last_segment_ms = timestamp_ms

    def total_bytes(self) -> int:
        return sum(len(c) for c in self._audio_chunks)

    def duration_ms(self) -> int:
        if not self._audio_chunks:
            return 0
        return max(0, self._last_segment_ms - self.started_at_ms)

    def is_empty(self) -> bool:
        return not self._audio_chunks

    def finalize(
        self,
        *,
        finalized_at_ms: int,
        resume_window_ms: int,
    ) -> AsyncCapsule:
        """Pack the accumulated chunks into an immutable capsule.

        Concatenates audio chunks into a single payload (opus
        permits this; container reframing is the receiver's job).
        Computes the payload hash and the resumable-until time."""
        if self.is_empty():
            raise ValueError("cannot finalize an empty capsule")

        payload = b"".join(self._audio_chunks)
        payload_hash = make_segment_hash(payload).hex()
        duration = max(0, self._last_segment_ms - self.started_at_ms)

        return AsyncCapsule(
            capsule_id=self.capsule_id,
            call_id=self.call_id,
            kind=self.kind,
            sender_master_vk_hex=self.sender_master_vk_hex,
            recipient_master_vk_hex=self.recipient_master_vk_hex,
            started_at_ms=self.started_at_ms,
            finalized_at_ms=finalized_at_ms,
            duration_ms=duration,
            audio_payload=payload,
            audio_codec=self.audio_codec,
            sample_rate_hz=self.sample_rate_hz,
            provenance_chain=tuple(self._provenance_chain),
            recording_state_at_conversion=self.recording_state_at_conversion,
            resumable_until_ms=finalized_at_ms + resume_window_ms,
            payload_hash=payload_hash,
        )


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------

CAPSULE_OFFER     = "CAPSULE_OFFER"       # sender announces a capsule
CAPSULE_CHUNK     = "CAPSULE_CHUNK"       # capsule data chunk
CAPSULE_COMPLETE  = "CAPSULE_COMPLETE"    # end of capsule transfer


def capsule_to_offer_msg(capsule: AsyncCapsule, sender_short_id: str) -> dict:
    """Build the wire message for the offer phase. The actual
    bytes travel via the existing file-transfer pipeline (which
    already handles chunking, FrameProvenance per chunk, and
    resumable transfer)."""
    from one_link.wire import make_msg
    return make_msg(
        CAPSULE_OFFER,
        sender_short_id,
        capsule_id=capsule.capsule_id,
        call_id=capsule.call_id,
        kind=int(capsule.kind),
        size=capsule.size_bytes(),
        duration_ms=capsule.duration_ms,
        codec=capsule.audio_codec,
        sample_rate=capsule.sample_rate_hz,
        payload_hash=capsule.payload_hash,
        recording_state=int(capsule.recording_state_at_conversion),
        resumable_until_ms=capsule.resumable_until_ms,
    )


# ---------------------------------------------------------------------------
# UI rendering (plain language)
# ---------------------------------------------------------------------------

def capsule_label(kind: CapsuleKind) -> str:
    """Doctrine §3.2.e — never reference 'failed' or 'missed'.
    Capsules are positive artifacts of conversation, not failures."""
    return {
        CapsuleKind.VOICE_NOTE_OUTGOING:    "You left a voice note",
        CapsuleKind.VOICE_NOTE_INCOMING:    "Voice note arrived",
        CapsuleKind.SHARED_CALL_RECORDING:  "Shared recording",
    }[kind]


def format_duration_human(duration_ms: int) -> str:
    """Plain-language duration. Always shows a positive number;
    never 'expires in' (Doctrine §3.4.d). 'voice note · 23 sec'
    style for the chat surface."""
    seconds = max(0, duration_ms // 1000)
    if seconds < 60:
        return f"{seconds} sec"
    minutes = seconds // 60
    remaining = seconds % 60
    if minutes < 60:
        if remaining == 0:
            return f"{minutes} min"
        return f"{minutes} min {remaining} sec"
    hours = minutes // 60
    remaining_min = minutes % 60
    return f"{hours} hr {remaining_min} min"
