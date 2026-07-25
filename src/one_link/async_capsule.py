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

import re
from dataclasses import dataclass, field
from enum import IntEnum

from one_link.frame_provenance import (
    FrameProvenance,
    RecordingState,
    make_segment_hash,
)


MAX_CAPSULE_BYTES = 16 * 1024 * 1024
MAX_CAPSULE_DURATION_MS = 24 * 60 * 60 * 1000
MAX_CAPSULE_PROVENANCE_ENTRIES = 8192
MAX_CAPSULE_RESUME_WINDOW_MS = 30 * 24 * 60 * 60 * 1000
MAX_CAPSULE_TIMESTAMP_MS = 2**63 - 1
_CAPSULE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_CALL_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


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
    tags covering the entire capsule duration. The paired
    ``provenance_segment_sizes`` reconstruct exact byte boundaries,
    so the receiver verifies both each payload slice and each tag
    against the sender's pinned master_vk.

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
    # Exact byte boundaries for the signed segments above.  Without these,
    # signatures can be valid while referring to unrelated audio because a
    # receiver cannot reconstruct how the concatenated payload was sliced.
    provenance_segment_sizes: tuple[int, ...]
    recording_state_at_conversion: RecordingState
    resumable_until_ms: int
    payload_hash: str           # BLAKE3(audio_payload) hex

    def __post_init__(self) -> None:
        if (
            not isinstance(self.capsule_id, str)
            or _CAPSULE_ID_RE.fullmatch(self.capsule_id) is None
        ):
            raise ValueError("capsule_id is invalid")
        if (
            not isinstance(self.call_id, str)
            or _CALL_ID_RE.fullmatch(self.call_id) is None
        ):
            raise ValueError("call_id is invalid")
        if not isinstance(self.kind, CapsuleKind):
            raise ValueError("kind must be a CapsuleKind")
        if (
            not isinstance(self.sender_master_vk_hex, str)
            or len(self.sender_master_vk_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in self.sender_master_vk_hex)
        ):
            raise ValueError("sender identity fingerprint is invalid")
        if (
            not isinstance(self.recipient_master_vk_hex, str)
            or len(self.recipient_master_vk_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in self.recipient_master_vk_hex)
        ):
            raise ValueError("recipient identity fingerprint is invalid")
        for field_name, value in (
            ("started_at_ms", self.started_at_ms),
            ("finalized_at_ms", self.finalized_at_ms),
            ("duration_ms", self.duration_ms),
            ("resumable_until_ms", self.resumable_until_ms),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not (0 <= value <= MAX_CAPSULE_TIMESTAMP_MS)
            ):
                raise ValueError(f"{field_name} must be a non-negative integer")
        if self.finalized_at_ms < self.started_at_ms:
            raise ValueError("finalized_at_ms precedes started_at_ms")
        if self.duration_ms > MAX_CAPSULE_DURATION_MS:
            raise ValueError("duration_ms exceeds capsule limit")
        if self.duration_ms > self.finalized_at_ms - self.started_at_ms:
            raise ValueError("duration_ms exceeds capture interval")
        if self.resumable_until_ms < self.finalized_at_ms:
            raise ValueError("resumable_until_ms precedes finalization")
        if (
            self.resumable_until_ms - self.finalized_at_ms
            > MAX_CAPSULE_RESUME_WINDOW_MS
        ):
            raise ValueError("capsule resume window exceeds limit")
        if not isinstance(self.audio_payload, bytes):
            raise ValueError("audio_payload must be bytes")
        if not (1 <= len(self.audio_payload) <= MAX_CAPSULE_BYTES):
            raise ValueError("audio_payload must be non-empty and within capsule limit")
        if (
            not isinstance(self.audio_codec, str)
            or not self.audio_codec
            or len(self.audio_codec) > 32
            or any(
                not (ch.isascii() and (ch.isalnum() or ch in "-_."))
                for ch in self.audio_codec
            )
        ):
            raise ValueError("audio_codec is invalid")
        if (
            isinstance(self.sample_rate_hz, bool)
            or not isinstance(self.sample_rate_hz, int)
            or not (8000 <= self.sample_rate_hz <= 384000)
        ):
            raise ValueError("sample_rate_hz is invalid")
        if not isinstance(self.provenance_chain, tuple):
            raise ValueError("provenance_chain must be a tuple")
        if len(self.provenance_chain) > MAX_CAPSULE_PROVENANCE_ENTRIES:
            raise ValueError("provenance_chain exceeds capsule limit")
        if not isinstance(self.provenance_segment_sizes, tuple):
            raise ValueError("provenance_segment_sizes must be a tuple")
        if len(self.provenance_segment_sizes) != len(self.provenance_chain):
            raise ValueError("provenance segment count does not match chain")
        offset = 0
        for index, (provenance, segment_size) in enumerate(zip(
            self.provenance_chain,
            self.provenance_segment_sizes,
        )):
            if not isinstance(provenance, FrameProvenance):
                raise ValueError("provenance_chain contains an invalid entry")
            if provenance.device_id != self.sender_master_vk_hex[:8]:
                raise ValueError(
                    f"provenance segment {index} is bound to another device"
                )
            if (
                isinstance(segment_size, bool)
                or not isinstance(segment_size, int)
                or not (1 <= segment_size <= MAX_CAPSULE_BYTES)
            ):
                raise ValueError("provenance segment size is invalid")
            end = offset + segment_size
            if end > len(self.audio_payload):
                raise ValueError("provenance segments exceed audio payload")
            if provenance.segment_hash != make_segment_hash(
                self.audio_payload[offset:end]
            ):
                raise ValueError(
                    f"provenance segment {index} does not cover audio payload"
                )
            offset = end
        if offset != len(self.audio_payload):
            raise ValueError("provenance segments do not cover audio payload")
        if not isinstance(self.recording_state_at_conversion, RecordingState):
            raise ValueError("recording_state_at_conversion is invalid")
        expected_hash = make_segment_hash(self.audio_payload).hex()
        if self.payload_hash != expected_hash:
            raise ValueError("payload_hash does not match audio_payload")

    # ── Read helpers ──────────────────────────────────────────

    def is_resumable_at(self, now_ms: int) -> bool:
        return now_ms < self.resumable_until_ms

    def size_bytes(self) -> int:
        return len(self.audio_payload)

    def all_frames_verified_by(self, sender_public_bytes: bytes) -> bool:
        """Every FrameProvenance in the chain must verify against
        the sender's pinned key. Returns True only if all do."""
        from one_link.frame_provenance import verify_provenance
        from one_link.identity import fingerprint_of

        try:
            if fingerprint_of(sender_public_bytes) != self.sender_master_vk_hex:
                return False
        except (TypeError, ValueError):
            return False
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
    _provenance_segment_sizes: list[int] = field(default_factory=list)
    _last_segment_ms: int = 0
    _total_audio_bytes: int = 0

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
        if not isinstance(chunk, bytes):
            raise ValueError("chunk must be bytes")
        if not chunk:
            return
        if self._total_audio_bytes + len(chunk) > MAX_CAPSULE_BYTES:
            raise ValueError("capsule audio exceeds size limit")
        if len(self._provenance_chain) >= MAX_CAPSULE_PROVENANCE_ENTRIES:
            raise ValueError("capsule provenance chain exceeds entry limit")
        if not isinstance(provenance, FrameProvenance):
            raise ValueError("provenance must be a FrameProvenance")
        if provenance.device_id != self.sender_master_vk_hex[:8]:
            raise ValueError("provenance is bound to another device")
        if provenance.segment_hash != make_segment_hash(chunk):
            raise ValueError("provenance hash does not match audio chunk")
        if (
            isinstance(timestamp_ms, bool)
            or not isinstance(timestamp_ms, int)
            or not (self.started_at_ms <= timestamp_ms <= MAX_CAPSULE_TIMESTAMP_MS)
            or (self._audio_chunks and timestamp_ms < self._last_segment_ms)
        ):
            raise ValueError("timestamp_ms is invalid or non-monotonic")
        self._audio_chunks.append(chunk)
        self._provenance_chain.append(provenance)
        self._provenance_segment_sizes.append(len(chunk))
        self._last_segment_ms = timestamp_ms
        self._total_audio_bytes += len(chunk)

    def total_bytes(self) -> int:
        return self._total_audio_bytes

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
        if (
            isinstance(finalized_at_ms, bool)
            or not isinstance(finalized_at_ms, int)
            or finalized_at_ms < self._last_segment_ms
        ):
            raise ValueError("finalized_at_ms precedes captured audio")
        if (
            isinstance(resume_window_ms, bool)
            or not isinstance(resume_window_ms, int)
            or not (0 <= resume_window_ms <= MAX_CAPSULE_RESUME_WINDOW_MS)
        ):
            raise ValueError("resume_window_ms outside capsule limit")

        payload = b"".join(self._audio_chunks)
        payload_hash = make_segment_hash(payload).hex()
        duration = max(0, self._last_segment_ms - self.started_at_ms)
        if duration > MAX_CAPSULE_DURATION_MS:
            raise ValueError("capsule duration exceeds limit")

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
            provenance_segment_sizes=tuple(self._provenance_segment_sizes),
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
    from one_link.frame_provenance import to_wire_dict
    from one_link.wire import make_msg
    return make_msg(
        CAPSULE_OFFER,
        sender_short_id,
        capsule_id=capsule.capsule_id,
        call_id=capsule.call_id,
        started_at_ms=capsule.started_at_ms,
        finalized_at_ms=capsule.finalized_at_ms,
        kind=int(capsule.kind),
        size=capsule.size_bytes(),
        duration_ms=capsule.duration_ms,
        codec=capsule.audio_codec,
        sample_rate=capsule.sample_rate_hz,
        payload_hash=capsule.payload_hash,
        recording_state=int(capsule.recording_state_at_conversion),
        resumable_until_ms=capsule.resumable_until_ms,
        provenance_chain=[to_wire_dict(p) for p in capsule.provenance_chain],
        provenance_segment_sizes=list(capsule.provenance_segment_sizes),
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
