"""Capsule transport — deliver an :class:`AsyncCapsule` to the peer.

After :class:`CallLifecycle` transitions to RESUMABLE the daemon
needs to actually deliver the capsule's bytes to the receiving
peer. We piggyback on the existing file-transfer pipeline:

  1. Sender emits ``CAPSULE_OFFER`` (header-only).
  2. The receiver's daemon, on receiving ``CAPSULE_OFFER``, marks
     the capsule as expected and opens an inbound slot keyed on
     ``capsule_id``.
  3. The sender then transfers the payload bytes via a sequence of
     ``CAPSULE_CHUNK`` messages.
  4. Sender ends with ``CAPSULE_COMPLETE``; receiver verifies the
     concatenated payload's BLAKE3 matches the offer's
     ``payload_hash``, then verifies the chained FrameProvenance
     before surfacing the capsule in the chat UI.

This module is the pure transport adapter. The daemon owns the
actual ``await channel.send(...)`` calls — same separation as
every other module in this codebase.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §6.6 (capsule format)
           docs/LIVING_PRESENCE_ARCHITECTURE.md §6.7 (resume flow)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Iterator, Optional

from one_link.async_capsule import (
    CAPSULE_CHUNK,
    CAPSULE_COMPLETE,
    CAPSULE_OFFER,
    AsyncCapsule,
    capsule_to_offer_msg,
)
from one_link.frame_provenance import (
    FrameProvenance,
    from_wire_dict,
    make_segment_hash,
    to_wire_dict,
    verify_provenance,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Outbound: stream a capsule to the peer
# ---------------------------------------------------------------------------

# Chunk size for capsule payload transfer. Matched to the existing
# file pipeline's chunk size convention; opus voice payloads are
# small (10s of KB for a 30s clip), so a single chunk often holds
# the whole capsule.
DEFAULT_CAPSULE_CHUNK_SIZE = 16 * 1024


@dataclass(frozen=True)
class OutboundCapsuleChunk:
    """One wire message for the chunked transfer. The daemon
    iterates the generator and ``channel.send(encode_msg(...))``s
    each in order."""

    msg_type: str
    payload: dict


def stream_capsule_to_messages(
    capsule: AsyncCapsule,
    *,
    sender_short_id: str,
    chunk_size: int = DEFAULT_CAPSULE_CHUNK_SIZE,
) -> Iterator[dict]:
    """Yield the JSON-envelope dicts the daemon should
    ``encode_msg`` + ``channel.send`` to deliver this capsule.

    The provenance chain is carried in the OFFER header (one per
    captured frame), independent of how the audio_payload is
    chunked for transport. This decoupling is correct because
    frame granularity (audio frame, e.g. 50 fps) differs from
    transport granularity (16 KB blocks).
    """
    if chunk_size < 1:
        raise ValueError(f"chunk_size must be ≥1, got {chunk_size}")

    # 1) Offer (header + provenance chain)
    offer_msg = capsule_to_offer_msg(capsule, sender_short_id)
    offer_msg["provenance_chain"] = [
        to_wire_dict(p) for p in capsule.provenance_chain
    ]
    yield offer_msg

    # 2) Chunks (audio data only — provenance carried in offer)
    payload = capsule.audio_payload
    n_chunks = (len(payload) + chunk_size - 1) // chunk_size or 1
    from one_link.wire import make_msg
    import base64
    for i in range(n_chunks):
        start = i * chunk_size
        end = start + chunk_size
        chunk_bytes = payload[start:end]
        chunk_msg = make_msg(
            CAPSULE_CHUNK,
            sender_short_id,
            capsule_id=capsule.capsule_id,
            seq=i,
            total=n_chunks,
            data_b64=base64.b64encode(chunk_bytes).decode("ascii"),
        )
        yield chunk_msg

    # 3) Complete
    complete_msg = make_msg(
        CAPSULE_COMPLETE,
        sender_short_id,
        capsule_id=capsule.capsule_id,
        payload_hash=capsule.payload_hash,
        n_chunks=n_chunks,
    )
    yield complete_msg


# ---------------------------------------------------------------------------
# Inbound: assemble a streamed capsule on the receiver side
# ---------------------------------------------------------------------------

class InboundError(Exception):
    """Sentinel raised when a streamed capsule is rejected.
    The daemon's dispatch catches it and logs + drops silently
    (doctrine §3.2.d: no error codes leak to the user)."""


@dataclass
class InboundCapsule:
    """In-progress receive state. The daemon holds one of these
    per active inbound transfer."""

    capsule_id: str
    sender_master_vk_hex: str
    expected_payload_hash: str
    declared_size: int
    declared_duration_ms: int
    declared_recording_state: int
    declared_resumable_until_ms: int
    declared_kind: int
    declared_codec: str
    declared_sample_rate: int
    # Provenance chain comes in the OFFER and is verified before
    # finalization. Empty tuple means "no chain advertised."
    provenance_chain: tuple[FrameProvenance, ...] = ()

    # Chunk accumulation
    _chunks: dict[int, bytes] = field(default_factory=dict)
    _expected_n_chunks: Optional[int] = None
    _completed: bool = False

    def add_chunk(
        self,
        *,
        seq: int,
        data: bytes,
        declared_total: Optional[int],
    ) -> None:
        """Buffer one chunk. Re-receiving the same seq overwrites
        (idempotent on retransmit)."""
        if seq < 0:
            raise InboundError("seq must be non-negative")
        if declared_total is not None:
            if self._expected_n_chunks is None:
                self._expected_n_chunks = int(declared_total)
            elif self._expected_n_chunks != int(declared_total):
                raise InboundError(
                    f"declared chunk total flipped: was "
                    f"{self._expected_n_chunks}, now {declared_total}"
                )
        if (
            self._expected_n_chunks is not None
            and seq >= self._expected_n_chunks
        ):
            raise InboundError(
                f"seq {seq} ≥ declared total {self._expected_n_chunks}"
            )
        self._chunks[seq] = data

    def all_chunks_present(self) -> bool:
        if self._expected_n_chunks is None:
            return False
        return len(self._chunks) == self._expected_n_chunks

    def assemble_payload(self) -> bytes:
        if not self.all_chunks_present():
            raise InboundError("missing chunks; cannot assemble")
        ordered = sorted(self._chunks.items(), key=lambda kv: kv[0])
        return b"".join(c for _, c in ordered)

    def verify_and_finalize(
        self,
        *,
        sender_public_bytes: bytes,
    ) -> AsyncCapsule:
        """Verify the assembled payload + each provenance against
        the sender's pinned key. Returns the final immutable
        :class:`AsyncCapsule`. Raises :class:`InboundError` if
        verification fails for any reason."""
        if self._completed:
            raise InboundError("already finalized")
        if not self.all_chunks_present():
            raise InboundError("not all chunks received")

        payload = self.assemble_payload()
        actual_hash = make_segment_hash(payload).hex()
        if actual_hash != self.expected_payload_hash:
            raise InboundError(
                f"payload hash mismatch: expected "
                f"{self.expected_payload_hash}, got {actual_hash}"
            )

        # Every provenance in the offer-carried chain must verify
        # against the sender's pinned key.
        for p in self.provenance_chain:
            if not verify_provenance(p, sender_public_bytes):
                raise InboundError("provenance verification failed")

        from one_link.async_capsule import CapsuleKind
        capsule = AsyncCapsule(
            capsule_id=self.capsule_id,
            call_id="",                # filled in by daemon if it knows
            kind=CapsuleKind(self.declared_kind),
            sender_master_vk_hex=self.sender_master_vk_hex,
            recipient_master_vk_hex="",
            started_at_ms=0,
            finalized_at_ms=0,
            duration_ms=self.declared_duration_ms,
            audio_payload=payload,
            audio_codec=self.declared_codec,
            sample_rate_hz=self.declared_sample_rate,
            provenance_chain=self.provenance_chain,
            recording_state_at_conversion=self.declared_recording_state,  # type: ignore[arg-type]
            resumable_until_ms=self.declared_resumable_until_ms,
            payload_hash=self.expected_payload_hash,
        )
        self._completed = True
        return capsule


# ---------------------------------------------------------------------------
# Receiver-side registry
# ---------------------------------------------------------------------------

class InboundCapsuleRegistry:
    """Thread-safe map of capsule_id → :class:`InboundCapsule`.

    The daemon holds one. On CAPSULE_OFFER it opens an entry; on
    each CAPSULE_CHUNK it routes the chunk into the entry; on
    CAPSULE_COMPLETE it verifies + finalises + closes the entry."""

    # Bound the number of concurrent inbound capsules so a peer
    # can't exhaust memory by spamming offers.
    DEFAULT_MAX_INFLIGHT = 64

    def __init__(self, *, max_inflight: int = DEFAULT_MAX_INFLIGHT) -> None:
        self._max = int(max_inflight)
        self._by_id: dict[str, InboundCapsule] = {}
        self._lock = threading.Lock()

    def open_inbound(
        self,
        *,
        capsule_id: str,
        sender_master_vk_hex: str,
        expected_payload_hash: str,
        declared_size: int,
        declared_duration_ms: int,
        declared_recording_state: int,
        declared_resumable_until_ms: int,
        declared_kind: int,
        declared_codec: str,
        declared_sample_rate: int,
        provenance_chain: tuple[FrameProvenance, ...] = (),
    ) -> InboundCapsule:
        with self._lock:
            if capsule_id in self._by_id:
                return self._by_id[capsule_id]
            if len(self._by_id) >= self._max:
                # FIFO eviction — drop the oldest inbound.
                oldest = next(iter(self._by_id))
                del self._by_id[oldest]
            entry = InboundCapsule(
                capsule_id=capsule_id,
                sender_master_vk_hex=sender_master_vk_hex,
                expected_payload_hash=expected_payload_hash,
                declared_size=int(declared_size),
                declared_duration_ms=int(declared_duration_ms),
                declared_recording_state=int(declared_recording_state),
                declared_resumable_until_ms=int(declared_resumable_until_ms),
                declared_kind=int(declared_kind),
                declared_codec=str(declared_codec),
                declared_sample_rate=int(declared_sample_rate),
                provenance_chain=tuple(provenance_chain),
            )
            self._by_id[capsule_id] = entry
            return entry

    def get(self, capsule_id: str) -> Optional[InboundCapsule]:
        with self._lock:
            return self._by_id.get(capsule_id)

    def close(self, capsule_id: str) -> None:
        with self._lock:
            self._by_id.pop(capsule_id, None)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)


# ---------------------------------------------------------------------------
# Wire-message parsers (defensive — never raise on malformed input)
# ---------------------------------------------------------------------------

def parse_inbound_offer(msg: dict) -> dict:
    """Validate a CAPSULE_OFFER message. Returns the structured
    fields on success; raises :class:`InboundError` on malformed."""
    if msg.get("t") != CAPSULE_OFFER:
        raise InboundError(f"not a {CAPSULE_OFFER}: t={msg.get('t')!r}")
    capsule_id = msg.get("capsule_id")
    if not isinstance(capsule_id, str) or not capsule_id:
        raise InboundError("missing capsule_id")
    payload_hash = msg.get("payload_hash")
    if not isinstance(payload_hash, str) or len(payload_hash) != 64:
        raise InboundError("missing or invalid payload_hash")
    try:
        size = int(msg.get("size", 0))
        duration_ms = int(msg.get("duration_ms", 0))
        recording_state = int(msg.get("recording_state", 0))
        resumable_until_ms = int(msg.get("resumable_until_ms", 0))
        kind = int(msg.get("kind", 0))
        sample_rate = int(msg.get("sample_rate", 48_000))
    except (TypeError, ValueError) as exc:
        raise InboundError(f"malformed numeric field: {exc}") from exc
    codec = msg.get("codec", "opus")
    if not isinstance(codec, str):
        raise InboundError("codec must be string")
    # Provenance chain — optional but typical. Each entry is the
    # wire form of a FrameProvenance.
    raw_chain = msg.get("provenance_chain")
    chain: list[FrameProvenance] = []
    if raw_chain is not None:
        if not isinstance(raw_chain, list):
            raise InboundError("provenance_chain must be a list")
        for entry in raw_chain:
            if not isinstance(entry, dict):
                raise InboundError("provenance_chain entry must be dict")
            try:
                chain.append(from_wire_dict(entry))
            except ValueError as exc:
                raise InboundError(
                    f"provenance_chain entry malformed: {exc}"
                ) from exc
    return {
        "capsule_id": capsule_id,
        "payload_hash": payload_hash,
        "size": size,
        "duration_ms": duration_ms,
        "recording_state": recording_state,
        "resumable_until_ms": resumable_until_ms,
        "kind": kind,
        "codec": codec,
        "sample_rate": sample_rate,
        "provenance_chain": tuple(chain),
    }


def parse_inbound_chunk(msg: dict) -> dict:
    """Validate a CAPSULE_CHUNK message."""
    import base64
    if msg.get("t") != CAPSULE_CHUNK:
        raise InboundError(f"not a {CAPSULE_CHUNK}: t={msg.get('t')!r}")
    capsule_id = msg.get("capsule_id")
    if not isinstance(capsule_id, str):
        raise InboundError("missing capsule_id")
    try:
        seq = int(msg.get("seq", -1))
        total = (
            int(msg.get("total"))
            if msg.get("total") is not None
            else None
        )
    except (TypeError, ValueError) as exc:
        raise InboundError(f"malformed seq/total: {exc}") from exc
    if seq < 0:
        raise InboundError("seq required")
    data_b64 = msg.get("data_b64")
    if not isinstance(data_b64, str):
        raise InboundError("missing data_b64")
    try:
        data = base64.b64decode(data_b64.encode("ascii"))
    except Exception as exc:
        raise InboundError(f"data_b64 not valid base64: {exc}") from exc
    return {
        "capsule_id": capsule_id,
        "seq": seq,
        "total": total,
        "data": data,
    }


def parse_inbound_complete(msg: dict) -> dict:
    if msg.get("t") != CAPSULE_COMPLETE:
        raise InboundError(f"not a {CAPSULE_COMPLETE}: t={msg.get('t')!r}")
    capsule_id = msg.get("capsule_id")
    if not isinstance(capsule_id, str):
        raise InboundError("missing capsule_id")
    payload_hash = msg.get("payload_hash")
    if not isinstance(payload_hash, str):
        raise InboundError("missing payload_hash")
    return {
        "capsule_id": capsule_id,
        "payload_hash": payload_hash,
    }
