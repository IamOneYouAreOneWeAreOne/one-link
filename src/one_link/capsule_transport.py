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

import base64
import binascii
import logging
import threading
from dataclasses import dataclass, field
from typing import Iterator, Optional

from one_link.async_capsule import (
    CAPSULE_CHUNK,
    CAPSULE_COMPLETE,
    CAPSULE_OFFER,
    MAX_CAPSULE_BYTES,
    MAX_CAPSULE_DURATION_MS,
    MAX_CAPSULE_PROVENANCE_ENTRIES,
    MAX_CAPSULE_RESUME_WINDOW_MS,
    MAX_CAPSULE_TIMESTAMP_MS,
    AsyncCapsule,
    capsule_to_offer_msg,
)
from one_link.frame_provenance import (
    FrameProvenance,
    RecordingState,
    from_wire_dict,
    make_segment_hash,
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
MAX_CAPSULE_CHUNK_BYTES = 256 * 1024
MAX_CAPSULE_CHUNKS = 8192
MAX_CAPSULE_ID_CHARS = 128
MAX_CAPSULE_CODEC_CHARS = 32


def _strict_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InboundError(f"{field_name} must be an integer")
    return value


def _valid_capsule_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_CAPSULE_ID_CHARS:
        raise InboundError("missing or invalid capsule_id")
    if any(not (ch.isascii() and (ch.isalnum() or ch in "-_.")) for ch in value):
        raise InboundError("missing or invalid capsule_id")
    return value


def _valid_call_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise InboundError("missing or invalid call_id")
    if any(
        not (ch.isascii() and (ch.isalnum() or ch in "-_.:"))
        for ch in value
    ):
        raise InboundError("missing or invalid call_id")
    return value


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

    The provenance chain and its exact segment byte lengths are carried in
    the OFFER header, independent of how ``audio_payload`` is chunked for
    transport. This decoupling is correct because capture granularity differs
    from transport granularity, while the authenticated lengths still let the
    receiver reconstruct and hash every signed capture segment.
    """
    if (
        isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or chunk_size < 1
        or chunk_size > MAX_CAPSULE_CHUNK_BYTES
    ):
        raise ValueError(
            f"chunk_size must be in 1..{MAX_CAPSULE_CHUNK_BYTES}, got {chunk_size}"
        )
    if capsule.size_bytes() > MAX_CAPSULE_BYTES:
        raise ValueError(f"capsule exceeds {MAX_CAPSULE_BYTES}-byte transport limit")

    # 1) Offer (header + provenance chain)
    yield capsule_to_offer_msg(capsule, sender_short_id)

    # 2) Chunks (audio data only — provenance carried in offer)
    payload = capsule.audio_payload
    n_chunks = (len(payload) + chunk_size - 1) // chunk_size or 1
    if n_chunks > MAX_CAPSULE_CHUNKS:
        raise ValueError(
            f"chunk_size produces {n_chunks} chunks; limit is {MAX_CAPSULE_CHUNKS}"
        )
    from one_link.wire import make_msg
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
    declared_call_id: str = ""
    declared_started_at_ms: int = 0
    declared_finalized_at_ms: int = 0
    recipient_master_vk_hex: str = ""
    # Provenance chain comes in the OFFER and is verified before
    # finalization. Segment sizes make the signed hashes cover exact,
    # reconstructible slices of the concatenated payload.
    provenance_chain: tuple[FrameProvenance, ...] = ()
    provenance_segment_sizes: tuple[int, ...] = ()

    # Chunk accumulation
    _chunks: dict[int, bytes] = field(default_factory=dict)
    _expected_n_chunks: Optional[int] = None
    _completed: bool = False
    _buffered_bytes: int = 0
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _valid_capsule_id(self.capsule_id)
        if (
            not isinstance(self.sender_master_vk_hex, str)
            or len(self.sender_master_vk_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in self.sender_master_vk_hex)
        ):
            raise InboundError("invalid sender identity fingerprint")
        if (
            not isinstance(self.expected_payload_hash, str)
            or len(self.expected_payload_hash) != 64
            or any(ch not in "0123456789abcdef" for ch in self.expected_payload_hash)
        ):
            raise InboundError("invalid expected payload_hash")
        if (
            isinstance(self.declared_size, bool)
            or not isinstance(self.declared_size, int)
            or not (1 <= self.declared_size <= MAX_CAPSULE_BYTES)
        ):
            raise InboundError("declared capsule size outside limit")
        if (
            isinstance(self.declared_duration_ms, bool)
            or not isinstance(self.declared_duration_ms, int)
            or not (0 <= self.declared_duration_ms <= MAX_CAPSULE_DURATION_MS)
        ):
            raise InboundError("declared capsule duration outside limit")
        if (
            isinstance(self.declared_recording_state, bool)
            or not isinstance(self.declared_recording_state, int)
            or self.declared_recording_state not in {0, 1, 2, 3}
        ):
            raise InboundError("invalid recording_state")
        if (
            isinstance(self.declared_kind, bool)
            or not isinstance(self.declared_kind, int)
            or self.declared_kind not in {0, 1, 2}
        ):
            raise InboundError("invalid capsule kind")
        if (
            not isinstance(self.declared_codec, str)
            or not self.declared_codec
            or len(self.declared_codec) > MAX_CAPSULE_CODEC_CHARS
            or any(
                not (ch.isascii() and (ch.isalnum() or ch in "-_."))
                for ch in self.declared_codec
            )
        ):
            raise InboundError("invalid capsule codec")
        if (
            isinstance(self.declared_sample_rate, bool)
            or not isinstance(self.declared_sample_rate, int)
            or not (8000 <= self.declared_sample_rate <= 384000)
        ):
            raise InboundError("invalid capsule sample_rate")
        if not isinstance(self.provenance_chain, tuple):
            raise InboundError("provenance_chain must be a tuple")
        if len(self.provenance_chain) > MAX_CAPSULE_PROVENANCE_ENTRIES:
            raise InboundError("provenance_chain exceeds entry limit")
        if not self.provenance_chain:
            raise InboundError("capsule requires provenance coverage")
        if not isinstance(self.provenance_segment_sizes, tuple):
            raise InboundError("provenance_segment_sizes must be a tuple")
        if len(self.provenance_segment_sizes) != len(self.provenance_chain):
            raise InboundError("provenance segment count does not match chain")
        segment_total = 0
        for segment_size in self.provenance_segment_sizes:
            if (
                isinstance(segment_size, bool)
                or not isinstance(segment_size, int)
                or not (1 <= segment_size <= MAX_CAPSULE_BYTES)
            ):
                raise InboundError("invalid provenance segment size")
            segment_total += segment_size
            if segment_total > self.declared_size:
                raise InboundError("provenance segments exceed declared size")
        if segment_total != self.declared_size:
            raise InboundError("provenance segments do not cover declared size")
        _valid_call_id(self.declared_call_id)
        for field_name, value in (
            ("started_at_ms", self.declared_started_at_ms),
            ("finalized_at_ms", self.declared_finalized_at_ms),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not (0 <= value <= MAX_CAPSULE_TIMESTAMP_MS)
            ):
                raise InboundError(f"invalid capsule {field_name}")
        if self.declared_finalized_at_ms < self.declared_started_at_ms:
            raise InboundError("capsule finalized_at_ms precedes started_at_ms")
        if self.declared_duration_ms > (
            self.declared_finalized_at_ms - self.declared_started_at_ms
        ):
            raise InboundError("capsule duration exceeds capture interval")
        if (
            not isinstance(self.recipient_master_vk_hex, str)
            or len(self.recipient_master_vk_hex) != 64
            or any(ch not in "0123456789abcdef" for ch in self.recipient_master_vk_hex)
        ):
            raise InboundError("invalid recipient identity fingerprint")
        if (
            isinstance(self.declared_resumable_until_ms, bool)
            or not isinstance(self.declared_resumable_until_ms, int)
            or not (
                self.declared_finalized_at_ms
                <= self.declared_resumable_until_ms
                <= MAX_CAPSULE_TIMESTAMP_MS
            )
        ):
            raise InboundError("invalid capsule resumable_until_ms")
        if (
            self.declared_resumable_until_ms - self.declared_finalized_at_ms
            > MAX_CAPSULE_RESUME_WINDOW_MS
        ):
            raise InboundError("capsule resume window exceeds limit")

    def add_chunk(
        self,
        *,
        seq: int,
        data: bytes,
        declared_total: Optional[int],
    ) -> None:
        """Buffer one chunk with exact-replay idempotency."""
        with self._lock:
            self._add_chunk_locked(
                seq=seq,
                data=data,
                declared_total=declared_total,
            )

    def _add_chunk_locked(
        self,
        *,
        seq: int,
        data: bytes,
        declared_total: Optional[int],
    ) -> None:
        if self._completed:
            raise InboundError("capsule is already finalized")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise InboundError("seq must be non-negative")
        if seq >= MAX_CAPSULE_CHUNKS:
            raise InboundError("seq exceeds chunk limit")
        if not isinstance(data, bytes):
            raise InboundError("chunk data must be bytes")
        if len(data) > MAX_CAPSULE_CHUNK_BYTES:
            raise InboundError("chunk exceeds size limit")
        if declared_total is not None:
            if (
                isinstance(declared_total, bool)
                or not isinstance(declared_total, int)
                or declared_total < 1
                or declared_total > MAX_CAPSULE_CHUNKS
            ):
                raise InboundError("declared chunk total outside limit")
            if self._expected_n_chunks is None:
                self._expected_n_chunks = declared_total
            elif self._expected_n_chunks != declared_total:
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
        if not data:
            raise InboundError("non-empty capsule contains an empty chunk")
        previous = self._chunks.get(seq)
        if previous is not None:
            if previous != data:
                raise InboundError("chunk sequence replay changed content")
            return
        projected = self._buffered_bytes - len(previous or b"") + len(data)
        if projected > self.declared_size or projected > MAX_CAPSULE_BYTES:
            raise InboundError("chunk bytes exceed declared capsule size")
        if previous is None and len(self._chunks) >= MAX_CAPSULE_CHUNKS:
            raise InboundError("capsule exceeds chunk count limit")
        self._chunks[seq] = data
        self._buffered_bytes = projected

    def all_chunks_present(self) -> bool:
        with self._lock:
            if self._expected_n_chunks is None:
                return False
            return len(self._chunks) == self._expected_n_chunks

    def assemble_payload(self) -> bytes:
        with self._lock:
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
        with self._lock:
            return self._verify_and_finalize_locked(
                sender_public_bytes=sender_public_bytes,
            )

    def _verify_and_finalize_locked(
        self,
        *,
        sender_public_bytes: bytes,
    ) -> AsyncCapsule:
        if self._completed:
            raise InboundError("already finalized")
        if not self.all_chunks_present():
            raise InboundError("not all chunks received")

        from one_link.identity import fingerprint_of

        try:
            observed_sender = fingerprint_of(sender_public_bytes)
        except (TypeError, ValueError) as exc:
            raise InboundError("sender public key is invalid") from exc
        if observed_sender != self.sender_master_vk_hex:
            raise InboundError("sender public key does not match capsule identity")

        payload = self.assemble_payload()
        if len(payload) != self.declared_size:
            raise InboundError(
                f"payload size mismatch: expected {self.declared_size}, got {len(payload)}"
            )
        actual_hash = make_segment_hash(payload).hex()
        if actual_hash != self.expected_payload_hash:
            raise InboundError(
                f"payload hash mismatch: expected "
                f"{self.expected_payload_hash}, got {actual_hash}"
            )

        # Every provenance must both verify against the pinned sender and bind
        # to its exact payload slice. Signature validity alone is not
        # coverage: without authenticated boundaries, valid provenance from
        # unrelated audio could be attached to this capsule.
        offset = 0
        for index, (p, segment_size) in enumerate(zip(
            self.provenance_chain,
            self.provenance_segment_sizes,
        )):
            end = offset + segment_size
            if p.device_id != self.sender_master_vk_hex[:8]:
                raise InboundError(
                    f"provenance segment {index} belongs to another device"
                )
            if p.segment_hash != make_segment_hash(payload[offset:end]):
                raise InboundError(
                    f"provenance segment {index} does not cover payload"
                )
            if not verify_provenance(p, sender_public_bytes):
                raise InboundError("provenance verification failed")
            offset = end
        if offset != len(payload):
            raise InboundError("provenance segments do not cover payload")

        from one_link.async_capsule import CapsuleKind
        capsule = AsyncCapsule(
            capsule_id=self.capsule_id,
            call_id=self.declared_call_id,
            kind=CapsuleKind(self.declared_kind),
            sender_master_vk_hex=self.sender_master_vk_hex,
            recipient_master_vk_hex=self.recipient_master_vk_hex,
            started_at_ms=self.declared_started_at_ms,
            finalized_at_ms=self.declared_finalized_at_ms,
            duration_ms=self.declared_duration_ms,
            audio_payload=payload,
            audio_codec=self.declared_codec,
            sample_rate_hz=self.declared_sample_rate,
            provenance_chain=self.provenance_chain,
            provenance_segment_sizes=self.provenance_segment_sizes,
            recording_state_at_conversion=RecordingState(
                self.declared_recording_state
            ),
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
    DEFAULT_MAX_INFLIGHT = 16

    def __init__(self, *, max_inflight: int = DEFAULT_MAX_INFLIGHT) -> None:
        if isinstance(max_inflight, bool) or not isinstance(max_inflight, int):
            raise ValueError("max_inflight must be an integer")
        if not (1 <= max_inflight <= 4096):
            raise ValueError("max_inflight outside 1..4096")
        self._max = max_inflight
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
        declared_call_id: str = "",
        declared_started_at_ms: int = 0,
        declared_finalized_at_ms: int = 0,
        recipient_master_vk_hex: str = "",
        provenance_chain: tuple[FrameProvenance, ...] = (),
        provenance_segment_sizes: tuple[int, ...] = (),
    ) -> InboundCapsule:
        with self._lock:
            if capsule_id in self._by_id:
                existing = self._by_id[capsule_id]
                contract = (
                    sender_master_vk_hex,
                    expected_payload_hash,
                    declared_size,
                    declared_duration_ms,
                    declared_recording_state,
                    declared_resumable_until_ms,
                    declared_kind,
                    declared_codec,
                    declared_sample_rate,
                    declared_call_id,
                    declared_started_at_ms,
                    declared_finalized_at_ms,
                    recipient_master_vk_hex,
                    tuple(provenance_chain),
                    tuple(provenance_segment_sizes),
                )
                existing_contract = (
                    existing.sender_master_vk_hex,
                    existing.expected_payload_hash,
                    existing.declared_size,
                    existing.declared_duration_ms,
                    existing.declared_recording_state,
                    existing.declared_resumable_until_ms,
                    existing.declared_kind,
                    existing.declared_codec,
                    existing.declared_sample_rate,
                    existing.declared_call_id,
                    existing.declared_started_at_ms,
                    existing.declared_finalized_at_ms,
                    existing.recipient_master_vk_hex,
                    existing.provenance_chain,
                    existing.provenance_segment_sizes,
                )
                if contract != existing_contract:
                    raise InboundError("capsule_id reused with a conflicting offer")
                return existing
            if len(self._by_id) >= self._max:
                # Never evict an authenticated transfer to admit a new offer.
                # The daemon owns TTL pruning; silent FIFO replacement here
                # would desynchronise its peer/byte accounting metadata.
                raise InboundError("inbound capsule capacity reached")
            entry = InboundCapsule(
                capsule_id=capsule_id,
                sender_master_vk_hex=sender_master_vk_hex,
                expected_payload_hash=expected_payload_hash,
                declared_size=declared_size,
                declared_duration_ms=declared_duration_ms,
                declared_recording_state=declared_recording_state,
                declared_resumable_until_ms=declared_resumable_until_ms,
                declared_kind=declared_kind,
                declared_codec=declared_codec,
                declared_sample_rate=declared_sample_rate,
                declared_call_id=declared_call_id,
                declared_started_at_ms=declared_started_at_ms,
                declared_finalized_at_ms=declared_finalized_at_ms,
                recipient_master_vk_hex=recipient_master_vk_hex,
                provenance_chain=tuple(provenance_chain),
                provenance_segment_sizes=tuple(provenance_segment_sizes),
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
    if not isinstance(msg, dict):
        raise InboundError("capsule offer must be an object")
    if msg.get("t") != CAPSULE_OFFER:
        raise InboundError(f"not a {CAPSULE_OFFER}: t={msg.get('t')!r}")
    capsule_id = _valid_capsule_id(msg.get("capsule_id"))
    payload_hash = msg.get("payload_hash")
    if (
        not isinstance(payload_hash, str)
        or len(payload_hash) != 64
        or any(ch not in "0123456789abcdef" for ch in payload_hash)
    ):
        raise InboundError("missing or invalid payload_hash")
    size = _strict_int(msg.get("size"), "size")
    duration_ms = _strict_int(msg.get("duration_ms"), "duration_ms")
    recording_state = _strict_int(msg.get("recording_state"), "recording_state")
    resumable_until_ms = _strict_int(
        msg.get("resumable_until_ms"),
        "resumable_until_ms",
    )
    kind = _strict_int(msg.get("kind"), "kind")
    sample_rate = _strict_int(msg.get("sample_rate"), "sample_rate")
    call_id = _valid_call_id(msg.get("call_id"))
    started_at_ms = _strict_int(msg.get("started_at_ms"), "started_at_ms")
    finalized_at_ms = _strict_int(
        msg.get("finalized_at_ms"),
        "finalized_at_ms",
    )
    if not (1 <= size <= MAX_CAPSULE_BYTES):
        raise InboundError("capsule size outside limit")
    if not (0 <= duration_ms <= MAX_CAPSULE_DURATION_MS):
        raise InboundError("capsule duration outside limit")
    if recording_state not in {0, 1, 2, 3}:
        raise InboundError("invalid recording_state")
    if kind not in {0, 1, 2}:
        raise InboundError("invalid capsule kind")
    if resumable_until_ms < 0 or resumable_until_ms > MAX_CAPSULE_TIMESTAMP_MS:
        raise InboundError("invalid resumable_until_ms")
    if (
        started_at_ms < 0
        or finalized_at_ms < started_at_ms
        or finalized_at_ms > MAX_CAPSULE_TIMESTAMP_MS
    ):
        raise InboundError("invalid capsule capture timestamps")
    if duration_ms > finalized_at_ms - started_at_ms:
        raise InboundError("capsule duration exceeds capture interval")
    if resumable_until_ms < finalized_at_ms:
        raise InboundError("resumable_until_ms precedes finalization")
    if resumable_until_ms - finalized_at_ms > MAX_CAPSULE_RESUME_WINDOW_MS:
        raise InboundError("capsule resume window exceeds limit")
    if not (8000 <= sample_rate <= 384000):
        raise InboundError("invalid sample_rate")
    codec = msg.get("codec")
    if (
        not isinstance(codec, str)
        or not codec
        or len(codec) > MAX_CAPSULE_CODEC_CHARS
        or any(
            not (ch.isascii() and (ch.isalnum() or ch in "-_."))
            for ch in codec
        )
    ):
        raise InboundError("invalid codec")
    # Provenance is mandatory: every payload byte must be covered by an
    # authenticated segment before this offer may consume an inbound slot.
    raw_chain = msg.get("provenance_chain")
    chain: list[FrameProvenance] = []
    if not isinstance(raw_chain, list) or not raw_chain:
        raise InboundError("provenance_chain must be a non-empty list")
    if len(raw_chain) > MAX_CAPSULE_PROVENANCE_ENTRIES:
        raise InboundError("provenance_chain exceeds entry limit")
    for entry in raw_chain:
        if not isinstance(entry, dict):
            raise InboundError("provenance_chain entry must be dict")
        try:
            chain.append(from_wire_dict(entry))
        except (TypeError, ValueError) as exc:
            raise InboundError(
                f"provenance_chain entry malformed: {exc}"
            ) from exc
    raw_segment_sizes = msg.get("provenance_segment_sizes")
    if not isinstance(raw_segment_sizes, list):
        raise InboundError("provenance_segment_sizes must be a list")
    if len(raw_segment_sizes) > MAX_CAPSULE_PROVENANCE_ENTRIES:
        raise InboundError("provenance_segment_sizes exceeds entry limit")
    segment_sizes: list[int] = []
    segment_total = 0
    for raw_segment_size in raw_segment_sizes:
        segment_size = _strict_int(raw_segment_size, "provenance segment size")
        if not (1 <= segment_size <= MAX_CAPSULE_BYTES):
            raise InboundError("provenance segment size outside limit")
        segment_total += segment_size
        if segment_total > size:
            raise InboundError("provenance segments exceed capsule size")
        segment_sizes.append(segment_size)
    if len(segment_sizes) != len(chain):
        raise InboundError("provenance segment count does not match chain")
    if segment_total != size:
        raise InboundError("provenance segments do not cover capsule size")
    return {
        "capsule_id": capsule_id,
        "call_id": call_id,
        "started_at_ms": started_at_ms,
        "finalized_at_ms": finalized_at_ms,
        "payload_hash": payload_hash,
        "size": size,
        "duration_ms": duration_ms,
        "recording_state": recording_state,
        "resumable_until_ms": resumable_until_ms,
        "kind": kind,
        "codec": codec,
        "sample_rate": sample_rate,
        "provenance_chain": tuple(chain),
        "provenance_segment_sizes": tuple(segment_sizes),
    }


def parse_inbound_chunk(msg: dict) -> dict:
    """Validate a CAPSULE_CHUNK message."""
    if not isinstance(msg, dict):
        raise InboundError("capsule chunk must be an object")
    if msg.get("t") != CAPSULE_CHUNK:
        raise InboundError(f"not a {CAPSULE_CHUNK}: t={msg.get('t')!r}")
    capsule_id = _valid_capsule_id(msg.get("capsule_id"))
    seq = _strict_int(msg.get("seq", -1), "seq")
    total = (
        _strict_int(msg.get("total"), "total")
        if msg.get("total") is not None
        else None
    )
    if seq < 0:
        raise InboundError("seq required")
    if seq >= MAX_CAPSULE_CHUNKS:
        raise InboundError("seq exceeds chunk limit")
    if total is not None and not (1 <= total <= MAX_CAPSULE_CHUNKS):
        raise InboundError("total outside chunk limit")
    if total is not None and seq >= total:
        raise InboundError("seq exceeds declared total")
    data_b64 = msg.get("data_b64")
    if not isinstance(data_b64, str):
        raise InboundError("missing data_b64")
    max_encoded = ((MAX_CAPSULE_CHUNK_BYTES + 2) // 3) * 4
    if len(data_b64) > max_encoded:
        raise InboundError("data_b64 exceeds chunk size limit")
    try:
        data = base64.b64decode(data_b64.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise InboundError(f"data_b64 not valid base64: {exc}") from exc
    if len(data) > MAX_CAPSULE_CHUNK_BYTES:
        raise InboundError("decoded chunk exceeds size limit")
    if base64.b64encode(data).decode("ascii") != data_b64:
        raise InboundError("data_b64 is not canonical")
    return {
        "capsule_id": capsule_id,
        "seq": seq,
        "total": total,
        "data": data,
    }


def parse_inbound_complete(msg: dict) -> dict:
    if not isinstance(msg, dict):
        raise InboundError("capsule completion must be an object")
    if msg.get("t") != CAPSULE_COMPLETE:
        raise InboundError(f"not a {CAPSULE_COMPLETE}: t={msg.get('t')!r}")
    capsule_id = _valid_capsule_id(msg.get("capsule_id"))
    payload_hash = msg.get("payload_hash")
    if (
        not isinstance(payload_hash, str)
        or len(payload_hash) != 64
        or any(ch not in "0123456789abcdef" for ch in payload_hash)
    ):
        raise InboundError("missing or invalid payload_hash")
    n_chunks = _strict_int(msg.get("n_chunks"), "n_chunks")
    if not (1 <= n_chunks <= MAX_CAPSULE_CHUNKS):
        raise InboundError("n_chunks outside chunk limit")
    return {
        "capsule_id": capsule_id,
        "payload_hash": payload_hash,
        "n_chunks": n_chunks,
    }
