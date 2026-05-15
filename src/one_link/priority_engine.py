"""Human Signal Priority Engine — bandwidth allocator.

Under bandwidth pressure, the human survives. Voice beats video;
intelligibility beats fidelity; faces beat backgrounds; files cede
to media. This module is the deterministic allocator that turns a
total available bandwidth + the active rung into a per-stream
allocation.

Ships AUTOPILOT from day one. The user never opts in or out — this
is a transport-layer safety property, not a feature.

Per the architecture doc §4.6 the priority hierarchy is:

    P0_VOICE              intelligibility-critical
    P1_TIMING             turn-taking signals, ack pings
    P2_FACE_PRIMARY       primary face region (semantic)
    P3_GESTURE            hands, body pose
    P4_FILE_INFLIGHT      files in transit
    P5_VIDEO_BACKGROUND   background pixels
    P6_AMBIENT            background environmental data

Each class gets a strictly higher weight than every class below it,
so under contention the lower-class streams cede first. The
allocation is in kbps; the QUIC layer maps the kbps to per-stream
priorities at the wire.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.6
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Mapping

from one_link.call_session import Rung


# ---------------------------------------------------------------------------
# QoS class
# ---------------------------------------------------------------------------

class QoSClass(IntEnum):
    """Lower number = higher priority. Strict ordering — under
    contention, lower-classes get every bit they need before any
    higher-class gets one."""

    P0_VOICE             = 0
    P1_TIMING            = 1
    P2_FACE_PRIMARY      = 2
    P3_GESTURE           = 3
    P4_FILE_INFLIGHT     = 4
    P5_VIDEO_BACKGROUND  = 5
    P6_AMBIENT           = 6


# ---------------------------------------------------------------------------
# Stream descriptors
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MediaStream:
    """One outbound media stream. The QUIC layer maintains one of
    these per `m=` line + auxiliary stream (control, semantic, file).

    ``min_kbps`` is the minimum the stream needs to be usable at all
    (below this it should be paused, not allocated a partial share).
    ``ideal_kbps`` is what it wants when bandwidth is plentiful.
    """

    stream_id: str
    qos_class: QoSClass
    min_kbps: float
    ideal_kbps: float
    enabled: bool = True


# ---------------------------------------------------------------------------
# Allocation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class StreamAllocation:
    """Per-stream output of the allocator. ``allocated_kbps == 0``
    means the stream is paused — there isn't enough budget. The
    QUIC layer should suspend it gracefully."""

    stream_id: str
    qos_class: QoSClass
    allocated_kbps: float
    paused: bool


# ---------------------------------------------------------------------------
# Rung → mask
# ---------------------------------------------------------------------------

# Which QoS classes are PERMITTED at each rung. Higher rungs permit
# everything; lower rungs progressively mask out video / file /
# ambient classes so the allocator never wastes budget on streams
# the Compiler has already turned off.
_RUNG_MASKS: dict[Rung, frozenset[QoSClass]] = {
    Rung.RAW_AV: frozenset(QoSClass),
    Rung.OPUS_VIDEO: frozenset(QoSClass),
    Rung.SEMANTIC_DELTA_AV: frozenset({
        QoSClass.P0_VOICE, QoSClass.P1_TIMING,
        QoSClass.P2_FACE_PRIMARY, QoSClass.P3_GESTURE,
        QoSClass.P4_FILE_INFLIGHT, QoSClass.P6_AMBIENT,
    }),
    Rung.FACE_STILL_MOTION: frozenset({
        QoSClass.P0_VOICE, QoSClass.P1_TIMING,
        QoSClass.P2_FACE_PRIMARY,
        QoSClass.P4_FILE_INFLIGHT, QoSClass.P6_AMBIENT,
    }),
    Rung.AUDIO_ONLY: frozenset({
        QoSClass.P0_VOICE, QoSClass.P1_TIMING,
        QoSClass.P4_FILE_INFLIGHT, QoSClass.P6_AMBIENT,
    }),
    Rung.PUSH_TO_TALK: frozenset({
        QoSClass.P0_VOICE, QoSClass.P1_TIMING,
    }),
    Rung.CONCEPT_TEXT: frozenset({
        QoSClass.P0_VOICE, QoSClass.P1_TIMING,
    }),
    Rung.ASYNC_CAPSULE: frozenset({
        QoSClass.P1_TIMING,  # control plane only; no live media
    }),
    Rung.AMBIENT_PRESENCE: frozenset({
        QoSClass.P1_TIMING,
    }),
}


# ---------------------------------------------------------------------------
# The allocator
# ---------------------------------------------------------------------------

def allocate(
    *,
    streams: list[MediaStream],
    total_bandwidth_kbps: float,
    current_rung: Rung,
) -> list[StreamAllocation]:
    """Compute the per-stream bandwidth allocation.

    Allocation discipline:
      1. Mask streams whose QoS class isn't permitted at the
         current rung. Those are forced paused.
      2. Sort the remaining streams by (qos_class, stream_id) —
         highest priority (lowest class number) first; lex-min
         stream_id as the deterministic tiebreak within a class.
      3. Greedily allocate each stream its ``min_kbps`` first.
         If the budget runs out, lower-class streams are paused.
      4. Distribute leftover budget proportionally to (ideal - min)
         in priority order — highest-priority gets its full
         (ideal - min) topup before any lower-class stream gets any
         of theirs.
      5. Disabled streams emit a paused allocation with 0 kbps so
         the caller can still iterate the full list.
    """
    if total_bandwidth_kbps < 0:
        total_bandwidth_kbps = 0.0

    permitted = _RUNG_MASKS[current_rung]
    out: dict[str, StreamAllocation] = {}

    # Step 1: emit paused allocations for disabled or masked-out streams.
    eligible: list[MediaStream] = []
    for s in streams:
        if not s.enabled:
            out[s.stream_id] = StreamAllocation(
                stream_id=s.stream_id,
                qos_class=s.qos_class,
                allocated_kbps=0.0,
                paused=True,
            )
            continue
        if s.qos_class not in permitted:
            out[s.stream_id] = StreamAllocation(
                stream_id=s.stream_id,
                qos_class=s.qos_class,
                allocated_kbps=0.0,
                paused=True,
            )
            continue
        eligible.append(s)

    if not eligible:
        return _flat(out, streams)

    # Step 2: priority-ordered, deterministic.
    eligible.sort(key=lambda s: (int(s.qos_class), s.stream_id))

    # Step 3: allocate min_kbps to as many streams as budget allows,
    # in priority order. Streams that don't fit are paused.
    remaining = total_bandwidth_kbps
    funded: list[MediaStream] = []
    for s in eligible:
        if remaining >= s.min_kbps:
            remaining -= s.min_kbps
            funded.append(s)
        else:
            out[s.stream_id] = StreamAllocation(
                stream_id=s.stream_id,
                qos_class=s.qos_class,
                allocated_kbps=0.0,
                paused=True,
            )

    # Step 4: topup. Each funded stream wants up to (ideal - min)
    # additional kbps; priority order, fully fund higher-class
    # streams before lower-class ones get any topup.
    topups: dict[str, float] = {s.stream_id: 0.0 for s in funded}
    for s in funded:
        want = max(0.0, s.ideal_kbps - s.min_kbps)
        give = min(want, remaining)
        topups[s.stream_id] = give
        remaining -= give
        if remaining <= 0.0:
            break

    for s in funded:
        out[s.stream_id] = StreamAllocation(
            stream_id=s.stream_id,
            qos_class=s.qos_class,
            allocated_kbps=s.min_kbps + topups[s.stream_id],
            paused=False,
        )

    return _flat(out, streams)


def _flat(
    allocations: dict[str, StreamAllocation],
    original: list[MediaStream],
) -> list[StreamAllocation]:
    """Return allocations in the original stream order so callers
    don't get a surprise reorder."""
    return [allocations[s.stream_id] for s in original]


# ---------------------------------------------------------------------------
# Convenience: total allocated kbps (for telemetry)
# ---------------------------------------------------------------------------

def total_allocated(allocations: list[StreamAllocation]) -> float:
    return sum(a.allocated_kbps for a in allocations)


def stream_by_class(
    allocations: list[StreamAllocation],
) -> Mapping[QoSClass, list[StreamAllocation]]:
    out: dict[QoSClass, list[StreamAllocation]] = {}
    for a in allocations:
        out.setdefault(a.qos_class, []).append(a)
    return out
