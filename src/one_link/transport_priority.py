"""Transport Prioritizer — weighted-fair-queuing per QoS class.

The Priority Engine in :mod:`priority_engine` decides *how much*
bandwidth each conversation class deserves. This module is the
mechanism — it accepts outbound messages tagged with a QoS class,
holds them in per-class queues, and emits them under a scheduling
policy that honours the priority weights.

Why not just "send everything in order":
  - On a saturated link, voice packets MUST not queue behind
    file-transfer chunks. The single-stream daemon transport
    appends-in-order — without prioritization, a 1 MiB file chunk
    pinned in front of a 200-byte voice packet adds hundreds of
    milliseconds of latency.
  - The Immune System's bandwidth controller emits
    REQUEST_VOICE_ONLY when total link capacity drops below the
    P0 floor. This module is what makes that emission
    operationally meaningful — when the budget is tight, the
    P0 queue (voice) drains, and lower-class queues (P3
    file-bytes) starve until budget recovers.

The scheduler implements **deficit weighted round-robin (DWRR)**:
  - Each class gets a "deficit counter" that grows by its weight
    every scheduling tick.
  - When a class's deficit covers the size of the head-of-queue
    packet, that packet is emitted and the deficit decremented.
  - This gives strict ordering by priority class AND fair
    bandwidth sharing within a class.

Pure module: no I/O, no sockets, no daemon imports. The daemon
plugs the prioritizer between its message-producer code and the
channel write loop.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.6 (Priority Engine)
"""

from __future__ import annotations

import threading
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# QoS class hierarchy
# ---------------------------------------------------------------------------

class QoSClass(IntEnum):
    """Maps message types to scheduling priority. Lower = higher
    priority. Values are intentionally sparse so future tiers can
    insert classes without breaking persisted state."""

    # P0 — must-survive
    VOICE_FRAMES        = 0   # opus, every 20 ms
    CALL_LIFECYCLE      = 1   # INVITE / ACCEPT / END — small, urgent
    PRESENCE_LIVENESS   = 2   # heartbeat, alive pings

    # P1 — timing critical
    SDP_ICE             = 10  # signaling — must complete fast
    FRAME_ATTESTATION   = 11  # Tier β rolling-window attestations

    # P2 — face + video keyframes
    VIDEO_KEYFRAME      = 20
    SAS_VERIFICATION    = 21

    # P3 — bulk
    VIDEO_DELTA         = 30
    CAPABILITY_GRANT    = 31
    GROUP_EVENT         = 32

    # P4 — best-effort
    FILE_CHUNK          = 40
    FOLDER_SYNC         = 41
    GROUP_BULK          = 42

    # P5 — background
    DHT_MAINTENANCE     = 50
    METRICS             = 51


# Default weights — how many bytes per scheduling tick each class
# may emit. The ratios encode the doctrine: voice is sacred, file
# bytes wait. Operators can tune at construction time.
DEFAULT_WEIGHTS_PER_CLASS: dict[QoSClass, int] = {
    QoSClass.VOICE_FRAMES:       2_000,
    QoSClass.CALL_LIFECYCLE:     2_000,
    QoSClass.PRESENCE_LIVENESS:    500,
    QoSClass.SDP_ICE:            1_500,
    QoSClass.FRAME_ATTESTATION:    500,
    QoSClass.VIDEO_KEYFRAME:     1_500,
    QoSClass.SAS_VERIFICATION:     500,
    QoSClass.VIDEO_DELTA:        1_000,
    QoSClass.CAPABILITY_GRANT:     500,
    QoSClass.GROUP_EVENT:          500,
    QoSClass.FILE_CHUNK:           500,
    QoSClass.FOLDER_SYNC:          500,
    QoSClass.GROUP_BULK:           500,
    QoSClass.DHT_MAINTENANCE:      200,
    QoSClass.METRICS:              200,
}


# Map wire-message type → QoS class. The daemon's send path looks
# up the class by message type. Unknown types fall through to
# FILE_CHUNK (best-effort).
WIRE_TYPE_TO_QOS: dict[str, QoSClass] = {
    # Voice / video frame plane (Tier β+)
    "CALL_FRAME": QoSClass.VOICE_FRAMES,
    "CALL_FRAME_ATTEST": QoSClass.FRAME_ATTESTATION,
    # Call lifecycle
    "CALL_INVITE": QoSClass.CALL_LIFECYCLE,
    "CALL_ACCEPT": QoSClass.CALL_LIFECYCLE,
    "CALL_DECLINE": QoSClass.CALL_LIFECYCLE,
    "CALL_END": QoSClass.CALL_LIFECYCLE,
    "CALL_RESUME_OFFER": QoSClass.CALL_LIFECYCLE,
    # SDP + ICE
    "CALL_SDP_OFFER": QoSClass.SDP_ICE,
    "CALL_SDP_ANSWER": QoSClass.SDP_ICE,
    "CALL_ICE": QoSClass.SDP_ICE,
    # Recording consent
    "RECORDING_REQUEST": QoSClass.SAS_VERIFICATION,
    "RECORDING_GRANT": QoSClass.SAS_VERIFICATION,
    "RECORDING_DECLINE": QoSClass.SAS_VERIFICATION,
    "RECORDING_STOP": QoSClass.SAS_VERIFICATION,
    # Presence + heartbeat
    "PRESENCE": QoSClass.PRESENCE_LIVENESS,
    "PING": QoSClass.PRESENCE_LIVENESS,
    "PONG": QoSClass.PRESENCE_LIVENESS,
    # Capability grants
    "CAPABILITY_GRANT": QoSClass.CAPABILITY_GRANT,
    "CAPS": QoSClass.CAPABILITY_GRANT,
    # Group messages
    "GROUP_EVENT": QoSClass.GROUP_EVENT,
    "GROUP_KEY_OFFER": QoSClass.GROUP_EVENT,
    "GROUP_MSG": QoSClass.GROUP_BULK,
    # File transfer
    "FILE_OFFER": QoSClass.FILE_CHUNK,
    "FILE_CHUNK": QoSClass.FILE_CHUNK,
    "FILE_BIN_CHUNK": QoSClass.FILE_CHUNK,
    "FILE_NATIVE_CHUNK": QoSClass.FILE_CHUNK,
    "FILE_CDC_CHUNK": QoSClass.FILE_CHUNK,
    "CHUNK_QUERY": QoSClass.FILE_CHUNK,
    "CHUNK_PULL": QoSClass.FILE_CHUNK,
    # Folder sync
    "MANIFEST_PUSH": QoSClass.FOLDER_SYNC,
    "MANIFEST_WANTS": QoSClass.FOLDER_SYNC,
    "BLOB_OFFER": QoSClass.FOLDER_SYNC,
    "BLOB_CHUNK": QoSClass.FOLDER_SYNC,
    # Text + reactions
    "TEXT": QoSClass.SAS_VERIFICATION,  # interactive chat = P2-ish
    "REACTION": QoSClass.SAS_VERIFICATION,
    "EDIT_MSG": QoSClass.SAS_VERIFICATION,
    "DELETE_MSG": QoSClass.SAS_VERIFICATION,
    "TYPING": QoSClass.METRICS,
    "READ_MARKER": QoSClass.METRICS,
    # ACK
    "ACK": QoSClass.PRESENCE_LIVENESS,
}


def classify(msg_type: str) -> QoSClass:
    """Map a wire-message type string to its QoS class. Unknown
    types fall through to FILE_CHUNK (best-effort)."""
    return WIRE_TYPE_TO_QOS.get(msg_type, QoSClass.FILE_CHUNK)


# ---------------------------------------------------------------------------
# Prioritizer
# ---------------------------------------------------------------------------

@dataclass
class _QueuedMessage:
    payload: bytes
    qos_class: QoSClass
    size: int
    # Optional callback fired after the message is dispatched
    # (lets the daemon free buffers / record send timestamps).
    on_sent: Optional[Callable[[], None]] = None


class TransportPrioritizer:
    """Deficit weighted round-robin scheduler.

    Use:
      - :meth:`enqueue` to admit one message tagged with its QoS class.
      - :meth:`drain` to drain ready messages in priority order; the
        caller writes each to the underlying channel.
      - :meth:`set_budget_per_tick` to clip total bytes per drain
        cycle (the Immune System uses this when bandwidth tightens).

    Thread-safe.
    """

    def __init__(
        self,
        *,
        weights: Optional[dict[QoSClass, int]] = None,
        max_queue_bytes_per_class: int = 4 * 1024 * 1024,
    ) -> None:
        self._lock = threading.Lock()
        self._weights = dict(weights or DEFAULT_WEIGHTS_PER_CLASS)
        self._queues: dict[QoSClass, deque[_QueuedMessage]] = {
            qc: deque() for qc in QoSClass
        }
        self._deficits: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}
        self._queue_bytes: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}
        self._max_queue_bytes = max_queue_bytes_per_class
        self._budget_per_tick: Optional[int] = None
        # Stats — exposed for the Immune System + audit log.
        self._enqueued_count: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}
        self._dropped_count: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}
        self._sent_count: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}
        self._sent_bytes: dict[QoSClass, int] = {qc: 0 for qc in QoSClass}

    def enqueue(
        self,
        *,
        payload: bytes,
        qos_class: QoSClass,
        on_sent: Optional[Callable[[], None]] = None,
    ) -> bool:
        """Admit a message. Returns True if accepted, False if the
        class's queue is full (back-pressure → drop)."""
        with self._lock:
            if self._queue_bytes[qos_class] + len(payload) > self._max_queue_bytes:
                self._dropped_count[qos_class] += 1
                return False
            self._queues[qos_class].append(_QueuedMessage(
                payload=payload, qos_class=qos_class,
                size=len(payload), on_sent=on_sent,
            ))
            self._queue_bytes[qos_class] += len(payload)
            self._enqueued_count[qos_class] += 1
            return True

    def set_budget_per_tick(self, budget_bytes: Optional[int]) -> None:
        """Hard cap on bytes emitted per drain cycle. None = no cap."""
        with self._lock:
            self._budget_per_tick = budget_bytes

    def set_weight(self, qos_class: QoSClass, weight: int) -> None:
        """Adjust the per-tick credit for one class. The Immune
        System calls this when it asks for REQUEST_VOICE_ONLY —
        it caps every non-voice class to a token weight."""
        if weight < 0:
            raise ValueError("weight must be non-negative")
        with self._lock:
            self._weights[qos_class] = weight

    def drain(self) -> list[_QueuedMessage]:
        """Emit one scheduling tick worth of messages, in priority
        order. Returns the ordered list the caller writes to the
        wire."""
        ready: list[_QueuedMessage] = []
        with self._lock:
            budget_remaining = self._budget_per_tick
            for qc in sorted(QoSClass, key=lambda x: int(x)):
                self._deficits[qc] += self._weights[qc]
                q = self._queues[qc]
                while q:
                    head = q[0]
                    if self._deficits[qc] < head.size:
                        break
                    if budget_remaining is not None and budget_remaining <= 0:
                        # Hard cap reached — stop entirely.
                        # Carry over deficits to the next tick so
                        # we don't starve under repeated tight caps.
                        return ready
                    q.popleft()
                    self._queue_bytes[qc] -= head.size
                    self._deficits[qc] -= head.size
                    if budget_remaining is not None:
                        budget_remaining -= head.size
                    self._sent_count[qc] += 1
                    self._sent_bytes[qc] += head.size
                    ready.append(head)
        return ready

    def queue_depth(self, qos_class: QoSClass) -> int:
        with self._lock:
            return len(self._queues[qos_class])

    def total_queue_bytes(self) -> int:
        with self._lock:
            return sum(self._queue_bytes.values())

    def stats(self) -> dict[str, dict[str, int]]:
        """Snapshot of per-class counters. The Immune System's
        controller reads this each tick to decide if pressure has
        eased enough to lift voice-only mode."""
        with self._lock:
            return {
                qc.name: {
                    "enqueued": self._enqueued_count[qc],
                    "sent": self._sent_count[qc],
                    "sent_bytes": self._sent_bytes[qc],
                    "dropped": self._dropped_count[qc],
                    "queue_depth": len(self._queues[qc]),
                    "queue_bytes": self._queue_bytes[qc],
                    "weight": self._weights[qc],
                }
                for qc in QoSClass
            }

    def reset_counters(self) -> None:
        with self._lock:
            for qc in QoSClass:
                self._enqueued_count[qc] = 0
                self._sent_count[qc] = 0
                self._sent_bytes[qc] = 0
                self._dropped_count[qc] = 0

    # ── Immune-System bridge helpers ────────────────────────────

    def enter_voice_only_mode(self) -> None:
        """Cap every non-P0 class to its minimum weight so voice
        bytes drain first. Reversible via :meth:`exit_voice_only_mode`."""
        with self._lock:
            self._saved_weights: dict[QoSClass, int] | None = dict(self._weights)
            # P0 (VOICE / LIFECYCLE / PRESENCE) keeps full weight.
            for qc in QoSClass:
                if int(qc) >= 10:  # any class P1+ is throttled to a token
                    self._weights[qc] = max(1, self._weights[qc] // 100)

    def exit_voice_only_mode(self) -> None:
        with self._lock:
            saved = getattr(self, "_saved_weights", None)
            if saved is not None:
                self._weights = saved
                self._saved_weights = None
