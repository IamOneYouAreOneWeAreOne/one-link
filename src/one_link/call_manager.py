"""CallManager — per-call orchestrator.

One instance per active call. Composes:

  - :class:`CallLifecycle` (INVITE/RING/ACCEPT/END/ASYNC/RESUME FSM)
  - :class:`RecordingConsent` (recording state FSM)
  - :class:`CapsuleBuilder` (during ASYNC_CAPTURE)
  - References to the shared engines (Immune, Compiler, Body,
    Route, Priority, Predictive) — held by the daemon, threaded
    through events.

The daemon owns a ``dict[call_id, CallManager]``. On every inbound
wire message + every user action + every timer + every immune
decision, the daemon looks up the manager and calls
:meth:`CallManager.handle`. The manager dispatches to the right
internal FSM, updates state, and returns a :class:`ManagerOutput`
describing the side-effects the daemon should perform.

Pure-ish: the manager itself is stateful (it holds the per-call
CRDT + FSM cells), but every transition is a pure function of
``(state, event)``. The daemon does ALL I/O.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §3 (flow diagram)
           docs/LIVING_PRESENCE_ARCHITECTURE.md §6 (lifecycle flows)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from one_link.async_capsule import (
    AsyncCapsule,
    CapsuleBuilder,
    CapsuleKind,
)
from one_link.call_session import (
    CallSession,
    Intensity,
)
from one_link.call_signaling import (
    CallLifecycle,
    CallPhase,
    CallState,
    EndCause,
    EventKind as LifecycleEventKind,
    LifecycleEvent,
    LocalAction,
    OutboundMessage,
)
from one_link.frame_provenance import RecordingState
from one_link.recording_consent import (
    ConsentEvent,
    ConsentEventKind,
    ConsentPhase,
    ConsentState,
    OutboundConsentMessage,
    RecordingConsent,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Event surface — what the daemon sends in
# ---------------------------------------------------------------------------

class ManagerEventKind(IntEnum):
    """The unified event vocabulary the CallManager accepts. The
    daemon translates wire messages, user clicks, timers, and
    engine decisions into these."""

    # User actions
    USER_INITIATE_CALL            = 0
    USER_ACCEPT                   = 1
    USER_DECLINE                  = 2
    USER_HANGUP                   = 3
    USER_RESUME                   = 4
    USER_REQUEST_RECORDING        = 10
    USER_APPROVE_RECORDING        = 11
    USER_DECLINE_RECORDING        = 12
    USER_STOP_RECORDING           = 13

    # Inbound wire messages
    WIRE_CALL_INVITE              = 20
    WIRE_CALL_ACCEPT              = 21
    WIRE_CALL_DECLINE             = 22
    WIRE_CALL_END                 = 23
    WIRE_RESUME_OFFER             = 24
    WIRE_RECORDING_REQUEST        = 25
    WIRE_RECORDING_GRANT          = 26
    WIRE_RECORDING_DECLINE        = 27
    WIRE_RECORDING_STOP           = 28
    WIRE_CAPSULE_OFFER            = 29

    # Timers + engine notifications
    INVITE_TIMER_EXPIRED          = 40
    IMMUNE_CONVERT_TO_ASYNC       = 41
    CAPSULE_FINALIZED             = 42
    RESUME_WINDOW_EXPIRED         = 43

    # Capture path — daemon feeds buffered media into the capsule
    CAPTURE_AUDIO_SEGMENT         = 50


@dataclass(frozen=True)
class ManagerEvent:
    """One input to the CallManager."""

    kind: ManagerEventKind
    occurred_at_ms: int
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Output surface — what the daemon should DO
# ---------------------------------------------------------------------------

class TailEventKind(IntEnum):
    """UI-level events the daemon broadcasts to the web UI."""

    PHASE_CHANGED              = 0
    SHOW_RING                  = 1
    HIDE_RING                  = 2
    SAS_CHALLENGE_PRESENT      = 3
    SAS_VERIFICATION_REQUIRED  = 4
    RECORDING_STATE_CHANGED    = 5
    CAPSULE_CAPTURED           = 6
    RESUME_OFFER_AVAILABLE     = 7
    REALITY_DOT_UPDATE         = 8


@dataclass(frozen=True)
class TailEvent:
    kind: TailEventKind
    payload: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ManagerOutput:
    """What the daemon does after handle() returns.

    Pure data — daemon performs the actual side-effects."""

    outbound_msgs: tuple[OutboundMessage, ...] = ()
    consent_msgs: tuple[OutboundConsentMessage, ...] = ()
    local_actions: tuple[LocalAction, ...] = ()
    tail_events: tuple[TailEvent, ...] = ()
    finalized_capsule: Optional[AsyncCapsule] = None
    # If True, the daemon may remove this manager from the active set.
    call_complete: bool = False


# ---------------------------------------------------------------------------
# Per-call state
# ---------------------------------------------------------------------------

@dataclass
class CallManagerState:
    """Mutable holder for one call. Each cell within is itself
    immutable; mutation is replacing whole cells."""

    call_id: str
    peer_master_vk_hex: str
    local_role: str                # "originator" or "recipient"

    # FSM cells
    lifecycle: CallState
    consent: ConsentState

    # CRDT
    session: CallSession

    # Capture (during ASYNC_CAPTURE → RESUMABLE)
    capsule_builder: Optional[CapsuleBuilder] = None
    finalized_capsule: Optional[AsyncCapsule] = None

    # Resume window close time (mirrored from lifecycle)
    resume_window_close_at_ms: int = 0


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------

class CallManager:
    """One instance per active call. Thread-safe under a single
    internal lock (the daemon may call ``handle`` from both the
    network recv loop and the tick loop concurrently)."""

    def __init__(
        self,
        *,
        call_id: str,
        peer_master_vk_hex: str,
        local_role: str,
        local_master_vk_hex: str,
        started_at_ms: int,
        negotiated_capabilities: frozenset[str] = frozenset(),
        model_pack_hash: Optional[str] = None,
    ) -> None:
        # RLock so any internal helper that reads a thread-safe
        # property from inside an already-held critical section
        # doesn't deadlock. The CallManager's transition handlers
        # call into helpers that themselves acquire — RLock is
        # the correct primitive for this pattern.
        self._lock = threading.RLock()
        self._lifecycle = CallLifecycle()
        self._consent = RecordingConsent()
        # The local master_vk (hex) is the writer_id for LWW writes
        # to the shared CallSession.
        self._writer_id = local_master_vk_hex

        # Initialise the CallSession CRDT.
        session = CallSession(
            call_id=call_id,
            started_at_ms=started_at_ms,
            negotiated_capabilities=negotiated_capabilities,
            model_pack_hash=model_pack_hash,
        )
        # Originator opens the dial at HIGH intensity (they initiated).
        # Recipient leaves it at the default AMBIENT until ACCEPT.
        if local_role == "originator":
            session = session.with_intensity(
                Intensity.HIGH,
                timestamp_ms=started_at_ms,
                writer_id=local_master_vk_hex,
            )

        self.state = CallManagerState(
            call_id=call_id,
            peer_master_vk_hex=peer_master_vk_hex,
            local_role=local_role,
            lifecycle=CallLifecycle.initial_state(
                call_id=call_id,
                peer_master_vk_hex=peer_master_vk_hex,
                local_role=local_role,
                started_at_ms=started_at_ms,
            ),
            consent=RecordingConsent.initial_state(call_id=call_id),
            session=session,
        )

    # ── Public introspection ──────────────────────────────────

    @property
    def call_id(self) -> str:
        return self.state.call_id

    @property
    def phase(self) -> CallPhase:
        with self._lock:
            return self.state.lifecycle.phase

    @property
    def consent_phase(self) -> ConsentPhase:
        with self._lock:
            return self.state.consent.phase

    @property
    def current_recording_state(self) -> RecordingState:
        """The provenance tag that should appear on outbound frames
        right now. The Reality Engine reads this when signing."""
        with self._lock:
            if self.state.consent.phase == ConsentPhase.RECORDING:
                return RecordingState.RECORDING_MUTUAL
            return RecordingState.NOT_RECORDING

    @property
    def is_active(self) -> bool:
        with self._lock:
            return self.state.lifecycle.phase == CallPhase.ACTIVE

    @property
    def is_capturing(self) -> bool:
        with self._lock:
            return self.state.lifecycle.phase == CallPhase.ASYNC_CAPTURE

    @property
    def is_resumable(self) -> bool:
        with self._lock:
            return self.state.lifecycle.phase == CallPhase.RESUMABLE

    @property
    def is_complete(self) -> bool:
        with self._lock:
            return self.state.lifecycle.phase == CallPhase.ENDED

    def session_snapshot(self) -> CallSession:
        with self._lock:
            return self.state.session

    # ── Event dispatch ────────────────────────────────────────

    def handle(self, event: ManagerEvent) -> ManagerOutput:
        """Process one event. Returns the side-effects the daemon
        should perform. Thread-safe."""
        with self._lock:
            return self._dispatch(event)

    def _dispatch(self, event: ManagerEvent) -> ManagerOutput:
        kind = event.kind

        # ── Lifecycle events ────────────────────────────────
        if kind == ManagerEventKind.USER_INITIATE_CALL:
            return self._lifecycle_event(
                LifecycleEventKind.USER_INITIATE_CALL, event,
            )
        if kind == ManagerEventKind.USER_ACCEPT:
            return self._lifecycle_event(
                LifecycleEventKind.USER_ACCEPT, event,
            )
        if kind == ManagerEventKind.USER_DECLINE:
            return self._lifecycle_event(
                LifecycleEventKind.USER_DECLINE, event,
            )
        if kind == ManagerEventKind.USER_HANGUP:
            return self._lifecycle_event(
                LifecycleEventKind.USER_HANGUP, event,
            )
        if kind == ManagerEventKind.USER_RESUME:
            return self._lifecycle_event(
                LifecycleEventKind.USER_RESUME, event,
            )
        if kind == ManagerEventKind.WIRE_CALL_INVITE:
            return self._lifecycle_event(
                LifecycleEventKind.WIRE_INVITE, event,
            )
        if kind == ManagerEventKind.WIRE_CALL_ACCEPT:
            return self._lifecycle_event(
                LifecycleEventKind.WIRE_ACCEPT, event,
            )
        if kind == ManagerEventKind.WIRE_CALL_DECLINE:
            return self._lifecycle_event(
                LifecycleEventKind.WIRE_DECLINE, event,
            )
        if kind == ManagerEventKind.WIRE_CALL_END:
            return self._lifecycle_event(
                LifecycleEventKind.WIRE_END, event,
            )
        if kind == ManagerEventKind.WIRE_RESUME_OFFER:
            return self._lifecycle_event(
                LifecycleEventKind.WIRE_RESUME_OFFER, event,
            )
        if kind == ManagerEventKind.INVITE_TIMER_EXPIRED:
            return self._lifecycle_event(
                LifecycleEventKind.INVITE_TIMER_EXPIRED, event,
            )
        if kind == ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC:
            return self._lifecycle_event(
                LifecycleEventKind.IMMUNE_CONVERT_TO_ASYNC, event,
            )
        if kind == ManagerEventKind.RESUME_WINDOW_EXPIRED:
            return self._lifecycle_event(
                LifecycleEventKind.RESUME_WINDOW_EXPIRED, event,
            )

        # ── Consent events ──────────────────────────────────
        if kind == ManagerEventKind.USER_REQUEST_RECORDING:
            return self._consent_event(
                ConsentEventKind.LOCAL_REQUEST_START, event,
            )
        if kind == ManagerEventKind.USER_APPROVE_RECORDING:
            return self._consent_event(
                ConsentEventKind.LOCAL_APPROVE_REQUEST, event,
            )
        if kind == ManagerEventKind.USER_DECLINE_RECORDING:
            return self._consent_event(
                ConsentEventKind.LOCAL_DECLINE_REQUEST, event,
            )
        if kind == ManagerEventKind.USER_STOP_RECORDING:
            return self._consent_event(
                ConsentEventKind.LOCAL_STOP, event,
            )
        if kind == ManagerEventKind.WIRE_RECORDING_REQUEST:
            return self._consent_event(
                ConsentEventKind.REMOTE_REQUEST_START, event,
            )
        if kind == ManagerEventKind.WIRE_RECORDING_GRANT:
            return self._consent_event(
                ConsentEventKind.REMOTE_GRANT, event,
            )
        if kind == ManagerEventKind.WIRE_RECORDING_DECLINE:
            return self._consent_event(
                ConsentEventKind.REMOTE_DECLINE, event,
            )
        if kind == ManagerEventKind.WIRE_RECORDING_STOP:
            return self._consent_event(
                ConsentEventKind.REMOTE_STOP, event,
            )

        # ── Capture path ────────────────────────────────────
        if kind == ManagerEventKind.CAPTURE_AUDIO_SEGMENT:
            return self._capture_audio_segment(event)
        if kind == ManagerEventKind.CAPSULE_FINALIZED:
            return self._finalize_capsule_event(event)

        # Unknown event: no-op
        return ManagerOutput()

    # ── Lifecycle wrapper ─────────────────────────────────────

    def _lifecycle_event(
        self,
        kind: LifecycleEventKind,
        manager_event: ManagerEvent,
    ) -> ManagerOutput:
        ev = LifecycleEvent(
            kind=kind,
            occurred_at_ms=manager_event.occurred_at_ms,
            data=manager_event.data,
        )
        old_phase = self.state.lifecycle.phase
        result = self._lifecycle.handle(self.state.lifecycle, ev)
        self.state.lifecycle = result.state

        # Mirror lifecycle into CRDT.
        tail_events: list[TailEvent] = []
        if result.state.phase != old_phase:
            tail_events.append(TailEvent(
                kind=TailEventKind.PHASE_CHANGED,
                payload={
                    "call_id": self.state.call_id,
                    "new_phase": result.state.phase.name.lower(),
                    "end_cause": result.state.end_cause.name.lower(),
                },
            ))

            # Side-effects per phase transition that aren't already
            # covered by LocalAction.
            if result.state.phase == CallPhase.RINGING:
                tail_events.append(TailEvent(
                    kind=TailEventKind.SHOW_RING,
                    payload={"call_id": self.state.call_id},
                ))
            elif result.state.phase == CallPhase.ASYNC_CAPTURE:
                # Open the capsule builder if we don't have one yet.
                if self.state.capsule_builder is None:
                    # Inline current_recording_state read — the property
                    # acquires self._lock; we already hold it, and
                    # threading.Lock is not re-entrant.
                    if self.state.consent.phase == ConsentPhase.RECORDING:
                        cap_rec_state = RecordingState.RECORDING_MUTUAL
                    else:
                        cap_rec_state = RecordingState.NOT_RECORDING
                    self.state.capsule_builder = CapsuleBuilder(
                        capsule_id=f"capsule-{self.state.call_id}",
                        call_id=self.state.call_id,
                        sender_master_vk_hex=self._writer_id,
                        recipient_master_vk_hex=self.state.peer_master_vk_hex,
                        kind=CapsuleKind.VOICE_NOTE_OUTGOING,
                        started_at_ms=self.state.lifecycle.started_at_ms,
                        recording_state_at_conversion=cap_rec_state,
                    )
            elif result.state.phase == CallPhase.RESUMABLE:
                tail_events.append(TailEvent(
                    kind=TailEventKind.RESUME_OFFER_AVAILABLE,
                    payload={
                        "call_id": self.state.call_id,
                        "resume_until_ms": result.state.resume_window_close_at_ms,
                    },
                ))

            # CRDT mirror of end state
            if result.state.phase == CallPhase.ENDED:
                self.state.session = self.state.session.with_ended(
                    reason=_lifecycle_end_to_session_end(result.state.end_cause),
                    ended_at_ms=manager_event.occurred_at_ms,
                    writer_id=self._writer_id,
                )

        # Resume window close timestamp mirrored
        self.state.resume_window_close_at_ms = (
            result.state.resume_window_close_at_ms
        )

        return ManagerOutput(
            outbound_msgs=result.outbound,
            local_actions=result.local_actions,
            tail_events=tuple(tail_events),
            call_complete=(result.state.phase == CallPhase.ENDED),
        )

    # ── Consent wrapper ───────────────────────────────────────

    def _consent_event(
        self,
        kind: ConsentEventKind,
        manager_event: ManagerEvent,
    ) -> ManagerOutput:
        ev = ConsentEvent(
            kind=kind, occurred_at_ms=manager_event.occurred_at_ms,
        )
        old_phase = self.state.consent.phase
        result = self._consent.handle(self.state.consent, ev)
        self.state.consent = result.state

        tail_events: list[TailEvent] = []
        if result.state.phase != old_phase:
            tail_events.append(TailEvent(
                kind=TailEventKind.RECORDING_STATE_CHANGED,
                payload={
                    "call_id": self.state.call_id,
                    "consent_phase": result.state.phase.name.lower(),
                    "recording_state": int(result.recording_state_for_provenance),
                },
            ))
            # Also mirror into the CallSession's recording_state LWW.
            self.state.session = self.state.session._replace_recording_state(
                result.recording_state_for_provenance,
                timestamp_ms=manager_event.occurred_at_ms,
                writer_id=self._writer_id,
            ) if hasattr(self.state.session, "_replace_recording_state") else self.state.session
            # Update via direct LWW mutation since CallSession.with_recording_state
            # isn't a top-level helper. Use the LWWRegister directly.
            from dataclasses import replace
            new_reg = self.state.session.recording_state.with_value(
                int(result.recording_state_for_provenance),
                timestamp_ms=manager_event.occurred_at_ms,
                writer_id=self._writer_id,
            )
            self.state.session = replace(
                self.state.session, recording_state=new_reg,
            )

        return ManagerOutput(
            consent_msgs=result.outbound,
            tail_events=tuple(tail_events),
        )

    # ── Capture path ──────────────────────────────────────────

    def _capture_audio_segment(self, event: ManagerEvent) -> ManagerOutput:
        """Daemon hands one audio segment to the capsule builder
        during ASYNC_CAPTURE."""
        if self.state.capsule_builder is None:
            return ManagerOutput()
        chunk = event.data.get("chunk")
        provenance = event.data.get("provenance")
        if not chunk or provenance is None:
            return ManagerOutput()
        self.state.capsule_builder.append_audio(
            chunk=chunk,
            provenance=provenance,
            timestamp_ms=event.occurred_at_ms,
        )
        return ManagerOutput()

    def _finalize_capsule_event(self, event: ManagerEvent) -> ManagerOutput:
        """Daemon signals it's done feeding segments; finalise +
        emit ASYNC_CAPSULE_FINALIZED to the lifecycle so RESUMABLE
        opens."""
        if (
            self.state.capsule_builder is None
            or self.state.capsule_builder.is_empty()
        ):
            return ManagerOutput()
        try:
            capsule = self.state.capsule_builder.finalize(
                finalized_at_ms=event.occurred_at_ms,
                resume_window_ms=self.state.lifecycle.resume_window_ms,
            )
        except Exception as exc:
            log.warning("capsule finalize failed for %s: %s",
                        self.state.call_id, exc)
            return ManagerOutput()
        self.state.finalized_capsule = capsule

        # Now drive the lifecycle through ASYNC_CAPSULE_FINALIZED.
        lifecycle_out = self._lifecycle_event(
            LifecycleEventKind.ASYNC_CAPSULE_FINALIZED,
            ManagerEvent(
                kind=ManagerEventKind.CAPSULE_FINALIZED,
                occurred_at_ms=event.occurred_at_ms,
            ),
        )
        # Attach the capsule itself + a tail event.
        from dataclasses import replace as dc_replace
        return dc_replace(
            lifecycle_out,
            finalized_capsule=capsule,
            tail_events=lifecycle_out.tail_events + (
                TailEvent(
                    kind=TailEventKind.CAPSULE_CAPTURED,
                    payload={
                        "call_id": self.state.call_id,
                        "capsule_id": capsule.capsule_id,
                        "duration_ms": capsule.duration_ms,
                        "size_bytes": capsule.size_bytes(),
                    },
                ),
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _lifecycle_end_to_session_end(end_cause: EndCause):
    """Map call_signaling.EndCause to call_session.EndReason."""
    from one_link.call_session import EndReason
    return {
        EndCause.UNSET: EndReason.ACTIVE,
        EndCause.USER_HANGUP_LOCAL: EndReason.USER_HANGUP_LOCAL,
        EndCause.USER_HANGUP_REMOTE: EndReason.USER_HANGUP_REMOTE,
        EndCause.PEER_DECLINED: EndReason.USER_HANGUP_REMOTE,
        EndCause.INVITE_TIMEOUT: EndReason.NETWORK_ASYNC,
        EndCause.NETWORK_ASYNC_CONVERSION: EndReason.NETWORK_ASYNC,
        EndCause.EMERGENCY_REKEY: EndReason.EMERGENCY_REKEY,
    }.get(end_cause, EndReason.ACTIVE)


# ---------------------------------------------------------------------------
# Registry — the daemon holds one of these
# ---------------------------------------------------------------------------

class CallManagerRegistry:
    """Thread-safe ``dict[call_id, CallManager]`` plus convenience
    lookups + cleanup of completed calls."""

    def __init__(self) -> None:
        self._calls: dict[str, CallManager] = {}
        self._lock = threading.Lock()

    def open(
        self,
        *,
        call_id: str,
        peer_master_vk_hex: str,
        local_role: str,
        local_master_vk_hex: str,
        started_at_ms: int,
        negotiated_capabilities: frozenset[str] = frozenset(),
    ) -> CallManager:
        with self._lock:
            if call_id in self._calls:
                return self._calls[call_id]
            mgr = CallManager(
                call_id=call_id,
                peer_master_vk_hex=peer_master_vk_hex,
                local_role=local_role,
                local_master_vk_hex=local_master_vk_hex,
                started_at_ms=started_at_ms,
                negotiated_capabilities=negotiated_capabilities,
            )
            self._calls[call_id] = mgr
            return mgr

    def get(self, call_id: str) -> Optional[CallManager]:
        with self._lock:
            return self._calls.get(call_id)

    def close(self, call_id: str) -> None:
        with self._lock:
            self._calls.pop(call_id, None)

    def active_call_ids(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._calls.keys())

    def reap_completed(self) -> tuple[str, ...]:
        """Remove all calls whose lifecycle is ENDED. Returns the
        removed call_ids so the daemon can release any pinned
        resources (media tracks, etc.)."""
        with self._lock:
            to_remove = [
                cid for cid, mgr in self._calls.items() if mgr.is_complete
            ]
            for cid in to_remove:
                del self._calls[cid]
            return tuple(to_remove)

    def __len__(self) -> int:
        with self._lock:
            return len(self._calls)
