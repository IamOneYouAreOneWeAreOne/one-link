"""Call lifecycle signaling — wire types + state machine.

This module owns the per-call FSM (Finite State Machine) that takes
a call from INVITE → RING → ACCEPT → ACTIVE → END, with detours
through DECLINE, ASYNC, and RESUME as conditions require.

The FSM is *pure*: given a starting state + an incoming event, it
returns the new state and any outbound signaling messages.
Concretely:

    CallLifecycle.handle(event) -> (new_state, outbound_msgs)

Everything that touches the wire — sending the messages, persisting
the conversation, kicking off media — is downstream of the FSM.
This separation keeps the lifecycle replayable and testable.

Doctrine of Invisibility compliance:

  - No error codes in any state transition. Failures convert.
  - No "busy" / "missed call" states (Doctrine §3.2, §3.10).
  - DECLINED isn't surfaced as failure; it becomes async capsule
    on the originator side automatically.
  - Time limits ARE expressed but the user sees them in plain
    language ("for the next few minutes…"), not as countdowns.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §6 (lifecycle flows)
           docs/DOCTRINE_OF_INVISIBILITY.md §3.2, §3.10
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


# ---------------------------------------------------------------------------
# Wire message types
# ---------------------------------------------------------------------------

# These are the strings the daemon's _on_peer_message dispatches on.
# Adding a new one requires extending the daemon dispatch table —
# see [src/one_link/daemon.py] _on_peer_message().
CALL_INVITE      = "CALL_INVITE"
CALL_RING        = "CALL_RING"           # device-to-device fan-out within a peer's mesh
CALL_ACCEPT      = "CALL_ACCEPT"
CALL_DECLINE     = "CALL_DECLINE"
CALL_END         = "CALL_END"
CALL_STATE_DELTA = "CALL_STATE_DELTA"    # CRDT delta over CallSession
RESUME_OFFER     = "RESUME_OFFER"        # within the 10-min window after async


# ---------------------------------------------------------------------------
# Lifecycle states
# ---------------------------------------------------------------------------

class CallPhase(IntEnum):
    """The FSM states. Ordered roughly by lifetime progression."""

    INVITING        = 0   # we sent INVITE, awaiting ACCEPT/DECLINE/timeout
    RINGING         = 1   # we received INVITE, surfaced ring on local devices
    ACTIVE          = 2   # call connected, media flowing
    ASYNC_CAPTURE   = 3   # converted to async; capturing the message
    RESUMABLE       = 4   # async committed; resume window open
    ENDED           = 5   # terminal — call is over (clean or async or refused)


class EndCause(IntEnum):
    """Why the call left ACTIVE. None of these surface to the user
    as 'errors' — the Compiler + Capsule conversion makes them
    invisible. Recorded internally for telemetry + audit."""

    UNSET                  = 0   # call hasn't ended yet
    USER_HANGUP_LOCAL      = 1
    USER_HANGUP_REMOTE     = 2
    PEER_DECLINED          = 3
    INVITE_TIMEOUT         = 4
    NETWORK_ASYNC_CONVERSION = 5
    EMERGENCY_REKEY        = 6


# ---------------------------------------------------------------------------
# Events the FSM accepts
# ---------------------------------------------------------------------------

class EventKind(IntEnum):
    """Inputs the lifecycle FSM consumes. The handle() switch is
    over these."""

    # Local-user actions
    USER_INITIATE_CALL  = 0   # user tapped "Call Mom"
    USER_ACCEPT         = 1
    USER_DECLINE        = 2
    USER_HANGUP         = 3
    USER_RESUME         = 4
    # Inbound wire messages
    WIRE_INVITE         = 10
    WIRE_RING           = 11
    WIRE_ACCEPT         = 12
    WIRE_DECLINE        = 13
    WIRE_END            = 14
    WIRE_RESUME_OFFER   = 15
    # Timers + engine notifications
    INVITE_TIMER_EXPIRED = 20
    IMMUNE_CONVERT_TO_ASYNC = 21
    ASYNC_CAPSULE_FINALIZED = 22
    RESUME_WINDOW_EXPIRED = 23


@dataclass(frozen=True)
class LifecycleEvent:
    """One input to the FSM. ``data`` carries event-specific payload
    (e.g., the inbound message dict for WIRE_* events)."""

    kind: EventKind
    occurred_at_ms: int
    data: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Outbound messages — what the FSM tells the daemon to send
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OutboundMessage:
    """A wire message the daemon should encrypt + send to a peer.
    The FSM doesn't send — it emits intent."""

    type: str                     # one of the CALL_* constants
    target_peer_fp: str            # who to send it to
    payload: dict                  # body fields beyond the standard wire envelope


@dataclass(frozen=True)
class LocalAction(IntEnum):
    """Side-effects the FSM requests on the LOCAL side. The daemon
    fulfills these. Always tagged so the daemon can log them."""

    NONE                = 0
    START_INVITE_TIMER  = 1
    STOP_INVITE_TIMER   = 2
    SHOW_RING           = 3
    HIDE_RING           = 4
    START_MEDIA         = 5
    STOP_MEDIA          = 6
    CAPTURE_TO_CAPSULE  = 7
    OPEN_RESUME_WINDOW  = 8
    CLOSE_RESUME_WINDOW = 9


# ---------------------------------------------------------------------------
# The FSM
# ---------------------------------------------------------------------------

# Default invite timeout — after this many ms the originator gives
# up waiting and converts to async capsule. 30 seconds matches the
# default ring duration in voice messaging products; long enough
# to reach for a phone, short enough to not feel abandoned.
DEFAULT_INVITE_TIMEOUT_MS = 30_000

# Resume window — after a call converts to async, the user has
# this long to tap "resume" before the window closes. 10 minutes
# matches LIVING_PRESENCE_ARCHITECTURE.md §6.7.
DEFAULT_RESUME_WINDOW_MS = 10 * 60 * 1000


@dataclass(frozen=True)
class CallState:
    """Immutable snapshot of the call's lifecycle position. The FSM
    returns a NEW state on each event; the daemon stores the latest."""

    call_id: str
    peer_master_vk_hex: str    # who we're calling / called by
    local_role: str            # "originator" or "recipient"
    phase: CallPhase
    started_at_ms: int
    invite_sent_at_ms: int = 0
    accepted_at_ms: int = 0
    ended_at_ms: int = 0
    end_cause: EndCause = EndCause.UNSET
    resume_window_close_at_ms: int = 0
    invite_timeout_ms: int = DEFAULT_INVITE_TIMEOUT_MS
    resume_window_ms: int = DEFAULT_RESUME_WINDOW_MS


@dataclass(frozen=True)
class FSMOutput:
    """What the FSM returns on each event: the new state, the
    outbound messages to send, and the local actions to perform.
    Pure data — daemon does the I/O."""

    state: CallState
    outbound: tuple[OutboundMessage, ...] = ()
    local_actions: tuple[LocalAction, ...] = ()


class CallLifecycle:
    """Pure-function FSM. No I/O, no daemon refs. Tests instantiate
    directly; the daemon wraps it with persistence + signaling."""

    @staticmethod
    def initial_state(
        *,
        call_id: str,
        peer_master_vk_hex: str,
        local_role: str,
        started_at_ms: int,
        invite_timeout_ms: int = DEFAULT_INVITE_TIMEOUT_MS,
        resume_window_ms: int = DEFAULT_RESUME_WINDOW_MS,
    ) -> CallState:
        if local_role not in ("originator", "recipient"):
            raise ValueError(
                f"local_role must be 'originator' or 'recipient', "
                f"got {local_role!r}"
            )
        # Originator starts ready to send INVITE on USER_INITIATE_CALL.
        # Recipient starts in INVITING-equivalent waiting-for-WIRE_INVITE,
        # but practically the state machine is driven by events from the
        # first event onward; we use INVITING as the "pre-invite" state
        # for the originator too, distinguishing by local_role.
        return CallState(
            call_id=call_id,
            peer_master_vk_hex=peer_master_vk_hex,
            local_role=local_role,
            phase=CallPhase.INVITING,
            started_at_ms=started_at_ms,
            invite_timeout_ms=invite_timeout_ms,
            resume_window_ms=resume_window_ms,
        )

    def handle(self, state: CallState, event: LifecycleEvent) -> FSMOutput:
        """Dispatch on (phase, event.kind). Returns new state +
        outputs. Unknown / illegal transitions are no-ops — the FSM
        is forgiving so flaky network deliveries don't break the
        call."""
        phase = state.phase
        kind = event.kind

        # ── INVITING ─────────────────────────────────────────────
        if phase == CallPhase.INVITING:
            if state.local_role == "originator":
                if kind == EventKind.USER_INITIATE_CALL:
                    return self._originator_send_invite(state, event)
                if kind == EventKind.WIRE_ACCEPT:
                    return self._originator_on_accept(state, event)
                if kind == EventKind.WIRE_DECLINE:
                    return self._originator_on_decline(state, event)
                if kind == EventKind.INVITE_TIMER_EXPIRED:
                    return self._originator_on_invite_timeout(state, event)
                if kind == EventKind.USER_HANGUP:
                    return self._originator_cancel_invite(state, event)
            else:  # recipient
                if kind == EventKind.WIRE_INVITE:
                    return self._recipient_on_invite(state, event)

        # ── RINGING ──────────────────────────────────────────────
        if phase == CallPhase.RINGING:
            if kind == EventKind.USER_ACCEPT:
                return self._recipient_accept(state, event)
            if kind == EventKind.USER_DECLINE:
                return self._recipient_decline(state, event)
            if kind == EventKind.INVITE_TIMER_EXPIRED:
                return self._recipient_invite_timeout(state, event)
            if kind == EventKind.WIRE_END:
                # Originator hung up before we picked up.
                return self._recipient_caller_cancelled(state, event)

        # ── ACTIVE ───────────────────────────────────────────────
        if phase == CallPhase.ACTIVE:
            if kind == EventKind.USER_HANGUP:
                return self._active_user_hangup(state, event)
            if kind == EventKind.WIRE_END:
                return self._active_remote_hangup(state, event)
            if kind == EventKind.IMMUNE_CONVERT_TO_ASYNC:
                return self._active_to_async(state, event)

        # ── ASYNC_CAPTURE ────────────────────────────────────────
        if phase == CallPhase.ASYNC_CAPTURE:
            if kind == EventKind.ASYNC_CAPSULE_FINALIZED:
                return self._async_to_resumable(state, event)

        # ── RESUMABLE ────────────────────────────────────────────
        if phase == CallPhase.RESUMABLE:
            if kind == EventKind.USER_RESUME:
                return self._resumable_to_new_call(state, event)
            if kind == EventKind.WIRE_RESUME_OFFER:
                return self._resumable_remote_resume(state, event)
            if kind == EventKind.RESUME_WINDOW_EXPIRED:
                return self._resumable_window_close(state, event)

        # No-op (illegal / late event in this phase). Don't error.
        return FSMOutput(state=state)

    # ── Originator transitions ────────────────────────────────

    def _originator_send_invite(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        new_state = _replace(
            state,
            invite_sent_at_ms=event.occurred_at_ms,
        )
        return FSMOutput(
            state=new_state,
            outbound=(OutboundMessage(
                type=CALL_INVITE,
                target_peer_fp=state.peer_master_vk_hex,
                payload={
                    "call_id": state.call_id,
                    "originator_role": "caller",
                    "ttl_ms": state.invite_timeout_ms,
                },
            ),),
            local_actions=(LocalAction.START_INVITE_TIMER,),
        )

    def _originator_on_accept(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ACTIVE,
                accepted_at_ms=event.occurred_at_ms,
            ),
            local_actions=(LocalAction.STOP_INVITE_TIMER, LocalAction.START_MEDIA),
        )

    def _originator_on_decline(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # Per Doctrine §3.2.e — "Call failed" is forbidden. Convert
        # the declined call into an async capsule capture so the
        # user can leave a message instead of seeing failure.
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ASYNC_CAPTURE,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.PEER_DECLINED,
            ),
            local_actions=(
                LocalAction.STOP_INVITE_TIMER,
                LocalAction.CAPTURE_TO_CAPSULE,
            ),
        )

    def _originator_on_invite_timeout(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ASYNC_CAPTURE,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.INVITE_TIMEOUT,
            ),
            local_actions=(LocalAction.CAPTURE_TO_CAPSULE,),
        )

    def _originator_cancel_invite(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # User explicitly cancelled before peer answered — clean end.
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.USER_HANGUP_LOCAL,
            ),
            outbound=(OutboundMessage(
                type=CALL_END,
                target_peer_fp=state.peer_master_vk_hex,
                payload={"call_id": state.call_id, "reason": "cancelled"},
            ),),
            local_actions=(LocalAction.STOP_INVITE_TIMER,),
        )

    # ── Recipient transitions ─────────────────────────────────

    def _recipient_on_invite(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(state, phase=CallPhase.RINGING),
            local_actions=(LocalAction.SHOW_RING, LocalAction.START_INVITE_TIMER),
        )

    def _recipient_invite_timeout(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        """Stop an unanswered ring locally when the authenticated TTL ends."""

        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.INVITE_TIMEOUT,
            ),
            local_actions=(LocalAction.STOP_INVITE_TIMER, LocalAction.HIDE_RING),
        )

    def _recipient_accept(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ACTIVE,
                accepted_at_ms=event.occurred_at_ms,
            ),
            outbound=(OutboundMessage(
                type=CALL_ACCEPT,
                target_peer_fp=state.peer_master_vk_hex,
                payload={"call_id": state.call_id},
            ),),
            local_actions=(LocalAction.HIDE_RING, LocalAction.START_MEDIA),
        )

    def _recipient_decline(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.USER_HANGUP_LOCAL,
            ),
            outbound=(OutboundMessage(
                type=CALL_DECLINE,
                target_peer_fp=state.peer_master_vk_hex,
                payload={"call_id": state.call_id},
            ),),
            local_actions=(LocalAction.HIDE_RING,),
        )

    def _recipient_caller_cancelled(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.USER_HANGUP_REMOTE,
            ),
            local_actions=(LocalAction.HIDE_RING,),
        )

    # ── Active transitions ────────────────────────────────────

    def _active_user_hangup(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.USER_HANGUP_LOCAL,
            ),
            outbound=(OutboundMessage(
                type=CALL_END,
                target_peer_fp=state.peer_master_vk_hex,
                payload={"call_id": state.call_id, "reason": "hangup"},
            ),),
            local_actions=(LocalAction.STOP_MEDIA,),
        )

    def _active_remote_hangup(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ENDED,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.USER_HANGUP_REMOTE,
            ),
            local_actions=(LocalAction.STOP_MEDIA,),
        )

    def _active_to_async(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # Immune System converted the call to async. We stop media,
        # start capturing the in-flight buffer as a capsule.
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.ASYNC_CAPTURE,
                ended_at_ms=event.occurred_at_ms,
                end_cause=EndCause.NETWORK_ASYNC_CONVERSION,
            ),
            local_actions=(LocalAction.STOP_MEDIA, LocalAction.CAPTURE_TO_CAPSULE),
        )

    # ── Async / Resumable transitions ─────────────────────────

    def _async_to_resumable(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        close_at = event.occurred_at_ms + state.resume_window_ms
        return FSMOutput(
            state=_replace(
                state,
                phase=CallPhase.RESUMABLE,
                resume_window_close_at_ms=close_at,
            ),
            local_actions=(LocalAction.OPEN_RESUME_WINDOW,),
        )

    def _resumable_to_new_call(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # User tapped Resume — emit a RESUME_OFFER. The peer
        # receives it; the daemon then starts a NEW CallSession
        # with resume_of pointing at this call_id.
        return FSMOutput(
            state=_replace(state, phase=CallPhase.ENDED),
            outbound=(OutboundMessage(
                type=RESUME_OFFER,
                target_peer_fp=state.peer_master_vk_hex,
                payload={
                    "prior_call_id": state.call_id,
                    "originator_role": "caller",
                },
            ),),
            local_actions=(LocalAction.CLOSE_RESUME_WINDOW,),
        )

    def _resumable_remote_resume(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # Peer resumed first. We close OUR resume window.
        return FSMOutput(
            state=_replace(state, phase=CallPhase.ENDED),
            local_actions=(LocalAction.CLOSE_RESUME_WINDOW,),
        )

    def _resumable_window_close(
        self, state: CallState, event: LifecycleEvent,
    ) -> FSMOutput:
        # Resume window expired without anyone tapping resume. The
        # capsule remains in the chat surface — the user can still
        # listen to it, just not "pick up where you left off" live.
        return FSMOutput(
            state=_replace(state, phase=CallPhase.ENDED),
            local_actions=(LocalAction.CLOSE_RESUME_WINDOW,),
        )


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _replace(state: CallState, **kw) -> CallState:
    """frozen-dataclass replace, but we use a thin wrapper for
    readability inside the FSM body."""
    from dataclasses import replace
    return replace(state, **kw)
