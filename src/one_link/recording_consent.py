"""Recording consent flow.

Recording is the single most-felt privacy moment in any call app.
The doctrine treats it as a load-bearing surface (§3.5.b, §3.5.c,
§7.2 in LIVING_PRESENCE_ARCHITECTURE.md):

  - Both ends must explicitly tap a recording-start affordance.
  - The recording indicator is VISIBLE during the entire duration —
    never a 1-pixel dot, never tucked in a settings menu.
  - Either party stopping ends recording immediately at that frame.
  - Recorded artifacts are cryptographically signed via per-frame
    FrameProvenance so they're authenticatable + undeepfakeable.
  - There is NO silent recording. Ever.

This module owns the state machine for the consent flow:

    1. One side taps "Save this call" → emit RECORDING_REQUEST.
    2. The peer sees the request explicitly. Approve/decline.
    3. On mutual approval, recording state transitions to
       RECORDING_MUTUAL. Frames thereafter carry
       FrameKind.REAL + recording_state=RECORDING_MUTUAL in
       their FrameProvenance.
    4. Either side tapping stop → state returns to NOT_RECORDING.
    5. Daemon receives stop event → emit RECORDING_STOP to peer.

The state machine is pure: same input sequence → same output. The
daemon handles the I/O (encrypt, store, sign) downstream.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §7.2
           docs/DOCTRINE_OF_INVISIBILITY.md §3.5.b, §3.5.c
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from one_link.frame_provenance import RecordingState


# ---------------------------------------------------------------------------
# Wire types
# ---------------------------------------------------------------------------

RECORDING_REQUEST = "RECORDING_REQUEST"   # "I'd like to save this call"
RECORDING_GRANT   = "RECORDING_GRANT"     # peer approves
RECORDING_DECLINE = "RECORDING_DECLINE"   # peer refuses
RECORDING_STOP    = "RECORDING_STOP"      # either side stops


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class ConsentEventKind(IntEnum):
    """Inputs the consent FSM consumes."""

    LOCAL_REQUEST_START   = 0   # user tapped "Save this call"
    LOCAL_APPROVE_REQUEST = 1   # user accepts peer's request
    LOCAL_DECLINE_REQUEST = 2   # user declines peer's request
    LOCAL_STOP            = 3   # user tapped Stop Recording

    REMOTE_REQUEST_START  = 10  # peer wants to record
    REMOTE_GRANT          = 11  # peer approves our request
    REMOTE_DECLINE        = 12  # peer refuses our request
    REMOTE_STOP           = 13  # peer stopped recording

    # Force-revoke (e.g., capability granted to "record" was
    # revoked by the user post-hoc): treated identically to LOCAL_STOP
    LOCAL_REVOKE          = 20


@dataclass(frozen=True)
class ConsentEvent:
    kind: ConsentEventKind
    occurred_at_ms: int


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

class ConsentPhase(IntEnum):
    NONE                       = 0   # not recording, no request pending
    AWAITING_REMOTE_RESPONSE   = 1   # we asked, waiting for peer
    AWAITING_LOCAL_RESPONSE    = 2   # peer asked, awaiting our user
    RECORDING                  = 3   # mutual approval; recording live


# ---------------------------------------------------------------------------
# Output messages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OutboundConsentMessage:
    """Message the daemon should send to the peer."""

    type: str   # one of the RECORDING_* constants
    payload: dict


# ---------------------------------------------------------------------------
# State + FSM output
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ConsentState:
    """Immutable per-call consent state."""

    call_id: str
    phase: ConsentPhase
    started_at_ms: int = 0
    requestor: Optional[str] = None   # "local" or "remote" — who initiated


@dataclass(frozen=True)
class ConsentOutput:
    state: ConsentState
    outbound: tuple[OutboundConsentMessage, ...] = ()
    # The provenance-tagging hint for the media pipeline. The
    # daemon reads this on every state transition and passes it
    # into subsequent sign_provenance() calls.
    recording_state_for_provenance: RecordingState = RecordingState.NOT_RECORDING


# ---------------------------------------------------------------------------
# The FSM
# ---------------------------------------------------------------------------

class RecordingConsent:
    """Pure-function FSM. Like CallLifecycle, no I/O."""

    @staticmethod
    def initial_state(*, call_id: str) -> ConsentState:
        return ConsentState(call_id=call_id, phase=ConsentPhase.NONE)

    def handle(
        self, state: ConsentState, event: ConsentEvent,
    ) -> ConsentOutput:
        phase = state.phase
        kind = event.kind

        # ── NONE ──────────────────────────────────────────────
        if phase == ConsentPhase.NONE:
            if kind == ConsentEventKind.LOCAL_REQUEST_START:
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.AWAITING_REMOTE_RESPONSE,
                        requestor="local",
                    ),
                    outbound=(OutboundConsentMessage(
                        type=RECORDING_REQUEST,
                        payload={"call_id": state.call_id},
                    ),),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )
            if kind == ConsentEventKind.REMOTE_REQUEST_START:
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.AWAITING_LOCAL_RESPONSE,
                        requestor="remote",
                    ),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )
            # Any other event in NONE is a no-op (e.g., stale
            # REMOTE_STOP from a prior session).

        # ── AWAITING_REMOTE_RESPONSE ──────────────────────────
        if phase == ConsentPhase.AWAITING_REMOTE_RESPONSE:
            if kind == ConsentEventKind.REMOTE_GRANT:
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.RECORDING,
                        started_at_ms=event.occurred_at_ms,
                    ),
                    recording_state_for_provenance=RecordingState.RECORDING_MUTUAL,
                )
            if kind == ConsentEventKind.REMOTE_DECLINE:
                # Peer declined. State returns to NONE — no
                # error code surfaced; UI shows a calm "they
                # didn't agree" badge briefly.
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )
            if kind == ConsentEventKind.LOCAL_STOP:
                # User cancelled their own request before the peer
                # responded. Withdraw cleanly.
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    outbound=(OutboundConsentMessage(
                        type=RECORDING_STOP,
                        payload={"call_id": state.call_id, "reason": "withdrawn"},
                    ),),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )

        # ── AWAITING_LOCAL_RESPONSE ───────────────────────────
        if phase == ConsentPhase.AWAITING_LOCAL_RESPONSE:
            if kind == ConsentEventKind.LOCAL_APPROVE_REQUEST:
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.RECORDING,
                        started_at_ms=event.occurred_at_ms,
                    ),
                    outbound=(OutboundConsentMessage(
                        type=RECORDING_GRANT,
                        payload={"call_id": state.call_id},
                    ),),
                    recording_state_for_provenance=RecordingState.RECORDING_MUTUAL,
                )
            if kind == ConsentEventKind.LOCAL_DECLINE_REQUEST:
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    outbound=(OutboundConsentMessage(
                        type=RECORDING_DECLINE,
                        payload={"call_id": state.call_id},
                    ),),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )
            if kind == ConsentEventKind.REMOTE_STOP:
                # Peer withdrew their request before we responded.
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )

        # ── RECORDING ─────────────────────────────────────────
        if phase == ConsentPhase.RECORDING:
            if kind in (
                ConsentEventKind.LOCAL_STOP,
                ConsentEventKind.LOCAL_REVOKE,
            ):
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    outbound=(OutboundConsentMessage(
                        type=RECORDING_STOP,
                        payload={"call_id": state.call_id},
                    ),),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )
            if kind == ConsentEventKind.REMOTE_STOP:
                # Peer stopped. We stop too — recording requires
                # both sides agreeing throughout. Doctrine §7.2.
                return ConsentOutput(
                    state=_replace(
                        state,
                        phase=ConsentPhase.NONE,
                        requestor=None,
                    ),
                    recording_state_for_provenance=RecordingState.NOT_RECORDING,
                )

        # Unknown / late event: no-op (doctrine says we never crash).
        return ConsentOutput(
            state=state,
            recording_state_for_provenance=_phase_to_provenance(state.phase),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _phase_to_provenance(phase: ConsentPhase) -> RecordingState:
    """The FrameProvenance.recording_state tag for the current
    consent phase. NONE / AWAITING_* all map to NOT_RECORDING —
    the media pipeline only tags frames as recording while the FSM
    is in RECORDING."""
    if phase == ConsentPhase.RECORDING:
        return RecordingState.RECORDING_MUTUAL
    return RecordingState.NOT_RECORDING


def _replace(state: ConsentState, **kw) -> ConsentState:
    from dataclasses import replace
    return replace(state, **kw)


# ---------------------------------------------------------------------------
# UI surface (plain-language)
# ---------------------------------------------------------------------------

def consent_label(phase: ConsentPhase) -> str:
    """The text the Reality dot detail pane shows for the current
    consent state. NEVER includes 'may be recorded' or 'quality
    assurance' (Doctrine §3.5.b)."""
    return {
        ConsentPhase.NONE:                     "Not recording",
        ConsentPhase.AWAITING_REMOTE_RESPONSE: "Waiting for them to agree to save",
        ConsentPhase.AWAITING_LOCAL_RESPONSE:  "They want to save this call",
        ConsentPhase.RECORDING:                "Recording (both sides agreed)",
    }[phase]
