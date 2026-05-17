"""Call API adapter — JSON request handler for browser/UI clients.

Sits between the daemon's HTTP/WebSocket layer and the
:class:`CallManager`. The browser (or any UI surface) POSTs a JSON
request; this module dispatches into the right CallManager and
returns a structured response.

Design:
  - Pure adapter: no I/O of its own. The daemon's HTTP server
    calls into ``CallAPI.handle()`` with a parsed JSON dict and
    sends back the returned :class:`ApiResponse`.
  - Doctrine-compliant errors: every failure returns a calm,
    plain-language ``user_message`` field — never an error code.
    Internal codes live in ``server_log`` for engineers.
  - Idempotent where possible: re-initiating a call to the same
    peer that's already active returns the existing call_id.
  - Stateless dispatch: holds only the registry; the registry
    holds state.

HTTP route mapping (suggested):

    POST /api/calls                          → initiate
    POST /api/calls/{id}/accept              → accept
    POST /api/calls/{id}/decline             → decline
    POST /api/calls/{id}/hangup              → hangup
    POST /api/calls/{id}/resume              → resume
    POST /api/calls/{id}/recording/request   → request_recording
    POST /api/calls/{id}/recording/approve   → approve_recording
    POST /api/calls/{id}/recording/decline   → decline_recording
    POST /api/calls/{id}/recording/stop      → stop_recording
    GET  /api/calls                          → list_active
    GET  /api/calls/{id}                     → status

The HTTP layer can ALSO take everything through one route as a
JSON command pattern; the daemon picks. This module supports both
shapes via the unified ``handle()`` entry point + targeted methods.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §6 (call lifecycle)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional

from one_link.call_manager import (
    CallManager,
    CallManagerRegistry,
    ManagerEvent,
    ManagerEventKind,
    ManagerOutput,
    TailEvent,
    TailEventKind,
)
from one_link.call_signaling import CallPhase
from one_link.recording_consent import ConsentPhase

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Action vocabulary
# ---------------------------------------------------------------------------

class CallAction(IntEnum):
    """Actions the UI can take. Maps to ManagerEventKind under
    the hood but exposed as a stable string-typed API for the
    HTTP layer to consume."""

    INITIATE          = 0
    ACCEPT            = 1
    DECLINE           = 2
    HANGUP            = 3
    RESUME            = 4
    REQUEST_RECORDING = 10
    APPROVE_RECORDING = 11
    DECLINE_RECORDING = 12
    STOP_RECORDING    = 13


# String-form for the HTTP layer.
_ACTION_BY_NAME: dict[str, CallAction] = {
    "initiate":           CallAction.INITIATE,
    "accept":             CallAction.ACCEPT,
    "decline":            CallAction.DECLINE,
    "hangup":             CallAction.HANGUP,
    "resume":             CallAction.RESUME,
    "request_recording":  CallAction.REQUEST_RECORDING,
    "approve_recording":  CallAction.APPROVE_RECORDING,
    "decline_recording":  CallAction.DECLINE_RECORDING,
    "stop_recording":     CallAction.STOP_RECORDING,
}

_ACTION_TO_EVENT: dict[CallAction, ManagerEventKind] = {
    CallAction.INITIATE:          ManagerEventKind.USER_INITIATE_CALL,
    CallAction.ACCEPT:            ManagerEventKind.USER_ACCEPT,
    CallAction.DECLINE:           ManagerEventKind.USER_DECLINE,
    CallAction.HANGUP:            ManagerEventKind.USER_HANGUP,
    CallAction.RESUME:            ManagerEventKind.USER_RESUME,
    CallAction.REQUEST_RECORDING: ManagerEventKind.USER_REQUEST_RECORDING,
    CallAction.APPROVE_RECORDING: ManagerEventKind.USER_APPROVE_RECORDING,
    CallAction.DECLINE_RECORDING: ManagerEventKind.USER_DECLINE_RECORDING,
    CallAction.STOP_RECORDING:    ManagerEventKind.USER_STOP_RECORDING,
}


# ---------------------------------------------------------------------------
# Request / response shapes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ApiRequest:
    """One inbound action from the UI."""

    action: CallAction
    call_id: Optional[str] = None
    # For INITIATE only:
    peer_master_vk_hex: Optional[str] = None
    # Optional negotiated caps for the new call. The HTTP layer
    # gets these from the daemon's capability negotiation state.
    negotiated_capabilities: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ApiOutboundMessage:
    """A wire message the daemon should send to the peer."""

    type: str
    peer_master_vk_hex: str
    payload: dict


@dataclass(frozen=True)
class ApiResponse:
    """Structured response. ``ok=False`` means the action was
    refused; ``user_message`` is the plain-language reason."""

    ok: bool
    call_id: Optional[str] = None
    phase: Optional[str] = None
    consent_phase: Optional[str] = None
    user_message: str = ""
    server_log: str = ""
    outbound: tuple[ApiOutboundMessage, ...] = ()
    tail_events: tuple[TailEvent, ...] = ()
    # When the call has been fully terminated and the daemon may
    # reap the manager.
    call_complete: bool = False


# ---------------------------------------------------------------------------
# CallAPI
# ---------------------------------------------------------------------------

class CallAPI:
    """JSON-friendly adapter. Holds a reference to the daemon's
    :class:`CallManagerRegistry`; otherwise stateless."""

    def __init__(
        self,
        *,
        registry: CallManagerRegistry,
        local_master_vk_hex: str,
    ) -> None:
        self._registry = registry
        self._local_vk = local_master_vk_hex

    # ── Generic entry point ──────────────────────────────────

    def handle(self, request: ApiRequest) -> ApiResponse:
        """Dispatch one action. Returns a fully-formed
        :class:`ApiResponse`. Never raises — all errors flow as
        ok=False with a plain-language explanation."""
        try:
            return self._dispatch(request)
        except Exception as exc:
            log.warning("CallAPI dispatch crashed: %s", exc)
            return ApiResponse(
                ok=False,
                user_message="Something didn't work. Please try in a moment.",
                server_log=f"unhandled: {exc!r}",
            )

    # ── Convenience for JSON-from-HTTP ───────────────────────

    def handle_json(self, body: dict) -> ApiResponse:
        """Take a JSON dict (already-parsed by the HTTP layer) and
        dispatch. The expected shape is:

            {"action": "initiate", "peer_master_vk_hex": "...",
             "negotiated_capabilities": ["webrtc_av_v1", ...]}

        or any of the call-scoped actions:

            {"action": "accept", "call_id": "..."}
            {"action": "hangup", "call_id": "..."}
            …
        """
        if not isinstance(body, dict):
            return ApiResponse(
                ok=False,
                user_message="Request shape was unexpected.",
                server_log="non-dict body",
            )
        action_name = body.get("action")
        if not isinstance(action_name, str):
            return ApiResponse(
                ok=False,
                user_message="That action is not available.",
                server_log=f"missing action; got {body!r}",
            )
        action = _ACTION_BY_NAME.get(action_name.lower())
        if action is None:
            return ApiResponse(
                ok=False,
                user_message="That action is not available.",
                server_log=f"unknown action {action_name!r}",
            )
        return self.handle(ApiRequest(
            action=action,
            call_id=body.get("call_id"),
            peer_master_vk_hex=body.get("peer_master_vk_hex"),
            negotiated_capabilities=frozenset(
                body.get("negotiated_capabilities") or []
            ),
        ))

    # ── Targeted methods (the HTTP layer may use these directly) ──

    def initiate(
        self,
        *,
        peer_master_vk_hex: str,
        negotiated_capabilities: frozenset[str] = frozenset(),
    ) -> ApiResponse:
        return self.handle(ApiRequest(
            action=CallAction.INITIATE,
            peer_master_vk_hex=peer_master_vk_hex,
            negotiated_capabilities=negotiated_capabilities,
        ))

    def status(self, call_id: str) -> ApiResponse:
        mgr = self._registry.get(call_id)
        if mgr is None:
            return ApiResponse(
                ok=False, user_message="That call is not active.",
                server_log=f"status: unknown call_id {call_id!r}",
            )
        return ApiResponse(
            ok=True, call_id=call_id,
            phase=mgr.phase.name.lower(),
            consent_phase=mgr.consent_phase.name.lower(),
        )

    def list_active(self) -> tuple[ApiResponse, ...]:
        return tuple(self.status(cid) for cid in self._registry.active_call_ids())

    # ── Internal dispatch ───────────────────────────────────

    def _dispatch(self, request: ApiRequest) -> ApiResponse:
        if request.action == CallAction.INITIATE:
            return self._dispatch_initiate(request)
        # Every other action requires a call_id
        call_id = request.call_id
        if not isinstance(call_id, str) or not call_id:
            return ApiResponse(
                ok=False,
                user_message="That call is no longer available.",
                server_log=f"{request.action.name}: missing call_id",
            )
        mgr = self._registry.get(call_id)
        if mgr is None:
            return ApiResponse(
                ok=False, call_id=call_id,
                user_message="That call is no longer available.",
                server_log=f"{request.action.name}: unknown call_id",
            )
        event_kind = _ACTION_TO_EVENT[request.action]
        out = mgr.handle(ManagerEvent(
            kind=event_kind,
            occurred_at_ms=int(time.time() * 1000),
        ))
        return self._make_response(mgr, out, call_id=call_id)

    def _dispatch_initiate(self, request: ApiRequest) -> ApiResponse:
        peer = request.peer_master_vk_hex
        if not isinstance(peer, str) or not peer:
            return ApiResponse(
                ok=False,
                user_message="Pick someone to call.",
                server_log="initiate: missing peer_master_vk_hex",
            )
        # Idempotent: if there's already an active call with this
        # peer, return its id.
        existing = self._find_active_call_with_peer(peer)
        if existing is not None:
            return ApiResponse(
                ok=True, call_id=existing.call_id,
                phase=existing.phase.name.lower(),
                consent_phase=existing.consent_phase.name.lower(),
                user_message="",
            )
        call_id = _mint_call_id()
        started_at_ms = int(time.time() * 1000)
        mgr = self._registry.open(
            call_id=call_id,
            peer_master_vk_hex=peer,
            local_role="originator",
            local_master_vk_hex=self._local_vk,
            started_at_ms=started_at_ms,
            negotiated_capabilities=request.negotiated_capabilities,
        )
        out = mgr.handle(ManagerEvent(
            kind=ManagerEventKind.USER_INITIATE_CALL,
            occurred_at_ms=started_at_ms,
        ))
        return self._make_response(mgr, out, call_id=call_id)

    def _find_active_call_with_peer(self, peer_vk_hex: str) -> Optional[CallManager]:
        """Return an existing in-progress call to this peer, if any.

        An "in-progress" call is one in INVITING / RINGING / ACTIVE
        phase. Calls that have converted to ASYNC_CAPTURE (declined
        or degraded), RESUMABLE (capsule committed), or ENDED are NOT
        considered active for dedupe purposes — re-initiating to the
        same peer should open a fresh call, not silently join the
        leftover stub. Doctrine §3.2.e: a declined call becoming a
        voice-note is its own thing; the next live attempt is a
        separate conversation.
        """
        for cid in self._registry.active_call_ids():
            mgr = self._registry.get(cid)
            if mgr is None:
                continue
            phase = mgr.phase
            if phase not in (
                CallPhase.INVITING, CallPhase.RINGING, CallPhase.ACTIVE,
            ):
                continue
            # Peer match comes from the CallManager state.
            with mgr._lock:  # noqa: SLF001 — adapter has friend access
                if mgr.state.peer_master_vk_hex == peer_vk_hex:
                    return mgr
        return None

    @staticmethod
    def _make_response(
        mgr: CallManager,
        out: ManagerOutput,
        *,
        call_id: str,
    ) -> ApiResponse:
        outbound = tuple(
            ApiOutboundMessage(
                type=m.type,
                peer_master_vk_hex=m.target_peer_fp,
                payload=m.payload,
            )
            for m in out.outbound_msgs
        ) + tuple(
            ApiOutboundMessage(
                type=m.type,
                peer_master_vk_hex=mgr.state.peer_master_vk_hex
                if hasattr(mgr, "state") else "",
                payload=m.payload,
            )
            for m in out.consent_msgs
        )
        return ApiResponse(
            ok=True,
            call_id=call_id,
            phase=mgr.phase.name.lower(),
            consent_phase=mgr.consent_phase.name.lower(),
            outbound=outbound,
            tail_events=out.tail_events,
            call_complete=out.call_complete,
        )


# ---------------------------------------------------------------------------
# call_id minting
# ---------------------------------------------------------------------------

def _mint_call_id() -> str:
    """ULID-ish: 26-char base32 monotonic id. We use uuid4 as the
    randomness source and prefix with a millisecond timestamp so
    sort order matches creation order in chat logs."""
    import uuid
    ts = int(time.time() * 1000)
    return f"call-{ts:013d}-{uuid.uuid4().hex[:12]}"
