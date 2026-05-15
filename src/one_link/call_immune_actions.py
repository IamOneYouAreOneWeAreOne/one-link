"""Translate ImmuneDecisions into concrete call-side actions.

The :mod:`call_immune` module is pure — it emits :class:`ImmuneAction`
codes that name what *should* happen ("request lower fidelity",
"convert to async") but the engine itself never reaches into the
RTC pipeline. This module is the actuator.

Two output channels:

  - **Browser tail events** for actions the local browser must
    perform (setParameters bitrate, disable video track, start
    MediaRecorder for capsule capture).
  - **ManagerEvents** injected into the per-call CallManager so the
    lifecycle FSM advances correctly (IMMUNE_CONVERT_TO_ASYNC ticks
    the call into ASYNC_CAPTURE → RESUMABLE).

Pure module: no I/O, no daemon imports. The daemon glues this to
its real broadcast + injection paths via a small adapter.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.1, §6.5
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from one_link.call_immune import ImmuneAction, ImmuneDecision
from one_link.call_manager import (
    CallManager,
    ManagerEvent,
    ManagerEventKind,
    ManagerOutput,
)
from one_link.call_session import Rung

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Wire format for browser tail events
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BrowserAction:
    """One side-effect the local browser should perform.

    Carried as a ``call_event`` tail message over the daemon's
    WebSocket. The UI's call_event router dispatches by
    ``tail_kind``.

    Doctrine: the ``user_message`` is the calm UI string. If
    empty, the action is invisible to the user (just a quiet
    knob turn).
    """

    tail_kind: str           # "immune_lower_fidelity" / "immune_voice_only" / ...
    call_id: str
    user_message: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {
            "type": "call_event",
            "tail_kind": self.tail_kind,
            "call_id": self.call_id,
            "user_message": self.user_message,
            **self.payload,
        }


@dataclass(frozen=True)
class ActionPlan:
    """The full plan for a single ImmuneDecision. The daemon
    executes both lists: ``browser_actions`` flow through the
    WebSocket; ``manager_events`` are fed back into the
    CallManager."""

    browser_actions: tuple[BrowserAction, ...] = ()
    manager_events: tuple[ManagerEvent, ...] = ()


# ---------------------------------------------------------------------------
# Plan emission
# ---------------------------------------------------------------------------

def plan_for_decision(
    *,
    decision: ImmuneDecision,
    call_id: str,
    now_ms: int,
) -> ActionPlan:
    """Translate one emitted decision into a concrete action plan.

    Non-emitted decisions (SHADOW HOLDs) yield an empty plan: the
    decision is still recorded in the audit log, but nothing
    side-effecting happens.
    """
    if not decision.emitted:
        return ActionPlan()
    action = decision.action

    if action == ImmuneAction.REQUEST_LOWER_FIDELITY:
        # The Compiler maps this to "drop a rung." For Tier δ the
        # browser-visible effect is reduced video bitrate.
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_lower_fidelity",
                    call_id=call_id,
                    payload={
                        "target_video_bitrate_kbps": 200,
                        "compiler_rung_hint": int(Rung.OPUS_VIDEO),
                    },
                ),
            ),
        )

    if action == ImmuneAction.REQUEST_VOICE_ONLY:
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_voice_only",
                    call_id=call_id,
                    user_message=(
                        "Voice is holding strong. Camera is paused "
                        "until the connection steadies."
                    ),
                    payload={
                        "compiler_rung_hint": int(Rung.AUDIO_ONLY),
                    },
                ),
            ),
        )

    if action == ImmuneAction.CONVERT_TO_ASYNC:
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_convert_to_async",
                    call_id=call_id,
                    user_message=(
                        "Connection's gone for a moment. Keep talking. "
                        "It'll pick up where you left off."
                    ),
                    payload={
                        "compiler_rung_hint": int(Rung.ASYNC_CAPSULE),
                    },
                ),
            ),
            manager_events=(
                ManagerEvent(
                    kind=ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC,
                    occurred_at_ms=now_ms,
                    data={"reason_code": decision.reason_code},
                ),
            ),
        )

    if action == ImmuneAction.PREWARM_BACKUP_ROUTE:
        # Tier ε territory — the Route Brain will pick the actual
        # route. We just signal the intent to the browser so the
        # UI can hint "looking for a stronger path" if it chooses.
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_prewarm_route",
                    call_id=call_id,
                ),
            ),
        )

    if action == ImmuneAction.SUGGEST_DEVICE_HANDOFF:
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_suggest_handoff",
                    call_id=call_id,
                    user_message=(
                        "Your phone has a clearer mic right now. "
                        "Switch?"
                    ),
                ),
            ),
        )

    if action == ImmuneAction.SWITCH_ROUTE:
        # Tier ε — the actual switch is the daemon's responsibility;
        # we just signal completion to the UI.
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_switch_route",
                    call_id=call_id,
                ),
            ),
        )

    if action == ImmuneAction.EMERGENCY_REKEY:
        return ActionPlan(
            browser_actions=(
                BrowserAction(
                    tail_kind="immune_rekey",
                    call_id=call_id,
                    user_message=(
                        "Refreshing the secure connection."
                    ),
                ),
            ),
        )

    # HOLD or unknown — no action.
    return ActionPlan()


# ---------------------------------------------------------------------------
# Execution helper
# ---------------------------------------------------------------------------

def execute_plan(
    *,
    plan: ActionPlan,
    manager: Optional[CallManager],
    broadcast_tail: Any,
) -> tuple[ManagerOutput, ...]:
    """Apply a plan to the live system.

    - Each ``BrowserAction`` is broadcast via ``broadcast_tail``.
    - Each ``ManagerEvent`` is fed to ``manager.handle()`` and the
      returned :class:`ManagerOutput` is collected so the daemon
      can flush it (it may contain new outbound wire messages).

    Returns the tuple of ManagerOutputs (one per event), in order.
    Empty tuple if no events fire or no manager.
    """
    for action in plan.browser_actions:
        try:
            broadcast_tail(action.to_wire())
        except Exception as exc:
            log.warning("execute_plan: tail broadcast raised: %s", exc)
    outputs: list[ManagerOutput] = []
    if manager is not None:
        for ev in plan.manager_events:
            try:
                outputs.append(manager.handle(ev))
            except Exception as exc:
                log.warning(
                    "execute_plan: manager.handle raised on %s: %s",
                    ev.kind.name, exc,
                )
    return tuple(outputs)
