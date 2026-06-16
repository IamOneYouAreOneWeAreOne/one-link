"""Activation policy for the Universal Comms Fabric.

The fabric is allowed to be ambitious, but transport activation must be boring
in the best possible way: deterministic, auditable, deny-by-risk, and easy for
the UI to explain. This module decides whether a discovered path may be used
automatically, requires a user ceremony, or must remain disabled.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .transport_adapters.base import AdapterProbe, RouteScore


class ActivationState(str, Enum):
    ACTIVE = "active"
    READY = "ready"
    ASK_USER = "ask_user"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"


class ActivationRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ActivationIntent:
    """What the caller wants to move over a path."""

    needs_bulk: bool = True
    needs_control: bool = True
    cross_internet_ok: bool = True
    offline_ok: bool = True
    allow_admin: bool = False
    allow_user_ceremony: bool = True
    min_bps: float = 0.0
    trusted_peer: bool = False
    verified_peer: bool = False


@dataclass(frozen=True)
class ActivationPlan:
    adapter_id: str
    route_name: str
    state: ActivationState
    risk: ActivationRisk
    score: float
    automatic: bool
    needs_user: bool
    reason: str
    next_action: str
    safeguards: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "adapter_id": self.adapter_id,
            "route_name": self.route_name,
            "state": self.state.value,
            "risk": self.risk.value,
            "score": round(self.score, 6),
            "automatic": self.automatic,
            "needs_user": self.needs_user,
            "reason": self.reason,
            "next_action": self.next_action,
            "safeguards": list(self.safeguards),
        }


def activation_plan_for(
    score: RouteScore,
    probe: AdapterProbe | None = None,
    *,
    intent: ActivationIntent | None = None,
    peer: object | None = None,
) -> ActivationPlan:
    """Return the activation decision for one scored path.

    ``peer`` is intentionally duck-typed. Current daemon peer records are not a
    stable cross-layer type, so callers can pass any object exposing useful
    trust/verification hints; missing attributes simply keep the policy
    conservative.
    """

    intent = intent or ActivationIntent()
    trusted = intent.trusted_peer or _truthy_attr(peer, "trusted") or _trust_is_pinned(peer)
    verified = intent.verified_peer or _truthy_attr(peer, "verified")
    safeguards = _base_safeguards(score, probe)

    if score.score <= 0.0 or (probe is not None and not probe.available):
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.UNAVAILABLE,
            risk=ActivationRisk.LOW,
            score=0.0,
            automatic=False,
            needs_user=False,
            reason=score.reason or "path unavailable",
            next_action="wait_for_path",
            safeguards=safeguards,
        )

    if intent.needs_bulk and not score.usable_for_bulk:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.ASK_USER if score.usable_for_control else ActivationState.BLOCKED,
            risk=ActivationRisk.MEDIUM,
            score=min(score.score, 0.25),
            automatic=False,
            needs_user=score.usable_for_control,
            reason="control-only path cannot carry this transfer",
            next_action="use_for_pairing_or_find_bulk_path" if score.usable_for_control else "find_bulk_path",
            safeguards=safeguards + ("bulk payloads are never forced through control-only hardware",),
        )

    if intent.needs_control and not score.usable_for_control:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.BLOCKED,
            risk=ActivationRisk.HIGH,
            score=0.0,
            automatic=False,
            needs_user=False,
            reason="path cannot carry required control handshake",
            next_action="find_control_path",
            safeguards=safeguards,
        )

    if score.estimated_bps < intent.min_bps:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.READY,
            risk=ActivationRisk.MEDIUM,
            score=min(score.score, 0.40),
            automatic=False,
            needs_user=False,
            reason="path is below the requested speed floor",
            next_action="prefer_faster_path",
            safeguards=safeguards,
        )

    if _is_cross_internet(score) and not intent.cross_internet_ok:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.BLOCKED,
            risk=ActivationRisk.HIGH,
            score=0.0,
            automatic=False,
            needs_user=False,
            reason="internet route disabled for this intent",
            next_action="use_local_or_offline_path",
            safeguards=safeguards,
        )

    if score.route_name == "courier" and not intent.offline_ok:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.BLOCKED,
            risk=ActivationRisk.MEDIUM,
            score=0.0,
            automatic=False,
            needs_user=False,
            reason="offline courier route disabled for this intent",
            next_action="wait_for_live_path",
            safeguards=safeguards,
        )

    if probe is not None and probe.requires_admin and not intent.allow_admin:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.ASK_USER if intent.allow_user_ceremony else ActivationState.BLOCKED,
            risk=ActivationRisk.HIGH,
            score=min(score.score, 0.35),
            automatic=False,
            needs_user=intent.allow_user_ceremony,
            reason="path requires elevated OS permission",
            next_action="ask_user_for_permission" if intent.allow_user_ceremony else "choose_non_admin_path",
            safeguards=safeguards + ("admin-required paths cannot auto-start",),
        )

    if probe is not None and probe.requires_user_action:
        return ActivationPlan(
            adapter_id=score.adapter_id,
            route_name=score.route_name,
            state=ActivationState.ASK_USER if intent.allow_user_ceremony else ActivationState.READY,
            risk=_risk_for(score, probe),
            score=min(score.score, 0.65),
            automatic=False,
            needs_user=intent.allow_user_ceremony,
            reason="path needs a user-visible device ceremony",
            next_action="ask_user_for_ceremony" if intent.allow_user_ceremony else "wait_for_existing_path",
            safeguards=safeguards + ("user-ceremony paths are explicit and revocable",),
        )

    risk = _risk_for(score, probe)
    automatic = trusted and verified and risk in {ActivationRisk.LOW, ActivationRisk.MEDIUM}
    if not trusted:
        reason = "peer is not trusted yet"
        next_action = "pair_and_verify_peer"
        state = ActivationState.ASK_USER
        needs_user = True
    elif not verified and _is_sensitive_route(score):
        reason = "peer identity needs verification before automatic activation"
        next_action = "verify_peer"
        state = ActivationState.ASK_USER
        needs_user = True
    elif risk == ActivationRisk.HIGH:
        reason = "route is high risk and needs explicit approval"
        next_action = "ask_user_for_route"
        state = ActivationState.ASK_USER
        needs_user = True
    else:
        reason = score.reason or "path ready"
        next_action = "open_route" if automatic else "keep_ready"
        state = ActivationState.ACTIVE if automatic else ActivationState.READY
        needs_user = False

    return ActivationPlan(
        adapter_id=score.adapter_id,
        route_name=score.route_name,
        state=state,
        risk=risk,
        score=score.score,
        automatic=automatic,
        needs_user=needs_user,
        reason=reason,
        next_action=next_action,
        safeguards=safeguards,
    )


def activation_plans_for(
    scores: Iterable[RouteScore],
    probes: Iterable[AdapterProbe] = (),
    *,
    intent: ActivationIntent | None = None,
    peer: object | None = None,
) -> tuple[ActivationPlan, ...]:
    probes_by_id = {p.adapter_id: p for p in probes}
    plans = [
        activation_plan_for(
            score,
            probes_by_id.get(score.adapter_id),
            intent=intent,
            peer=peer,
        )
        for score in scores
    ]
    return tuple(sorted(
        plans,
        key=lambda p: (
            _state_rank(p.state),
            _risk_rank(p.risk),
            -p.score,
            p.route_name,
            p.adapter_id,
        ),
    ))


def _base_safeguards(score: RouteScore, probe: AdapterProbe | None) -> tuple[str, ...]:
    out = [
        "peer identity is verified above transport",
        "all payload chunks are cryptographically verified",
        "route can be dropped and reopened without losing the send intent",
    ]
    if score.usable_for_bulk:
        out.append("bulk path uses backpressure and chunk-level retry")
    if probe is not None and probe.requires_user_action:
        out.append("activation is gated by explicit local device state")
    if _is_cross_internet(score):
        out.append("internet paths stay end-to-end encrypted and relay-blind")
    if score.route_name in {"lan", "wifi_direct"}:
        out.append("local paths never require cloud storage")
    return tuple(dict.fromkeys(out))


def _risk_for(score: RouteScore, probe: AdapterProbe | None) -> ActivationRisk:
    if probe is not None and probe.safety_state not in {"ok", "ready", ""}:
        return ActivationRisk.CRITICAL
    if probe is not None and probe.requires_admin:
        return ActivationRisk.HIGH
    if _is_cross_internet(score):
        return ActivationRisk.MEDIUM
    if score.privacy in {"same_machine", "direct_local", "proximity"}:
        return ActivationRisk.LOW
    if score.privacy == "offline_physical":
        return ActivationRisk.MEDIUM
    if score.privacy == "experimental_hardware":
        return ActivationRisk.HIGH
    return ActivationRisk.MEDIUM


def _is_cross_internet(score: RouteScore) -> bool:
    return score.route_name in {"relay", "webrtc"} or score.privacy == "direct_or_relayed_internet"


def _is_sensitive_route(score: RouteScore) -> bool:
    return _is_cross_internet(score) or score.route_name in {"onefield", "courier"}


def _state_rank(state: ActivationState) -> int:
    return {
        ActivationState.ACTIVE: 0,
        ActivationState.READY: 1,
        ActivationState.ASK_USER: 2,
        ActivationState.UNAVAILABLE: 3,
        ActivationState.BLOCKED: 4,
    }[state]


def _risk_rank(risk: ActivationRisk) -> int:
    return {
        ActivationRisk.LOW: 0,
        ActivationRisk.MEDIUM: 1,
        ActivationRisk.HIGH: 2,
        ActivationRisk.CRITICAL: 3,
    }[risk]


def _truthy_attr(obj: object | None, name: str) -> bool:
    if obj is None:
        return False
    return bool(getattr(obj, name, False))


def _trust_is_pinned(obj: object | None) -> bool:
    if obj is None:
        return False
    return str(getattr(obj, "trust", "") or "").lower() in {"pinned", "trusted", "verified"}
