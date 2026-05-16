"""Device Guardian policy for lost, stolen, and abused-device safety.

Guardian is deliberately two-speed: fast reversible protection, slow
destructive revocation. A single device may freeze another device quickly,
but hard revoke needs stronger proof unless the device is already frozen.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

SAFETY_STATES = frozenset({
    "trusted",
    "suspicious",
    "maybe_lost",
    "frozen",
    "revoked",
    "recovered",
    "quarantined",
})
PROTECTIVE_STATES = frozenset({"suspicious", "maybe_lost", "frozen", "quarantined"})
REMOTE_BLOCK_STATES = frozenset({"maybe_lost", "frozen", "revoked", "quarantined"})
ROUTE_BLOCK_STATES = frozenset({"maybe_lost", "frozen", "revoked", "quarantined"})
DESTRUCTIVE_STATES = frozenset({"revoked"})

PROOF_RECENT_UNLOCK = "recent_unlock"
PROOF_RECOVERY_SECRET = "recovery_secret"
PROOF_QUORUM = "quorum"
PROOF_HARDWARE_KEY = "hardware_key"
PROOF_ALREADY_FROZEN = "already_frozen"
PROOF_SUSPICIOUS_BEHAVIOR = "suspicious_behavior"
STRONG_PROOFS = frozenset({
    PROOF_RECOVERY_SECRET,
    PROOF_QUORUM,
    PROOF_HARDWARE_KEY,
})
REVERSIBLE_TRANSITIONS = {
    "trusted": {"suspicious", "maybe_lost", "frozen", "quarantined", "revoked"},
    "suspicious": {"trusted", "maybe_lost", "frozen", "quarantined", "revoked"},
    "maybe_lost": {"trusted", "frozen", "recovered", "quarantined", "revoked"},
    "frozen": {"recovered", "revoked", "trusted"},
    "recovered": {"trusted", "suspicious", "maybe_lost", "frozen", "revoked"},
    "quarantined": {"trusted", "frozen", "revoked", "recovered"},
    "revoked": set(),
}


def now_ms() -> int:
    return int(time.time() * 1000)


def canonical_policy_json(obj: Mapping[str, Any]) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def event_hash(event: Mapping[str, Any], previous_hash: str = "") -> str:
    h = hashlib.sha256()
    h.update(b"OL/device-guardian/event/v1|")
    h.update(str(previous_hash or "").encode("ascii", "ignore"))
    h.update(b"|")
    h.update(canonical_policy_json(event))
    return h.hexdigest()


@dataclass(frozen=True)
class GuardianDecision:
    allowed: bool
    target_state: str
    severity: str
    event: str
    detail: str
    required_proofs: tuple[str, ...] = field(default_factory=tuple)
    effects: tuple[str, ...] = field(default_factory=tuple)
    reversible: bool = True
    cooldown_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target_state": self.target_state,
            "severity": self.severity,
            "event": self.event,
            "detail": self.detail,
            "required_proofs": list(self.required_proofs),
            "effects": list(self.effects),
            "reversible": self.reversible,
            "cooldown_ms": self.cooldown_ms,
        }


def normalize_safety_state(state: str | None) -> str:
    value = str(state or "trusted").strip().lower().replace("-", "_")
    if value not in SAFETY_STATES:
        raise ValueError(f"unsupported device safety state {state!r}")
    return value


def normalize_proofs(proofs: Any) -> frozenset[str]:
    if proofs is None:
        return frozenset()
    if isinstance(proofs, str):
        raw = [proofs]
    else:
        raw = list(proofs)
    return frozenset(str(p or "").strip().lower() for p in raw if str(p or "").strip())


def decide_device_safety_transition(
    current_state: str | None,
    requested_state: str,
    *,
    proofs: Any = None,
    actor_is_local: bool = True,
    active_suspicion: bool = False,
    now: int | None = None,
) -> GuardianDecision:
    """Authorize a device safety-state transition.

    Freeze/maybe-lost are deliberately quick and reversible. Revocation is
    destructive, so it requires a strong proof unless the device is already
    frozen/quarantined or an explicit suspicious-behavior proof is present.
    """
    _ = now if now is not None else now_ms()
    current = normalize_safety_state(current_state)
    requested = normalize_safety_state(requested_state)
    given = normalize_proofs(proofs)

    if current == "revoked" and requested != "revoked":
        return GuardianDecision(
            False,
            current,
            "bad",
            "guardian_transition_denied",
            "revoked devices must be re-enrolled instead of silently restored",
            required_proofs=("re_enroll",),
            effects=("no_state_change",),
            reversible=False,
        )
    if requested == current:
        return GuardianDecision(
            True,
            requested,
            "info",
            "guardian_state_unchanged",
            f"device already {requested}",
            effects=("audit_only",),
            reversible=requested not in DESTRUCTIVE_STATES,
        )
    if requested not in REVERSIBLE_TRANSITIONS.get(current, set()):
        return GuardianDecision(
            False,
            current,
            "bad",
            "guardian_transition_denied",
            f"transition {current}->{requested} is not allowed",
            effects=("no_state_change",),
            reversible=current not in DESTRUCTIVE_STATES,
        )

    if requested in {"suspicious", "maybe_lost"}:
        return GuardianDecision(
            True,
            requested,
            "warn",
            f"guardian_{requested}",
            "soft protection enabled; sensitive actions now require extra trust",
            effects=(
                "remote_sensitive_actions_limited",
                "audit_visible",
                "reversible",
            ),
        )

    if requested == "frozen":
        if not actor_is_local and PROOF_RECENT_UNLOCK not in given:
            return GuardianDecision(
                False,
                current,
                "bad",
                "guardian_transition_denied",
                "remote freeze requires recent local unlock proof",
                required_proofs=(PROOF_RECENT_UNLOCK,),
                effects=("no_state_change",),
            )
        return GuardianDecision(
            True,
            requested,
            "bad",
            "guardian_frozen",
            "device frozen; it cannot route, sync, pull files, or run remote commands",
            effects=(
                "exclude_from_routing",
                "block_remote_instruct",
                "block_future_epoch_keys",
                "audit_visible",
                "reversible",
            ),
        )

    if requested == "revoked":
        strong = bool(given & STRONG_PROOFS)
        frozen_path = current in {"frozen", "quarantined"} and PROOF_ALREADY_FROZEN in given
        suspicion_path = active_suspicion and PROOF_SUSPICIOUS_BEHAVIOR in given
        if not (strong or frozen_path or suspicion_path):
            return GuardianDecision(
                False,
                current,
                "bad",
                "guardian_revoke_pending",
                "hard revoke needs recovery, quorum, hardware-key, or already-frozen proof",
                required_proofs=tuple(sorted(STRONG_PROOFS | {PROOF_ALREADY_FROZEN})),
                effects=("no_state_change", "offer_freeze_first"),
                reversible=False,
                cooldown_ms=2 * 60 * 60 * 1000,
            )
        return GuardianDecision(
            True,
            requested,
            "bad",
            "guardian_revoked",
            "device permanently removed from trust; re-enrollment is required to return",
            effects=(
                "exclude_from_routing",
                "block_remote_instruct",
                "block_future_epoch_keys",
                "require_reenrollment",
                "audit_visible",
            ),
            reversible=False,
        )

    if requested == "recovered":
        return GuardianDecision(
            True,
            requested,
            "good",
            "guardian_recovered",
            "device marked recovered; re-proof before returning to full trust",
            effects=("remote_sensitive_actions_limited", "audit_visible"),
        )

    if requested == "trusted":
        if current in {"frozen", "quarantined", "maybe_lost"} and not (
            given & {PROOF_RECENT_UNLOCK, PROOF_RECOVERY_SECRET, PROOF_HARDWARE_KEY}
        ):
            return GuardianDecision(
                False,
                current,
                "warn",
                "guardian_recovery_pending",
                "restoring trust requires recent unlock, recovery, or hardware-key proof",
                required_proofs=(PROOF_RECENT_UNLOCK, PROOF_RECOVERY_SECRET, PROOF_HARDWARE_KEY),
                effects=("no_state_change",),
            )
        return GuardianDecision(
            True,
            requested,
            "good",
            "guardian_trusted",
            "device returned to trusted state",
            effects=("routing_allowed", "remote_instruct_allowed", "audit_visible"),
        )

    if requested == "quarantined":
        return GuardianDecision(
            True,
            requested,
            "bad",
            "guardian_quarantined",
            "device quarantined after suspicious behavior",
            effects=("exclude_from_routing", "block_remote_instruct", "audit_visible"),
        )

    raise ValueError(f"unhandled guardian transition {current}->{requested}")


def safety_blocks_routing(state: str | None) -> bool:
    return normalize_safety_state(state) in ROUTE_BLOCK_STATES


def safety_blocks_remote_instruction(state: str | None) -> bool:
    return normalize_safety_state(state) in REMOTE_BLOCK_STATES


def safety_score_penalty(state: str | None) -> float:
    value = normalize_safety_state(state)
    if value in {"suspicious", "recovered"}:
        return 80.0
    return 0.0
