from __future__ import annotations

from one_link.device_guardian import (
    PROOF_ALREADY_FROZEN,
    PROOF_RECENT_UNLOCK,
    PROOF_RECOVERY_SECRET,
    decide_device_safety_transition,
    safety_blocks_remote_instruction,
    safety_blocks_routing,
)


def test_guardian_freeze_is_fast_reversible_protection():
    decision = decide_device_safety_transition(
        "trusted",
        "frozen",
        proofs=[PROOF_RECENT_UNLOCK],
        actor_is_local=False,
    )

    assert decision.allowed
    assert decision.target_state == "frozen"
    assert decision.reversible is True
    assert "exclude_from_routing" in decision.effects
    assert safety_blocks_routing("frozen")
    assert safety_blocks_remote_instruction("frozen")


def test_guardian_hard_revoke_requires_strong_proof_or_frozen_path():
    denied = decide_device_safety_transition("trusted", "revoked", proofs=[])
    assert denied.allowed is False
    assert denied.cooldown_ms > 0
    assert "offer_freeze_first" in denied.effects

    strong = decide_device_safety_transition(
        "trusted",
        "revoked",
        proofs=[PROOF_RECOVERY_SECRET],
    )
    assert strong.allowed
    assert strong.reversible is False

    frozen = decide_device_safety_transition(
        "frozen",
        "revoked",
        proofs=[PROOF_ALREADY_FROZEN],
    )
    assert frozen.allowed


def test_guardian_revoked_device_cannot_silently_return():
    decision = decide_device_safety_transition(
        "revoked",
        "trusted",
        proofs=[PROOF_RECOVERY_SECRET],
    )

    assert decision.allowed is False
    assert decision.target_state == "revoked"
    assert decision.required_proofs == ("re_enroll",)
