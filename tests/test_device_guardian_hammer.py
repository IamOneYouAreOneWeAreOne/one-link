from __future__ import annotations

import itertools
import random

from one_link.device_guardian import (
    PROOF_ALREADY_FROZEN,
    PROOF_HARDWARE_KEY,
    PROOF_QUORUM,
    PROOF_RECENT_UNLOCK,
    PROOF_RECOVERY_SECRET,
    PROOF_SUSPICIOUS_BEHAVIOR,
    SAFETY_STATES,
    decide_device_safety_transition,
    event_hash,
    safety_blocks_remote_instruction,
    safety_blocks_routing,
)
from one_link.state import State


ALL_PROOFS = (
    PROOF_RECENT_UNLOCK,
    PROOF_RECOVERY_SECRET,
    PROOF_QUORUM,
    PROOF_HARDWARE_KEY,
    PROOF_ALREADY_FROZEN,
    PROOF_SUSPICIOUS_BEHAVIOR,
)
BLOCKING_STATES = {"maybe_lost", "frozen", "revoked", "quarantined"}


def _proof_sets() -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = [()]
    for size in range(1, len(ALL_PROOFS) + 1):
        out.extend(itertools.combinations(ALL_PROOFS, size))
    return out


def test_guardian_transition_matrix_is_total_and_safety_invariants_hold():
    for current in sorted(SAFETY_STATES):
        for requested in sorted(SAFETY_STATES):
            for proofs in _proof_sets():
                for actor_is_local in (True, False):
                    for active_suspicion in (True, False):
                        decision = decide_device_safety_transition(
                            current,
                            requested,
                            proofs=proofs,
                            actor_is_local=actor_is_local,
                            active_suspicion=active_suspicion,
                            now=1_777_000_000_000,
                        )
                        assert decision.target_state in SAFETY_STATES
                        assert decision.event
                        assert decision.detail
                        if current == "revoked" and requested != "revoked":
                            assert decision.allowed is False
                            assert decision.target_state == "revoked"
                        if requested == "revoked" and current != "revoked" and decision.allowed:
                            assert decision.reversible is False
                        if (
                            current != requested
                            and requested == "frozen"
                            and not actor_is_local
                            and PROOF_RECENT_UNLOCK not in proofs
                        ):
                            assert decision.allowed is False


def test_guardian_route_and_remote_blocks_match_policy_states():
    for state in SAFETY_STATES:
        assert safety_blocks_routing(state) is (state in BLOCKING_STATES)
        assert safety_blocks_remote_instruction(state) is (state in BLOCKING_STATES)


def test_guardian_event_hash_chain_detects_reordering_and_tamper():
    previous = ""
    chain: list[str] = []
    events = [
        {"ts_ms": i, "device_pub": "d" * 64, "to_state": state}
        for i, state in enumerate(("trusted", "frozen", "trusted", "revoked"))
    ]
    for event in events:
        digest = event_hash(event, previous)
        assert len(digest) == 64
        chain.append(digest)
        previous = digest

    tampered = dict(events[2])
    tampered["to_state"] = "frozen"
    assert event_hash(tampered, chain[1]) != chain[2]
    assert event_hash(events[2], chain[0]) != chain[2]


def test_guardian_state_hammer_preserves_hash_chain_and_blocking_truth(tmp_path):
    rng = random.Random(0x0E11_1EAD)
    db = tmp_path / "guardian-hammer.db"
    root_pub = b"r" * 32
    actor_pub = b"a" * 32
    devices = [bytes([65 + i]) * 32 for i in range(6)]
    state = State(db_path=db)
    try:
        for i, device_pub in enumerate(devices):
            state.upsert_self_mesh_device(
                root_pub=root_pub,
                device_pub=device_pub,
                device_kind="phone" if i % 2 else "laptop",
                label=f"Device {i}",
                trusted=True,
            )
        for step in range(300):
            device_pub = rng.choice(devices)
            requested = rng.choice(tuple(sorted(SAFETY_STATES)))
            proofs = [
                proof for proof in ALL_PROOFS
                if rng.random() < 0.35
            ]
            result = state.set_self_mesh_device_safety(
                root_pub=root_pub,
                device_pub=device_pub,
                requested_state=requested,
                actor_device_pub=actor_pub,
                proofs=proofs,
                reason=f"hammer step {step}",
                actor_is_local=bool(rng.getrandbits(1)),
                active_suspicion=bool(rng.getrandbits(1)),
                ts_ms=20_000 + step,
            )
            row = result["device"]
            if row["safety_state"] in BLOCKING_STATES:
                assert row["trusted"] is False
            if row["safety_state"] == "revoked":
                assert row["revoked"] is True

        for device_pub in devices:
            events = list(reversed(state.list_device_guardian_events(
                root_pub=root_pub,
                device_pub=device_pub,
                limit=400,
            )))
            previous = ""
            for event in events:
                assert event["prev_hash"] == previous
                previous = event["event_hash"]
    finally:
        state.close()
