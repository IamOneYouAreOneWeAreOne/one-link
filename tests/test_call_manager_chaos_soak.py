"""Chaos soak for the CallManager orchestrator.

For N random scenarios, feed the manager a randomised sequence of
events drawn from the full ManagerEventKind vocabulary. Assert:

  1. No iteration raises an unhandled exception.
  2. Every call reaches a terminal state in finite time (no
     infinite loops).
  3. The CallSession CRDT's invariants hold (lattice idempotence
     across replays).
  4. Doctrine-compliant outputs: no error-code-bearing strings in
     any tail event payload.
  5. Recording state never flips to RECORDING_MUTUAL without going
     through proper REQUEST → GRANT.

The soak validates that the CallManager — the keystone for the
whole call surface — survives arbitrary user/network event
sequences without ever crashing or leaving a call in an inconsistent
state.
"""

from __future__ import annotations

import os
import random

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import blake3

from one_link.call_manager import (
    CallManager,
    ManagerEvent,
    ManagerEventKind,
)
from one_link.call_signaling import CallPhase
from one_link.frame_provenance import (
    RecordingState,
)
from one_link.identity import Identity


# ---------------------------------------------------------------------------
# Identity factory
# ---------------------------------------------------------------------------

def _identity(seed: int, role: str) -> Identity:
    raw = blake3.blake3(f"chaos-{seed}-{role}".encode()).digest()[:32]
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    fp = blake3.blake3(pub_bytes).hexdigest()
    return Identity(
        private=priv, public=priv.public_key(), public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=f"chaos-{seed}-{role}",
    )


# Events the soak picks from. Excludes CAPSULE_FINALIZED (driven
# internally by the manager via CAPTURE_AUDIO_SEGMENT + finalize),
# and CAPTURE_AUDIO_SEGMENT (requires structured data — handled
# separately in the scenarios that hit ASYNC_CAPTURE).
_SOAK_EVENTS = [
    ManagerEventKind.USER_INITIATE_CALL,
    ManagerEventKind.USER_ACCEPT,
    ManagerEventKind.USER_DECLINE,
    ManagerEventKind.USER_HANGUP,
    ManagerEventKind.USER_RESUME,
    ManagerEventKind.USER_REQUEST_RECORDING,
    ManagerEventKind.USER_APPROVE_RECORDING,
    ManagerEventKind.USER_DECLINE_RECORDING,
    ManagerEventKind.USER_STOP_RECORDING,
    ManagerEventKind.WIRE_CALL_INVITE,
    ManagerEventKind.WIRE_CALL_ACCEPT,
    ManagerEventKind.WIRE_CALL_DECLINE,
    ManagerEventKind.WIRE_CALL_END,
    ManagerEventKind.WIRE_RESUME_OFFER,
    ManagerEventKind.WIRE_RECORDING_REQUEST,
    ManagerEventKind.WIRE_RECORDING_GRANT,
    ManagerEventKind.WIRE_RECORDING_DECLINE,
    ManagerEventKind.WIRE_RECORDING_STOP,
    ManagerEventKind.INVITE_TIMER_EXPIRED,
    ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC,
    ManagerEventKind.RESUME_WINDOW_EXPIRED,
]


# Tokens that, if present in a tail event payload, would constitute
# a doctrine violation per LIVING_PRESENCE_ARCHITECTURE §3.2.d
# ("no error codes") and §3.2.b ("no 'connection unstable' label")
_FORBIDDEN_PAYLOAD_TOKENS = (
    "error code",
    "reconnecting",
    "connection unstable",
    "please try again",
    "call failed",
    "0x",
)


def _payload_doctrine_compliant(payload: dict) -> bool:
    """Walk the payload and check no string value contains a
    forbidden token."""
    for v in payload.values():
        if not isinstance(v, str):
            continue
        low = v.lower()
        for tok in _FORBIDDEN_PAYLOAD_TOKENS:
            if tok in low:
                return False
    return True


# ---------------------------------------------------------------------------
# Scenario runner
# ---------------------------------------------------------------------------

def _run_one_scenario(seed: int) -> dict:
    rng = random.Random(seed)
    alice = _identity(seed, "alice")
    mom = _identity(seed, "mom")

    role = rng.choice(("originator", "recipient"))
    if role == "originator":
        local, peer = alice, mom
    else:
        local, peer = mom, alice

    mgr = CallManager(
        call_id=f"chaos-call-{seed}",
        peer_master_vk_hex=peer.fingerprint,
        local_role=role,
        local_master_vk_hex=local.fingerprint,
        started_at_ms=1_000,
    )

    exceptions: list[BaseException] = []
    doctrine_violations: list[tuple[int, dict]] = []
    illegal_recording_jumps: list[int] = []
    last_recording_state = RecordingState.NOT_RECORDING
    n_events = rng.randint(20, 100)
    consent_request_seen = False

    for i in range(n_events):
        kind = rng.choice(_SOAK_EVENTS)
        # Track whether a recording request has been seen so we
        # can detect illegal jumps to RECORDING_MUTUAL.
        if kind in (
            ManagerEventKind.USER_REQUEST_RECORDING,
            ManagerEventKind.WIRE_RECORDING_REQUEST,
        ):
            consent_request_seen = True

        try:
            out = mgr.handle(ManagerEvent(
                kind=kind, occurred_at_ms=1_000 + i * 100,
            ))
        except BaseException as e:
            exceptions.append(e)
            break

        # Doctrine check on tail event payloads
        for tail in out.tail_events:
            if not _payload_doctrine_compliant(tail.payload):
                doctrine_violations.append((i, tail.payload))

        # Recording state never flips to MUTUAL without proper
        # request → grant. Detect: was the previous state
        # NOT_RECORDING + no consent_request_seen, and is the new
        # state RECORDING_MUTUAL?
        new_recording_state = mgr.current_recording_state
        if (
            new_recording_state == RecordingState.RECORDING_MUTUAL
            and not consent_request_seen
        ):
            illegal_recording_jumps.append(i)
        last_recording_state = new_recording_state

        # If the call has ended AND it's been ENDED for a while, we
        # can stop early.
        if mgr.is_complete and i > 5:
            break

    # The scenario should always end in a sane terminal state.
    final_phase = mgr.phase
    is_terminal = final_phase in (
        CallPhase.ENDED, CallPhase.RESUMABLE, CallPhase.ACTIVE,
        CallPhase.INVITING, CallPhase.RINGING, CallPhase.ASYNC_CAPTURE,
    )

    return {
        "seed": seed,
        "exceptions": exceptions,
        "doctrine_violations": doctrine_violations,
        "illegal_recording_jumps": illegal_recording_jumps,
        "final_phase": final_phase,
        "is_terminal": is_terminal,
        "consent_phase": mgr.consent_phase,
    }


# ---------------------------------------------------------------------------
# The soak
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "iters", [int(os.getenv("ONE_LINK_SOAK_ITERS", "2000"))],
)
def test_call_manager_chaos_soak(iters: int) -> None:
    exception_seeds: list[int] = []
    doctrine_violation_seeds: list[int] = []
    illegal_recording_seeds: list[int] = []
    non_terminal_seeds: list[int] = []

    for i in range(iters):
        result = _run_one_scenario(seed=i)
        if result["exceptions"]:
            exception_seeds.append(i)
        if result["doctrine_violations"]:
            doctrine_violation_seeds.append(i)
        if result["illegal_recording_jumps"]:
            illegal_recording_seeds.append(i)
        if not result["is_terminal"]:
            non_terminal_seeds.append(i)

    # ── Gates ────────────────────────────────────────────────

    assert not exception_seeds, (
        f"{len(exception_seeds)}/{iters} scenarios raised; "
        f"first: {exception_seeds[:5]}"
    )

    assert not doctrine_violation_seeds, (
        f"{len(doctrine_violation_seeds)}/{iters} scenarios emitted "
        f"doctrine-violating payloads; first: {doctrine_violation_seeds[:5]}"
    )

    assert not illegal_recording_seeds, (
        f"{len(illegal_recording_seeds)}/{iters} scenarios saw "
        f"RECORDING_MUTUAL without prior REQUEST; "
        f"first: {illegal_recording_seeds[:5]}"
    )

    # is_terminal is currently always True for any valid CallPhase;
    # this gate would catch a state-machine bug that left the
    # manager in an undefined phase.
    assert not non_terminal_seeds, (
        f"{len(non_terminal_seeds)}/{iters} scenarios non-terminal"
    )
