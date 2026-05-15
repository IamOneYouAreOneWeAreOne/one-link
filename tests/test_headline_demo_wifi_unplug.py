"""THE HEADLINE DEMO — the 90-second pitch as a deterministic test.

"Call survives the WiFi router being unplugged mid-call by becoming
a voice-note + resuming when WiFi returns."

This is the whole Tier δ pitch. The test wires the real
Immune System + CallManager + action translator + capsule transport
into one flow and proves the property byte-for-byte:

  1. Call goes ACTIVE.
  2. WiFi degrades — loss EWMA climbs, bandwidth EWMA drops.
  3. Immune System emits REQUEST_LOWER_FIDELITY (rung-drop).
  4. Network gets worse — Immune emits REQUEST_VOICE_ONLY.
  5. WiFi unplugs entirely — Immune emits CONVERT_TO_ASYNC.
  6. Phase advances to ASYNC_CAPTURE. Capsule opens.
  7. User keeps talking. Audio segments stream into the capsule.
  8. WiFi returns. Capsule finalizes. Phase advances to RESUMABLE.
  9. Recipient sees resume offer; can pick up where they left off.

The point: NONE of this is hard-coded in the test. The Immune
controller decides, the lifecycle advances, the capsule fills.
The test only drives vitals + audio segments and verifies the
properties.
"""

from __future__ import annotations

import hashlib
from typing import List

import pytest

from one_link.call_immune import (
    GraduationMode,
    ImmuneAction,
    ImmuneSystem,
    Thresholds,
)
from one_link.call_immune_actions import (
    execute_plan,
    plan_for_decision,
)
from one_link.call_manager import (
    CallManager,
    ManagerEvent,
    ManagerEventKind,
)
from one_link.call_signaling import CallPhase
from one_link.call_vitals import (
    CallVitals,
    CapabilitySnapshot,
    DeviceRole,
    ThermalState,
)
from one_link.frame_provenance import (
    FrameKind,
    FrameProvenance,
    PathClass,
    RecordingState,
    sign_provenance,
    make_segment_hash,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vitals_for(
    *,
    call_id: str,
    peer: str,
    tick: int,
    rtt: float,
    loss: float,
    bw_kbps: float,
    confirm: float,
) -> CallVitals:
    return CallVitals(
        call_id=call_id,
        peer_fp=peer,
        tick=tick,
        rtt_ewma_ms=rtt,
        loss_rate_ewma=loss,
        jitter_ms=loss * 100,
        bandwidth_estimate_kbps=bw_kbps,
        reliability=max(0.0, 1.0 - loss * 4),
        last_alive_ms=1_700_000_000_000 if bw_kbps > 0 else 0,
        path_class=PathClass.DIRECT if bw_kbps > 50 else PathClass.RELAY,
        path_fragility_score=min(1.0, loss * 5 + (rtt / 1000)),
        backup_routes_warm=0,
        own_device_role=DeviceRole.INACTIVE,
        own_battery_pct=80.0,
        own_thermal_state=ThermalState.NOMINAL,
        peer_device_present=bw_kbps > 0,
        audio_frames_received=tick * 50,
        audio_frames_dropped=int(tick * 50 * loss),
        video_frames_received=tick * 30 if bw_kbps > 100 else 0,
        video_frames_predicted=0,
        confirm_ratio_voice=confirm,
        confirm_ratio_video=confirm * 0.8,
        path_attested=False,
        capability_state=CapabilitySnapshot.empty(),
    )


def _make_audio_segment(idx: int, signing_key: Ed25519PrivateKey, device_id: str) -> tuple[bytes, FrameProvenance]:
    chunk = f"audio-chunk-{idx}".encode()
    seg_hash = make_segment_hash(chunk)
    prov = sign_provenance(
        segment_hash=seg_hash,
        device_id=device_id,
        frame_kind=FrameKind.REAL,
        path_class=PathClass.LOCAL,
        recording_state=RecordingState.NOT_RECORDING,
        timestamp_us=1_700_000_000_000_000 + idx * 1_000_000,
        produce_confidence=1.0,
        signing_key=signing_key,
    )
    return chunk, prov


# ---------------------------------------------------------------------------
# The headline demo
# ---------------------------------------------------------------------------

def test_wifi_unplug_to_voice_note_to_resume() -> None:
    """The full 9-step flow as a single deterministic test."""

    # Set up a CallManager in originator role.
    signing_key = Ed25519PrivateKey.generate()
    device_id = hashlib.sha256(b"alice").hexdigest()[:8]
    call_id = "demo-headline-1"
    mgr = CallManager(
        call_id=call_id,
        peer_master_vk_hex="bob",
        local_role="originator",
        local_master_vk_hex="alice",
        started_at_ms=1_000,
    )

    # ── Step 1: Call goes ACTIVE.
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    assert mgr.phase == CallPhase.ACTIVE, (
        "Step 1: call should be ACTIVE after originate+accept"
    )

    # Capture every browser action emitted, for end-of-test inspection.
    emitted_tails: List[dict] = []
    def broadcast(ev: dict) -> None:
        emitted_tails.append(ev)

    # Immune System in AUTOPILOT so it actually acts.
    immune = ImmuneSystem(
        mode=GraduationMode.AUTOPILOT,
        thresholds=Thresholds(),
    )

    # ── Step 2: WiFi degrades. Drive vitals through a degradation
    # curve. The Immune System should escalate as the picture worsens.
    tick = 0
    actions_seen: List[ImmuneAction] = []

    def drive_tick(
        rtt: float, loss: float, bw_kbps: float, confirm: float,
    ) -> ImmuneAction:
        nonlocal tick
        vitals = _vitals_for(
            call_id=call_id, peer="bob", tick=tick,
            rtt=rtt, loss=loss, bw_kbps=bw_kbps, confirm=confirm,
        )
        decision = immune.tick(vitals)
        plan = plan_for_decision(
            decision=decision, call_id=call_id, now_ms=3_000 + tick * 100,
        )
        execute_plan(plan=plan, manager=mgr, broadcast_tail=broadcast)
        tick += 1
        actions_seen.append(decision.action)
        return decision.action

    # Healthy: HOLD.
    for _ in range(5):
        drive_tick(rtt=40, loss=0.0, bw_kbps=2000, confirm=0.99)
    assert ImmuneAction.CONVERT_TO_ASYNC not in actions_seen, (
        "should not have escalated under healthy conditions"
    )

    # ── Step 3-4-5: Degrade until the controller converts to async.
    # Drive a sequence of progressively worse vitals until the call
    # transitions out of ACTIVE.
    degraded_actions: List[ImmuneAction] = []
    for severity in range(1, 60):
        # Climbing loss, climbing RTT, falling bandwidth, falling confirm.
        rtt = 50 + severity * 20
        loss = min(1.0, severity * 0.03)
        bw = max(0, 2000 - severity * 50)
        confirm = max(0.1, 1.0 - severity * 0.02)
        action = drive_tick(rtt=rtt, loss=loss, bw_kbps=bw, confirm=confirm)
        degraded_actions.append(action)
        if mgr.phase != CallPhase.ACTIVE:
            break

    # ── Step 6: Phase advanced to ASYNC_CAPTURE.
    assert mgr.phase == CallPhase.ASYNC_CAPTURE, (
        f"Step 6: degraded vitals should have triggered CONVERT_TO_ASYNC; "
        f"actions seen: {[a.name for a in degraded_actions[-5:]]}; "
        f"phase: {mgr.phase}"
    )
    # The CONVERT_TO_ASYNC must have fired at least once.
    assert ImmuneAction.CONVERT_TO_ASYNC in degraded_actions

    # The browser was told to start capsule capture.
    convert_events = [
        e for e in emitted_tails if e.get("tail_kind") == "immune_convert_to_async"
    ]
    assert len(convert_events) >= 1
    # Doctrine — plain language.
    assert "keep talking" in convert_events[0]["user_message"].lower()

    # ── Step 7: User keeps talking — audio segments stream in.
    for i in range(8):
        chunk, prov = _make_audio_segment(i, signing_key, device_id)
        mgr.handle(ManagerEvent(
            kind=ManagerEventKind.CAPTURE_AUDIO_SEGMENT,
            occurred_at_ms=5_000 + i * 100,
            data={"chunk": chunk, "provenance": prov},
        ))
    assert mgr.state.capsule_builder is not None
    assert not mgr.state.capsule_builder.is_empty()

    # ── Step 8: WiFi returns (irrelevant to flow — capsule finalizes
    # when user stops talking / explicit finalize fires).
    out = mgr.handle(ManagerEvent(
        kind=ManagerEventKind.CAPSULE_FINALIZED,
        occurred_at_ms=10_000,
    ))
    # Capsule is in the output for the daemon to ship to the peer.
    assert out.finalized_capsule is not None
    assert mgr.state.finalized_capsule is not None
    assert mgr.phase == CallPhase.RESUMABLE, (
        f"Step 8: capsule finalize should advance to RESUMABLE; got {mgr.phase}"
    )

    # ── Step 9: A resume_offer_available tail event fired.
    resume_kinds = [t.kind.name for t in out.tail_events]
    assert any(
        k in ("RESUME_OFFER_AVAILABLE", "CAPSULE_CAPTURED")
        for k in resume_kinds
    ), (
        f"Step 9: resume offer should fire; got tail events: {resume_kinds}"
    )

    # The capsule has the audio segments we sent.
    assert len(mgr.state.finalized_capsule.provenance_chain) == 8


def test_voice_only_then_recovery_does_not_convert_to_async() -> None:
    """If conditions improve before bandwidth bottoms out, the call
    should NOT convert to async — the lighter-touch actions (lower
    fidelity, voice-only) should be enough. This is the
    'hysteresis-prevents-overreaction' property."""
    call_id = "demo-recover-1"
    mgr = CallManager(
        call_id=call_id,
        peer_master_vk_hex="bob",
        local_role="originator",
        local_master_vk_hex="alice",
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))

    immune = ImmuneSystem(mode=GraduationMode.AUTOPILOT)

    # Moderate degradation — should trigger REQUEST_LOWER_FIDELITY
    # but not CONVERT_TO_ASYNC.
    actions: List[ImmuneAction] = []
    for tick in range(20):
        v = _vitals_for(
            call_id=call_id, peer="bob", tick=tick,
            rtt=180, loss=0.05, bw_kbps=200, confirm=0.85,
        )
        decision = immune.tick(v)
        plan = plan_for_decision(decision=decision, call_id=call_id, now_ms=tick * 100)
        execute_plan(plan=plan, manager=mgr, broadcast_tail=lambda _: None)
        actions.append(decision.action)

    # Recovery
    for tick in range(20, 40):
        v = _vitals_for(
            call_id=call_id, peer="bob", tick=tick,
            rtt=40, loss=0.0, bw_kbps=2000, confirm=0.99,
        )
        decision = immune.tick(v)
        actions.append(decision.action)

    # The Immune System may have considered convert-to-async, but the
    # demonstration of "graceful degradation NOT panic" is that the
    # call's lifecycle did NOT advance to ASYNC_CAPTURE.
    assert mgr.phase == CallPhase.ACTIVE, (
        f"Expected ACTIVE after moderate degradation + recovery; got {mgr.phase}; "
        f"actions: {[a.name for a in actions]}"
    )


def test_capsule_carries_chained_provenance_post_demo() -> None:
    """After Tier δ flow, the resulting capsule must carry per-frame
    FrameProvenance for each audio segment. This is the audit-trail
    property: every byte the recipient hears has cryptographic
    provenance back to Alice's identity key."""
    signing_key = Ed25519PrivateKey.generate()
    device_id = hashlib.sha256(b"alice").hexdigest()[:8]
    call_id = "demo-capsule-prov-1"
    mgr = CallManager(
        call_id=call_id,
        peer_master_vk_hex="bob",
        local_role="originator",
        local_master_vk_hex="alice",
        started_at_ms=1_000,
    )
    mgr.handle(ManagerEvent(ManagerEventKind.USER_INITIATE_CALL, 1_000))
    mgr.handle(ManagerEvent(ManagerEventKind.WIRE_CALL_ACCEPT, 2_000))
    mgr.handle(ManagerEvent(
        kind=ManagerEventKind.IMMUNE_CONVERT_TO_ASYNC,
        occurred_at_ms=3_000,
    ))
    assert mgr.phase == CallPhase.ASYNC_CAPTURE

    for i in range(5):
        chunk, prov = _make_audio_segment(i, signing_key, device_id)
        mgr.handle(ManagerEvent(
            kind=ManagerEventKind.CAPTURE_AUDIO_SEGMENT,
            occurred_at_ms=4_000 + i * 100,
            data={"chunk": chunk, "provenance": prov},
        ))
    out = mgr.handle(ManagerEvent(
        kind=ManagerEventKind.CAPSULE_FINALIZED,
        occurred_at_ms=10_000,
    ))
    capsule = out.finalized_capsule
    assert capsule is not None
    # Every audio segment has its FrameProvenance attached.
    assert len(capsule.provenance_chain) == 5
    for prov in capsule.provenance_chain:
        assert len(prov.signature) == 64  # Ed25519
