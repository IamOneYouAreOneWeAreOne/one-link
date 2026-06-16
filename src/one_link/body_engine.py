"""Multi-Device Body Engine — surface role arbitration.

The user is one entity; their devices are organs that present them.
The Body Engine reads the set of devices each participant has
active in a call and decides which device plays which surface role
(mic, cam, display, speaker, relay).

Each device publishes its own :class:`DeviceCapability` snapshot to
the :class:`CallSession` (via the OR-set + LWW machinery already in
call_session.py). All devices in the participant's mesh see the
merged view. They each independently compute the role assignment
from the merged view. Because the scoring algorithm is pure and the
tiebreak is deterministic, all devices arrive at the same answer
without a synchronous round-trip.

When the answer changes (e.g., phone goes hot, laptop should take
mic), the device that holds the role and the device taking it over
both publish a :class:`SurfaceHandoff` event. The 200 ms crossfade
window during which both devices emit RTP is a real-media concern
handled downstream; this module emits the *protocol* event.

Two load-bearing invariants:

  1. Pure scoring + deterministic tiebreak.

     ``score_role(device, role) -> float`` depends only on the
     device's published capabilities + role. Two devices computing
     against the same merged view get the same scores. Ties are
     broken by lexicographic ``device_id``, so the winner is
     identical on both sides.

  2. Surface handoff is a CRDT write, not a synchronous protocol.

     When a device decides it should take a role, it writes its
     own device_id into the LWWRegister with timestamp = local
     monotonic clock. The CRDT merge settles which write wins.
     Crossfade windows execute on whichever device sees the merge
     resolve toward it.

Companion: docs/LIVING_PRESENCE_ARCHITECTURE.md §4.3
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from typing import Optional

from one_link.call_session import (
    LWWRegister,
    ParticipantState,
)
from one_link.call_vitals import DeviceRole, ThermalState
from one_link.frame_provenance import PathClass

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-device capability snapshot
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DeviceCapability:
    """What one device can do + how good it is at each role.

    Quality scores are in [0.0, 1.0]. Devices learn their quality
    over time from prior calls (e.g., the phone's mic might rate
    higher on quiet rooms, the laptop's on noisy ones). For Tier
    α-pre they default to hardware-class priors.
    """

    device_id: str                  # 8-hex-char from Identity.short_id-like
    has_mic: bool
    has_cam: bool
    has_display: bool
    has_speaker: bool
    can_relay: bool
    mic_quality: float = 0.0        # 0..1, 0 if no mic
    cam_quality: float = 0.0
    display_size_px_area: int = 0   # for "biggest screen wins display"
    speaker_quality: float = 0.0
    is_battery_powered: bool = True
    battery_pct: Optional[float] = None
    is_charging: Optional[bool] = None
    thermal_state: ThermalState = ThermalState.NOMINAL
    network_class: PathClass = PathClass.DIRECT
    alive_at_ms: int = 0            # monotonic timestamp from device


# ---------------------------------------------------------------------------
# Scoring weights — used by the per-role arbitration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScoringWeights:
    """Composite score weights for each role's arbitration.

    All weights sum to 1.0. Tuning these is a follow-up; defaults
    reflect the architecture doc's prescription
    (role-quality 0.40, thermal 0.20, battery 0.15, network 0.15,
    recency 0.10).
    """

    role_quality: float = 0.40
    thermal_penalty: float = 0.20
    battery_penalty: float = 0.15
    network_class_score: float = 0.15
    recency_score: float = 0.10


# ---------------------------------------------------------------------------
# Pure scoring functions
# ---------------------------------------------------------------------------

_THERMAL_PENALTY = {
    ThermalState.NOMINAL:  0.00,
    ThermalState.WARM:     0.20,
    ThermalState.HOT:      0.60,
    ThermalState.CRITICAL: 0.95,
}

# Higher = better network for a relay role; lower = preferred consumer device.
_NETWORK_SCORE = {
    PathClass.LOCAL:  0.50,
    PathClass.LAN:    1.00,
    PathClass.DIRECT: 0.85,
    PathClass.RELAY:  0.40,
    PathClass.ONION:  0.30,
    PathClass.MESH:   0.50,
}


def _role_quality(cap: DeviceCapability, role: DeviceRole) -> float:
    """Native quality of this device for this role. Returns 0.0
    if the device fundamentally cannot perform the role."""
    if role == DeviceRole.MIC:
        return cap.mic_quality if cap.has_mic else 0.0
    if role == DeviceRole.CAM:
        return cap.cam_quality if cap.has_cam else 0.0
    if role == DeviceRole.DISPLAY:
        if not cap.has_display:
            return 0.0
        # Normalise display area: a 1080p display = ~2M px area = 1.0.
        return min(1.0, cap.display_size_px_area / 2_073_600.0)
    if role == DeviceRole.SPEAKER:
        return cap.speaker_quality if cap.has_speaker else 0.0
    if role == DeviceRole.RELAY:
        return 1.0 if cap.can_relay else 0.0
    return 0.0


def _battery_factor(cap: DeviceCapability) -> float:
    """Higher = more reliable. Non-battery devices = 1.0; charging
    devices = 1.0; otherwise scaled by battery percentage."""
    if not cap.is_battery_powered:
        return 1.0
    if cap.is_charging is True:
        return 1.0
    if cap.battery_pct is None:
        return 0.5  # unknown — middling
    return max(0.0, min(1.0, cap.battery_pct / 100.0))


def _recency_factor(cap: DeviceCapability, now_ms: int) -> float:
    """1.0 if the device sent a heartbeat in the last 5 seconds,
    decaying linearly to 0.0 over 30 seconds of silence."""
    if cap.alive_at_ms <= 0:
        return 0.0
    age_ms = max(0, now_ms - cap.alive_at_ms)
    if age_ms <= 5_000:
        return 1.0
    if age_ms >= 30_000:
        return 0.0
    return 1.0 - (age_ms - 5_000) / 25_000.0


def score_device_for_role(
    cap: DeviceCapability,
    role: DeviceRole,
    *,
    now_ms: int,
    weights: Optional[ScoringWeights] = None,
) -> float:
    """Composite score in [0.0, 1.0]. Higher = better fit for this
    role. Pure function: deterministic given inputs."""
    w = weights or ScoringWeights()
    rq = _role_quality(cap, role)
    if rq == 0.0:
        # Fundamentally unable — short-circuit so a phone without
        # a camera can never be elected primary_cam regardless of
        # how cool / charged it is.
        return 0.0
    if cap.thermal_state == ThermalState.CRITICAL:
        # Device is at thermal cutoff — its OS will start denying
        # access to sensors any moment. Treat as unable so the
        # Body Engine never picks it; the handoff margin is bypassed
        # because the score is 0.
        return 0.0
    thermal = 1.0 - _THERMAL_PENALTY.get(cap.thermal_state, 0.0)
    battery = _battery_factor(cap)
    net = _NETWORK_SCORE.get(cap.network_class, 0.5)
    recency = _recency_factor(cap, now_ms=now_ms)
    return (
        w.role_quality * rq
        + w.thermal_penalty * thermal
        + w.battery_penalty * battery
        + w.network_class_score * net
        + w.recency_score * recency
    )


# ---------------------------------------------------------------------------
# Surface handoff event
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SurfaceHandoff:
    """Emitted when the Body Engine decides a role changes hands.

    Both the old device and the new device see this same event
    after CRDT merge. Each is responsible for its half of the 200ms
    crossfade (old fades out, new fades in). The receiver's jitter
    buffer picks the higher-confidence frame per output slot.
    """

    role: DeviceRole
    from_device_id: Optional[str]      # None = unassigned previously
    to_device_id: str
    crossfade_ms: int = 200
    reason_code: str = "score_better"
    decided_at_ms: int = 0


# ---------------------------------------------------------------------------
# The Body Engine
# ---------------------------------------------------------------------------

# The roles the Body Engine arbitrates. Order matters only for
# deterministic iteration in logs.
_ARBITRATED_ROLES: tuple[DeviceRole, ...] = (
    DeviceRole.MIC,
    DeviceRole.CAM,
    DeviceRole.DISPLAY,
    DeviceRole.SPEAKER,
    DeviceRole.RELAY,
)


class BodyEngine:
    """Per-participant role arbitrator.

    Holds no mutable state. The "state" of the system is the
    :class:`ParticipantState` itself — which is a CRDT that
    converges across devices. The Body Engine is a pure function
    over (devices, current_state) → (new_state, handoffs).
    """

    def __init__(
        self,
        *,
        weights: Optional[ScoringWeights] = None,
        # Minimum score margin required to force a handoff. Below
        # this margin the current holder stays — prevents flicker
        # between two near-equal devices.
        handoff_margin: float = 0.10,
    ) -> None:
        self._weights = weights or ScoringWeights()
        self._handoff_margin = float(handoff_margin)

    # ── Pure arbitration ──────────────────────────────────────

    def arbitrate(
        self,
        *,
        devices: dict[str, DeviceCapability],
        state: ParticipantState,
        now_ms: int,
    ) -> tuple[ParticipantState, list[SurfaceHandoff]]:
        """Compute the optimal role assignment given the devices
        currently active in this participant's mesh.

        Returns the updated :class:`ParticipantState` and the list
        of :class:`SurfaceHandoff` events to emit. Both are
        deterministic functions of the inputs.
        """
        handoffs: list[SurfaceHandoff] = []
        new_state = state

        for role in _ARBITRATED_ROLES:
            best_device, best_score = self._best_device_for_role(
                role=role, devices=devices, now_ms=now_ms,
            )
            if best_device is None:
                # No device can fill this role.
                continue
            current_register = self._register_for_role(new_state, role)
            current = current_register.value
            if current == best_device:
                continue
            # If a current holder exists, only switch if the new
            # winner beats them by at least the margin.
            if current is not None and current in devices:
                current_score = score_device_for_role(
                    devices[current], role,
                    now_ms=now_ms, weights=self._weights,
                )
                if best_score - current_score < self._handoff_margin:
                    continue
            # Commit the change.
            updated_register = current_register.with_value(
                best_device, timestamp_ms=now_ms, writer_id=best_device,
            )
            new_state = self._set_register(new_state, role, updated_register)
            handoffs.append(SurfaceHandoff(
                role=role,
                from_device_id=current,
                to_device_id=best_device,
                reason_code="score_better" if current else "initial_assignment",
                decided_at_ms=now_ms,
            ))

        return new_state, handoffs

    # ── Active-devices OR-set helpers ─────────────────────────

    @staticmethod
    def add_device(
        state: ParticipantState,
        *,
        device_id: str,
        add_token: str,
    ) -> ParticipantState:
        """Register a device as active in this participant's mesh.
        Idempotent given the same (device_id, add_token) pair."""
        return replace(
            state,
            active_devices=state.active_devices.add(device_id, add_token=add_token),
        )

    @staticmethod
    def remove_device(
        state: ParticipantState,
        *,
        device_id: str,
    ) -> ParticipantState:
        """Tombstone a device. The OR-set's add-wins property means
        if the same device rejoins with a fresh add_token, it
        re-establishes."""
        return replace(
            state,
            active_devices=state.active_devices.remove(device_id),
        )

    # ── Internal: per-role helpers ────────────────────────────

    def _best_device_for_role(
        self,
        *,
        role: DeviceRole,
        devices: dict[str, DeviceCapability],
        now_ms: int,
    ) -> tuple[Optional[str], float]:
        """Return (device_id, score) of the best candidate, or
        (None, 0.0) if no device can perform the role. Tiebreak
        on equal scores is lex-min device_id."""
        scored: list[tuple[str, float]] = []
        for device_id, cap in devices.items():
            s = score_device_for_role(
                cap, role, now_ms=now_ms, weights=self._weights,
            )
            if s > 0.0:
                scored.append((device_id, s))
        if not scored:
            return None, 0.0
        # Highest score wins. Tiebreak by lex-min device_id (NOT
        # lex-max — we want stable convergence even when devices
        # have indistinguishable scores; min is the canonical pick).
        scored.sort(key=lambda kv: (-kv[1], kv[0]))
        return scored[0]

    @staticmethod
    def _register_for_role(
        state: ParticipantState, role: DeviceRole,
    ) -> LWWRegister[str]:
        if role == DeviceRole.MIC:
            return state.primary_mic
        if role == DeviceRole.CAM:
            return state.primary_cam
        if role == DeviceRole.DISPLAY:
            return state.primary_display
        if role == DeviceRole.SPEAKER:
            return state.primary_speaker
        if role == DeviceRole.RELAY:
            return state.preferred_relay
        raise ValueError(f"role {role!r} is not Body-Engine arbitrated")

    @staticmethod
    def _set_register(
        state: ParticipantState,
        role: DeviceRole,
        register: LWWRegister[str],
    ) -> ParticipantState:
        if role == DeviceRole.MIC:
            return replace(state, primary_mic=register)
        if role == DeviceRole.CAM:
            return replace(state, primary_cam=register)
        if role == DeviceRole.DISPLAY:
            return replace(state, primary_display=register)
        if role == DeviceRole.SPEAKER:
            return replace(state, primary_speaker=register)
        if role == DeviceRole.RELAY:
            return replace(state, preferred_relay=register)
        raise ValueError(f"role {role!r} is not Body-Engine arbitrated")
